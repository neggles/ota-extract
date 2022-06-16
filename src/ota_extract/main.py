import bz2
import io
import lzma
import struct
import sys
from functools import partial
from pathlib import Path

import bsdiff4
import click
import protos.update_metadata_pb2 as UpdateMetadata
from tqdm import tqdm


# flatten list of lists
def flatten(list):
    return [item for sublist in list for item in sublist]


# get uint32_t from bytes
def u32(x):
    return struct.unpack(">I", x)[0]


# get uint64_t from bytes
def u64(x):
    return struct.unpack(">Q", x)[0]


# verify if the extents are contiguous
def verify_contiguous(exts):
    blocks = 0
    for ext in exts:
        if ext.start_block != blocks:
            return False
        blocks += ext.num_blocks
    return True


# various payload operations
def execute_op(
    op,
    in_file: io.FileIO,
    out_file: io.FileIO,
    base_file: io.FileIO,
    data_offset: int,
    block_size: int,
    delta: bool = False,
):

    # seek to the global data offset + operation data offset
    in_file.seek(data_offset + op.data_offset)
    # seek to the output file offset
    out_file.seek(op.dst_extents[0].start_block * block_size)

    if op.type == op.REPLACE_XZ:
        dec = lzma.LZMADecompressor()
        out_file.write(dec.decompress(in_file.read(op.data_length)))
        return

    elif op.type == op.REPLACE_BZ:
        dec = bz2.BZ2Decompressor()
        out_file.write(dec.decompress(in_file.read(op.data_length)))
        return

    elif op.type == op.REPLACE:
        out_file.write(in_file.read(op.data_length))
        return

    elif op.type == op.ZERO:
        for ext in op.dst_extents:
            out_file.seek(ext.start_block * block_size)
            out_file.write(b"\x00" * ext.num_blocks * block_size)
        return

    # delta ops because sane control flow is for squares amirite
    if delta is True:
        if op.type == op.SOURCE_COPY:
            for ext in op.src_extents:
                base_file.seek(ext.start_block * block_size)
                out_file.write(base_file.read(ext.num_blocks * block_size))
            return

        elif op.type == op.SOURCE_BSDIFF:
            diff_buff = io.BytesIO()

            # get base extents
            for ext in op.src_extents:
                base_file.seek(ext.start_block * block_size)
                old_data = base_file.read(ext.num_blocks * block_size)
                diff_buff.write(old_data)

            # replace old data with diff extents
            diff_buff.seek(0)
            old_data = diff_buff.read()

            # apply bsdiff to old data
            diff_buff.seek(0)
            diff_buff.write(bsdiff4.patch(old_data, in_file.read(op.data_length)))

            # write modified data to output file
            n = 0
            for ext in op.dst_extents:
                diff_buff.seek(n * block_size)
                n += ext.num_blocks
                data = diff_buff.read(ext.num_blocks * block_size)
                out_file.seek(ext.start_block * block_size)
                out_file.write(data)
            return
        pass

    raise Exception(f"Unsupported operation type: {op.type}")


def process_partition(
    partition,
    block_size: int,
    data_offset: int,
    in_file: io.FileIO,
    out_dir: Path,
    base_dir: Path = None,
    delta: bool = False,
):
    out_path = Path(f"{out_dir}/{partition.partition_name}.img")
    if delta is True:
        base_path = Path(f"{base_dir}/{partition.partition_name}.img")
        base_file = base_path.open("rb")
    else:
        base_file = None

    with out_path.open("wb") as out_file:
        for op in tqdm(partition.operations, desc=partition.partition_name, ncols=120, unit="ops"):
            execute_op(
                op=op,
                in_file=in_file,
                out_file=out_file,
                base_file=base_file,
                data_offset=data_offset,
                block_size=block_size,
                delta=delta,
            )

    if base_file is not None:
        base_file.close()


@click.command()
@click.version_option(package_name="ota-extract")
@click.option(
    "-p",
    "--payload",
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=False),
    required=False,
    default="./payload.bin",
    help="Path to the payload file",
)
@click.option(
    "-o",
    "--out-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True),
    required=False,
    default="./out",
    help="Output directory for extracted files",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Print verbose output.")
@click.option(
    "-b",
    "--base-dir",
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=False),
    required=False,
    default=None,
    help="Path to base partition images for delta OTA",
)
@click.argument(
    "partition_name",
    type=str,
    required=False,
    default="",
)
def cli(payload: Path, out_dir: Path, verbose: bool, base_dir: Path, partition_name: str):
    click.echo(f"Extracting file {payload} to {out_dir}")
    with open(payload, "rb") as in_file:
        file_magic = in_file.read(4)
        if file_magic != b"CrAU":
            click.echo(f"Invalid payload file magic: {file_magic}")
            raise Exception("Invalid payload file magic")

        # read header
        payload_version = u64(in_file.read(8))
        manifest_length = u64(in_file.read(8))

        # load manifest
        if payload_version == 2:
            pass
        else:
            click.echo(f"Unsupported payload version: {payload_version}")
            raise Exception("Unsupported payload version")

        click.echo(f"Found payload with version {payload_version}")
        signature_length = u32(in_file.read(4))
        manifest_data = in_file.read(manifest_length)
        signature = in_file.read(signature_length)  # we don't check the signature
        del signature
        data_offset = in_file.tell()

        # parse manifest
        click.echo(f"Parsing {manifest_length}-byte manifest... ", nl=False)
        manifest = UpdateMetadata.DeltaArchiveManifest()
        manifest.ParseFromString(manifest_data)
        block_size = manifest.block_size

        # print partition names
        click.echo(f"found {len(manifest.partitions)} partitions:")
        for partition in manifest.partitions:
            click.echo(f"  - {partition.partition_name}")

        if verbose is True:
            click.echo(f"raw manifest: {manifest}")

        if partition_name != "":
            click.echo(f"Extracting partition {partition_name}...")
            for partition in manifest.partitions:
                if partition.partition_name == partition_name:
                    process_partition(
                        partition=partition,
                        block_size=block_size,
                        data_offset=data_offset,
                        in_file=in_file,
                        out_dir=out_dir,
                        base_dir=base_dir,
                    )
                    return
            click.echo(f"Partition {partition_name} not found")
            raise Exception("Partition not found")
        else:
            click.echo("Extracting all partitions...")
            for partition in tqdm(manifest.partitions, ncols=120, desc="Extracting", disable=True):
                process_partition(
                    partition=partition,
                    in_file=in_file,
                    out_dir=out_dir,
                    block_size=block_size,
                    data_offset=data_offset,
                )

    click.echo("done")
    sys.exit(0)


if __name__ == "__main__":
    cli()
