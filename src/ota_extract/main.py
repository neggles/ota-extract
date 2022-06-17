import bz2
import io
import lzma
import struct
import sys
import hashlib
from pathlib import Path

import bsdiff4
import click
import google.protobuf.json_format as pb_json
from tqdm import tqdm
from update_metadata.update_metadata_pb2 import (
    DeltaArchiveManifest,
    InstallOperation,
    PartitionUpdate,
)


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
def do_install_op(
    op: InstallOperation,
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

    if op.type == op.REPLACE:
        out_file.write(in_file.read(op.data_length))
        return

    elif op.type == op.REPLACE_BZ:
        dec = bz2.BZ2Decompressor()
        out_file.write(dec.decompress(in_file.read(op.data_length)))
        return

    elif op.type == op.REPLACE_XZ:
        dec = lzma.LZMADecompressor()
        out_file.write(dec.decompress(in_file.read(op.data_length)))
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

        elif op.type == op.BROTLI_BSDIFF or op.type == op.BROTLI_BSDIFF:
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
    else:
        if op.type == op.SOURCE_COPY:
            raise Exception(f"SOURCE_COPY not supported in non-delta update")
        elif op.type == op.SOURCE_BSDIFF:
            raise Exception(f"SOURCE_BSDIFF not supported in non-delta update")
        elif op.type == op.BROTLI_BSDIFF:
            raise Exception(f"BROTLI_BSDIFF not supported in non-delta update")
        pass

    raise Exception(f"{InstallOperation.Type.Name(op.type)} not implemented")


def do_partition_update(
    partition: PartitionUpdate,
    block_size: int,
    data_offset: int,
    in_file: io.FileIO,
    out_dir: Path,
    base_dir: Path = None,
    delta: bool = False,
):
    if delta is True and base_dir is not None:
        base_path = base_dir.joinpath(f"{partition.partition_name}.img")
        base_file = base_path.open("rb")
    elif delta is True:
        raise Exception("Delta update found and base image directory not specified")
    else:
        base_file = None

    out_path = out_dir.joinpath(f"{partition.partition_name}.img")

    try:
        with out_path.open("wb") as out_file:
            op_iter = tqdm(
                partition.operations, desc=partition.partition_name, ncols=120, unit="ops"
            )
            for op in op_iter:
                do_install_op(
                    op=op,
                    in_file=in_file,
                    out_file=out_file,
                    base_file=base_file,
                    data_offset=data_offset,
                    block_size=block_size,
                    delta=delta,
                )
    except Exception as e:
        op_iter.write(f"Error extracting partition {partition.partition_name}: {e}")
        out_path.unlink()

    finally:
        if base_file is not None:
            base_file.close()


@click.command()
@click.version_option(package_name="ota-extract")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable verbose console output.")
@click.option(
    "-p",
    "--payload",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=False,
    default="./payload.bin",
    help="Path to the payload file",
)
@click.option(
    "-o",
    "--out-dir",
    type=click.Path(writable=True, file_okay=False, path_type=Path),
    required=False,
    default="./out",
    help="Output directory for extracted files",
)
@click.option(
    "-b",
    "--base-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=False,
    default=None,
    help="Path to base partition images for delta OTA",
)
@click.option(
    "-d",
    "--delta",
    is_flag=True,
    default=False,
    help="Extract delta OTA - requires base partition images",
)
@click.argument(
    "partition_name",
    type=str,
    required=False,
    default="",
)
def cli(
    verbose: bool, payload: Path, out_dir: Path, base_dir: Path, delta: bool, partition_name: str
):
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
        data_offset = in_file.tell()

        # parse manifest
        click.echo(f"Parsing {manifest_length}-byte manifest... ", nl=False)
        manifest = DeltaArchiveManifest()
        manifest.ParseFromString(manifest_data)
        block_size = manifest.block_size

        # hash the manifest and use the last 8 chars in the output subdirectory name
        # this deals with filename collisions, but is deterministic so repeated runs
        # on the same payload will always produce the same output directory
        manifest_hash = hashlib.sha1(signature, usedforsecurity=False).hexdigest()[-8:]
        out_dir = out_dir.joinpath(in_file.name + "-" + manifest_hash)
        out_dir.mkdir(parents=True, exist_ok=True)

        # print partition names
        click.echo(f"found {len(manifest.partitions)} partitions:")
        for partition in manifest.partitions:
            click.echo(f"  - {partition.partition_name}")

        with Path(f"{out_dir}/manifest.json").open("w") as f:
            f.write(pb_json.MessageToJson(manifest))

        if partition_name != "":
            click.echo(f"Extracting partition {partition_name}...")
            for partition in manifest.partitions:
                if partition.partition_name == partition_name:
                    do_partition_update(
                        partition=partition,
                        block_size=block_size,
                        data_offset=data_offset,
                        in_file=in_file,
                        out_dir=out_dir,
                        base_dir=base_dir,
                        delta=delta,
                    )
                    return
            click.echo(f"Partition {partition_name} not found")
            raise Exception("Partition not found")
        else:
            click.echo("Extracting all partitions...")
            partition_iterator = tqdm(
                manifest.partitions, ncols=120, desc="Extracting", disable=True
            )
            for partition in partition_iterator:
                do_partition_update(
                    partition=partition,
                    block_size=block_size,
                    data_offset=data_offset,
                    in_file=in_file,
                    out_dir=out_dir,
                    base_dir=base_dir,
                    delta=delta,
                )

    click.echo("done")
    sys.exit(0)


if __name__ == "__main__":
    cli()
