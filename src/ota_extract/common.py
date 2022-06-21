# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2022 Andrew Powers-Holmes <aholmes@omnom.net>
# Copyright (C) 2013 The Android Open Source Project
#

import bz2
import hashlib
import io
import itertools
import lzma
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import bsdiff4
import tqdm
from update_metadata.update_metadata_pb2 import Extent, InstallOperation

from .error import PayloadError

OpType = InstallOperation.Type

# Constants
PSEUDO_EXTENT_MARKER = (1 << 64) - 1  # UINT64_MAX


def encode_digest(digest: bytes) -> str:
    """Encode a hash digest as a base64 string.

    Args:
        digest: The digest to encode (bytes)

    Returns:
        The encoded digest (string)
    """
    return digest.encode("base64").strip()


def decode_digest(hash: str) -> bytes:
    """Decode a hash digest from a base64 string.

    Args:
        hash: The hash to decode (string)

    Returns:
        The decoded digest (bytes)
    """
    return hash.decode("base64")


def _verify_sha256(fileobj: io.FileIO, hash: bytes or str, name: str, length: int = -1) -> bool:
    """Verify a file's SHA256 hash.

    Args:
        fileobj: The file to verify (io.FileIO)
        hash: The expected hash (raw bytes or hex string)
        name: Name of the file for error reporting (string)
        length: The expected size of the file in bytes (int) (optional)

    Returns:
        True if the hash matches, False otherwise.

    Raises:
        ValueError: If the hash is not a valid hex string
        PayloadError: If the hash does not match the file's contents
        PayloadError: If the file is too short
        PayloadError: If the file is not at offset 0
    """
    if fileobj.tell() != 0:
        raise PayloadError("file %s is not at offset 0" % name)

    if isinstance(hash, bytes):
        hash = encode_digest(hash)

    max_length = length if length >= 0 else sys.maxsize

    shasum = hashlib.sha256()
    blocksize_bytes = 2**20

    while max_length > 0:
        read_length = min(blocksize_bytes, max_length)
        data = fileobj.read(read_length)
        if not data:
            break
        max_length -= len(data)
        shasum.update(data)

    if length >= 0 and max_length > 0:
        raise PayloadError(f"{name} length error: expected {length} bytes, got {length - max_length}")

    file_hash = encode_digest(shasum.digest())
    if file_hash != hash:
        raise PayloadError(f"{name} hash mismatch: expected {hash}, got {file_hash}")

    return True


def _bytes_in_extents(self, extents: list, block_size: int) -> int:
    """Returns the number of bytes in the given extents."""
    length = 0
    for ex in extents:
        length += ex.num_blocks * block_size
    return length


def read_extents(fileobj: io.FileIO, extents: list, block_size: int, max_length: int = -1) -> bytes:
    """Reads the extent data from an InstallOperation.

    Args:
        fileobj: The file to read from (io.FileIO)
        extents: Extents to read from (list of Extent)
        block_size: The block size of the file (int)
        max_length: The maximum number of bytes to read (int) (optional)

    Returns:
        A bytes() object containing the data read.

    Raises:
        PayloadError: If the file is too short
        FileError: If an error occurs reading from the file
    """

    max_length = sys.maxsize if max_length < 0 else max_length

    data = io.BytesIO()

    for ex in extents:
        if max_length == 0:
            break

        read_length = min(max_length, ex.num_blocks * block_size)

        # Fill with zeros or read from file, depending on the type of extent.
        if ex.start_block == PSEUDO_EXTENT_MARKER:
            data.write(itertools.repeat("\0", read_length))
        else:
            fileobj.seek(ex.start_block * block_size)
            data.write(fileobj.read(read_length))
        max_length -= read_length

    return data.getvalue()


def write_extents(
    fileobj: io.FileIO, data: bytes or io.BytesIO, extents: list, block_size: int, base_name: str
) -> None:
    """Write the extent data from an InstallOperation.

    Args:
        fileobj: The file to read from (io.FileIO)
        data: Data to write (io.BytesIO)
        extents: Extents to read from (list of Extent)
        block_size: The block size of the file (int)
        base_name: Name of the file for error reporting (string)

    Returns:
        A bytes() object containing the data read.

    Raises:
        PayloadError: If the data is too long
        FileError: If an error occurs reading from the file
    """

    if fileobj.tell() != 0:
        raise PayloadError("file is not at offset 0")

    if isinstance(data, bytes):
        data = io.BytesIO(data)

    data_offset = 0
    data_length = len(data)
    ex_num = 1
    for ex in extents:
        if data_length <= 0:
            raise PayloadError(f"{base_name}: data for extent {ex_num} is too short")
        write_length = min(data_length, ex.num_blocks * block_size)

        # Only write to file if the extent is not a pseudo-extent.
        if ex.start_block != PSEUDO_EXTENT_MARKER:
            data.seek(data_offset)
            fileobj.seek(ex.start_block * block_size)
            fileobj.write(data.read(write_length))

        data_length -= write_length
        data_offset = data.tell()
        ex_num += 1

    if data_length > 0:
        raise PayloadError(f"{base_name}: more data than write extents")

    pass


def extents_to_arg(
    extents: list, block_size: int, base_name: str, data_length: int = -1
) -> Tuple[str, int, int]:
    """Translate an extent sequence into a bspatch/puffin-compatible command line.

    Args:
        extents: Extents to read from (list of Extent)
        block_size: The block size of the file (int)
        base_name: Name of the file for error reporting (string)
        data_length: The length of the data to write (int) (optional)

    Returns:
        a tuple containing:
            - The bspatch/puffin-compatible command line (string)
            - an offset where zero-padding is needed for the last extent (int)
            - the length of the zero-pad (0=no padding required) (int)

    Raises:
        PayloadError: If the data is too short or too long.
    """

    cmdline: str = ""
    pad_off = 0
    pad_len = 0
    data_length = sys.maxsize if data_length < 0 else data_length

    ex_num = 1
    for ex in extents:
        if data_length <= 0:
            raise PayloadError(f"{base_name}: data for extent {ex_num} is too short")

        is_pseudo = ex.start_block == PSEUDO_EXTENT_MARKER
        start_byte = -1 if is_pseudo else ex.start_block * block_size
        num_bytes = ex.num_blocks * block_size

        if data_length < num_bytes:
            # Padding a real extent
            if is_pseudo is not True:
                pad_off = start_byte + data_length
                pad_len = num_bytes - data_length

            num_bytes = data_length

        cmdline += f"{start_byte}:{num_bytes},"
        data_length -= num_bytes
        ex_num += 1

    # trim extra comma from the end there
    cmdline = cmdline[:-1]

    if data_length >= 0:
        raise PayloadError(f"{base_name}: data for extent {ex_num} is too long")

    return cmdline, pad_off, pad_len


# Operator for applying an InstallOperation to a file.
class PayloadOperator(object):
    """Applies an InstallOperation to a file.

    This class is used to apply an InstallOperation, it exists to isolate the logic
    used for each type of operation.
    """

    def __init__(
        self,
        block_size: int,
        bsdiff_in_place: bool = True,
        bspatch_path: Path = None,
        puffin_path: Path = None,
        truncate: bool = True,
    ) -> None:
        """Initialize the operator.

        Args:
            block_size: The block size of the file (int)
            bsdiff_in_place: Whether to apply bsdiffs in-place (bool) (optional)
            bspatch_path: Path to the bspatch binary (Path) (optional)
            puffin_path: Path to the puffin binary (Path) (optional)
            truncate: Whether to truncate the file before writing (bool) (optional)
        """
        self.block_size = block_size
        self.bsdiff_in_place = bsdiff_in_place
        self.bspatch_path = bspatch_path or "bspatch"
        self.puffin_path = puffin_path or "puffin"
        self.truncate = truncate
        pass

    def _apply_replace(
        self,
        op: InstallOperation,
        out_data: bytes,
        out_file: io.FileIO,
        out_size: int,
    ) -> None:
        """Applies a REPLACE{,_BZ,_XZ} operation.

        Args:
            op: the operation object
            out_data: the data to be written (bytes)
            out_file: the target file object (io.FileIO)
            out_size: the final size of the target file (int)

        Raises:
            PayloadError if something goes wrong.
        """

        block_size = self.block_size

        # decompress the data if needed
        if op.type == InstallOperation.Type.REPLACE_BZ:
            out_data = bz2.decompress(out_data)
        if op.type == InstallOperation.Type.REPLACE_XZ:
            out_data = lzma.decompress(out_data)
        data_length = len(out_data)

        data_start = 0
        ex_num = 1
        for ex in op.dst_extents:
            start_block = ex.start_block
            num_blocks = ex.num_blocks
            count = num_blocks * block_size

            # do nothing for pseudo-extents
            if ex.start_block != PSEUDO_EXTENT_MARKER:
                data_end = data_start + count

                # Make sure we're not running past partition boundary.
                if (start_block + num_blocks) * block_size > out_size:
                    raise PayloadError(f"extent {ex_num} exceeds partition size ({out_size})")

                # Make sure that we have enough data to write.
                if data_end >= data_length + block_size:
                    raise PayloadError("more dst blocks than data (even with padding)")

                # Pad the end of the data if needed.
                if data_end > data_length:
                    out_data += itertools.repeat(b"\0", (data_end - data_length))

                # Write the data.
                out_file.seek(start_block * block_size)
                out_file.write(out_data[data_start:data_end])

            data_start += count
            ex_num += 1

        # Make sure we wrote everything.
        if data_start < data_length:
            raise PayloadError(f"wrote {data_start} bytes, expected {data_length}")

    def _apply_move(self, op: InstallOperation, out_file: io.FileIO) -> None:
        """Applies a MOVE operation.

        Args:
            op: the InstallOperation object
            out_file: the target file object (io.FileIO)

        Raises:
            PayloadError if something goes wrong.
        """

        # get data from extents
        source_data = read_extents(op.src_extents, out_file, self.block_size)

        # write data to extents
        write_extents(op.dst_extents, source_data, out_file, self.block_size)

    def _apply_zero(self, op: InstallOperation, out_file: io.FileIO) -> None:
        """Applies a ZERO operation.

        Args:
            op: the InstallOperation object
            out_file: the target file object (io.FileIO)

        Raises:
            PayloadError if something goes wrong.
        """
        for ex in op.dst_extents:
            if ex.start_block != PSEUDO_EXTENT_MARKER:
                out_file.seek(ex.start_block * self.block_size)
                out_file.write(itertools.repeat(b"\0", ex.num_blocks * self.block_size))

    def _apply_source_copy(self, op: InstallOperation, in_file: io.FileIO, out_file: io.FileIO) -> None:
        """Applies a SOURCE_COPY operation.

        Args:
            op: the InstallOperation object
            in_file: the source file object (io.FileIO)
            out_file: the target file object (io.FileIO)

        Raises:
            PayloadError if something goes wrong.
        """

        in_data = read_extents(op.src_extents, in_file, self.block_size)
        write_extents(op.dst_extents, in_data, out_file, self.block_size)

    def _apply_diff(
        self, op: InstallOperation, op_num: int, patch_data: bytes, in_file: io.FileIO, out_file: io.FileIO
    ) -> None:
        """Applies a BSDIFF, SOURCE_BSDIFF, or BROTLI_BSDIFF operation.

        Args:
            op: the InstallOperation object
            op_num: the operation number (int)
            patch_data: the binary patch content (bytes)
            in_file: the source file object (io.FileIO)
            out_file: the target file object (io.FileIO)

        Raises:
            PayloadError if something goes wrong.
        """
        patch_buff = io.BytesIO()

        # get data from extents
        old_data = read_extents(op.src_extents, in_file, self.block_size)

        # apply patch
        patch_buff.write(bsdiff4.patch(old_data, patch_data))

        # write data to extents
        write_extents(op.dst_extents, patch_buff.getvalue(), out_file, self.block_size)

        pass

    def _apply_puffdiff(
        self,
        op: InstallOperation,
        op_num: int,
        patch_data: bytes,
        in_file: io.FileIO,
        out_file: io.FileIO,
        out_dir: Path,
    ) -> None:
        """Applies a PUFFDIFF operation.

        Args:
            op: the operation object
            op_num: the operation number (int)
            patch_data: the binary patch content (bytes)
            in_file: the source partition file object (io.FileIO)
            out_file: the target partition file object (io.FileIO)
            out_dir: the target directory (Path)

        Raises:
          PayloadError if something goes wrong.
        """
        if not in_file:
            raise PayloadError(f"no source file provided for op ({op.type})")

        block_size = self.block_size

        # dir for temp storage of patch chunks
        patch_dir: Path = out_dir.joinpath(f"{out_file.name}-diffs")
        patch_dir.mkdir(exist_ok=True, parents=True)

        # patchfile paths and commandfile path
        cmd_file: Path = patch_dir.joinpath("cmds.sh")
        patch_path: Path = patch_dir.joinpath(f"diff_{op_num}_patch.bin")
        src_ext_path: Path = patch_dir.joinpath(f"diff_{op_num}_src.bin")
        dst_ext_path: Path = patch_dir.joinpath(f"diff_{op_num}_dst.bin")

        # gather input raw data and write to src_ext_path
        src_ext_path.write_bytes(read_extents(op.src_extents, in_file, block_size))

        # write patch data to patch_path
        patch_path.write_bytes(patch_data)

        # Invoke puffpatch on the patch_path and src_ext_path
        puffpatch_cmd = [
            "puffin",
            "--operation=puffpatch",
            "--verbose",
            f"--src_file={src_ext_path}",
            f"--dst_file={dst_ext_path}",
            f"--patch_file={patch_path}",
        ]

        with cmd_file.open("a") as cmd_file_handle:
            cmd_file_handle.write(" ".join(puffpatch_cmd) + "\n")
        subprocess.check_call(puffpatch_cmd)

        # write dst_ext_path to out_file, with padding
        out_data = dst_ext_path.read_bytes()
        unaligned_len = len(out_data) % block_size
        if unaligned_len != 0:
            out_data += itertools.repeat(b"\0", block_size - unaligned_len)
        write_extents(op.dst_extents, out_data, out_file, block_size)

    def _ApplyOperations(
        self, part_name: str, operations: list, in_file: io.FileIO, out_file: io.FileIO, part_size: int
    ) -> None:
        """Applies a sequence of update operations to a partition.

        This assumes an in-place update semantics for MOVE and BSDIFF, namely all
        reads are performed first, then the data is processed and written back to
        the same file.

        Args:
            part_name: the partition name (str)
            operations: list of InstallOperations (list)
            in_file: the old partition file object, open for reading/writing
            out_file: the new partition file object, open for reading/writing
            payload_file: the payload file object, open for reading
            part_size: the partition size

        Raises:
          PayloadError if anything goes wrong while processing the payload.
        """

        # create output directory for patch chunks
        out_dir: Path = Path(out_file.name).parent

        op_num = 1
        for op in tqdm(operations):
            # Read data blob.
            data = self.payload.ReadDataBlob(op.data_offset, op.data_length)

            if op.type in (
                InstallOperation.Type.REPLACE,
                InstallOperation.Type.REPLACE_BZ,
                InstallOperation.Type.REPLACE_XZ,
            ):
                self._apply_replace(op, data, out_file, part_size)
            elif op.type == InstallOperation.Type.MOVE:
                self._apply_move(op, out_file)
            elif op.type == InstallOperation.Type.ZERO:
                self._apply_zero(op, out_file)
            elif op.type == InstallOperation.Type.BSDIFF:
                self._apply_diff(op, op_num, data, out_file, out_file)
            elif op.type == InstallOperation.Type.SOURCE_COPY:
                self._apply_source_copy(op, in_file, out_file)
            elif op.type in (
                InstallOperation.Type.SOURCE_BSDIFF,
                InstallOperation.Type.BROTLI_BSDIFF,
            ):
                self._apply_diff(op, op_num, data, in_file, out_file)
            elif op.type == InstallOperation.Type.PUFFDIFF:
                self._apply_puffdiff(op, op_num, data, in_file, out_file, out_dir)
            else:
                raise PayloadError("%s: unknown operation type (%d)" % (part_name, op.type))
            op_num += 1
