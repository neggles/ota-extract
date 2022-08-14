#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""payload_info: Show information about an update payload."""
import textwrap
from pathlib import Path

import typer
from rich import box
from rich.text import Text
from rich.columns import Columns
from rich.console import Console, Group, group
from rich.panel import Panel
from rich.table import Table

import update_payload
from update_metadata.update_metadata_pb2 import Signatures

console = Console()
app = typer.Typer()

MAJOR_PAYLOAD_VERSION_BRILLO = 2
PANEL_WIDTH = 75


def add_kv_row(grid: Table, key: str, value) -> None:
    """Add a key, value row to the grid."""
    if value is not None and value != "":
        grid.add_row(key, str(value))
    else:
        grid.add_row(key, "Not specified")


def HexTable(data) -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=46, justify="right")
    grid.add_column(width=1)
    grid.add_column(width=16)
    rows = [bytearray(data[i : i + 16]) for i in range(0, len(data), 16)]
    for row in rows:
        grid.add_row(
            " ".join(f"{byte:02x}" for byte in row),
            "|",
            "".join(chr(c) if 32 <= c < 127 else "." for c in row),
        )
    return grid


def DisplayValue(key, value):
    """Print out a key, value pair with values left-aligned."""
    if value is not None:
        console.print("%-*s %s" % (32, key + ":", value))
    else:
        raise ValueError("Cannot display an empty value.")


class PayloadInfo(object):
    """Show basic information about an update payload.
    This command parses an update payload and displays information from
    its header and manifest.
    """

    def __init__(self, payload_file: Path):
        """Initialize the payload info object."""
        self.payload_file = payload_file
        self.payload = update_payload.Payload(payload_file)
        self.payload.Init()

    def DisplayHeader(self):
        """Show information from the payload header."""
        header = self.payload.header
        columns = Columns(
            [
                Panel(f"[b]Payload version\n[/b][blue]{header.version}"),
                Panel(f"[b]Manifest length\n[/b][blue]{header.manifest_len} bytes"),
            ],
            equal=True,
        )
        console.print(
            Panel(columns, width=PANEL_WIDTH, title="[b]Header", title_align="left", border_style="blue")
        )

    def DisplayManifest(self):
        """Show information from the payload manifest."""
        manifest = self.payload.manifest

        part_table = Table(box=box.ROUNDED, min_width=71)
        part_table.add_column("Partition", ratio=10)
        part_table.add_column("Ops", ratio=2)
        part_table.add_column("Version", ratio=2)
        part_table.add_column("COW Size", ratio=2)

        for partition in manifest.partitions:
            part_table.add_row(
                str(partition.partition_name),
                str(len(partition.operations)),
                str(partition.version) if partition.version else "-",
                str(partition.estimate_cow_size),
            )

        columns = Columns(
            [
                Panel(f"[b]Partitions[/b]\n[green]{len(manifest.partitions)}"),
                Panel(f"[b]Block size[/b]\n[green]{manifest.block_size} bytes"),
                Panel(f"[b]Minor version[/b]\n[green]{manifest.minor_version}"),
            ],
            equal=True,
        )

        manifest_panel = Panel(
            columns, title="[b]Manifest", title_align="left", width=PANEL_WIDTH, border_style="green"
        )
        console.print(manifest_panel)

        part_panel = Panel(
            part_table, title="[b]Partitions", title_align="left", width=PANEL_WIDTH, border_style="green"
        )
        console.print(part_panel)

    def DisplaySignatures(self):
        """Show information about the signatures from the manifest."""
        header = self.payload.header
        if header.metadata_signature_len:
            offset = header.size + header.manifest_len
            # pylint: disable=invalid-unary-operand-type
            signatures_blob = self.payload.ReadDataBlob(
                -header.metadata_signature_len, header.metadata_signature_len
            )
            self.DisplaySignaturesBlob(
                "Metadata", signatures_blob, f"file_offset={offset} ({header.metadata_signature_len} bytes)"
            )
        else:
            console.print(
                Panel("No metadata signatures stored in the payload", title="[b]Metadata Signatures")
            )

        manifest = self.payload.manifest
        if manifest.HasField("signatures_offset"):
            signature_meta = f"blob_offset={manifest.signatures_offset}"
            if manifest.signatures_size:
                signature_meta += f" ({manifest.signatures_size} bytes)"
            signatures_blob = self.payload.ReadDataBlob(manifest.signatures_offset, manifest.signatures_size)
            self.DisplaySignaturesBlob("Payload", signatures_blob, signature_meta)
        else:
            console.print(Panel("No payload signatures stored in the payload", title="[b]Payload Signatures"))

    @staticmethod
    def DisplaySignaturesBlob(signature_name, signatures_blob, signature_meta=None):
        """Show information about the signatures blob."""
        signatures = Signatures()
        signatures.ParseFromString(signatures_blob)
        count = len(signatures.signatures)
        count_str = f"{count} signature{'s' if count > 1 else ''} in blob"

        @group()
        def signatures_group():
            if signature_meta is not None:
                yield Panel(f"{signature_meta}\n{count_str}" if signature_meta else count_str)
            for idx, signature in enumerate(signatures.signatures):
                version = signature.version if signature.HasField("version") else None
                sig_title = (
                    f"[b]Signature {idx+1} (version: {version}, hex_data: {len(signature.data)} bytes)"
                )
                yield Panel.fit(HexTable(signature.data), title=sig_title, title_align="left")

        panel = Group(
            Panel.fit(
                signatures_group(),
                title=f"[b]{signature_name} signatures",
                title_align="left",
                border_style="yellow",
            ),
        )
        console.print(panel)

    def DisplayOps(self, name, operations):
        """Show information about the install operations from the manifest.
        The list shown includes operation type, data offset, data length, source
        extents, source length, destination extents, and destinations length.
        Args:
          name: The name you want displayed above the operation table.
          operations: The operations object that you want to display information
                      about.
        """

        def DisplayExtents(extents, name):
            """Show information about extents."""
            num_blocks = sum([ext.num_blocks for ext in extents])
            ext_str = " ".join("(%s,%s)" % (ext.start_block, ext.num_blocks) for ext in extents)
            # Make extent list wrap around at 80 chars.
            ext_str = "\n      ".join(textwrap.wrap(ext_str, 74))
            extent_plural = "s" if len(extents) > 1 else ""
            block_plural = "s" if num_blocks > 1 else ""
            console.print(
                "    %s: %d extent%s (%d block%s)"
                % (name, len(extents), extent_plural, num_blocks, block_plural)
            )
            console.print("      %s" % ext_str)

        op_dict = update_payload.common.OpType.NAMES
        console.print("%s:" % name)
        for op_count, op in enumerate(operations):
            console.print("  %d: %s" % (op_count, op_dict[op.type]))
            if op.HasField("data_offset"):
                console.print("    Data offset: %s" % op.data_offset)
            if op.HasField("data_length"):
                console.print("    Data length: %s" % op.data_length)
            if op.src_extents:
                DisplayExtents(op.src_extents, "Source")
            if op.dst_extents:
                DisplayExtents(op.dst_extents, "Destination")

    def _GetStats(self, manifest):
        """Returns various statistics about a payload file.
        Returns a dictionary containing the number of blocks read during payload
        application, the number of blocks written, and the number of seeks done
        when writing during operation application.
        """
        read_blocks = 0
        written_blocks = 0
        num_write_seeks = 0
        for partition in manifest.partitions:
            last_ext = None
            for curr_op in partition.operations:
                read_blocks += sum([ext.num_blocks for ext in curr_op.src_extents])
                written_blocks += sum([ext.num_blocks for ext in curr_op.dst_extents])
                for curr_ext in curr_op.dst_extents:
                    # See if the extent is contiguous with the last extent seen.
                    if last_ext and (curr_ext.start_block != last_ext.start_block + last_ext.num_blocks):
                        num_write_seeks += 1
                    last_ext = curr_ext
            # Old and new partitions are read once during verification.
            read_blocks += partition.old_partition_info.size // manifest.block_size
            read_blocks += partition.new_partition_info.size // manifest.block_size
        stats = {
            "read_blocks": read_blocks,
            "written_blocks": written_blocks,
            "num_write_seeks": num_write_seeks,
        }
        return stats

    def DisplayStats(self, manifest):
        """Show statistics about the payload file."""
        stats = self._GetStats(manifest)
        grid = Table.grid(padding=(0, 1))
        grid.add_column(min_width=32, justify="left")
        grid.add_column()
        grid.add_row("Read Blocks:", f'{stats["read_blocks"]}')
        grid.add_row("Written Blocks:", f'{stats["written_blocks"]}')
        grid.add_row("Seeks when writing:", f'{stats["num_write_seeks"]}')
        console.print(
            Panel(
                grid,
                title="[b]Payload Statistics",
                title_align="left",
                width=PANEL_WIDTH,
                border_style="red",
            )
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    payload_file: Path = typer.Argument(
        ...,
        help="The update payload file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
):
    """
    Show information about an update payload.
    """
    console.print(
        Panel(
            str(payload_file),
            title="[b]Payload File",
            border_style="magenta",
            title_align="left",
            width=PANEL_WIDTH,
        )
    )
    ctx.obj = PayloadInfo(payload_file)
    ctx.obj.DisplayHeader()
    ctx.obj.DisplayManifest()
    if ctx.invoked_subcommand is None:
        signatures(ctx)
        stats(ctx)


@app.command()
def list_ops(ctx: typer.Context):
    """
    List the install operations in the payload.
    """
    for partition in ctx.obj.payload.manifest.partitions:
        ctx.obj.DisplayOps("%s install operations" % partition.partition_name, partition.operations)


@app.command()
def signatures(ctx: typer.Context):
    """
    List the signatures in the payload.
    """
    ctx.obj.DisplaySignatures()


@app.command()
def stats(ctx: typer.Context):
    """
    Show statistics about the payload.
    """
    ctx.obj.DisplayStats(ctx.obj.payload.manifest)


if __name__ == "__main__":
    app()
