import argparse
import os
import struct
import sys
from typing import List

from bemani.common import PEFile
from bemani.protocol import Node
from bemani.utils.responsegen import generate_lines


def parse_psmap(pe: PEFile, offset: str, rootname: str, *, verbose: bool = False) -> Node:
    root = Node.void(rootname)
    base = int(offset, 16)

    if pe.is_virtual(base):
        # Assume this is virtual
        base = pe.virtual_to_physical(base)

    def read_string(offset: int) -> str:
        # First, translate load offset in memory to disk offset
        offset = pe.virtual_to_physical(offset)

        # Now, grab bytes until we're null-terminated
        bytestring = []
        while pe.data[offset] != 0:
            bytestring.append(pe.data[offset])
            offset = offset + 1

        # Its shift-jis encoded, so decode it now
        return bytes(bytestring).decode("shift_jisx0213")

    # For recursing into nodes
    saved_root: List[Node] = []
    saved_loc: List[int] = []

    while True:
        readbase = base
        if pe.is_64bit():  # 64 bit
            chunk = pe.data[base : (base + 24)]
            base = base + 24

            (nodetype, mandatory, outoffset, width, nameptr, default) = struct.unpack("<BBHIQQ", chunk)
        else:  # 32 bit
            chunk = pe.data[base : (base + 16)]
            base = base + 16

            (nodetype, mandatory, outoffset, width, nameptr, default) = struct.unpack("<BBHIII", chunk)

        if nodetype == 0xFF or nodetype == 0x00:  # if nodetype is 0 then we probably read garbage
            # End of nodes, see if we should exit
            if len(saved_root) == 0:
                break
            else:
                root = saved_root.pop()
                oldbase = saved_loc.pop()
                if oldbase is not None:
                    base = oldbase
                continue

        # Grab name, get rid of parse numbers
        name = read_string(nameptr)
        try:
            if name.index("#") >= 0:
                name = name[: name.index("#")]
        except ValueError:
            pass

        # Grab the default
        if default != 0:
            try:
                defaultptr = pe.virtual_to_physical(default)
            except Exception:
                defaultptr = 0

        if verbose:
            space = "    " * len(saved_root)
            print(
                f"{space}Node offset: {hex(readbase)}{os.linesep}"
                + f"{space}  Type: {hex(nodetype)}{os.linesep}"
                + f"{space}  Mandatory: {'yes' if mandatory != 0 else 'no'}{os.linesep}"
                + f"{space}  Name: {name}{os.linesep}"
                + f"{space}  Parse Offset: {outoffset}{os.linesep}"
                + f"{space}  Data Width: {width}{os.linesep}"
                + (
                    f"{space}  Data Pointer: {'null' if defaultptr == 0 else hex(defaultptr)}"
                    if nodetype == 0x01
                    else f"{space}  Default: {default}"
                ),
                file=sys.stderr,
            )

        if nodetype == 0x01:
            # This is a void node, so we should handle by recursing
            node = Node.void(name)
            root.add_child(node)

            # Recurse here
            saved_root.append(root)

            if defaultptr != 0:
                saved_loc.append(base)
                base = defaultptr
            else:
                saved_loc.append(None)

            root = node
            continue
        elif nodetype == 0x02 or nodetype == 0x43:
            if nodetype < 0x40:
                elements = int(width / 1)
            else:
                elements = width
            if elements > 1:
                node = Node.s8_array(name, [-1] * elements)
            else:
                node = Node.s8(name, -1)
        elif nodetype == 0x03 or nodetype == 0x44:
            if nodetype < 0x40:
                elements = int(width / 1)
            else:
                elements = width
            if elements > 1:
                node = Node.u8_array(name, [0] * elements)
            else:
                node = Node.u8(name, 0)
        elif nodetype == 0x04 or nodetype == 0x45:
            if nodetype < 0x40:
                elements = int(width / 2)
            else:
                elements = width
            if elements > 1:
                node = Node.s16_array(name, [-1] * elements)
            else:
                node = Node.s16(name, -1)
        elif nodetype == 0x05 or nodetype == 0x46:
            if nodetype < 0x40:
                elements = int(width / 2)
            else:
                elements = width
            if elements > 1:
                node = Node.u16_array(name, [0] * elements)
            else:
                node = Node.u16(name, 0)
        elif nodetype == 0x06 or nodetype == 0x47:
            if nodetype < 0x40:
                elements = int(width / 4)
            else:
                elements = width
            if elements > 1:
                node = Node.s32_array(name, [-1] * elements)
            else:
                node = Node.s32(name, -1)
        elif nodetype == 0x07 or nodetype == 0x48:
            if nodetype < 0x40:
                elements = int(width / 4)
            else:
                elements = width
            if elements > 1:
                node = Node.u32_array(name, [0] * elements)
            else:
                node = Node.u32(name, 0)
        elif nodetype == 0x08 or nodetype == 0x49:
            if nodetype < 0x40:
                elements = int(width / 8)
            else:
                elements = width
            if elements > 1:
                node = Node.s64_array(name, [-1] * elements)
            else:
                node = Node.s64(name, -1)
        elif nodetype == 0x09 or nodetype == 0x4A:
            if nodetype < 0x40:
                elements = int(width / 8)
            else:
                elements = width
            if elements > 1:
                node = Node.u64_array(name, [0] * elements)
            else:
                node = Node.u64(name, 0)
        elif nodetype == 0x0A:
            node = Node.string(name, "")
        elif nodetype == 0x0D:
            node = Node.float(name, 0.0)
        elif nodetype == 0x32 or nodetype == 0x6D:
            if nodetype < 0x40:
                elements = int(width / 1)
            else:
                elements = width
            if elements > 1:
                node = Node.bool_array(name, [False] * elements)
            else:
                node = Node.bool(name, False)
        elif nodetype == 0x2F:
            # Special case, this is an attribute
            if name[-1] != "@":
                raise Exception(f"Attribute name {name} expected to end with @")
            root.set_attribute(name[:-1], "")
            continue
        else:
            raise Exception(f"Unimplemented node type 0x{nodetype:02x}")

        # Append it
        root.add_child(node)

    return root


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to extract psmap node lists and generate code.")
    parser.add_argument(
        "--file",
        help="DLL file to extract from.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--offset",
        help="Hex offset into the file. This can be specified as either a raw offset into the DLL or as a virtual offset.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "-o",
        "--outfile",
        help="File to write python code to. Use - for stdout.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--root",
        help="Root node name to be used for the generated code.",
        type=str,
        default="root",
    )
    parser.add_argument(
        "--emulate-code",
        help=(
            "Hex offset pair of addresses where we should emulate x86/x64 code to "
            "reconstuct a dynamic psmap structure, separated by a colon. This can "
            "be specified as either a raw offset into the DLL or as a virtual offset. "
            "If multiple sections must be emulated you can specify this multiple times."
        ),
        type=str,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--emulate-function",
        help=(
            "Hex offset address of a function that we should emulate to reconstruct a "
            "dynamic psmap structure. This can be specified as either a raw offset into "
            "the DLL or as a virtual offset. If multiple functions must be emulated you "
            "can specify this multiple times."
        ),
        type=str,
        action="append",
        default=[],
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Display verbose parsing info.",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    fp = open(args.file, "rb")
    data = fp.read()
    fp.close()

    pe = PEFile(data=data)

    # If asked, attempt to emulate code which dynamically constructs a psmap structure.
    if args.emulate_code:
        for chunk in args.emulate_code:
            emulate_start, emulate_end = chunk.split(":", 1)
            start = int(emulate_start, 16)
            end = int(emulate_end, 16)
            pe.emulate_code(start, end, verbose=args.verbose)

    if args.emulate_function:
        for function_address in args.emulate_function:
            fun = int(function_address, 16)
            pe.emulate_function(fun, verbose=args.verbose)

    layout = parse_psmap(pe, args.offset, args.root, verbose=args.verbose)

    # Walk through, outputting each node and attaching it to its parent
    code = "\n".join(generate_lines(layout, {}))

    if args.outfile == "-":
        print(code)
    else:
        with open(args.outfile, mode="a") as outfp:
            outfp.write(code)
            outfp.close


if __name__ == "__main__":
    main()
