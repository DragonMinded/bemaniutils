import argparse
import pefile  # type: ignore
import struct
from typing import List

from bemani.protocol import Node
from bemani.utils.responsegen import generate_lines


def parse_psmap(data: bytes, offset: str, rootname: str) -> Node:
    pe = pefile.PE(data=data, fast_load=True)
    root = Node.void(rootname)
    base = int(offset, 16)

    def virtual_to_physical(offset: int) -> int:
        for section in pe.sections:
            start = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.PointerToRawData
        raise Exception(f'Couldn\'t find raw offset for virtual offset 0x{offset:08x}')

    if base >= pe.OPTIONAL_HEADER.ImageBase:
        # Assume this is virtual
        base = virtual_to_physical(base)

    def read_string(offset: int) -> str:
        # First, translate load offset in memory to disk offset
        offset = virtual_to_physical(offset)

        # Now, grab bytes until we're null-terminated
        bytestring = []
        while data[offset] != 0:
            bytestring.append(data[offset])
            offset = offset + 1

        # Its shift-jis encoded, so decode it now
        return bytes(bytestring).decode('shift_jisx0213')

    # For recursing into nodes
    saved_root: List[Node] = []
    saved_loc: List[int] = []

    while True:
        if hex(pe.FILE_HEADER.Machine) == '0x8664':  # 64 bit
            chunk = data[base:(base + 24)]
            base = base + 24

            (nodetype, mandatory, outoffset, width, nameptr, defaultptr) = struct.unpack('<BBHIQQ', chunk)
        else:  # 32 bit
            chunk = data[base:(base + 16)]
            base = base + 16

            (nodetype, mandatory, outoffset, width, nameptr, defaultptr) = struct.unpack('<BBHIII', chunk)

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
            if name.index('#') >= 0:
                name = name[:name.index('#')]
        except ValueError:
            pass

        if nodetype == 0x01:
            # This is a void node, so we should handle by recursing
            node = Node.void(name)
            root.add_child(node)

            # Recurse here
            saved_root.append(root)

            if defaultptr != 0:
                saved_loc.append(base)
                base = virtual_to_physical(defaultptr)
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
            node = Node.string(name, '')
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
            if name[-1] != '@':
                raise Exception(f'Attribute name {name} expected to end with @')
            root.set_attribute(name[:-1], '')
            continue
        else:
            raise Exception(f'Unimplemented node type 0x{nodetype:02x}')

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
        help="Hex offset into the file.",
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
        help="Root node name.",
        type=str,
        default="root",
    )
    args = parser.parse_args()

    fp = open(args.file, 'rb')
    data = fp.read()
    fp.close()

    layout = parse_psmap(data, args.offset, args.root)
    # Walk through, outputting each node and attaching it to its parent
    code = '\n'.join(generate_lines(layout, {}))

    if args.outfile == '-':
        print(code)
    else:
        with open(args.outfile, mode="a") as outfp:
            outfp.write(code)
            outfp.close


if __name__ == '__main__':
    main()
