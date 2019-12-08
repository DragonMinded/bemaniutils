import argparse
import pefile  # type: ignore
import struct


def parse_struct(data: bytes, startaddr: str, endaddr: str, fmt: str) -> None:
    pe = pefile.PE(data=data, fast_load=True)
    start: int = int(startaddr, 16)
    end: int = int(endaddr, 16)

    def virtual_to_physical(offset: int) -> int:
        for section in pe.sections:
            start = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.PointerToRawData
        raise Exception('Couldn\'t find raw offset for virtual offset 0x{:08x}'.format(offset))

    if start >= pe.OPTIONAL_HEADER.ImageBase:
        # Assume this is virtual
        start = virtual_to_physical(start)

    if end >= pe.OPTIONAL_HEADER.ImageBase:
        # Assume this is virtual
        end = virtual_to_physical(end)

    size: int = struct.calcsize(fmt)

    while start < end:
        chunk = data[start:(start + size)]
        start = start + size

        print(list(struct.unpack(fmt, chunk)))


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to print structs out of a DLL.")
    parser.add_argument(
        "--file",
        help="DLL file to extract from.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--start",
        help="Hex offset into the file we should start at.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--end",
        help="Hex offset into the file we should go until.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--format",
        help="Python struct format we should print using.",
        type=str,
        default=None,
        required=True,
    )
    args = parser.parse_args()

    fp = open(args.file, 'rb')
    data = fp.read()
    fp.close()

    parse_struct(data, args.start, args.end, args.format)


if __name__ == '__main__':
    main()
