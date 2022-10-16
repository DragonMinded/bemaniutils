import argparse
import struct
import sys
from typing import Optional, Tuple, List, Any

from bemani.common import PEFile


class LineNumber:
    def __init__(self, offset: int, hex: bool) -> None:
        self.offset = offset
        self.hex = hex

    def toStr(self, lineno: int) -> str:
        if self.hex:
            return str(hex(self.offset + lineno))
        else:
            return str(self.offset + lineno)


class StructPrinter:
    def __init__(self, pe: PEFile, default_encoding: str = "ascii") -> None:
        self.default_encoding = default_encoding
        self.pe = pe

    def parse_format_spec(self, fmt: str) -> Tuple[str, List[Any]]:
        prefix: str = ""
        cur_accum: str = ""
        specs: List[Any] = []
        in_prefix: bool = True
        in_dereference: bool = False
        parens: int = 0

        for c in fmt:
            if in_prefix:
                # Remember byte ordering prefix.
                if c in ["@", "=", "<", ">", "!"]:
                    prefix += c
                    continue
                else:
                    in_prefix = False

            if c == "*":
                if parens == 0:
                    # Track if we're in a dereference section.
                    if not in_dereference:
                        in_dereference = True
                        if cur_accum:
                            raise Exception(
                                "Cannot have dereference marker in middle of specifier!"
                            )
                    else:
                        # Double-indirect dereference.
                        cur_accum += c
                else:
                    # Just add it, its part of a subsection.
                    cur_accum += c
                continue

            if c == "(":
                # Clump together format specs inside parens.
                if not in_dereference:
                    raise Exception("Cannot have parenthesis in middle of specifier!")
                if parens > 0:
                    cur_accum += c

                parens += 1
                continue

            if c == ")":
                # If we hit the end of a paren, we gotta recursively parse.
                if not in_dereference:
                    raise Exception("Cannot have parenthesis in middle of specifier!")
                parens -= 1
                if parens > 0:
                    cur_accum += c
                else:
                    # Parse the accumulated data as its own format spec.
                    _, subspec = self.parse_format_spec(cur_accum)
                    cur_accum = ""
                    in_dereference = False
                    specs.append(subspec)

                continue

            # If we have either an integer prefix, or an offset prefix, accumulate here.
            if (
                c.isdigit()
                or c in "+-"
                or (c in "xabcdefABCDEF" and ("+" in cur_accum or "-" in cur_accum))
            ):
                cur_accum += c
                continue

            if c == "&":
                if cur_accum:
                    raise Exception(
                        "Hex specifier should be at beginning of specifier!"
                    )
                cur_accum += c
                continue

            cur_accum += c

            # If we're dereferencing, still do the subparse even though its only one thing.
            if parens == 0:
                if in_dereference:
                    _, subspec = self.parse_format_spec(cur_accum)
                    specs.append(subspec)
                    in_dereference = False
                else:
                    specs.append(cur_accum)

                cur_accum = ""

        return prefix, specs

    def parse_struct(
        self, startaddr: str, endaddr: str, countstr: str, fmt: str
    ) -> List[Any]:
        start: int = int(startaddr, 16)
        end: Optional[int] = int(endaddr, 16) if endaddr is not None else None
        count: Optional[int] = (
            int(countstr, 16 if "0x" in countstr else 10)
            if countstr is not None
            else None
        )

        if end is None and count is None:
            raise Exception("Can't handle endless structures!")
        if end is not None and count is not None:
            raise Exception("Can't handle providing two ends!")

        if self.pe.is_virtual(start):
            # Assume this is virtual
            start = self.pe.virtual_to_physical(start)

        if end is not None and self.pe.is_virtual(end):
            # Assume this is virtual
            end = self.pe.virtual_to_physical(end)

        # Parse out any dereference instructions.
        prefix, specs = self.parse_format_spec(fmt)

        return self.__parse_struct(start, end, count, prefix, specs)

    def __parse_struct(
        self,
        start: int,
        end: Optional[int],
        count: Optional[int],
        prefix: str,
        specs: List[Any],
    ) -> List[Any]:
        # Now, parse out each chunk.
        output = []
        offset = start
        while True:
            if end is not None:
                if offset >= end:
                    break
            if count is not None:
                if count <= 0:
                    break
                count -= 1

            line: List[Any] = []
            for spec in specs:
                if isinstance(spec, str):
                    if spec[0] == "&":
                        dohex = True
                        spec = spec[1:]
                    else:
                        dohex = False

                    if spec[-1] == "#":
                        if len(spec) > 1:
                            if spec[0] not in "+-":
                                raise Exception(
                                    "Line number offsets must include a '+' or '-' prefix!"
                                )
                            val = int(spec[:-1], 16 if "0x" in spec else 10)
                        else:
                            val = 0
                        line.append(LineNumber(val, dohex))
                    elif spec == "z":
                        # Null-terminated string
                        bs = b""
                        while self.pe.data[offset : (offset + 1)] != b"\x00":
                            bs += self.pe.data[offset : (offset + 1)]
                            offset += 1
                        # Advance past null byte
                        offset += 1

                        # Hex makes no sense here
                        if dohex:
                            raise Exception("Cannot display string as hex!")
                        line.append(bs.decode(self.default_encoding))
                    else:
                        size = struct.calcsize(prefix + spec)
                        chunk = self.pe.data[offset : (offset + size)]
                        if spec != "x":
                            if dohex:
                                line.append(hex(struct.unpack(prefix + spec, chunk)[0]))
                            else:
                                line.append(struct.unpack(prefix + spec, chunk)[0])
                        offset += size
                else:
                    if self.pe.is_64bit():
                        chunk = self.pe.data[offset : (offset + 8)]
                        pointer = struct.unpack(prefix + "Q", chunk)[0]
                        offset += 8
                    else:
                        chunk = self.pe.data[offset : (offset + 4)]
                        pointer = struct.unpack(prefix + "I", chunk)[0]
                        offset += 4

                    # Resolve the physical address of this pointer, trick the substructure into
                    # parsing only one iteration.
                    if pointer == 0x0:
                        # Null pointer
                        line.append(None)
                    else:
                        pointer = self.pe.virtual_to_physical(pointer)
                        subparse = self.__parse_struct(
                            pointer, pointer + 1, None, prefix, spec
                        )
                        if len(subparse) != 1:
                            raise Exception("Logic error!")
                        line.append(subparse[0])

            output.append(line)

        return output


def main() -> int:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="A utility to print structs out of a DLL.",
        epilog=(
            """
Some examples of valid format specifiers and what they do are as follows:

*h = Decodes an array of short pointers, decoding the resulting shorts for each pointer in the array.

*(hbb) = Decodes an array of pointers to a structure containing a short and two bytes, decoding that short and both bytes for each entry in the array.

*z = Decodes an array null-terminated string pointers.

Ih&h = Decodes an array of structures containing an unsigned integer and two shorts, displaying the second short in hex instead of decimal.

#I = Decodes an array of unsigned integers, displaying the array entry number and the integer.

+64#h = Decodes an array of shorts, displaying the array entry number starting at 64 and the integer.

*z&+0x200# = Decodes an array of null-terminated string pointers, displaying the array entry number in hex starting at 0x200 and string. Broken down, it has the following parts:
    *z = Dereference the current value (*) and treat that integer as a pointer to a null-terminated string (z).
    &+0x200# = Print the current line number (#), offset by the value 0x200 (+0x200) as a hex number (&).
"""
        ),
    )
    parser.add_argument(
        "--file",
        help="DLL file to extract from.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--start",
        help="Hex offset into the file we should start at. This can be specified as either a raw offset into the DLL or as a virtual offset.",
        type=str,
        default=None,
        required=True,
    )
    parser.add_argument(
        "--end",
        help="Hex offset into the file we should go until. Alternatively you can use --count and the end offset will be calclated based on the start and format size.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--count",
        help="Number of entries to parse, as a decimal or hex integer. Alternatively you can use --end and the count will be calculated based on the start, end and format size.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--encoding",
        help="Encoding to use for strings, such as 'ascii', 'utf-8' or 'shift-jis'.",
        default="ascii",
        type=str,
    )
    parser.add_argument(
        "--format",
        help=(
            "Python struct format we should print using. See https://docs.python.org/3/library/struct.html "
            "for details. Additionally, prefixing a format specifier with * allows dereferencing pointers. "
            "Surround a chunk of format specifiers with parenthesis to dereference structures. Note that "
            "structures can be arbitrarily nested to decode complex data types. For ease of unpacking C string "
            'pointers, the specifier "z" is recognzied to mean null-terminated string. A & preceeding a '
            "format specifier means that we should convert to hex before displaying. For the ease of decoding "
            'enumerations, the specifier "#" is recognized to mean entry number. You can provide it an '
            'offset value such as "+20#" to start at a certain number.'
        ),
        type=str,
        default=None,
        required=True,
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

    if args.end is None and args.count is None:
        print("You must specify either an --end or a --count!", file=sys.stderr)
        return 1
    if args.end is not None and args.count is not None:
        print("You cannot specify both an --end and a --count!", file=sys.stderr)
        return 1

    fp = open(args.file, "rb")
    data = fp.read()
    fp.close()

    def __str(obj: object, lineno: int) -> str:
        if obj is None:
            return "NULL"
        elif isinstance(obj, LineNumber):
            return obj.toStr(lineno)
        elif isinstance(obj, list):
            if len(obj) == 1:
                return __str(obj[0], lineno)
            else:
                return f"({', '.join(__str(o, lineno) for o in obj)})"
        else:
            return repr(obj)

    pe = PEFile(data)

    # If asked, attempt to emulate code which dynamically constructs the structure
    # we're about to parse.
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

    printer = StructPrinter(pe, default_encoding=args.encoding)
    lines = printer.parse_struct(args.start, args.end, args.count, args.format)
    for i, line in enumerate(lines):
        print(", ".join(__str(entry, i) for entry in line))

    return 0


if __name__ == "__main__":
    sys.exit(main())
