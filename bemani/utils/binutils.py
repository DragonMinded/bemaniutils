import argparse
import sys

from bemani.protocol.binary import BinaryEncoding


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility to convert binxml files to their XML representation."
    )
    parser.add_argument(
        "-i",
        "--infile",
        help="File containing an XML or binary node structure. Use - for stdin.",
        type=str,
        default=None,
        required=True,
    )
    args = parser.parse_args()

    if args.infile == "-":
        # Load from stdin
        packet = sys.stdin.buffer.read()
    else:
        with open(args.infile, mode="rb") as myfile:
            packet = myfile.read()
            myfile.close()

    benc = BinaryEncoding()
    filexml = benc.decode(packet)
    print(filexml)


if __name__ == "__main__":
    main()
