import argparse
import os

from bemani.format import ARC


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to extract ARC files.")
    parser.add_argument(
        "file",
        help="ARC file to extract.",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--directory",
        help="Directory to extract to. Defaults to current directory.",
        default=".",
    )
    parser.add_argument(
        "-l",
        "--list-only",
        action="store_true",
        help="Print files but do not extract them.",
    )
    args = parser.parse_args()

    root = args.directory
    if root[-1] != "/":
        root = root + "/"
    root = os.path.realpath(root)

    rfp = open(args.file, "rb")
    data = rfp.read()
    rfp.close()

    arc = ARC(data)
    for fn in arc.filenames:
        if args.list_only:
            print(fn)
        else:
            print(f"Extracting {fn} to disk...")
            realfn = os.path.join(root, fn)
            dirof = os.path.dirname(realfn)
            os.makedirs(dirof, exist_ok=True)
            with open(realfn, "wb") as wfp:
                wfp.write(arc.read_file(fn))


if __name__ == "__main__":
    main()
