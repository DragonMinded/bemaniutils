import argparse
import os

from bemani.format import TwoDX


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to extract/build 2dx files.")
    parser.add_argument(
        "file",
        help="2dx file to extract/build.",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--directory",
        help="Directory to extract to. Specify this parameter if you want to extract an existing 2dx file.",
        default=None,
    )
    parser.add_argument(
        "-w",
        "--wavfile",
        help=(
            "ADPCM wave file to add to a new or existing archive. Specify this parameter to update an "
            "existing 2dx file with a new wav file or build a new archive containing a particular wav file. "
            "Note that you can specify this parameter multiple times to bundle multiple wav files into one "
            "archive."
        ),
        action="append",
        default=[],
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Name of the archive when creating a new 2dx file from scratch.",
        default=None,
    )
    args = parser.parse_args()

    if args.directory is not None:
        root = args.directory
        if root[-1] != "/":
            root = root + "/"
        root = os.path.realpath(root)

        rfp = open(args.file, "rb")
        data = rfp.read()
        rfp.close()

        twodx = TwoDX(data)

        for fn in twodx.filenames:
            print(f"Extracting {fn} to disk...")
            realfn = os.path.join(root, fn)
            dirof = os.path.dirname(realfn)
            os.makedirs(dirof, exist_ok=True)
            with open(realfn, "wb") as wfp:
                wfp.write(twodx.read_file(fn))
    elif len(args.wavfile) > 0:
        try:
            rfp = open(args.file, "rb")
            data = rfp.read()
            rfp.close()

            twodx = TwoDX(data)
        except FileNotFoundError:
            twodx = TwoDX()
            if args.name is not None:
                twodx.set_name(args.name)
            else:
                twodx.set_name(os.path.splitext(os.path.basename(args.file))[0])

        for fn in args.wavfile:
            rfp = open(fn, "rb")
            data = rfp.read()
            rfp.close()

            twodx.write_file(os.path.basename(fn), data)

        wfp = open(args.file, "wb")
        wfp.write(twodx.get_new_data())
        wfp.close()
    else:
        raise Exception("Please provide either a directory to extract to, or a wav file to build into a 2dx file!")


if __name__ == "__main__":
    main()
