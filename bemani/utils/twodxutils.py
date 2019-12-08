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
        help="Directory to extract to.",
        default=None,
    )
    parser.add_argument(
        "-w",
        "--wavfile",
        help="ADPCM wave file to add to archive.",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Name of the archive when updating.",
        default=None,
    )
    args = parser.parse_args()

    if args.directory is not None:
        root = args.directory
        if root[-1] != '/':
            root = root + '/'
        root = os.path.realpath(root)

        fp = open(args.file, 'rb')
        data = fp.read()
        fp.close()

        twodx = TwoDX(data)

        for fn in twodx.filenames:
            print('Extracting {} to disk...'.format(fn))
            realfn = os.path.join(root, fn)
            dirof = os.path.dirname(realfn)
            os.makedirs(dirof, exist_ok=True)
            with open(realfn, 'wb') as fp:
                fp.write(twodx.read_file(fn))

    if len(args.wavfile) > 0:
        try:
            fp = open(args.file, 'rb')
            data = fp.read()
            fp.close()

            twodx = TwoDX(data)
        except FileNotFoundError:
            twodx = TwoDX()
            if args.name is not None:
                twodx.set_name(args.name)
            else:
                twodx.set_name(os.path.splitext(os.path.basename(args.file))[0])

        for fn in args.wavfile:
            fp = open(fn, 'rb')
            data = fp.read()
            fp.close()

            twodx.write_file(os.path.basename(fn), data)

        fp = open(args.file, 'wb')
        fp.write(twodx.get_new_data())
        fp.close()


if __name__ == '__main__':
    main()
