import argparse
import os

from typing import Optional

from bemani.format import IFS


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to extract IFS files.")
    parser.add_argument(
        "file",
        help="IFS file to extract.",
        type=str,
    )
    parser.add_argument(
        "-d",
        "--directory",
        help="Directory to extract to. Defaults to current directroy.",
        default=".",
    )
    parser.add_argument(
        "--convert-xml-files",
        help="Convert xml files that are in binary to readable text.",
        action="store_true",
    )
    parser.add_argument(
        "--convert-texture-files",
        help="Convert texture files that are in game-format to PNG files.",
        action="store_true",
    )
    args = parser.parse_args()

    root = args.directory
    if root[-1] != "/":
        root = root + "/"
    root = os.path.realpath(root)

    fileroot = os.path.dirname(os.path.realpath(args.file))

    def load_ifs(fname: str, root: bool = False) -> Optional[IFS]:
        fname = os.path.join(fileroot, fname)
        if os.path.isfile(fname):
            fp = open(fname, "rb")
            data = fp.read()
            fp.close()

            return IFS(
                data,
                decode_binxml=root and args.convert_xml_files,
                decode_textures=root and args.convert_texture_files,
                keep_hex_names=not root,
                reference_loader=load_ifs,
            )
        else:
            return None

    ifs = load_ifs(args.file, root=True)
    if ifs is None:
        raise Exception(f"Couldn't locate file {args.file}!")

    for fn in ifs.filenames:
        print(f"Extracting {fn} to disk...")
        realfn = os.path.join(root, fn)
        dirof = os.path.dirname(realfn)
        os.makedirs(dirof, exist_ok=True)
        with open(realfn, "wb") as fp:
            fp.write(ifs.read_file(fn))


if __name__ == "__main__":
    main()
