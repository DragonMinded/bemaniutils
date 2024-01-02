import argparse
import os
from react.jsx import JSXTransformer  # type: ignore

from bemani.frontend.app import polyfill_fragments


SCRIPT_PATH: str = os.path.dirname(os.path.realpath(__file__))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prebuild all JSX files so they can be statically served by nginx or similar."
    )
    parser.add_argument(
        "-d",
        "--output-directory",
        help="Output directory for the JSX files.",
        type=str,
        default="./build/jsx",
    )
    args = parser.parse_args()

    outdir = os.path.abspath(args.output_directory)
    print(f"Compiling all files into {outdir}...")
    os.makedirs(outdir, exist_ok=True)

    basedir = os.path.abspath(os.path.join(SCRIPT_PATH, "../frontend/static"))
    if not basedir.endswith("/"):
        basedir += "/"

    dirs = [basedir]
    files = []
    while dirs:
        curdir = dirs.pop()
        for dirpath, dnames, fnames in os.walk(curdir):
            for fname in fnames:
                if fname.endswith(".react.js"):
                    fullpath = os.path.join(dirpath, fname)
                    if fullpath.startswith(basedir):
                        files.append(fullpath[len(basedir) :])
            for dname in dnames:
                if dname == "." or dname == "..":
                    continue
                dirs.append(os.path.join(dirpath, dname))

    transformer = JSXTransformer()
    for fname in sorted(list(set(files))):
        print(f"Building {fname}...")
        infile = os.path.join(basedir, fname)
        outfile = os.path.join(outdir, fname)
        os.makedirs(os.path.dirname(outfile), exist_ok=True)

        with open(infile, "rb") as f:
            jsx = transformer.transform_string(polyfill_fragments(f.read().decode("utf-8"))).encode("utf-8")

        print(f"Writing {outfile}...")
        with open(outfile, "wb") as f:
            f.write(jsx)


if __name__ == "__main__":
    main()
