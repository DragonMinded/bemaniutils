#! /usr/bin/env python3
import argparse
import io
import json
import math
import os
import os.path
import sys
import textwrap
from PIL import Image, ImageDraw
from typing import Any, Dict, List, Optional, Tuple, TypeVar

from bemani.format import TDXT


def extract_texture(
    fname: str,
    output_fname: Optional[str],
) -> int:
    with open(fname, "rb") as bfp:
        tdxt = TDXT.fromBytes(bfp.read())

    if output_fname is None:
        output_fname = os.path.splitext(os.path.abspath(fname))[0] + ".png"

    if not output_fname.lower().endswith(".png"):
        raise Exception("Invalid output file format!")

    # Actually place the files down.
    output_dir = os.path.dirname(os.path.abspath(output_fname))
    os.makedirs(output_dir, exist_ok=True)

    print(f"Extracting texture from {os.path.abspath(fname)} to {os.path.abspath(output_fname)}")
    with open(output_fname, "wb") as bfp:
        tdxt.img.save(bfp, format="PNG")

    return 0


def update_texture(
    fname: str,
    input_fname: str,
) -> int:
    with open(fname, "rb") as bfp:
        tdxt = TDXT.fromBytes(bfp.read())

    if not input_fname.lower().endswith(".png"):
        raise Exception("Invalid output file format!")

    with open(input_fname, "rb") as bfp:
        img = Image.open(io.BytesIO(bfp.read()))

    tdxt.img = img

    print(f"Updating texture in {os.path.abspath(fname)} from {os.path.abspath(input_fname)}")
    with open(fname, "wb") as bfp:
        bfp.write(tdxt.toBytes())

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Konami TDXT graphic file unpacker/repacker."
    )
    subparsers = parser.add_subparsers(help="Action to take", dest="action")

    unpack_parser = subparsers.add_parser(
        "unpack",
        help="Unpack texture data into a PNG file.",
    )
    unpack_parser.add_argument(
        "infile",
        metavar="INFILE",
        help="The TDXT container to unpack the texture from.",
    )
    unpack_parser.add_argument(
        "outfile",
        metavar="OUTFILE",
        nargs="?",
        default=None,
        help="The PNG file to unpack the texture to.",
    )

    update_parser = subparsers.add_parser(
        "update",
        help="Update texture data from a PNG file.",
    )
    update_parser.add_argument(
        "outfile",
        metavar="OUTFILE",
        help="The TDXT container to update the texture to, must already exist.",
    )
    update_parser.add_argument(
        "infile",
        metavar="INFILE",
        help="The PNG file to update the texture from.",
    )

    args = parser.parse_args()

    if args.action == "unpack":
        return extract_texture(
            args.infile,
            args.outfile,
        )
    elif args.action == "update":
        return update_texture(
            args.outfile,
            args.infile,
        )
    else:
        raise Exception(f"Invalid action {args.action}!")


if __name__ == "__main__":
    sys.exit(main())
