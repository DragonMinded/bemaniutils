#! /usr/bin/env python3
import argparse
import json
import os
import os.path
import sys
import textwrap
from PIL import Image, ImageDraw  # type: ignore
from typing import Any, Dict

from bemani.format.afp import AFPFile


def main() -> int:
    parser = argparse.ArgumentParser(description="Konami AFP graphic file unpacker/repacker")
    subparsers = parser.add_subparsers(help='Action to take', dest='action')

    extract_parser = subparsers.add_parser('extract', help='Extract relevant textures from file')
    extract_parser.add_argument(
        "file",
        metavar="FILE",
        help="The file to extract",
    )
    extract_parser.add_argument(
        "dir",
        metavar="DIR",
        help="Directory to extract to",
    )
    extract_parser.add_argument(
        "-p",
        "--pretend",
        action="store_true",
        help="Pretend to extract instead of extracting",
    )
    extract_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )
    extract_parser.add_argument(
        "-r",
        "--write-raw",
        action="store_true",
        help="Always write raw texture files",
    )
    extract_parser.add_argument(
        "-m",
        "--write-mappings",
        action="store_true",
        help="Write mapping files to disk",
    )
    extract_parser.add_argument(
        "-g",
        "--generate-mapping-overlays",
        action="store_true",
        help="Generate overlay images showing mappings",
    )
    extract_parser.add_argument(
        "-s",
        "--split-textures",
        action="store_true",
        help="Split textures into individual sprites",
    )

    update_parser = subparsers.add_parser('update', help='Update relevant textures in a file from a directory')
    update_parser.add_argument(
        "file",
        metavar="FILE",
        help="The file to update",
    )
    update_parser.add_argument(
        "dir",
        metavar="DIR",
        help="Directory to update from",
    )
    update_parser.add_argument(
        "-p",
        "--pretend",
        action="store_true",
        help="Pretend to update instead of updating",
    )
    update_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    print_parser = subparsers.add_parser('print', help='Print the file contents as a JSON dictionary')
    print_parser.add_argument(
        "file",
        metavar="FILE",
        help="The file to print",
    )

    args = parser.parse_args()

    if args.action == "extract":
        if args.split_textures:
            if args.write_raw:
                raise Exception("Cannot write raw textures when splitting sprites!")
            if args.generate_mapping_overlays:
                raise Exception("Cannot generate mapping overlays when splitting sprites!")

        with open(args.file, "rb") as bfp:
            afpfile = AFPFile(bfp.read(), verbose=args.verbose)

        # Actually place the files down.
        os.makedirs(args.dir, exist_ok=True)

        if not args.split_textures:
            for texture in afpfile.textures:
                filename = os.path.join(args.dir, texture.name)

                if texture.img:
                    if args.pretend:
                        print(f"Would write {filename}.png texture...")
                    else:
                        print(f"Writing {filename}.png texture...")
                        with open(f"{filename}.png", "wb") as bfp:
                            texture.img.save(bfp, format='PNG')

                if not texture.img or args.write_raw:
                    if args.pretend:
                        print(f"Would write {filename}.raw texture...")
                    else:
                        print(f"Writing {filename}.raw texture...")
                        with open(f"{filename}.raw", "wb") as bfp:
                            bfp.write(texture.raw)

                    if args.pretend:
                        print(f"Would write {filename}.xml texture info...")
                    else:
                        print(f"Writing {filename}.xml texture info...")
                        with open(f"{filename}.xml", "w") as sfp:
                            sfp.write(textwrap.dedent(f"""
                                <info>
                                    <width>{texture.width}</width>
                                    <height>{texture.height}</height>
                                    <type>{hex(texture.fmt)}</type>
                                    <raw>{filename}.raw</raw>
                                </info>
                            """).strip())

        if args.write_mappings:
            if not args.split_textures:
                for i, name in enumerate(afpfile.regionmap.entries):
                    if i < 0 or i >= len(afpfile.texture_to_region):
                        raise Exception(f"Out of bounds region {i}")
                    region = afpfile.texture_to_region[i]
                    texturename = afpfile.texturemap.entries[region.textureno]
                    filename = os.path.join(args.dir, name)

                    if args.pretend:
                        print(f"Would write {filename}.xml region information...")
                    else:
                        print(f"Writing {filename}.xml region information...")
                        with open(f"{filename}.xml", "w") as sfp:
                            sfp.write(textwrap.dedent(f"""
                                <info>
                                    <left>{region.left}</left>
                                    <top>{region.top}</top>
                                    <right>{region.right}</right>
                                    <bottom>{region.bottom}</bottom>
                                    <texture>{texturename}</texture>
                                </info>
                            """).strip())

            if afpfile.fontdata is not None:
                filename = os.path.join(args.dir, "fontinfo.xml")

                if args.pretend:
                    print(f"Would write {filename} font information...")
                else:
                    print(f"Writing {filename} font information...")
                    with open(filename, "w") as sfp:
                        sfp.write(str(afpfile.fontdata))

        if args.generate_mapping_overlays:
            overlays: Dict[str, Any] = {}

            for i, name in enumerate(afpfile.regionmap.entries):
                if i < 0 or i >= len(afpfile.texture_to_region):
                    raise Exception(f"Out of bounds region {i}")
                region = afpfile.texture_to_region[i]
                texturename = afpfile.texturemap.entries[region.textureno]

                if texturename not in overlays:
                    for texture in afpfile.textures:
                        if texture.name == texturename:
                            overlays[texturename] = Image.new(
                                'RGBA',
                                (texture.width, texture.height),
                                (0, 0, 0, 0),
                            )
                            break
                    else:
                        raise Exception(f"Couldn't find texture {texturename}")

                draw = ImageDraw.Draw(overlays[texturename])
                draw.rectangle(
                    ((region.left // 2, region.top // 2), (region.right // 2, region.bottom // 2)),
                    fill=(0, 0, 0, 0),
                    outline=(255, 0, 0, 255),
                    width=1,
                )
                draw.text(
                    (region.left // 2, region.top // 2),
                    name,
                    fill=(255, 0, 255, 255),
                )

            for name, img in overlays.items():
                filename = os.path.join(args.dir, name) + "_overlay.png"
                if args.pretend:
                    print(f"Would write {filename} overlay...")
                else:
                    print(f"Writing {filename} overlay...")
                    with open(filename, "wb") as bfp:
                        img.save(bfp, format='PNG')

        if args.split_textures:
            textures: Dict[str, Any] = {}
            announced: Dict[str, bool] = {}

            for i, name in enumerate(afpfile.regionmap.entries):
                if i < 0 or i >= len(afpfile.texture_to_region):
                    raise Exception(f"Out of bounds region {i}")
                region = afpfile.texture_to_region[i]
                texturename = afpfile.texturemap.entries[region.textureno]

                if texturename not in textures:
                    for tex in afpfile.textures:
                        if tex.name == texturename:
                            textures[texturename] = tex
                            break
                    else:
                        raise Exception("Could not find texture {texturename} to split!")

                if textures[texturename].img:
                    # Grab the location in the image, save it out to a new file.
                    filename = f"{texturename}_{name}.png"
                    filename = os.path.join(args.dir, filename)

                    if args.pretend:
                        print(f"Would write {filename} sprite...")
                    else:
                        print(f"Writing {filename} sprite...")
                        sprite = textures[texturename].img.crop(
                            (region.left // 2, region.top // 2, region.right // 2, region.bottom // 2),
                        )
                        with open(filename, "wb") as bfp:
                            sprite.save(bfp, format='PNG')
                else:
                    if not announced.get(texturename, False):
                        print(f"Cannot extract sprites from {texturename} because it is not a supported format!")
                        announced[texturename] = True

    if args.action == "update":
        # First, parse the file out
        with open(args.file, "rb") as bfp:
            afpfile = AFPFile(bfp.read(), verbose=args.verbose)

        # Now, find any PNG files that match texture names.
        for texture in afpfile.textures:
            filename = os.path.join(args.dir, texture.name) + ".png"

            if os.path.isfile(filename):
                print(f"Updating {texture.name} from {filename}...")

                with open(filename, "rb") as bfp:
                    afpfile.update_texture(texture.name, bfp.read())

        # Now, find any PNG files that match a specific sprite.
        for i, spritename in enumerate(afpfile.regionmap.entries):
            if i < 0 or i >= len(afpfile.texture_to_region):
                raise Exception(f"Out of bounds region {i}")
            region = afpfile.texture_to_region[i]
            texturename = afpfile.texturemap.entries[region.textureno]

            # Grab the location in the image to see if it exists.
            filename = f"{texturename}_{spritename}.png"
            filename = os.path.join(args.dir, filename)

            if os.path.isfile(filename):
                print(f"Updating {texturename} sprite piece {spritename} from {filename}...")

                with open(filename, "rb") as bfp:
                    afpfile.update_sprite(texturename, spritename, bfp.read())

        # Now, write out the updated file
        if args.pretend:
            print(f"Would write {args.file}...")
            afpfile.unparse()
        else:
            print(f"Writing {args.file}...")
            data = afpfile.unparse()
            with open(args.file, "wb") as bfp:
                bfp.write(data)

    if args.action == "print":
        # First, parse the file out
        with open(args.file, "rb") as bfp:
            afpfile = AFPFile(bfp.read(), verbose=False)

        # Now, print it
        print(json.dumps(afpfile.as_dict(), sort_keys=True, indent=4))

    return 0


if __name__ == "__main__":
    sys.exit(main())
