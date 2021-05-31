#! /usr/bin/env python3
import argparse
import io
import json
import math
import os
import os.path
import sys
import textwrap
from PIL import Image, ImageDraw  # type: ignore
from typing import Any, Dict, List, Optional

from bemani.format.afp import TXP2File, Shape, SWF, Frame, Tag, AP2DoActionTag, AP2PlaceObjectTag, AP2DefineSpriteTag, AFPRenderer, Color, Matrix
from bemani.format import IFS


def write_bytecode(swf: SWF, directory: str, *, verbose: bool) -> None:
    # Actually place the files down.
    os.makedirs(directory, exist_ok=True)

    # Buffer for where the decompiled data goes.
    buff: List[str] = []
    lut: Dict[str, int] = {}

    def bytecode_from_frames(frames: List[Frame]) -> None:
        for frame in frames:
            for tag in frame.imported_tags:
                if tag.init_bytecode:
                    buff.append(tag.init_bytecode.decompile(verbose=verbose))

    def bytecode_from_tags(tags: List[Tag]) -> None:
        for tag in tags:
            if isinstance(tag, AP2DoActionTag):
                buff.append(tag.bytecode.decompile(verbose=verbose))
            elif isinstance(tag, AP2PlaceObjectTag):
                for _, triggers in tag.triggers.items():
                    for trigger in triggers:
                        buff.append(trigger.decompile(verbose=verbose))
            elif isinstance(tag, AP2DefineSpriteTag):
                lut.update(tag.labels)
                bytecode_from_frames(tag.frames)
                bytecode_from_tags(tag.tags)

    lut.update(swf.labels)
    bytecode_from_frames(swf.frames)
    bytecode_from_tags(swf.tags)

    # If we have frame labels, put them at the top as global defines.
    if lut:
        buff = [
            os.linesep.join([
                '// Defined frame labels from SWF container, as used for frame lookups.',
                'FRAME_LUT = {',
                *[f"    {name!r}: {frame}," for name, frame in lut.items()],
                '};',
            ]),
            *buff,
        ]

    # Now, write it out.
    filename = os.path.join(directory, swf.exported_name) + ".code"
    print(f"Writing code to {filename}...")
    with open(filename, "wb") as bfp:
        bfp.write(f"{os.linesep}{os.linesep}".join(buff).encode('utf-8'))


def parse_intlist(data: str) -> List[int]:
    ints: List[int] = []

    for chunk in data.split(","):
        chunk = chunk.strip()
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            start_int = int(start.strip())
            end_int = int(end.strip())
            ints.extend(range(start_int, end_int + 1))
        else:
            ints.append(int(chunk))

    return sorted(set(ints))


def extract_txp2(
    fname: str,
    output_dir: str,
    *,
    split_textures: bool=False,
    generate_mapping_overlays: bool=False,
    write_mappings: bool=False,
    write_raw: bool=False,
    write_binaries: bool=False,
    pretend: bool=False,
    verbose: bool=False,
) -> int:
    if split_textures:
        if write_raw:
            raise Exception("Cannot write raw textures when splitting sprites!")
        if generate_mapping_overlays:
            raise Exception("Cannot generate mapping overlays when splitting sprites!")

    with open(fname, "rb") as bfp:
        afpfile = TXP2File(bfp.read(), verbose=verbose)

    # Actually place the files down.
    os.makedirs(output_dir, exist_ok=True)

    if not split_textures:
        for texture in afpfile.textures:
            filename = os.path.join(output_dir, texture.name)

            if texture.img:
                if pretend:
                    print(f"Would write {filename}.png texture...")
                else:
                    print(f"Writing {filename}.png texture...")
                    with open(f"{filename}.png", "wb") as bfp:
                        texture.img.save(bfp, format='PNG')

            if not texture.img or write_raw:
                if pretend:
                    print(f"Would write {filename}.raw texture...")
                else:
                    print(f"Writing {filename}.raw texture...")
                    with open(f"{filename}.raw", "wb") as bfp:
                        bfp.write(texture.raw)

                if pretend:
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

    if write_mappings:
        if not split_textures:
            for i, name in enumerate(afpfile.regionmap.entries):
                if i < 0 or i >= len(afpfile.texture_to_region):
                    raise Exception(f"Out of bounds region {i}")
                region = afpfile.texture_to_region[i]
                texturename = afpfile.texturemap.entries[region.textureno]
                filename = os.path.join(output_dir, name)

                if pretend:
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
            filename = os.path.join(output_dir, "fontinfo.xml")

            if pretend:
                print(f"Would write {filename} font information...")
            else:
                print(f"Writing {filename} font information...")
                with open(filename, "w") as sfp:
                    sfp.write(str(afpfile.fontdata))

    if write_binaries:
        for i, name in enumerate(afpfile.swfmap.entries):
            swf = afpfile.swfdata[i]
            filename = os.path.join(output_dir, name)

            if pretend:
                print(f"Would write {filename}.afp SWF data...")
                print(f"Would write {filename}.bsi SWF descramble data...")
            else:
                print(f"Writing {filename}.afp SWF data...")
                with open(f"{filename}.afp", "wb") as bfp:
                    bfp.write(swf.data)
                print(f"Writing {filename}.bsi SWF descramble data...")
                with open(f"{filename}.bsi", "wb") as bfp:
                    bfp.write(swf.descramble_info)

        for i, name in enumerate(afpfile.shapemap.entries):
            shape = afpfile.shapes[i]
            filename = os.path.join(output_dir, f"{name}.geo")

            if pretend:
                print(f"Would write {filename} shape data...")
            else:
                print(f"Writing {filename} shape data...")
                with open(filename, "wb") as bfp:
                    bfp.write(shape.data)

    if generate_mapping_overlays:
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
            filename = os.path.join(output_dir, name) + "_overlay.png"
            if pretend:
                print(f"Would write {filename} overlay...")
            else:
                print(f"Writing {filename} overlay...")
                with open(filename, "wb") as bfp:
                    img.save(bfp, format='PNG')

    if split_textures:
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
                filename = os.path.join(output_dir, filename)

                if pretend:
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
    if write_bytecode:
        for swf in afpfile.swfdata:
            write_bytecode(swf, output_dir, verbose=verbose)

    return 0


def update_txp2(fname: str, update_dir: str, *, pretend: bool=False, verbose: bool=False) -> int:
    # First, parse the file out
    with open(fname, "rb") as bfp:
        afpfile = TXP2File(bfp.read(), verbose=verbose)

    # Now, find any PNG files that match texture names.
    for texture in afpfile.textures:
        filename = os.path.join(update_dir, texture.name) + ".png"

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
        filename = os.path.join(update_dir, filename)

        if os.path.isfile(filename):
            print(f"Updating {texturename} sprite piece {spritename} from {filename}...")

            with open(filename, "rb") as bfp:
                afpfile.update_sprite(texturename, spritename, bfp.read())

    # Now, write out the updated file
    if pretend:
        print(f"Would write {fname}...")
        afpfile.unparse()
    else:
        print(f"Writing {fname}...")
        data = afpfile.unparse()
        with open(fname, "wb") as bfp:
            bfp.write(data)

    return 0


def print_txp2(fname: str, *, decompile_bytecode: bool=False, verbose: bool=False) -> int:
    # First, parse the file out
    with open(fname, "rb") as bfp:
        afpfile = TXP2File(bfp.read(), verbose=verbose)

    # Now, print it
    print(json.dumps(afpfile.as_dict(decompile_bytecode=decompile_bytecode, verbose=verbose), sort_keys=True, indent=4))

    return 0


def parse_afp(afp: str, bsi: str, *, decompile_bytecode: bool=False, verbose: bool=False) -> int:
    # First, load the AFP and BSI files
    with open(afp, "rb") as bafp:
        with open(bsi, "rb") as bbsi:
            swf = SWF("<unnamed>", bafp.read(), bbsi.read())

    # Now, print it
    swf.parse(verbose=verbose)
    print(json.dumps(swf.as_dict(decompile_bytecode=decompile_bytecode, verbose=verbose), sort_keys=True, indent=4))

    return 0


def decompile_afp(afp: str, bsi: str, output_dir: str, *, decompile_bytecode: bool=False, verbose: bool=False) -> int:
    # First, load the AFP and BSI files
    with open(afp, "rb") as bafp:
        with open(bsi, "rb") as bbsi:
            swf = SWF("<unnamed>", bafp.read(), bbsi.read())

    # Now, decompile it
    swf.parse(verbose=verbose)
    write_bytecode(swf, output_dir, verbose=verbose)

    return 0


def parse_geo(geo: str, *, verbose: bool=False) -> int:
    # First, load the AFP and BSI files
    with open(geo, "rb") as bfp:
        shape = Shape("<unnamed>", bfp.read())

    # Now, print it
    shape.parse()
    if verbose:
        print(shape, file=sys.stderr)
    print(json.dumps(shape.as_dict(), sort_keys=True, indent=4))

    return 0


def load_containers(renderer: AFPRenderer, containers: List[str], *, need_extras: bool, verbose: bool) -> None:
    # This is a complicated one, as we need to be able to specify multiple
    # directories of files as well as support IFS files and TXP2 files.
    for container in containers:
        # TODO: Allow specifying individual folders and such.
        with open(container, "rb") as bfp:
            data = bfp.read()

        afpfile = None
        try:
            afpfile = TXP2File(data, verbose=verbose)
        except Exception:
            pass

        if afpfile is not None:
            if verbose:
                print(f"Loading files out of TXP2 container {container}...", file=sys.stderr)

            if need_extras:
                # First, load GE2D structures into the renderer.
                for i, name in enumerate(afpfile.shapemap.entries):
                    shape = afpfile.shapes[i]
                    renderer.add_shape(name, shape)

                    if verbose:
                        print(f"Added {name} to SWF shape library.", file=sys.stderr)

                # Now, split and load textures into the renderer.
                sheets: Dict[str, Any] = {}

                for i, name in enumerate(afpfile.regionmap.entries):
                    if i < 0 or i >= len(afpfile.texture_to_region):
                        raise Exception(f"Out of bounds region {i}")
                    region = afpfile.texture_to_region[i]
                    texturename = afpfile.texturemap.entries[region.textureno]

                    if texturename not in sheets:
                        for tex in afpfile.textures:
                            if tex.name == texturename:
                                sheets[texturename] = tex
                                break
                        else:
                            raise Exception("Could not find texture {texturename} to split!")

                    if sheets[texturename].img:
                        sprite = sheets[texturename].img.crop(
                            (region.left // 2, region.top // 2, region.right // 2, region.bottom // 2),
                        )
                        renderer.add_texture(name, sprite)

                        if verbose:
                            print(f"Added {name} to SWF texture library.", file=sys.stderr)
                    else:
                        print(f"Cannot load {name} from {texturename} because it is not a supported format!")

            # Finally, load the SWF data itself into the renderer.
            for i, name in enumerate(afpfile.swfmap.entries):
                swf = afpfile.swfdata[i]
                renderer.add_swf(name, swf)

                if verbose:
                    print(f"Added {name} to SWF library.", file=sys.stderr)

            continue

        ifsfile = None
        try:
            ifsfile = IFS(data, decode_textures=True)
        except Exception:
            pass

        if ifsfile is not None:
            if verbose:
                print(f"Loading files out of IFS container {container}...", file=sys.stderr)
            for fname in ifsfile.filenames:
                if fname.startswith(f"geo{os.sep}"):
                    if not need_extras:
                        continue

                    # Trim off directory.
                    shapename = fname[(3 + len(os.sep)):]

                    # Load file, register it.
                    fdata = ifsfile.read_file(fname)
                    shape = Shape(shapename, fdata)
                    renderer.add_shape(shapename, shape)

                    if verbose:
                        print(f"Added {shapename} to SWF shape library.", file=sys.stderr)
                elif fname.startswith(f"tex{os.sep}") and fname.endswith(".png"):
                    if not need_extras:
                        continue

                    # Trim off directory, png extension.
                    texname = fname[(3 + len(os.sep)):][:-4]

                    # Load file, register it.
                    fdata = ifsfile.read_file(fname)
                    tex = Image.open(io.BytesIO(fdata))
                    renderer.add_texture(texname, tex)

                    if verbose:
                        print(f"Added {texname} to SWF texture library.", file=sys.stderr)
                elif fname.startswith(f"afp{os.sep}"):
                    # Trim off directory, see if it has a corresponding bsi.
                    afpname = fname[(3 + len(os.sep)):]
                    bsipath = f"afp{os.sep}bsi{os.sep}{afpname}"

                    if bsipath in ifsfile.filenames:
                        afpdata = ifsfile.read_file(fname)
                        bsidata = ifsfile.read_file(bsipath)
                        flash = SWF(afpname, afpdata, bsidata)
                        renderer.add_swf(afpname, flash)

                        if verbose:
                            print(f"Added {afpname} to SWF library.", file=sys.stderr)
            continue


def list_paths(containers: List[str], *, include_frames: bool=False, include_size: bool=False, verbose: bool=False) -> int:
    renderer = AFPRenderer()
    load_containers(renderer, containers, need_extras=False, verbose=verbose)

    for path in renderer.list_paths(verbose=verbose):
        display = path
        if include_size:
            location = renderer.compute_path_size(path)
            display = f"{display} - {int(location.width)}x{int(location.height)}"
        if include_frames:
            frames = renderer.compute_path_frames(path)
            display = f"{display} - {frames} frames"
        print(display)

    return 0


def render_path(
    containers: List[str],
    path: str,
    output: str,
    *,
    disable_threads: bool = False,
    enable_anti_aliasing: bool = False,
    background_color: Optional[str] = None,
    background_image: Optional[str] = None,
    force_aspect_ratio: Optional[str] = None,
    scale_width: float = 1.0,
    scale_height: float = 1.0,
    only_depths: Optional[str] = None,
    only_frames: Optional[str] = None,
    verbose: bool = False,
) -> int:
    renderer = AFPRenderer(single_threaded=disable_threads, enable_aa=enable_anti_aliasing)
    load_containers(renderer, containers, need_extras=True, verbose=verbose)

    # Verify the correct params.
    if output.lower().endswith(".gif"):
        fmt = "GIF"
    elif output.lower().endswith(".webp"):
        fmt = "WEBP"
    elif output.lower().endswith(".png"):
        fmt = "PNG"
    else:
        raise Exception("Unrecognized file extension for output!")

    # Allow overriding background color.
    if background_color:
        colorvals = background_color.split(",")
        if len(colorvals) not in [3, 4]:
            raise Exception("Invalid color, specify a color as a comma-separated RGB or RGBA value!")

        if len(colorvals) == 3:
            colorvals.append("255")
        colorints = [int(c.strip()) for c in colorvals]
        for c in colorints:
            if c < 0 or c > 255:
                raise Exception("Color values should be between 0 and 255!")

        color = Color(*[c / 255.0 for c in colorints])
    else:
        color = None

    # Allow inserting a background image.
    if background_image:
        background = Image.open(background_image)
    else:
        background = None

    # Calculate the size of the SWF so we can apply scaling options.
    swf_location = renderer.compute_path_location(path)
    requested_width = swf_location.width
    requested_height = swf_location.height

    # Allow overriding the aspect ratio.
    if force_aspect_ratio:
        ratio = force_aspect_ratio.split(":")
        if len(ratio) != 2:
            raise Exception("Invalid aspect ratio, specify a ratio such as 16:9 or 4:3!")

        rx, ry = [float(r.strip()) for r in ratio]
        if rx <= 0 or ry <= 0:
            raise Exception("Ratio must only include positive numbers!")

        actual_ratio = rx / ry
        swf_ratio = swf_location.width / swf_location.height

        if abs(swf_ratio - actual_ratio) > 0.0001:
            new_width = actual_ratio * swf_location.height
            new_height = swf_location.width / actual_ratio

            if new_width < swf_location.width and new_height < swf_location.height:
                raise Exception("Impossible aspect ratio!")
            if new_width > swf_location.width and new_height > swf_location.height:
                raise Exception("Impossible aspect ratio!")

            # We know that one is larger and one is smaller, pick the larger.
            # This way we always stretch instead of shrinking.
            if new_width > swf_location.width:
                requested_width = new_width
            else:
                requested_height = new_height

    requested_width *= scale_width
    requested_height *= scale_height

    # Calculate the overall view matrix based on the requested width/height.
    transform = Matrix(
        a=requested_width / swf_location.width,
        b=0.0,
        c=0.0,
        d=requested_height / swf_location.height,
        tx=0.0,
        ty=0.0,
    )

    # Support rendering only certain depth planes.
    if only_depths is not None:
        requested_depths = parse_intlist(only_depths)
    else:
        requested_depths = None

    # Support rendering only certain frames.
    if only_frames is not None:
        requested_frames = parse_intlist(only_frames)
    else:
        requested_frames = None

    if fmt in ["GIF", "WEBP"]:
        # Write all the frames out in one file.
        duration = renderer.compute_path_frame_duration(path)
        images = list(
            renderer.render_path(
                path,
                verbose=verbose,
                background_color=color,
                background_image=background,
                only_depths=requested_depths,
                only_frames=requested_frames,
                movie_transform=transform,
            )
        )
        if len(images) > 0:
            with open(output, "wb") as bfp:
                images[0].save(bfp, format=fmt, save_all=True, append_images=images[1:], duration=duration, optimize=True)

            print(f"Wrote animation to {output}")
    else:
        # Write all the frames out in individual_files.
        filename = output[:-4]
        ext = output[-4:]

        # Figure out padding for the images.
        frames = renderer.compute_path_frames(path)
        if frames > 0:
            digits = f"0{int(math.log10(frames)) + 1}"

            for i, img in enumerate(
                renderer.render_path(
                    path,
                    verbose=verbose,
                    background_color=color,
                    background_image=background,
                    only_depths=requested_depths,
                    only_frames=requested_frames,
                    movie_transform=transform,
                )
            ):
                fullname = f"{filename}-{i:{digits}}{ext}"

                with open(fullname, "wb") as bfp:
                    img.save(bfp, format=fmt)

                print(f"Wrote animation frame to {fullname}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Konami AFP graphic file unpacker/repacker")
    subparsers = parser.add_subparsers(help='Action to take', dest='action')

    extract_parser = subparsers.add_parser('extract', help='Extract relevant file data and textures from a TXP2 container')
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
    extract_parser.add_argument(
        "-b",
        "--write-binaries",
        action="store_true",
        help="Write binary SWF files to disk",
    )
    extract_parser.add_argument(
        "-y",
        "--write-bytecode",
        action="store_true",
        help="Write decompiled bytecode files to disk",
    )

    update_parser = subparsers.add_parser('update', help='Update relevant textures in a TXP2 container from a directory')
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

    print_parser = subparsers.add_parser('print', help='Print the TXP2 container contents as a JSON dictionary')
    print_parser.add_argument(
        "file",
        metavar="FILE",
        help="The file to print",
    )
    print_parser.add_argument(
        "-d",
        "--decompile-bytecode",
        action="store_true",
        help="Attempt to decompile and print bytecode instead of printing the raw representation.",
    )
    print_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    parseafp_parser = subparsers.add_parser('parseafp', help='Parse a raw AFP/BSI file pair previously extracted from an IFS or TXP2 container')
    parseafp_parser.add_argument(
        "afp",
        metavar="AFPFILE",
        help="The AFP file to parse",
    )
    parseafp_parser.add_argument(
        "bsi",
        metavar="BSIFILE",
        help="The BSI file to parse",
    )
    parseafp_parser.add_argument(
        "-d",
        "--decompile-bytecode",
        action="store_true",
        help="Attempt to decompile and print bytecode instead of printing the raw representation.",
    )
    parseafp_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    decompile_parser = subparsers.add_parser('decompile', help='Decompile bytecode in a raw AFP/BSI file pair previously extracted from an IFS or TXP2 container')
    decompile_parser.add_argument(
        "afp",
        metavar="AFPFILE",
        help="The AFP file to parse",
    )
    decompile_parser.add_argument(
        "bsi",
        metavar="BSIFILE",
        help="The BSI file to parse",
    )
    decompile_parser.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        default='.',
        type=str,
        help="Directory to extract to after decompiling. Defaults to current directory.",
    )
    decompile_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    parsegeo_parser = subparsers.add_parser('parsegeo', help='Parse a raw GEO file previously extracted from an IFS or TXP2 container')
    parsegeo_parser.add_argument(
        "geo",
        metavar="GEOFILE",
        help="The GEO file to parse",
    )
    parsegeo_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    render_parser = subparsers.add_parser('render', help='Render a particular animation out of a series of SWFs')
    render_parser.add_argument(
        "container",
        metavar="CONTAINER",
        type=str,
        nargs='+',
        help="A container file to use for loading SWF data. Can be either a TXP2 or IFS container.",
    )
    render_parser.add_argument(
        "--path",
        metavar="PATH",
        type=str,
        required=True,
        help='A path to render, specified as "moviename" of the animation to render. Use the "list" command to discover paths in a file.',
    )
    render_parser.add_argument(
        "--output",
        metavar="IMAGE",
        type=str,
        default="out.gif",
        help='The output file (ending either in .gif, .webp or .png) where the render should be saved.',
    )
    render_parser.add_argument(
        "--background-color",
        type=str,
        default=None,
        help="Set the background color of the animation as a comma-separated RGB or RGBA color, overriding a default if present in the SWF.",
    )
    render_parser.add_argument(
        "--background-image",
        type=str,
        default=None,
        help="Set a background image to be placed behind the animation. Note that it will be stretched to fit the animation.",
    )
    render_parser.add_argument(
        "--only-depths",
        type=str,
        default=None,
        help="Only render objects on these depth planes. Can provide either a number or a comma-separated list of numbers, or a range such as 3-5.",
    )
    render_parser.add_argument(
        "--only-frames",
        type=str,
        default=None,
        help="Only render these frames. Can provide either a number or a comma-separated list of numbers, or a range such as 10-20.",
    )
    render_parser.add_argument(
        "--force-aspect-ratio",
        type=str,
        default=None,
        help="Force the aspect ratio of the rendered image, as a colon-separated aspect ratio such as 16:9 or 4:3.",
    )
    render_parser.add_argument(
        "--scale-width",
        type=float,
        default=1.0,
        help="Scale the width of the animation by some factor, such as 2.0 or 0.5.",
    )
    render_parser.add_argument(
        "--scale-height",
        type=float,
        default=1.0,
        help="Scale the height of the animation by some factor, such as 2.0 or 0.5.",
    )
    render_parser.add_argument(
        "--disable-threads",
        action="store_true",
        help="Disable multi-threaded rendering.",
    )
    render_parser.add_argument(
        "--enable-anti-aliasing",
        action="store_true",
        help="Enable experimental anti-aliased rendering.",
    )
    render_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    list_parser = subparsers.add_parser('list', help='List out the possible paths to render from a series of SWFs')
    list_parser.add_argument(
        "container",
        metavar="CONTAINER",
        type=str,
        nargs='+',
        help="A container file to use for loading SWF data. Can be either a TXP2 or IFS container.",
    )
    list_parser.add_argument(
        "--include-frames",
        action="store_true",
        help="Include number of frames per path in the output list.",
    )
    list_parser.add_argument(
        "--include-size",
        action="store_true",
        help="Include width/height of the path in the output list.",
    )
    list_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output",
    )

    args = parser.parse_args()

    if args.action == "extract":
        return extract_txp2(
            args.file,
            args.dir,
            split_textures=args.split_textures,
            generate_mapping_overlays=args.generate_mapping_overlays,
            write_mappings=args.write_mappings,
            write_raw=args.write_raw,
            write_binaries=args.write_binaries,
            pretend=args.pretend,
            verbose=args.verbose,
        )
    elif args.action == "update":
        return update_txp2(args.file, args.dir, pretend=args.pretend, verbose=args.verbose)
    elif args.action == "print":
        return print_txp2(args.file, decompile_bytecode=args.decompile_bytecode, verbose=args.verbose)
    elif args.action == "parseafp":
        return parse_afp(args.afp, args.bsi, decompile_bytecode=args.decompile_bytecode, verbose=args.verbose)
    elif args.action == "decompile":
        return decompile_afp(args.afp, args.bsi, args.directory, decompile_bytecode=args.decompile_bytecode, verbose=args.verbose)
    elif args.action == "parsegeo":
        return parse_geo(args.geo, verbose=args.verbose)
    elif args.action == "list":
        return list_paths(args.container, include_size=args.include_size, include_frames=args.include_frames, verbose=args.verbose)
    elif args.action == "render":
        return render_path(
            args.container,
            args.path,
            args.output,
            disable_threads=args.disable_threads,
            enable_anti_aliasing=args.enable_anti_aliasing,
            background_color=args.background_color,
            background_image=args.background_image,
            force_aspect_ratio=args.force_aspect_ratio,
            scale_width=args.scale_width,
            scale_height=args.scale_height,
            only_depths=args.only_depths,
            only_frames=args.only_frames,
            verbose=args.verbose,
        )
    else:
        raise Exception(f"Invalid action {args.action}!")


if __name__ == "__main__":
    sys.exit(main())
