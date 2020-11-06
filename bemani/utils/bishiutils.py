#! /usr/bin/env python3
import argparse
import os
import os.path
import struct
import sys
from PIL import Image, ImageOps  # type: ignore
from typing import Any, List

from bemani.format.dxt import DXTBuffer
from bemani.protocol.binary import BinaryEncoding
from bemani.protocol.lz77 import Lz77


def get_until_null(data: bytes, offset: int) -> bytes:
    out = b""
    while data[offset] != 0:
        out += data[offset:(offset + 1)]
        offset += 1
    return out


def descramble_text(text: bytes, obfuscated: bool) -> str:
    if len(text):
        if obfuscated and (text[0] - 0x20) > 0x7F:
            # Gotta do a weird demangling where we swap the
            # top bit.
            return bytes(((x + 0x80) & 0xFF) for x in text).decode('ascii')
        else:
            return text.decode('ascii')
    else:
        return ""


def descramble_pman(package_data: bytes, offset: int, obfuscated: bool) -> List[str]:
    magic, _, _, _, numentries, _, offset = struct.unpack(
        "<4sIIIIII",
        package_data[offset:(offset + 28)],
    )

    if magic != b"PMAN":
        raise Exception("Invalid magic value in PMAN structure!")

    names = []
    if numentries > 0:
        # Jump to the offset, parse it out
        for i in range(numentries):
            file_offset = offset + (i * 12)
            _, entry_no, nameoffset = struct.unpack(
                "<III",
                package_data[file_offset:(file_offset + 12)],
            )
            if nameoffset == 0:
                raise Exception("Expected name offset in PMAN data!")

            bytedata = get_until_null(package_data, nameoffset)
            name = descramble_text(bytedata, obfuscated)
            names.append(name)

    return names


def swap32(i: int) -> int:
    return struct.unpack("<I", struct.pack(">I", i))[0]


def extract(filename: str, output_dir: str, *, write: bool, verbose: bool = False) -> None:
    with open(filename, "rb") as fp:
        data = fp.read()

    # Suppress debug text unless asked
    if verbose:
        vprint = print
    else:
        def vprint(*args: Any) -> None:  # type: ignore
            pass

    # First, check the signature
    if data[0:4] != b"2PXT":
        raise Exception("Invalid graphic file format!")

    # Not sure what words 2 and 3 are, they seem to be some sort of
    # version or date?

    # Now, grab the file length, verify that we have the right amount
    # of data.
    length = struct.unpack("<I", data[12:16])[0]
    if length != len(data):
        raise Exception(f"Invalid graphic file length, expecting {length} bytes!")

    # I think that offset 16-20 are the file data offset, but I'm not sure?
    header_length = struct.unpack("<I", data[16:20])[0]

    # Now, the meat of the file format. Bytes 20-24 are a bitfield for
    # what parts of the header exist in the file. We need to understand
    # each bit so we know how to skip past each section.
    feature_mask = struct.unpack("<I", data[20:24])[0]
    header_offset = 24

    # Lots of magic happens if this bit is set.
    text_obfuscated = bool(feature_mask & 0x20)
    legacy_lz = bool(feature_mask & 0x04)
    modern_lz = bool(feature_mask & 0x40000)

    # Get raw directory where we want to put files
    path = os.path.abspath(output_dir)

    if feature_mask & 0x01:
        # List of textures that exist in the file, with pointers to their data.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        names = []
        for x in range(length):
            interesting_offset = offset + (x * 12)
            if interesting_offset != 0:
                name_offset, _, texture_offset = struct.unpack(
                    "<III",
                    data[interesting_offset:(interesting_offset + 12)],
                )

                if name_offset != 0:
                    # Let's decode this until the first null.
                    bytedata = get_until_null(data, name_offset)
                    name = descramble_text(bytedata, text_obfuscated)
                    names.append(name)

                if texture_offset != 0:
                    filename = os.path.join(path, name)

                    if not write:
                        print(f"Would extract {filename}...")
                    else:
                        if legacy_lz:
                            raise Exception("We don't support legacy lz mode!")
                        elif modern_lz:
                            # Get size, round up to nearest power of 4
                            tex_size = struct.unpack(">I", data[texture_offset:(texture_offset + 4)])[0]
                            tex_size = (tex_size + 3) & (~3)

                            # Get the data offset
                            lz_data_offset = texture_offset + 8
                            lz_data = data[lz_data_offset:(lz_data_offset + tex_size)]

                            lz77 = Lz77()

                            print(f"Extracting {filename}...")
                            raw_data = lz77.decompress(lz_data)
                        else:
                            # File data doesn't seem to have any length.
                            # TODO: Calculate length from width/height.
                            raw_data = data[(texture_offset + 8):]
                            raise Exception("Unfinished section, unknown raw length!")

                        # Now, see if we can extract this data.
                        magic, _, _, _, width, height, fmt, _, flags2, flags1 = struct.unpack(
                            "<4sIIIHHBBBB",
                            raw_data[0:24],
                        )

                        if magic != b"TDXT":
                            raise Exception("Unexpected texture format!")

                        img = None
                        if fmt == 0x20:
                            img = Image.frombytes(
                                'RGBA', (width, height), raw_data[64:], 'raw', 'BGRA',
                            )
                        elif fmt == 0x0E:
                            img = Image.frombytes(
                                'RGB', (width, height), raw_data[64:], 'raw', 'RGB',
                            )
                        elif fmt == 0x1A:
                            # DXT5 format.
                            dxt = DXTBuffer(width, height)
                            img = Image.frombuffer(
                                'RGBA',
                                (width, height),
                                dxt.DXT5Decompress(raw_data[64:]),
                                'raw',
                                'RGBA',
                                0,
                                1,
                            )
                            img = ImageOps.flip(img).rotate(-90, expand=True)
                        else:
                            print(f"Unsupported format {hex(fmt)} for texture {name}")

                        # Actually place the file down.
                        os.makedirs(path, exist_ok=True)
                        with open(f"{filename}.raw", "wb") as bfp:
                            bfp.write(raw_data)
                        if img:
                            with open(f"{filename}.png", "wb") as bfp:
                                img.save(bfp, format='PNG')

        vprint(f"Bit 0x000001 - count: {length}, offset: {hex(offset)}")
        for name in names:
            vprint(f"    {name}")
    else:
        vprint("Bit 0x000001 - NOT PRESENT")

    if feature_mask & 0x02:
        # Seems to be a structure that duplicates texture names? Maybe this is
        # used elsewhere to map sections to textures? The structure includes
        # the entry number that seems to correspond with the above table.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        vprint(f"Bit 0x000002 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                vprint(f"    {name}")
    else:
        vprint("Bit 0x000002 - NOT PRESENT")

    if feature_mask & 0x04:
        vprint("Bit 0x000004 - legacy lz mode on")
    else:
        vprint("Bit 0x000004 - legacy lz mode off")

    if feature_mask & 0x08:
        # I *THINK* that this is the mapping between sections and their
        # respective textures, but I haven't dug in yet.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        print(f"Bit 0x000008 - count: {length}, offset: {hex(offset)}")
    else:
        print("Bit 0x000008 - NOT PRESENT")

    if feature_mask & 0x10:
        # Seems to be a strucure that duplicates the above section?
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        print(f"Bit 0x000010 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                print(f"    {name}")
    else:
        print("Bit 0x000010 - NOT PRESENT")

    if feature_mask & 0x20:
        vprint(f"Bit 0x000020 - text obfuscation on")
    else:
        vprint(f"Bit 0x000020 - text obfuscation off")

    if feature_mask & 0x40:
        # Two unknown bytes, first is a length or a count. Secound is
        # an optional offset to grab another set of bytes from.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        # TODO: 0x40 has some weird offset calculations, gotta look into
        # this further.

        names = []
        for x in range(length):
            interesting_offset = offset + (x * 12)
            if interesting_offset != 0:
                interesting_offset = struct.unpack(
                    "<I",
                    data[interesting_offset:(interesting_offset + 4)],
                )[0]
            if interesting_offset != 0:
                # Let's decode this until the first null.
                bytedata = get_until_null(data, interesting_offset)
                name = descramble_text(bytedata, text_obfuscated)
                names.append(name)

        print(f"Bit 0x000040 - count: {length}, offset: {hex(offset)}")
        for name in names:
            print(f"    {name}")
    else:
        print("Bit 0x000040 - NOT PRESENT")

    if feature_mask & 0x80:
        # One unknown byte, treated as an offset.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        print(f"Bit 0x000080 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                print(f"    {name}")
    else:
        print("Bit 0x000080 - NOT PRESENT")

    if feature_mask & 0x100:
        # Two unknown bytes, first is a length or a count. Secound is
        # an optional offset to grab another set of bytes from.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        print(f"Bit 0x000100 - count: {length}, offset: {hex(offset)}")

        # TODO: We do something if length is > 0, we use the magic flag
        # from above in this case to optionally transform each thing we
        # extract.
    else:
        print("Bit 0x000100 - NOT PRESENT")

    if feature_mask & 0x200:
        # One unknown byte, treated as an offset.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        print(f"Bit 0x000200 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                print(f"    {name}")
    else:
        print("Bit 0x000200 - NOT PRESENT")

    if feature_mask & 0x400:
        # One unknown byte, treated as an offset.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        print(f"Bit 0x000400 - offset: {hex(offset)}")
    else:
        print("Bit 0x000400 - NOT PRESENT")

    if feature_mask & 0x800:
        # This is the names of the animations as far as I can tell.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        pp_19 = length
        pp_20 = offset

        vprint(f"Bit 0x000800 - count: {length}, offset: {hex(offset)}")

        names = []
        for x in range(length):
            interesting_offset = offset + (x * 12)
            if interesting_offset != 0:
                interesting_offset = struct.unpack(
                    "<I",
                    data[interesting_offset:(interesting_offset + 4)],
                )[0]
            if interesting_offset != 0:
                # Let's decode this until the first null.
                bytedata = get_until_null(data, interesting_offset)
                name = descramble_text(bytedata, text_obfuscated)
                names.append(name)

        for name in names:
            vprint(f"    {name}")
    else:
        vprint("Bit 0x000800 - NOT PRESENT")
        pp_19 = 0
        pp_20 = 0

    if feature_mask & 0x1000:
        # Seems to be a secondary structure mirroring the above.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        vprint(f"Bit 0x001000 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                vprint(f"    {name}")
    else:
        vprint("Bit 0x001000 - NOT PRESENT")

    if feature_mask & 0x2000:
        # I am making a very preliminary guess that these are shapes used along
        # with animations specified below. The names in these sections tend to
        # have the word "shape" in them.
        length, offset = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        header_offset += 8

        vprint(f"Bit 0x002000 - count: {length}, offset: {hex(offset)}")

        # TODO: We do a LOT of extra stuff with this one, if count > 0...

        names = []
        for x in range(length):
            interesting_offset = offset + (x * 12)
            if interesting_offset != 0:
                interesting_offset = struct.unpack(
                    "<I",
                    data[interesting_offset:(interesting_offset + 4)],
                )[0]
            if interesting_offset != 0:
                # Let's decode this until the first null.
                bytedata = get_until_null(data, interesting_offset)
                name = descramble_text(bytedata, text_obfuscated)
                names.append(name)

        for name in names:
            vprint(f"    {name}")
    else:
        vprint("Bit 0x002000 - NOT PRESENT")

    if feature_mask & 0x4000:
        # Seems to be a secondary section mirroring the names from above.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        vprint(f"Bit 0x004000 - offset: {hex(offset)}")

        if offset != 0:
            names = descramble_pman(data, offset, text_obfuscated)
            for name in names:
                vprint(f"    {name}")
    else:
        vprint("Bit 0x004000 - NOT PRESENT")

    if feature_mask & 0x8000:
        # One unknown byte, treated as an offset.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        vprint(f"Bit 0x008000 - offset: {hex(offset)}")
    else:
        vprint("Bit 0x008000 - NOT PRESENT")

    if feature_mask & 0x10000:
        # Included font package, BINXRPC encoded.
        offset, length = struct.unpack("<II", data[header_offset:(header_offset + 8)])
        binxrpc_offset = struct.unpack("<I", data[(offset + 8):(offset + 12)])[0]
        header_offset += 4

        if binxrpc_offset != 0:
            benc = BinaryEncoding()
            fontdata = benc.decode(data[binxrpc_offset:(binxrpc_offset + length)])
        else:
            fontdata = None

        vprint(f"Bit 0x010000 - offset: {hex(offset)}, binxrpc offset: {hex(binxrpc_offset)}")
        if fontdata is not None:
            filename = os.path.join(path, "fontinfo.xml")

            if write:
                os.makedirs(path, exist_ok=True)
                print(f"Writing {filename} font information...")
                with open(filename, "w") as sfp:
                    sfp.write(str(fontdata))
            else:
                print(f"Would write {filename} font information...")
    else:
        vprint("Bit 0x010000 - NOT PRESENT")

    if feature_mask & 0x20000:
        # I am beginning to suspect that this is animation/level data. I have
        # no idea what "afp" is.
        offset = struct.unpack("<I", data[header_offset:(header_offset + 4)])[0]
        header_offset += 4

        vprint(f"Bit 0x020000 - offset: {hex(offset)}")

        if offset > 0 and pp_19 > 0 and pp_20 > 0:
            for x in range(pp_19):
                structure_offset = offset + (x * 12)
                tex_info_ptr = pp_20 + (x * 12)
                _, tex_type, afp_header = struct.unpack(
                    "<III",
                    data[structure_offset:(structure_offset + 12)]
                )
                tex_name_offset, _, tex_afp_data_offset = struct.unpack(
                    "<III",
                    data[tex_info_ptr:(tex_info_ptr + 12)],
                )
                bytedata = get_until_null(data, tex_name_offset)
                name = descramble_text(bytedata, text_obfuscated)
                afp_data = hex(tex_afp_data_offset)
                vprint(f"    type: {hex(tex_type)}, afp_offset: {hex(afp_header)}, name: {name}, data: {afp_data}")
    else:
        vprint("Bit 0x020000 - NOT PRESENT")

    if feature_mask & 0x40000:
        vprint("Bit 0x040000 - modern lz mode on")
    else:
        vprint("Bit 0x040000 - modern lz mode off")

    if header_offset != header_length:
        raise Exception("Failed to parse bitfield of header correctly!")


def main() -> int:
    parser = argparse.ArgumentParser(description="BishiBashi graphic file unpacker.")
    parser.add_argument(
        "file",
        metavar="FILE",
        help="The file to extract",
    )
    parser.add_argument(
        "dir",
        metavar="DIR",
        help="Directory to extract to",
    )
    parser.add_argument(
        "-p",
        "--pretend",
        action="store_true",
        help="Pretend to extract instead of extracting.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display verbuse debugging output.",
    )
    args = parser.parse_args()

    extract(args.file, args.dir, write=not args.pretend, verbose=args.verbose)

    return 0


if __name__ == "__main__":
    sys.exit(main())
