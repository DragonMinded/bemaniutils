#! /usr/bin/env python3
import argparse
import os
import os.path
import struct
import sys
import textwrap
from PIL import Image  # type: ignore
from typing import Any, List, Optional

from bemani.format.dxt import DXTBuffer
from bemani.protocol.binary import BinaryEncoding
from bemani.protocol.lz77 import Lz77
from bemani.protocol.node import Node


class PMAN:
    def __init__(self, entries: List[str] = []) -> None:
        self.entries = entries


class Texture:
    def __init__(
        self,
        name: str,
        width: int,
        height: int,
        fmt: int,
        header_flags1: int,
        header_flags2: int,
        header_flags3: int,
        unk_flags1: int,
        unk_flags2: int,
        unk_flags3: int,
        unk_flags4: int,
        rawdata: bytes,
        imgdata: Any,
    ) -> None:
        self.name = name
        self.width = width
        self.height = height
        self.fmt = fmt
        self.header_flags1 = header_flags1
        self.header_flags2 = header_flags2
        self.header_flags3 = header_flags3
        self.unk_flags1 = unk_flags1
        self.unk_flags2 = unk_flags2
        self.unk_flags3 = unk_flags3
        self.unk_flags4 = unk_flags4
        self.raw = rawdata
        self.img = imgdata


class TextureRegion:
    def __init__(self, textureno: int, left: int, top: int, right: int, bottom: int) -> None:
        self.textureno = textureno
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class Animation:
    def __init__(
        self,
        name: str,
        data: bytes,
        header: bytes = b"",
    ) -> None:
        self.name = name
        self.data = data
        self.header = header


class AFPFile:
    def __init__(self, contents: bytes, verbose: bool = False) -> None:
        # Initialize coverage. This is used to help find missed/hidden file
        # sections that we aren't parsing correctly.
        self.coverage: List[bool] = [False] * len(contents)

        # Original file data that we parse into structures.
        self.data = contents

        # All of the crap!
        self.endian: str = "<"
        self.features: int = 0
        self.text_obfuscated: bool = False
        self.legacy_lz: bool = False
        self.modern_lz: bool = False

        # List of all textures in this file. This is unordered, textures should
        # be looked up by name.
        self.textures: List[Texture] = []

        # Texture mapping, which allows other structures to refer to texture
        # by number instead of name.
        self.texturemap: PMAN = PMAN()

        # List of all regions found inside textures, mapped to their textures
        # using texturenos that can be looked up using the texturemap above.
        # This structure is ordered, and the regionno from the regionmap
        # below can be used to look into this structure.
        self.texture_to_region: List[TextureRegion] = []

        # Region mapping, which allows other structures to refer to regions
        # by number instead of name.
        self.regionmap: PMAN = PMAN()

        # Animations(?) and their names found in this file. This is unordered,
        # animations should be looked up by name.
        self.animations: List[Animation] = []

        # Animation(?) mapping, which allows other structures to refer to
        # animations by number instead of name.
        self.animmap: PMAN = PMAN()

        # Font information (mapping for various coepoints to their region in
        # a particular font texture.
        self.fontdata: Optional[Node] = None

        # Parse out the file structure.
        self.__parse(verbose)

    def add_coverage(self, offset: int, length: int, unique: bool = True) -> None:
        for i in range(offset, offset + length):
            if self.coverage[i] and unique:
                raise Exception(f"Already covered {hex(offset)}!")
            self.coverage[i] = True

    def print_coverage(self) -> None:
        # First offset that is not coverd in a run.
        start = None

        for offset, covered in enumerate(self.coverage):
            if covered:
                if start is not None:
                    print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)")
                    start = None
            else:
                if start is None:
                    start = offset
        if start is not None:
            # Print final range
            offset = len(self.coverage)
            print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)")

    @staticmethod
    def cap32(val: int) -> int:
        return val & 0xFFFFFFFF

    @staticmethod
    def poly(val: int) -> int:
        if (val >> 31) & 1 != 0:
            return 0x4C11DB7
        else:
            return 0

    @staticmethod
    def crc32(bytestream: bytes) -> int:
        # Janky 6-bit CRC for ascii names in PMAN structures.
        result = 0
        for byte in bytestream:
            for i in range(6):
                result = AFPFile.poly(result) ^ AFPFile.cap32((result << 1) | ((byte >> i) & 1))
        return result

    @staticmethod
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

    def get_until_null(self, offset: int) -> bytes:
        out = b""
        while self.data[offset] != 0:
            out += self.data[offset:(offset + 1)]
            offset += 1
        return out

    def descramble_pman(self, offset: int) -> PMAN:
        # Unclear what the first three unknowns are, but the fourth
        # looks like it could possibly be two int16s indicating unknown?
        magic, expect_zero, flags1, flags2, numentries, flags3, data_offset = struct.unpack(
            f"{self.endian}4sIIIIII",
            self.data[offset:(offset + 28)],
        )
        self.add_coverage(offset, 28)

        # I have never seen the first unknown be anything other than zero,
        # so lets lock that down.
        if expect_zero != 0:
            raise Exception("Got a non-zero value for expected zero location in PMAN!")

        if self.endian == "<" and magic != b"PMAN":
            raise Exception("Invalid magic value in PMAN structure!")
        if self.endian == ">" and magic != b"NAMP":
            raise Exception("Invalid magic value in PMAN structure!")

        names: List[Optional[str]] = [None] * numentries
        if numentries > 0:
            # Jump to the offset, parse it out
            for i in range(numentries):
                file_offset = data_offset + (i * 12)
                name_crc, entry_no, nameoffset = struct.unpack(
                    f"{self.endian}III",
                    self.data[file_offset:(file_offset + 12)],
                )
                self.add_coverage(file_offset, 12)

                if nameoffset == 0:
                    raise Exception("Expected name offset in PMAN data!")

                bytedata = self.get_until_null(nameoffset)
                self.add_coverage(nameoffset, len(bytedata) + 1, unique=False)
                name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                names[entry_no] = name

                if name_crc != AFPFile.crc32(name.encode('ascii')):
                    raise Exception(f"Name CRC failed for {name}")

        for i, name in enumerate(names):
            if name is None:
                raise Exception(f"Didn't get mapping for entry {i + 1}")

        return PMAN(
            entries=names
        )

    def __parse(
        self,
        verbose: bool = False,
    ) -> None:
        # Suppress debug text unless asked
        if verbose:
            vprint = print
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        # First, check the signature
        self.add_coverage(0, 4)
        if self.data[0:4] == b"2PXT":
            self.endian = "<"
        elif self.data[0:4] == b"TXP2":
            self.endian = ">"
        else:
            raise Exception("Invalid graphic file format!")

        # Not sure what words 2 and 3 are, they seem to be some sort of
        # version or date?
        self.add_coverage(4, 8)

        # Now, grab the file length, verify that we have the right amount
        # of data.
        length = struct.unpack(f"{self.endian}I", self.data[12:16])[0]
        self.add_coverage(12, 4)
        if length != len(self.data):
            raise Exception(f"Invalid graphic file length, expecting {length} bytes!")

        # I think that offset 16-20 are the file data offset, but I'm not sure?
        header_length = struct.unpack(f"{self.endian}I", self.data[16:20])[0]
        self.add_coverage(16, 4)

        # Now, the meat of the file format. Bytes 20-24 are a bitfield for
        # what parts of the header exist in the file. We need to understand
        # each bit so we know how to skip past each section.
        feature_mask = struct.unpack(f"{self.endian}I", self.data[20:24])[0]
        self.add_coverage(20, 4)
        header_offset = 24

        # Lots of magic happens if this bit is set.
        self.text_obfuscated = bool(feature_mask & 0x20)
        self.legacy_lz = bool(feature_mask & 0x04)
        self.modern_lz = bool(feature_mask & 0x40000)
        self.features = feature_mask

        if feature_mask & 0x01:
            # List of textures that exist in the file, with pointers to their data.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            texturenames = []
            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, texture_length, texture_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset:(interesting_offset + 12)],
                    )
                    self.add_coverage(interesting_offset, 12)

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                        texturenames.append(name)

                    if texture_offset != 0:
                        if self.legacy_lz:
                            raise Exception("We don't support legacy lz mode!")
                        elif self.modern_lz:
                            # Get size, round up to nearest power of 4
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset:(texture_offset + 8)],
                            )
                            self.add_coverage(texture_offset, 8)
                            if deflated_size != (texture_length - 8):
                                raise Exception("We got an incorrect length for lz texture!")
                            inflated_size = (inflated_size + 3) & (~3)

                            # Get the data offset.
                            lz_data_offset = texture_offset + 8
                            lz_data = self.data[lz_data_offset:(lz_data_offset + deflated_size)]
                            self.add_coverage(lz_data_offset, deflated_size)

                            # This takes forever, so skip it if we're pretending.
                            lz77 = Lz77()
                            raw_data = lz77.decompress(lz_data)
                        else:
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset:(texture_offset + 8)],
                            )

                            # I'm guessing how raw textures work because I haven't seen them.
                            # I assume they're like the above, so lets put in some asertions.
                            if deflated_size != (texture_length - 8):
                                raise Exception("We got an incorrect length for raw texture!")
                            raw_data = self.data[(texture_offset + 8):(texture_offset + 8 + deflated_size)]
                            self.add_coverage(texture_offset, deflated_size + 8)

                        (
                            magic,
                            header_flags1,
                            header_flags2,
                            length,
                            width,
                            height,
                            fmtflags,
                            expected_zero1,
                            expected_zero2,
                        ) = struct.unpack(
                            f"{self.endian}4sIIIHHIII",
                            raw_data[0:32],
                        )
                        if length != len(raw_data):
                            raise Exception("Invalid texture length!")
                        # I have only ever observed the following values across two different games.
                        # Don't want to keep the chunk around so let's assert our assumptions.
                        if (expected_zero1 | expected_zero2) != 0:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        if raw_data[32:44] != b'\0' * 12:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        # This is almost ALWAYS 3, but I've seen it be 1 as well, so I guess we have to
                        # round-trip it if we want to write files back out. I have no clue what it's for.
                        # I've seen it be 1 only on files used for fonts so far, but I am not sure there
                        # is any correlation there.
                        header_flags3 = struct.unpack(f"{self.endian}I", raw_data[44:48])[0]
                        if raw_data[48:64] != b'\0' * 16:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        fmt = fmtflags & 0xFF

                        # Extract flags that the game cares about.
                        flags1 = (fmtflags >> 24) & 0xFF
                        flags2 = (fmtflags >> 16) & 0xFF

                        # These flags may have some significance, such as
                        # the unk3/unk4 possibly indicating texture doubling?
                        unk1 = 3 if (flags1 & 0xF == 1) else 1
                        unk2 = 3 if ((flags1 >> 4) & 0xF == 1) else 1
                        unk3 = 1 if (flags2 & 0xF == 1) else 2
                        unk4 = 1 if ((flags2 >> 4) & 0xF == 1) else 2

                        if self.endian == "<" and magic != b"TDXT":
                            raise Exception("Unexpected texture format!")
                        if self.endian == ">" and magic != b"TXDT":
                            raise Exception("Unexpected texture format!")

                        if fmt == 0x0B:
                            # 16-bit 565 color RGB format.
                            newdata = []
                            for i in range(width * height):
                                pixel = struct.unpack(
                                    f"{self.endian}H",
                                    raw_data[(64 + (i * 2)):(66 + (i * 2))],
                                )[0]
                                red = ((pixel >> 0) & 0x1F) << 3
                                green = ((pixel >> 5) & 0x3F) << 2
                                blue = ((pixel >> 11) & 0x1F) << 3
                                newdata.append(
                                    struct.pack("<BBB", blue, green, red)
                                )
                            img = Image.frombytes(
                                'RGB', (width, height), b''.join(newdata), 'raw', 'RGB',
                            )
                        elif fmt == 0x0E:
                            # RGB image, no alpha.
                            img = Image.frombytes(
                                'RGB', (width, height), raw_data[64:], 'raw', 'RGB',
                            )
                        # 0x10 = Seems to be some sort of RGB with color swapping.
                        elif fmt == 0x15:
                            # RGBA format.
                            # TODO: The colors are wrong on this, need to investigate
                            # further.
                            img = Image.frombytes(
                                'RGBA', (width, height), raw_data[64:], 'raw', 'BGRA',
                            )
                        # 0x16 = DTX1 format, when I encounter this I'll hook it up.
                        elif fmt == 0x1A:
                            # DXT5 format.
                            dxt = DXTBuffer(width, height)
                            img = Image.frombuffer(
                                'RGBA',
                                (width, height),
                                dxt.DXT5Decompress(raw_data[64:], endian=self.endian),
                                'raw',
                                'RGBA',
                                0,
                                1,
                            )
                        # 0x1E = I have no idea what format this is.
                        elif fmt == 0x1F:
                            # 16-bit 4-4-4-4 RGBA format.
                            newdata = []
                            for i in range(width * height):
                                pixel = struct.unpack(
                                    f"{self.endian}H",
                                    raw_data[(64 + (i * 2)):(66 + (i * 2))],
                                )[0]
                                blue = ((pixel >> 0) & 0xF) << 4
                                green = ((pixel >> 4) & 0xF) << 4
                                red = ((pixel >> 8) & 0xF) << 4
                                alpha = ((pixel >> 12) & 0xF) << 4
                                newdata.append(
                                    struct.pack("<BBBB", red, green, blue, alpha)
                                )
                            img = Image.frombytes(
                                'RGBA', (width, height), b''.join(newdata), 'raw', 'RGBA',
                            )
                        elif fmt == 0x20:
                            # RGBA format.
                            img = Image.frombytes(
                                'RGBA', (width, height), raw_data[64:], 'raw', 'BGRA',
                            )
                        else:
                            vprint(f"Unsupported format {hex(fmt)} for texture {name}")
                            img = None

                        self.textures.append(
                            Texture(
                                name,
                                width,
                                height,
                                fmt,
                                header_flags1,
                                header_flags2,
                                header_flags3,
                                unk1,
                                unk2,
                                unk3,
                                unk4,
                                raw_data,
                                img,
                            )
                        )

            vprint(f"Bit 0x000001 - count: {length}, offset: {hex(offset)}")
            for name in texturenames:
                vprint(f"    {name}")
        else:
            vprint("Bit 0x000001 - NOT PRESENT")

        # Mapping between texture index and the name of the texture.
        if feature_mask & 0x02:
            # Seems to be a structure that duplicates texture names? I am pretty
            # sure this is used to map texture names to file indexes used elsewhere.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000002 - offset: {hex(offset)}")

            if offset != 0:
                self.texturemap = self.descramble_pman(offset)
                for i, name in enumerate(self.texturemap.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x000002 - NOT PRESENT")

        if feature_mask & 0x04:
            vprint("Bit 0x000004 - legacy lz mode on")
        else:
            vprint("Bit 0x000004 - legacy lz mode off")

        # Mapping between region index and the texture it goes to as well as the
        # region of texture that this particular graphic makes up.
        if feature_mask & 0x08:
            # Mapping between individual graphics and their respective textures.
            # This is 10 bytes per entry. Seems to need both 0x2 (texture index)
            # and 0x10 (region index).
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            if offset != 0 and length > 0:
                self.texture_to_region = [TextureRegion(0, 0, 0, 0, 0)] * length

                for i in range(length):
                    descriptor_offset = offset + (10 * i)
                    texture_no, left, top, right, bottom = struct.unpack(
                        f"{self.endian}HHHHH",
                        self.data[descriptor_offset:(descriptor_offset + 10)],
                    )
                    self.add_coverage(descriptor_offset, 10)

                    if texture_no < 0 or texture_no >= len(self.texturemap.entries):
                        raise Exception(f"Out of bounds texture {texture_no}")

                    # TODO: The offsets here seem to be off by a power of 2, there
                    # might be more flags in the above texture format that specify
                    # device scaling and such?
                    self.texture_to_region[i] = TextureRegion(texture_no, left, top, right, bottom)

            vprint(f"Bit 0x000008 - count: {length}, offset: {hex(offset)}")
        else:
            vprint("Bit 0x000008 - NOT PRESENT")

        if feature_mask & 0x10:
            # Names of the graphics regions, so we can look into the texture_to_region
            # mapping above.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000010 - offset: {hex(offset)}")

            if offset != 0:
                self.regionmap = self.descramble_pman(offset)
                for i, name in enumerate(self.regionmap.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x000010 - NOT PRESENT")

        if feature_mask & 0x20:
            vprint(f"Bit 0x000020 - text obfuscation on")
        else:
            vprint(f"Bit 0x000020 - text obfuscation off")

        if feature_mask & 0x40:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000040 - count: {length}, offset: {hex(offset)}")

            # TODO: 0x40 has some weird offset calculations, gotta look into
            # this further. Also, gotta actually parse this structure.
        else:
            vprint("Bit 0x000040 - NOT PRESENT")

        if feature_mask & 0x80:
            # One unknown byte, treated as an offset.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000080 - offset: {hex(offset)}")

            # TODO: We don't save this PMAN structure, I have no idea what it's for, but if
            # we find files with a nonzero value here and update textures, we're hosed.
            if offset != 0:
                pman = self.descramble_pman(offset)
                for i, name in enumerate(pman.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x000080 - NOT PRESENT")

        if feature_mask & 0x100:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000100 - count: {length}, offset: {hex(offset)}")

            # TODO: We do something if length is > 0, we use the magic flag
            # from above in this case to optionally transform each thing we
            # extract. This is possibly names of some other type of struture?
        else:
            vprint("Bit 0x000100 - NOT PRESENT")

        if feature_mask & 0x200:
            # One unknown byte, treated as an offset.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000200 - offset: {hex(offset)}")

            # TODO: We don't save this PMAN structure, I have no idea what it's for, but if
            # we find files with a nonzero value here and update textures, we're hosed.
            if offset != 0:
                pman = self.descramble_pman(offset)
                for i, name in enumerate(pman.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x000200 - NOT PRESENT")

        if feature_mask & 0x400:
            # One unknown byte, treated as an offset.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000400 - offset: {hex(offset)}")
        else:
            vprint("Bit 0x000400 - NOT PRESENT")

        if feature_mask & 0x800:
            # This is the names of the animations as far as I can tell.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000800 - count: {length}, offset: {hex(offset)}")

            animnames = []
            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, anim_length, anim_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset:(interesting_offset + 12)],
                    )
                    self.add_coverage(interesting_offset, 12)
                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                        animnames.append(name)

                    if anim_offset != 0:
                        self.animations.append(
                            Animation(
                                name,
                                self.data[anim_offset:(anim_offset + anim_length)]
                            )
                        )
                        self.add_coverage(anim_offset, anim_length)

            for name in animnames:
                vprint(f"    {name}")
        else:
            vprint("Bit 0x000800 - NOT PRESENT")

        if feature_mask & 0x1000:
            # Seems to be a secondary structure mirroring the above.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x001000 - offset: {hex(offset)}")

            if offset != 0:
                self.animmap = self.descramble_pman(offset)
                for i, name in enumerate(self.animmap.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x001000 - NOT PRESENT")

        if feature_mask & 0x2000:
            # I am making a very preliminary guess that these are shapes used along
            # with animations specified below. The names in these sections tend to
            # have the word "shape" in them.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            self.add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x002000 - count: {length}, offset: {hex(offset)}")

            # TODO: We do a LOT of extra stuff with this one, if count > 0...

            shapenames = []
            for x in range(length):
                shape_base_offset = offset + (x * 12)
                if shape_base_offset != 0:
                    name_offset, shape_length, shape_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[shape_base_offset:(shape_base_offset + 12)],
                    )
                    self.add_coverage(shape_base_offset, 12)
                    self.add_coverage(shape_offset, shape_length)

                    # TODO: At the shape offset is a "D2EG" structure of some sort.
                    # I have no idea what these do. I would have to look into it
                    # more if its important.

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                        shapenames.append(name)

            for name in shapenames:
                vprint(f"    {name}")
        else:
            vprint("Bit 0x002000 - NOT PRESENT")

        if feature_mask & 0x4000:
            # Seems to be a secondary section mirroring the names from above.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x004000 - offset: {hex(offset)}")

            if offset != 0:
                pman = self.descramble_pman(offset)
                for i, name in enumerate(pman.entries):
                    vprint(f"    {i}: {name}")
        else:
            vprint("Bit 0x004000 - NOT PRESENT")

        if feature_mask & 0x8000:
            # One unknown byte, treated as an offset.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x008000 - offset: {hex(offset)}")
        else:
            vprint("Bit 0x008000 - NOT PRESENT")

        if feature_mask & 0x10000:
            # Included font package, BINXRPC encoded.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            # I am not sure what the unknown byte is for. It always appears as
            # all zeros in all files I've looked at.
            expect_zero, length, binxrpc_offset = struct.unpack(f"{self.endian}III", self.data[offset:(offset + 12)])
            self.add_coverage(offset, 12)

            if expect_zero != 0:
                # If we find non-zero versions of this, then that means updating the file is
                # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                raise Exception("Expected a zero in font package header!")

            if binxrpc_offset != 0:
                benc = BinaryEncoding()
                self.fontdata = benc.decode(self.data[binxrpc_offset:(binxrpc_offset + length)])
                self.add_coverage(binxrpc_offset, length)
            else:
                self.fontdata = None

            vprint(f"Bit 0x010000 - offset: {hex(offset)}, binxrpc offset: {hex(binxrpc_offset)}")
        else:
            vprint("Bit 0x010000 - NOT PRESENT")

        if feature_mask & 0x20000:
            # I am beginning to suspect that this is animation/level data. I have
            # no idea what "afp" is. Games refer to these as "afp streams".
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x020000 - offset: {hex(offset)}")

            if offset > 0 and len(self.animations) > 0:
                for i in range(len(self.animations)):
                    structure_offset = offset + (i * 12)

                    # First word is always zero, as observed. I am not ENTIRELY sure that
                    # the second field is length, but it lines up with everything else
                    # I've observed and seems to make sense.
                    expect_zero, afp_header_length, afp_header = struct.unpack(
                        f"{self.endian}III",
                        self.data[structure_offset:(structure_offset + 12)]
                    )
                    self.add_coverage(structure_offset, 12)

                    if expect_zero != 0:
                        # If we find non-zero versions of this, then that means updating the file is
                        # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                        raise Exception("Expected a zero in font package header!")

                    self.animations[i].header = self.data[afp_header:(afp_header + afp_header_length)]
                    self.add_coverage(afp_header, afp_header_length)
        else:
            vprint("Bit 0x020000 - NOT PRESENT")

        if feature_mask & 0x40000:
            vprint("Bit 0x040000 - modern lz mode on")
        else:
            vprint("Bit 0x040000 - modern lz mode off")

        if header_offset != header_length:
            raise Exception("Failed to parse bitfield of header correctly!")

        if verbose:
            self.print_coverage()


def main() -> int:
    parser = argparse.ArgumentParser(description="Konami AFP graphic file unpacker.")
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
    parser.add_argument(
        "-r",
        "--write-raw",
        action="store_true",
        help="Always write raw texture files.",
    )
    parser.add_argument(
        "--write-mappings",
        action="store_true",
        help="Write mapping files to disk.",
    )
    args = parser.parse_args()

    with open(args.file, "rb") as bfp:
        afpfile = AFPFile(bfp.read(), verbose=args.verbose)

    # Actually place the files down.
    os.makedirs(args.dir, exist_ok=True)

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

            if args.xml:
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
                print(f"Writing {filename} font information...")
            else:
                print(f"Writing {filename} font information...")
                with open(filename, "w") as sfp:
                    sfp.write(str(afpfile.fontdata))

    return 0


if __name__ == "__main__":
    sys.exit(main())
