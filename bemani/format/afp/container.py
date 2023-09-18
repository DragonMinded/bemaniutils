import io
import os
import struct
from PIL import Image
from typing import Any, Dict, List, Optional, Tuple

from bemani.format.tdxt import TDXT
from bemani.protocol.binary import BinaryEncoding
from bemani.protocol.lz77 import Lz77
from bemani.protocol.node import Node

from .swf import SWF
from .geo import Shape
from .util import (
    TrackedCoverage,
    VerboseOutput,
    scramble_text,
    descramble_text,
    pad,
    align,
)


class PMAN:
    def __init__(
        self,
        entries: List[str] = [],
        ordering: List[int] = [],
        flags1: int = 0,
        flags2: int = 0,
        flags3: int = 0,
    ) -> None:
        self.entries = entries
        self.ordering = ordering
        self.flags1 = flags1
        self.flags2 = flags2
        self.flags3 = flags3

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "flags": [self.flags1, self.flags2, self.flags3],
            "entries": self.entries,
            "ordering": self.ordering,
        }


class Texture:
    def __init__(
        self,
        name: str,
        tdxt: TDXT,
        compressed: Optional[bytes],
    ) -> None:
        self.name = name
        self.tdxt = tdxt
        self.compressed = compressed

    @property
    def width(self) -> int:
        return self.tdxt.width

    @property
    def height(self) -> int:
        return self.tdxt.height

    @property
    def fmt(self) -> int:
        return self.tdxt.fmt

    @property
    def fmtflags(self) -> int:
        return self.tdxt.fmtflags

    @property
    def header_flags1(self) -> int:
        return self.tdxt.header_flags1

    @property
    def header_flags2(self) -> int:
        return self.tdxt.header_flags2

    @property
    def header_flags3(self) -> int:
        return self.tdxt.header_flags3

    @property
    def raw(self) -> bytes:
        return self.tdxt.raw

    @property
    def img(self) -> Optional[Image.Image]:
        return self.tdxt.img

    @img.setter
    def img(self, newdata: Image.Image) -> None:
        # The TDXT magic container will update the raw for us as well, as long as it's supported.
        self.tdxt.img = newdata

        # Unset our cache, so we don't accidentally write the unmodified original data.
        self.compressed = None

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "name": self.name,
            "width": self.width,
            "height": self.height,
            "fmt": self.fmt,
            "header_flags": [
                self.header_flags1,
                self.header_flags2,
                self.header_flags3,
            ],
            "fmt_flags": self.fmtflags,
            "raw": self.raw.hex(),
            "compressed": self.compressed.hex()
            if self.compressed is not None
            else None,
        }


class TextureRegion:
    def __init__(
        self, textureno: int, left: int, top: int, right: int, bottom: int
    ) -> None:
        self.textureno = textureno
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "texture": self.textureno,
            "left": self.left,
            "top": self.top,
            "right": self.right,
            "bottom": self.bottom,
        }

    def __repr__(self) -> str:
        return (
            f"texture: {self.textureno}, "
            + f"left: {self.left / 2}, "
            + f"top: {self.top / 2}, "
            + f"right: {self.right / 2}, "
            + f"bottom: {self.bottom / 2}, "
            + f"width: {(self.right - self.left) / 2}, "
            + f"height: {(self.bottom - self.top) / 2}"
        )


class Unknown1:
    def __init__(
        self,
        name: str,
        data: bytes,
    ) -> None:
        self.name = name
        self.data = data
        if len(data) != 12:
            raise Exception("Unexpected length for Unknown1 structure!")

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "name": self.name,
            "data": self.data.hex(),
        }


class Unknown2:
    def __init__(
        self,
        data: bytes,
    ) -> None:
        self.data = data
        if len(data) != 4:
            raise Exception("Unexpected length for Unknown2 structure!")

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "data": self.data.hex(),
        }


class TXP2File(TrackedCoverage, VerboseOutput):
    def __init__(self, contents: bytes, verbose: bool = False) -> None:
        # Make sure our coverage engine is initialized.
        super().__init__()

        # Original file data that we parse into structures.
        self.data = contents

        # Font data encoding handler. We keep this around as it manages
        # remembering the actual BinXML encoding.
        self.benc = BinaryEncoding()

        # All of the crap!
        self.endian: str = "<"
        self.features: int = 0
        self.file_flags: bytes = b""
        self.text_obfuscated: bool = False
        self.legacy_lz: bool = False
        self.modern_lz: bool = False

        # If we encounter parts of the file that we don't know how to read
        # or save, we drop into read-only mode and throw if somebody tries
        # to update the file.
        self.read_only: bool = False

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

        # Level data (swf-derivative) and their names found in this file. This is
        # unordered, swfdata should be looked up by name.
        self.swfdata: List[SWF] = []

        # Level data (swf-derivative) mapping, which allows other structures to
        # refer to swfdata by number instead of name.
        self.swfmap: PMAN = PMAN()

        # Font information (mapping for various coepoints to their region in
        # a particular font texture.
        self.fontdata: Optional[Node] = None

        # Shapes(?) with their raw data.
        self.shapes: List[Shape] = []

        # Shape(?) mapping, not understood or used.
        self.shapemap: PMAN = PMAN()

        # Unknown data structures that we have to roundtrip. They correlate to
        # the PMAN structures below.
        self.unknown1: List[Unknown1] = []
        self.unknown2: List[Unknown2] = []

        # Unknown PMAN structures that we have to roundtrip. They correlate to
        # the unknown data structures above.
        self.unk_pman1: PMAN = PMAN()
        self.unk_pman2: PMAN = PMAN()

        # Parse out the file structure.
        with self.covered(len(contents), verbose):
            with self.debugging(verbose):
                self.__parse(verbose)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "endian": self.endian,
            "features": self.features,
            "file_flags": self.file_flags.hex(),
            "obfuscated": self.text_obfuscated,
            "legacy_lz": self.legacy_lz,
            "modern_lz": self.modern_lz,
            "textures": [tex.as_dict(*args, **kwargs) for tex in self.textures],
            "texturemap": self.texturemap.as_dict(*args, **kwargs),
            "textureregion": [
                reg.as_dict(*args, **kwargs) for reg in self.texture_to_region
            ],
            "regionmap": self.regionmap.as_dict(*args, **kwargs),
            "swfdata": [data.as_dict(*args, **kwargs) for data in self.swfdata],
            "swfmap": self.swfmap.as_dict(*args, **kwargs),
            "fontdata": str(self.fontdata) if self.fontdata is not None else None,
            "shapes": [shape.as_dict(*args, **kwargs) for shape in self.shapes],
            "shapemap": self.shapemap.as_dict(*args, **kwargs),
            "unknown1": [unk.as_dict(*args, **kwargs) for unk in self.unknown1],
            "unknown1map": self.unk_pman1.as_dict(*args, **kwargs),
            "unknown2": [unk.as_dict(*args, **kwargs) for unk in self.unknown2],
            "unknown2map": self.unk_pman2.as_dict(*args, **kwargs),
        }

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
                result = TXP2File.poly(result) ^ TXP2File.cap32(
                    (result << 1) | ((byte >> i) & 1)
                )
        return result

    def get_until_null(self, offset: int) -> bytes:
        out = b""
        while self.data[offset] != 0:
            out += self.data[offset : (offset + 1)]
            offset += 1
        return out

    def descramble_pman(self, offset: int) -> PMAN:
        # Unclear what the first three unknowns are, but the fourth
        # looks like it could possibly be two int16s indicating unknown?
        (
            magic,
            expect_zero,
            flags1,
            flags2,
            numentries,
            flags3,
            data_offset,
        ) = struct.unpack(
            f"{self.endian}4sIIIIII",
            self.data[offset : (offset + 28)],
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
        ordering: List[Optional[int]] = [None] * numentries
        if numentries > 0:
            # Jump to the offset, parse it out
            for i in range(numentries):
                file_offset = data_offset + (i * 12)
                name_crc, entry_no, nameoffset = struct.unpack(
                    f"{self.endian}III",
                    self.data[file_offset : (file_offset + 12)],
                )
                self.add_coverage(file_offset, 12)

                if nameoffset == 0:
                    raise Exception("Expected name offset in PMAN data!")

                bytedata = self.get_until_null(nameoffset)
                self.add_coverage(nameoffset, len(bytedata) + 1, unique=False)
                name = descramble_text(bytedata, self.text_obfuscated)
                names[entry_no] = name
                ordering[entry_no] = i
                self.vprint(f"    {entry_no}: {name}, offset: {hex(nameoffset)}")

                if name_crc != TXP2File.crc32(name.encode("ascii")):
                    raise Exception(f"Name CRC failed for {name}")

        for i, n in enumerate(names):
            if n is None:
                raise Exception(f"Didn't get mapping for entry {i + 1}")

        for i, o in enumerate(ordering):
            if o is None:
                raise Exception(f"Didn't get ordering for entry {i + 1}")

        return PMAN(
            entries=[n for n in names if n is not None],
            ordering=[o for o in ordering if o is not None],
            flags1=flags1,
            flags2=flags2,
            flags3=flags3,
        )

    def __parse(self, verbose: bool) -> None:
        # First, check the signature
        if self.data[0:4] == b"2PXT":
            self.endian = "<"
        elif self.data[0:4] == b"TXP2":
            self.endian = ">"
        else:
            raise Exception("Invalid graphic file format!")
        self.add_coverage(0, 4)

        # Not sure what words 2 and 3 are, they seem to be some sort of
        # version or date?
        self.file_flags = self.data[4:12]
        self.add_coverage(4, 8)

        # Now, grab the file length, verify that we have the right amount
        # of data.
        length = struct.unpack(f"{self.endian}I", self.data[12:16])[0]
        self.add_coverage(12, 4)
        if length != len(self.data):
            raise Exception(f"Invalid graphic file length, expecting {length} bytes!")

        # This is always the header length, or the offset of the data payload.
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
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x000001 - textures; count: {length}, offset: {hex(offset)}"
            )

            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, texture_length, texture_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset : (interesting_offset + 12)],
                    )
                    self.add_coverage(interesting_offset, 12)

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = descramble_text(bytedata, self.text_obfuscated)

                    if name_offset != 0 and texture_offset != 0:
                        lz_data: Optional[bytes] = None
                        if self.legacy_lz:
                            raise Exception("We don't support legacy lz mode!")
                        elif self.modern_lz:
                            # Get size, round up to nearest power of 4
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset : (texture_offset + 8)],
                            )
                            self.add_coverage(texture_offset, 8)
                            if deflated_size != (texture_length - 8):
                                raise Exception(
                                    "We got an incorrect length for lz texture!"
                                )
                            self.vprint(
                                f"    {name}, length: {texture_length}, offset: {hex(texture_offset)}, deflated_size: {deflated_size}, inflated_size: {inflated_size}"
                            )
                            inflated_size = (inflated_size + 3) & (~3)

                            # Get the data offset.
                            lz_data_offset = texture_offset + 8
                            lz_data = self.data[
                                lz_data_offset : (lz_data_offset + deflated_size)
                            ]
                            self.add_coverage(lz_data_offset, deflated_size)

                            # This takes forever, so skip it if we're pretending.
                            lz77 = Lz77()
                            raw_data = lz77.decompress(lz_data)
                        else:
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset : (texture_offset + 8)],
                            )

                            # I'm guessing how raw textures work because I haven't seen them.
                            # I assume they're like the above, so lets put in some asertions.
                            if deflated_size != (texture_length - 8):
                                raise Exception(
                                    "We got an incorrect length for raw texture!"
                                )
                            self.vprint(
                                f"    {name}, length: {texture_length}, offset: {hex(texture_offset)}, deflated_size: {deflated_size}, inflated_size: {inflated_size}"
                            )

                            # Just grab the raw data.
                            raw_data = self.data[
                                (texture_offset + 8) : (
                                    texture_offset + 8 + deflated_size
                                )
                            ]
                            self.add_coverage(texture_offset, deflated_size + 8)

                        tdxt = TDXT.fromBytes(raw_data)
                        if tdxt.endian != self.endian:
                            raise Exception("Unexpected texture format!")

                        if tdxt.img is None:
                            self.vprint(
                                f"Unsupported format {hex(tdxt.fmt)} for texture {name}"
                            )

                        self.textures.append(
                            Texture(
                                name,
                                tdxt,
                                lz_data,
                            )
                        )
        else:
            self.vprint("Bit 0x000001 - textures; NOT PRESENT")

        # Mapping between texture index and the name of the texture.
        if feature_mask & 0x02:
            # Mapping of texture name to texture index. This is used by regions to look up textures.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x000002 - texturemapping; offset: {hex(offset)}")

            if offset != 0:
                self.texturemap = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x000002 - texturemapping; NOT PRESENT")

        if feature_mask & 0x04:
            self.vprint("Bit 0x000004 - legacy lz mode on")
        else:
            self.vprint("Bit 0x000004 - legacy lz mode off")

        # Mapping between region index and the texture it goes to as well as the
        # region of texture that this particular graphic makes up.
        if feature_mask & 0x08:
            # Mapping between individual graphics and their respective textures.
            # This is 10 bytes per entry. Seems to need both 0x2 (texture index)
            # and 0x10 (region index).
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x000008 - regions; count: {length}, offset: {hex(offset)}"
            )

            if offset != 0 and length > 0:
                for i in range(length):
                    descriptor_offset = offset + (10 * i)
                    texture_no, left, top, right, bottom = struct.unpack(
                        f"{self.endian}HHHHH",
                        self.data[descriptor_offset : (descriptor_offset + 10)],
                    )
                    self.add_coverage(descriptor_offset, 10)

                    if texture_no < 0 or texture_no >= len(self.texturemap.entries):
                        raise Exception(f"Out of bounds texture {texture_no}")

                    # Texture regions are multiplied by a power of 2. Not sure why, but the games I
                    # looked at hardcode a divide by 2 when loading regions.
                    region = TextureRegion(texture_no, left, top, right, bottom)
                    self.texture_to_region.append(region)

                    self.vprint(f"    {region}, offset: {hex(descriptor_offset)}")
        else:
            self.vprint("Bit 0x000008 - regions; NOT PRESENT")

        if feature_mask & 0x10:
            # Names of the graphics regions, so we can look into the texture_to_region
            # mapping above. Used by shapes to find the right region offset given a name.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x000010 - regionmapping; offset: {hex(offset)}")

            if offset != 0:
                self.regionmap = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x000010 - regionmapping; NOT PRESENT")

        if feature_mask & 0x20:
            self.vprint("Bit 0x000020 - text obfuscation on")
        else:
            self.vprint("Bit 0x000020 - text obfuscation off")

        if feature_mask & 0x40:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x000040 - unknown; count: {length}, offset: {hex(offset)}"
            )

            if offset != 0 and length > 0:
                for i in range(length):
                    unk_offset = offset + (i * 16)
                    name_offset = struct.unpack(
                        f"{self.endian}I", self.data[unk_offset : (unk_offset + 4)]
                    )[0]
                    self.add_coverage(unk_offset, 4)

                    # The game does some very bizarre bit-shifting. Its clear tha the first value
                    # points at a name structure, but its not in the correct endianness. This replicates
                    # the weird logic seen in game disassembly.
                    name_offset = (((name_offset >> 7) & 0x1FF) << 16) + (
                        (name_offset >> 16) & 0xFFFF
                    )
                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = descramble_text(bytedata, self.text_obfuscated)
                        self.vprint(f"    {name}")

                    self.unknown1.append(
                        Unknown1(
                            name=name,
                            data=self.data[(unk_offset + 4) : (unk_offset + 16)],
                        )
                    )
                    self.add_coverage(unk_offset + 4, 12)
        else:
            self.vprint("Bit 0x000040 - unknown; NOT PRESENT")

        if feature_mask & 0x80:
            # One unknown byte, treated as an offset. This is clearly the mapping for the parsed
            # structures from 0x40, but I don't know what those are.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x000080 - unknownmapping; offset: {hex(offset)}")

            # TODO: I have no idea what this is for.
            if offset != 0:
                self.unk_pman1 = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x000080 - unknownmapping; NOT PRESENT")

        if feature_mask & 0x100:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x000100 - unknown; count: {length}, offset: {hex(offset)}"
            )

            if offset != 0 and length > 0:
                for i in range(length):
                    unk_offset = offset + (i * 4)
                    self.unknown2.append(
                        Unknown2(self.data[unk_offset : (unk_offset + 4)])
                    )
                    self.add_coverage(unk_offset, 4)
        else:
            self.vprint("Bit 0x000100 - unknown; NOT PRESENT")

        if feature_mask & 0x200:
            # One unknown byte, treated as an offset. Almost positive its a string mapping
            # for the above 0x100 structure. That's how this file format appears to work.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x000200 - unknownmapping; offset: {hex(offset)}")

            # TODO: I have no idea what this is for.
            if offset != 0:
                self.unk_pman2 = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x000200 - unknownmapping; NOT PRESENT")

        if feature_mask & 0x400:
            # One unknown byte, treated as an offset. I have no idea what this is used for,
            # it seems to be empty data in files that I've looked at, it doesn't go to any
            # structure or mapping.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x000400 - unknown; offset: {hex(offset)}")
        else:
            self.vprint("Bit 0x000400 - unknown; NOT PRESENT")

        if feature_mask & 0x800:
            # SWF raw data that is loaded and passed to AFP core. It is equivalent to the
            # afp files in an IFS container.
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x000800 - swfdata; count: {length}, offset: {hex(offset)}"
            )

            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, swf_length, swf_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset : (interesting_offset + 12)],
                    )
                    self.add_coverage(interesting_offset, 12)
                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = descramble_text(bytedata, self.text_obfuscated)
                        self.vprint(
                            f"    {name}, length: {swf_length}, offset: {hex(swf_offset)}"
                        )

                    if swf_offset != 0:
                        self.swfdata.append(
                            SWF(name, self.data[swf_offset : (swf_offset + swf_length)])
                        )
                        self.add_coverage(swf_offset, swf_length)
        else:
            self.vprint("Bit 0x000800 - swfdata; NOT PRESENT")

        if feature_mask & 0x1000:
            # A mapping structure that allows looking up SWF data by name.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x001000 - swfmapping; offset: {hex(offset)}")

            if offset != 0:
                self.swfmap = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x001000 - swfmapping; NOT PRESENT")

        if feature_mask & 0x2000:
            # These are shapes as used with the SWF data above. They contain mappings between a
            # loaded texture shape and the region that contains data. They are equivalent to the
            # geo files found in an IFS container.
            length, offset = struct.unpack(
                f"{self.endian}II", self.data[header_offset : (header_offset + 8)]
            )
            self.add_coverage(header_offset, 8)
            header_offset += 8

            self.vprint(
                f"Bit 0x002000 - shapes; count: {length}, offset: {hex(offset)}"
            )

            for x in range(length):
                shape_base_offset = offset + (x * 12)
                if shape_base_offset != 0:
                    name_offset, shape_length, shape_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[shape_base_offset : (shape_base_offset + 12)],
                    )
                    self.add_coverage(shape_base_offset, 12)

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        self.add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = descramble_text(bytedata, self.text_obfuscated)
                    else:
                        name = "<unnamed>"

                    if shape_offset != 0:
                        shape = Shape(
                            name,
                            self.data[shape_offset : (shape_offset + shape_length)],
                        )
                        shape.parse(text_obfuscated=self.text_obfuscated)
                        self.shapes.append(shape)
                        self.add_coverage(shape_offset, shape_length)

                        self.vprint(
                            f"    {name}, length: {shape_length}, offset: {hex(shape_offset)}"
                        )
                        for line in str(shape).split(os.linesep):
                            self.vprint(f"        {line}")

        else:
            self.vprint("Bit 0x002000 - shapes; NOT PRESENT")

        if feature_mask & 0x4000:
            # Mapping so that shapes can be looked up by name to get their offset.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x004000 - shapesmapping; offset: {hex(offset)}")

            if offset != 0:
                self.shapemap = self.descramble_pman(offset)
        else:
            self.vprint("Bit 0x004000 - shapesmapping; NOT PRESENT")

        if feature_mask & 0x8000:
            # One unknown byte, treated as an offset. I have no idea what this is because
            # the games I've looked at don't include this bit.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x008000 - unknown; offset: {hex(offset)}")

            # Since I've never seen this, I'm going to assume that it showing up is
            # bad and make things read only.
            self.read_only = True
        else:
            self.vprint("Bit 0x008000 - unknown; NOT PRESENT")

        if feature_mask & 0x10000:
            # Included font package, BINXRPC encoded. This is basically a texture sheet with an XML
            # pointing at the region in the texture sheet for every renderable character.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            # I am not sure what the unknown byte is for. It always appears as
            # all zeros in all files I've looked at.
            expect_zero, length, binxrpc_offset = struct.unpack(
                f"{self.endian}III", self.data[offset : (offset + 12)]
            )
            self.add_coverage(offset, 12)

            self.vprint(
                f"Bit 0x010000 - fontinfo; offset: {hex(offset)}, binxrpc offset: {hex(binxrpc_offset)}"
            )

            if expect_zero != 0:
                # If we find non-zero versions of this, then that means updating the file is
                # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                raise Exception("Expected a zero in font package header!")

            if binxrpc_offset != 0:
                self.fontdata = self.benc.decode(
                    self.data[binxrpc_offset : (binxrpc_offset + length)]
                )
                self.add_coverage(binxrpc_offset, length)
            else:
                self.fontdata = None
        else:
            self.vprint("Bit 0x010000 - fontinfo; NOT PRESENT")

        if feature_mask & 0x20000:
            # This is the byteswapping headers that allow us to byteswap the SWF data before passing it
            # to AFP core. It is equivalent to the bsi files in an IFS container.
            offset = struct.unpack(
                f"{self.endian}I", self.data[header_offset : (header_offset + 4)]
            )[0]
            self.add_coverage(header_offset, 4)
            header_offset += 4

            self.vprint(f"Bit 0x020000 - swfheaders; offset: {hex(offset)}")

            if offset > 0 and len(self.swfdata) > 0:
                for i in range(len(self.swfdata)):
                    structure_offset = offset + (i * 12)

                    # First word is always zero, as observed. I am not ENTIRELY sure that
                    # the second field is length, but it lines up with everything else
                    # I've observed and seems to make sense.
                    expect_zero, afp_header_length, afp_header = struct.unpack(
                        f"{self.endian}III",
                        self.data[structure_offset : (structure_offset + 12)],
                    )
                    self.vprint(
                        f"    length: {afp_header_length}, offset: {hex(afp_header)}"
                    )
                    self.add_coverage(structure_offset, 12)

                    if expect_zero != 0:
                        # If we find non-zero versions of this, then that means updating the file is
                        # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                        raise Exception("Expected a zero in SWF header!")

                    self.swfdata[i].descramble_info = self.data[
                        afp_header : (afp_header + afp_header_length)
                    ]
                    self.add_coverage(afp_header, afp_header_length)
        else:
            self.vprint("Bit 0x020000 - swfheaders; NOT PRESENT")

        if feature_mask & 0x40000:
            self.vprint("Bit 0x040000 - modern lz mode on")
        else:
            self.vprint("Bit 0x040000 - modern lz mode off")

        if feature_mask & 0x80000:
            self.vprint("Bit 0x080000 - unknown MGA flag on")
        else:
            self.vprint("Bit 0x080000 - unknown MGA flag off")

        if feature_mask & 0xFFF00000:
            # We don't know these bits at all!
            raise Exception(
                f"Invalid bits set in feature mask {hex(feature_mask & 0xFFF80000)}!"
            )

        if header_offset != header_length:
            raise Exception("Failed to parse bitfield of header correctly!")
        if verbose:
            self.print_coverage()

        # Now, parse out the SWF data in each of the SWF structures we found.
        for swf in self.swfdata:
            swf.parse(verbose)

    def write_strings(self, data: bytes, strings: Dict[str, int]) -> bytes:
        tuples: List[Tuple[str, int]] = [(name, strings[name]) for name in strings]
        tuples = sorted(tuples, key=lambda tup: tup[1])

        for string, offset in tuples:
            data = pad(data, offset)
            data += scramble_text(string, self.text_obfuscated)

        return data

    def write_pman(
        self, data: bytes, offset: int, pman: PMAN, string_offsets: Dict[str, int]
    ) -> bytes:
        # First, lay down the PMAN header
        if self.endian == "<":
            magic = b"PMAN"
        elif self.endian == ">":
            magic = b"NAMP"
        else:
            raise Exception("Logic error, unexpected endianness!")

        # Calculate where various data goes
        data = pad(data, offset)
        payload_offset = offset + 28
        string_offset = payload_offset + (len(pman.entries) * 12)
        pending_strings: Dict[str, int] = {}

        data += struct.pack(
            f"{self.endian}4sIIIIII",
            magic,
            0,
            pman.flags1,
            pman.flags2,
            len(pman.entries),
            pman.flags3,
            payload_offset,
        )

        # Now, lay down the individual entries
        datas: List[bytes] = [b""] * len(pman.entries)
        for entry_no, name in enumerate(pman.entries):
            name_crc = TXP2File.crc32(name.encode("ascii"))

            if name not in string_offsets:
                # We haven't written this string out yet, so put it on our pending list.
                pending_strings[name] = string_offset
                string_offsets[name] = string_offset

                # Room for the null byte!
                string_offset += len(name) + 1

            # Write out the chunk itself.
            datas[pman.ordering[entry_no]] = struct.pack(
                f"{self.endian}III",
                name_crc,
                entry_no,
                string_offsets[name],
            )

        # Write it out in the correct order. Some files are hardcoded in various
        # games so we MUST preserve the order of PMAN entries.
        data += b"".join(datas)

        # Now, put down the strings that were new in this pman structure.
        return self.write_strings(data, pending_strings)

    def unparse(self) -> bytes:
        if self.read_only:
            raise Exception("This file is read-only because we can't parse some of it!")

        # Mapping from various strings found in the file to their offsets.
        string_offsets: Dict[str, int] = {}
        pending_strings: Dict[str, int] = {}

        # The true file header, containing magic, some file flags, file length and
        # header length.
        header: bytes = b""

        # The bitfield structure that dictates what's found in the file and where.
        bitfields: bytes = b""

        # The data itself.
        body: bytes = b""

        # First, plop down the file magic as well as the unknown file flags we
        # roundtripped.
        if self.endian == "<":
            header += b"2PXT"
        elif self.endian == ">":
            header += b"TXP2"
        else:
            raise Exception("Invalid graphic file format!")

        # Not sure what words 2 and 3 are, they seem to be some sort of
        # version or date?
        header += self.data[4:12]

        # We can't plop the length down yet, since we don't know it. So, let's first
        # figure out what our bitfield length is.
        header_length = 0
        if self.features & 0x1:
            header_length += 8
        if self.features & 0x2:
            header_length += 4
        # Bit 0x4 is for lz options.
        if self.features & 0x8:
            header_length += 8
        if self.features & 0x10:
            header_length += 4
        # Bit 0x20 is for text obfuscation options.
        if self.features & 0x40:
            header_length += 8
        if self.features & 0x80:
            header_length += 4
        if self.features & 0x100:
            header_length += 8
        if self.features & 0x200:
            header_length += 4
        if self.features & 0x400:
            header_length += 4
        if self.features & 0x800:
            header_length += 8
        if self.features & 0x1000:
            header_length += 4
        if self.features & 0x2000:
            header_length += 8
        if self.features & 0x4000:
            header_length += 4
        if self.features & 0x8000:
            header_length += 4
        if self.features & 0x10000:
            header_length += 4
        if self.features & 0x20000:
            header_length += 4
        # Bit 0x40000 is for lz options.

        # We keep this indirection because we want to do our best to preserve
        # the file order we observe in actual files. So, that means writing data
        # out of order of when it shows in the header, and as such we must remember
        # what chunks go where. We key by feature bitmask so its safe to have empties.
        bitchunks = [b""] * 32

        # Pad out the body for easier calculations below
        body = pad(body, 24 + header_length)

        # Start laying down various file pieces.
        texture_to_update_offset: Dict[str, Tuple[int, bytes]] = {}
        if self.features & 0x01:
            # List of textures that exist in the file, with pointers to their data.
            offset = align(len(body))
            body = pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[0] = struct.pack(f"{self.endian}II", len(self.textures), offset)

            # Now, calculate how long each texture is and formulate the data itself.
            name_to_length: Dict[str, int] = {}

            # Now, possibly compress and lay down textures.
            for texture in self.textures:
                # Construct the TXDT texture format from our parsed results.
                raw_texture = texture.tdxt.toBytes()

                if self.legacy_lz:
                    raise Exception("We don't support legacy lz mode!")
                elif self.modern_lz:
                    if texture.compressed:
                        # We didn't change this texture, use the original compression.
                        compressed_texture = texture.compressed
                    else:
                        # We need to compress the raw texture.
                        lz77 = Lz77()
                        compressed_texture = lz77.compress(raw_texture)

                    # Construct the mini-header and the texture itself.
                    name_to_length[texture.name] = len(compressed_texture) + 8
                    texture_to_update_offset[texture.name] = (
                        0xDEADBEEF,
                        struct.pack(
                            ">II",
                            len(raw_texture),
                            len(compressed_texture),
                        )
                        + compressed_texture,
                    )
                else:
                    # We just need to place the raw texture down.
                    name_to_length[texture.name] = len(raw_texture) + 8
                    texture_to_update_offset[texture.name] = (
                        0xDEADBEEF,
                        struct.pack(
                            ">II",
                            len(raw_texture),
                            len(raw_texture),
                        )
                        + raw_texture,
                    )

            # Now, make sure the texture block is padded to 4 bytes, so we can figure out
            # where strings go.
            string_offset = align(len(body) + (len(self.textures) * 12))

            # Now, write out texture pointers and strings.
            for texture in self.textures:
                if texture.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[texture.name] = string_offset
                    string_offsets[texture.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(texture.name) + 1

                # Write out the chunk itself, remember where we need to fix up later.
                texture_to_update_offset[texture.name] = (
                    len(body) + 8,
                    texture_to_update_offset[texture.name][1],
                )
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[texture.name],
                    name_to_length[texture.name],  # Structure length
                    0xDEADBEEF,  # Structure offset (we will fix this later)
                )

            # Now, put down the texture chunk itself and then strings that were new in this chunk.
            body = self.write_strings(body, pending_strings)
            pending_strings = {}

        if self.features & 0x08:
            # Mapping between individual graphics and their respective textures.
            offset = align(len(body))
            body = pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[3] = struct.pack(
                f"{self.endian}II", len(self.texture_to_region), offset
            )

            for bounds in self.texture_to_region:
                body += struct.pack(
                    f"{self.endian}HHHHH",
                    bounds.textureno,
                    bounds.left,
                    bounds.top,
                    bounds.right,
                    bounds.bottom,
                )

        if self.features & 0x40:
            # Unknown file chunk.
            offset = align(len(body))
            body = pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[6] = struct.pack(f"{self.endian}II", len(self.unknown1), offset)

            # Now, calculate where we can put strings.
            string_offset = align(len(body) + (len(self.unknown1) * 16))

            # Now, write out chunks and strings.
            for entry1 in self.unknown1:
                if entry1.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[entry1.name] = string_offset
                    string_offsets[entry1.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(entry1.name) + 1

                # Write out the chunk itself.
                body += (
                    struct.pack(f"{self.endian}I", string_offsets[entry1.name])
                    + entry1.data
                )

            # Now, put down the strings that were new in this chunk.
            body = self.write_strings(body, pending_strings)
            pending_strings = {}

        if self.features & 0x100:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            offset = align(len(body))
            body = pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[8] = struct.pack(f"{self.endian}II", len(self.unknown2), offset)

            # Now, write out chunks and strings.
            for entry2 in self.unknown2:
                # Write out the chunk itself.
                body += entry2.data

        if self.features & 0x800:
            # This is the names and locations of the SWF data as far as I can tell.
            offset = align(len(body))
            body = pad(body, offset)

            bitchunks[11] = struct.pack(f"{self.endian}II", len(self.swfdata), offset)

            # Now, calculate where we can put SWF data and their names.
            swfdata_offset = align(len(body) + (len(self.swfdata) * 12))
            string_offset = align(
                swfdata_offset + sum(align(len(a.data)) for a in self.swfdata)
            )
            swfdata = b""

            # Now, lay them out.
            for data in self.swfdata:
                if data.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[data.name] = string_offset
                    string_offsets[data.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(data.name) + 1

                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[data.name],
                    len(data.data),
                    swfdata_offset + len(swfdata),
                )
                swfdata += pad(data.data, align(len(data.data)))

            # Now, lay out the data itself and finally string names.
            body = self.write_strings(body + swfdata, pending_strings)
            pending_strings = {}

        if self.features & 0x2000:
            # This is the names and data for shapes as far as I can tell.
            offset = align(len(body))
            body = pad(body, offset)

            bitchunks[13] = struct.pack(f"{self.endian}II", len(self.shapes), offset)

            # Now, calculate where we can put shapes and their names.
            shape_offset = align(len(body) + (len(self.shapes) * 12))
            string_offset = align(
                shape_offset + sum(align(len(s.data)) for s in self.shapes)
            )
            shapedata = b""

            # Now, lay them out.
            for shape in self.shapes:
                if shape.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[shape.name] = string_offset
                    string_offsets[shape.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(shape.name) + 1

                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[shape.name],
                    len(shape.data),
                    shape_offset + len(shapedata),
                )
                shapedata += pad(shape.data, align(len(shape.data)))

            # Now, lay out the data itself and finally string names.
            body = self.write_strings(body + shapedata, pending_strings)
            pending_strings = {}

        if self.features & 0x02:
            # Mapping between texture index and the name of the texture.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[1] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.texturemap, string_offsets)

        if self.features & 0x10:
            # Names of the graphics regions, so we can look into the texture_to_region
            # mapping above.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[4] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.regionmap, string_offsets)

        if self.features & 0x80:
            # One unknown byte, treated as an offset. This is clearly the mapping for the parsed
            # structures from 0x40, but I don't know what those are.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[7] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.unk_pman1, string_offsets)

        if self.features & 0x200:
            # I am pretty sure this is a mapping for the structures parsed at 0x100.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[9] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.unk_pman2, string_offsets)

        if self.features & 0x1000:
            # Mapping of SWF data to their ID.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[12] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.swfmap, string_offsets)

        if self.features & 0x4000:
            # Mapping of shapes to their ID.
            offset = align(len(body))
            body = pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[14] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.shapemap, string_offsets)

        if self.features & 0x10000:
            # Font information.
            offset = align(len(body))
            body = pad(body, offset)

            bitchunks[16] = struct.pack(f"{self.endian}I", offset)

            # Now, encode the font information.
            if self.fontdata is None:
                raise Exception("Container has fontdata, but fontdata is None!")
            fontbytes = self.benc.encode(self.fontdata)
            body += struct.pack(
                f"{self.endian}III",
                0,
                len(fontbytes),
                offset + 12,
            )
            body += fontbytes

        if self.features & 0x400:
            # I haven't seen any files with any meaningful information for this, but
            # it gets included anyway since games seem to parse it.
            offset = align(len(body))
            body = pad(body, offset)

            # Point to current data location (seems to be what original files do too).
            bitchunks[10] = struct.pack(f"{self.endian}I", offset)

        if self.features & 0x8000:
            # Unknown, never seen bit. We shouldn't be here, we set ourselves
            # to read-only.
            raise Exception("This should not be possible!")

        if self.features & 0x20000:
            # SWF header information.
            offset = align(len(body))
            body = pad(body, offset)

            bitchunks[17] = struct.pack(f"{self.endian}I", offset)

            # Now, calculate where we can put SWF headers.
            swfdata_offset = align(len(body) + (len(self.swfdata) * 12))
            swfheader = b""

            # Now, lay them out.
            for data in self.swfdata:
                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    0,
                    len(data.descramble_info),
                    swfdata_offset + len(swfheader),
                )
                swfheader += pad(data.descramble_info, align(len(data.descramble_info)))

            # Now, lay out the header itself
            body += swfheader

        if self.features & 0x01:
            # Now, go back and add texture data to the end of the file, fixing up the
            # pointer to said data we wrote down earlier.
            for texture in self.textures:
                # Grab the offset we need to fix, our current offset and place
                # the texture data itself down.
                fix_offset, texture_data = texture_to_update_offset[texture.name]
                offset = align(len(body))
                body = pad(body, offset) + texture_data

                # Now, update the patch location to make sure we point at the texture data.
                body = (
                    body[:fix_offset]
                    + struct.pack(f"{self.endian}I", offset)
                    + body[(fix_offset + 4) :]
                )

        # Bit 0x40000 is for lz options.

        # Now, no matter what happened above, make sure file is aligned to 4 bytes.
        offset = align(len(body))
        body = pad(body, offset)

        # Record the bitfield options into the bitfield structure, and we can
        # get started writing the file out.
        bitfields = struct.pack(f"{self.endian}I", self.features) + b"".join(bitchunks)

        # Finally, now that we know the full file length, we can finish
        # writing the header.
        header += struct.pack(f"{self.endian}II", len(body), header_length + 24)
        if len(header) != 20:
            raise Exception("Logic error, incorrect header length!")

        # Skip over padding to the body that we inserted specifically to track offsets
        # against the headers.
        return header + bitfields + body[(header_length + 24) :]

    def update_texture(self, name: str, png_data: bytes) -> None:
        for texture in self.textures:
            if texture.name == name:
                # First, let's get the dimensions of this new picture and
                # ensure that it is identical to the existing one.
                img = Image.open(io.BytesIO(png_data))
                if img.width != texture.width or img.height != texture.height:
                    raise Exception("Cannot update texture with different size!")

                # Now, get the raw image data, and let the TDXT container refresh the raw.
                img = img.convert("RGBA")
                texture.img = img

                return
        else:
            raise Exception(f"There is no texture named {name}!")

    def update_sprite(self, texture: str, sprite: str, png_data: bytes) -> None:
        # First, identify the bounds where the texture lives.
        for no, name in enumerate(self.texturemap.entries):
            if name == texture:
                textureno = no
                break
        else:
            raise Exception(f"There is no texture named {texture}!")

        for no, name in enumerate(self.regionmap.entries):
            if name == sprite:
                region = self.texture_to_region[no]
                if region.textureno == textureno:
                    # We found the region associated with the sprite we want to update.
                    break
        else:
            raise Exception(f"There is no sprite named {sprite} on texture {texture}!")

        # Now, figure out if the PNG data we got is valid.
        sprite_img = Image.open(io.BytesIO(png_data))
        if sprite_img.width != (
            (region.right // 2) - (region.left // 2)
        ) or sprite_img.height != ((region.bottom // 2) - (region.top // 2)):
            raise Exception("Cannot update sprite with different size!")

        # Now, copy the data over and update the raw texture.
        for tex in self.textures:
            if tex.name == texture:
                # Now, composite and refresh the texture so when we save the file its updated.
                img = tex.img
                img.paste(sprite_img, (region.left // 2, region.top // 2))
                tex.img = img
