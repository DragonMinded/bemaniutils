import struct
from PIL import Image
from typing import Optional

from bemani.format.dxt import DXTBuffer


class TDXT:
    def __init__(
        self,
        header_flags1: int,
        header_flags2: int,
        header_flags3: int,
        width: int,
        height: int,
        fmt: int,
        fmtflags: int,
        endian: str,
        raw: bytes,
        img: Optional[Image.Image],
    ) -> None:
        self.header_flags1 = header_flags1
        self.header_flags2 = header_flags2
        self.header_flags3 = header_flags3
        self.width = width
        self.height = height
        self.fmt = fmt
        self.fmtflags = fmtflags
        self.endian = endian
        self.__raw = raw
        self.__img = img

    @property
    def raw(self) -> bytes:
        return self.__raw

    @raw.setter
    def raw(self, newdata: bytes) -> None:
        self.__raw = newdata
        newimg = self._rawToImg(self.width, self.height, self.fmt, self.endian, newdata)
        width, height = newimg.size
        if width != self.width or height != self.height:
            raise Exception("Unsupported texture resize operation for TDXT file!")
        self.__img = newimg

    @property
    def img(self) -> Optional[Image.Image]:
        return self.__img

    @img.setter
    def img(self, newimg: Image.Image) -> None:
        self.__img = newimg
        self.__raw = self._imgToRaw(newimg)

    @staticmethod
    def fromBytes(raw_data: bytes) -> "TDXT":
        # First, check the endianness.
        (magic,) = struct.unpack_from("4s", raw_data)

        if magic == b"TDXT":
            endian = "<"
        elif magic == b"TXDT":
            endian = ">"
        else:
            raise Exception("Unexpected texture format!")

        (
            magic,
            header_flags1,
            header_flags2,
            raw_length,
            width,
            height,
            fmtflags,
            expected_zero1,
            expected_zero2,
        ) = struct.unpack(
            f"{endian}4sIIIHHIII",
            raw_data[0:32],
        )
        if raw_length != len(raw_data):
            raise Exception("Invalid texture length!")

        # I have only ever observed the following values across two different games.
        # Don't want to keep the chunk around so let's assert our assumptions.
        if (expected_zero1 | expected_zero2) != 0:
            raise Exception("Found unexpected non-zero value in texture header!")
        if raw_data[32:44] != b"\0" * 12:
            raise Exception("Found unexpected non-zero value in texture header!")

        # This is almost ALWAYS 3, but I've seen it be 1 as well, so I guess we have to
        # round-trip it if we want to write files back out. I have no clue what it's for.
        # I've seen it be 1 only on files used for fonts so far, but I am not sure there
        # is any correlation there.
        header_flags3 = struct.unpack(f"{endian}I", raw_data[44:48])[0]
        if raw_data[48:64] != b"\0" * 16:
            raise Exception("Found unexpected non-zero value in texture header!")
        fmt = fmtflags & 0xFF

        # Extract flags that the game cares about.
        # flags1 = (fmtflags >> 24) & 0xFF
        # flags2 = (fmtflags >> 16) & 0xFF

        # unk1 = 3 if (flags1 & 0xF == 1) else 1
        # unk2 = 3 if ((flags1 >> 4) & 0xF == 1) else 1
        # unk3 = 1 if (flags2 & 0xF == 1) else 2
        # unk4 = 1 if ((flags2 >> 4) & 0xF == 1) else 2

        # Convert texture to image if possible, create structure.
        return TDXT(
            header_flags1=header_flags1,
            header_flags2=header_flags2,
            header_flags3=header_flags3,
            width=width,
            height=height,
            fmt=fmt,
            fmtflags=fmtflags & 0xFFFFFF00,
            endian=endian,
            raw=raw_data[64:],
            img=TDXT._rawToImg(width, height, fmt, endian, raw_data[64:]),
        )

    @staticmethod
    def _rawToImg(
        width: int, height: int, fmt: int, endian: str, raw_data: bytes
    ) -> Optional[Image.Image]:
        # Since the AFP file format can be found in both big and little endian, its
        # possible that some of these loaders might need byteswapping on some platforms.
        # This has been tested on files intended for X86 (little endian) as well as PS3
        # (big endian). I've found that the "correct" thing to do is always treat data as
        # little-endian instead of the determined endianness of the file. But, this could
        # also be broken per-game, so I'm not entirely sure this is fully possible to do
        # generically. However, what's here has been tested across a broad range of games
        # and does seem to work.

        if fmt == 0x01:
            # As far as I can tell, this is 8 bit grayscale. Decoding as such results in
            # images that are recognizeable and look correct.
            img = Image.frombytes(
                "L",
                (width, height),
                raw_data,
                "raw",
                "L",
            )
        elif fmt == 0x0B:
            # 16-bit 565 color RGB format. Game references D3D9 texture format 23 (R5G6B5).
            newdata = []
            for i in range(width * height):
                pixel = struct.unpack(
                    "<H",
                    raw_data[(i * 2) : (2 + (i * 2))],
                )[0]

                # Extract the raw values
                red = ((pixel >> 0) & 0x1F) << 3
                green = ((pixel >> 5) & 0x3F) << 2
                blue = ((pixel >> 11) & 0x1F) << 3

                # Scale the colors so they fill the entire 8 bit range.
                red = red | (red >> 5)
                green = green | (green >> 6)
                blue = blue | (blue >> 5)

                newdata.append(struct.pack("<BBB", blue, green, red))
            img = Image.frombytes(
                "RGB",
                (width, height),
                b"".join(newdata),
                "raw",
                "RGB",
            )
        elif fmt == 0x0E:
            # RGB image, no alpha. Game references D3D9 texture format 22 (R8G8B8).
            img = Image.frombytes(
                "RGB",
                (width, height),
                raw_data,
                "raw",
                "RGB",
            )
        elif fmt == 0x10:
            # Seems to be some sort of RGBA with color swapping. Game references D3D9 texture
            # format 21 (A8R8B8G8) but does manual byteswapping.
            img = Image.frombytes(
                "RGBA",
                (width, height),
                raw_data,
                "raw",
                "BGRA",
            )
        elif fmt == 0x13:
            # Some 16-bit texture format. Game references D3D9 texture format 25 (A1R5G5B5).
            newdata = []
            for i in range(width * height):
                pixel = struct.unpack(
                    "<H",
                    raw_data[(i * 2) : (2 + (i * 2))],
                )[0]

                # Extract the raw values
                alpha = 255 if ((pixel >> 15) & 0x1) != 0 else 0
                red = ((pixel >> 0) & 0x1F) << 3
                green = ((pixel >> 5) & 0x1F) << 3
                blue = ((pixel >> 10) & 0x1F) << 3

                # Scale the colors so they fill the entire 8 bit range.
                red = red | (red >> 5)
                green = green | (green >> 5)
                blue = blue | (blue >> 5)

                newdata.append(struct.pack("<BBBB", blue, green, red, alpha))
            img = Image.frombytes(
                "RGBA",
                (width, height),
                b"".join(newdata),
                "raw",
                "RGBA",
            )
        elif fmt == 0x15:
            # RGBA format. Game references D3D9 texture format 21 (A8R8G8B8).
            # Looks like unlike 0x20 below, the game does some endianness swapping.
            img = Image.frombytes(
                "RGBA",
                (width, height),
                raw_data,
                "raw",
                "ARGB",
            )
        elif fmt == 0x16:
            # DXT1 format. Game references D3D9 DXT1 texture format.
            # Konami seems to have screwed up with DDR PS3 where they
            # swap every other byte in the format, even though its specified
            # as little-endian by all DXT1 documentation.
            dxt = DXTBuffer(width, height)
            img = Image.frombuffer(
                "RGBA",
                (width, height),
                dxt.DXT1Decompress(raw_data, swap=endian != "<"),
                "raw",
                "RGBA",
                0,
                1,
            )
        elif fmt == 0x1A:
            # DXT5 format. Game references D3D9 DXT5 texture format.
            # Konami seems to have screwed up with DDR PS3 where they
            # swap every other byte in the format, even though its specified
            # as little-endian by all DXT5 documentation.
            dxt = DXTBuffer(width, height)
            img = Image.frombuffer(
                "RGBA",
                (width, height),
                dxt.DXT5Decompress(raw_data, swap=endian != "<"),
                "raw",
                "RGBA",
                0,
                1,
            )
        elif fmt == 0x1E:
            # I have no idea what format this is. The game does some byte
            # swapping but doesn't actually call any texture create calls.
            # This might be leftover from another game.
            pass
        elif fmt == 0x1F:
            # 16-bit 4-4-4-4 RGBA format. Game references D3D9 texture format 26 (A4R4G4B4).
            newdata = []
            for i in range(width * height):
                pixel = struct.unpack(
                    "<H",
                    raw_data[(i * 2) : (2 + (i * 2))],
                )[0]

                # Extract the raw values
                blue = ((pixel >> 0) & 0xF) << 4
                green = ((pixel >> 4) & 0xF) << 4
                red = ((pixel >> 8) & 0xF) << 4
                alpha = ((pixel >> 12) & 0xF) << 4

                # Scale the colors so they fill the entire 8 bit range.
                red = red | (red >> 4)
                green = green | (green >> 4)
                blue = blue | (blue >> 4)
                alpha = alpha | (alpha >> 4)

                newdata.append(struct.pack("<BBBB", red, green, blue, alpha))
            img = Image.frombytes(
                "RGBA",
                (width, height),
                b"".join(newdata),
                "raw",
                "RGBA",
            )
        elif fmt == 0x20:
            # RGBA format. Game references D3D9 surface format 21 (A8R8G8B8).
            img = Image.frombytes(
                "RGBA",
                (width, height),
                raw_data,
                "raw",
                "BGRA",
            )
        else:
            img = None

        return img

    def toBytes(self) -> bytes:
        # Construct the TDXT texture format from our parsed results.
        if self.endian == "<":
            magic = b"TDXT"
        elif self.endian == ">":
            magic = b"TXDT"
        else:
            raise Exception("Unexpected texture format!")

        fmtflags = (self.fmtflags & 0xFFFFFF00) | (self.fmt & 0xFF)

        return (
            struct.pack(
                f"{self.endian}4sIIIHHIII",
                magic,
                self.header_flags1,
                self.header_flags2,
                64 + len(self.raw),
                self.width,
                self.height,
                fmtflags,
                0,
                0,
            )
            + (b"\0" * 12)
            + struct.pack(
                f"{self.endian}I",
                self.header_flags3,
            )
            + (b"\0" * 16)
            + self.raw
        )

    def _imgToRaw(self, imgdata: Image.Image) -> bytes:
        width, height = imgdata.size
        if width != self.width or height != self.height:
            raise Exception("Unsupported texture resize operation for TDXT file!")

        if self.fmt == 0x0B:
            # 16-bit 565 color RGB format.
            raw = b"".join(
                struct.pack(
                    "<H",
                    (
                        (((pixel[0] >> 3) & 0x1F) << 11)
                        | (((pixel[1] >> 2) & 0x3F) << 5)
                        | ((pixel[2] >> 3) & 0x1F)
                    ),
                )
                for pixel in imgdata.getdata()
            )
        elif self.fmt == 0x13:
            # 16-bit A1R5G55 texture format.
            raw = b"".join(
                struct.pack(
                    "<H",
                    (
                        (0x8000 if pixel[3] >= 128 else 0x0000)
                        | (((pixel[0] >> 3) & 0x1F) << 10)
                        | (((pixel[1] >> 3) & 0x1F) << 5)
                        | ((pixel[2] >> 3) & 0x1F)
                    ),
                )
                for pixel in imgdata.getdata()
            )
        elif self.fmt == 0x1F:
            # 16-bit 4-4-4-4 RGBA format.
            raw = b"".join(
                struct.pack(
                    "<H",
                    (
                        ((pixel[2] >> 4) & 0xF)
                        | (((pixel[1] >> 4) & 0xF) << 4)
                        | (((pixel[0] >> 4) & 0xF) << 8)
                        | (((pixel[3] >> 4) & 0xF) << 12)
                    ),
                )
                for pixel in imgdata.getdata()
            )
        elif self.fmt == 0x20:
            # 32-bit RGBA format, stored in BGRA order.
            raw = b"".join(
                struct.pack(
                    "<BBBB",
                    pixel[2],
                    pixel[1],
                    pixel[0],
                    pixel[3],
                )
                for pixel in imgdata.getdata()
            )
        else:
            raise Exception(f"Unsupported format {hex(self.fmt)} for TDXT file!")

        return raw
