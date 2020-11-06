"""
S3TC DXT1/DXT5 Texture Decompression

Adapted from https://github.com/leamsii/Python-DXT-Decompress to add types
and take in bytes instead of file pointers. Inspired by Benjamin Dobell.

Original C++ code https://github.com/Benjamin-Dobell/s3tc-dxt-decompression
"""

import io
import struct

from typing import List, Optional, Tuple


def unpack(endian: str, _bytes: bytes) -> int:
    STRUCT_SIGNS = {
        1: 'B',
        2: 'H',
        4: 'I',
        8: 'Q'
    }
    return struct.unpack(endian + STRUCT_SIGNS[len(_bytes)], _bytes)[0]


# This function converts RGB565 format to raw pixels
def unpackRGB(packed: int) -> Tuple[int, int, int, int]:
    R = (packed >> 11) & 0x1F
    G = (packed >> 5) & 0x3F
    B = (packed) & 0x1F

    R = (R << 3) | (R >> 2)
    G = (G << 2) | (G >> 4)
    B = (B << 3) | (B >> 2)

    return (R, G, B, 255)


class DXTBuffer:
    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height

        self.block_countx = self.width // 4
        self.block_county = self.height // 4

        self.decompressed_buffer: List[Optional[bytes]] = [None] * ((width * height) * 2)  # Dont ask me why

    def DXT5Decompress(self, filedata: bytes, endian: str = "<") -> bytes:
        # Loop through each block and decompress it
        file = io.BytesIO(filedata)
        for row in range(self.block_county):
            for col in range(self.block_countx):
                # Get the alpha values
                a0 = unpack(endian, file.read(1))
                a1 = unpack(endian, file.read(1))
                atable = file.read(6)

                acode0 = atable[2] | (atable[3] << 8) | (atable[4] << 16) | (atable[5] << 24)
                acode1 = atable[0] | (atable[1] << 8)

                # Color 1 color 2, color look up table
                c0 = unpack(endian, file.read(2))
                c1 = unpack(endian, file.read(2))
                ctable = unpack(endian, file.read(4))

                # The 4x4 Lookup table loop
                for j in range(4):
                    for i in range(4):
                        alpha = self.getAlpha(i, j, a0, a1, acode0, acode1)
                        self.getColors(
                            col * 4,
                            row * 4,
                            i,
                            j,
                            ctable,
                            unpackRGB(c0),
                            unpackRGB(c1),
                            alpha,
                        )  # Set the color for the current pixel

        return b''.join([x for x in self.decompressed_buffer if x is not None])

    def DXT1Decompress(self, filedata: bytes, endian: str = "<") -> bytes:
        # Loop through each block and decompress it
        file = io.BytesIO(filedata)
        for row in range(self.block_county):
            for col in range(self.block_countx):

                # Color 1 color 2, color look up table
                c0 = unpack(endian, file.read(2))
                c1 = unpack(endian, file.read(2))
                ctable = unpack(endian, file.read(4))

                # The 4x4 Lookup table loop
                for j in range(4):
                    for i in range(4):
                        self.getColors(
                            col * 4,
                            row * 4,
                            i,
                            j,
                            ctable,
                            unpackRGB(c0),
                            unpackRGB(c1),
                            255,
                        )  # Set the color for the current pixel

        return b''.join([_ for _ in self.decompressed_buffer if _ != 'X'])

    def getColors(
        self,
        x: int,
        y: int,
        i: int,
        j: int,
        ctable: int,
        c0: Tuple[int, int, int, int],
        c1: Tuple[int, int, int, int],
        alpha: int,
    ) -> None:
        code = (ctable >> (2 * ((4 * j) + i))) & 0x03  # Get the color of the current pixel
        pixel_color = None

        r0 = c0[0]
        g0 = c0[1]
        b0 = c0[2]

        r1 = c1[0]
        g1 = c1[1]
        b1 = c1[2]

        # Sliding scale between colors.
        if code == 0:
            pixel_color = (r0, g0, b0, alpha)
        if code == 1:
            pixel_color = (r1, g1, b1, alpha)
        if code == 2:
            pixel_color = ((2 * r0 + r1) // 3, (2 * g0 + g1) // 3, (2 * b0 + b1) // 3, alpha)
        if code == 3:
            pixel_color = ((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3, (b0 + 2 * b1) // 3, alpha)

        # While not surpassing the image dimensions, assign pixels the colors.
        if (x + i) < self.width and (y + j) < self.height:
            self.decompressed_buffer[(y + j) * self.width + (x + i)] = (
                struct.pack('<BBBB', *pixel_color)
            )

    def getAlpha(self, i: int, j: int, a0: int, a1: int, acode0: int, acode1: int) -> int:
        # Using the same method as the colors calculate the alpha values
        alpha_index = 3 * ((4 * j) + i)
        alpha_code = None

        if alpha_index <= 12:
            alpha_code = (acode1 >> alpha_index) & 0x07
        elif alpha_index == 15:
            alpha_code = (acode1 >> 15) | ((acode0 << 1) & 0x06)
        else:
            alpha_code = (acode0 >> (alpha_index - 16)) & 0x07

        if alpha_code == 0:
            alpha = a0
        elif alpha_code == 1:
            alpha = a1
        else:
            if a0 > a1:
                alpha = ((8 - alpha_code) * a0 + (alpha_code - 1) * a1) // 7
            else:
                if alpha_code == 6:
                    alpha = 0
                elif alpha_code == 7:
                    alpha = 255
                else:
                    alpha = ((6 - alpha_code) * a0 + (alpha_code - 1) * a1) // 5
        return alpha
