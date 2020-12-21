"""
S3TC DXT1/DXT5 Texture Decompression

Adapted from https://github.com/leamsii/Python-DXT-Decompress to add types
and take in bytes instead of file pointers. Inspired by Benjamin Dobell.

Original C++ code https://github.com/Benjamin-Dobell/s3tc-dxt-decompression
"""

import io
import struct

from typing import List, Optional, Tuple


class DXTBuffer:
    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height

        self.block_countx = self.width // 4
        self.block_county = self.height // 4

        self.decompressed_buffer: List[Optional[bytes]] = [None] * ((width * height) * 2)

    def unpackRGB(self, packed: int) -> Tuple[int, int, int]:
        # This function converts RGB565 format to raw pixels
        R = (packed >> 11) & 0x1F
        G = (packed >> 5) & 0x3F
        B = (packed) & 0x1F

        R = (R << 3) | (R >> 2)
        G = (G << 2) | (G >> 4)
        B = (B << 3) | (B >> 2)

        return (R, G, B)

    def swapbytes(self, data: bytes, swap: bool) -> bytes:
        if swap:
            return b"".join([
                data[(x + 1):(x + 2)] + data[x:(x + 1)]
                for x in range(0, len(data), 2)
            ])
        return data

    def DXT5Decompress(self, filedata: bytes, swap: bool = False) -> bytes:
        # Loop through each block and decompress it
        file = io.BytesIO(filedata)
        for row in range(self.block_county):
            for col in range(self.block_countx):
                # Get the alpha values, and color lookup table
                a0, a1, acode0, acode1, c0, c1, ctable = struct.unpack("<BBHIHHI", self.swapbytes(file.read(16), swap))

                # The 4x4 Lookup table loop
                for j in range(4):
                    for i in range(4):
                        self.getColors(
                            col * 4,
                            row * 4,
                            i,
                            j,
                            ctable,
                            c0,
                            c1,
                            self.getAlpha(i, j, a0, a1, (acode1 << 16) | acode0),
                        )  # Set the color for the current pixel

        return b''.join([x for x in self.decompressed_buffer if x is not None])

    def DXT1Decompress(self, filedata: bytes, swap: bool = False) -> bytes:
        # Loop through each block and decompress it
        file = io.BytesIO(filedata)
        for row in range(self.block_county):
            for col in range(self.block_countx):

                # Color 1 color 2, color look up table
                c0, c1, ctable = struct.unpack("<HHI", self.swapbytes(file.read(8), swap))

                # The 4x4 Lookup table loop
                for j in range(4):
                    for i in range(4):
                        self.getColors(
                            col * 4,
                            row * 4,
                            i,
                            j,
                            ctable,
                            c0,
                            c1,
                            255,
                        )  # Set the color for the current pixel

        return b''.join([x for x in self.decompressed_buffer if x is not None])

    def getColors(
        self,
        x: int,
        y: int,
        i: int,
        j: int,
        ctable: int,
        c0: int,
        c1: int,
        alpha: int,
    ) -> None:
        code = (ctable >> (2 * ((4 * j) + i))) & 0x03  # Get the color of the current pixel
        pixel_color = None

        r0, g0, b0 = self.unpackRGB(c0)
        r1, g1, b1 = self.unpackRGB(c1)

        # Sliding scale between colors.
        if code == 0:
            pixel_color = (r0, g0, b0, alpha)
        if code == 1:
            pixel_color = (r1, g1, b1, alpha)
        if code == 2:
            if c0 > c1:
                pixel_color = ((2 * r0 + r1) // 3, (2 * g0 + g1) // 3, (2 * b0 + b1) // 3, alpha)
            else:
                pixel_color = ((r0 + r1) // 2, (g0 + g1) // 2, (b0 + b1) // 2, alpha)
        if code == 3:
            if c0 > c1:
                pixel_color = ((r0 + 2 * r1) // 3, (g0 + 2 * g1) // 3, (b0 + 2 * b1) // 3, alpha)
            else:
                pixel_color = (0, 0, 0, alpha)

        # While not surpassing the image dimensions, assign pixels the colors.
        if (x + i) < self.width and (y + j) < self.height:
            self.decompressed_buffer[(y + j) * self.width + (x + i)] = (
                struct.pack('<BBBB', *pixel_color)
            )

    def getAlpha(self, i: int, j: int, a0: int, a1: int, acode: int) -> int:
        # Using the same method as the colors calculate the alpha values
        alpha_code = (acode >> (3 * ((4 * j) + i))) & 0x07

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
