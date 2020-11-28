# vim: set fileencoding=utf-8
import os
import random
import unittest

from bemani.protocol.lz77 import Lz77, Lz77Decompress


class TestLZ77Decompressor(unittest.TestCase):
    def test_ringbuffer_fuzz(self) -> None:
        dec = Lz77Decompress(b'')

        for _ in range(100):
            amount = random.randint(1, Lz77Decompress.RING_LENGTH)
            data = os.urandom(amount)

            # Save our ring position, write a chunk of data
            readpos = dec.write_pos
            dec._Lz77Decompress__ring_write(data)

            # Read a chunk of data back from that buffer, see its the same
            newdata = b''.join(dec._Lz77Decompress__ring_read(readpos, amount))
            self.assertEqual(data, newdata)

            # Verify integrity of ringbuffer
            self.assertEqual(len(dec.ring), Lz77Decompress.RING_LENGTH)


def get_fixture(name: str) -> bytes:
    location = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(location, name), "rb") as fp:
        return fp.read()


class TestLz77RealCompressor(unittest.TestCase):
    def test_small_data_random(self) -> None:
        lz77 = Lz77()
        data = os.urandom(1 * 1024)

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_large_data_random(self) -> None:
        lz77 = Lz77()
        data = os.urandom(100 * 1024)

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_huge_data_random(self) -> None:
        lz77 = Lz77()
        data = os.urandom(1 * 1024 * 1024)

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_declaration(self) -> None:
        lz77 = Lz77()
        data = get_fixture("declaration.txt")

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)
        self.assertTrue(len(compresseddata) < len(data))

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_lorem_ipsum(self) -> None:
        lz77 = Lz77()
        data = get_fixture("lorem.txt")

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)
        self.assertTrue(len(compresseddata) < len(data))

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_texture(self) -> None:
        lz77 = Lz77()
        data = get_fixture("rawdata")

        compresseddata = lz77.compress(data)
        self.assertNotEqual(data, compresseddata)
        self.assertTrue(len(compresseddata) < len(data))

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)

    def test_known_compression(self) -> None:
        """
        Specifically tests for ability to compress an overlap,
        verifies that we don't regress on known compressions.
        """
        lz77 = Lz77()
        data = b"abcabcabcabc"
        compresseddata = lz77.compress(data)
        self.assertEqual(b"\x07abc\x006\x00\x00", compresseddata)

        decompresseddata = lz77.decompress(compresseddata)
        self.assertEqual(data, decompresseddata)
