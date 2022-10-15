# vim: set fileencoding=utf-8
import random
import unittest

from bemani.protocol.protocol import EAmuseProtocol


class TestRC4Cipher(unittest.TestCase):
    def test_crypto(self) -> None:
        key = b"12345"
        data = b"This is a wonderful text string to cypher."
        encrypted = b"\x04]Q\x11\x0cw\x7fO\xfa\x03\xa3\xdf\xb6\x02\xb7d\x9f\x13U\x19\xc9-j\x96\x15yl\x98\xee_<\xfa\x9b\x8f\xbe}\xf4\x05l5\x0e\xd6"
        proto = EAmuseProtocol()

        cyphertext = proto._rc4_crypt(data, key)
        self.assertEqual(encrypted, cyphertext)

        plaintext = proto._rc4_crypt(cyphertext, key)
        self.assertEqual(data, plaintext)

    def test_small_data_random(self) -> None:
        data = bytes([random.randint(0, 255) for _ in range(1 * 1024)])
        key = bytes([random.randint(0, 255) for _ in range(16)])
        proto = EAmuseProtocol()

        cyphertext = proto._rc4_crypt(data, key)
        self.assertNotEqual(data, cyphertext)

        plaintext = proto._rc4_crypt(cyphertext, key)
        self.assertEqual(data, plaintext)

    def test_large_data_random(self) -> None:
        data = bytes([random.randint(0, 255) for _ in range(100 * 1024)])
        key = bytes([random.randint(0, 255) for _ in range(16)])
        proto = EAmuseProtocol()

        cyphertext = proto._rc4_crypt(data, key)
        self.assertNotEqual(data, cyphertext)

        plaintext = proto._rc4_crypt(cyphertext, key)
        self.assertEqual(data, plaintext)
