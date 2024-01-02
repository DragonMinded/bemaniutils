# vim: set fileencoding=utf-8
import unittest

from bemani.common import AESCipher


class TestAESCipher(unittest.TestCase):
    def test_pad(self) -> None:
        aes = AESCipher("a wonderful key")
        self.assertEqual(aes._pad(""), "0.--------------")
        self.assertEqual(aes._unpad(aes._pad("")), "")
        self.assertEqual(aes._pad("1337"), "4.1337----------")
        self.assertEqual(aes._unpad(aes._pad("1337")), "1337")
        self.assertEqual(aes._pad("aaaaaaaaaaaaaaaa"), "16.aaaaaaaaaaaaaaaa-------------")
        self.assertEqual(aes._unpad(aes._pad("aaaaaaaaaaaaaaaa")), "aaaaaaaaaaaaaaaa")
        self.assertEqual(aes._pad("aaaaaaaaaaaaa"), "13.aaaaaaaaaaaaa")
        self.assertEqual(aes._unpad(aes._pad("aaaaaaaaaaaaa")), "aaaaaaaaaaaaa")

    def test_crypto(self) -> None:
        aes = AESCipher("a wonderful key")
        ciphertext = aes.encrypt("testing")
        plaintext = aes.decrypt(ciphertext)
        self.assertEqual(plaintext, "testing")
        self.assertNotEqual(ciphertext, plaintext)
