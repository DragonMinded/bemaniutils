# vim: set fileencoding=utf-8
import unittest

from bemani.common import CardCipher


class TestCardCipher(unittest.TestCase):
    def test_internal_cipher(self) -> None:
        test_ciphers = [
            (
                [0x68, 0xFC, 0xA5, 0x27, 0x00, 0x01, 0x04, 0xE0],
                [0xC7, 0xD0, 0xB3, 0x85, 0xAD, 0x1F, 0xD9, 0x49],
            ),
            (
                [0x2C, 0x10, 0xA6, 0x27, 0x00, 0x01, 0x04, 0xE0],
                [0x33, 0xC6, 0xE6, 0x2E, 0x6E, 0x33, 0x38, 0x74],
            ),
        ]

        for pair in test_ciphers:
            inp = bytes(pair[0])
            out = bytes(pair[1])
            encoded = CardCipher.INTERNAL_CIPHER.encrypt(inp)
            self.assertEqual(
                encoded, out, f"Card encode {encoded!r} doesn't match expected {out!r}"
            )
            decoded = CardCipher.INTERNAL_CIPHER.decrypt(out)
            self.assertEqual(
                decoded, inp, f"Card decode {decoded!r} doesn't match expected {inp!r}"
            )

    def test_external_cipher(self) -> None:
        test_cards = [
            ("S6E523E30ZK7ML1P", "E004010027A5FC68"),
            ("78B592HZSM9E6712", "E004010027A6102C"),
        ]

        for card in test_cards:
            back = card[0]
            db = card[1]
            decoded = CardCipher.decode(back)
            self.assertEqual(
                decoded, db, f"Card DB {decoded} doesn't match expected {db}"
            )
            encoded = CardCipher.encode(db)
            self.assertEqual(
                encoded, back, f"Card back {encoded} doesn't match expected {back}"
            )
