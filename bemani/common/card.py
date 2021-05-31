from typing import Dict, Final, List


class CardCipherException(Exception):
    pass


class CardCipher:
    """
    Algorithm for converting between the Card ID as stored in an
    eAmusement card and the 16 character card string as shown on
    the back of a card and in-game. All of this was kindly RE'd by
    Tau and converted ham-fistedly to Python.
    """

    KEY: Final[List[int]] = [
        0x20d0d03c, 0x868ecb41, 0xbcd89c84, 0x4c0e0d0d,
        0x84fc30ac, 0x4cc1890e, 0xfc5418a4, 0x02c50f44,
        0x68acb4e0, 0x06cd4a4e, 0xcc28906c, 0x4f0c8ac0,
        0xb03ca468, 0x884ac7c4, 0x389490d8, 0xcf80c6c2,
        0x58d87404, 0xc48ec444, 0xb4e83c50, 0x498d0147,
        0x64f454c0, 0x4c4701c8, 0xec302cc4, 0xc6c949c1,
        0xc84c00f0, 0xcdcc49cc, 0x883c5cf4, 0x8b0fcb80,
        0x703cc0b0, 0xcb820a8d, 0x78804c8c, 0x4fca830e,
        0x80d0f03c, 0x8ec84f8c, 0x98c89c4c, 0xc80d878f,
        0x54bc949c, 0xc801c5ce, 0x749078dc, 0xc3c80d46,
        0x2c8070f0, 0x0cce4dcf, 0x8c3874e4, 0x8d448ac3,
        0x987cac70, 0xc0c20ac5, 0x288cfc78, 0xc28543c8,
        0x4c8c7434, 0xc50e4f8d, 0x8468f4b4, 0xcb4a0307,
        0x2854dc98, 0x48430b45, 0x6858fce8, 0x4681cd49,
        0xd04808ec, 0x458d0fcb, 0xe0a48ce4, 0x880f8fce,
        0x7434b8fc, 0xce080a8e, 0x5860fc6c, 0x46c886cc,
        0xd01098a4, 0xce090b8c, 0x1044cc2c, 0x86898e0f,
        0xd0809c3c, 0x4a05860f, 0x54b4f80c, 0x4008870e,
        0x1480b88c, 0x0ac8854f, 0x1c9034cc, 0x08444c4e,
        0x0cb83c64, 0x41c08cc6, 0x1c083460, 0xc0c603ce,
        0x2ca0645c, 0x818246cb, 0x0408e454, 0xc5464487,
        0x88607c18, 0xc1424187, 0x284c7c90, 0xc1030509,
        0x40486c94, 0x4603494b, 0xe0404ce4, 0x4109094d,
        0x60443ce4, 0x4c0b8b8d, 0xe054e8bc, 0x02008e89,
    ]

    LUT_A0: Final[List[int]] = [
        0x02080008, 0x02082000, 0x00002008, 0x00000000,
        0x02002000, 0x00080008, 0x02080000, 0x02082008,
        0x00000008, 0x02000000, 0x00082000, 0x00002008,
        0x00082008, 0x02002008, 0x02000008, 0x02080000,
        0x00002000, 0x00082008, 0x00080008, 0x02002000,
        0x02082008, 0x02000008, 0x00000000, 0x00082000,
        0x02000000, 0x00080000, 0x02002008, 0x02080008,
        0x00080000, 0x00002000, 0x02082000, 0x00000008,
        0x00080000, 0x00002000, 0x02000008, 0x02082008,
        0x00002008, 0x02000000, 0x00000000, 0x00082000,
        0x02080008, 0x02002008, 0x02002000, 0x00080008,
        0x02082000, 0x00000008, 0x00080008, 0x02002000,
        0x02082008, 0x00080000, 0x02080000, 0x02000008,
        0x00082000, 0x00002008, 0x02002008, 0x02080000,
        0x00000008, 0x02082000, 0x00082008, 0x00000000,
        0x02000000, 0x02080008, 0x00002000, 0x00082008,
    ]

    LUT_A1: Final[List[int]] = [
        0x08000004, 0x00020004, 0x00000000, 0x08020200,
        0x00020004, 0x00000200, 0x08000204, 0x00020000,
        0x00000204, 0x08020204, 0x00020200, 0x08000000,
        0x08000200, 0x08000004, 0x08020000, 0x00020204,
        0x00020000, 0x08000204, 0x08020004, 0x00000000,
        0x00000200, 0x00000004, 0x08020200, 0x08020004,
        0x08020204, 0x08020000, 0x08000000, 0x00000204,
        0x00000004, 0x00020200, 0x00020204, 0x08000200,
        0x00000204, 0x08000000, 0x08000200, 0x00020204,
        0x08020200, 0x00020004, 0x00000000, 0x08000200,
        0x08000000, 0x00000200, 0x08020004, 0x00020000,
        0x00020004, 0x08020204, 0x00020200, 0x00000004,
        0x08020204, 0x00020200, 0x00020000, 0x08000204,
        0x08000004, 0x08020000, 0x00020204, 0x00000000,
        0x00000200, 0x08000004, 0x08000204, 0x08020200,
        0x08020000, 0x00000204, 0x00000004, 0x08020004,
    ]

    LUT_A2: Final[List[int]] = [
        0x80040100, 0x01000100, 0x80000000, 0x81040100,
        0x00000000, 0x01040000, 0x81000100, 0x80040000,
        0x01040100, 0x81000000, 0x01000000, 0x80000100,
        0x81000000, 0x80040100, 0x00040000, 0x01000000,
        0x81040000, 0x00040100, 0x00000100, 0x80000000,
        0x00040100, 0x81000100, 0x01040000, 0x00000100,
        0x80000100, 0x00000000, 0x80040000, 0x01040100,
        0x01000100, 0x81040000, 0x81040100, 0x00040000,
        0x81040000, 0x80000100, 0x00040000, 0x81000000,
        0x00040100, 0x01000100, 0x80000000, 0x01040000,
        0x81000100, 0x00000000, 0x00000100, 0x80040000,
        0x00000000, 0x81040000, 0x01040100, 0x00000100,
        0x01000000, 0x81040100, 0x80040100, 0x00040000,
        0x81040100, 0x80000000, 0x01000100, 0x80040100,
        0x80040000, 0x00040100, 0x01040000, 0x81000100,
        0x80000100, 0x01000000, 0x81000000, 0x01040100,
    ]

    LUT_A3: Final[List[int]] = [
        0x04010801, 0x00000000, 0x00010800, 0x04010000,
        0x04000001, 0x00000801, 0x04000800, 0x00010800,
        0x00000800, 0x04010001, 0x00000001, 0x04000800,
        0x00010001, 0x04010800, 0x04010000, 0x00000001,
        0x00010000, 0x04000801, 0x04010001, 0x00000800,
        0x00010801, 0x04000000, 0x00000000, 0x00010001,
        0x04000801, 0x00010801, 0x04010800, 0x04000001,
        0x04000000, 0x00010000, 0x00000801, 0x04010801,
        0x00010001, 0x04010800, 0x04000800, 0x00010801,
        0x04010801, 0x00010001, 0x04000001, 0x00000000,
        0x04000000, 0x00000801, 0x00010000, 0x04010001,
        0x00000800, 0x04000000, 0x00010801, 0x04000801,
        0x04010800, 0x00000800, 0x00000000, 0x04000001,
        0x00000001, 0x04010801, 0x00010800, 0x04010000,
        0x04010001, 0x00010000, 0x00000801, 0x04000800,
        0x04000801, 0x00000001, 0x04010000, 0x00010800,
    ]

    LUT_B0: Final[List[int]] = [
        0x00000400, 0x00000020, 0x00100020, 0x40100000,
        0x40100420, 0x40000400, 0x00000420, 0x00000000,
        0x00100000, 0x40100020, 0x40000020, 0x00100400,
        0x40000000, 0x00100420, 0x00100400, 0x40000020,
        0x40100020, 0x00000400, 0x40000400, 0x40100420,
        0x00000000, 0x00100020, 0x40100000, 0x00000420,
        0x40100400, 0x40000420, 0x00100420, 0x40000000,
        0x40000420, 0x40100400, 0x00000020, 0x00100000,
        0x40000420, 0x00100400, 0x40100400, 0x40000020,
        0x00000400, 0x00000020, 0x00100000, 0x40100400,
        0x40100020, 0x40000420, 0x00000420, 0x00000000,
        0x00000020, 0x40100000, 0x40000000, 0x00100020,
        0x00000000, 0x40100020, 0x00100020, 0x00000420,
        0x40000020, 0x00000400, 0x40100420, 0x00100000,
        0x00100420, 0x40000000, 0x40000400, 0x40100420,
        0x40100000, 0x00100420, 0x00100400, 0x40000400,
    ]

    LUT_B1: Final[List[int]] = [
        0x00800000, 0x00001000, 0x00000040, 0x00801042,
        0x00801002, 0x00800040, 0x00001042, 0x00801000,
        0x00001000, 0x00000002, 0x00800002, 0x00001040,
        0x00800042, 0x00801002, 0x00801040, 0x00000000,
        0x00001040, 0x00800000, 0x00001002, 0x00000042,
        0x00800040, 0x00001042, 0x00000000, 0x00800002,
        0x00000002, 0x00800042, 0x00801042, 0x00001002,
        0x00801000, 0x00000040, 0x00000042, 0x00801040,
        0x00801040, 0x00800042, 0x00001002, 0x00801000,
        0x00001000, 0x00000002, 0x00800002, 0x00800040,
        0x00800000, 0x00001040, 0x00801042, 0x00000000,
        0x00001042, 0x00800000, 0x00000040, 0x00001002,
        0x00800042, 0x00000040, 0x00000000, 0x00801042,
        0x00801002, 0x00801040, 0x00000042, 0x00001000,
        0x00001040, 0x00801002, 0x00800040, 0x00000042,
        0x00000002, 0x00001042, 0x00801000, 0x00800002,
    ]

    LUT_B2: Final[List[int]] = [
        0x10400000, 0x00404010, 0x00000010, 0x10400010,
        0x10004000, 0x00400000, 0x10400010, 0x00004010,
        0x00400010, 0x00004000, 0x00404000, 0x10000000,
        0x10404010, 0x10000010, 0x10000000, 0x10404000,
        0x00000000, 0x10004000, 0x00404010, 0x00000010,
        0x10000010, 0x10404010, 0x00004000, 0x10400000,
        0x10404000, 0x00400010, 0x10004010, 0x00404000,
        0x00004010, 0x00000000, 0x00400000, 0x10004010,
        0x00404010, 0x00000010, 0x10000000, 0x00004000,
        0x10000010, 0x10004000, 0x00404000, 0x10400010,
        0x00000000, 0x00404010, 0x00004010, 0x10404000,
        0x10004000, 0x00400000, 0x10404010, 0x10000000,
        0x10004010, 0x10400000, 0x00400000, 0x10404010,
        0x00004000, 0x00400010, 0x10400010, 0x00004010,
        0x00400010, 0x00000000, 0x10404000, 0x10000010,
        0x10400000, 0x10004010, 0x00000010, 0x00404000,
    ]

    LUT_B3: Final[List[int]] = [
        0x00208080, 0x00008000, 0x20200000, 0x20208080,
        0x00200000, 0x20008080, 0x20008000, 0x20200000,
        0x20008080, 0x00208080, 0x00208000, 0x20000080,
        0x20200080, 0x00200000, 0x00000000, 0x20008000,
        0x00008000, 0x20000000, 0x00200080, 0x00008080,
        0x20208080, 0x00208000, 0x20000080, 0x00200080,
        0x20000000, 0x00000080, 0x00008080, 0x20208000,
        0x00000080, 0x20200080, 0x20208000, 0x00000000,
        0x00000000, 0x20208080, 0x00200080, 0x20008000,
        0x00208080, 0x00008000, 0x20000080, 0x00200080,
        0x20208000, 0x00000080, 0x00008080, 0x20200000,
        0x20008080, 0x20000000, 0x20200000, 0x00208000,
        0x20208080, 0x00008080, 0x00208000, 0x20200080,
        0x00200000, 0x20000080, 0x20008000, 0x00000000,
        0x00008000, 0x00200000, 0x20200080, 0x00208080,
        0x20000000, 0x20208000, 0x00000080, 0x20008080,
    ]

    VALID_CHARS: Final[str] = "0123456789ABCDEFGHJKLMNPRSTUWXYZ"
    CONV_CHARS: Final[Dict[str, str]] = {
        "I": "1",
        "O": "0",
    }

    @staticmethod
    def __type_from_cardid(cardid: str) -> int:
        if cardid[:2].upper() == 'E0':
            return 1
        if cardid[:2].upper() == '01':
            return 2
        raise CardCipherException('Unrecognized card type')

    @staticmethod
    def encode(cardid: str) -> str:
        """
        Given a card ID as stored on a card (Usually starting with E004), convert
        it to the card string as shown on the back of the card.

        Parameters:
            cardid - 16 digit card ID (hex values stored as string).

        Returns:
            String representation of the card string.
        """
        if len(cardid) != 16:
            raise CardCipherException(
                f'Expected 16-character card ID, got {len(cardid)}',
            )

        cardint = [int(cardid[i:(i + 2)], 16) for i in range(0, len(cardid), 2)]

        # Reverse bytes
        reverse = [0] * 8
        for i in range(0, 8):
            reverse[7 - i] = cardint[i]

        # Encipher
        ciphered = CardCipher._encode(bytes(reverse))

        # Convert 8 x 8 bit bytes into 13 x 5 bit groups (sort of)
        bits = [0] * 65
        for i in range(0, 64):
            bits[i] = (ciphered[i >> 3] >> (~i & 7)) & 1

        groups = [0] * 16
        for i in range(0, 13):
            groups[i] = (
                (bits[i * 5 + 0] << 4) |
                (bits[i * 5 + 1] << 3) |
                (bits[i * 5 + 2] << 2) |
                (bits[i * 5 + 3] << 1) |
                (bits[i * 5 + 4] << 0)
            )

        # Smear 13 groups out into 14 groups
        groups[13] = 1
        groups[0] ^= CardCipher.__type_from_cardid(cardid)

        for i in range(0, 14):
            groups[i] ^= groups[i - 1]

        # Scheme field is 1 for old-style, 2 for felica cards
        groups[14] = CardCipher.__type_from_cardid(cardid)
        groups[15] = CardCipher.__checksum(groups)

        # Convert to chars and return
        return ''.join([CardCipher.VALID_CHARS[i] for i in groups])

    @staticmethod
    def decode(cardid: str) -> str:
        """
        Given a card string as shown on the back of the card, return the card ID
        as stored on the card itself. Does some sanitization to remove dashes,
        spaces and convert confusing characters (1, L and 0, O) before converting.

        Parameters:
            cardid - String representation of the card string.

        Returns:
            16 digit card ID (hex values stored as string).
        """
        # First sanitize the input
        cardid = cardid.replace(' ', '')
        cardid = cardid.replace('-', '')
        cardid = cardid.upper()
        for c in CardCipher.CONV_CHARS:
            cardid = cardid.replace(c, CardCipher.CONV_CHARS[c])

        if len(cardid) != 16:
            raise CardCipherException(
                f'Expected 16-character card ID, got {len(cardid)}',
            )

        for c in cardid:
            if c not in CardCipher.VALID_CHARS:
                raise CardCipherException(
                    f'Got unexpected character {c} in card ID',
                )

        # Convert chars to groups
        groups = [0] * 16

        for i in range(0, 16):
            for j in range(0, 32):
                if cardid[i] == CardCipher.VALID_CHARS[j]:
                    groups[i] = j
                    break

        # Verify scheme and checksum
        if (groups[14] != 1 and groups[14] != 2):
            raise CardCipherException(
                "Unrecognized card type"
            )
        if groups[15] != CardCipher.__checksum(groups):
            raise CardCipherException(
                "Bad card number"
            )

        # Un-smear 14 fields back into 13
        for i in range(13, 0, -1):
            groups[i] ^= groups[i - 1]
        groups[0] ^= groups[14]

        # Explode groups into bits
        bits = [0] * 64

        for i in range(0, 64):
            bits[i] = (groups[int(i / 5)] >> (4 - (i % 5))) & 1

        # Re-pack bits into eight bytes
        ciphered = [0] * 8

        for i in range(0, 64):
            ciphered[int(i / 8)] |= bits[i] << (~i & 7)

        # Decipher and reverse
        deciphered = CardCipher._decode(bytes(ciphered))
        reverse = [0] * 8
        for i in range(0, 8):
            reverse[i] = deciphered[7 - i]

        def tohex(x: int) -> str:
            h = hex(x)[2:]
            while len(h) < 2:
                h = '0' + h
            return h.upper()

        # Convert to a string, verify we have the same type
        finalvalue = ''.join([tohex(v) for v in reverse])
        if groups[14] != CardCipher.__type_from_cardid(finalvalue):
            raise CardCipherException(
                "Card type mismatch"
            )
        return finalvalue

    @staticmethod
    def __checksum(data: List[int]) -> int:
        checksum = 0

        for i in range(0, 15):
            checksum += (i % 3 + 1) * data[i]

        while checksum >= 0x20:
            checksum = (checksum & 0x1F) + (checksum >> 5)

        return checksum

    @staticmethod
    def _encode(inbytes: bytes) -> bytes:
        if len(inbytes) != 8:
            raise CardCipherException(
                f'Expected 8-byte input, got {len(inbytes)}',
            )

        inp = [b for b in inbytes]
        out = [0] * 8

        CardCipher.__from_int(out, CardCipher.__operatorA(0x00, CardCipher.__to_int(inp)))
        CardCipher.__from_int(out, CardCipher.__operatorB(0x20, CardCipher.__to_int(out)))
        CardCipher.__from_int(out, CardCipher.__operatorA(0x40, CardCipher.__to_int(out)))

        return bytes(out)

    @staticmethod
    def _decode(inbytes: bytes) -> bytes:
        if len(inbytes) != 8:
            raise CardCipherException(
                f'Expected 8-byte input, got {len(inbytes)}',
            )

        inp = [b for b in inbytes]
        out = [0] * 8

        CardCipher.__from_int(out, CardCipher.__operatorB(0x40, CardCipher.__to_int(inp)))
        CardCipher.__from_int(out, CardCipher.__operatorA(0x20, CardCipher.__to_int(out)))
        CardCipher.__from_int(out, CardCipher.__operatorB(0x00, CardCipher.__to_int(out)))

        return bytes(out)

    @staticmethod
    def __to_int(data: List[int]) -> int:
        inX = (
            (data[0] & 0xFF) |
            ((data[1] & 0xFF) << 8) |
            ((data[2] & 0xFF) << 16) |
            ((data[3] & 0xFF) << 24)
        )

        inY = (
            (data[4] & 0xFF) |
            ((data[5] & 0xFF) << 8) |
            ((data[6] & 0xFF) << 16) |
            ((data[7] & 0xFF) << 24)
        )

        v7 = ((((inX ^ (inY >> 4)) & 0xF0F0F0F) << 4) ^ inY) & 0xFFFFFFFF
        v8 = (((inX ^ (inY >> 4)) & 0xF0F0F0F) ^ inX) & 0xFFFFFFFF

        v9 = ((v7 ^ (v8 >> 16))) & 0x0000FFFF
        v10 = (((v7 ^ (v8 >> 16)) << 16) ^ v8) & 0xFFFFFFFF

        v11 = (v9 ^ v7) & 0xFFFFFFFF
        v12 = (v10 ^ (v11 >> 2)) & 0x33333333
        v13 = (v11 ^ (v12 << 2)) & 0xFFFFFFFF

        v14 = (v12 ^ v10) & 0xFFFFFFFF
        v15 = (v13 ^ (v14 >> 8)) & 0x00FF00FF
        v16 = (v14 ^ (v15 << 8)) & 0xFFFFFFFF

        v17 = CardCipher.__ror(v15 ^ v13, 1)
        v18 = (v16 ^ v17) & 0x55555555

        v3 = CardCipher.__ror(v18 ^ v16, 1)
        v4 = (v18 ^ v17) & 0xFFFFFFFF

        return ((v3 & 0xFFFFFFFF) << 32) | (v4 & 0xFFFFFFFF)

    @staticmethod
    def __from_int(data: List[int], state: int) -> None:
        v3 = (state >> 32) & 0xFFFFFFFF
        v4 = state & 0xFFFFFFFF

        v22 = CardCipher.__ror(v4, 31)
        v23 = (v3 ^ v22) & 0x55555555
        v24 = (v23 ^ v22) & 0xFFFFFFFF

        v25 = CardCipher.__ror(v23 ^ v3, 31)
        v26 = (v25 ^ (v24 >> 8)) & 0x00FF00FF
        v27 = (v24 ^ (v26 << 8)) & 0xFFFFFFFF

        v28 = (v26 ^ v25) & 0xFFFFFFFF
        v29 = ((v28 >> 2) ^ v27) & 0x33333333
        v30 = ((v29 << 2) ^ v28) & 0xFFFFFFFF

        v31 = (v29 ^ v27) & 0xFFFFFFFF
        v32 = (v30 ^ (v31 >> 16)) & 0x0000FFFF
        v33 = (v31 ^ (v32 << 16)) & 0xFFFFFFFF

        v34 = (v32 ^ v30) & 0xFFFFFFFF
        v35 = (v33 ^ (v34 >> 4)) & 0xF0F0F0F

        outY = ((v35 << 4) ^ v34) & 0xFFFFFFFF
        outX = (v35 ^ v33) & 0xFFFFFFFF

        data[0] = outX & 0xFF
        data[1] = (outX >> 8) & 0xFF
        data[2] = (outX >> 16) & 0xFF
        data[3] = (outX >> 24) & 0xFF
        data[4] = outY & 0xFF
        data[5] = (outY >> 8) & 0xFF
        data[6] = (outY >> 16) & 0xFF
        data[7] = (outY >> 24) & 0xFF

    @staticmethod
    def __operatorA(off: int, state: int) -> int:
        v3 = (state >> 32) & 0xFFFFFFFF
        v4 = state & 0xFFFFFFFF

        for i in range(0, 32, 4):
            v20 = CardCipher.__ror(v3 ^ CardCipher.KEY[off + i + 1], 28)

            v4 ^= (
                CardCipher.LUT_B0[(v20 >> 26) & 0x3F] ^
                CardCipher.LUT_B1[(v20 >> 18) & 0x3F] ^
                CardCipher.LUT_B2[(v20 >> 10) & 0x3F] ^
                CardCipher.LUT_B3[(v20 >> 2) & 0x3F] ^
                CardCipher.LUT_A0[((v3 ^ CardCipher.KEY[off + i]) >> 26) & 0x3F] ^
                CardCipher.LUT_A1[((v3 ^ CardCipher.KEY[off + i]) >> 18) & 0x3F] ^
                CardCipher.LUT_A2[((v3 ^ CardCipher.KEY[off + i]) >> 10) & 0x3F] ^
                CardCipher.LUT_A3[((v3 ^ CardCipher.KEY[off + i]) >> 2) & 0x3F]
            )

            v21 = CardCipher.__ror(v4 ^ CardCipher.KEY[off + i + 3], 28)

            v3 ^= (
                CardCipher.LUT_B0[(v21 >> 26) & 0x3F] ^
                CardCipher.LUT_B1[(v21 >> 18) & 0x3F] ^
                CardCipher.LUT_B2[(v21 >> 10) & 0x3F] ^
                CardCipher.LUT_B3[(v21 >> 2) & 0x3F] ^
                CardCipher.LUT_A0[((v4 ^ CardCipher.KEY[off + i + 2]) >> 26) & 0x3F] ^
                CardCipher.LUT_A1[((v4 ^ CardCipher.KEY[off + i + 2]) >> 18) & 0x3F] ^
                CardCipher.LUT_A2[((v4 ^ CardCipher.KEY[off + i + 2]) >> 10) & 0x3F] ^
                CardCipher.LUT_A3[((v4 ^ CardCipher.KEY[off + i + 2]) >> 2) & 0x3F]
            )

        return ((v3 & 0xFFFFFFFF) << 32) | (v4 & 0xFFFFFFFF)

    @staticmethod
    def __operatorB(off: int, state: int) -> int:
        v3 = (state >> 32) & 0xFFFFFFFF
        v4 = state & 0xFFFFFFFF

        for i in range(0, 32, 4):
            v20 = CardCipher.__ror(v3 ^ CardCipher.KEY[off + 31 - i], 28)

            v4 ^= (
                CardCipher.LUT_A0[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 26) & 0x3F] ^
                CardCipher.LUT_A1[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 18) & 0x3F] ^
                CardCipher.LUT_A2[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 10) & 0x3F] ^
                CardCipher.LUT_A3[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 2) & 0x3F] ^
                CardCipher.LUT_B0[(v20 >> 26) & 0x3F] ^
                CardCipher.LUT_B1[(v20 >> 18) & 0x3F] ^
                CardCipher.LUT_B2[(v20 >> 10) & 0x3F] ^
                CardCipher.LUT_B3[(v20 >> 2) & 0x3F]
            )

            v21 = CardCipher.__ror(v4 ^ CardCipher.KEY[off + 29 - i], 28)

            v3 ^= (
                CardCipher.LUT_A0[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 26) & 0x3F] ^
                CardCipher.LUT_A1[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 18) & 0x3F] ^
                CardCipher.LUT_A2[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 10) & 0x3F] ^
                CardCipher.LUT_A3[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 2) & 0x3F] ^
                CardCipher.LUT_B0[(v21 >> 26) & 0x3F] ^
                CardCipher.LUT_B1[(v21 >> 18) & 0x3F] ^
                CardCipher.LUT_B2[(v21 >> 10) & 0x3F] ^
                CardCipher.LUT_B3[(v21 >> 2) & 0x3F]
            )

        return ((v3 & 0xFFFFFFFF) << 32) | (v4 & 0xFFFFFFFF)

    @staticmethod
    def __ror(val: int, amount: int) -> int:
        return ((val << (32 - amount)) & 0xFFFFFFFF) | ((val >> amount) & 0xFFFFFFFF)
