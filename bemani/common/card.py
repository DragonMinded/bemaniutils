from typing import Dict, List
from typing_extensions import Final


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
        0x20D0D03C,
        0x868ECB41,
        0xBCD89C84,
        0x4C0E0D0D,
        0x84FC30AC,
        0x4CC1890E,
        0xFC5418A4,
        0x02C50F44,
        0x68ACB4E0,
        0x06CD4A4E,
        0xCC28906C,
        0x4F0C8AC0,
        0xB03CA468,
        0x884AC7C4,
        0x389490D8,
        0xCF80C6C2,
        0x58D87404,
        0xC48EC444,
        0xB4E83C50,
        0x498D0147,
        0x64F454C0,
        0x4C4701C8,
        0xEC302CC4,
        0xC6C949C1,
        0xC84C00F0,
        0xCDCC49CC,
        0x883C5CF4,
        0x8B0FCB80,
        0x703CC0B0,
        0xCB820A8D,
        0x78804C8C,
        0x4FCA830E,
        0x80D0F03C,
        0x8EC84F8C,
        0x98C89C4C,
        0xC80D878F,
        0x54BC949C,
        0xC801C5CE,
        0x749078DC,
        0xC3C80D46,
        0x2C8070F0,
        0x0CCE4DCF,
        0x8C3874E4,
        0x8D448AC3,
        0x987CAC70,
        0xC0C20AC5,
        0x288CFC78,
        0xC28543C8,
        0x4C8C7434,
        0xC50E4F8D,
        0x8468F4B4,
        0xCB4A0307,
        0x2854DC98,
        0x48430B45,
        0x6858FCE8,
        0x4681CD49,
        0xD04808EC,
        0x458D0FCB,
        0xE0A48CE4,
        0x880F8FCE,
        0x7434B8FC,
        0xCE080A8E,
        0x5860FC6C,
        0x46C886CC,
        0xD01098A4,
        0xCE090B8C,
        0x1044CC2C,
        0x86898E0F,
        0xD0809C3C,
        0x4A05860F,
        0x54B4F80C,
        0x4008870E,
        0x1480B88C,
        0x0AC8854F,
        0x1C9034CC,
        0x08444C4E,
        0x0CB83C64,
        0x41C08CC6,
        0x1C083460,
        0xC0C603CE,
        0x2CA0645C,
        0x818246CB,
        0x0408E454,
        0xC5464487,
        0x88607C18,
        0xC1424187,
        0x284C7C90,
        0xC1030509,
        0x40486C94,
        0x4603494B,
        0xE0404CE4,
        0x4109094D,
        0x60443CE4,
        0x4C0B8B8D,
        0xE054E8BC,
        0x02008E89,
    ]

    LUT_A0: Final[List[int]] = [
        0x02080008,
        0x02082000,
        0x00002008,
        0x00000000,
        0x02002000,
        0x00080008,
        0x02080000,
        0x02082008,
        0x00000008,
        0x02000000,
        0x00082000,
        0x00002008,
        0x00082008,
        0x02002008,
        0x02000008,
        0x02080000,
        0x00002000,
        0x00082008,
        0x00080008,
        0x02002000,
        0x02082008,
        0x02000008,
        0x00000000,
        0x00082000,
        0x02000000,
        0x00080000,
        0x02002008,
        0x02080008,
        0x00080000,
        0x00002000,
        0x02082000,
        0x00000008,
        0x00080000,
        0x00002000,
        0x02000008,
        0x02082008,
        0x00002008,
        0x02000000,
        0x00000000,
        0x00082000,
        0x02080008,
        0x02002008,
        0x02002000,
        0x00080008,
        0x02082000,
        0x00000008,
        0x00080008,
        0x02002000,
        0x02082008,
        0x00080000,
        0x02080000,
        0x02000008,
        0x00082000,
        0x00002008,
        0x02002008,
        0x02080000,
        0x00000008,
        0x02082000,
        0x00082008,
        0x00000000,
        0x02000000,
        0x02080008,
        0x00002000,
        0x00082008,
    ]

    LUT_A1: Final[List[int]] = [
        0x08000004,
        0x00020004,
        0x00000000,
        0x08020200,
        0x00020004,
        0x00000200,
        0x08000204,
        0x00020000,
        0x00000204,
        0x08020204,
        0x00020200,
        0x08000000,
        0x08000200,
        0x08000004,
        0x08020000,
        0x00020204,
        0x00020000,
        0x08000204,
        0x08020004,
        0x00000000,
        0x00000200,
        0x00000004,
        0x08020200,
        0x08020004,
        0x08020204,
        0x08020000,
        0x08000000,
        0x00000204,
        0x00000004,
        0x00020200,
        0x00020204,
        0x08000200,
        0x00000204,
        0x08000000,
        0x08000200,
        0x00020204,
        0x08020200,
        0x00020004,
        0x00000000,
        0x08000200,
        0x08000000,
        0x00000200,
        0x08020004,
        0x00020000,
        0x00020004,
        0x08020204,
        0x00020200,
        0x00000004,
        0x08020204,
        0x00020200,
        0x00020000,
        0x08000204,
        0x08000004,
        0x08020000,
        0x00020204,
        0x00000000,
        0x00000200,
        0x08000004,
        0x08000204,
        0x08020200,
        0x08020000,
        0x00000204,
        0x00000004,
        0x08020004,
    ]

    LUT_A2: Final[List[int]] = [
        0x80040100,
        0x01000100,
        0x80000000,
        0x81040100,
        0x00000000,
        0x01040000,
        0x81000100,
        0x80040000,
        0x01040100,
        0x81000000,
        0x01000000,
        0x80000100,
        0x81000000,
        0x80040100,
        0x00040000,
        0x01000000,
        0x81040000,
        0x00040100,
        0x00000100,
        0x80000000,
        0x00040100,
        0x81000100,
        0x01040000,
        0x00000100,
        0x80000100,
        0x00000000,
        0x80040000,
        0x01040100,
        0x01000100,
        0x81040000,
        0x81040100,
        0x00040000,
        0x81040000,
        0x80000100,
        0x00040000,
        0x81000000,
        0x00040100,
        0x01000100,
        0x80000000,
        0x01040000,
        0x81000100,
        0x00000000,
        0x00000100,
        0x80040000,
        0x00000000,
        0x81040000,
        0x01040100,
        0x00000100,
        0x01000000,
        0x81040100,
        0x80040100,
        0x00040000,
        0x81040100,
        0x80000000,
        0x01000100,
        0x80040100,
        0x80040000,
        0x00040100,
        0x01040000,
        0x81000100,
        0x80000100,
        0x01000000,
        0x81000000,
        0x01040100,
    ]

    LUT_A3: Final[List[int]] = [
        0x04010801,
        0x00000000,
        0x00010800,
        0x04010000,
        0x04000001,
        0x00000801,
        0x04000800,
        0x00010800,
        0x00000800,
        0x04010001,
        0x00000001,
        0x04000800,
        0x00010001,
        0x04010800,
        0x04010000,
        0x00000001,
        0x00010000,
        0x04000801,
        0x04010001,
        0x00000800,
        0x00010801,
        0x04000000,
        0x00000000,
        0x00010001,
        0x04000801,
        0x00010801,
        0x04010800,
        0x04000001,
        0x04000000,
        0x00010000,
        0x00000801,
        0x04010801,
        0x00010001,
        0x04010800,
        0x04000800,
        0x00010801,
        0x04010801,
        0x00010001,
        0x04000001,
        0x00000000,
        0x04000000,
        0x00000801,
        0x00010000,
        0x04010001,
        0x00000800,
        0x04000000,
        0x00010801,
        0x04000801,
        0x04010800,
        0x00000800,
        0x00000000,
        0x04000001,
        0x00000001,
        0x04010801,
        0x00010800,
        0x04010000,
        0x04010001,
        0x00010000,
        0x00000801,
        0x04000800,
        0x04000801,
        0x00000001,
        0x04010000,
        0x00010800,
    ]

    LUT_B0: Final[List[int]] = [
        0x00000400,
        0x00000020,
        0x00100020,
        0x40100000,
        0x40100420,
        0x40000400,
        0x00000420,
        0x00000000,
        0x00100000,
        0x40100020,
        0x40000020,
        0x00100400,
        0x40000000,
        0x00100420,
        0x00100400,
        0x40000020,
        0x40100020,
        0x00000400,
        0x40000400,
        0x40100420,
        0x00000000,
        0x00100020,
        0x40100000,
        0x00000420,
        0x40100400,
        0x40000420,
        0x00100420,
        0x40000000,
        0x40000420,
        0x40100400,
        0x00000020,
        0x00100000,
        0x40000420,
        0x00100400,
        0x40100400,
        0x40000020,
        0x00000400,
        0x00000020,
        0x00100000,
        0x40100400,
        0x40100020,
        0x40000420,
        0x00000420,
        0x00000000,
        0x00000020,
        0x40100000,
        0x40000000,
        0x00100020,
        0x00000000,
        0x40100020,
        0x00100020,
        0x00000420,
        0x40000020,
        0x00000400,
        0x40100420,
        0x00100000,
        0x00100420,
        0x40000000,
        0x40000400,
        0x40100420,
        0x40100000,
        0x00100420,
        0x00100400,
        0x40000400,
    ]

    LUT_B1: Final[List[int]] = [
        0x00800000,
        0x00001000,
        0x00000040,
        0x00801042,
        0x00801002,
        0x00800040,
        0x00001042,
        0x00801000,
        0x00001000,
        0x00000002,
        0x00800002,
        0x00001040,
        0x00800042,
        0x00801002,
        0x00801040,
        0x00000000,
        0x00001040,
        0x00800000,
        0x00001002,
        0x00000042,
        0x00800040,
        0x00001042,
        0x00000000,
        0x00800002,
        0x00000002,
        0x00800042,
        0x00801042,
        0x00001002,
        0x00801000,
        0x00000040,
        0x00000042,
        0x00801040,
        0x00801040,
        0x00800042,
        0x00001002,
        0x00801000,
        0x00001000,
        0x00000002,
        0x00800002,
        0x00800040,
        0x00800000,
        0x00001040,
        0x00801042,
        0x00000000,
        0x00001042,
        0x00800000,
        0x00000040,
        0x00001002,
        0x00800042,
        0x00000040,
        0x00000000,
        0x00801042,
        0x00801002,
        0x00801040,
        0x00000042,
        0x00001000,
        0x00001040,
        0x00801002,
        0x00800040,
        0x00000042,
        0x00000002,
        0x00001042,
        0x00801000,
        0x00800002,
    ]

    LUT_B2: Final[List[int]] = [
        0x10400000,
        0x00404010,
        0x00000010,
        0x10400010,
        0x10004000,
        0x00400000,
        0x10400010,
        0x00004010,
        0x00400010,
        0x00004000,
        0x00404000,
        0x10000000,
        0x10404010,
        0x10000010,
        0x10000000,
        0x10404000,
        0x00000000,
        0x10004000,
        0x00404010,
        0x00000010,
        0x10000010,
        0x10404010,
        0x00004000,
        0x10400000,
        0x10404000,
        0x00400010,
        0x10004010,
        0x00404000,
        0x00004010,
        0x00000000,
        0x00400000,
        0x10004010,
        0x00404010,
        0x00000010,
        0x10000000,
        0x00004000,
        0x10000010,
        0x10004000,
        0x00404000,
        0x10400010,
        0x00000000,
        0x00404010,
        0x00004010,
        0x10404000,
        0x10004000,
        0x00400000,
        0x10404010,
        0x10000000,
        0x10004010,
        0x10400000,
        0x00400000,
        0x10404010,
        0x00004000,
        0x00400010,
        0x10400010,
        0x00004010,
        0x00400010,
        0x00000000,
        0x10404000,
        0x10000010,
        0x10400000,
        0x10004010,
        0x00000010,
        0x00404000,
    ]

    LUT_B3: Final[List[int]] = [
        0x00208080,
        0x00008000,
        0x20200000,
        0x20208080,
        0x00200000,
        0x20008080,
        0x20008000,
        0x20200000,
        0x20008080,
        0x00208080,
        0x00208000,
        0x20000080,
        0x20200080,
        0x00200000,
        0x00000000,
        0x20008000,
        0x00008000,
        0x20000000,
        0x00200080,
        0x00008080,
        0x20208080,
        0x00208000,
        0x20000080,
        0x00200080,
        0x20000000,
        0x00000080,
        0x00008080,
        0x20208000,
        0x00000080,
        0x20200080,
        0x20208000,
        0x00000000,
        0x00000000,
        0x20208080,
        0x00200080,
        0x20008000,
        0x00208080,
        0x00008000,
        0x20000080,
        0x00200080,
        0x20208000,
        0x00000080,
        0x00008080,
        0x20200000,
        0x20008080,
        0x20000000,
        0x20200000,
        0x00208000,
        0x20208080,
        0x00008080,
        0x00208000,
        0x20200080,
        0x00200000,
        0x20000080,
        0x20008000,
        0x00000000,
        0x00008000,
        0x00200000,
        0x20200080,
        0x00208080,
        0x20000000,
        0x20208000,
        0x00000080,
        0x20008080,
    ]

    VALID_CHARS: Final[str] = "0123456789ABCDEFGHJKLMNPRSTUWXYZ"
    CONV_CHARS: Final[Dict[str, str]] = {
        "I": "1",
        "O": "0",
    }

    @staticmethod
    def __type_from_cardid(cardid: str) -> int:
        if cardid[:2].upper() == "E0":
            return 1
        if cardid[:2].upper() == "01":
            return 2
        raise CardCipherException("Unrecognized card type")

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
                f"Expected 16-character card ID, got {len(cardid)}",
            )

        cardint = [int(cardid[i : (i + 2)], 16) for i in range(0, len(cardid), 2)]

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
                (bits[i * 5 + 0] << 4)
                | (bits[i * 5 + 1] << 3)
                | (bits[i * 5 + 2] << 2)
                | (bits[i * 5 + 3] << 1)
                | (bits[i * 5 + 4] << 0)
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
        return "".join([CardCipher.VALID_CHARS[i] for i in groups])

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
        cardid = cardid.replace(" ", "")
        cardid = cardid.replace("-", "")
        cardid = cardid.upper()
        for c in CardCipher.CONV_CHARS:
            cardid = cardid.replace(c, CardCipher.CONV_CHARS[c])

        if len(cardid) != 16:
            raise CardCipherException(
                f"Expected 16-character card ID, got {len(cardid)}",
            )

        for c in cardid:
            if c not in CardCipher.VALID_CHARS:
                raise CardCipherException(
                    f"Got unexpected character {c} in card ID",
                )

        # Convert chars to groups
        groups = [0] * 16

        for i in range(0, 16):
            for j in range(0, 32):
                if cardid[i] == CardCipher.VALID_CHARS[j]:
                    groups[i] = j
                    break

        # Verify scheme and checksum
        if groups[14] != 1 and groups[14] != 2:
            raise CardCipherException("Unrecognized card type")
        if groups[15] != CardCipher.__checksum(groups):
            raise CardCipherException("Bad card number")

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
                h = "0" + h
            return h.upper()

        # Convert to a string, verify we have the same type
        finalvalue = "".join([tohex(v) for v in reverse])
        if groups[14] != CardCipher.__type_from_cardid(finalvalue):
            raise CardCipherException("Card type mismatch")
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
                f"Expected 8-byte input, got {len(inbytes)}",
            )

        inp = [b for b in inbytes]
        out = [0] * 8

        CardCipher.__from_int(
            out, CardCipher.__operatorA(0x00, CardCipher.__to_int(inp))
        )
        CardCipher.__from_int(
            out, CardCipher.__operatorB(0x20, CardCipher.__to_int(out))
        )
        CardCipher.__from_int(
            out, CardCipher.__operatorA(0x40, CardCipher.__to_int(out))
        )

        return bytes(out)

    @staticmethod
    def _decode(inbytes: bytes) -> bytes:
        if len(inbytes) != 8:
            raise CardCipherException(
                f"Expected 8-byte input, got {len(inbytes)}",
            )

        inp = [b for b in inbytes]
        out = [0] * 8

        CardCipher.__from_int(
            out, CardCipher.__operatorB(0x40, CardCipher.__to_int(inp))
        )
        CardCipher.__from_int(
            out, CardCipher.__operatorA(0x20, CardCipher.__to_int(out))
        )
        CardCipher.__from_int(
            out, CardCipher.__operatorB(0x00, CardCipher.__to_int(out))
        )

        return bytes(out)

    @staticmethod
    def __to_int(data: List[int]) -> int:
        inX = (
            (data[0] & 0xFF)
            | ((data[1] & 0xFF) << 8)
            | ((data[2] & 0xFF) << 16)
            | ((data[3] & 0xFF) << 24)
        )

        inY = (
            (data[4] & 0xFF)
            | ((data[5] & 0xFF) << 8)
            | ((data[6] & 0xFF) << 16)
            | ((data[7] & 0xFF) << 24)
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
                CardCipher.LUT_B0[(v20 >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(v20 >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(v20 >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(v20 >> 2) & 0x3F]
                ^ CardCipher.LUT_A0[((v3 ^ CardCipher.KEY[off + i]) >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[((v3 ^ CardCipher.KEY[off + i]) >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[((v3 ^ CardCipher.KEY[off + i]) >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[((v3 ^ CardCipher.KEY[off + i]) >> 2) & 0x3F]
            )

            v21 = CardCipher.__ror(v4 ^ CardCipher.KEY[off + i + 3], 28)

            v3 ^= (
                CardCipher.LUT_B0[(v21 >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(v21 >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(v21 >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(v21 >> 2) & 0x3F]
                ^ CardCipher.LUT_A0[((v4 ^ CardCipher.KEY[off + i + 2]) >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[((v4 ^ CardCipher.KEY[off + i + 2]) >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[((v4 ^ CardCipher.KEY[off + i + 2]) >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[((v4 ^ CardCipher.KEY[off + i + 2]) >> 2) & 0x3F]
            )

        return ((v3 & 0xFFFFFFFF) << 32) | (v4 & 0xFFFFFFFF)

    @staticmethod
    def __operatorB(off: int, state: int) -> int:
        v3 = (state >> 32) & 0xFFFFFFFF
        v4 = state & 0xFFFFFFFF

        for i in range(0, 32, 4):
            v20 = CardCipher.__ror(v3 ^ CardCipher.KEY[off + 31 - i], 28)

            v4 ^= (
                CardCipher.LUT_A0[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[((v3 ^ CardCipher.KEY[off + 30 - i]) >> 2) & 0x3F]
                ^ CardCipher.LUT_B0[(v20 >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(v20 >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(v20 >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(v20 >> 2) & 0x3F]
            )

            v21 = CardCipher.__ror(v4 ^ CardCipher.KEY[off + 29 - i], 28)

            v3 ^= (
                CardCipher.LUT_A0[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[((v4 ^ CardCipher.KEY[off + 28 - i]) >> 2) & 0x3F]
                ^ CardCipher.LUT_B0[(v21 >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(v21 >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(v21 >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(v21 >> 2) & 0x3F]
            )

        return ((v3 & 0xFFFFFFFF) << 32) | (v4 & 0xFFFFFFFF)

    @staticmethod
    def __ror(val: int, amount: int) -> int:
        return ((val << (32 - amount)) & 0xFFFFFFFF) | ((val >> amount) & 0xFFFFFFFF)
