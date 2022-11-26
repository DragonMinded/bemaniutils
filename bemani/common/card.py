from typing import Dict, List, Tuple
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

    # precomputed round keys (unknown master key)
    DES3_KEY1: Final[List[int]] = [
        0x20D0D03C, 0x868ECB41, 0xBCD89C84, 0x4C0E0D0D,
        0x84FC30AC, 0x4CC1890E, 0xFC5418A4, 0x02C50F44,
        0x68ACB4E0, 0x06CD4A4E, 0xCC28906C, 0x4F0C8AC0,
        0xB03CA468, 0x884AC7C4, 0x389490D8, 0xCF80C6C2,
        0x58D87404, 0xC48EC444, 0xB4E83C50, 0x498D0147,
        0x64F454C0, 0x4C4701C8, 0xEC302CC4, 0xC6C949C1,
        0xC84C00F0, 0xCDCC49CC, 0x883C5CF4, 0x8B0FCB80,
        0x703CC0B0, 0xCB820A8D, 0x78804C8C, 0x4FCA830E,
    ]

    DES3_KEY2: Final[List[int]] = [
        0x80D0F03C, 0x8EC84F8C, 0x98C89C4C, 0xC80D878F,
        0x54BC949C, 0xC801C5CE, 0x749078DC, 0xC3C80D46,
        0x2C8070F0, 0x0CCE4DCF, 0x8C3874E4, 0x8D448AC3,
        0x987CAC70, 0xC0C20AC5, 0x288CFC78, 0xC28543C8,
        0x4C8C7434, 0xC50E4F8D, 0x8468F4B4, 0xCB4A0307,
        0x2854DC98, 0x48430B45, 0x6858FCE8, 0x4681CD49,
        0xD04808EC, 0x458D0FCB, 0xE0A48CE4, 0x880F8FCE,
        0x7434B8FC, 0xCE080A8E, 0x5860FC6C, 0x46C886CC,
    ]

    DES3_KEY3: Final[List[int]] = [
        0xD01098A4, 0xCE090B8C, 0x1044CC2C, 0x86898E0F,
        0xD0809C3C, 0x4A05860F, 0x54B4F80C, 0x4008870E,
        0x1480B88C, 0x0AC8854F, 0x1C9034CC, 0x08444C4E,
        0x0CB83C64, 0x41C08CC6, 0x1C083460, 0xC0C603CE,
        0x2CA0645C, 0x818246CB, 0x0408E454, 0xC5464487,
        0x88607C18, 0xC1424187, 0x284C7C90, 0xC1030509,
        0x40486C94, 0x4603494B, 0xE0404CE4, 0x4109094D,
        0x60443CE4, 0x4C0B8B8D, 0xE054E8BC, 0x02008E89,
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

        cardbytes = bytes.fromhex(cardid)

        # Reverse bytes
        reverse = cardbytes[::-1]

        # Encipher
        ciphered = CardCipher._encode(reverse)

        # Convert 8 x 8 bit bytes into 13 x 5 bit groups (sort of)
        bits = [0] * 65
        for i in range(0, 64):
            bits[i] = (ciphered[i // 8] >> (7 - (i % 8))) & 1

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
            bits[i] = (groups[i // 5] >> (4 - (i % 5))) & 1

        # Re-pack bits into eight bytes
        ciphered = bytearray(8)

        for i in range(0, 64):
            ciphered[i // 8] |= bits[i] << (7 - (i % 8))

        # Decipher and reverse
        deciphered = CardCipher._decode(ciphered)
        reverse = deciphered[::-1]

        # Convert to a string, verify we have the same type
        finalvalue = reverse.hex().upper()
        if groups[14] != CardCipher.__type_from_cardid(finalvalue):
            raise CardCipherException("Card type mismatch")
        return finalvalue

    # extended/modified luhn mod 32 checksum?
    @staticmethod
    def __checksum(data: List[int]) -> int:
        checksum = sum(n * 1 for n in data[0:15:3])
        checksum += sum(n * 2 for n in data[1:15:3])
        checksum += sum(n * 3 for n in data[2:15:3])

        while checksum >= 0x20:
            checksum = sum(divmod(checksum, 0x20))

        return checksum

    # DES3 implementation (unknown master key)
    @staticmethod
    def _encode(inbytes: bytes) -> bytes:
        if len(inbytes) != 8:
            raise CardCipherException(
                f"Expected 8-byte input, got {len(inbytes)}",
            )

        out = CardCipher.__des_encrypt(CardCipher.DES3_KEY1, inbytes)
        out = CardCipher.__des_decrypt(CardCipher.DES3_KEY2, out)
        out = CardCipher.__des_encrypt(CardCipher.DES3_KEY3, out)

        return bytes(out)

    # https://kernel.googlesource.com/pub/scm/linux/kernel/git/klassert/ipsec/+/refs/tags/v2.6.12-rc2/crypto/des.c
    @staticmethod
    def _decode(inbytes: bytes) -> bytes:
        if len(inbytes) != 8:
            raise CardCipherException(
                f"Expected 8-byte input, got {len(inbytes)}",
            )

        out = CardCipher.__des_decrypt(CardCipher.DES3_KEY3, inbytes)
        out = CardCipher.__des_encrypt(CardCipher.DES3_KEY2, out)
        out = CardCipher.__des_decrypt(CardCipher.DES3_KEY1, out)

        return bytes(out)

    @staticmethod
    def __initial_permutation(data: bytes) -> Tuple[int, int]:
        L = int.from_bytes(data[0:4], "little")
        R = int.from_bytes(data[4:8], "little")

        T = ((R >> 4) ^ L) & 0x0F0F0F0F
        R ^= T << 4
        L ^= T
        T = ((L >> 16) ^ R) & 0x0000FFFF
        L ^= T << 16
        R ^= T
        T = ((R >> 2) ^ L) & 0x33333333
        R ^= T << 2
        L ^= T
        T = ((L >> 8) ^ R) & 0x00FF00FF
        L ^= T << 8
        R ^= T
        R = CardCipher.__ror(R, 1)
        T = (L ^ R) & 0x55555555
        L ^= T
        R ^= T
        L = CardCipher.__ror(L, 1)

        return R & 0xFFFFFFFF, L & 0xFFFFFFFF

    @staticmethod
    def __final_permutation(L: int, R: int) -> bytes:
        R = CardCipher.__ror(R, 31)
        T = (L ^ R) & 0x55555555
        L ^= T
        R ^= T
        L = CardCipher.__ror(L, 31)
        T = ((R >> 8) ^ L) & 0x00FF00FF
        R ^= T << 8
        L ^= T
        T = ((L >> 2) ^ R) & 0x33333333
        L ^= T << 2
        R ^= T
        T = ((R >> 16) ^ L) & 0x0000FFFF
        R ^= T << 16
        L ^= T
        T = ((L >> 4) ^ R) & 0x0F0F0F0F
        L ^= T << 4
        R ^= T

        return R.to_bytes(4, "little") + L.to_bytes(4, "little")

    @staticmethod
    def __des_encrypt(expkey: List[int], inbytes: bytes) -> bytes:
        L, R = CardCipher.__initial_permutation(inbytes)

        for i in range(0, 32, 4):
            T = expkey[i] ^ R
            L ^= (
                CardCipher.LUT_A0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[(T >> 2) & 0x3F]
            )

            T = expkey[i + 1] ^ R
            T = CardCipher.__ror(T, 28)
            L ^= (
                CardCipher.LUT_B0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(T >> 2) & 0x3F]
            )

            T = expkey[i + 2] ^ L
            R ^= (
                CardCipher.LUT_A0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[(T >> 2) & 0x3F]
            )

            T = expkey[i + 3] ^ L
            T = CardCipher.__ror(T, 28)
            R ^= (
                CardCipher.LUT_B0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(T >> 2) & 0x3F]
            )

        return CardCipher.__final_permutation(R, L)

    @staticmethod
    def __des_decrypt(expkey: List[int], inbytes: bytes) -> bytes:
        L, R = CardCipher.__initial_permutation(inbytes)

        for i in range(0, 32, 4):
            T = expkey[31 - i] ^ R
            T = CardCipher.__ror(T, 28)
            L ^= (
                CardCipher.LUT_B0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(T >> 2) & 0x3F]
            )

            T = expkey[30 - i] ^ R
            L ^= (
                CardCipher.LUT_A0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[(T >> 2) & 0x3F]
            )

            T = expkey[29 - i] ^ L
            T = CardCipher.__ror(T, 28)
            R ^= (
                CardCipher.LUT_B0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_B1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_B2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_B3[(T >> 2) & 0x3F]
            )

            T = expkey[28 - i] ^ L
            R ^= (
                CardCipher.LUT_A0[(T >> 26) & 0x3F]
                ^ CardCipher.LUT_A1[(T >> 18) & 0x3F]
                ^ CardCipher.LUT_A2[(T >> 10) & 0x3F]
                ^ CardCipher.LUT_A3[(T >> 2) & 0x3F]
            )

        return CardCipher.__final_permutation(R, L)

    @staticmethod
    def __ror(val: int, amount: int) -> int:
        return ((val << (32 - amount)) & 0xFFFFFFFF) | ((val >> amount) & 0xFFFFFFFF)
