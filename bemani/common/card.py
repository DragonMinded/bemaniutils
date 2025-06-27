from typing import Dict, List
from typing_extensions import Final

from Crypto.Cipher import DES3


class CardCipherException(Exception):
    pass


class CardCipher:
    """
    Algorithm for converting between the Card ID as stored in an
    eAmusement card and the 16 character card string as shown on
    the back of a card and in-game. All of this was kindly RE'd by
    Tau and converted ham-fistedly to Python.
    """

    # https://bsnk.me/eamuse/cardid.html
    DES_KEY: Final[bytes] = bytes(c * 2 for c in b"?I'llB2c.YouXXXeMeHaYpy!")
    INTERNAL_CIPHER = DES3.new(DES_KEY, DES3.MODE_ECB)

    VALID_CHARS: Final[str] = "0123456789ABCDEFGHJKLMNPRSTUWXYZ"
    REVERSE_CHARS: Final[Dict[str, int]] = {char: off for off, char in enumerate("0123456789ABCDEFGHJKLMNPRSTUWXYZ")}
    CONV_CHARS: Final[Dict[str, str]] = {
        "I": "1",
        "O": "0",
    }

    @staticmethod
    def __type_from_cardid(cardid: str) -> int:
        if cardid[:4].upper() == "E004":
            return 1
        if cardid[:1] == "0":
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
        ciphered = CardCipher.INTERNAL_CIPHER.encrypt(reverse)

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
            groups[i] = CardCipher.REVERSE_CHARS[cardid[i]]

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
        deciphered = CardCipher.INTERNAL_CIPHER.decrypt(ciphered)
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
