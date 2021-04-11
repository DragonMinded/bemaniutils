def _hex(data: int) -> str:
    hexval = hex(data)[2:]
    if len(hexval) == 1:
        return "0" + hexval
    return hexval


def align(val: int) -> int:
    return (val + 3) & 0xFFFFFFFFC


def pad(data: bytes, length: int) -> bytes:
    if len(data) == length:
        return data
    elif len(data) > length:
        raise Exception("Logic error, padding request in data already written!")
    return data + (b"\0" * (length - len(data)))


def descramble_text(text: bytes, obfuscated: bool) -> str:
    if len(text):
        if obfuscated and (text[0] - 0x20) > 0x7F:
            # Gotta do a weird demangling where we swap the
            # top bit.
            return bytes(((x + 0x80) & 0xFF) for x in text).decode('ascii')
        else:
            return text.decode('ascii')
    else:
        return ""


def scramble_text(text: str, obfuscated: bool) -> bytes:
    if obfuscated:
        return bytes(((x + 0x80) & 0xFF) for x in text.encode('ascii')) + b'\0'
    else:
        return text.encode('ascii') + b'\0'
