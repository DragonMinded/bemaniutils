import random


def random_hex_string(length: int, caps: bool = False) -> str:
    if caps:
        string = "0123456789ABCDEF"
    else:
        string = "0123456789abcdef"
    return "".join([random.choice(string) for x in range(length)])
