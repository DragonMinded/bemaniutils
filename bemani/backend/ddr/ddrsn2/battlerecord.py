import logging
from ctypes import *


class BattleRecordStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("name", c_char * 14),
        ("wins", c_uint16),
        ("loses", c_uint16),
        ("draws", c_uint16),
    ]


class BattleRecord:
    @staticmethod
    def create(name: str, wins: int, losses: int, draws: int) -> BattleRecordStruct:
        this_name = name
        if len(this_name) > 8:
            this_name = this_name[:8]
            logging.warning("name {} too long, truncating to {}", name, this_name)
        elif len(this_name) < 8:
            logging.warning("name too short, padding with spaces")
            this_name = this_name.ljust(8, " ")

        return BattleRecordStruct(this_name.encode("ascii"), wins, losses, draws)
