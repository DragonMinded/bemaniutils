from ctypes import *


class GlobalRankingStateEntryStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c_int8),
        ("state", c_int8),  # 0 = disabled, 1 = English ("Global Ranking"), 2 = Japanese ("Gachinko Dance Matsuri")
        ("_unused", c_int8 * 2),
    ]


class GlobalRankingStateEntry:
    @staticmethod
    def create(id: int, state: int) -> GlobalRankingStateEntryStruct:
        return GlobalRankingStateEntryStruct(id, state)
