from ctypes import *

from bemani.backend.ddr.ddrsn2.globalrankingstateentry import GlobalRankingStateEntryStruct
from bemani.backend.ddr.ddrsn2.unlockentry import UnlockEntryStruct
from bemani.backend.ddr.ddrsn2.zukinteams import ZukinTeams


class EventInfoStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("unlocks", UnlockEntryStruct * 256),
        ("global_ranking_state", GlobalRankingStateEntryStruct * 8),
        ("_unused", c_uint8 * 4),  # Unused?
        ("event_ver", c_uint8),  # 0x624
        ("event_end", c_uint8),  # 0x625
        ("event_sel_team", c_uint8),  # 0x626
        ("event_rankings", c_uint8 * 3),  # 0x627
        ("event_avg", c_uint16),  # 0x62a
        ("event_score_green", c_uint32),  # 0x62c
        ("event_score_red", c_uint32),  # 0x62c
        ("event_score_yellow", c_uint32),  # 0x62c
        ("event_border", c_uint16),  # 0x638
    ]


class EventInfo:
    @staticmethod
    def create() -> EventInfoStruct:
        p = EventInfoStruct()
        p.event_ver = 5  # Event episode
        p.event_end = 1  # Event has ended
        p.event_sel_team = ZukinTeams.RED  # Winning team
        p.event_rankings[0] = ZukinTeams.RED
        p.event_rankings[1] = ZukinTeams.GREEN
        p.event_rankings[2] = ZukinTeams.YELLOW
        p.event_avg = 123  # ?
        p.event_score_green = 57312
        p.event_score_red = 3516541
        p.event_score_yellow = 5631
        p.event_border = 123

        for i in range(len(p.unlocks)):
            p.unlocks[i].id = i & 0xFF
            p.unlocks[i].enabled = 1

        for i in range(0, len(p.global_ranking_state)):
            p.global_ranking_state[i].id = i & 0xFF
            p.global_ranking_state[i].state = 2

        p.unlocks[0].enabled = 7  # Phase unlock max

        return p
