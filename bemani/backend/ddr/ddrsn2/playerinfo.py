from ctypes import *

from bemani.backend.ddr.ddrsn2.battlerecord import BattleRecordStruct
from bemani.common import Profile, PlayStatistics


class PlayerInfoStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("count", c_uint16),  # 0x00
        ("area", c_uint16),  # 0x02
        ("title", c_uint16),  # 0x04
        ("flag", c_uint16),  # 0x06
        ("id", c_uint32),  # 0x08
        ("exp", c_uint32),  # 0x0c
        ("weight", c_uint16),  # 0x10
        ("last_cate", c_uint8),  # 0x12
        ("last_mode", c_uint8),  # 0x13
        ("last_type", c_uint8),  # 0x14
        ("last_sort", c_uint8),  # 0x15
        ("last_music", c_uint8),  # 0x16
        ("_unused1", c_char * 6),  # 0x17 - 0x1b
        ("team", c_uint8),  # 0x1c
        ("_unused2", c_char * 8),  # 0x1d - 0x24
        ("takeover", c_uint8),  # 0x25
        ("count_b", c_uint8),  # 0x26
        ("_unused3", c_char * 2),  # 0x27 - 0x29
        ("groove_radar", c_uint16 * 5),  # 0x2a
        ("options", c_uint8 * 32),  # 0x34
        ("name", c_char * 14),  # 0x54
        ("_unused4", c_char * 2),  # 0x62 - 0x63
        # Bit is set to 1 = already displayed, 0 = not yet displayed
        ("unlock_prompt_bits", c_uint8 * 12),  # 0x64 - 0x70
        ("_unused5", c_char * 20),  # 0x70 - 0x83
        ("course", c_uint32 * 3),  # 0x84
        ("_unused6", c_char * (0x1344 - 0x90)),
        ("battle_records", BattleRecordStruct * 5),  # 0x1344
    ]


class PlayerInfo:
    @staticmethod
    def create(play_stats: PlayStatistics, profile: Profile, machine_region: int) -> PlayerInfoStruct:
        player = PlayerInfoStruct()

        player.count = play_stats.get_int("single_plays")
        player.area = profile.get_int("area", machine_region)
        player.title = profile.get_int("title")
        player.flag = profile.get_int("flag")
        player.id = profile.extid
        player.exp = play_stats.get_int("exp")
        player.weight = profile.get_int("weight")

        lastdict = profile.get_dict("last")
        player.last_cate = lastdict.get_int("cate")
        player.last_mode = lastdict.get_int("mode")
        player.last_type = lastdict.get_int("type")
        player.last_sort = lastdict.get_int("sort")
        player.last_music = lastdict.get_int("music")

        player.team = profile.get_int("team")

        player.takeover = profile.get_int("takeover")
        player.count_b = play_stats.get_int("battle_plays")

        idx = 0
        for entry in profile.get_int_array("gr_s", 5):
            player.groove_radar[idx] = entry
            idx += 1

        idx = 0

        # Empty option set is a non-zero opt array, unsure how to do this check with validated_dict cleanly?
        if not profile.has_key("opt"):
            profile.replace_int_array("opt", 16, [2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 2, 0, 0, 0, 0])

        for entry in profile.get_int_array("opt", 16):
            player.options[idx] = entry
            idx += 1

        player.name = (profile.get_str("name").ljust(8, " ")[:8]).encode("ascii")

        # Default, unlock everything?
        for i in range(len(player.unlock_prompt_bits)):
            player.unlock_prompt_bits[i] = 0xFF

        idx = 0
        for entry in profile.get_int_array("course", 3):
            player.course[idx] = entry
            idx += 1

        return player
