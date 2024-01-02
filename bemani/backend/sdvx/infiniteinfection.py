# vim: set fileencoding=utf-8
from typing import Any, Dict, List, Optional
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.sdvx.base import SoundVoltexBase
from bemani.backend.sdvx.booth import SoundVoltexBooth
from bemani.common import Profile, VersionConstants, ID
from bemani.data import UserID
from bemani.protocol import Node


class SoundVoltexInfiniteInfection(
    EventLogHandler,
    SoundVoltexBase,
):
    name: str = "SOUND VOLTEX II -infinite infection-"
    version: int = VersionConstants.SDVX_INFINITE_INFECTION

    GAME_LIMITED_LOCKED: Final[int] = 1
    GAME_LIMITED_UNLOCKABLE: Final[int] = 2
    GAME_LIMITED_UNLOCKED: Final[int] = 3

    GAME_CURRENCY_PACKETS: Final[int] = 0
    GAME_CURRENCY_BLOCKS: Final[int] = 1

    GAME_CLEAR_TYPE_NO_CLEAR: Final[int] = 1
    GAME_CLEAR_TYPE_CLEAR: Final[int] = 2
    GAME_CLEAR_TYPE_HARD_CLEAR: Final[int] = 5
    GAME_CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = 3
    GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[int] = 4

    GAME_GRADE_NO_PLAY: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_AA: Final[int] = 5
    GAME_GRADE_AAA: Final[int] = 6

    GAME_CATALOG_TYPE_SONG: Final[int] = 0
    GAME_CATALOG_TYPE_APPEAL_CARD: Final[int] = 1
    GAME_CATALOG_TYPE_SPECIAL_SONG: Final[int] = 2

    GAME_GAUGE_TYPE_SKILL: Final[int] = 1

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Disable Online Matching",
                    "tip": "Disable online matching between games.",
                    "category": "game_config",
                    "setting": "disable_matching",
                },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
                {
                    "name": "Force Appeal Card Unlock",
                    "tip": "Force unlock all appeal cards.",
                    "category": "game_config",
                    "setting": "force_unlock_cards",
                },
            ],
            "ints": [
                {
                    "name": "BEMANI Stadium Event Phase",
                    "tip": "BEMANI Stadium event phase for all players.",
                    "category": "game_config",
                    "setting": "bemani_stadium",
                    "values": {
                        0: "No Event",
                        1: "BEMANI Stadium",
                        2: "BEMANI iseki",
                    },
                },
            ],
        }

    def previous_version(self) -> Optional[SoundVoltexBase]:
        return SoundVoltexBooth(self.data, self.config, self.model)

    def __game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_CLEAR: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEAR: self.CLEAR_TYPE_CLEAR,
            self.GAME_CLEAR_TYPE_HARD_CLEAR: self.CLEAR_TYPE_HARD_CLEAR,
            self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN: self.CLEAR_TYPE_ULTIMATE_CHAIN,
            self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_CLEAR: self.GAME_CLEAR_TYPE_CLEAR,
            self.CLEAR_TYPE_HARD_CLEAR: self.GAME_CLEAR_TYPE_HARD_CLEAR,
            self.CLEAR_TYPE_ULTIMATE_CHAIN: self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN,
            self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __game_to_db_grade(self, grade: int) -> int:
        return {
            self.GAME_GRADE_NO_PLAY: self.GRADE_NO_PLAY,
            self.GAME_GRADE_D: self.GRADE_D,
            self.GAME_GRADE_C: self.GRADE_C,
            self.GAME_GRADE_B: self.GRADE_B,
            self.GAME_GRADE_A: self.GRADE_A,
            self.GAME_GRADE_AA: self.GRADE_AA,
            self.GAME_GRADE_AAA: self.GRADE_AAA,
        }[grade]

    def __db_to_game_grade(self, grade: int) -> int:
        return {
            self.GRADE_NO_PLAY: self.GAME_GRADE_NO_PLAY,
            self.GRADE_D: self.GAME_GRADE_D,
            self.GRADE_C: self.GAME_GRADE_C,
            self.GRADE_B: self.GAME_GRADE_B,
            self.GRADE_A: self.GAME_GRADE_A,
            self.GRADE_A_PLUS: self.GAME_GRADE_A,
            self.GRADE_AA: self.GAME_GRADE_AA,
            self.GRADE_AA_PLUS: self.GAME_GRADE_AA,
            self.GRADE_AAA: self.GAME_GRADE_AAA,
            self.GRADE_AAA_PLUS: self.GAME_GRADE_AAA,
            self.GRADE_S: self.GAME_GRADE_AAA,
        }[grade]

    def __get_skill_analyzer_seasons(self) -> Dict[int, str]:
        return {
            6: "SKILL ANALYZER 第6回 (2013/12/06)",
            7: "SKILL ANALYZER 第7回 (2014/01/10)",
            8: "SKILL ANALYZER 第8回 (2014/02/06)",
            9: "SKILL ANALYZER 第9回 (2014/03/06)",
            10: "SKILL ANALYZER 第10回 (2014/04/04)",
            11: "SKILL ANALYZER 第11回 (2014/05/01)",
            12: "SKILL ANALYZER 第12回 (2014/06/05)",
            13: "SKILL ANALYZER 第13回 (2014/07/04)",
            14: "SKILL ANALYZER 第14回 (2014/08/01)",
        }

    def __get_skill_analyzer_skill_levels(self) -> Dict[int, str]:
        return {
            0: "Skill LEVEL 01 岳翔",
            1: "Skill LEVEL 02 流星",
            2: "Skill LEVEL 03 月衝",
            3: "Skill LEVEL 04 瞬光",
            4: "Skill LEVEL 05 天極",
            5: "Skill LEVEL 06 烈風",
            6: "Skill LEVEL 07 雷電",
            7: "Skill LEVEL 08 麗華",
            8: "Skill LEVEL 09 魔騎士",
            9: "Skill LEVEL 10 剛力羅",
            10: "Skill LEVEL 11 或帝滅斗",
            11: "Skill LEVEL ∞(12) 暴龍天",
        }

    def __get_skill_analyzer_courses(self) -> List[Dict[str, Any]]:
        return [
            {
                "level": 0,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 109,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 24,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 245,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 313,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 7,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 4,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 39,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 134,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 314,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 59,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 23,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 86,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 128,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 2,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 256,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 255,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 246,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 96,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 139,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 216,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 244,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 250,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 180,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 7,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 214,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 54,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 221,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 51,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 6,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 111,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 183,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 56,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 333,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 10,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 134,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 75,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 369,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 224,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 323,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 128,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 85,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 344,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 241,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 251,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 139,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 341,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 346,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 302,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 19,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 329,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 289,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 54,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 221,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 51,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 6,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 111,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 183,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 56,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 333,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 10,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 134,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 75,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 369,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 224,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 323,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 128,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 85,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 344,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 241,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 251,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 139,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 341,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 346,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 302,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 19,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 329,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 289,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 60,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 328,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 278,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 313,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 41,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 80,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 295,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 45,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 44,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 326,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 340,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 23,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 115,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 288,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 57,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 267,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 246,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 304,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 155,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 373,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 122,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 359,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 247,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 221,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 229,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 363,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 365,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 328,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 51,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 111,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 41,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 15,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 10,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 259,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 23,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 66,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 62,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 85,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 288,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 78,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 311,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 71,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 341,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 173,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 228,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 166,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 155,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 229,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 384,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 54,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 365,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 374,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 183,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 56,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 39,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 10,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 369,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 222,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 103,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 158,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 74,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 262,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 128,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 79,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 264,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 71,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 192,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 253,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 341,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 58,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 269,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 289,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 376,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 189,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 245,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 278,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 340,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 183,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 426,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 349,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 342,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 190,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 222,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 158,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 352,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 212,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 275,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 198,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 331,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 184,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 345,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 218,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 268,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 373,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 244,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 414,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 269,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 408,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 376,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 189,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 219,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 278,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 340,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 313,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 223,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 407,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 77,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 92,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 337,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 8,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 375,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 426,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 401,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 345,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 290,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 432,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 72,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 373,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 125,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 302,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 252,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 247,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 437,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 342,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 228,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 374,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 24,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 76,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 8,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 309,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 412,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 155,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 99,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 269,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 24,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 171,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 92,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 34,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 42,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 275,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 480,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 170,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 264,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 307,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 253,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 72,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 430,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 220,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 413,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 437,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 10,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 374,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 360,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 11,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 366,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
        ]

    def handle_game_2_exception_request(self, request: Node) -> Node:
        return Node.void("game_2")

    def handle_game_2_play_e_request(self, request: Node) -> Node:
        return Node.void("game_2")

    def handle_game_2_save_e_request(self, request: Node) -> Node:
        # This has to do with Policy Break against ReflecBeat and
        # floor infection, but we don't implement multi-game support so meh.
        return Node.void("game_2")

    def handle_game_2_lounge_request(self, request: Node) -> Node:
        game = Node.void("game_2")
        # Refresh interval in seconds.
        game.add_child(Node.u32("interval", 10))
        return game

    def handle_game_2_entry_s_request(self, request: Node) -> Node:
        game = Node.void("game_2")
        # This should be created on the fly for a lobby that we're in.
        game.add_child(Node.u32("entry_id", 1))
        return game

    def handle_game_2_entry_e_request(self, request: Node) -> Node:
        # Lobby destroy method, eid node (u32) should be used
        # to destroy any open lobbies.
        return Node.void("game_2")

    def handle_game_2_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("shopname"))

        # Respond with number of milliseconds until next request
        game = Node.void("game_2")
        game.add_child(Node.u32("nxt_time", 1000 * 5 * 60))
        return game

    def handle_game_2_common_request(self, request: Node) -> Node:
        game = Node.void("game_2")
        limited = Node.void("music_limited")
        game.add_child(limited)

        # Song unlock config
        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            ids = set()
            songs = self.data.local.music.get_all_songs(self.game, self.version)
            for song in songs:
                if song.data.get_int("limited") in (
                    self.GAME_LIMITED_LOCKED,
                    self.GAME_LIMITED_UNLOCKABLE,
                ):
                    ids.add((song.id, song.chart))

            for songid, chart in ids:
                info = Node.void("info")
                limited.add_child(info)
                info.add_child(Node.s32("music_id", songid))
                info.add_child(Node.u8("music_type", chart))
                info.add_child(Node.u8("limited", self.GAME_LIMITED_UNLOCKED))

        # Event config
        event = Node.void("event")
        game.add_child(event)

        def enable_event(eid: int) -> None:
            evt = Node.void("info")
            event.add_child(evt)
            evt.add_child(Node.u32("event_id", eid))

        if not game_config.get_bool("disable_matching"):
            enable_event(1)  # Matching enabled
        enable_event(2)  # BEMANI Academy
        enable_event(3)  # Floor Infection
        enable_event(6)  # Skill Analyzer
        enable_event(9)  # Policy Break
        enable_event(14)  # Enable pages on Skill Analyzer

        stadium = game_config.get_int("bemani_stadium")
        if stadium == 1:
            enable_event(18)  # BEMANI Stadium (mutually exclusive with BEMANI iseki)
        if stadium == 2:
            enable_event(51)  # BEMANI iseki (mutually exclusive with BEMANI Stadium)

        # In-game purchases catalog config (this isn't necessary for SDVX 2 to work).
        catalog = Node.void("catalog")
        game.add_child(catalog)
        songunlocks = self.data.local.game.get_items(self.game, self.version)
        for unlock in songunlocks:
            if unlock.type == "song_unlock":
                info = Node.void("info")
                catalog.add_child(info)
                info.add_child(Node.u8("catalog_type", self.GAME_CATALOG_TYPE_SONG))
                info.add_child(Node.u32("catalog_id", unlock.id))
                info.add_child(Node.u32("currency_type", self.GAME_CURRENCY_BLOCKS))
                info.add_child(Node.u32("price", unlock.data.get_int("blocks")))
            elif unlock.type == "special_unlock":
                info = Node.void("info")
                catalog.add_child(info)
                info.add_child(Node.u8("catalog_type", self.GAME_CATALOG_TYPE_SPECIAL_SONG))
                info.add_child(Node.u32("catalog_id", unlock.id))
                info.add_child(Node.u32("currency_type", self.GAME_CURRENCY_BLOCKS))
                info.add_child(Node.u32("price", unlock.data.get_int("blocks")))

        # Skill Analyzer config
        skill_course = Node.void("skill_course")
        game.add_child(skill_course)

        seasons = self.__get_skill_analyzer_seasons()
        skillnames = self.__get_skill_analyzer_skill_levels()
        last_season = max(seasons.keys())
        for course in self.__get_skill_analyzer_courses():
            info = Node.void("info")
            skill_course.add_child(info)
            info.add_child(Node.s16("course_id", course["level"]))
            info.add_child(Node.s16("level", course["level"]))
            info.add_child(Node.s32("season_id", course["season_id"]))
            info.add_child(Node.string("season_name", seasons[course["season_id"]]))
            info.add_child(Node.bool("season_new_flg", course["season_id"] == last_season))
            info.add_child(Node.string("course_name", skillnames[course["level"]]))
            info.add_child(Node.s16("course_type", 0))
            info.add_child(Node.s16("skill_name_id", course["level"]))
            info.add_child(Node.bool("matching_assist", course["level"] <= 6))
            info.add_child(Node.s16("gauge_type", self.GAME_GAUGE_TYPE_SKILL))
            info.add_child(Node.s16("paseli_type", 0))

            trackno = 0
            for trackdata in course["tracks"]:
                track = Node.void("track")
                info.add_child(track)
                track.add_child(Node.s16("track_no", trackno))
                track.add_child(Node.s32("music_id", trackdata["id"]))
                track.add_child(Node.s8("music_type", trackdata["type"]))
                trackno = trackno + 1

        return game

    def handle_game_2_hiscore_request(self, request: Node) -> Node:
        # Grab location for local scores
        locid = ID.parse_machine_id(request.child_value("locid"))

        # Start the response packet
        game = Node.void("game_2")

        # First, grab hit chart
        playcounts = self.data.local.music.get_hit_chart(self.game, self.version, 1024)

        hitchart = Node.void("hitchart")
        game.add_child(hitchart)
        for songid, count in playcounts:
            info = Node.void("info")
            hitchart.add_child(info)
            info.add_child(Node.u32("id", songid))
            info.add_child(Node.u32("cnt", count))

        # Now, grab user records
        records = self.data.remote.music.get_all_records(self.game, self.version)
        missing_users = [userid for (userid, _) in records]
        users = {userid: profile for (userid, profile) in self.get_any_profiles(missing_users)}

        hiscore_allover = Node.void("hiscore_allover")
        game.add_child(hiscore_allover)

        # Output records
        for userid, score in records:
            info = Node.void("info")

            if userid not in users:
                raise Exception("Logic error, missing profile for user!")
            profile = users[userid]

            info.add_child(Node.u32("id", score.id))
            info.add_child(Node.u32("type", score.chart))
            info.add_child(Node.string("name", profile.get_str("name")))
            info.add_child(Node.string("code", ID.format_extid(profile.extid)))
            info.add_child(Node.u32("score", score.points))

            # Add to global scores
            hiscore_allover.add_child(info)

        # Now, grab local records
        area_users = [
            uid
            for (uid, prof) in self.data.local.user.get_all_profiles(self.game, self.version)
            if prof.get_int("loc", -1) == locid
        ]
        records = self.data.local.music.get_all_records(self.game, self.version, userlist=area_users)
        missing_users = [userid for (userid, _) in records if userid not in users]
        for userid, profile in self.get_any_profiles(missing_users):
            users[userid] = profile

        hiscore_location = Node.void("hiscore_location")
        game.add_child(hiscore_location)

        # Output records
        for userid, score in records:
            info = Node.void("info")

            if userid not in users:
                raise Exception("Logic error, missing profile for user!")
            profile = users[userid]

            info.add_child(Node.u32("id", score.id))
            info.add_child(Node.u32("type", score.chart))
            info.add_child(Node.string("name", profile.get_str("name")))
            info.add_child(Node.string("code", ID.format_extid(profile.extid)))
            info.add_child(Node.u32("score", score.points))

            # Add to local scores
            hiscore_location.add_child(info)

        # Now, grab clear rates
        clear_rate = Node.void("clear_rate")
        game.add_child(clear_rate)

        clears = self.get_clear_rates()
        for songid in clears:
            for chart in clears[songid]:
                if clears[songid][chart]["total"] > 0:
                    rate = float(clears[songid][chart]["clears"]) / float(clears[songid][chart]["total"])
                    dnode = Node.void("d")
                    clear_rate.add_child(dnode)
                    dnode.add_child(Node.u32("id", songid))
                    dnode.add_child(Node.u32("type", chart))
                    dnode.add_child(Node.s16("cr", int(rate * 10000)))

        return game

    def handle_game_2_new_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        name = request.child_value("name")
        loc = ID.parse_machine_id(request.child_value("locid"))
        self.new_profile_by_refid(refid, name, loc)

        root = Node.void("game_2")
        return root

    def handle_game_2_frozen_request(self, request: Node) -> Node:
        game = Node.void("game_2")
        game.add_child(Node.u8("result", 0))
        return game

    def handle_game_2_load_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        root = self.get_profile_by_refid(refid)
        if root is not None:
            return root

        # Figure out if this user has an older profile or not
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        if userid is not None:
            previous_game = self.previous_version()
        else:
            previous_game = None

        if previous_game is not None:
            profile = previous_game.get_profile(userid)
        else:
            profile = None

        if profile is not None:
            root = Node.void("game_2")
            root.add_child(Node.u8("result", 2))
            root.add_child(Node.string("name", profile.get_str("name")))
            return root
        else:
            root = Node.void("game_2")
            root.add_child(Node.u8("result", 1))
            return root

    def handle_game_2_save_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            oldprofile = self.get_profile(userid)
            newprofile = self.unformat_profile(userid, request, oldprofile)
        else:
            newprofile = None

        if userid is not None and newprofile is not None:
            self.put_profile(userid, newprofile)

        return Node.void("game_2")

    def handle_game_2_load_m_request(self, request: Node) -> Node:
        refid = request.child_value("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        else:
            scores = []

        # Output to the game
        game = Node.void("game_2")
        new = Node.void("new")
        game.add_child(new)

        for score in scores:
            music = Node.void("music")
            new.add_child(music)
            music.add_child(Node.u32("music_id", score.id))
            music.add_child(Node.u32("music_type", score.chart))
            music.add_child(Node.u32("score", score.points))
            music.add_child(Node.u32("cnt", score.plays))
            music.add_child(
                Node.u32(
                    "clear_type",
                    self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                )
            )
            music.add_child(Node.u32("score_grade", self.__db_to_game_grade(score.data.get_int("grade"))))
            stats = score.data.get_dict("stats")
            music.add_child(Node.u32("btn_rate", stats.get_int("btn_rate")))
            music.add_child(Node.u32("long_rate", stats.get_int("long_rate")))
            music.add_child(Node.u32("vol_rate", stats.get_int("vol_rate")))

        return game

    def handle_game_2_save_m_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        # Doesn't matter if userid is None here, that's an anonymous score
        musicid = request.child_value("music_id")
        chart = request.child_value("music_type")
        points = request.child_value("score")
        combo = request.child_value("max_chain")
        clear_type = self.__game_to_db_clear_type(request.child_value("clear_type"))
        grade = self.__game_to_db_grade(request.child_value("score_grade"))
        stats = {
            "btn_rate": request.child_value("btn_rate"),
            "long_rate": request.child_value("long_rate"),
            "vol_rate": request.child_value("vol_rate"),
            "critical": request.child_value("critical"),
            "near": request.child_value("near"),
            "error": request.child_value("error"),
        }

        # Save the score
        self.update_score(
            userid,
            musicid,
            chart,
            points,
            clear_type,
            grade,
            combo,
            stats,
        )

        # Return a blank response
        return Node.void("game_2")

    def handle_game_2_save_c_request(self, request: Node) -> Node:
        refid = request.child_value("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            course_id = request.child_value("crsid")
            clear_type = request.child_value("ct")
            achievement_rate = request.child_value("ar")
            season_id = request.child_value("ssnid")

            # Do not update the course achievement when old achievement rate is greater.
            old = self.data.local.user.get_achievement(
                self.game, self.version, userid, (season_id * 100) + course_id, "course"
            )
            if old is not None and old.get_int("achievement_rate") > achievement_rate:
                return Node.void("game_2")

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                (season_id * 100) + course_id,
                "course",
                {
                    "clear_type": clear_type,
                    "achievement_rate": achievement_rate,
                },
            )

        # Return a blank response
        return Node.void("game_2")

    def handle_game_2_buy_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            profile = self.get_profile(userid)
        else:
            profile = None

        if userid is not None and profile is not None:
            # Look up packets and blocks
            packet = profile.get_int("packet")
            block = profile.get_int("block")

            # Add on any additional we earned this round
            packet = packet + (request.child_value("earned_gamecoin_packet") or 0)
            block = block + (request.child_value("earned_gamecoin_block") or 0)

            currency_type = request.child_value("currency_type")
            price = request.child_value("price")

            if currency_type == self.GAME_CURRENCY_PACKETS:
                # This is a valid purchase
                newpacket = packet - price
                if newpacket < 0:
                    result = 1
                else:
                    packet = newpacket
                    result = 0
            elif currency_type == self.GAME_CURRENCY_BLOCKS:
                # This is a valid purchase
                newblock = block - price
                if newblock < 0:
                    result = 1
                else:
                    block = newblock
                    result = 0
            else:
                # Bad currency type
                result = 1

            if result == 0:
                # Transaction is valid, update the profile with new packets and blocks
                profile.replace_int("packet", packet)
                profile.replace_int("block", block)
                self.put_profile(userid, profile)

                # If this was a song unlock, we should mark it as unlocked
                item_type = request.child_value("item_type")
                item_id = request.child_value("item_id")
                param = request.child_value("param")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    item_id,
                    f"item_{item_type}",
                    {
                        "param": param,
                    },
                )

        else:
            # Unclear what to do here, return a bad response
            packet = 0
            block = 0
            result = 1

        game = Node.void("game_2")
        game.add_child(Node.u32("gamecoin_packet", packet))
        game.add_child(Node.u32("gamecoin_block", block))
        game.add_child(Node.s8("result", result))
        return game

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        game = Node.void("game_2")

        # Generic profile stuff
        game.add_child(Node.string("name", profile.get_str("name")))
        game.add_child(Node.string("code", ID.format_extid(profile.extid)))
        game.add_child(Node.u32("gamecoin_packet", profile.get_int("packet")))
        game.add_child(Node.u32("gamecoin_block", profile.get_int("block")))
        game.add_child(Node.s16("skill_name_id", profile.get_int("skill_name_id", -1)))
        game.add_child(Node.s32_array("hidden_param", profile.get_int_array("hidden_param", 20)))
        game.add_child(Node.u32("blaster_energy", profile.get_int("blaster_energy")))
        game.add_child(Node.u32("blaster_count", profile.get_int("blaster_count")))

        # Play statistics
        statistics = self.get_play_statistics(userid)
        game.add_child(Node.u32("play_count", statistics.total_plays))
        game.add_child(Node.u32("daily_count", statistics.today_plays))
        game.add_child(Node.u32("play_chain", statistics.consecutive_days))

        # Last played stuff
        if "last" in profile:
            lastdict = profile.get_dict("last")
            last = Node.void("last")
            game.add_child(last)
            last.add_child(Node.s32("music_id", lastdict.get_int("music_id", -1)))
            last.add_child(Node.u8("music_type", lastdict.get_int("music_type")))
            last.add_child(Node.u8("sort_type", lastdict.get_int("sort_type")))
            last.add_child(Node.u8("narrow_down", lastdict.get_int("narrow_down")))
            last.add_child(Node.u8("headphone", lastdict.get_int("headphone")))
            last.add_child(Node.u8("hispeed", lastdict.get_int("hispeed", 8)))
            last.add_child(Node.u16("appeal_id", lastdict.get_int("appeal_id", 1001)))
            last.add_child(Node.u16("comment_id", lastdict.get_int("comment_id")))
            last.add_child(Node.u8("gauge_option", lastdict.get_int("gauge_option")))

        # Item unlocks
        itemnode = Node.void("item")
        game.add_child(itemnode)

        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)

        for item in achievements:
            if item.type[:5] != "item_":
                continue
            itemtype = int(item.type[5:])

            if itemtype == self.GAME_CATALOG_TYPE_APPEAL_CARD:
                # Type 1 is appeal cards, and the game saves this for non-default cards but
                # we take care of this below.
                continue
            if itemtype == self.GAME_CATALOG_TYPE_SONG and game_config.get_bool("force_unlock_songs"):
                # We will echo this below in the force unlock song section
                continue

            info = Node.void("info")
            itemnode.add_child(info)
            info.add_child(Node.u8("type", itemtype))
            info.add_child(Node.u32("id", item.id))
            info.add_child(Node.u32("param", item.data.get_int("param")))

        if game_config.get_bool("force_unlock_songs"):
            ids: Dict[int, int] = {}
            songs = self.data.local.music.get_all_songs(self.game, self.version)
            for song in songs:
                if song.id not in ids:
                    ids[song.id] = 0

                if song.data.get_int("difficulty") > 0:
                    ids[song.id] = ids[song.id] | (1 << song.chart)

            for itemid in ids:
                if ids[itemid] == 0:
                    continue

                info = Node.void("info")
                itemnode.add_child(info)
                info.add_child(Node.u8("type", self.GAME_CATALOG_TYPE_SONG))
                info.add_child(Node.u32("id", itemid))
                info.add_child(Node.u32("param", ids[itemid]))

        # Appeal card unlocks
        appealcard = Node.void("appealcard")
        game.add_child(appealcard)

        if not game_config.get_bool("force_unlock_cards"):
            for card in achievements:
                if card.type != "appealcard":
                    continue

                info = Node.void("info")
                appealcard.add_child(info)
                info.add_child(Node.u32("id", card.id))
                info.add_child(Node.u32("count", card.data.get_int("count")))
        else:
            catalog = self.data.local.game.get_items(self.game, self.version)
            for unlock in catalog:
                if unlock.type != "appealcard":
                    continue
                info = Node.void("info")
                appealcard.add_child(info)
                info.add_child(Node.u32("id", unlock.id))
                info.add_child(Node.u32("count", 0))

        # Skill courses
        skill = Node.void("skill")
        game.add_child(skill)
        course_all = Node.void("course_all")
        skill.add_child(course_all)

        for course in achievements:
            if course.type != "course":
                continue

            course_id = course.id % 100
            season_id = int(course.id / 100)

            info = Node.void("d")
            course_all.add_child(info)
            info.add_child(Node.s16("crsid", course_id))
            info.add_child(Node.s16("ct", course.data.get_int("clear_type")))
            info.add_child(Node.s16("ar", course.data.get_int("achievement_rate")))
            info.add_child(Node.s32("ssnid", season_id))

        return game

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()

        # Update blaster energy and in-game currencies
        earned_gamecoin_packet = request.child_value("earned_gamecoin_packet")
        if earned_gamecoin_packet is not None:
            newprofile.replace_int("packet", newprofile.get_int("packet") + earned_gamecoin_packet)
        earned_gamecoin_block = request.child_value("earned_gamecoin_block")
        if earned_gamecoin_block is not None:
            newprofile.replace_int("block", newprofile.get_int("block") + earned_gamecoin_block)
        earned_blaster_energy = request.child_value("earned_blaster_energy")
        if earned_blaster_energy is not None:
            newprofile.replace_int(
                "blaster_energy",
                newprofile.get_int("blaster_energy") + earned_blaster_energy,
            )

        # Miscelaneous stuff
        newprofile.replace_int("blaster_count", request.child_value("blaster_count"))
        newprofile.replace_int("skill_name_id", request.child_value("skill_name_id"))
        newprofile.replace_int_array("hidden_param", 20, request.child_value("hidden_param"))

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()
        if not game_config.get_bool("force_unlock_cards"):
            for child in request.child("appealcard").children:
                if child.name != "info":
                    continue

                appealid = child.child_value("id")
                count = child.child_value("count")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    appealid,
                    "appealcard",
                    {
                        "count": count,
                    },
                )

        if not game_config.get_bool("force_unlock_songs"):
            for child in request.child("item").children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                param = child.child_value("param")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    item_id,
                    f"item_{item_type}",
                    {
                        "param": param,
                    },
                )

        # Grab last information.
        lastdict = newprofile.get_dict("last")
        lastdict.replace_int("headphone", request.child_value("headphone"))
        lastdict.replace_int("hispeed", request.child_value("hispeed"))
        lastdict.replace_int("appeal_id", request.child_value("appeal_id"))
        lastdict.replace_int("comment_id", request.child_value("comment_id"))
        lastdict.replace_int("music_id", request.child_value("music_id"))
        lastdict.replace_int("music_type", request.child_value("music_type"))
        lastdict.replace_int("sort_type", request.child_value("sort_type"))
        lastdict.replace_int("narrow_down", request.child_value("narrow_down"))
        lastdict.replace_int("gauge_option", request.child_value("gauge_option"))

        # Save back last information gleaned from results
        newprofile.replace_dict("last", lastdict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
