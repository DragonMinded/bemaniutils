# vim: set fileencoding=utf-8
from typing import Any, Dict, List, Optional, Tuple
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.sdvx.base import SoundVoltexBase
from bemani.backend.sdvx.gravitywars import SoundVoltexGravityWars
from bemani.common import ID, Profile, VersionConstants
from bemani.data import Score, UserID
from bemani.protocol import Node


class SoundVoltexHeavenlyHaven(
    EventLogHandler,
    SoundVoltexBase,
):
    name: str = "SOUND VOLTEX IV HEAVENLY HAVEN"
    version: int = VersionConstants.SDVX_HEAVENLY_HAVEN

    GAME_LIMITED_LOCKED: Final[int] = 1
    GAME_LIMITED_UNLOCKABLE: Final[int] = 2
    GAME_LIMITED_UNLOCKED: Final[int] = 3

    GAME_CURRENCY_PACKETS: Final[int] = 0
    GAME_CURRENCY_BLOCKS: Final[int] = 1

    GAME_CATALOG_TYPE_SONG: Final[int] = 0
    GAME_CATALOG_TYPE_APPEAL_CARD: Final[int] = 1
    GAME_CATALOG_TYPE_CREW: Final[int] = 4

    GAME_CLEAR_TYPE_NO_PLAY: Final[int] = 0
    GAME_CLEAR_TYPE_FAILED: Final[int] = 1
    GAME_CLEAR_TYPE_CLEAR: Final[int] = 2
    GAME_CLEAR_TYPE_HARD_CLEAR: Final[int] = 3
    GAME_CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = 4
    GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[int] = 5

    GAME_GRADE_NO_PLAY: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_A_PLUS: Final[int] = 5
    GAME_GRADE_AA: Final[int] = 6
    GAME_GRADE_AA_PLUS: Final[int] = 7
    GAME_GRADE_AAA: Final[int] = 8
    GAME_GRADE_AAA_PLUS: Final[int] = 9
    GAME_GRADE_S: Final[int] = 10

    GAME_SKILL_NAME_ID_LV_01: Final[int] = 1
    GAME_SKILL_NAME_ID_LV_02: Final[int] = 2
    GAME_SKILL_NAME_ID_LV_03: Final[int] = 3
    GAME_SKILL_NAME_ID_LV_04: Final[int] = 4
    GAME_SKILL_NAME_ID_LV_05: Final[int] = 5
    GAME_SKILL_NAME_ID_LV_06: Final[int] = 6
    GAME_SKILL_NAME_ID_LV_07: Final[int] = 7
    GAME_SKILL_NAME_ID_LV_08: Final[int] = 8
    GAME_SKILL_NAME_ID_LV_09: Final[int] = 9
    GAME_SKILL_NAME_ID_LV_10: Final[int] = 10
    GAME_SKILL_NAME_ID_LV_11: Final[int] = 11
    GAME_SKILL_NAME_ID_LV_INF: Final[int] = 12
    GAME_SKILL_NAME_ID_KAC_6TH_BODY: Final[int] = 13
    GAME_SKILL_NAME_ID_KAC_6TH_TECHNOLOGY: Final[int] = 14
    GAME_SKILL_NAME_ID_KAC_6TH_HEART: Final[int] = 15
    GAME_SKILL_NAME_ID_TENKAICHI: Final[int] = 16
    GAME_SKILL_NAME_ID_MUSIC_FESTIVAL: Final[int] = 17
    GAME_SKILL_NAME_ID_YELLOWTAIL: Final[int] = 18  # For the April Fool's day courses.
    GAME_SKILL_NAME_ID_BMK2017: Final[int] = 19
    GAME_SKILL_NAME_ID_KAC_7TH_TIGER: Final[int] = 20
    GAME_SKILL_NAME_ID_KAC_7TH_WOLF: Final[int] = 21
    GAME_SKILL_NAME_ID_RIKKA: Final[int] = 22  # For the course that ran from 1/18/2018-2/18/2018
    GAME_SKILL_NAME_ID_KAC_8TH: Final[int] = 23

    # Return the local2 service so that SDVX 4 and above will send certain packets.
    extra_services: List[str] = [
        "local2",
    ]

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
                {
                    "name": "Force Crew Card Unlock",
                    "tip": "Force unlock all crew and subcrew cards.",
                    "category": "game_config",
                    "setting": "force_unlock_crew",
                },
                {
                    "name": "50th Anniversary Celebration",
                    "tip": "Display the 50th anniversary screen in attract mode",
                    "category": "game_config",
                    "setting": "50th_anniversary",
                },
            ],
        }

    def previous_version(self) -> Optional[SoundVoltexBase]:
        return SoundVoltexGravityWars(self.data, self.config, self.model)

    def __game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_PLAY: self.CLEAR_TYPE_NO_PLAY,
            self.GAME_CLEAR_TYPE_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEAR: self.CLEAR_TYPE_CLEAR,
            self.GAME_CLEAR_TYPE_HARD_CLEAR: self.CLEAR_TYPE_HARD_CLEAR,
            self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN: self.CLEAR_TYPE_ULTIMATE_CHAIN,
            self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_PLAY,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_FAILED,
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
            self.GAME_GRADE_A_PLUS: self.GRADE_A_PLUS,
            self.GAME_GRADE_AA: self.GRADE_AA,
            self.GAME_GRADE_AA_PLUS: self.GRADE_AA_PLUS,
            self.GAME_GRADE_AAA: self.GRADE_AAA,
            self.GAME_GRADE_AAA_PLUS: self.GRADE_AAA_PLUS,
            self.GAME_GRADE_S: self.GRADE_S,
        }[grade]

    def __db_to_game_grade(self, grade: int) -> int:
        return {
            self.GRADE_NO_PLAY: self.GAME_GRADE_NO_PLAY,
            self.GRADE_D: self.GAME_GRADE_D,
            self.GRADE_C: self.GAME_GRADE_C,
            self.GRADE_B: self.GAME_GRADE_B,
            self.GRADE_A: self.GAME_GRADE_A,
            self.GRADE_A_PLUS: self.GAME_GRADE_A_PLUS,
            self.GRADE_AA: self.GAME_GRADE_AA,
            self.GRADE_AA_PLUS: self.GAME_GRADE_AA_PLUS,
            self.GRADE_AAA: self.GAME_GRADE_AAA,
            self.GRADE_AAA_PLUS: self.GAME_GRADE_AAA_PLUS,
            self.GRADE_S: self.GAME_GRADE_S,
        }[grade]

    def handle_game_sv4_exception_request(self, request: Node) -> Node:
        return Node.void("game")

    def handle_game_sv4_lounge_request(self, request: Node) -> Node:
        game = Node.void("game")
        # Refresh interval in seconds.
        game.add_child(Node.u32("interval", 10))
        return game

    def handle_game_sv4_entry_s_request(self, request: Node) -> Node:
        game = Node.void("game")
        # This should be created on the fly for a lobby that we're in.
        game.add_child(Node.u32("entry_id", 1))
        return game

    def handle_game_sv4_entry_e_request(self, request: Node) -> Node:
        # Lobby destroy method, eid node (u32) should be used
        # to destroy any open lobbies.
        return Node.void("game")

    def __get_skill_analyzer_seasons(self) -> Dict[int, str]:
        return {
            0: "第1回 Aコース",
            1: "第1回 Bコース",
            2: "第1回 Cコース",
            3: "第2回 Aコース",
            4: "第2回 Bコース",
            5: "第3回",
            6: "第4回 Aコース",
            7: "第4回 Bコース",
            8: "第4回 Cコース",
            9: "第5回",
            10: "第6回 Aコース",
            11: "第6回 Bコース",
            12: "第6回 Cコース",
            13: "The 6th KAC挑戦コース【体】",
            14: "The 6th KAC挑戦コース【技】",
            15: "The 6th KAC挑戦コース【心】",
            16: "天下一 (梅)",
            17: "天下一 (竹)",
            18: "天下一 (松)",
            19: "BEMANI MASTER KOREA 2017",
            20: "The 7th KACチャレンジコース【猛虎】",
            21: "The 7th KACチャレンジコース【餓狼】",
            22: "The 8th KACチャレンジコース【阿修羅】",
            23: "The 8th KACエンジョイコース【阿修羅】",
            24: "第5回 Bコース",
        }

    def __get_skill_analyzer_skill_levels(self) -> Dict[int, str]:
        return {
            1: "SKILL ANALYZER Level.01",
            2: "SKILL ANALYZER Level.02",
            3: "SKILL ANALYZER Level.03",
            4: "SKILL ANALYZER Level.04",
            5: "SKILL ANALYZER Level.05",
            6: "SKILL ANALYZER Level.06",
            7: "SKILL ANALYZER Level.07",
            8: "SKILL ANALYZER Level.08",
            9: "SKILL ANALYZER Level.09",
            10: "SKILL ANALYZER Level.10",
            11: "SKILL ANALYZER Level.11",
            12: "SKILL ANALYZER Level.∞",
        }

    def __get_skill_analyzer_skill_name_ids(self) -> Dict[int, int]:
        return {
            1: self.GAME_SKILL_NAME_ID_LV_01,
            2: self.GAME_SKILL_NAME_ID_LV_02,
            3: self.GAME_SKILL_NAME_ID_LV_03,
            4: self.GAME_SKILL_NAME_ID_LV_04,
            5: self.GAME_SKILL_NAME_ID_LV_05,
            6: self.GAME_SKILL_NAME_ID_LV_06,
            7: self.GAME_SKILL_NAME_ID_LV_07,
            8: self.GAME_SKILL_NAME_ID_LV_08,
            9: self.GAME_SKILL_NAME_ID_LV_09,
            10: self.GAME_SKILL_NAME_ID_LV_10,
            11: self.GAME_SKILL_NAME_ID_LV_11,
            12: self.GAME_SKILL_NAME_ID_LV_INF,
        }

    def __get_skill_analyzer_courses(self) -> List[Dict[str, Any]]:
        return [
            # Skill LV.01
            {
                "season_id": 0,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 653,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 846,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 23,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 60,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 770,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 16,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 17,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 922,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 76,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 201,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 182,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 766,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 106,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 568,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 768,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 795,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 110,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 51,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 913,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 189,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 1025,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 914,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 186,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 600,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 915,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 671,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 1035,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 1014,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1033,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 1044,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 1176,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 1083,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 1049,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 1005,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 1,
                "tracks": [
                    {
                        "id": 1190,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 636,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 1054,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Skill LV.02
            {
                "season_id": 0,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 6,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 222,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 48,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 566,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 748,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 19,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 40,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 275,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 171,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 950,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 513,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 185,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 700,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 923,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 219,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 528,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 996,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 486,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 66,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 93,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 664,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 3,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 191,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 771,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 8,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 405,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 451,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 173,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 1074,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1095,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 930,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 1057,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1081,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 868,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 2,
                "tracks": [
                    {
                        "id": 1076,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1002,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 916,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Skill LV.03
            {
                "season_id": 0,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 775,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 684,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 778,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 523,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 921,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 218,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Skill course for Season ID 2 was removed due to removed songs.
            {
                "season_id": 3,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 557,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 843,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 317,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 882,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 531,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 161,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 291,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 970,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 674,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 216,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 434,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 590,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 898,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 152,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 353,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 896,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 39,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 1008,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 608,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 815,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 1086,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1122,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1026,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 1001,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1092,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1113,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 3,
                "tracks": [
                    {
                        "id": 1004,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1111,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1090,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Skill LV.04
            {
                "season_id": 0,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 757,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 480,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 758,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 467,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 456,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 107,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 67,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 544,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 9,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 449,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 506,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 962,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 136,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 534,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 640,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 630,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 647,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 785,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 781,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 623,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 540,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 104,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 521,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 342,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 485,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 359,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 834,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 966,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 983,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 967,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 1070,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1073,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1022,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 1075,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1123,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1029,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 4,
                "tracks": [
                    {
                        "id": 1094,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1128,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1027,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Skill LV.05
            {
                "season_id": 0,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 871,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 327,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 66,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 435,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 750,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 700,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 318,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 157,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 567,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 760,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1020,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 923,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 65,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 966,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 874,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 645,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 335,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 961,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 695,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 276,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 870,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 743,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 958,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 441,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 790,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 277,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 944,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 964,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 58,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1025,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 1040,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1200,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 895,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 1024,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1201,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1124,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 5,
                "tracks": [
                    {
                        "id": 1007,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1220,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1067,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # Skill LV.06
            {
                "season_id": 0,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 713,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 40,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 33,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 230,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 827,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 146,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 239,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 375,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 94,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 80,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 678,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 928,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 856,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 488,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 968,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 172,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 262,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 781,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 998,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 885,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 400,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 301,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 879,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 62,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 897,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 2,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 986,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 898,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 962,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1032,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 1115,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1184,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1230,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 1154,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1114,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 891,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 6,
                "tracks": [
                    {
                        "id": 1139,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 864,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1010,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # Skill LV.07
            {
                "season_id": 0,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 349,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 896,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 246,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 210,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 558,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 368,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 769,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 710,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 609,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 967,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 711,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 594,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 738,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 264,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 834,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 762,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 544,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 898,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 211,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 14,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 183,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 666,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 54,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 763,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 145,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 99,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 490,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 889,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1042,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 1156,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1138,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1091,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 1012,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1248,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 926,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 7,
                "tracks": [
                    {
                        "id": 1134,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 919,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1250,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # Skill LV.08
            {
                "season_id": 0,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 690,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 380,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 492,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 603,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 278,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 557,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 357,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 562,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 612,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 26,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 503,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 945,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 639,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 644,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 521,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 572,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 173,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 659,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 749,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 251,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 361,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 744,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 831,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 372,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 747,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 872,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 971,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 752,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1062,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 336,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1199,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1197,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 955,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1037,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 812,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 8,
                "tracks": [
                    {
                        "id": 596,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 902,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 844,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # Skill LV.09
            # Skill course for Season ID 0 was removed due to removed songs.
            {
                "season_id": 1,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 295,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 742,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 302,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 759,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 607,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 599,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 122,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 946,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 394,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 228,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 124,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 456,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 852,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 252,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 918,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 47,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 917,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 959,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 912,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 576,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 943,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 359,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 497,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 948,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 954,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 841,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1087,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1112,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 761,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 765,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1006,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 9,
                "tracks": [
                    {
                        "id": 737,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 887,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 933,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            # Skill LV.10
            {
                "season_id": 0,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 833,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 858,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 229,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 1,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 333,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 871,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 259,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 2,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 779,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 817,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 3,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 961,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 967,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 993,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 625,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 214,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 365,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 966,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 876,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 506,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 641,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 463,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 712,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 390,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 655,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 707,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 8,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 922,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 166,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 670,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 1126,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1034,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 834,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 1217,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1041,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1078,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 1237,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1157,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 907,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 12,
                "skill_level": 10,
                "tracks": [
                    {
                        "id": 1228,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 881,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1135,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            # Skill LV.11
            {
                "season_id": 3,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 941,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 718,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 816,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 4,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 30,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 2,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 540,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 931,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 818,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 810,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 789,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 634,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 532,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 808,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 965,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 909,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 1013,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1035,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1107,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 173,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 151,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 11,
                "skill_level": 11,
                "tracks": [
                    {
                        "id": 1060,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1062,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1222,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            # Skill LV.Inf
            {
                "season_id": 3,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 654,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 360,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 1028,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 5,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 709,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 374,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 1036,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 6,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 551,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1032,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1099,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 7,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 927,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 525,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 1100,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 9,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 1102,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1148,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1185,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 24,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 661,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 258,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 791,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 10,
                "skill_level": 12,
                "tracks": [
                    {
                        "id": 679,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1178,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 1270,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            # 6th KAC
            {
                "season_id": 13,
                "course_id": 1,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_BODY,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 806,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 971,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 913,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 14,
                "course_id": 1,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_TECHNOLOGY,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 758,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 965,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 914,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 15,
                "course_id": 1,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_HEART,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 814,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 964,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 915,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "season_id": 13,
                "course_id": 2,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_BODY,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 806,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 971,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 913,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 14,
                "course_id": 2,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_TECHNOLOGY,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 758,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 965,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 914,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 15,
                "course_id": 2,
                "course_name": "The 6th KAC挑戦コース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_6TH_HEART,
                "course_type": 2,
                "tracks": [
                    {
                        "id": 814,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 964,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 915,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # Tenkaichi courses.
            {
                "season_id": 16,
                "course_id": 1,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_TENKAICHI,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 625,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 697,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 708,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "season_id": 17,
                "course_id": 1,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_TENKAICHI,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 625,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 697,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 708,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 18,
                "course_id": 1,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_TENKAICHI,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 625,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 697,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 708,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "season_id": 16,
                "course_id": 2,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_MUSIC_FESTIVAL,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 360,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 927,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                ],
            },
            {
                "season_id": 17,
                "course_id": 2,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_MUSIC_FESTIVAL,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 360,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 927,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 18,
                "course_id": 2,
                "course_name": "天下一",
                "skill_name_id": self.GAME_SKILL_NAME_ID_MUSIC_FESTIVAL,
                "course_type": 3,
                "tracks": [
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 360,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 927,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # BMK2017 courses
            {
                "season_id": 19,
                "course_id": 1,
                "course_name": "BEMANI MASTER KOREA",
                "skill_name_id": self.GAME_SKILL_NAME_ID_BMK2017,
                "tracks": [
                    {
                        "id": 954,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 960,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 961,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            # 7th KAC
            {
                "season_id": 20,
                "course_id": 1,
                "course_name": "The 7th KACチャレンジコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_7TH_TIGER,
                "course_type": 4,
                "tracks": [
                    {
                        "id": 1149,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1102,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 21,
                "course_id": 1,
                "course_name": "The 7th KACチャレンジコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_7TH_WOLF,
                "course_type": 4,
                "tracks": [
                    {
                        "id": 1042,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 1101,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 20,
                "course_id": 2,
                "course_name": "The 7th KACチャレンジコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_7TH_TIGER,
                "course_type": 4,
                "tracks": [
                    {
                        "id": 1149,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1102,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "season_id": 21,
                "course_id": 2,
                "course_name": "The 7th KACチャレンジコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_7TH_WOLF,
                "course_type": 4,
                "tracks": [
                    {
                        "id": 1042,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1101,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            # 8th KAC
            {
                "season_id": 22,
                "course_id": 1,
                "course_name": "The 8th KACチャレンジコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_8TH,
                "course_type": 5,
                "tracks": [
                    {
                        "id": 1334,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                    {
                        "id": 610,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 1033,
                        "type": self.CHART_TYPE_MAXIMUM,
                    },
                ],
            },
            {
                "season_id": 23,
                "course_id": 1,
                "course_name": "The 8th KACエンジョイコース",
                "skill_name_id": self.GAME_SKILL_NAME_ID_KAC_8TH,
                "course_type": 5,
                "tracks": [
                    {
                        "id": 1334,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 610,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 1033,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
        ]

    def handle_game_sv4_common_request(self, request: Node) -> Node:
        game = Node.void("game")

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

        # Catalog, maybe this is for the online store?
        catalog = Node.void("catalog")
        game.add_child(catalog)

        for _item in []:  # type: ignore
            info = Node.void("info")
            catalog.add_child(info)
            info.add_child(Node.u8("catalog_type", 0))
            info.add_child(Node.u32("catalog_id", 0))
            info.add_child(Node.u32("discount_rate", 0))

        # Event config
        event = Node.void("event")
        game.add_child(event)

        def enable_event(eid: str) -> None:
            evt = Node.void("info")
            event.add_child(evt)
            evt.add_child(Node.string("event_id", eid))

        if not game_config.get_bool("disable_matching"):
            # Matching enabled events
            enable_event("MATCHING_MODE")
            enable_event("MATCHING_MODE_FREE_IP")
        enable_event("ICON_FLOOR_INFECTION")
        enable_event("ICON_POLICY_BREAK")
        enable_event("ACHIEVEMENT_ENABLE")
        enable_event("VOLFORCE_ENABLE")
        enable_event("CONTINUATION")
        enable_event("TENKAICHI_MODE")
        enable_event("SERIALCODE_JAPAN")
        enable_event("DEMOGAME_PLAY")
        enable_event("TOTAL_MEMORIAL_ENABLE")
        enable_event("EVENT_IDS_SERIALCODE_TOHO_02")
        if game_config.get_bool("50th_anniversary"):
            enable_event("KONAMI_50TH_LOGO")
        enable_event("KAC6TH_FINISH")
        enable_event("KAC7TH_FINISH")
        enable_event("KAC8TH_FINISH")

        # An old collaboration event we don't support.
        reitaisai = Node.void("reitaisai2018")
        game.add_child(reitaisai)

        # Volte factory, an older event we don't support.
        volte_factory = Node.void("volte_factory")
        game.add_child(volte_factory)
        goods = Node.void("goods")
        volte_factory.add_child(goods)
        stock = Node.void("stock")
        volte_factory.add_child(stock)

        # I think this is a list of purchaseable appeal cards.
        appealcard = Node.void("appealcard")
        game.add_child(appealcard)

        # Event parameters (we don't support story mode).
        extend = Node.void("extend")
        game.add_child(extend)

        # Available skill courses
        skill_course = Node.void("skill_course")
        game.add_child(skill_course)

        achievements = self.data.local.user.get_all_achievements(self.game, self.version, achievementtype="course")
        courserates: Dict[Tuple[int, int], Dict[str, int]] = {}

        def getrates(season_id: int, course_id: int) -> Dict[str, int]:
            if (course_id, season_id) in courserates:
                return courserates[(course_id, season_id)]
            else:
                return {
                    "attempts": 0,
                    "clears": 0,
                    "total_score": 0,
                }

        for _, achievement in achievements:
            course_id = achievement.id % 100
            season_id = int(achievement.id / 100)
            rate = getrates(season_id, course_id)

            rate["attempts"] += 1
            if achievement.data.get_int("clear_type") >= 2:
                rate["clears"] += 1
            rate["total_score"] = achievement.data.get_int("score")
            courserates[(course_id, season_id)] = rate

        seasons = self.__get_skill_analyzer_seasons()
        skill_levels = self.__get_skill_analyzer_skill_levels()
        courses = self.__get_skill_analyzer_courses()
        skill_name_ids = self.__get_skill_analyzer_skill_name_ids()
        for course in courses:
            info = Node.void("info")
            skill_course.add_child(info)

            info.add_child(Node.s32("season_id", course["season_id"]))
            info.add_child(Node.string("season_name", seasons[course["season_id"]]))
            info.add_child(Node.bool("season_new_flg", course["season_id"] in {10, 11, 12, 22, 23}))
            info.add_child(Node.s16("course_id", course.get("course_id", course.get("skill_level", -1))))
            info.add_child(
                Node.string(
                    "course_name",
                    course.get(
                        "course_name",
                        skill_levels.get(course.get("skill_level", -1), ""),
                    ),
                )
            )
            # Course type 0 is skill level courses. The course type is the same as the skill level (01-12).
            # If skill level is specified as '0', then the course type shows up as 'OTHER' instead of Skill Lv.01-12.
            # Course type 2 = KAC 6th.
            # Course type 3 = TENKAICHI mode.
            # Course type 4 = KAC 7th.
            # Course type 5 = KAC 8th.
            info.add_child(Node.s16("course_type", course.get("course_type", 0)))
            info.add_child(Node.s16("skill_level", course.get("skill_level", 0)))
            info.add_child(
                Node.s16(
                    "skill_name_id",
                    course.get(
                        "skill_name_id",
                        skill_name_ids.get(course.get("skill_level", -1), 0),
                    ),
                )
            )
            info.add_child(
                Node.bool(
                    "matching_assist",
                    course.get("skill_level", -1) >= 1 and course.get("skill_level", -1) <= 7,
                )
            )

            # Calculate clear rate and average score
            rate = getrates(
                course["season_id"],
                course.get("course_id", course.get("skill_level", -1)),
            )
            if rate["attempts"] > 0:
                info.add_child(Node.s32("clear_rate", int(100.0 * (rate["clears"] / rate["attempts"]))))
                info.add_child(Node.u32("avg_score", rate["total_score"] // rate["attempts"]))
            else:
                info.add_child(Node.s32("clear_rate", 0))
                info.add_child(Node.u32("avg_score", 0))

            for trackno, trackdata in enumerate(course["tracks"]):
                track = Node.void("track")
                info.add_child(track)
                track.add_child(Node.s16("track_no", trackno))
                track.add_child(Node.s32("music_id", trackdata["id"]))
                track.add_child(Node.s8("music_type", trackdata["type"]))

        # Museca link event that we don't support.
        museca_link = Node.void("museca_link")
        game.add_child(museca_link)

        return game

    def handle_game_sv4_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("shopname"))

        # Respond with number of milliseconds until next request
        game = Node.void("game")
        game.add_child(Node.u32("nxt_time", 1000 * 5 * 60))
        return game

    def handle_game_sv4_hiscore_request(self, request: Node) -> Node:
        # Grab location for local scores
        locid = ID.parse_machine_id(request.child_value("locid"))

        game = Node.void("game")

        # Now, grab global and local scores as well as clear rates
        global_records = self.data.remote.music.get_all_records(self.game, self.version)
        users = {uid: prof for (uid, prof) in self.data.local.user.get_all_profiles(self.game, self.version)}
        area_users = [uid for uid in users if users[uid].get_int("loc", -1) == locid]
        area_records = self.data.local.music.get_all_records(self.game, self.version, userlist=area_users)
        clears = self.get_clear_rates()
        records: Dict[int, Dict[int, Dict[str, Tuple[UserID, Score]]]] = {}

        missing_users = [userid for (userid, _) in global_records if userid not in users] + [
            userid for (userid, _) in area_records if userid not in users
        ]
        for userid, profile in self.get_any_profiles(missing_users):
            users[userid] = profile

        for userid, score in global_records:
            if userid not in users:
                raise Exception("Logic error, missing profile for user!")
            if score.id not in records:
                records[score.id] = {}
            if score.chart not in records[score.id]:
                records[score.id][score.chart] = {}
            records[score.id][score.chart]["global"] = (userid, score)

        for userid, score in area_records:
            if userid not in users:
                raise Exception("Logic error, missing profile for user!")
            if score.id not in records:
                records[score.id] = {}
            if score.chart not in records[score.id]:
                records[score.id][score.chart] = {}
            records[score.id][score.chart]["area"] = (userid, score)

        # Output it to the game
        highscores = Node.void("sc")
        game.add_child(highscores)
        for musicid in records:
            for chart in records[musicid]:
                (globaluserid, globalscore) = records[musicid][chart]["global"]

                global_profile = users[globaluserid]
                if clears[musicid][chart]["total"] > 0:
                    clear_rate = float(clears[musicid][chart]["clears"]) / float(clears[musicid][chart]["total"])
                else:
                    clear_rate = 0.0

                info = Node.void("d")
                highscores.add_child(info)
                info.add_child(Node.u32("id", musicid))
                info.add_child(Node.u32("ty", chart))
                info.add_child(Node.string("a_sq", ID.format_extid(global_profile.extid)))
                info.add_child(Node.string("a_nm", global_profile.get_str("name")))
                info.add_child(Node.u32("a_sc", globalscore.points))
                info.add_child(Node.s32("cr", int(clear_rate * 10000)))
                info.add_child(Node.s32("avg_sc", clears[musicid][chart]["average"]))

                if "area" in records[musicid][chart]:
                    (localuserid, localscore) = records[musicid][chart]["area"]
                    local_profile = users[localuserid]
                    info.add_child(Node.string("l_sq", ID.format_extid(local_profile.extid)))
                    info.add_child(Node.string("l_nm", local_profile.get_str("name")))
                    info.add_child(Node.u32("l_sc", localscore.points))

        return game

    def handle_game_sv4_load_request(self, request: Node) -> Node:
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
            root = Node.void("game")
            root.add_child(Node.u8("result", 2))
            root.add_child(Node.string("name", profile.get_str("name")))
            return root
        else:
            root = Node.void("game")
            root.add_child(Node.u8("result", 1))
            return root

    def handle_game_sv4_frozen_request(self, request: Node) -> Node:
        game = Node.void("game")
        game.add_child(Node.u8("result", 0))
        return game

    def handle_game_sv4_new_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        name = request.child_value("name")
        loc = ID.parse_machine_id(request.child_value("locid"))
        self.new_profile_by_refid(refid, name, loc)

        root = Node.void("game")
        return root

    def handle_game_sv4_load_m_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        else:
            scores = []

        # Output to the game
        game = Node.void("game")
        music = Node.void("music")
        game.add_child(music)

        for score in scores:
            info = Node.void("info")
            music.add_child(info)

            stats = score.data.get_dict("stats")
            info.add_child(
                Node.u32_array(
                    "param",
                    [
                        score.id,
                        score.chart,
                        score.points,
                        self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                        self.__db_to_game_grade(score.data.get_int("grade")),
                        0,  # 5: Any value
                        0,  # 6: Any value
                        stats.get_int("btn_rate"),
                        stats.get_int("long_rate"),
                        stats.get_int("vol_rate"),
                        0,  # 10: Any value
                        0,  # 11: Another medal, perhaps old score medal?
                        0,  # 12: Another grade, perhaps old score grade?
                        0,  # 13: Any value
                        0,  # 14: Any value
                        0,  # 15: Any value
                        0,  # 16: Another medal, perhaps old score medal?
                        0,  # 17: Another grade, perhaps old score grade?
                        0,  # 18: Any value
                        0,  # 19: Any value
                    ],
                ),
            )

        return game

    def handle_game_sv4_load_r_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        game = Node.void("game")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            links = self.data.local.user.get_links(self.game, self.version, userid)
            index = 0
            for link in links:
                if link.type != "rival":
                    continue
                other_profile = self.get_profile(link.other_userid)
                if other_profile is None:
                    continue

                # Base information about rival
                rival = Node.void("rival")
                game.add_child(rival)
                rival.add_child(Node.s16("no", index))
                rival.add_child(Node.string("seq", ID.format_extid(other_profile.extid)))
                rival.add_child(Node.string("name", other_profile.get_str("name")))

                # Keep track of index
                index = index + 1

                # Return scores for this user on random charts
                scores = self.data.remote.music.get_scores(self.game, self.version, link.other_userid)
                for score in scores:
                    music = Node.void("music")
                    rival.add_child(music)
                    music.add_child(
                        Node.u32_array(
                            "param",
                            [
                                score.id,
                                score.chart,
                                score.points,
                                self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                                self.__db_to_game_grade(score.data.get_int("grade")),
                            ],
                        )
                    )

        return game

    def handle_game_sv4_save_request(self, request: Node) -> Node:
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

        return Node.void("game")

    def handle_game_sv4_save_m_request(self, request: Node) -> Node:
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
        return Node.void("game")

    def handle_game_sv4_play_e_request(self, request: Node) -> Node:
        return Node.void("game")

    def handle_game_sv4_save_e_request(self, request: Node) -> Node:
        # This has to do with Policy floor infection, but we don't
        # implement multi-game support so meh.
        game = Node.void("game")

        pbc_infection = Node.void("pbc_infection")
        game.add_child(pbc_infection)
        for name in ["packet", "block", "coloris"]:
            child = Node.void(name)
            pbc_infection.add_child(child)
            child.add_child(Node.s32("before", 0))
            child.add_child(Node.s32("after", 0))

        pb_infection = Node.void("pb_infection")
        game.add_child(pb_infection)
        for name in ["packet", "block"]:
            child = Node.void(name)
            pb_infection.add_child(child)
            child.add_child(Node.s32("before", 0))
            child.add_child(Node.s32("after", 0))

        return game

    def handle_game_sv4_play_s_request(self, request: Node) -> Node:
        root = Node.void("game")
        root.add_child(Node.u32("play_id", 1))
        return root

    def handle_game_sv4_buy_request(self, request: Node) -> Node:
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
            price = request.child_value("item/price")
            if isinstance(price, list):
                # Sometimes we end up buying more than one item at once
                price = sum(price)

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
                item_type = request.child_value("item/item_type")
                item_id = request.child_value("item/item_id")
                param = request.child_value("item/param")

                if not isinstance(item_type, list):
                    # Sometimes we buy multiple things at once. Make it easier by always assuming this.
                    item_type = [item_type]
                    item_id = [item_id]
                    param = [param]

                for i in range(len(item_type)):
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        item_id[i],
                        f"item_{item_type[i]}",
                        {
                            "param": param[i],
                        },
                    )

        else:
            # Unclear what to do here, return a bad response
            packet = 0
            block = 0
            result = 1

        game = Node.void("game")
        game.add_child(Node.u32("gamecoin_packet", packet))
        game.add_child(Node.u32("gamecoin_block", block))
        game.add_child(Node.s8("result", result))
        return game

    def handle_game_sv4_save_c_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            season_id = request.child_value("ssnid")
            course_id = request.child_value("crsid")
            clear_type = request.child_value("ct")
            achievement_rate = request.child_value("ar")
            grade = request.child_value("gr")
            score = request.child_value("sc")

            # Do not update the course achievement when old score is greater.
            old = self.data.local.user.get_achievement(
                self.game, self.version, userid, (season_id * 100) + course_id, "course"
            )
            if old is not None and old.get_int("score") > score:
                return Node.void("game")

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                (season_id * 100) + course_id,
                "course",
                {
                    "clear_type": clear_type,
                    "achievement_rate": achievement_rate,
                    "score": score,
                    "grade": grade,
                },
            )

        # Return a blank response
        return Node.void("game")

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        game = Node.void("game")

        # Generic profile stuff
        game.add_child(Node.string("name", profile.get_str("name")))
        game.add_child(Node.string("code", ID.format_extid(profile.extid)))
        game.add_child(Node.string("sdvx_id", ID.format_extid(profile.extid)))
        game.add_child(Node.u16("appeal_id", profile.get_int("appealid")))
        game.add_child(Node.s16("skill_base_id", profile.get_int("skill_base_id")))
        game.add_child(Node.s16("skill_name_id", profile.get_int("skill_name_id")))
        game.add_child(Node.u32("gamecoin_packet", profile.get_int("packet")))
        game.add_child(Node.u32("gamecoin_block", profile.get_int("block")))
        game.add_child(Node.u32("blaster_energy", profile.get_int("blaster_energy")))
        game.add_child(Node.u32("blaster_count", profile.get_int("blaster_count")))

        # Play statistics
        statistics = self.get_play_statistics(userid)
        game.add_child(Node.u32("play_count", statistics.total_plays))
        game.add_child(Node.u32("today_count", statistics.today_plays))
        game.add_child(Node.u32("play_chain", statistics.consecutive_days))

        # Also exists but we don't support:
        # - day_count: Number of days where this user had at least one play.
        # - max_play_chain: Max consecutive days in a row where the user had at last one play.
        # - week_count: Number of weeks here this user had at least one play.
        # - week_play_count: Number of plays in the last week (I think).
        # - week_chain: Number of weeks in a row where the user had at least one play in that week.
        # - max_week_chain: Maximum number of weeks in a row where the user had at least one play in that week.

        # Player options and last touched song.
        lastdict = profile.get_dict("last")
        game.add_child(Node.s32("last_music_id", lastdict.get_int("music_id", -1)))
        game.add_child(Node.u8("last_music_type", lastdict.get_int("music_type")))
        game.add_child(Node.u8("sort_type", lastdict.get_int("sort_type")))
        game.add_child(Node.u8("narrow_down", lastdict.get_int("narrow_down")))
        game.add_child(Node.u8("headphone", lastdict.get_int("headphone")))
        game.add_child(Node.u8("gauge_option", lastdict.get_int("gauge_option")))
        game.add_child(Node.u8("ars_option", lastdict.get_int("ars_option")))
        game.add_child(Node.u8("notes_option", lastdict.get_int("notes_option")))
        game.add_child(Node.u8("early_late_disp", lastdict.get_int("early_late_disp")))
        game.add_child(Node.u8("eff_c_left", lastdict.get_int("eff_c_left")))
        game.add_child(Node.u8("eff_c_right", lastdict.get_int("eff_c_right", 1)))
        game.add_child(Node.u32("lanespeed", lastdict.get_int("lanespeed")))
        game.add_child(Node.s32("hispeed", lastdict.get_int("hispeed")))
        game.add_child(Node.s32("draw_adjust", lastdict.get_int("draw_adjust")))

        # Item unlocks
        itemnode = Node.void("item")
        game.add_child(itemnode)

        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)

        for item in achievements:
            if item.type[:5] != "item_":
                continue
            itemtype = int(item.type[5:])

            if game_config.get_bool("force_unlock_songs") and itemtype == self.GAME_CATALOG_TYPE_SONG:
                # Don't echo unlocked songs, we will add all of them later
                continue
            if game_config.get_bool("force_unlock_cards") and itemtype == self.GAME_CATALOG_TYPE_APPEAL_CARD:
                # Don't echo unlocked appeal cards, we will add all of them later
                continue
            if game_config.get_bool("force_unlock_crew") and itemtype == self.GAME_CATALOG_TYPE_CREW:
                # Don't echo unlocked crew, we will add all of them later
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

        if game_config.get_bool("force_unlock_cards"):
            catalog = self.data.local.game.get_items(self.game, self.version)
            for unlock in catalog:
                if unlock.type != "appealcard":
                    continue

                info = Node.void("info")
                itemnode.add_child(info)
                info.add_child(Node.u8("type", self.GAME_CATALOG_TYPE_APPEAL_CARD))
                info.add_child(Node.u32("id", unlock.id))
                info.add_child(Node.u32("param", 1))

        if game_config.get_bool("force_unlock_crew"):
            for crewid in range(1, 999):
                info = Node.void("info")
                itemnode.add_child(info)
                info.add_child(Node.u8("type", self.GAME_CATALOG_TYPE_CREW))
                info.add_child(Node.u32("id", crewid))
                info.add_child(Node.u32("param", 1))

        # Skill courses
        skill = Node.void("skill")
        game.add_child(skill)
        skill_level = 0

        for course in achievements:
            if course.type != "course":
                continue

            course_id = course.id % 100
            season_id = int(course.id / 100)

            if course.data.get_int("clear_type") >= 2:
                # The user cleared this, lets take the highest level clear for this
                courselist = [
                    c
                    for c in self.__get_skill_analyzer_courses()
                    if c.get("course_id", c.get("skill_level", -1)) == course_id and c["season_id"] == season_id
                ]
                if len(courselist) > 0:
                    skill_level = max(skill_level, courselist[0]["skill_level"])

            course_node = Node.void("course")
            skill.add_child(course_node)
            course_node.add_child(Node.s16("ssnid", season_id))
            course_node.add_child(Node.s16("crsid", course_id))
            course_node.add_child(Node.s32("sc", course.data.get_int("score")))
            course_node.add_child(Node.s16("ct", course.data.get_int("clear_type")))
            course_node.add_child(Node.s16("gr", course.data.get_int("grade")))
            course_node.add_child(Node.s16("ar", course.data.get_int("achievement_rate")))
            course_node.add_child(Node.s16("cnt", 1))

        # Calculated skill level
        game.add_child(Node.s16("skill_level", skill_level))

        # Game parameters
        paramnode = Node.void("param")
        game.add_child(paramnode)

        for param in achievements:
            if param.type[:6] != "param_":
                continue
            paramtype = int(param.type[6:])

            info = Node.void("info")
            paramnode.add_child(info)
            info.add_child(Node.s32("id", param.id))
            info.add_child(Node.s32("type", paramtype))
            info.add_child(
                Node.s32_array("param", param.data["param"])
            )  # This looks to be variable, so no validation on length

        # Infection nodes, we don't support these but it here for posterity.
        pbc_infection = Node.void("pbc_infection")
        game.add_child(pbc_infection)
        for name in ["packet", "block", "coloris"]:
            child = Node.void(name)
            pbc_infection.add_child(child)
            child.add_child(Node.s32("before", 0))
            child.add_child(Node.s32("after", 0))

        pb_infection = Node.void("pb_infection")
        game.add_child(pb_infection)
        for name in ["packet", "block"]:
            child = Node.void(name)
            pb_infection.add_child(child)
            child.add_child(Node.s32("before", 0))
            child.add_child(Node.s32("after", 0))

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

        # Miscelaneous profile stuff
        newprofile.replace_int("blaster_count", request.child_value("blaster_count"))
        newprofile.replace_int("appealid", request.child_value("appeal_id"))
        newprofile.replace_int("skill_level", request.child_value("skill_level"))
        newprofile.replace_int("skill_base_id", request.child_value("skill_base_id"))
        newprofile.replace_int("skill_name_id", request.child_value("skill_name_id"))

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()

        if request.child("item") is not None:
            for child in request.child("item").children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                param = child.child_value("param")

                if game_config.get_bool("force_unlock_cards") and item_type == self.GAME_CATALOG_TYPE_APPEAL_CARD:
                    # Don't save back appeal cards because they were force unlocked
                    continue
                if game_config.get_bool("force_unlock_songs") and item_type == self.GAME_CATALOG_TYPE_SONG:
                    # Don't save back songs, because they were force unlocked
                    continue
                if game_config.get_bool("force_unlock_crew") and item_type == self.GAME_CATALOG_TYPE_CREW:
                    # Don't save back crew, because they were force unlocked
                    continue

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

        # Update params
        if request.child("param") is not None:
            for child in request.child("param").children:
                if child.name != "info":
                    continue

                param_id = child.child_value("id")
                param_type = child.child_value("type")
                param_param = child.child_value("param")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    param_id,
                    f"param_{param_type}",
                    {
                        "param": param_param,
                    },
                )

        # Grab last information and player options.
        lastdict = newprofile.get_dict("last")
        lastdict.replace_int("music_id", request.child_value("music_id"))
        lastdict.replace_int("music_type", request.child_value("music_type"))
        lastdict.replace_int("sort_type", request.child_value("sort_type"))
        lastdict.replace_int("narrow_down", request.child_value("narrow_down"))
        lastdict.replace_int("headphone", request.child_value("headphone"))
        lastdict.replace_int("gauge_option", request.child_value("gauge_option"))
        lastdict.replace_int("ars_option", request.child_value("ars_option"))
        lastdict.replace_int("notes_option", request.child_value("notes_option"))
        lastdict.replace_int("early_late_disp", request.child_value("early_late_disp"))
        lastdict.replace_int("eff_c_left", request.child_value("eff_c_left"))
        lastdict.replace_int("eff_c_right", request.child_value("eff_c_right"))
        lastdict.replace_int("lanespeed", request.child_value("lanespeed"))
        lastdict.replace_int("hispeed", request.child_value("hispeed"))
        lastdict.replace_int("draw_adjust", request.child_value("draw_adjust"))

        # Save back last information gleaned from results
        newprofile.replace_dict("last", lastdict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
