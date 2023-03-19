# vim: set fileencoding=utf-8
from typing import Any, Dict, List

from bemani.backend.sdvx.gravitywars import SoundVoltexGravityWars
from bemani.common import ID, Profile
from bemani.data import UserID
from bemani.protocol import Node


class SoundVoltexGravityWarsSeason1(
    SoundVoltexGravityWars,
):
    def _get_skill_analyzer_seasons(self) -> Dict[int, str]:
        return {
            1: "SKILL ANALYZER 第1回 Aコース",
            2: "SKILL ANALYZER 第1回 Bコース",
            3: "SKILL ANALYZER 第1回 Cコース",
            4: "The 4th KAC コース",
            5: "SKILL ANALYZER 第2回 Aコース",
            6: "SKILL ANALYZER 第2回 Bコース",
            7: "SKILL ANALYZER 第2回 Cコース",
            8: "SKILL ANALYZER 第3回 Aコース",
            9: "SKILL ANALYZER 第3回 Bコース",
            10: "SKILL ANALYZER 第3回 Cコース",
            11: "SKILL ANALYZER 第4回",
            12: "SKILL ANALYZER 第5回 Aコース",
            13: "SKILL ANALYZER 第5回 Bコース",
            14: "SKILL ANALYZER 第5回 Cコース",
            15: "SKILL ANALYZER 第6回 Aコース",
            16: "SKILL ANALYZER 第6回 Bコース",
        }

    def _get_skill_analyzer_courses(self) -> List[Dict[str, Any]]:
        return [
            {
                "level": 0,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 109,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 283,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 279,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 76,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 196,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 8,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 90,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 228,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 80,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 125,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 201,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 237,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 393,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 352,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 66,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 383,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 511,
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
                "season_id": 1,
                "tracks": [
                    {
                        "id": 422,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 445,
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
                "season_id": 1,
                "tracks": [
                    {
                        "id": 454,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 158,
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
                "season_id": 1,
                "tracks": [
                    {
                        "id": 322,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 124,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 1,
                "tracks": [
                    {
                        "id": 348,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 73,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 259,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 2,
                "tracks": [
                    {
                        "id": 374,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 84,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 303,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 2,
                "tracks": [
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 274,
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
                "season_id": 2,
                "tracks": [
                    {
                        "id": 56,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 244,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 4,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 2,
                "tracks": [
                    {
                        "id": 414,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 209,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 334,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 2,
                "tracks": [
                    {
                        "id": 123,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 403,
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
                "season_id": 2,
                "tracks": [
                    {
                        "id": 391,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 239,
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
                "season_id": 2,
                "tracks": [
                    {
                        "id": 389,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 89,
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
                "season_id": 2,
                "tracks": [
                    {
                        "id": 419,
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
                "season_id": 2,
                "tracks": [
                    {
                        "id": 394,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 466,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 47,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 2,
                "tracks": [
                    {
                        "id": 500,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 247,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 229,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 189,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 171,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 182,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 3,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 105,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 14,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 120,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 86,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 390,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 243,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 186,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 423,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 59,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 452,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 262,
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
                "season_id": 3,
                "tracks": [
                    {
                        "id": 411,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 70,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 211,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 30,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 72,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 293,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 3,
                "tracks": [
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 117,
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
                "season_id": 3,
                "tracks": [
                    {
                        "id": 498,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 437,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 0,
                "level": -1,
                "skill_name": "エンジョイ♪ごりらコースA",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 466,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 273,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 470,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 1,
                "level": -1,
                "skill_name": "エンジョイ♪ごりらコースB",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 194,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 501,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 2,
                "level": -1,
                "skill_name": "エンジョイ♪ごりらコースC",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 356,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 7,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 472,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 3,
                "level": -1,
                "skill_name": "エンジョイ♪ごりらコースD",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 333,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 583,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 4,
                "level": -1,
                "skill_name": "チャレンジ★ごりらコースA",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 466,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 273,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 470,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 5,
                "level": -1,
                "skill_name": "チャレンジ★ごりらコースB",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 194,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 501,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 6,
                "level": -1,
                "skill_name": "チャレンジ★ごりらコースC",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 356,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 7,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 472,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 7,
                "level": -1,
                "skill_name": "チャレンジ★ごりらコースD",
                "skill_name_id": 12,
                "season_id": 4,
                "tracks": [
                    {
                        "id": 299,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 333,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 583,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 47,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 334,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 10,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 11,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 224,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 132,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 137,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 336,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 380,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 109,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 308,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 113,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 101,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 200,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 478,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 487,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 254,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 410,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 196,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 170,
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
                "season_id": 5,
                "tracks": [
                    {
                        "id": 489,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 519,
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
                "season_id": 5,
                "tracks": [
                    {
                        "id": 456,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 263,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 390,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 5,
                "tracks": [
                    {
                        "id": 19,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 508,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 123,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 231,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 185,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 65,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 386,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 92,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 379,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 225,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 427,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 122,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 249,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 185,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 413,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 157,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 402,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 412,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 323,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 256,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 6,
                "tracks": [
                    {
                        "id": 400,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 368,
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
                "season_id": 6,
                "tracks": [
                    {
                        "id": 453,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 442,
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
                        "id": 370,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 244,
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
                "season_id": 6,
                "tracks": [
                    {
                        "id": 359,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 214,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 506,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 124,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 446,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 34,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 113,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 309,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 42,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 353,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 246,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 130,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 219,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 153,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 418,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 369,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 385,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 226,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 301,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 159,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 311,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 255,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 213,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 357,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 268,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 304,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 7,
                "tracks": [
                    {
                        "id": 295,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 36,
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
                        "id": 7,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 208,
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
                "season_id": 8,
                "tracks": [
                    {
                        "id": 101,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 219,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 159,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 87,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 337,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 403,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 30,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 596,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 39,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 430,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 561,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 328,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 444,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 618,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 100,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 447,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 545,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 94,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 291,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 2,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 475,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 627,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 624,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 427,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 464,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 122,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 591,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 8,
                "tracks": [
                    {
                        "id": 381,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 463,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 507,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 468,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 243,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 388,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 167,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 486,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 75,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 96,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 557,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 55,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 520,
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
                "season_id": 9,
                "tracks": [
                    {
                        "id": 507,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 567,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 205,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 86,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 488,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 80,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 184,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 130,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 524,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 521,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 576,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 503,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 473,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 125,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 538,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 9,
                "tracks": [
                    {
                        "id": 407,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 472,
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
                        "id": 122,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 209,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 24,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 405,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 554,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 77,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 426,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 262,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 194,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 564,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 248,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 471,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 276,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 476,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 120,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 57,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 146,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 622,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 152,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 562,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 531,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 449,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 404,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 123,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 607,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 10,
                "tracks": [
                    {
                        "id": 469,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 496,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 289,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            # Manually specify IDs here since this has more than one level 11.
            {
                "id": 0,
                "level": 0,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 190,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 568,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 191,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 1,
                "level": 1,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 278,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 41,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 18,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 2,
                "level": 2,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 15,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 483,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 467,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "id": 3,
                "level": 3,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 585,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 486,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 48,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 4,
                "level": 4,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 103,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 335,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 224,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 5,
                "level": 5,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 275,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 438,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 67,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 6,
                "level": 6,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 202,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 264,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 526,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 7,
                "level": 7,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 131,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 155,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 394,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 8,
                "level": 8,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 396,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 346,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 510,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 9,
                "level": 9,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 326,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 470,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 362,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 10,
                "level": 10,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 339,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 418,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 525,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "id": 11,
                "level": 10,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 36,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 47,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 73,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "id": 12,
                "level": 11,
                "season_id": 11,
                "tracks": [
                    {
                        "id": 126,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 367,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 636,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 507,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 671,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 176,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 27,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 520,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 103,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 478,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 264,
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
                        "id": 107,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 520,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 163,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 408,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 34,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 678,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 481,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 436,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 104,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 55,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 415,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 512,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 483,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 509,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 557,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 497,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 58,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 166,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 12,
                "tracks": [
                    {
                        "id": 581,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 439,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 443,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 250,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 245,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 186,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 13,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 618,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 31,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 436,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 144,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 79,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 489,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 245,
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
                "season_id": 13,
                "tracks": [
                    {
                        "id": 556,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 233,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 565,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 354,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 281,
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
                "season_id": 13,
                "tracks": [
                    {
                        "id": 14,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 267,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 490,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 467,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 585,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 560,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 599,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 101,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 109,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 13,
                "tracks": [
                    {
                        "id": 630,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 408,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 393,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 63,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 328,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 266,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 23,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 453,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 153,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 458,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 514,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 71,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 392,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 388,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 569,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 508,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 405,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 266,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 50,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 172,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 33,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 210,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 232,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 485,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 457,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 514,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 556,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 14,
                "tracks": [
                    {
                        "id": 534,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 273,
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
                        "id": 420,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 444,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 151,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 117,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 564,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 318,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 93,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 308,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 49,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 317,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 335,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 239,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 439,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 44,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 243,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 158,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 175,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 150,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 162,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 79,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 386,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 99,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 22,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 164,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 406,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 344,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 6,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 660,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 378,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 465,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 413,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 221,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 342,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 10,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 125,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 123,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 124,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 11,
                "season_id": 15,
                "tracks": [
                    {
                        "id": 366,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 695,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 692,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 0,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 343,
                        "type": self.CHART_TYPE_NOVICE,
                    },
                    {
                        "id": 144,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 569,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 1,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 515,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 254,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 354,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 2,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 441,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 524,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 187,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                ],
            },
            {
                "level": 3,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 117,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 446,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 435,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 4,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 180,
                        "type": self.CHART_TYPE_ADVANCED,
                    },
                    {
                        "id": 260,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 451,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 5,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 58,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 195,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 236,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 6,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 440,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 112,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 401,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 7,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 325,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 387,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 42,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
            {
                "level": 8,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 676,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 494,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 234,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 9,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 155,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 623,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 329,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                ],
            },
            {
                "level": 10,
                "season_id": 16,
                "tracks": [
                    {
                        "id": 450,
                        "type": self.CHART_TYPE_EXHAUST,
                    },
                    {
                        "id": 634,
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
                "season_id": 16,
                "tracks": [
                    {
                        "id": 116,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 693,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                    {
                        "id": 694,
                        "type": self.CHART_TYPE_INFINITE,
                    },
                ],
            },
        ]

    def handle_game_3_hiscore_request(self, request: Node) -> Node:
        # Grab location for local scores
        locid = ID.parse_machine_id(request.child_value("locid"))

        # Start the response packet
        game = Node.void("game_3")

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
        users = {
            userid: profile
            for (userid, profile) in self.get_any_profiles(missing_users)
        }

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
            for (uid, prof) in self.data.local.user.get_all_profiles(
                self.game, self.version
            )
            if prof.get_int("loc", -1) == locid
        ]
        records = self.data.local.music.get_all_records(
            self.game, self.version, userlist=area_users
        )
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

            # Add to global scores
            hiscore_location.add_child(info)

        # Now, grab clear rates
        clear_rate = Node.void("clear_rate")
        game.add_child(clear_rate)

        clears = self.get_clear_rates()
        for songid in clears:
            for chart in clears[songid]:
                if clears[songid][chart]["total"] > 0:
                    rate = float(clears[songid][chart]["clears"]) / float(
                        clears[songid][chart]["total"]
                    )
                    dnode = Node.void("d")
                    clear_rate.add_child(dnode)
                    dnode.add_child(Node.u32("id", songid))
                    dnode.add_child(Node.u32("type", chart))
                    dnode.add_child(Node.s16("cr", int(rate * 10000)))

        return game

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        game = Node.void("game_3")

        # Generic profile stuff
        game.add_child(Node.string("name", profile.get_str("name")))
        game.add_child(Node.string("code", ID.format_extid(profile.extid)))
        game.add_child(Node.u32("gamecoin_packet", profile.get_int("packet")))
        game.add_child(Node.u32("gamecoin_block", profile.get_int("block")))
        game.add_child(Node.s16("skill_name_id", profile.get_int("skill_name_id", -1)))
        game.add_child(
            Node.s32_array("hidden_param", profile.get_int_array("hidden_param", 20))
        )
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
            last.add_child(Node.u16("appeal_id", lastdict.get_int("appeal_id", 1001)))
            last.add_child(Node.u16("comment_id", lastdict.get_int("comment_id")))
            last.add_child(Node.u8("gauge_option", lastdict.get_int("gauge_option")))

        # Item unlocks
        itemnode = Node.void("item")
        game.add_child(itemnode)

        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )

        for item in achievements:
            if item.type[:5] != "item_":
                continue
            itemtype = int(item.type[5:])

            if (
                game_config.get_bool("force_unlock_songs")
                and itemtype == self.GAME_CATALOG_TYPE_SONG
            ):
                # Don't echo unlocked songs, we will add all of them later
                continue
            if (
                game_config.get_bool("force_unlock_cards")
                and itemtype == self.GAME_CATALOG_TYPE_APPEAL_CARD
            ):
                # Don't echo unlocked appeal cards, we will add all of them later
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

        # Story mode unlocks
        storynode = Node.void("story")
        game.add_child(storynode)

        for story in achievements:
            if story.type != "story":
                continue

            info = Node.void("info")
            storynode.add_child(info)
            info.add_child(Node.s32("story_id", story.id))
            info.add_child(Node.s32("progress_id", story.data.get_int("progress_id")))
            info.add_child(
                Node.s32("progress_param", story.data.get_int("progress_param"))
            )
            info.add_child(Node.s32("clear_cnt", story.data.get_int("clear_cnt")))
            info.add_child(Node.u32("route_flg", story.data.get_int("route_flg")))

        return game

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()

        # Update blaster energy and in-game currencies
        earned_gamecoin_packet = request.child_value("earned_gamecoin_packet")
        if earned_gamecoin_packet is not None:
            newprofile.replace_int(
                "packet", newprofile.get_int("packet") + earned_gamecoin_packet
            )
        earned_gamecoin_block = request.child_value("earned_gamecoin_block")
        if earned_gamecoin_block is not None:
            newprofile.replace_int(
                "block", newprofile.get_int("block") + earned_gamecoin_block
            )
        earned_blaster_energy = request.child_value("earned_blaster_energy")
        if earned_blaster_energy is not None:
            newprofile.replace_int(
                "blaster_energy",
                newprofile.get_int("blaster_energy") + earned_blaster_energy,
            )

        # Miscelaneous stuff
        newprofile.replace_int("blaster_count", request.child_value("blaster_count"))
        newprofile.replace_int("skill_name_id", request.child_value("skill_name_id"))
        newprofile.replace_int_array(
            "hidden_param", 20, request.child_value("hidden_param")
        )

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()

        if request.child("item") is not None:
            for child in request.child("item").children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                param = child.child_value("param")

                if (
                    game_config.get_bool("force_unlock_cards")
                    and item_type == self.GAME_CATALOG_TYPE_APPEAL_CARD
                ):
                    # Don't save back appeal cards because they were force unlocked
                    continue
                if (
                    game_config.get_bool("force_unlock_songs")
                    and item_type == self.GAME_CATALOG_TYPE_SONG
                ):
                    # Don't save back songs, because they were force unlocked
                    continue
                if (
                    game_config.get_bool("force_unlock_crew")
                    and item_type == self.GAME_CATALOG_TYPE_CREW
                ):
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

        # Update story progress
        if request.child("story") is not None:
            for child in request.child("story").children:
                if child.name != "info":
                    continue

                story_id = child.child_value("story_id")
                progress_id = child.child_value("progress_id")
                progress_param = child.child_value("progress_param")
                clear_cnt = child.child_value("clear_cnt")
                route_flg = child.child_value("route_flg")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    story_id,
                    "story",
                    {
                        "progress_id": progress_id,
                        "progress_param": progress_param,
                        "clear_cnt": clear_cnt,
                        "route_flg": route_flg,
                    },
                )

        # Grab last information.
        lastdict = newprofile.get_dict("last")
        lastdict.replace_int("headphone", request.child_value("headphone"))
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
