# vim: set fileencoding=utf-8
import random
from typing import Any, Dict, List, Optional, Set, Tuple
from typing_extensions import Final

from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.common import (
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
)
from bemani.backend.jubeat.clan import JubeatClan

from bemani.backend.base import Status
from bemani.common import Profile, Time, ValidatedDict, VersionConstants
from bemani.data import Data, UserID, Score, Song
from bemani.protocol import Node


class JubeatFesto(
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
    JubeatBase,
):
    name: str = "Jubeat Festo"
    version: int = VersionConstants.JUBEAT_FESTO

    JBOX_EMBLEM_NORMAL: Final[int] = 1
    JBOX_EMBLEM_PREMIUM: Final[int] = 2

    EVENT_STATUS_OPEN: Final[int] = 0x1
    EVENT_STATUS_COMPLETE: Final[int] = 0x2

    EVENTS: Dict[int, Dict[str, bool]] = {
        5: {
            "enabled": False,
        },
        6: {
            "enabled": False,
        },
        # Something to do with maintenance mode?
        15: {
            "enabled": True,
        },
        22: {
            "enabled": False,
        },
        23: {
            "enabled": False,
        },
        33: {
            "enabled": False,
        },
        101: {
            "enabled": False,
        },
        102: {
            "enabled": False,
        },
        103: {
            "enabled": False,
        },
        104: {
            "enabled": False,
        },
        105: {
            "enabled": False,
        },
        106: {
            "enabled": False,
        },
        107: {
            "enabled": False,
        },
        108: {
            "enabled": False,
        },
        109: {
            "enabled": False,
        },
    }

    COURSE_STATUS_SEEN: Final[int] = 0x01
    COURSE_STATUS_PLAYED: Final[int] = 0x02
    COURSE_STATUS_CLEARED: Final[int] = 0x04

    COURSE_TYPE_PERMANENT: Final[int] = 1
    COURSE_TYPE_TIME_BASED: Final[int] = 2

    COURSE_CLEAR_SCORE: Final[int] = 1
    COURSE_CLEAR_COMBINED_SCORE: Final[int] = 2
    COURSE_CLEAR_HAZARD: Final[int] = 3

    COURSE_HAZARD_EXC1: Final[int] = 1
    COURSE_HAZARD_EXC2: Final[int] = 2
    COURSE_HAZARD_EXC3: Final[int] = 3
    COURSE_HAZARD_FC1: Final[int] = 4
    COURSE_HAZARD_FC2: Final[int] = 5
    COURSE_HAZARD_FC3: Final[int] = 6

    GAME_CHART_TYPE_BASIC: Final[int] = 0
    GAME_CHART_TYPE_ADVANCED: Final[int] = 1
    GAME_CHART_TYPE_EXTREME: Final[int] = 2

    # Return the netlog service so that Festo doesn't crash on coin-in.
    extra_services: List[str] = [
        "netlog",
        "slocal",
    ]

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatClan(self.data, self.config, self.model)

    def game_to_db_chart(self, game_chart: int, hard_mode: bool) -> int:
        if hard_mode:
            return {
                self.GAME_CHART_TYPE_BASIC: self.CHART_TYPE_HARD_BASIC,
                self.GAME_CHART_TYPE_ADVANCED: self.CHART_TYPE_HARD_ADVANCED,
                self.GAME_CHART_TYPE_EXTREME: self.CHART_TYPE_HARD_EXTREME,
            }[game_chart]
        else:
            return {
                self.GAME_CHART_TYPE_BASIC: self.CHART_TYPE_BASIC,
                self.GAME_CHART_TYPE_ADVANCED: self.CHART_TYPE_ADVANCED,
                self.GAME_CHART_TYPE_EXTREME: self.CHART_TYPE_EXTREME,
            }[game_chart]

    def db_to_game_chart(self, db_chart: int) -> int:
        return {
            self.CHART_TYPE_BASIC: self.GAME_CHART_TYPE_BASIC,
            self.CHART_TYPE_ADVANCED: self.GAME_CHART_TYPE_ADVANCED,
            self.CHART_TYPE_EXTREME: self.GAME_CHART_TYPE_EXTREME,
            self.CHART_TYPE_HARD_BASIC: self.GAME_CHART_TYPE_BASIC,
            self.CHART_TYPE_HARD_ADVANCED: self.GAME_CHART_TYPE_ADVANCED,
            self.CHART_TYPE_HARD_EXTREME: self.GAME_CHART_TYPE_EXTREME,
        }[db_chart]

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Dict[str, Any]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Insert daily FC challenges into the DB.
        """
        events: List[Tuple[str, Dict[str, Any]]] = []
        if data.local.network.should_schedule(
            cls.game, cls.version, "fc_challenge", "daily"
        ):
            # Generate a new list of two FC challenge songs.
            start_time, end_time = data.local.network.get_schedule_duration("daily")
            all_songs = set(
                song.id
                for song in data.local.music.get_all_songs(cls.game, cls.version)
            )
            if len(all_songs) >= 2:
                daily_songs = random.sample(all_songs, 2)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "fc_challenge",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "today": daily_songs[0],
                        "whim": daily_songs[1],
                    },
                )
                events.append(
                    (
                        "jubeat_fc_challenge_charts",
                        {
                            "version": cls.version,
                            "today": daily_songs[0],
                            "whim": daily_songs[1],
                        },
                    )
                )

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "fc_challenge", "daily"
                )
        if data.local.network.should_schedule(
            cls.game, cls.version, "random_course", "daily"
        ):
            # Generate a new list of three random songs for random course mode.
            start_time, end_time = data.local.network.get_schedule_duration("daily")

            def is_ten(song: Song) -> bool:
                # We only want random songs that actually have a hard chart! This should be all songs right now,
                # but let's be conservative in case a future game screws things up.
                if song.chart not in {
                    cls.CHART_TYPE_HARD_BASIC,
                    cls.CHART_TYPE_HARD_ADVANCED,
                    cls.CHART_TYPE_HARD_EXTREME,
                }:
                    return False

                difficulty = song.data.get_float("difficulty", 13)
                if difficulty == 13.0:
                    difficulty = float(song.data.get_int("difficulty", 13))

                return difficulty >= 10.0 and difficulty < 11.0

            def chart_lut(chart: int) -> int:
                return {
                    cls.CHART_TYPE_HARD_BASIC: cls.CHART_TYPE_BASIC,
                    cls.CHART_TYPE_HARD_ADVANCED: cls.CHART_TYPE_ADVANCED,
                    cls.CHART_TYPE_HARD_EXTREME: cls.CHART_TYPE_EXTREME,
                }[chart]

            all_tens = [
                song
                for song in data.local.music.get_all_songs(cls.game, cls.version)
                if is_ten(song)
            ]
            if len(all_tens) >= 3:
                course_songs = random.sample(all_tens, 3)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "random_course",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "song1": {
                            "id": course_songs[0].id,
                            "chart": chart_lut(course_songs[0].chart),
                        },
                        "song2": {
                            "id": course_songs[1].id,
                            "chart": chart_lut(course_songs[1].chart),
                        },
                        "song3": {
                            "id": course_songs[2].id,
                            "chart": chart_lut(course_songs[2].chart),
                        },
                    },
                )
                events.append(
                    (
                        "jubeat_random_course_charts",
                        {
                            "version": cls.version,
                            "song1": {
                                "id": course_songs[0].id,
                                "chart": chart_lut(course_songs[0].chart),
                            },
                            "song2": {
                                "id": course_songs[1].id,
                                "chart": chart_lut(course_songs[1].chart),
                            },
                            "song3": {
                                "id": course_songs[2].id,
                                "chart": chart_lut(course_songs[2].chart),
                            },
                        },
                    )
                )

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "random_course", "daily"
                )
        return events

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "ints": [
                {
                    "name": "KAC Course Phase",
                    "tip": "The KAC competition courses that should be available in Tune Run",
                    "category": "game_config",
                    "setting": "kac_phase",
                    "values": {
                        0: "No KAC phase",
                        1: "The 8th KAC",
                        2: "The 9th KAC",
                        3: "The 10th KAC",
                    },
                },
            ],
            "bools": [
                {
                    "name": "Enable Stone Tablet Event",
                    "tip": "Enables the Stone Tablet event",
                    "category": "game_config",
                    "setting": "festo_dungeon",
                },
                {
                    "name": "50th Anniversary Celebration",
                    "tip": "Display the 50th anniversary screen in attract mode",
                    "category": "game_config",
                    "setting": "50th_anniversary",
                },
                {
                    "name": "Force Unlock All Songs",
                    "tip": "Forces all songs to be available by default",
                    "category": "game_config",
                    "setting": "force_song_unlock",
                },
            ],
        }

    def __get_course_list(self) -> List[Dict[str, Any]]:
        # Note that several of the below courses originally included removed songs, because older
        # versions of the game included them and they were removed sometime in its 4 year lifespan.
        # For those courses, the game will not display them unless you are on a data version that
        # includes the song. BemaniWiki notes when they were changed, so we check to see what the
        # data version of the game running is to provide the correct course. We could just support
        # only final data, but that's no fun!
        dataver = self.model.version or 2022052400

        # If it is available, then grab the random course. If we haven't generated that course, then
        # just don't bother trying to create it.
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "random_course"
        )
        random_course: List[Dict[str, Any]] = []

        if entry is not None:
            song1 = entry.get_dict("song1")
            song2 = entry.get_dict("song2")
            song3 = entry.get_dict("song3")

            random_course = [
                {
                    "id": 57,
                    "name": "腕試し！ランダムコース",
                    "course_type": self.COURSE_TYPE_PERMANENT,
                    "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                    "hard": True,
                    "difficulty": 15,
                    "score": 2850000,
                    "music": [
                        [(song1.get_int("id"), song1.get_int("chart"))],
                        [(song2.get_int("id"), song2.get_int("chart"))],
                        [(song3.get_int("id"), song3.get_int("chart"))],
                    ],
                }
            ]

        # So the game has a hard limit of 60 courses, but if we include everything from the
        # lifetime of festo including the random course we end up with 61 courses, which means
        # the game truncates the last course. Boo, that sucks. So, we have to have certain
        # courses switched. Let's do the KAC courses since in real life there would never have
        # been multiple KAC courses available at once.
        game_config = self.get_game_config()
        kac_phase = game_config.get_int("kac_phase")
        kac_8th = []
        kac_9th = []
        kac_10th = []

        if kac_phase == 1:
            kac_8th = [
                {
                    "id": 41,
                    "name": "The 8th KAC 個人部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000052, 2)],
                        [(90000013, 2)],
                        [(70000167, 2)],
                    ],
                },
                {
                    "id": 42,
                    "name": "The 8th KAC 団体部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000009, 2)],
                        [(80000133, 2)],
                        [(80000101, 2)],
                    ],
                },
            ]
        elif kac_phase == 2:
            kac_9th = [
                {
                    "id": 201,
                    "name": "The 9th KAC 1st Stage 個人部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000125, 2)],
                        [(60000065, 2)],
                        [(90000023, 2)],
                    ],
                },
                {
                    "id": 202,
                    "name": "The 9th KAC 1st Stage 団体部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000125, 2)],
                        [(50000135, 2)],
                        [(90000045, 2)],
                    ],
                },
                {
                    "id": 203,
                    "name": "The 9th KAC 2nd Stage 個人部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000095, 2)],
                        [(80000085, 2)],
                        [(80000090, 2)],
                    ],
                },
                {
                    "id": 204,
                    "name": "The 9th KAC 2nd Stage 団体部門",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000113, 2)],
                        [(50000344, 2)],
                        [(90000096, 2)],
                    ],
                },
            ]
        elif kac_phase == 3:
            kac_10th = [
                {
                    "id": 205,
                    "name": "The 10th KAC 1st Stage",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000003, 2)],
                        [(90000151, 2)],
                        [(90000174, 2)],
                    ],
                },
                {
                    "id": 206,
                    "name": "The 10th KAC 2nd Stage",
                    "course_type": self.COURSE_TYPE_TIME_BASED,
                    "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                    "clear_type": self.COURSE_CLEAR_SCORE,
                    "hard": True,
                    "difficulty": 14,
                    "score": 700000,
                    "music": [
                        [(90000121, 2)],
                        [(90000113, 2)],
                        [(90000124, 2)],
                    ],
                },
            ]

        return [
            # ASARI CUP
            {
                "id": 1,
                "name": "はじめてのビーチ",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 1,
                "score": 700000,
                "music": [
                    [
                        (60000080, 0),
                        (90000025 if dataver < 2021081600 else 90000077, 0),
                        (90000040 if dataver < 2021081600 else 90000139, 0),
                    ],
                    [(60000086, 0), (70000047, 0)],
                    [(90000027 if dataver < 2021081600 else 90000141, 0)],
                ],
            },
            {
                "id": 2,
                "name": "【初段】超幸せハイテンション",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 1,
                "score": 700000,
                "music": [
                    [
                        (
                            70000057
                            if dataver < 2019062100
                            else (90000079 if dataver < 2022021600 else 20000031),
                            0,
                        ),
                        (60000100, 0),
                        (90000030 if dataver < 2021081600 else 90000078, 0),
                    ],
                    [(70000125, 0), (90000050, 0)],
                    [(70000106, 0)],
                ],
            },
            {
                "id": 3,
                "name": "アニメランニング",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 2,
                "score": 750000,
                "music": [
                    [
                        (
                            80000020
                            if dataver < 2019062100
                            else (90000082 if dataver < 2022021600 else 60000092),
                            0,
                        ),
                        (90000031, 0),
                        (90000037 if dataver < 2021081600 else 90000172, 0),
                    ],
                    [
                        (
                            80000034
                            if dataver < 2020062900
                            else (
                                30000108
                                if dataver < 2020091300
                                else (40000107 if dataver < 2021020100 else 30000004)
                            ),
                            0,
                        ),
                        (80000120 if dataver < 2021020200 else 80000059, 0),
                    ],
                    [
                        (80000125 if dataver < 2021031900 else 50000209, 0),
                    ],
                ],
            },
            {
                "id": 4,
                "name": "パブリックリゾート",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 2,
                "score": 750000,
                "music": [
                    [
                        (
                            70000148
                            if dataver < 2020021900
                            else (90000040 if dataver < 2021081600 else 80000097),
                            0,
                        ),
                        (50000296 if dataver < 2021081600 else 90000029, 0),
                        (90000044 if dataver < 2021081600 else 90000076, 0),
                    ],
                    [
                        (90000033 if dataver < 2021081600 else 80000093, 0),
                        (90000039 if dataver < 2021081600 else 90000048, 0),
                    ],
                    [
                        (80000091 if dataver < 2021020200 else 80000038, 0),
                    ],
                ],
            },
            {
                "id": 5,
                "name": "【二段】その笑顔は甘く蕩ける",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 3,
                "score": 800000,
                "music": [
                    [(50000268, 0), (70000039, 0), (90000051, 0)],
                    [(70000091, 0), (70000042, 0)],
                    [(60000053, 0)],
                ],
            },
            {
                "id": 6,
                "name": "#オレのユビティズム",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 3,
                "score": 2100000,
                "music": [
                    [(20000042, 0), (20000042, 1), (20000042, 2)],
                    [(70000119, 0), (70000119, 1), (70000119, 2)],
                    [(50000115, 0), (50000115, 1), (50000115, 2)],
                ],
            },
            # KISAGO CUP
            {
                "id": 11,
                "name": "電脳享受空間",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 800000,
                "music": [
                    [
                        (70000046, 1),
                        (70000160, 1),
                        (80000126 if dataver < 2021020200 else 50000233, 1),
                    ],
                    [(80000031, 1), (80000097, 1)],
                    [(90000049, 1)],
                ],
            },
            {
                "id": 12,
                "name": "孤高の少女は破滅を願う",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 850000,
                "music": [
                    [(50000202, 0), (70000117, 0), (70000134, 0)],
                    [(50000212, 0), (80000124, 1)],
                    [(90001008, 1)],
                ],
            },
            {
                "id": 13,
                "name": "スタミナアップ！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 5,
                "score": 2600000,
                "music": [
                    [
                        (50000242, 0),
                        (
                            80000034
                            if dataver < 2020063000
                            else (90000079 if dataver < 2022021600 else 50000277),
                            1,
                        ),
                        (90000037 if dataver < 2021081600 else 50000294, 1),
                    ],
                    [(50000260, 1), (50000261, 1)],
                    [
                        (
                            70000085
                            if dataver < 2019062100
                            else (90000081 if dataver < 2022021600 else 90000143),
                            1,
                        ),
                    ],
                ],
            },
            {
                "id": 14,
                "name": "【三段】この花を貴方へ",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 850000,
                "music": [
                    [
                        (20000111 if dataver < 2019062100 else 90000034, 1),
                        (90000037 if dataver < 2021081600 else 90000107, 1),
                        (
                            70000131
                            if dataver < 2019111800
                            else (90000042 if dataver < 2021081600 else 90000140),
                            1,
                        ),
                    ],
                    [
                        (80000120 if dataver < 2021020200 else 80000052, 1),
                        (80001010, 1),
                    ],
                    [(40000051, 1)],
                ],
            },
            {
                "id": 15,
                "name": "【四段】嗚呼、大繁盛！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 6,
                "score": 2600000,
                "music": [
                    [(50000085, 2), (50000237, 2), (80000080, 2)],
                    [(50000172, 2), (50000235, 2)],
                    [(70000065, 2)],
                ],
            },
            {
                "id": 16,
                "name": "#シャレを言いなシャレ",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 4,
                "score": 2400000,
                "music": [
                    [(70000003, 0), (70000003, 1), (70000003, 2)],
                    [(70000045, 0), (70000045, 1), (70000045, 2)],
                    [(70000076, 0), (70000076, 1), (70000076, 2)],
                ],
            },
            {
                "id": 101,
                "name": "jubeat大回顧展 ROOM 1",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 950000,
                "music": [
                    [(50000277, 0), (50000277, 1), (50000277, 2)],
                    [(50000325, 0), (50000325, 1), (50000325, 2)],
                    [(90000014, 0), (90000014, 1), (90000014, 2)],
                ],
            },
            {
                "id": 102,
                "name": "jubeat大回顧展 ROOM 2",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 4,
                "score": 2750000,
                "music": [
                    [(30000048, 0), (30000048, 1), (30000048, 2)],
                    [(30000121, 0), (30000121, 1), (30000121, 2)],
                    [(90000012, 0), (90000012, 1), (90000012, 2)],
                ],
            },
            {
                "id": 103,
                "name": "jubeat大回顧展 ROOM 3",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 925000,
                "music": [
                    [(60000007, 0), (60000007, 1), (60000007, 2)],
                    [(60000070, 0), (60000070, 1), (60000070, 2)],
                    [(90000016, 0), (90000016, 1), (90000016, 2)],
                ],
            },
            {
                "id": 104,
                "name": "jubeat大回顧展 ROOM 4",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 4,
                "score": 2800000,
                "music": [
                    [(40000051, 0), (40000051, 1), (40000051, 2)],
                    [(40000129, 0), (40000129, 1), (40000129, 2)],
                    [(90000013, 0), (90000013, 1), (90000013, 2)],
                ],
            },
            {
                "id": 105,
                "name": "jubeat大回顧展 ROOM 5",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 4,
                "score": 2775000,
                "music": [
                    [(70000177, 0), (70000177, 1), (70000177, 2)],
                    [(70000011, 0), (70000011, 1), (70000011, 2)],
                    [(90000017, 0), (90000017, 1), (90000017, 2)],
                ],
            },
            {
                "id": 106,
                "name": "jubeat大回顧展 ROOM 6",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 940000,
                "music": [
                    [(20000123, 0), (20000123, 1), (20000123, 2)],
                    [(20000038, 0), (20000038, 1), (20000038, 2)],
                    [(90000011, 0), (90000011, 1), (90000011, 2)],
                ],
            },
            {
                "id": 107,
                "name": "jubeat大回顧展 ROOM 7",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 950000,
                "music": [
                    [(50000021, 0), (50000021, 1), (50000021, 2)],
                    [(50000078, 0), (50000078, 1), (50000078, 2)],
                    [(90000015, 0), (90000015, 1), (90000015, 2)],
                ],
            },
            {
                "id": 108,
                "name": "jubeat大回顧展 ROOM 8",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 4,
                "score": 2800000,
                "music": [
                    [(80000028, 0), (80000028, 1), (80000028, 2)],
                    [(80000087, 0), (80000087, 1), (80000087, 2)],
                    [(90000018, 0), (90000018, 1), (90000018, 2)],
                ],
            },
            {
                "id": 109,
                "name": "jubeat大回顧展 ROOM 9",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 4,
                "score": 930000,
                "music": [
                    [(10000038, 0), (10000038, 1), (10000038, 2)],
                    [(10000065, 0), (10000065, 1), (10000065, 2)],
                    [(90000010, 0), (90000010, 1), (90000010, 2)],
                ],
            },
            # MURU CUP
            {
                "id": 21,
                "name": "黒船来航",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 7,
                "score": 850000,
                "music": [
                    [(50000086, 2), (60000066, 2), (80000040, 1)],
                    [(50000096, 2), (80000048, 2)],
                    [(50000091, 2)],
                ],
            },
            {
                "id": 22,
                "name": "【五段】濁流を乗り越えて",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 7,
                "score": 2650000,
                "music": [
                    [
                        (50000343, 2),
                        (60000060, 2),
                        (70000156 if dataver < 2020040300 else 60000071, 2),
                    ],
                    [(60000027, 2), (80000048, 2)],
                    [(20000038, 2)],
                ],
            },
            {
                "id": 23,
                "name": "のんびり。ゆったり。ほがらかに。",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 8,
                "score": 950000,
                "music": [
                    [
                        (40000154, 2),
                        (80000124, 2),
                        (80000126 if dataver < 2021020200 else 90000139, 2),
                    ],
                    [
                        (60000048, 2),
                        (70000157 if dataver < 2020040300 else 80000041, 2),
                    ],
                    [(90000050, 2)],
                ],
            },
            {
                "id": 24,
                "name": "海・KOI・スィニョーレ！！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 8,
                "score": 2650000,
                "music": [
                    [(50000201, 2)],
                    [(50000339, 2)],
                    [(50000038, 2)],
                ],
            },
            {
                "id": 25,
                "name": "【六段】電柱を見ると思出す",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 9,
                "score": 2750000,
                "music": [
                    [(50000288, 2), (80000046, 2), (80001008, 2)],
                    [(50000207, 2), (70000117, 2)],
                    [(30000048, 2)],
                ],
            },
            {
                "id": 26,
                "name": "雨上がりレインボー",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 9,
                "score": 2650000,
                "music": [
                    [(50000138, 2)],
                    [(80000057, 2)],
                    [(90000011, 2)],
                ],
            },
            {
                "id": 27,
                "name": "Rain時々雨ノチ雨",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 9,
                "score": 2650000,
                "music": [
                    [(30000050, 2)],
                    [(80000123, 2)],
                    [(50000092, 2)],
                ],
            },
            {
                "id": 28,
                "name": "#心に残った曲",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 7,
                "score": 2700000,
                "music": [
                    [(80000136, 0), (80000136, 1), (80000136, 2)],
                    [(20000038, 0), (20000038, 1), (20000038, 2)],
                    [(60000065, 0), (60000065, 1), (70000084, 1)],
                ],
            },
            # SAZAE CUP
            {
                "id": 31,
                "name": "超フェスタ！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 10,
                "score": 930000,
                "music": [
                    [(70000076, 2), (70000077, 2)],
                    [(20000038, 2), (40000160, 2)],
                    [(70000145, 2)],
                ],
            },
            {
                "id": 32,
                "name": "【七段】操り人形はほくそ笑む",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 10,
                "score": 2800000,
                "music": [
                    [(70000006, 2), (70000171, 2), (80000003, 2)],
                    [(50000078, 2), (50000324, 2)],
                    [(80000118, 2)],
                ],
            },
            {
                "id": 33,
                "name": "絶体絶命スリーチャレンジ！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_HAZARD,
                "hazard_type": self.COURSE_HAZARD_FC3,
                "difficulty": 11,
                "music": [
                    [(50000238, 2), (70000003, 2), (90000051, 1)],
                    [(50000027, 2), (50000387, 2)],
                    [(80000056, 2)],
                ],
            },
            {
                "id": 34,
                "name": "天国の舞踏会",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 11,
                "score": 2800000,
                "music": [
                    [(60000065, 1)],
                    [(80001007, 2)],
                    [(90001007, 2)],
                ],
            },
            {
                "id": 35,
                "name": "【八段】山の賽子",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 12,
                "score": 2820000,
                "music": [
                    [(50000200, 2), (50000291, 2), (60000003, 2)],
                    [(50000129, 2), (80000021, 2)],
                    [(80000087, 2)],
                ],
            },
            {
                "id": 36,
                "name": "#コクがある曲",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 12,
                "score": 2400000,
                "music": [
                    [(50000139, 0), (50000139, 1), (50000139, 2)],
                    [(90000002, 0), (90000002, 1), (90000002, 2)],
                    [(50000060, 0), (50000060, 1), (50000060, 2)],
                ],
            },
            # HOTATE CUP
            *kac_8th,  # Contains courses 41 and 42.
            {
                "id": 43,
                "name": "BEMANI MASTER KOREA 2019",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "hard": True,
                "difficulty": 14,
                "score": 700000,
                "music": [
                    [(90000003, 2)],
                    [(80000090, 2)],
                    [(90000009, 2)],
                ],
            },
            *kac_9th,  # Contains courses 201, 202, 203 and 204.
            *kac_10th,  # Contains courses 205 and 206.
            {
                "id": 207,
                "name": "#どうやって押してる？",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 13,
                "score": 2600000,
                "music": [
                    [(40000127, 0)],
                    [(50000123, 0)],
                    [(50000126, 0)],
                ],
            },
            {
                "id": 208,
                "name": "BEMANI MASTER KOREA 2021",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "hard": True,
                "difficulty": 14,
                "score": 700000,
                "music": [
                    [(90000180, 2)],
                    [(90000095, 2)],
                    [(90000047, 2)],
                ],
            },
            {
                "id": 44,
                "name": "初めてのHARD MODE再び",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 13,
                "score": 2750000,
                "music": [
                    [(50000096, 2), (50000263, 2), (80000119, 2)],
                    [(60000021, 2), (60000075, 2)],
                    [(60000039, 2)],
                ],
            },
            {
                "id": 45,
                "name": "【九段】2人からの挑戦状",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 13,
                "score": 2830000,
                "music": [
                    [(50000023, 2), (80000025, 2), (80000106, 2)],
                    [(50000124, 2), (80000082, 2)],
                    [(60000115, 2)],
                ],
            },
            {
                "id": 46,
                "name": "天空の庭　太陽の園",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "difficulty": 13,
                "score": 965000,
                "music": [
                    [(40000153, 2)],
                    [(80000007, 2)],
                    [(70000173, 2)],
                ],
            },
            {
                "id": 47,
                "name": "緊急！迅速！大混乱！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 14,
                "score": 2900000,
                "music": [
                    [(20000040, 2), (50000244, 2), (60000074, 2)],
                    [(40000152, 2), (50000158, 2)],
                    [(40000057, 2)],
                ],
            },
            {
                "id": 48,
                "name": "【十段】時の超越者",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 14,
                "score": 2820000,
                "music": [
                    [(20000051, 2), (50000249, 2), (70000145, 2)],
                    [(40000046, 2), (50000180, 2)],
                    [(50000134, 2)],
                ],
            },
            {
                "id": 49,
                "name": "【伝導】10代目最強に挑戦！",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 14,
                "score": 2998179,
                "music": [
                    [(50000100, 2)],
                    [(90000047, 2)],
                    [(90000057, 2)],
                ],
            },
            {
                "id": 110,
                "name": "jubeat大回顧展 ROOM 10",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "difficulty": 13,
                "score": 2850000,
                "music": [
                    [(30000127, 2)],
                    [(60000078, 2)],
                    [(90000047, 2)],
                ],
            },
            # OSHAKO CUP
            {
                "id": 51,
                "name": "【皆伝】甘味なのに甘くない",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 15,
                "score": 2850000,
                "music": [
                    [(90000010, 2)],
                    [(80000101, 2)],
                    [(50000102, 2)],
                ],
            },
            {
                "id": 52,
                "name": "【伝導】真の青が魅せた空",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_SCORE,
                "hard": True,
                "difficulty": 15,
                "score": 970000,
                "music": [
                    [(50000332, 2)],
                    [(70000098, 2)],
                    [(90001005, 2)],
                ],
            },
            {
                "id": 53,
                "name": "豪華絢爛高揚絶頂",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 16,
                "score": 2960000,
                "music": [
                    [(10000065, 2)],
                    [(50000323, 2)],
                    [(50000208, 2)],
                ],
            },
            {
                "id": 54,
                "name": "絢爛豪華激情無常",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 16,
                "score": 2960000,
                "music": [
                    [(60000010, 2)],
                    [(70000110, 2)],
                    [(90000047, 2)],
                ],
            },
            {
                "id": 55,
                "name": "【指神】王の降臨",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 16,
                "score": 2980000,
                "music": [
                    [(70000094, 2)],
                    [(80000088, 2)],
                    [(70000110, 2)],
                ],
            },
            {
                "id": 56,
                "name": "【伝導】1116全てを超越した日",
                "course_type": self.COURSE_TYPE_PERMANENT,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 16,
                "score": 2975000,
                "music": [
                    [(50000208, 2)],
                    [(80000050, 2)],
                    [(90000057, 2)],
                ],
            },
            *random_course,  # Contains course 57.
            {
                "id": 58,
                "name": "#あなたのjubeatはどこから？",
                "course_type": self.COURSE_TYPE_TIME_BASED,
                "end_time": Time.end_of_this_week() + Time.SECONDS_IN_WEEK,
                "clear_type": self.COURSE_CLEAR_COMBINED_SCORE,
                "hard": True,
                "difficulty": 15,
                "score": 2900000,
                "music": [
                    [(10000065, 0), (10000065, 1), (10000065, 2)],
                    [(30000048, 0), (30000048, 1), (30000048, 2)],
                    [(90000047, 0), (90000047, 1), (90000047, 2)],
                ],
            },
        ]

    def __get_global_info(self) -> Node:
        info = Node.void("info")

        # Event info.
        event_info = Node.void("event_info")
        info.add_child(event_info)
        for event in self.EVENTS:
            evt = Node.void("event")
            event_info.add_child(evt)
            evt.set_attribute("type", str(event))
            evt.add_child(Node.u8("state", 1 if self.EVENTS[event]["enabled"] else 0))

        genre_def_music = Node.void("genre_def_music")
        info.add_child(genre_def_music)

        info.add_child(
            Node.s32_array(
                "black_jacket_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        # Mapping of what music is allowed by default, if this is set to all 0's
        # then the game will crash because it can't figure out what default song
        # to choose for new player sort. The way to calculate what song one of the
        # bits is for in any music_list array below is to look at the "pos_index"
        # field in the music_info.xml file. The entry in the array is calculated by
        # "(pos_index / 32)" and the bit to set is "1 << (pos_index % 32)"
        info.add_child(
            Node.s32_array(
                "white_music_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        # Mapping of what markers and themes are allowed for profile customization
        # by default. If this is set to all 0's then there are no markers or themes
        # offered and the default marker is forced.
        info.add_child(
            Node.s32_array(
                "white_marker_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "white_theme_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        # Possibly default unlocks for songs. Need to investigate further.
        info.add_child(
            Node.s32_array(
                "open_music_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "shareable_music_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        # Bitfield that determines what music is considered "pick up" versus "common" on the jubility
        # jacket field at the end of the game. Hot music is just the music in the current mix. The
        # bitfield values were taken from the "pos_index" field for all songs that are in festo.
        info.add_child(
            Node.s32_array(
                "hot_music_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    -4194304,
                    -2080769,
                    -1,
                    -17,
                    -3,
                    -33554433,
                    -242,
                    -268435473,
                    1073741823,
                    -1073748992,
                    15,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        jbox = Node.void("jbox")
        info.add_child(jbox)
        jbox.add_child(Node.s32("point", 0))
        emblem = Node.void("emblem")
        jbox.add_child(emblem)
        normal = Node.void("normal")
        emblem.add_child(normal)
        premium = Node.void("premium")
        emblem.add_child(premium)
        normal.add_child(Node.s16("index", 2))
        premium.add_child(Node.s16("index", 1))

        born = Node.void("born")
        info.add_child(born)
        born.add_child(Node.s8("status", 0))
        born.add_child(Node.s16("year", 0))

        game_config = self.get_game_config()
        konami_logo_50th = Node.void("konami_logo_50th")
        info.add_child(konami_logo_50th)
        konami_logo_50th.add_child(
            Node.bool("is_available", game_config.get_bool("50th_anniversary"))
        )

        expert_option = Node.void("expert_option")
        info.add_child(expert_option)
        expert_option.add_child(Node.bool("is_available", True))

        all_music_matching = Node.void("all_music_matching")
        info.add_child(all_music_matching)
        all_music_matching.add_child(Node.bool("is_available", True))

        department = Node.void("department")
        info.add_child(department)
        department.add_child(Node.void("shop_list"))

        question_list = Node.void("question_list")
        info.add_child(question_list)

        # Set up TUNE RUN course requirements
        clan_course_list = Node.void("course_list")
        info.add_child(clan_course_list)

        valid_courses: Set[int] = set()
        dataver = self.model.version or 2022052400
        for course in self.__get_course_list():
            if course["id"] < 1:
                raise Exception(
                    f"Invalid course ID {course['id']} found in course list!"
                )
            if course["id"] in valid_courses:
                raise Exception(f"Duplicate ID {course['id']} found in course list!")
            if (
                course["clear_type"] == self.COURSE_CLEAR_HAZARD
                and "hazard_type" not in course
            ):
                raise Exception(f"Need 'hazard_type' set in course {course['id']}!")
            if (
                course["course_type"] == self.COURSE_TYPE_TIME_BASED
                and "end_time" not in course
            ):
                raise Exception(f"Need 'end_time' set in course {course['id']}!")
            if (
                course["clear_type"]
                in [self.COURSE_CLEAR_SCORE, self.COURSE_CLEAR_COMBINED_SCORE]
                and "score" not in course
            ):
                raise Exception(f"Need 'score' set in course {course['id']}!")
            if (
                course["clear_type"] == self.COURSE_CLEAR_SCORE
                and course["score"] > 1000000
            ):
                raise Exception(f"Invalid per-coure score in course {course['id']}!")
            if (
                course["clear_type"] == self.COURSE_CLEAR_COMBINED_SCORE
                and course["score"] <= 1000000
            ):
                raise Exception(f"Invalid combined score in course {course['id']}!")
            valid_courses.add(course["id"])

            # Basics
            clan_course = Node.void("course")
            clan_course_list.add_child(clan_course)
            clan_course.set_attribute("release_code", str(dataver))
            clan_course.set_attribute("version_id", "0")
            clan_course.set_attribute("id", str(course["id"]))
            clan_course.set_attribute("course_type", str(course["course_type"]))
            clan_course.add_child(Node.s32("difficulty", course["difficulty"]))
            clan_course.add_child(
                Node.u64(
                    "etime", (course["end_time"] if "end_time" in course else 0) * 1000
                )
            )
            clan_course.add_child(Node.string("name", course["name"]))

            # List of included songs
            tune_list = Node.void("tune_list")
            clan_course.add_child(tune_list)
            for order, charts in enumerate(course["music"]):
                tune = Node.void("tune")
                tune_list.add_child(tune)
                tune.set_attribute("no", str(order + 1))

                seq_list = Node.void("seq_list")
                tune.add_child(seq_list)

                for songid, chart in charts:
                    seq = Node.void("seq")
                    seq_list.add_child(seq)
                    seq.add_child(Node.s32("music_id", songid))
                    seq.add_child(Node.s32("difficulty", chart))
                    seq.add_child(Node.bool("is_secret", False))

            # Clear criteria
            clear = Node.void("clear")
            clan_course.add_child(clear)
            ex_option = Node.void("ex_option")
            clear.add_child(ex_option)
            ex_option.add_child(
                Node.bool("is_hard", course["hard"] if "hard" in course else False)
            )
            ex_option.add_child(
                Node.s32(
                    "hazard_type",
                    course["hazard_type"] if "hazard_type" in course else 0,
                )
            )
            clear.set_attribute("type", str(course["clear_type"]))
            clear.add_child(
                Node.s32("score", course["score"] if "score" in course else 0)
            )

            reward_list = Node.void("reward_list")
            clear.add_child(reward_list)

        # Each of the following two sections should have zero or more child nodes (no
        # particular name) which look like the following:
        #     <node>
        #         <id __type="s32">songid</id>
        #         <stime __type="str">start time?</stime>
        #         <etime __type="str">end time?</etime>
        #     </node>
        # Share music?
        share_music = Node.void("share_music")
        info.add_child(share_music)

        weekly_music = Node.void("weekly_music")
        info.add_child(weekly_music)
        weekly_music.add_child(Node.s32("value", 0))

        info.add_child(
            Node.s32_array(
                "add_default_music_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        # The following section should have zero or more child nodes (no particular
        # name) which look like the following, with a song ID in the node's id attribute:
        #     <node id="" />
        weekly_music_list = Node.void("music_list")
        weekly_music.add_child(weekly_music_list)

        # Enable/disable festo dungeon.
        if game_config.get_bool("festo_dungeon"):
            festo_dungeon = Node.void("festo_dungeon")
            info.add_child(festo_dungeon)
            festo_dungeon.add_child(
                Node.u64("etime", (Time.now() + Time.SECONDS_IN_WEEK) * 1000)
            )

        # Unsupported team_battle nodes.
        info.add_child(Node.void("team_battle"))

        # Unsupported EMO list for EMO shop.
        info.add_child(Node.void("emo_list"))

        # Unsupported hike_event.
        info.add_child(Node.void("hike_event"))

        # Unsupported tip_list, this probably lets the server control the tips between songs.
        info.add_child(Node.void("tip_list"))

        # Unsupported mission travel event, which is very server-controlled.
        info.add_child(Node.void("travel"))

        # Unsupported stamp rally event, since this poorly undocumented.
        info.add_child(Node.void("stamp"))

        return info

    def handle_shopinfo_regist_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("shop/name"))

        shopinfo = Node.void("shopinfo")

        data = Node.void("data")
        shopinfo.add_child(data)
        data.add_child(Node.u32("cabid", 1))
        data.add_child(Node.string("locationid", "nowhere"))
        data.add_child(Node.u8("tax_phase", 1))

        facility = Node.void("facility")
        data.add_child(facility)
        facility.add_child(Node.u32("exist", 1))

        data.add_child(self.__get_global_info())

        return shopinfo

    def handle_demodata_get_info_request(self, request: Node) -> Node:
        root = Node.void("demodata")
        data = Node.void("data")
        root.add_child(data)

        info = Node.void("info")
        data.add_child(info)

        # This is the same stuff set in the common info, so if we ever do make this
        # configurable, I think we'll need to return the same thing in both spots.
        info.add_child(
            Node.s32_array(
                "black_jacket_list",
                [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        )

        return root

    def handle_demodata_get_jbox_list_request(self, request: Node) -> Node:
        root = Node.void("demodata")
        return root

    def handle_jbox_get_agreement_request(self, request: Node) -> Node:
        root = Node.void("jbox")
        root.add_child(Node.bool("is_agreement", True))
        return root

    def handle_jbox_get_list_request(self, request: Node) -> Node:
        root = Node.void("jbox")
        root.add_child(Node.void("selection_list"))
        return root

    def handle_ins_netlog_request(self, request: Node) -> Node:
        root = Node.void("ins")
        return root

    def handle_lab_get_ranking_request(self, request: Node) -> Node:
        root = Node.void("lab")
        root.add_child(Node.s8("category", request.child_value("category") or 0))

        entries = Node.void("entries")
        root.add_child(entries)

        # The game allows up to 10 entries, each looking like this:
        #     <entry>
        #         <seq_id __type="str">XXXXXXXXX</seq_id>
        #     <entry>
        entries.set_attribute("count", "0")

        return root

    def handle_recommend_get_recommend_request(self, request: Node) -> Node:
        recommend = Node.void("recommend")
        data = Node.void("data")
        recommend.add_child(data)

        player = Node.void("player")
        data.add_child(player)
        music_list = Node.void("music_list")
        player.add_child(music_list)

        # TODO: Might be a way to figure out who plays what song and then offer
        # recommendations based on that. There should be 12 songs returned here.
        recommended_songs: List[Song] = []
        for i, song in enumerate(recommended_songs):
            music = Node.void("music")
            music_list.add_child(music)
            music.set_attribute("order", str(i))
            music.add_child(Node.s32("music_id", song.id))
            music.add_child(Node.s8("seq", song.chart))

        return recommend

    def handle_gametop_get_info_request(self, request: Node) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)
        data.add_child(self.__get_global_info())

        return root

    def handle_gametop_regist_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        refid = player.child_value("refid")
        name = player.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        return root

    def handle_gametop_get_pdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        refid = player.child_value("refid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("gametop")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_gametop_get_mdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        extid = player.child_value("jid")
        mdata_ver = player.child_value("mdata_ver")
        root = self.get_scores_by_extid(extid, mdata_ver, 3)
        if root is None:
            root = Node.void("gametop")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_gameend_final_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")

        if player is not None:
            refid = player.child_value("refid")
        else:
            refid = None

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            profile = self.get_profile(userid)

            # Grab unlock progress
            item = player.child("item")
            if item is not None:
                owned_emblems = self.calculate_owned_items(
                    item.child_value("emblem_list")
                )
                for index in owned_emblems:
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        index,
                        "emblem",
                        {},
                    )

            # jbox stuff
            jbox = player.child("jbox")
            jboxdict = profile.get_dict("jbox")
            if jbox is not None:
                jboxdict.replace_int("point", jbox.child_value("point"))
                emblemtype = jbox.child_value("emblem/type")
                index = jbox.child_value("emblem/index")
                if emblemtype == self.JBOX_EMBLEM_NORMAL:
                    jboxdict.replace_int("normal_index", index)
                elif emblemtype == self.JBOX_EMBLEM_PREMIUM:
                    jboxdict.replace_int("premium_index", index)
            profile.replace_dict("jbox", jboxdict)

            # Born stuff
            born = player.child("born")
            if born is not None:
                profile.replace_int("born_status", born.child_value("status"))
                profile.replace_int("born_year", born.child_value("year"))
        else:
            profile = None

        if userid is not None and profile is not None:
            self.put_profile(userid, profile)

        return Node.void("gameend")

    def format_scores(
        self, userid: UserID, profile: Profile, scores: List[Score]
    ) -> Node:
        root = Node.void("gametop")
        datanode = Node.void("data")
        root.add_child(datanode)
        player = Node.void("player")
        datanode.add_child(player)
        player.add_child(Node.s32("jid", profile.extid))
        playdata = Node.void("mdata_list")
        player.add_child(playdata)

        music = ValidatedDict()
        for score in scores:
            chart = self.db_to_game_chart(score.chart)
            if score.chart in {
                self.CHART_TYPE_HARD_BASIC,
                self.CHART_TYPE_HARD_ADVANCED,
                self.CHART_TYPE_HARD_EXTREME,
            }:
                prefix = "hard"
            else:
                prefix = "normal"

            data = music.get_dict(str(score.id))
            play_cnt = data.get_int_array(f"{prefix}_play_cnt", 3)
            clear_cnt = data.get_int_array(f"{prefix}_clear_cnt", 3)
            clear_flags = data.get_int_array(f"{prefix}_clear_flags", 3)
            fc_cnt = data.get_int_array(f"{prefix}_fc_cnt", 3)
            ex_cnt = data.get_int_array(f"{prefix}_ex_cnt", 3)
            points = data.get_int_array(f"{prefix}_points", 3)
            music_rate = data.get_int_array(f"{prefix}_music_rate", 3)

            # Replace data for this chart type
            play_cnt[chart] = score.plays
            clear_cnt[chart] = score.data.get_int("clear_count")
            fc_cnt[chart] = score.data.get_int("full_combo_count")
            ex_cnt[chart] = score.data.get_int("excellent_count")
            points[chart] = score.points
            music_rate[chart] = score.data.get_int("music_rate")

            # Format the clear flags
            clear_flags[chart] = self.GAME_FLAG_BIT_PLAYED
            if score.data.get_int("clear_count") > 0:
                clear_flags[chart] |= self.GAME_FLAG_BIT_CLEARED
            if score.data.get_int("full_combo_count") > 0:
                clear_flags[chart] |= self.GAME_FLAG_BIT_FULL_COMBO
            if score.data.get_int("excellent_count") > 0:
                clear_flags[chart] |= self.GAME_FLAG_BIT_EXCELLENT

            # Save chart data back
            data.replace_int_array(f"{prefix}_play_cnt", 3, play_cnt)
            data.replace_int_array(f"{prefix}_clear_cnt", 3, clear_cnt)
            data.replace_int_array(f"{prefix}_clear_flags", 3, clear_flags)
            data.replace_int_array(f"{prefix}_fc_cnt", 3, fc_cnt)
            data.replace_int_array(f"{prefix}_ex_cnt", 3, ex_cnt)
            data.replace_int_array(f"{prefix}_points", 3, points)
            data.replace_int_array(f"{prefix}_music_rate", 3, music_rate)

            # Update the ghost (untyped)
            ghost = data.get(f"{prefix}_ghost", [None, None, None])
            ghost[chart] = score.data.get("ghost")
            data[f"{prefix}_ghost"] = ghost

            # Save it back
            music.replace_dict(str(score.id), data)

        for scoreid in music:
            scoredata = music.get_dict(scoreid)
            musicdata = Node.void("musicdata")
            playdata.add_child(musicdata)
            musicdata.set_attribute("music_id", scoreid)

            # Since in the worst case, we could be wasting a lot of data by always sending both a normal and hard mode block
            # we need to check if there's even a score array worth sending. This should help with performance for larger
            # score databases.
            if scoredata.get_int_array("normal_play_cnt", 3) != [0, 0, 0]:
                normalnode = Node.void("normal")
                musicdata.add_child(normalnode)

                normalnode.add_child(
                    Node.s32_array(
                        "play_cnt", scoredata.get_int_array("normal_play_cnt", 3)
                    )
                )
                normalnode.add_child(
                    Node.s32_array(
                        "clear_cnt", scoredata.get_int_array("normal_clear_cnt", 3)
                    )
                )
                normalnode.add_child(
                    Node.s32_array(
                        "fc_cnt", scoredata.get_int_array("normal_fc_cnt", 3)
                    )
                )
                normalnode.add_child(
                    Node.s32_array(
                        "ex_cnt", scoredata.get_int_array("normal_ex_cnt", 3)
                    )
                )
                normalnode.add_child(
                    Node.s32_array("score", scoredata.get_int_array("normal_points", 3))
                )
                normalnode.add_child(
                    Node.s8_array(
                        "clear", scoredata.get_int_array("normal_clear_flags", 3)
                    )
                )
                normalnode.add_child(
                    Node.s32_array(
                        "music_rate", scoredata.get_int_array("normal_music_rate", 3)
                    )
                )

                for i, ghost in enumerate(
                    scoredata.get("normal_ghost", [None, None, None])
                ):
                    if ghost is None:
                        continue

                    bar = Node.u8_array("bar", ghost)
                    normalnode.add_child(bar)
                    bar.set_attribute("seq", str(i))

            if scoredata.get_int_array("hard_play_cnt", 3) != [0, 0, 0]:
                hardnode = Node.void("hard")
                musicdata.add_child(hardnode)

                hardnode.add_child(
                    Node.s32_array(
                        "play_cnt", scoredata.get_int_array("hard_play_cnt", 3)
                    )
                )
                hardnode.add_child(
                    Node.s32_array(
                        "clear_cnt", scoredata.get_int_array("hard_clear_cnt", 3)
                    )
                )
                hardnode.add_child(
                    Node.s32_array("fc_cnt", scoredata.get_int_array("hard_fc_cnt", 3))
                )
                hardnode.add_child(
                    Node.s32_array("ex_cnt", scoredata.get_int_array("hard_ex_cnt", 3))
                )
                hardnode.add_child(
                    Node.s32_array("score", scoredata.get_int_array("hard_points", 3))
                )
                hardnode.add_child(
                    Node.s8_array(
                        "clear", scoredata.get_int_array("hard_clear_flags", 3)
                    )
                )
                hardnode.add_child(
                    Node.s32_array(
                        "music_rate", scoredata.get_int_array("hard_music_rate", 3)
                    )
                )

                for i, ghost in enumerate(
                    scoredata.get("hard_ghost", [None, None, None])
                ):
                    if ghost is None:
                        continue

                    bar = Node.u8_array("bar", ghost)
                    hardnode.add_child(bar)
                    bar.set_attribute("seq", str(i))

        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)

        # Figure out if we're force-unlocking songs.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        # Calculate all of our achievement-backed entities.
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        owned_songs: Set[int] = set()
        owned_secrets: Set[int] = set()
        owned_emblems: Set[int] = set()
        event_completion: Dict[int, bool] = {}
        course_completion: Dict[int, ValidatedDict] = {}
        for achievement in achievements:
            if achievement.type == "event":
                event_completion[achievement.id] = achievement.data.get_bool(
                    "is_completed"
                )
            elif achievement.type == "course":
                course_completion[achievement.id] = achievement.data
            elif achievement.type == "emblem":
                owned_emblems.add(achievement.id)
            elif achievement.type == "song":
                owned_songs.add(achievement.id)
            elif achievement.type == "secret":
                owned_secrets.add(achievement.id)

        # Make sure we grant ownership of default main parts.
        default_emblems = self.default_select_jbox()
        owned_emblems.update(default_emblems)
        default_main = next(iter(default_emblems)) if default_emblems else 0

        # Jubeat Clan appears to allow full event overrides per-player
        data.add_child(self.__get_global_info())

        player = Node.void("player")
        data.add_child(player)

        # Basic profile info
        player.add_child(Node.string("name", profile.get_str("name", "なし")))
        player.add_child(Node.s32("jid", profile.extid))

        # Miscelaneous crap
        player.add_child(Node.s32("session_id", 1))
        player.add_child(Node.u64("event_flag", profile.get_int("event_flag")))

        # Player info and statistics
        info = Node.void("info")
        player.add_child(info)
        info.add_child(Node.s32("tune_cnt", profile.get_int("tune_cnt")))
        info.add_child(Node.s32("save_cnt", profile.get_int("save_cnt")))
        info.add_child(Node.s32("saved_cnt", profile.get_int("saved_cnt")))
        info.add_child(Node.s32("fc_cnt", profile.get_int("fc_cnt")))
        info.add_child(Node.s32("ex_cnt", profile.get_int("ex_cnt")))
        info.add_child(Node.s32("clear_cnt", profile.get_int("clear_cnt")))
        info.add_child(Node.s32("match_cnt", profile.get_int("match_cnt")))
        info.add_child(Node.s32("beat_cnt", profile.get_int("beat_cnt")))
        info.add_child(Node.s32("mynews_cnt", profile.get_int("mynews_cnt")))
        info.add_child(Node.s32("mtg_entry_cnt", profile.get_int("mtg_entry_cnt")))
        info.add_child(Node.s32("mtg_hold_cnt", profile.get_int("mtg_hold_cnt")))
        info.add_child(Node.u8("mtg_result", profile.get_int("mtg_result")))
        info.add_child(
            Node.s32("bonus_tune_points", profile.get_int("bonus_tune_points"))
        )
        info.add_child(
            Node.bool("is_bonus_tune_played", profile.get_bool("is_bonus_tune_played"))
        )

        # Looks to be set to true when there's an old profile, stops tutorial from
        # happening on first load.
        info.add_child(
            Node.bool(
                "inherit",
                profile.get_bool("has_old_version") and not profile.get_bool("saved"),
            )
        )

        # Last played data, for showing cursor and such
        lastdict = profile.get_dict("last")
        last = Node.void("last")
        player.add_child(last)
        last.add_child(Node.s64("play_time", lastdict.get_int("play_time")))
        last.add_child(Node.string("shopname", lastdict.get_str("shopname")))
        last.add_child(Node.string("areaname", lastdict.get_str("areaname")))
        last.add_child(Node.s32("music_id", lastdict.get_int("music_id")))
        last.add_child(Node.s8("seq_id", lastdict.get_int("seq_id")))
        last.add_child(Node.s8("sort", lastdict.get_int("sort")))
        last.add_child(Node.s8("category", lastdict.get_int("category")))
        last.add_child(Node.s8("expert_option", lastdict.get_int("expert_option")))

        settings = Node.void("settings")
        last.add_child(settings)
        settings.add_child(Node.s8("marker", lastdict.get_int("marker")))
        settings.add_child(Node.s8("theme", lastdict.get_int("theme")))
        settings.add_child(Node.s16("title", lastdict.get_int("title")))
        settings.add_child(Node.s16("parts", lastdict.get_int("parts")))
        settings.add_child(Node.s8("rank_sort", lastdict.get_int("rank_sort")))
        settings.add_child(Node.s8("combo_disp", lastdict.get_int("combo_disp")))
        settings.add_child(Node.s8("matching", lastdict.get_int("matching")))
        settings.add_child(Node.s8("hard", lastdict.get_int("hard")))
        settings.add_child(Node.s8("hazard", lastdict.get_int("hazard")))

        # Hack to make the default emblem appear properly.
        partslist = lastdict.get_int_array("emblem", 5, [0, default_main, 0, 0, 0])
        if partslist[1] == 0:
            partslist[1] = default_main
        settings.add_child(Node.s16_array("emblem", partslist))

        item = Node.void("item")
        player.add_child(item)

        # Default music availability, I think? The game doesn't seem to make much use of this, so I think
        # we can safely set it to all 1's much like we do the open_music_list bitfield in global settings.
        item.add_child(
            Node.s32_array(
                "music_list", profile.get_int_array("music_list", 64, [-1] * 64)
            )
        )

        # Song unlocks, force everything on if force unlocked, otherwise default to what the game granted.
        item.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 64)
                if force_unlock
                else self.create_owned_items(owned_songs, 64),
            )
        )

        # We force unlock all themes, markers, titles, and parts, regardless of what the client ended up earning.
        item.add_child(
            Node.s32_array(
                "theme_list", profile.get_int_array("theme_list", 16, [-1] * 16)
            )
        )
        item.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list", 16, [-1] * 16)
            )
        )
        item.add_child(
            Node.s32_array(
                "title_list", profile.get_int_array("title_list", 160, [-1] * 160)
            )
        )
        item.add_child(
            Node.s32_array(
                "parts_list", profile.get_int_array("parts_list", 160, [-1] * 160)
            )
        )

        # These get earned by unlocking them through JBOX.
        item.add_child(
            Node.s32_array("emblem_list", self.create_owned_items(owned_emblems, 96))
        )

        # I got no idea wtf this is, so I'm defaulting it to all on like the above ones.
        item.add_child(
            Node.s32_array(
                "commu_list", profile.get_int_array("commu_list", 16, [-1] * 16)
            )
        )

        # I have no idea what these are for. I figured it was for the server to grant songs/themes/markers
        # outside of gameplay, but the game doesn't seem to react to setting values here. So, lets set them
        # to all 1's and move on. Tracing the handling of this shows that the game usually sets the same bit
        # in both the secret list above and this one, and doesn't seem to care about parsing the values as
        # they come in.
        new = Node.void("new")
        item.add_child(new)
        new.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 64)
                if force_unlock
                else self.create_owned_items(owned_secrets, 64),
            )
        )
        new.add_child(
            Node.s32_array(
                "theme_list", profile.get_int_array("theme_list_new", 16, [-1] * 16)
            )
        )
        new.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list_new", 16, [-1] * 16)
            )
        )

        # Add rivals to profile.
        rivallist = Node.void("rivallist")
        player.add_child(rivallist)

        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivalcount = 0
        for link in links:
            if link.type != "rival":
                continue

            rprofile = self.get_profile(link.other_userid)
            if rprofile is None:
                continue

            rival = Node.void("rival")
            rivallist.add_child(rival)
            rival.add_child(Node.s32("jid", rprofile.extid))
            rival.add_child(Node.string("name", rprofile.get_str("name")))

            # This looks like a carry-over from prop's career and isn't displayed.
            career = Node.void("career")
            rival.add_child(career)
            career.add_child(Node.s16("level", 1))

            # Lazy way of keeping track of rivals, since we can only have 3
            # or the game with throw up.
            rivalcount += 1
            if rivalcount >= 3:
                break

        lab_edit_seq = Node.void("lab_edit_seq")
        player.add_child(lab_edit_seq)
        lab_edit_seq.set_attribute("count", "0")

        # Full combo challenge
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "fc_challenge"
        )
        if entry is None:
            entry = ValidatedDict()

        # Figure out if we've played these songs
        start_time, end_time = self.data.local.network.get_schedule_duration("daily")
        today_attempts = self.data.local.music.get_all_attempts(
            self.game,
            self.music_version,
            userid,
            entry.get_int("today", -1),
            timelimit=start_time,
        )
        whim_attempts = self.data.local.music.get_all_attempts(
            self.game,
            self.music_version,
            userid,
            entry.get_int("whim", -1),
            timelimit=start_time,
        )

        # Full combo challenge and whim challenge
        fc_challenge = Node.void("fc_challenge")
        player.add_child(fc_challenge)
        today = Node.void("today")
        fc_challenge.add_child(today)
        today.add_child(Node.s32("music_id", entry.get_int("today", -1)))
        today.add_child(Node.u8("state", 0x40 if len(today_attempts) > 0 else 0x0))
        whim = Node.void("whim")
        fc_challenge.add_child(whim)
        whim.add_child(Node.s32("music_id", entry.get_int("whim", -1)))
        whim.add_child(Node.u8("state", 0x40 if len(whim_attempts) > 0 else 0x0))

        # No news, ever.
        official_news = Node.void("official_news")
        player.add_child(official_news)
        news_list = Node.void("news_list")
        official_news.add_child(news_list)

        # Sane defaults for unknown/who cares nodes
        history = Node.void("history")
        player.add_child(history)
        history.set_attribute("count", "0")

        free_first_play = Node.void("free_first_play")
        player.add_child(free_first_play)
        free_first_play.add_child(Node.bool("is_available", False))

        # Player status for events
        event_info = Node.void("event_info")
        player.add_child(event_info)
        for eventid, eventdata in self.EVENTS.items():
            # There are two significant bits here, bit 0 and bit 1, I think the first
            # one is whether the event is started, second is if its finished?
            event = Node.void("event")
            event_info.add_child(event)
            event.set_attribute("type", str(eventid))

            state = 0x0
            state |= self.EVENT_STATUS_OPEN if eventdata["enabled"] else 0
            state |= (
                self.EVENT_STATUS_COMPLETE
                if event_completion.get(eventid, False)
                else 0
            )
            event.add_child(Node.u8("state", state))

        # JBox stuff
        jbox = Node.void("jbox")
        jboxdict = profile.get_dict("jbox")
        player.add_child(jbox)
        jbox.add_child(Node.s32("point", jboxdict.get_int("point")))
        emblem = Node.void("emblem")
        jbox.add_child(emblem)
        normal = Node.void("normal")
        emblem.add_child(normal)
        premium = Node.void("premium")
        emblem.add_child(premium)

        # Calculate a random index for normal and premium to give to player
        # as a gatcha.
        normalindex, premiumindex = self.random_select_jbox(owned_emblems)
        normal.add_child(Node.s16("index", normalindex))
        premium.add_child(Node.s16("index", premiumindex))

        # New Music stuff
        new_music = Node.void("new_music")
        player.add_child(new_music)

        navi = Node.void("navi")
        player.add_child(navi)
        navi.add_child(Node.u64("flag", profile.get_int("navi_flag")))

        # Gift list, maybe from other players?
        gift_list = Node.void("gift_list")
        player.add_child(gift_list)
        # If we had gifts, they look like this. This is incomplete, however,
        # because I never bothered to find the virtual function to decode "detail".
        # Note that detail is only necessary if you don't want to give reason/id,
        # so its gotta be some hacked-on override.
        #     <gift reason="??" id="??">
        #         <detail>??</detail>
        #     </gift>

        # Birthday event?
        born = Node.void("born")
        player.add_child(born)
        born.add_child(Node.s8("status", profile.get_int("born_status")))
        born.add_child(Node.s16("year", profile.get_int("born_year")))

        # More crap
        question_list = Node.void("question_list")
        player.add_child(question_list)

        emo_list = Node.void("emo_list")
        player.add_child(emo_list)

        # Some server node
        server = Node.void("server")
        player.add_child(server)

        # Course List Progress
        course_list = Node.void("course_list")
        player.add_child(course_list)

        # Each course that we have completed has one of the following nodes.
        for course in self.__get_course_list():
            status_dict = course_completion.get(course["id"], ValidatedDict())
            status = 0
            status |= self.COURSE_STATUS_SEEN if status_dict.get_bool("seen") else 0
            status |= self.COURSE_STATUS_PLAYED if status_dict.get_bool("played") else 0
            status |= (
                self.COURSE_STATUS_CLEARED if status_dict.get_bool("cleared") else 0
            )

            coursenode = Node.void("course")
            course_list.add_child(coursenode)
            coursenode.set_attribute("id", str(course["id"]))
            coursenode.add_child(Node.s8("status", status))

        # For some reason, this is on the course list node this time around.
        category_list = Node.void("category_list")
        course_list.add_child(category_list)
        for categoryid in range(1, 7):
            category = Node.void("category")
            category_list.add_child(category)
            category.set_attribute("id", str(categoryid))
            category.add_child(Node.bool("is_display", True))

        # Fill in category
        fill_in_category = Node.void("fill_in_category")
        player.add_child(fill_in_category)

        normal = Node.void("normal")
        fill_in_category.add_child(normal)
        normal.add_child(
            Node.s32_array(
                "no_gray_flag_list",
                profile.get_int_array("normal_no_gray_flag_list", 16, [0] * 16),
            )
        )
        normal.add_child(
            Node.s32_array(
                "all_yellow_flag_list",
                profile.get_int_array("normal_all_yellow_flag_list", 16, [0] * 16),
            )
        )
        normal.add_child(
            Node.s32_array(
                "full_combo_flag_list",
                profile.get_int_array("normal_full_combo_flag_list", 16, [0] * 16),
            )
        )
        normal.add_child(
            Node.s32_array(
                "excellent_flag_list",
                profile.get_int_array("normal_excellent_flag_list", 16, [0] * 16),
            )
        )

        hard = Node.void("hard")
        fill_in_category.add_child(hard)
        hard.add_child(
            Node.s32_array(
                "no_gray_flag_list",
                profile.get_int_array("hard_no_gray_flag_list", 16, [0] * 16),
            )
        )
        hard.add_child(
            Node.s32_array(
                "all_yellow_flag_list",
                profile.get_int_array("hard_all_yellow_flag_list", 16, [0] * 16),
            )
        )
        hard.add_child(
            Node.s32_array(
                "full_combo_flag_list",
                profile.get_int_array("hard_full_combo_flag_list", 16, [0] * 16),
            )
        )
        hard.add_child(
            Node.s32_array(
                "excellent_flag_list",
                profile.get_int_array("hard_excellent_flag_list", 16, [0] * 16),
            )
        )

        # Unknown department shop stuff, I think this handles the EMO shop.
        department = Node.void("department")
        player.add_child(department)
        department.add_child(Node.void("shop_list"))

        # Stamp rally stuff, this is too server-controlled and not documented on BemaniWiki.
        stamp = Node.void("stamp")
        player.add_child(stamp)
        stamp.add_child(Node.void("sheet_list"))

        # Missing team_battle, which we do not support.

        # Missing eamuse_gift_list, which we do not support.

        # Missing hike_event, which I can't find any info on.

        # Festo dungeon
        festo_dungeon = Node.void("festo_dungeon")
        player.add_child(festo_dungeon)
        festo_dungeon.add_child(
            Node.s32("phase", profile.get_int("festo_dungeon_phase"))
        )
        festo_dungeon.add_child(
            Node.s32("clear_flag", profile.get_int("festo_dungeon_clear_flag"))
        )

        # Missing travel event, which I do not want to implement.

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()
        newprofile.replace_bool("saved", True)
        data = request.child("data")

        # Figure out if we're force-unlocking songs. If we are, we don't want to persist
        # secret stuff otherwise the game will accidentally unlock everything in the profile.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        # Grab system information
        sysinfo = data.child("info")

        # Grab player information
        player = data.child("player")

        # Grab result information
        result = data.child("result")

        # Grab last information. Lots of this will be filled in while grabbing scores
        last = newprofile.get_dict("last")
        if sysinfo is not None:
            last.replace_int("play_time", sysinfo.child_value("time_gameend"))
            last.replace_str("shopname", sysinfo.child_value("shopname"))
            last.replace_str("areaname", sysinfo.child_value("areaname"))

        # Grab player info for echoing back
        info = player.child("info")
        if info is not None:
            newprofile.replace_int("tune_cnt", info.child_value("tune_cnt"))
            newprofile.replace_int("save_cnt", info.child_value("save_cnt"))
            newprofile.replace_int("saved_cnt", info.child_value("saved_cnt"))
            newprofile.replace_int("fc_cnt", info.child_value("fc_cnt"))
            newprofile.replace_int("ex_cnt", info.child_value("ex_cnt"))
            newprofile.replace_int("clear_cnt", info.child_value("clear_cnt"))
            newprofile.replace_int("match_cnt", info.child_value("match_cnt"))
            newprofile.replace_int("beat_cnt", info.child_value("beat_cnt"))
            newprofile.replace_int("mynews_cnt", info.child_value("mynews_cnt"))

            newprofile.replace_int(
                "bonus_tune_points", info.child_value("bonus_tune_points")
            )
            newprofile.replace_bool(
                "is_bonus_tune_played", info.child_value("is_bonus_tune_played")
            )

        # Grab last settings
        lastnode = player.child("last")
        if lastnode is not None:
            last.replace_int("expert_option", lastnode.child_value("expert_option"))
            last.replace_int("sort", lastnode.child_value("sort"))
            last.replace_int("category", lastnode.child_value("category"))

            settings = lastnode.child("settings")
            if settings is not None:
                last.replace_int("matching", settings.child_value("matching"))
                last.replace_int("hazard", settings.child_value("hazard"))
                last.replace_int("hard", settings.child_value("hard"))
                last.replace_int("marker", settings.child_value("marker"))
                last.replace_int("theme", settings.child_value("theme"))
                last.replace_int("title", settings.child_value("title"))
                last.replace_int("parts", settings.child_value("parts"))
                last.replace_int("rank_sort", settings.child_value("rank_sort"))
                last.replace_int("combo_disp", settings.child_value("combo_disp"))
                last.replace_int_array("emblem", 5, settings.child_value("emblem"))

        # Grab unlock progress
        item = player.child("item")
        if item is not None:
            newprofile.replace_int_array(
                "music_list", 64, item.child_value("music_list")
            )
            newprofile.replace_int_array(
                "theme_list", 16, item.child_value("theme_list")
            )
            newprofile.replace_int_array(
                "marker_list", 16, item.child_value("marker_list")
            )
            newprofile.replace_int_array(
                "title_list", 160, item.child_value("title_list")
            )
            newprofile.replace_int_array(
                "parts_list", 160, item.child_value("parts_list")
            )
            newprofile.replace_int_array(
                "commu_list", 16, item.child_value("commu_list")
            )

            if not force_unlock:
                # Don't persist if we're force-unlocked, this data will be bogus.
                owned_songs = self.calculate_owned_items(
                    item.child_value("secret_list")
                )
                for index in owned_songs:
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        index,
                        "song",
                        {},
                    )

            owned_emblems = self.calculate_owned_items(item.child_value("emblem_list"))
            for index in owned_emblems:
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    index,
                    "emblem",
                    {},
                )

            newitem = item.child("new")
            if newitem is not None:
                newprofile.replace_int_array(
                    "theme_list_new", 16, newitem.child_value("theme_list")
                )
                newprofile.replace_int_array(
                    "marker_list_new", 16, newitem.child_value("marker_list")
                )

                if not force_unlock:
                    # Don't persist if we're force-unlocked, this data will be bogus.
                    owned_secrets = self.calculate_owned_items(
                        newitem.child_value("secret_list")
                    )
                    for index in owned_secrets:
                        self.data.local.user.put_achievement(
                            self.game,
                            self.version,
                            userid,
                            index,
                            "secret",
                            {},
                        )

        # Grab categories stuff
        fill_in_category = player.child("fill_in_category")
        if fill_in_category is not None:
            fill_in_category_normal = fill_in_category.child("normal")
            if fill_in_category_normal is not None:
                newprofile.replace_int_array(
                    "normal_no_gray_flag_list",
                    16,
                    fill_in_category_normal.child_value("no_gray_flag_list"),
                )
                newprofile.replace_int_array(
                    "normal_all_yellow_flag_list",
                    16,
                    fill_in_category_normal.child_value("all_yellow_flag_list"),
                )
                newprofile.replace_int_array(
                    "normal_full_combo_flag_list",
                    16,
                    fill_in_category_normal.child_value("full_combo_flag_list"),
                )
                newprofile.replace_int_array(
                    "normal_excellent_flag_list",
                    16,
                    fill_in_category_normal.child_value("excellent_flag_list"),
                )
            fill_in_category_hard = fill_in_category.child("hard")
            if fill_in_category_hard is not None:
                newprofile.replace_int_array(
                    "hard_no_gray_flag_list",
                    16,
                    fill_in_category_hard.child_value("no_gray_flag_list"),
                )
                newprofile.replace_int_array(
                    "hard_all_yellow_flag_list",
                    16,
                    fill_in_category_hard.child_value("all_yellow_flag_list"),
                )
                newprofile.replace_int_array(
                    "hard_full_combo_flag_list",
                    16,
                    fill_in_category_hard.child_value("full_combo_flag_list"),
                )
                newprofile.replace_int_array(
                    "hard_excellent_flag_list",
                    16,
                    fill_in_category_hard.child_value("excellent_flag_list"),
                )

        # jbox stuff
        jbox = player.child("jbox")
        jboxdict = newprofile.get_dict("jbox")
        if jbox is not None:
            jboxdict.replace_int("point", jbox.child_value("point"))
            emblemtype = jbox.child_value("emblem/type")
            index = jbox.child_value("emblem/index")
            if emblemtype == self.JBOX_EMBLEM_NORMAL:
                jboxdict.replace_int("normal_index", index)
            elif emblemtype == self.JBOX_EMBLEM_PREMIUM:
                jboxdict.replace_int("premium_index", index)
        newprofile.replace_dict("jbox", jboxdict)

        # event stuff
        newprofile.replace_int("event_flag", player.child_value("event_flag"))
        event_info = player.child("event_info")
        if event_info is not None:
            for child in event_info.children:
                try:
                    eventid = int(child.attribute("type"))
                except TypeError:
                    # Event is empty
                    continue
                is_completed = child.child_value("is_completed")

                # Figure out if we should update the rating/scores or not
                oldevent = self.data.local.user.get_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventid,
                    "event",
                )

                if oldevent is None:
                    # Create a new event structure for this
                    oldevent = ValidatedDict()

                oldevent.replace_bool("is_completed", is_completed)

                # Save it as an achievement
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventid,
                    "event",
                    oldevent,
                )

        # Still don't know what this is for lol
        newprofile.replace_int("navi_flag", player.child_value("navi/flag"))

        # Grab scores and save those
        if result is not None:
            for tune in result.children:
                if tune.name != "tune":
                    continue
                result = tune.child("player")
                songid = tune.child_value("music")
                timestamp = tune.child_value("timestamp") / 1000
                chart = self.game_to_db_chart(
                    int(result.child("score").attribute("seq")),
                    bool(result.child_value("is_hard_mode")),
                )
                points = result.child_value("score")
                flags = int(result.child("score").attribute("clear"))
                combo = int(result.child("score").attribute("combo"))
                ghost = result.child_value("mbar")
                music_rate = result.child_value("music_rate")

                stats = {
                    "perfect": result.child_value("nr_perfect"),
                    "great": result.child_value("nr_great"),
                    "good": result.child_value("nr_good"),
                    "poor": result.child_value("nr_poor"),
                    "miss": result.child_value("nr_miss"),
                }

                # Miscelaneous last data for echoing to profile get
                last.replace_int("music_id", songid)
                last.replace_int("seq_id", int(result.child("score").attribute("seq")))

                mapping = {
                    self.GAME_FLAG_BIT_CLEARED: self.PLAY_MEDAL_CLEARED,
                    self.GAME_FLAG_BIT_FULL_COMBO: self.PLAY_MEDAL_FULL_COMBO,
                    self.GAME_FLAG_BIT_EXCELLENT: self.PLAY_MEDAL_EXCELLENT,
                    self.GAME_FLAG_BIT_NEARLY_FULL_COMBO: self.PLAY_MEDAL_NEARLY_FULL_COMBO,
                    self.GAME_FLAG_BIT_NEARLY_EXCELLENT: self.PLAY_MEDAL_NEARLY_EXCELLENT,
                }

                # Figure out the highest medal based on bits passed in
                medal = self.PLAY_MEDAL_FAILED
                for bit in mapping:
                    if flags & bit > 0:
                        medal = max(medal, mapping[bit])

                self.update_score(
                    userid,
                    timestamp,
                    songid,
                    chart,
                    points,
                    medal,
                    combo,
                    ghost,
                    stats,
                    music_rate,
                )

        # Born stuff
        born = player.child("born")
        if born is not None:
            newprofile.replace_int("born_status", born.child_value("status"))
            newprofile.replace_int("born_year", born.child_value("year"))

        # jubility list sent looks like this
        # <jubility>
        #     <target_music>
        #         <hot_music_list param="36385">
        #             <music>
        #                 <music_id __type="s32">90000130</music_id>
        #                 <seq __type="s8">2</seq>
        #                 <rate __type="s32">975</rate>
        #                 <value __type="s32">1280</value>
        #                 <is_hard_mode __type="bool">0</is_hard_mode>
        #             </music>
        #         </hot_music_list>
        #         <other_music_list param="36770">

        # Grab jubility
        jubility = player.child("jubility")
        if jubility is not None:
            target_music = jubility.child("target_music")

            # Pick up jubility stuff
            hot_music_list = target_music.child("hot_music_list")
            pick_up_chart = ValidatedDict()
            for music in hot_music_list.children:
                music_id = music.child_value("music_id")
                chart = self.game_to_db_chart(
                    int(music.child_value("seq")),
                    bool(music.child_value("is_hard_mode")),
                )
                music_rate = float(music.child_value("rate")) / 10
                value = float(music.child_value("value")) / 10
                entry = {
                    "music_id": music_id,
                    "seq": chart,
                    "music_rate": music_rate,
                    "value": value,
                }
                pick_up_chart.replace_dict(f"{music_id}_{chart}", entry)

            # Save it back
            newprofile.replace_dict("pick_up_chart", pick_up_chart)
            newprofile.replace_float(
                "pick_up_jubility", float(hot_music_list.attribute("param")) / 10
            )

            # Common jubility stuff
            other_music_list = target_music.child("other_music_list")
            common_chart = ValidatedDict()
            for music in other_music_list.children:
                music_id = music.child_value("music_id")
                chart = self.game_to_db_chart(
                    int(music.child_value("seq")),
                    bool(music.child_value("is_hard_mode")),
                )
                music_rate = float(music.child_value("rate")) / 10
                value = float(music.child_value("value")) / 10
                entry = {
                    "music_id": music_id,
                    "seq": chart,
                    "music_rate": music_rate,
                    "value": value,
                }
                common_chart.replace_dict(f"{music_id}_{chart}", entry)

            # Save it back
            newprofile.replace_dict("common_chart", common_chart)
            newprofile.replace_float(
                "common_jubility", float(other_music_list.attribute("param")) / 10
            )

        # Clan course saving
        clan_course_list = player.child("course_list")
        if clan_course_list is not None:
            for course in clan_course_list.children:
                if course.name != "course":
                    continue

                courseid = int(course.attribute("id"))
                status = course.child_value("status")
                is_seen = (status & self.COURSE_STATUS_SEEN) != 0
                is_played = (status & self.COURSE_STATUS_PLAYED) != 0

                # Update seen status and played status
                oldcourse = self.data.local.user.get_achievement(
                    self.game,
                    self.version,
                    userid,
                    courseid,
                    "course",
                )

                if oldcourse is None:
                    # Create a new course structure for this
                    oldcourse = ValidatedDict()

                oldcourse.replace_bool("seen", oldcourse.get_bool("seen") or is_seen)
                oldcourse.replace_bool(
                    "played", oldcourse.get_bool("played") or is_played
                )

                # Save it as an achievement
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    courseid,
                    "course",
                    oldcourse,
                )

        # If they played a course, figure out if they cleared it.
        select_course = player.child("select_course")
        if select_course is not None:
            try:
                courseid = int(select_course.attribute("id"))
            except Exception:
                courseid = 0
            cleared = select_course.child_value("is_cleared")

            if courseid > 0 and cleared:
                # Update course cleared status
                oldcourse = self.data.local.user.get_achievement(
                    self.game,
                    self.version,
                    userid,
                    courseid,
                    "course",
                )

                if oldcourse is None:
                    # Create a new course structure for this
                    oldcourse = ValidatedDict()

                oldcourse.replace_bool("cleared", True)

                # Save it as an achievement
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    courseid,
                    "course",
                    oldcourse,
                )

        # Save back last information gleaned from results
        newprofile.replace_dict("last", last)

        festo_dungeon = player.child("festo_dungeon")
        if festo_dungeon is not None:
            newprofile.replace_int(
                "festo_dungeon_phase", festo_dungeon.child_value("phase")
            )
            newprofile.replace_int(
                "festo_dungeon_clear_flag", festo_dungeon.child_value("clear_flag")
            )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
