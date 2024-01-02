# vim: set fileencoding=utf-8
import random
import struct
from typing import Optional, Dict, Any, List, Tuple
from typing_extensions import Final

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.course import IIDXCourse
from bemani.backend.iidx.cannonballers import IIDXCannonBallers

from bemani.common import (
    Profile,
    ValidatedDict,
    VersionConstants,
    BroadcastConstants,
    Time,
    ID,
    intish,
)
from bemani.data import Data, UserID
from bemani.protocol import Node


class IIDXRootage(IIDXCourse, IIDXBase):
    name: str = "Beatmania IIDX ROOTAGE"
    version: int = VersionConstants.IIDX_ROOTAGE

    GAME_CLTYPE_SINGLE: Final[int] = 0
    GAME_CLTYPE_DOUBLE: Final[int] = 1

    DAN_STAGES: Final[int] = 4

    GAME_CLEAR_STATUS_NO_PLAY: Final[int] = 0
    GAME_CLEAR_STATUS_FAILED: Final[int] = 1
    GAME_CLEAR_STATUS_ASSIST_CLEAR: Final[int] = 2
    GAME_CLEAR_STATUS_EASY_CLEAR: Final[int] = 3
    GAME_CLEAR_STATUS_CLEAR: Final[int] = 4
    GAME_CLEAR_STATUS_HARD_CLEAR: Final[int] = 5
    GAME_CLEAR_STATUS_EX_HARD_CLEAR: Final[int] = 6
    GAME_CLEAR_STATUS_FULL_COMBO: Final[int] = 7

    GAME_GHOST_TYPE_RIVAL: Final[int] = 1
    GAME_GHOST_TYPE_GLOBAL_TOP: Final[int] = 2
    GAME_GHOST_TYPE_GLOBAL_AVERAGE: Final[int] = 3
    GAME_GHOST_TYPE_LOCAL_TOP: Final[int] = 4
    GAME_GHOST_TYPE_LOCAL_AVERAGE: Final[int] = 5
    GAME_GHOST_TYPE_DAN_TOP: Final[int] = 6
    GAME_GHOST_TYPE_DAN_AVERAGE: Final[int] = 7
    GAME_GHOST_TYPE_RIVAL_TOP: Final[int] = 8
    GAME_GHOST_TYPE_RIVAL_AVERAGE: Final[int] = 9

    GAME_GHOST_LENGTH: Final[int] = 64

    GAME_SP_DAN_RANK_7_KYU: Final[int] = 0
    GAME_SP_DAN_RANK_6_KYU: Final[int] = 1
    GAME_SP_DAN_RANK_5_KYU: Final[int] = 2
    GAME_SP_DAN_RANK_4_KYU: Final[int] = 3
    GAME_SP_DAN_RANK_3_KYU: Final[int] = 4
    GAME_SP_DAN_RANK_2_KYU: Final[int] = 5
    GAME_SP_DAN_RANK_1_KYU: Final[int] = 6
    GAME_SP_DAN_RANK_1_DAN: Final[int] = 7
    GAME_SP_DAN_RANK_2_DAN: Final[int] = 8
    GAME_SP_DAN_RANK_3_DAN: Final[int] = 9
    GAME_SP_DAN_RANK_4_DAN: Final[int] = 10
    GAME_SP_DAN_RANK_5_DAN: Final[int] = 11
    GAME_SP_DAN_RANK_6_DAN: Final[int] = 12
    GAME_SP_DAN_RANK_7_DAN: Final[int] = 13
    GAME_SP_DAN_RANK_8_DAN: Final[int] = 14
    GAME_SP_DAN_RANK_9_DAN: Final[int] = 15
    GAME_SP_DAN_RANK_10_DAN: Final[int] = 16
    GAME_SP_DAN_RANK_CHUDEN: Final[int] = 17
    GAME_SP_DAN_RANK_KAIDEN: Final[int] = 18

    GAME_DP_DAN_RANK_7_KYU: Final[int] = 0
    GAME_DP_DAN_RANK_6_KYU: Final[int] = 1
    GAME_DP_DAN_RANK_5_KYU: Final[int] = 2
    GAME_DP_DAN_RANK_4_KYU: Final[int] = 3
    GAME_DP_DAN_RANK_3_KYU: Final[int] = 4
    GAME_DP_DAN_RANK_2_KYU: Final[int] = 5
    GAME_DP_DAN_RANK_1_KYU: Final[int] = 6
    GAME_DP_DAN_RANK_1_DAN: Final[int] = 7
    GAME_DP_DAN_RANK_2_DAN: Final[int] = 8
    GAME_DP_DAN_RANK_3_DAN: Final[int] = 9
    GAME_DP_DAN_RANK_4_DAN: Final[int] = 10
    GAME_DP_DAN_RANK_5_DAN: Final[int] = 11
    GAME_DP_DAN_RANK_6_DAN: Final[int] = 12
    GAME_DP_DAN_RANK_7_DAN: Final[int] = 13
    GAME_DP_DAN_RANK_8_DAN: Final[int] = 14
    GAME_DP_DAN_RANK_9_DAN: Final[int] = 15
    GAME_DP_DAN_RANK_10_DAN: Final[int] = 16
    GAME_DP_DAN_RANK_CHUDEN: Final[int] = 17
    GAME_DP_DAN_RANK_KAIDEN: Final[int] = 18

    FAVORITE_LIST_LENGTH: Final[int] = 20

    GAME_CHART_TYPE_N7: Final[int] = 0
    GAME_CHART_TYPE_H7: Final[int] = 1
    GAME_CHART_TYPE_A7: Final[int] = 2
    GAME_CHART_TYPE_N14: Final[int] = 3
    GAME_CHART_TYPE_H14: Final[int] = 4
    GAME_CHART_TYPE_A14: Final[int] = 5
    GAME_CHART_TYPE_B7: Final[int] = 6

    requires_extended_regions = True

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXCannonBallers(self.data, self.config, self.model)

    @classmethod
    def run_scheduled_work(cls, data: Data, config: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Insert dailies into the DB.
        """
        events = []
        if data.local.network.should_schedule(cls.game, cls.version, "daily_charts", "daily"):
            # Generate a new list of three dailies.
            start_time, end_time = data.local.network.get_schedule_duration("daily")
            all_songs = list(set([song.id for song in data.local.music.get_all_songs(cls.game, cls.version)]))
            if len(all_songs) >= 3:
                daily_songs = random.sample(all_songs, 3)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "dailies",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "music": daily_songs,
                    },
                )
                events.append(
                    (
                        "iidx_daily_charts",
                        {
                            "version": cls.version,
                            "music": daily_songs,
                        },
                    )
                )

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(cls.game, cls.version, "daily_charts", "daily")
        return events

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Global Shop Ranking",
                    "tip": "Return network-wide ranking instead of shop ranking on results screen.",
                    "category": "game_config",
                    "setting": "global_shop_ranking",
                },
                {
                    "name": "Events In Omnimix",
                    "tip": "Allow events to be enabled at all for Omnimix.",
                    "category": "game_config",
                    "setting": "omnimix_events_enabled",
                },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
            "ints": [
                {
                    "name": "Event Phase",
                    "tip": "Event phase for all players.",
                    "category": "game_config",
                    "setting": "event_phase",
                    "values": {
                        0: "No Event",
                        1: "蜃気楼の図書館(The Bibliotheca of Mirage) Phase 1",
                        2: "蜃気楼の図書館(The Bibliotheca of Mirage) Phase 2",
                        3: "蜃気楼の図書館(The Bibliotheca of Mirage) Phase 3",
                        4: "蜃気楼の図書館(The Bibliotheca of Mirage) Phase 4",
                        5: "DELABITY LABORATORY",
                    },
                },
            ],
        }

    def db_to_game_status(self, db_status: int) -> int:
        return {
            self.CLEAR_STATUS_NO_PLAY: self.GAME_CLEAR_STATUS_NO_PLAY,
            self.CLEAR_STATUS_FAILED: self.GAME_CLEAR_STATUS_FAILED,
            self.CLEAR_STATUS_ASSIST_CLEAR: self.GAME_CLEAR_STATUS_ASSIST_CLEAR,
            self.CLEAR_STATUS_EASY_CLEAR: self.GAME_CLEAR_STATUS_EASY_CLEAR,
            self.CLEAR_STATUS_CLEAR: self.GAME_CLEAR_STATUS_CLEAR,
            self.CLEAR_STATUS_HARD_CLEAR: self.GAME_CLEAR_STATUS_HARD_CLEAR,
            self.CLEAR_STATUS_EX_HARD_CLEAR: self.GAME_CLEAR_STATUS_EX_HARD_CLEAR,
            self.CLEAR_STATUS_FULL_COMBO: self.GAME_CLEAR_STATUS_FULL_COMBO,
        }[db_status]

    def game_to_db_status(self, game_status: int) -> int:
        return {
            self.GAME_CLEAR_STATUS_NO_PLAY: self.CLEAR_STATUS_NO_PLAY,
            self.GAME_CLEAR_STATUS_FAILED: self.CLEAR_STATUS_FAILED,
            self.GAME_CLEAR_STATUS_ASSIST_CLEAR: self.CLEAR_STATUS_ASSIST_CLEAR,
            self.GAME_CLEAR_STATUS_EASY_CLEAR: self.CLEAR_STATUS_EASY_CLEAR,
            self.GAME_CLEAR_STATUS_CLEAR: self.CLEAR_STATUS_CLEAR,
            self.GAME_CLEAR_STATUS_HARD_CLEAR: self.CLEAR_STATUS_HARD_CLEAR,
            self.GAME_CLEAR_STATUS_EX_HARD_CLEAR: self.CLEAR_STATUS_EX_HARD_CLEAR,
            self.GAME_CLEAR_STATUS_FULL_COMBO: self.CLEAR_STATUS_FULL_COMBO,
        }[game_status]

    def db_to_game_rank(self, db_dan: int, cltype: int) -> int:
        # Special case for no DAN rank
        if db_dan == -1:
            return -1

        if cltype == self.GAME_CLTYPE_SINGLE:
            return {
                self.DAN_RANK_7_KYU: self.GAME_SP_DAN_RANK_7_KYU,
                self.DAN_RANK_6_KYU: self.GAME_SP_DAN_RANK_6_KYU,
                self.DAN_RANK_5_KYU: self.GAME_SP_DAN_RANK_5_KYU,
                self.DAN_RANK_4_KYU: self.GAME_SP_DAN_RANK_4_KYU,
                self.DAN_RANK_3_KYU: self.GAME_SP_DAN_RANK_3_KYU,
                self.DAN_RANK_2_KYU: self.GAME_SP_DAN_RANK_2_KYU,
                self.DAN_RANK_1_KYU: self.GAME_SP_DAN_RANK_1_KYU,
                self.DAN_RANK_1_DAN: self.GAME_SP_DAN_RANK_1_DAN,
                self.DAN_RANK_2_DAN: self.GAME_SP_DAN_RANK_2_DAN,
                self.DAN_RANK_3_DAN: self.GAME_SP_DAN_RANK_3_DAN,
                self.DAN_RANK_4_DAN: self.GAME_SP_DAN_RANK_4_DAN,
                self.DAN_RANK_5_DAN: self.GAME_SP_DAN_RANK_5_DAN,
                self.DAN_RANK_6_DAN: self.GAME_SP_DAN_RANK_6_DAN,
                self.DAN_RANK_7_DAN: self.GAME_SP_DAN_RANK_7_DAN,
                self.DAN_RANK_8_DAN: self.GAME_SP_DAN_RANK_8_DAN,
                self.DAN_RANK_9_DAN: self.GAME_SP_DAN_RANK_9_DAN,
                self.DAN_RANK_10_DAN: self.GAME_SP_DAN_RANK_10_DAN,
                self.DAN_RANK_CHUDEN: self.GAME_SP_DAN_RANK_CHUDEN,
                self.DAN_RANK_KAIDEN: self.GAME_SP_DAN_RANK_KAIDEN,
            }[db_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
                self.DAN_RANK_7_KYU: self.GAME_DP_DAN_RANK_7_KYU,
                self.DAN_RANK_6_KYU: self.GAME_DP_DAN_RANK_6_KYU,
                self.DAN_RANK_5_KYU: self.GAME_DP_DAN_RANK_5_KYU,
                self.DAN_RANK_4_KYU: self.GAME_DP_DAN_RANK_4_KYU,
                self.DAN_RANK_3_KYU: self.GAME_DP_DAN_RANK_3_KYU,
                self.DAN_RANK_2_KYU: self.GAME_DP_DAN_RANK_2_KYU,
                self.DAN_RANK_1_KYU: self.GAME_DP_DAN_RANK_1_KYU,
                self.DAN_RANK_1_DAN: self.GAME_DP_DAN_RANK_1_DAN,
                self.DAN_RANK_2_DAN: self.GAME_DP_DAN_RANK_2_DAN,
                self.DAN_RANK_3_DAN: self.GAME_DP_DAN_RANK_3_DAN,
                self.DAN_RANK_4_DAN: self.GAME_DP_DAN_RANK_4_DAN,
                self.DAN_RANK_5_DAN: self.GAME_DP_DAN_RANK_5_DAN,
                self.DAN_RANK_6_DAN: self.GAME_DP_DAN_RANK_6_DAN,
                self.DAN_RANK_7_DAN: self.GAME_DP_DAN_RANK_7_DAN,
                self.DAN_RANK_8_DAN: self.GAME_DP_DAN_RANK_8_DAN,
                self.DAN_RANK_9_DAN: self.GAME_DP_DAN_RANK_9_DAN,
                self.DAN_RANK_10_DAN: self.GAME_DP_DAN_RANK_10_DAN,
                self.DAN_RANK_CHUDEN: self.GAME_DP_DAN_RANK_CHUDEN,
                self.DAN_RANK_KAIDEN: self.GAME_DP_DAN_RANK_KAIDEN,
            }[db_dan]
        else:
            raise Exception("Invalid cltype!")

    def game_to_db_rank(self, game_dan: int, cltype: int) -> int:
        # Special case for no DAN rank
        if game_dan == -1:
            return -1

        if cltype == self.GAME_CLTYPE_SINGLE:
            return {
                self.GAME_SP_DAN_RANK_7_KYU: self.DAN_RANK_7_KYU,
                self.GAME_SP_DAN_RANK_6_KYU: self.DAN_RANK_6_KYU,
                self.GAME_SP_DAN_RANK_5_KYU: self.DAN_RANK_5_KYU,
                self.GAME_SP_DAN_RANK_4_KYU: self.DAN_RANK_4_KYU,
                self.GAME_SP_DAN_RANK_3_KYU: self.DAN_RANK_3_KYU,
                self.GAME_SP_DAN_RANK_2_KYU: self.DAN_RANK_2_KYU,
                self.GAME_SP_DAN_RANK_1_KYU: self.DAN_RANK_1_KYU,
                self.GAME_SP_DAN_RANK_1_DAN: self.DAN_RANK_1_DAN,
                self.GAME_SP_DAN_RANK_2_DAN: self.DAN_RANK_2_DAN,
                self.GAME_SP_DAN_RANK_3_DAN: self.DAN_RANK_3_DAN,
                self.GAME_SP_DAN_RANK_4_DAN: self.DAN_RANK_4_DAN,
                self.GAME_SP_DAN_RANK_5_DAN: self.DAN_RANK_5_DAN,
                self.GAME_SP_DAN_RANK_6_DAN: self.DAN_RANK_6_DAN,
                self.GAME_SP_DAN_RANK_7_DAN: self.DAN_RANK_7_DAN,
                self.GAME_SP_DAN_RANK_8_DAN: self.DAN_RANK_8_DAN,
                self.GAME_SP_DAN_RANK_9_DAN: self.DAN_RANK_9_DAN,
                self.GAME_SP_DAN_RANK_10_DAN: self.DAN_RANK_10_DAN,
                self.GAME_SP_DAN_RANK_CHUDEN: self.DAN_RANK_CHUDEN,
                self.GAME_SP_DAN_RANK_KAIDEN: self.DAN_RANK_KAIDEN,
            }[game_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
                self.GAME_DP_DAN_RANK_7_KYU: self.DAN_RANK_7_KYU,
                self.GAME_DP_DAN_RANK_6_KYU: self.DAN_RANK_6_KYU,
                self.GAME_DP_DAN_RANK_5_KYU: self.DAN_RANK_5_KYU,
                self.GAME_DP_DAN_RANK_4_KYU: self.DAN_RANK_4_KYU,
                self.GAME_DP_DAN_RANK_3_KYU: self.DAN_RANK_3_KYU,
                self.GAME_DP_DAN_RANK_2_KYU: self.DAN_RANK_2_KYU,
                self.GAME_DP_DAN_RANK_1_KYU: self.DAN_RANK_1_KYU,
                self.GAME_DP_DAN_RANK_1_DAN: self.DAN_RANK_1_DAN,
                self.GAME_DP_DAN_RANK_2_DAN: self.DAN_RANK_2_DAN,
                self.GAME_DP_DAN_RANK_3_DAN: self.DAN_RANK_3_DAN,
                self.GAME_DP_DAN_RANK_4_DAN: self.DAN_RANK_4_DAN,
                self.GAME_DP_DAN_RANK_5_DAN: self.DAN_RANK_5_DAN,
                self.GAME_DP_DAN_RANK_6_DAN: self.DAN_RANK_6_DAN,
                self.GAME_DP_DAN_RANK_7_DAN: self.DAN_RANK_7_DAN,
                self.GAME_DP_DAN_RANK_8_DAN: self.DAN_RANK_8_DAN,
                self.GAME_DP_DAN_RANK_9_DAN: self.DAN_RANK_9_DAN,
                self.GAME_DP_DAN_RANK_10_DAN: self.DAN_RANK_10_DAN,
                self.GAME_DP_DAN_RANK_CHUDEN: self.DAN_RANK_CHUDEN,
                self.GAME_DP_DAN_RANK_KAIDEN: self.DAN_RANK_KAIDEN,
            }[game_dan]
        else:
            raise Exception("Invalid cltype!")

    def game_to_db_chart(self, db_chart: int) -> int:
        return {
            self.GAME_CHART_TYPE_B7: self.CHART_TYPE_B7,
            self.GAME_CHART_TYPE_N7: self.CHART_TYPE_N7,
            self.GAME_CHART_TYPE_H7: self.CHART_TYPE_H7,
            self.GAME_CHART_TYPE_A7: self.CHART_TYPE_A7,
            self.GAME_CHART_TYPE_N14: self.CHART_TYPE_N14,
            self.GAME_CHART_TYPE_H14: self.CHART_TYPE_H14,
            self.GAME_CHART_TYPE_A14: self.CHART_TYPE_A14,
        }[db_chart]

    def handle_IIDX26shop_getname_request(self, request: Node) -> Node:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine is not None:
            machine_name = machine.name
            close = machine.data.get_bool("close")
            hour = machine.data.get_int("hour")
            minute = machine.data.get_int("minute")
        else:
            machine_name = ""
            close = False
            hour = 0
            minute = 0

        root = Node.void("IIDX26shop")
        root.set_attribute("opname", machine_name)
        root.set_attribute("pid", str(self.get_machine_region()))
        root.set_attribute("cls_opt", "1" if close else "0")
        root.set_attribute("hr", str(hour))
        root.set_attribute("mi", str(minute))
        return root

    def handle_IIDX26shop_savename_request(self, request: Node) -> Node:
        self.update_machine_name(request.attribute("opname"))

        shop_close = intish(request.attribute("cls_opt")) or 0
        minutes = intish(request.attribute("mnt")) or 0
        hours = intish(request.attribute("hr")) or 0

        self.update_machine_data(
            {
                "close": shop_close != 0,
                "minutes": minutes,
                "hours": hours,
            }
        )

        return Node.void("IIDX26shop")

    def handle_IIDX26shop_sentinfo_request(self, request: Node) -> Node:
        return Node.void("IIDX26shop")

    def handle_IIDX26shop_sendescapepackageinfo_request(self, request: Node) -> Node:
        root = Node.void("IIDX26shop")
        root.set_attribute("expire", str((Time.now() + 86400 * 365) * 1000))
        return root

    def handle_IIDX26shop_getconvention_request(self, request: Node) -> Node:
        root = Node.void("IIDX26shop")
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            course = self.data.local.machine.get_settings(machine.arcade, self.game, self.music_version, "shop_course")
        else:
            course = None

        if course is None:
            course = ValidatedDict()

        root.set_attribute("music_0", str(course.get_int("music_0", 20032)))
        root.set_attribute("music_1", str(course.get_int("music_1", 20009)))
        root.set_attribute("music_2", str(course.get_int("music_2", 20015)))
        root.set_attribute("music_3", str(course.get_int("music_3", 20064)))
        root.add_child(Node.bool("valid", course.get_bool("valid")))
        return root

    def handle_IIDX26shop_setconvention_request(self, request: Node) -> Node:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            course = ValidatedDict()
            course.replace_int("music_0", request.child_value("music_0"))
            course.replace_int("music_1", request.child_value("music_1"))
            course.replace_int("music_2", request.child_value("music_2"))
            course.replace_int("music_3", request.child_value("music_3"))
            course.replace_bool("valid", request.child_value("valid"))
            self.data.local.machine.put_settings(machine.arcade, self.game, self.music_version, "shop_course", course)

        return Node.void("IIDX26shop")

    def handle_IIDX26ranking_getranker_request(self, request: Node) -> Node:
        # Expert mode is removed so do nothing
        return Node.void("IIDX26ranking")

    def handle_IIDX26music_crate_request(self, request: Node) -> Node:
        root = Node.void("IIDX26music")
        attempts = self.get_clear_rates()

        all_songs = list(set([song.id for song in self.data.local.music.get_all_songs(self.game, self.music_version)]))
        for song in all_songs:
            clears = []
            fcs = []

            for chart in [0, 1, 2, 3, 4, 5]:
                placed = False
                if song in attempts and chart in attempts[song]:
                    values = attempts[song][chart]
                    if values["total"] > 0:
                        clears.append(int((1000 * values["clears"]) / values["total"]))
                        fcs.append(int((1000 * values["fcs"]) / values["total"]))
                        placed = True
                if not placed:
                    clears.append(1001)
                    fcs.append(1001)

            clearnode = Node.s32_array("c", clears + fcs)
            clearnode.set_attribute("mid", str(song))
            root.add_child(clearnode)

        return root

    def handle_IIDX26music_getrank_request(self, request: Node) -> Node:
        cltype = int(request.attribute("cltype"))

        root = Node.void("IIDX26music")
        style = Node.void("style")
        root.add_child(style)
        style.set_attribute("type", str(cltype))

        for rivalid in [-1, 0, 1, 2, 3, 4]:
            if rivalid == -1:
                attr = "iidxid"
            else:
                attr = f"iidxid{rivalid}"

            try:
                extid = int(request.attribute(attr))
            except Exception:
                # Invalid extid
                continue
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
            if userid is not None:
                scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)

                # Grab score data for user/rival
                scoredata = self.make_score_struct(
                    scores,
                    self.CLEAR_TYPE_SINGLE if cltype == self.GAME_CLTYPE_SINGLE else self.CLEAR_TYPE_DOUBLE,
                    rivalid,
                )
                for s in scoredata:
                    root.add_child(Node.s16_array("m", s))

                # Grab most played for user/rival
                most_played = [
                    play[0] for play in self.data.local.music.get_most_played(self.game, self.music_version, userid, 20)
                ]
                if len(most_played) < 20:
                    most_played.extend([0] * (20 - len(most_played)))
                best = Node.u16_array("best", most_played)
                best.set_attribute("rno", str(rivalid))
                root.add_child(best)

                if rivalid == -1:
                    # Grab beginner statuses for user only
                    beginnerdata = self.make_beginner_struct(scores)
                    for b in beginnerdata:
                        root.add_child(Node.u16_array("b", b))

        return root

    def handle_IIDX26music_appoint_request(self, request: Node) -> Node:
        musicid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("clid")))
        ghost_type = int(request.attribute("ctype"))
        extid = int(request.attribute("iidxid"))
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        root = Node.void("IIDX26music")

        if userid is not None:
            # Try to look up previous ghost for user
            my_score = self.data.remote.music.get_score(self.game, self.music_version, userid, musicid, chart)
            if my_score is not None:
                mydata = Node.binary("mydata", my_score.data.get_bytes("ghost"))
                mydata.set_attribute("score", str(my_score.points))
                root.add_child(mydata)

            ghost_score = self.get_ghost(
                {
                    self.GAME_GHOST_TYPE_RIVAL: self.GHOST_TYPE_RIVAL,
                    self.GAME_GHOST_TYPE_GLOBAL_TOP: self.GHOST_TYPE_GLOBAL_TOP,
                    self.GAME_GHOST_TYPE_GLOBAL_AVERAGE: self.GHOST_TYPE_GLOBAL_AVERAGE,
                    self.GAME_GHOST_TYPE_LOCAL_TOP: self.GHOST_TYPE_LOCAL_TOP,
                    self.GAME_GHOST_TYPE_LOCAL_AVERAGE: self.GHOST_TYPE_LOCAL_AVERAGE,
                    self.GAME_GHOST_TYPE_DAN_TOP: self.GHOST_TYPE_DAN_TOP,
                    self.GAME_GHOST_TYPE_DAN_AVERAGE: self.GHOST_TYPE_DAN_AVERAGE,
                    self.GAME_GHOST_TYPE_RIVAL_TOP: self.GHOST_TYPE_RIVAL_TOP,
                    self.GAME_GHOST_TYPE_RIVAL_AVERAGE: self.GHOST_TYPE_RIVAL_AVERAGE,
                }.get(ghost_type, self.GHOST_TYPE_NONE),
                request.attribute("subtype"),
                self.GAME_GHOST_LENGTH,
                musicid,
                chart,
                userid,
            )

            # Add ghost score if we support it
            if ghost_score is not None:
                sdata = Node.binary("sdata", ghost_score["ghost"])
                sdata.set_attribute("score", str(ghost_score["score"]))
                if "name" in ghost_score:
                    sdata.set_attribute("name", ghost_score["name"])
                if "pid" in ghost_score:
                    sdata.set_attribute("pid", str(ghost_score["pid"]))
                if "extid" in ghost_score:
                    sdata.set_attribute("riidxid", str(ghost_score["extid"]))
                root.add_child(sdata)

        return root

    def handle_IIDX26music_breg_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        musicid = int(request.attribute("mid"))
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        if userid is not None:
            clear_status = self.game_to_db_status(int(request.attribute("cflg")))
            pgreats = int(request.attribute("pgnum"))
            greats = int(request.attribute("gnum"))

        self.update_score(
            userid,
            musicid,
            self.CHART_TYPE_B7,
            clear_status,
            pgreats,
            greats,
            -1,
            b"",
            None,
        )

        # Return nothing.
        return Node.void("IIDX26music")

    def handle_IIDX26music_reg_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        musicid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("clid")))
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        # See if we need to report global or shop scores
        if self.machine_joined_arcade():
            game_config = self.get_game_config()
            global_scores = game_config.get_bool("global_shop_ranking")
            machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        else:
            # If we aren't in an arcade, we can only show global scores
            global_scores = True
            machine = None

        # First, determine our current ranking before saving the new score
        all_scores = sorted(
            self.data.remote.music.get_all_scores(
                game=self.game,
                version=self.music_version,
                songid=musicid,
                songchart=chart,
            ),
            key=lambda s: (s[1].points, s[1].timestamp),
            reverse=True,
        )
        all_players = {uid: prof for (uid, prof) in self.get_any_profiles([s[0] for s in all_scores])}

        shop_id = ID.parse_machine_id(request.attribute("location_id"))
        if not global_scores:
            all_scores = [score for score in all_scores if (score[0] == userid or score[1].location == shop_id)]

        # Find our actual index
        oldindex = None
        for i in range(len(all_scores)):
            if all_scores[i][0] == userid:
                oldindex = i
                break

        if userid is not None:
            clear_status = self.game_to_db_status(int(request.attribute("cflg")))
            pgreats = int(request.attribute("pgnum"))
            greats = int(request.attribute("gnum"))
            miss_count = int(request.attribute("mnum"))
            ghost = request.child_value("ghost")
            shopid = ID.parse_machine_id(request.attribute("convid"))

            self.update_score(
                userid,
                musicid,
                chart,
                clear_status,
                pgreats,
                greats,
                miss_count,
                ghost,
                shopid,
            )

        # Calculate and return statistics about this song
        root = Node.void("IIDX26music")
        root.set_attribute("clid", request.attribute("clid"))
        root.set_attribute("mid", request.attribute("mid"))

        attempts = self.get_clear_rates(musicid, chart)
        count = attempts[musicid][chart]["total"]
        clear = attempts[musicid][chart]["clears"]
        full_combo = attempts[musicid][chart]["fcs"]

        if count > 0:
            root.set_attribute("crate", str(int((1000 * clear) / count)))
            root.set_attribute("frate", str(int((1000 * full_combo) / count)))
        else:
            root.set_attribute("crate", "0")
            root.set_attribute("frate", "0")
        root.set_attribute("rankside", "0")

        if userid is not None:
            # Shop ranking
            shopdata = Node.void("shopdata")
            root.add_child(shopdata)
            shopdata.set_attribute("rank", "-1" if oldindex is None else str(oldindex + 1))

            # Grab the rank of some other players on this song
            ranklist = Node.void("ranklist")
            root.add_child(ranklist)

            all_scores = sorted(
                self.data.remote.music.get_all_scores(
                    game=self.game,
                    version=self.music_version,
                    songid=musicid,
                    songchart=chart,
                ),
                key=lambda s: (s[1].points, s[1].timestamp),
                reverse=True,
            )
            missing_players = [uid for (uid, _) in all_scores if uid not in all_players]
            for uid, prof in self.get_any_profiles(missing_players):
                all_players[uid] = prof

            if not global_scores:
                all_scores = [score for score in all_scores if (score[0] == userid or score[1].location == shop_id)]

            # Find our actual index
            ourindex = None
            for i in range(len(all_scores)):
                if all_scores[i][0] == userid:
                    ourindex = i
                    break
            if ourindex is None:
                raise Exception("Cannot find our own score after saving to DB!")
            start = ourindex - 4
            end = ourindex + 4
            if start < 0:
                start = 0
            if end >= len(all_scores):
                end = len(all_scores) - 1
            relevant_scores = all_scores[start : (end + 1)]

            record_num = start + 1
            for score in relevant_scores:
                profile = all_players[score[0]]

                data = Node.void("data")
                ranklist.add_child(data)
                data.set_attribute("iidx_id", str(profile.extid))
                data.set_attribute("name", profile.get_str("name"))

                machine_name = ""
                machine = self.get_machine_by_id(shop_id)
                if machine is not None:
                    machine_name = machine.name
                data.set_attribute("opname", machine_name)
                data.set_attribute("rnum", str(record_num))
                data.set_attribute("score", str(score[1].points))
                data.set_attribute(
                    "clflg",
                    str(self.db_to_game_status(score[1].data.get_int("clear_status"))),
                )
                data.set_attribute("pid", str(profile.get_int("pid")))
                data.set_attribute("myFlg", "1" if score[0] == userid else "0")
                data.set_attribute("update", "0")

                data.set_attribute(
                    "sgrade",
                    str(
                        self.db_to_game_rank(
                            profile.get_int(self.DAN_RANKING_SINGLE, -1),
                            self.GAME_CLTYPE_SINGLE,
                        ),
                    ),
                )
                data.set_attribute(
                    "dgrade",
                    str(
                        self.db_to_game_rank(
                            profile.get_int(self.DAN_RANKING_DOUBLE, -1),
                            self.GAME_CLTYPE_DOUBLE,
                        ),
                    ),
                )

                qpro = profile.get_dict("qpro")
                data.set_attribute("head", str(qpro.get_int("head")))
                data.set_attribute("hair", str(qpro.get_int("hair")))
                data.set_attribute("face", str(qpro.get_int("face")))
                data.set_attribute("body", str(qpro.get_int("body")))
                data.set_attribute("hand", str(qpro.get_int("hand")))

                record_num = record_num + 1

        return root

    def handle_IIDX26music_play_request(self, request: Node) -> Node:
        musicid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("clid")))
        clear_status = self.game_to_db_status(int(request.attribute("cflg")))

        self.update_score(
            None,  # No userid since its anonymous
            musicid,
            chart,
            clear_status,
            0,  # No ex score
            0,  # No ex score
            0,  # No miss count
            None,  # No ghost
            None,  # No shop for this user
        )

        # Calculate and return statistics about this song
        root = Node.void("IIDX26music")
        root.set_attribute("clid", request.attribute("clid"))
        root.set_attribute("mid", request.attribute("mid"))

        attempts = self.get_clear_rates(musicid, chart)
        count = attempts[musicid][chart]["total"]
        clear = attempts[musicid][chart]["clears"]
        full_combo = attempts[musicid][chart]["fcs"]

        if count > 0:
            root.set_attribute("crate", str(int((1000 * clear) / count)))
            root.set_attribute("frate", str(int((1000 * full_combo) / count)))
        else:
            root.set_attribute("crate", "0")
            root.set_attribute("frate", "0")

        return root

    # Bare minimum response to say we handled the request
    def handle_IIDX26music_beginnerplay_request(self, request: Node) -> Node:
        return Node.void("IIDX26music")

    def handle_IIDX26music_arenaCPU_request(self, request: Node) -> Node:
        root = Node.void("IIDX26music")
        music_list = [0, 0, 0, 0]
        cpu_list = [0, 0, 0, 0]
        grade_to_percentage_map = {
            6: 50,
            7: 55,
            8: 60,
            9: 60,
            10: 65,
            11: 65,
            12: 70,
            13: 70,
            14: 75,
            15: 75,
            16: 80,
            17: 80,
            18: 80,
        }
        for item in request.children:
            if item.name == "music_list":
                music_list[int(item.child_value("index"))] = int(item.child_value("total_notes"))
            if item.name == "cpu_list":
                cpu_list[int(item.child_value("index"))] = int(item.child_value("grade_id"))
        for index in range(4):
            cpu_score_list = Node.void("cpu_score_list")
            cpu_score_list.add_child(Node.s32("index", index))
            root.add_child(cpu_score_list)
            for i in range(4):
                score_list = Node.void("score_list")
                cpu_score_list.add_child(score_list)
                percentage = grade_to_percentage_map.get(cpu_list[index], 0)
                notes = music_list[i]
                score = (notes * 2 * percentage) // 100
                ghost_section = score // 64
                ghost = [ghost_section] * 64
                ghost_total = ghost_section * 64
                ghost_lost = score - ghost_total
                ghost[0] = ghost[0] + ghost_lost
                score_list.add_child(Node.s32("score", score))
                score_list.add_child(Node.bool("enable_score", True))
                score_list.add_child(Node.u8_array("ghost", ghost))
                score_list.add_child(Node.bool("enable_ghost", True))
        return root

    def handle_IIDX26grade_raised_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        cltype = int(request.attribute("gtype"))
        rank = self.game_to_db_rank(int(request.attribute("gid")), cltype)

        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            percent = int(request.attribute("achi"))
            stages_cleared = int(request.attribute("cstage"))
            cleared = stages_cleared == self.DAN_STAGES

            if cltype == self.GAME_CLTYPE_SINGLE:
                index = self.DAN_RANKING_SINGLE
            else:
                index = self.DAN_RANKING_DOUBLE

            self.update_rank(
                userid,
                index,
                rank,
                percent,
                cleared,
                stages_cleared,
            )

        # Figure out number of players that played this ranking
        all_achievements = self.data.local.user.get_all_achievements(
            self.game, self.version, achievementid=rank, achievementtype=index
        )
        root = Node.void("IIDX26grade")
        root.set_attribute("pnum", str(len(all_achievements)))
        return root

    def handle_IIDX26pc_common_request(self, request: Node) -> Node:
        root = Node.void("IIDX26pc")
        root.set_attribute("expire", "600")

        ir = Node.void("ir")
        root.add_child(ir)
        ir.set_attribute("beat", "2")

        escape_package_info = Node.void("escape_package_info")
        root.add_child(escape_package_info)

        vip_black_pass = Node.void("vip_pass_black")
        root.add_child(vip_black_pass)

        newsong_another = Node.void("newsong_another")
        root.add_child(newsong_another)
        newsong_another.set_attribute("open", "1")

        deller_bonus = Node.void("deller_bonus")
        root.add_child(deller_bonus)
        deller_bonus.set_attribute("open", "1")

        common_evnet = Node.void("common_evnet")  # Yes, this is misspelled in the game
        root.add_child(common_evnet)
        common_evnet.set_attribute("flg", "0")

        # See if we configured event overrides
        if self.machine_joined_arcade():
            game_config = self.get_game_config()
            event_phase = game_config.get_int("event_phase")
            omni_events = game_config.get_bool("omnimix_events_enabled")
        else:
            # If we aren't in an arcade, we turn off events
            event_phase = 0
            omni_events = False

        if event_phase == 0 or (self.omnimix and (not omni_events)):
            boss_phase = 0
            event1 = 0
            event2 = 0
        elif event_phase in [1, 2, 3, 4]:
            boss_phase = 1
            event1 = event_phase - 1
            event2 = 0
        elif event_phase == 5:
            boss_phase = 2
            event1 = 0
            event2 = 2

        boss = Node.void("boss")
        root.add_child(boss)
        boss.set_attribute("phase", str(boss_phase))

        event1_phase = Node.void("event1_phase")
        root.add_child(event1_phase)
        event1_phase.set_attribute("phase", str(event1))

        event2_phase = Node.void("event2_phase")
        root.add_child(event2_phase)
        event2_phase.set_attribute("phase", str(event2))

        extra_boss_event = Node.void("extra_boss_event")
        root.add_child(extra_boss_event)
        extra_boss_event.set_attribute("phase", "2")

        return root

    def handle_IIDX26pc_delete_request(self, request: Node) -> Node:
        return Node.void("IIDX26pc")

    def handle_IIDX26pc_playstart_request(self, request: Node) -> Node:
        return Node.void("IIDX26pc")

    def handle_IIDX26pc_playend_request(self, request: Node) -> Node:
        return Node.void("IIDX26pc")

    def handle_IIDX26pc_visit_request(self, request: Node) -> Node:
        root = Node.void("IIDX26pc")
        root.set_attribute("anum", "0")
        root.set_attribute("snum", "0")
        root.set_attribute("pnum", "0")
        root.set_attribute("aflg", "0")
        root.set_attribute("sflg", "0")
        root.set_attribute("pflg", "0")
        return root

    def handle_IIDX26pc_shopregister_request(self, request: Node) -> Node:  # Not used anymore????
        root = Node.void("IIDX26pc")
        return root

    def handle_IIDX26pc_oldget_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            oldversion = self.previous_version()
            profile = oldversion.get_profile(userid)
        else:
            profile = None

        root = Node.void("IIDX26pc")
        root.set_attribute("status", "1" if profile is None else "0")
        return root

    def handle_IIDX26pc_getname_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            oldversion = self.previous_version()
            profile = oldversion.get_profile(userid)
        else:
            profile = None
        if profile is None:
            raise Exception(
                "Should not get here if we have no profile, we should "
                + "have returned '1' in the 'oldget' method above "
                + "which should tell the game not to present a migration."
            )

        root = Node.void("IIDX26pc")
        root.set_attribute("name", profile.get_str("name"))
        root.set_attribute("idstr", ID.format_extid(profile.extid))
        root.set_attribute("pid", str(profile.get_int("pid")))
        return root

    def handle_IIDX26pc_takeover_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        name = request.attribute("name")
        pid = int(request.attribute("pid"))
        newprofile = self.new_profile_by_refid(refid, name, pid)

        root = Node.void("IIDX26pc")
        if newprofile is not None:
            root.set_attribute("id", str(newprofile.extid))
        return root

    def handle_IIDX26pc_reg_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        name = request.attribute("name")
        pid = int(request.attribute("pid"))
        profile = self.new_profile_by_refid(refid, name, pid)

        root = Node.void("IIDX26pc")
        if profile is not None:
            root.set_attribute("id", str(profile.extid))
            root.set_attribute("id_str", ID.format_extid(profile.extid))
        return root

    def handle_IIDX26pc_get_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("IIDX26pc")
        return root

    def handle_IIDX26pc_save_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        self.put_profile_by_extid(extid, request)

        return Node.void("IIDX26pc")

    def handle_IIDX26pc_logout_request(self, request: Node) -> Node:
        return Node.void("IIDX26pc")

    def handle_IIDX26pc_eaappliresult_request(self, request: Node) -> Node:
        clear_map = {
            self.GAME_CLEAR_STATUS_NO_PLAY: "NO PLAY",
            self.GAME_CLEAR_STATUS_FAILED: "FAILED",
            self.GAME_CLEAR_STATUS_ASSIST_CLEAR: "ASSIST CLEAR",
            self.GAME_CLEAR_STATUS_EASY_CLEAR: "EASY CLEAR",
            self.GAME_CLEAR_STATUS_CLEAR: "CLEAR",
            self.GAME_CLEAR_STATUS_HARD_CLEAR: "HARD CLEAR",
            self.GAME_CLEAR_STATUS_EX_HARD_CLEAR: "EX HARD CLEAR",
            self.GAME_CLEAR_STATUS_FULL_COMBO: "FULL COMBO",
        }
        # first we'll grab the data from the packet
        # did = request.child_value('did')
        # rid = request.child_value('rid')
        name = request.child_value("name")
        # qpro_hair = request.child_value('qpro_hair')
        # qpro_head = request.child_value('qpro_head')
        # qpro_body = request.child_value('qpro_body')
        # qpro_hand = request.child_value('qpro_hand')
        music_id = request.child_value("music_id")
        class_id = request.child_value("class_id")
        # no_save = request.child_value('no_save')
        # is_couple = request.child_value('is_couple')
        # target_graph = request.child_value('target_graph')
        target_exscore = request.child_value("target_exscore")
        # pacemaker = request.child_value('pacemaker')
        best_clear = request.child_value("best_clear")
        # best_djlevel = request.child_value('best_djlevel')
        # best_exscore = request.child_value('best_exscore')
        # best_misscount = request.child_value('best_misscount')
        now_clear = request.child_value("now_clear")
        # now_djlevel = request.child_value('now_djlevel')
        now_exscore = request.child_value("now_exscore")
        # now_misscount = request.child_value('now_misscount')
        now_pgreat = request.child_value("now_pgreat")
        now_great = request.child_value("now_great")
        now_good = request.child_value("now_good")
        now_bad = request.child_value("now_bad")
        now_poor = request.child_value("now_poor")
        now_combo = request.child_value("now_combo")
        now_fast = request.child_value("now_fast")
        now_slow = request.child_value("now_slow")
        best_clear_string = clear_map.get(best_clear, "NO PLAY")
        now_clear_string = clear_map.get(now_clear, "NO PLAY")
        # let's get the song info first
        song = self.data.local.music.get_song(self.game, self.music_version, music_id, self.game_to_db_chart(class_id))
        notecount = song.data.get("notecount", 0)
        # Construct the dictionary for the broadcast
        card_data = {
            BroadcastConstants.DJ_NAME: name,
            BroadcastConstants.SONG_NAME: song.name,
            BroadcastConstants.ARTIST_NAME: song.artist,
            BroadcastConstants.DIFFICULTY: song.data.get("difficulty", 0),
            BroadcastConstants.TARGET_EXSCORE: target_exscore,
            BroadcastConstants.EXSCORE: now_exscore,
            BroadcastConstants.BEST_CLEAR_STATUS: best_clear_string,
            BroadcastConstants.CLEAR_STATUS: now_clear_string,
            BroadcastConstants.PLAY_STATS_HEADER: "How did you do?",
            BroadcastConstants.PERFECT_GREATS: now_pgreat,
            BroadcastConstants.GREATS: now_great,
            BroadcastConstants.GOODS: now_good,
            BroadcastConstants.BADS: now_bad,
            BroadcastConstants.POORS: now_poor,
            BroadcastConstants.COMBO_BREAKS: now_combo,
            BroadcastConstants.SLOWS: now_slow,
            BroadcastConstants.FASTS: now_fast,
        }
        if notecount != 0:
            max_score = notecount * 2
            percent = now_exscore / max_score
            grade = int(9 * percent)
            grades = ["F", "F", "E", "D", "C", "B", "A", "AA", "AAA", "MAX"]
            card_data[BroadcastConstants.GRADE] = grades[grade]
            card_data[BroadcastConstants.RATE] = str(round(percent, 2))

        # Try to broadcast out the score to our webhook(s)
        self.data.triggers.broadcast_score(card_data, self.game, song)

        return Node.void("IIDX26pc")

    def handle_IIDX26gameSystem_systemInfo_request(self, request: Node) -> Node:
        root = Node.void("IIDX26gameSystem")
        arena_schedule = Node.void("arena_schedule")
        root.add_child(arena_schedule)
        arena_schedule.add_child(Node.u8("phase", 1))
        arena_schedule.add_child(Node.u32("start", 0))
        arena_schedule.add_child(Node.u32("end", 0))
        cpu_grades = [
            6,
            7,
            8,
            9,
            10,
            10,
            11,
            11,
            12,
            12,
            13,
            13,
            14,
            14,
            15,
            15,
            16,
            16,
            17,
            18,
        ]
        cpu_low_diff = [
            4,
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            9,
            10,
            10,
            10,
            11,
            11,
            11,
            11,
            12,
            12,
        ]
        cpu_high_diff = [
            5,
            6,
            6,
            7,
            7,
            8,
            8,
            9,
            9,
            10,
            10,
            10,
            11,
            11,
            11,
            12,
            12,
            12,
            12,
            12,
        ]
        for playstyle in range(2):
            for arena_class in range(20):
                arena_music_difficult = Node.void("arena_music_difficult")
                root.add_child(arena_music_difficult)
                arena_music_difficult.add_child(Node.s32("play_style", playstyle))
                arena_music_difficult.add_child(Node.s32("arena_class", arena_class))
                arena_music_difficult.add_child(Node.s32("low_difficult", 1))
                arena_music_difficult.add_child(Node.s32("high_difficult", 12))
                arena_music_difficult.add_child(Node.bool("is_leggendaria", True))
                arena_music_difficult.add_child(Node.s32("force_music_list_id", 0))
                arena_cpu_define = Node.void("arena_cpu_define")
                root.add_child(arena_cpu_define)
                arena_cpu_define.add_child(Node.s32("play_style", playstyle))
                arena_cpu_define.add_child(Node.s32("arena_class", arena_class))
                arena_cpu_define.add_child(Node.s32("grade_id", cpu_grades[arena_class]))
                arena_cpu_define.add_child(Node.s32("low_music_difficult", cpu_low_diff[arena_class]))
                arena_cpu_define.add_child(Node.s32("high_music_difficult", cpu_high_diff[arena_class]))
                arena_cpu_define.add_child(Node.bool("is_leggendaria", arena_class >= 13))
            for matching_class in range(21):
                matching_class_range = Node.void("matching_class_range")
                root.add_child(matching_class_range)
                matching_class_range.add_child(Node.s32("play_style", playstyle))
                matching_class_range.add_child(Node.s32("matching_class", matching_class))
                matching_class_range.add_child(Node.s32("low_arena_class", 1))
                matching_class_range.add_child(Node.s32("high_arena_class", 20))
        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("IIDX26pc")

        # Look up play stats we bridge to every mix
        play_stats = self.get_play_statistics(userid)

        # Look up judge window adjustments
        judge_dict = profile.get_dict("machine_judge_adjust")
        machine_judge = judge_dict.get_dict(self.config.machine.pcbid)

        # Profile data
        pcdata = Node.void("pcdata")
        root.add_child(pcdata)
        pcdata.set_attribute("id", str(profile.extid))
        pcdata.set_attribute("idstr", ID.format_extid(profile.extid))
        pcdata.set_attribute("name", profile.get_str("name"))
        pcdata.set_attribute("pid", str(profile.get_int("pid")))
        pcdata.set_attribute("spnum", str(play_stats.get_int("single_plays")))
        pcdata.set_attribute("dpnum", str(play_stats.get_int("double_plays")))
        pcdata.set_attribute("sach", str(play_stats.get_int("single_dj_points")))
        pcdata.set_attribute("dach", str(play_stats.get_int("double_dj_points")))
        pcdata.set_attribute("mode", str(profile.get_int("mode")))
        pcdata.set_attribute("pmode", str(profile.get_int("pmode")))
        pcdata.set_attribute("rtype", str(profile.get_int("rtype")))
        pcdata.set_attribute("sp_opt", str(profile.get_int("sp_opt")))
        pcdata.set_attribute("dp_opt", str(profile.get_int("dp_opt")))
        pcdata.set_attribute("dp_opt2", str(profile.get_int("dp_opt2")))
        pcdata.set_attribute("gpos", str(profile.get_int("gpos")))
        pcdata.set_attribute("s_sorttype", str(profile.get_int("s_sorttype")))
        pcdata.set_attribute("d_sorttype", str(profile.get_int("d_sorttype")))
        pcdata.set_attribute("s_pace", str(profile.get_int("s_pace")))
        pcdata.set_attribute("d_pace", str(profile.get_int("d_pace")))
        pcdata.set_attribute("s_gno", str(profile.get_int("s_gno")))
        pcdata.set_attribute("d_gno", str(profile.get_int("d_gno")))
        pcdata.set_attribute("s_gtype", str(profile.get_int("s_gtype")))
        pcdata.set_attribute("d_gtype", str(profile.get_int("d_gtype")))
        pcdata.set_attribute("s_sdlen", str(profile.get_int("s_sdlen")))
        pcdata.set_attribute("d_sdlen", str(profile.get_int("d_sdlen")))
        pcdata.set_attribute("s_sdtype", str(profile.get_int("s_sdtype")))
        pcdata.set_attribute("d_sdtype", str(profile.get_int("d_sdtype")))
        pcdata.set_attribute("s_timing", str(profile.get_int("s_timing")))
        pcdata.set_attribute("d_timing", str(profile.get_int("d_timing")))
        pcdata.set_attribute("s_notes", str(profile.get_float("s_notes")))
        pcdata.set_attribute("d_notes", str(profile.get_float("d_notes")))
        pcdata.set_attribute("s_judge", str(profile.get_int("s_judge")))
        pcdata.set_attribute("d_judge", str(profile.get_int("d_judge")))
        pcdata.set_attribute("s_judgeAdj", str(machine_judge.get_int("single")))
        pcdata.set_attribute("d_judgeAdj", str(machine_judge.get_int("double")))
        pcdata.set_attribute("s_hispeed", str(profile.get_float("s_hispeed")))
        pcdata.set_attribute("d_hispeed", str(profile.get_float("d_hispeed")))
        pcdata.set_attribute("s_liflen", str(profile.get_int("s_lift")))
        pcdata.set_attribute("d_liflen", str(profile.get_int("d_lift")))
        pcdata.set_attribute("s_disp_judge", str(profile.get_int("s_disp_judge")))
        pcdata.set_attribute("d_disp_judge", str(profile.get_int("d_disp_judge")))
        pcdata.set_attribute("s_opstyle", str(profile.get_int("s_opstyle")))
        pcdata.set_attribute("d_opstyle", str(profile.get_int("d_opstyle")))
        pcdata.set_attribute("s_graph_score", str(profile.get_int("s_graph_score")))
        pcdata.set_attribute("d_graph_score", str(profile.get_int("d_graph_score")))
        pcdata.set_attribute("s_auto_scrach", str(profile.get_int("s_auto_scrach")))
        pcdata.set_attribute("d_auto_scrach", str(profile.get_int("d_auto_scrach")))
        pcdata.set_attribute("s_gauge_disp", str(profile.get_int("s_gauge_disp")))
        pcdata.set_attribute("d_gauge_disp", str(profile.get_int("d_gauge_disp")))
        pcdata.set_attribute("s_lane_brignt", str(profile.get_int("s_lane_brignt")))
        pcdata.set_attribute("d_lane_brignt", str(profile.get_int("d_lane_brignt")))
        pcdata.set_attribute("s_camera_layout", str(profile.get_int("s_camera_layout")))
        pcdata.set_attribute("d_camera_layout", str(profile.get_int("d_camera_layout")))
        pcdata.set_attribute("s_ghost_score", str(profile.get_int("s_ghost_score")))
        pcdata.set_attribute("d_ghost_score", str(profile.get_int("d_ghost_score")))
        pcdata.set_attribute("s_tsujigiri_disp", str(profile.get_int("s_tsujigiri_disp")))
        pcdata.set_attribute("d_tsujigiri_disp", str(profile.get_int("d_tsujigiri_disp")))

        # KAC stuff
        # kac_entry_info = Node.void('kac_entry_info')
        # root.add_child(kac_entry_info)
        # kac_entry_info.add_child(Node.void('enable_kac_deller'))
        # kac_entry_info.add_child(Node.void('disp_kac_mark'))
        # kac_entry_info.add_child(Node.void('is_kac_evnet_entry'))
        # kac_secret_music = Node.void('kac_secret_music')
        # kac_entry_info.add_child(kac_secret_music)

        legendarias = Node.void("leggendaria_open")
        root.add_child(legendarias)

        premium_unlocks = Node.void("ea_premium_course")
        root.add_child(premium_unlocks)

        # Song unlock flags
        secret_dict = profile.get_dict("secret")
        secret = Node.void("secret")
        root.add_child(secret)

        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            secret.add_child(Node.s64_array("flg1", [-1, -1, -1]))
            secret.add_child(Node.s64_array("flg2", [-1, -1, -1]))
            secret.add_child(Node.s64_array("flg3", [-1, -1, -1]))
        else:
            secret.add_child(Node.s64_array("flg1", secret_dict.get_int_array("flg1", 3)))
            secret.add_child(Node.s64_array("flg2", secret_dict.get_int_array("flg2", 3)))
            secret.add_child(Node.s64_array("flg3", secret_dict.get_int_array("flg3", 3)))

        # Favorites
        for folder in ["favorite1", "favorite2", "favorite3"]:
            favorite_dict = profile.get_dict(folder)
            sp_mlist = b""
            sp_clist = b""
            singles_list = favorite_dict["single"] if "single" in favorite_dict else []
            for single in singles_list:
                sp_mlist = sp_mlist + struct.pack("<L", single["id"])
                sp_clist = sp_clist + struct.pack("B", single["chart"])
            while len(sp_mlist) < (4 * self.FAVORITE_LIST_LENGTH):
                sp_mlist = sp_mlist + b"\x00\x00\x00\x00"
            while len(sp_clist) < self.FAVORITE_LIST_LENGTH:
                sp_clist = sp_clist + b"\x00"

            dp_mlist = b""
            dp_clist = b""
            doubles_list = favorite_dict["double"] if "double" in favorite_dict else []
            for double in doubles_list:
                dp_mlist = dp_mlist + struct.pack("<L", double["id"])
                dp_clist = dp_clist + struct.pack("B", double["chart"])
            while len(dp_mlist) < (4 * self.FAVORITE_LIST_LENGTH):
                dp_mlist = dp_mlist + b"\x00\x00\x00\x00"
            while len(dp_clist) < self.FAVORITE_LIST_LENGTH:
                dp_clist = dp_clist + b"\x00"

            if folder == "favorite1":
                favorite = Node.void("favorite")
            elif folder == "favorite2":
                favorite = Node.void("extra_favorite")
                favorite.set_attribute("folder_id", "0")
            elif folder == "favorite3":
                favorite = Node.void("extra_favorite")
                favorite.set_attribute("folder_id", "1")
            root.add_child(favorite)
            favorite.add_child(Node.binary("sp_mlist", sp_mlist))
            favorite.add_child(Node.binary("sp_clist", sp_clist))
            favorite.add_child(Node.binary("dp_mlist", dp_mlist))
            favorite.add_child(Node.binary("dp_clist", dp_clist))

        # Playlist stuff, not currently saved
        # playlist = Node.void('playlist')
        # root.add_child(playlist)

        # Qpro secret data from step-up mode
        qpro_secrete_dict = profile.get_dict("qpro_secret")
        qpro_secret = Node.void("qpro_secret")
        root.add_child(qpro_secret)
        qpro_secret.add_child(Node.s64_array("head", qpro_secrete_dict.get_int_array("head", 5)))
        qpro_secret.add_child(Node.s64_array("hair", qpro_secrete_dict.get_int_array("hair", 5)))
        qpro_secret.add_child(Node.s64_array("face", qpro_secrete_dict.get_int_array("face", 5)))
        qpro_secret.add_child(Node.s64_array("body", qpro_secrete_dict.get_int_array("body", 5)))
        qpro_secret.add_child(Node.s64_array("hand", qpro_secrete_dict.get_int_array("hand", 5)))

        # DAN rankings
        grade = Node.void("grade")
        root.add_child(grade)
        grade.set_attribute(
            "sgid",
            str(
                self.db_to_game_rank(
                    profile.get_int(self.DAN_RANKING_SINGLE, -1),
                    self.GAME_CLTYPE_SINGLE,
                )
            ),
        )
        grade.set_attribute(
            "dgid",
            str(
                self.db_to_game_rank(
                    profile.get_int(self.DAN_RANKING_DOUBLE, -1),
                    self.GAME_CLTYPE_DOUBLE,
                )
            ),
        )
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        for rank in achievements:
            if rank.type == self.DAN_RANKING_SINGLE:
                grade.add_child(
                    Node.u8_array(
                        "g",
                        [
                            self.GAME_CLTYPE_SINGLE,
                            self.db_to_game_rank(rank.id, self.GAME_CLTYPE_SINGLE),
                            rank.data.get_int("stages_cleared"),
                            rank.data.get_int("percent"),
                        ],
                    )
                )
            if rank.type == self.DAN_RANKING_DOUBLE:
                grade.add_child(
                    Node.u8_array(
                        "g",
                        [
                            self.GAME_CLTYPE_DOUBLE,
                            self.db_to_game_rank(rank.id, self.GAME_CLTYPE_DOUBLE),
                            rank.data.get_int("stages_cleared"),
                            rank.data.get_int("percent"),
                        ],
                    )
                )

        # User settings
        settings_dict = profile.get_dict("settings")
        skin = Node.s16_array(
            "skin",
            [
                settings_dict.get_int("frame"),
                settings_dict.get_int("turntable"),
                settings_dict.get_int("burst"),
                settings_dict.get_int("bgm"),
                settings_dict.get_int("flags"),
                settings_dict.get_int("towel"),
                settings_dict.get_int("judge_pos"),
                settings_dict.get_int("voice"),
                settings_dict.get_int("noteskin"),
                settings_dict.get_int("full_combo"),
                settings_dict.get_int("beam"),
                settings_dict.get_int("judge"),
                0,
                settings_dict.get_int("disable_song_preview"),
                settings_dict.get_int("pacemaker"),
                settings_dict.get_int("effector_lock"),
                settings_dict.get_int("effector_preset"),
                settings_dict.get_int("explosion_size"),
                settings_dict.get_int("disable_hcn_color"),
                settings_dict.get_int("note_preview"),
            ],
        )
        root.add_child(skin)

        skin_customize_flg = Node.void("skin_customize_flg")
        root.add_child(skin_customize_flg)
        skin_customize_flg.set_attribute("skin_bgm_flg", "1")
        skin_customize_flg.set_attribute("skin_frame_flg", "1")

        # Qpro data
        qpro_dict = profile.get_dict("qpro")
        root.add_child(
            Node.u32_array(
                "qprodata",
                [
                    qpro_dict.get_int("head"),
                    qpro_dict.get_int("hair"),
                    qpro_dict.get_int("face"),
                    qpro_dict.get_int("hand"),
                    qpro_dict.get_int("body"),
                ],
            )
        )

        # Rivals
        rlist = Node.void("rlist")
        root.add_child(rlist)
        links = self.data.local.user.get_links(self.game, self.version, userid)
        for link in links:
            rival_type = None
            if link.type == "sp_rival":
                rival_type = "1"
            elif link.type == "dp_rival":
                rival_type = "2"
            else:
                # No business with this link type
                continue

            other_profile = self.get_profile(link.other_userid)
            if other_profile is None:
                continue
            other_play_stats = self.get_play_statistics(link.other_userid)

            rival = Node.void("rival")
            rlist.add_child(rival)
            rival.set_attribute("spdp", rival_type)
            rival.set_attribute("id", str(other_profile.extid))
            rival.set_attribute("id_str", ID.format_extid(other_profile.extid))
            rival.set_attribute("djname", other_profile.get_str("name"))
            rival.set_attribute("pid", str(other_profile.get_int("pid")))
            rival.set_attribute(
                "sg",
                str(
                    self.db_to_game_rank(
                        other_profile.get_int(self.DAN_RANKING_SINGLE, -1),
                        self.GAME_CLTYPE_SINGLE,
                    )
                ),
            )
            rival.set_attribute(
                "dg",
                str(
                    self.db_to_game_rank(
                        other_profile.get_int(self.DAN_RANKING_DOUBLE, -1),
                        self.GAME_CLTYPE_DOUBLE,
                    )
                ),
            )
            rival.set_attribute("sa", str(other_play_stats.get_int("single_dj_points")))
            rival.set_attribute("da", str(other_play_stats.get_int("double_dj_points")))

            rival.add_child(Node.bool("is_robo", False))

            qprodata = Node.void("qprodata")
            rival.add_child(qprodata)
            qpro = other_profile.get_dict("qpro")
            qprodata.set_attribute("head", str(qpro.get_int("head")))
            qprodata.set_attribute("hair", str(qpro.get_int("hair")))
            qprodata.set_attribute("face", str(qpro.get_int("face")))
            qprodata.set_attribute("body", str(qpro.get_int("body")))
            qprodata.set_attribute("hand", str(qpro.get_int("hand")))

            challenge = Node.void("challenge")
            rival.add_child(challenge)

        # DJ RANK
        for dj_rank in achievements:
            if dj_rank.type != "dj_rank":
                continue

            dj_rank_node = Node.void("dj_rank")
            root.add_child(dj_rank_node)
            dj_rank_node.set_attribute("style", str(dj_rank.id))
            dj_rank_node.add_child(Node.s32_array("rank", dj_rank.data.get_int_array("rank", 15)))
            dj_rank_node.add_child(Node.s32_array("point", dj_rank.data.get_int_array("point", 15)))

        dj_rank_ranking_node = Node.void("dj_rank_ranking")
        root.add_child(dj_rank_ranking_node)
        dj_rank_ranking_node.set_attribute("style", "0")
        for j in range(15):
            detail = Node.void("detail")
            dj_rank_ranking_node.add_child(detail)
            detail.set_attribute("category", str(j))
            detail.set_attribute("total_user", "0")
            detail.set_attribute("rank", "0")
            detail.set_attribute("platinum_point", "0")
            detail.set_attribute("platinum_rank", "0")
            detail.set_attribute("gold_point", "0")
            detail.set_attribute("gold_rank", "0")
            detail.set_attribute("silver_point", "0")
            detail.set_attribute("silver_rank", "0")
            detail.set_attribute("bronze_point", "0")
            detail.set_attribute("bronze_rank", "0")
            detail.set_attribute("white_point", "0")
            detail.set_attribute("white_rank", "0")

        dj_rank_ranking_node = Node.void("dj_rank_ranking")
        root.add_child(dj_rank_ranking_node)
        dj_rank_ranking_node.set_attribute("style", "1")
        for j in range(15):
            detail = Node.void("detail")
            dj_rank_ranking_node.add_child(detail)
            detail.set_attribute("category", str(j))
            detail.set_attribute("total_user", "0")
            detail.set_attribute("rank", "0")
            detail.set_attribute("platinum_point", "0")
            detail.set_attribute("platinum_rank", "0")
            detail.set_attribute("gold_point", "0")
            detail.set_attribute("gold_rank", "0")
            detail.set_attribute("silver_point", "0")
            detail.set_attribute("silver_rank", "0")
            detail.set_attribute("bronze_point", "0")
            detail.set_attribute("bronze_rank", "0")
            detail.set_attribute("white_point", "0")
            detail.set_attribute("white_rank", "0")

        # 蜃気楼の図書館(Biblioteca of Mirage) event
        event1_dict = profile.get_dict("event1")
        event1 = Node.void("event1")
        root.add_child(event1)
        event1.set_attribute("event_play_num", str(event1_dict.get_int("event_play_num")))
        event1.set_attribute("fragment_num", str(event1_dict.get_int("fragment_num")))
        event1.set_attribute("last_select_map_id", str(event1_dict.get_int("last_select_map")))
        event1.set_attribute("read_tips_list", str(event1_dict.get_int("read_tips_list")))
        event1.set_attribute("continuous_correct", str(event1_dict.get_int("continuous_correct")))
        event1.set_attribute("bookshelf_release_num", str(event1_dict.get_int("bookshelf_release_num")))
        event1.add_child(Node.binary("quiz_control_list", event1_dict.get_bytes("quiz_control_list")))
        for map_data in achievements:
            if map_data.type != "map_data":
                continue

            map_data_node = Node.void("map_data")
            event1.add_child(map_data_node)
            map_data_node.set_attribute("map_id", str(map_data.id))
            map_data_node.set_attribute("play_num", str(map_data.data.get_int("play_num")))
            map_data_node.set_attribute(
                "last_select_route_id",
                str(map_data.data.get_int("last_select_route_id")),
            )
            map_data_node.set_attribute(
                "bookshelf_release_num",
                str(map_data.data.get_int("bookshelf_release_num")),
            )
            map_data_node.add_child(Node.bool("is_clear", map_data.data.get_bool("is_clear")))
            map_data_node.add_child(Node.binary("map_route_damage", map_data.data.get_bytes("map_route_damage")))

        # DELABITY LABORATORY event
        event2_dict = profile.get_dict("event2")
        event2 = Node.void("event2")
        root.add_child(event2)
        event2.set_attribute("play_num", str(event2_dict.get_int("play_num")))
        event2.set_attribute("delabity", str(event2_dict.get_int("delabity")))
        event2.set_attribute("floor_0_last_area", str(event2_dict.get_int("floor_0_last_area")))
        event2.set_attribute("floor_1_last_area", str(event2_dict.get_int("floor_1_last_area")))
        event2.set_attribute("floor_2_last_area", str(event2_dict.get_int("floor_2_last_area")))
        event2.set_attribute("floor_3_last_area", str(event2_dict.get_int("floor_3_last_area")))
        event2.set_attribute("floor_4_last_area", str(event2_dict.get_int("floor_4_last_area")))
        event2.set_attribute("floor_clear_flg_list", str(event2_dict.get_int("floor_clear_flg_list")))
        event2.set_attribute("last_select_floor", str(event2_dict.get_int("last_select_floor")))
        event2.set_attribute("tips_list", str(event2_dict.get_int("tips_list")))

        areas = self.data.local.user.get_achievements(self.game, self.version, userid)
        for area in areas:
            if "area_data_floor_" not in area.type:
                continue
            area_data = Node.void("area_data")
            event2.add_child(area_data)
            area_data.set_attribute("area_id", str(area.id))
            area_data.set_attribute("floor_id", str(area.data.get_int("floor_id")))
            area_data.set_attribute("last_select_note", str(area.data.get_int("last_select_note")))
            area_data.set_attribute("normal_play_num", str(area.data.get_int("normal_play_num")))
            area_data.set_attribute("hyper_play_num", str(area.data.get_int("hyper_play_num")))
            area_data.set_attribute("another_play_num", str(area.data.get_int("another_play_num")))
            area_data.set_attribute("area_clear_flg_list", str(area.data.get_int("area_clear_flg_list")))
            area_data.set_attribute("normal_grade_point", str(area.data.get_int("normal_grade_point")))
            area_data.set_attribute("hyper_grade_point", str(area.data.get_int("hyper_grade_point")))
            area_data.set_attribute("another_grade_point", str(area.data.get_int("another_grade_point")))

        tonyutsu = Node.void("tonyutsu")
        tonyutsu_dict = profile.get_dict("tonyutsu")
        tonyutsu.set_attribute("platinum_pass", str(tonyutsu_dict.get_int("platiunum_pass")))
        tonyutsu.set_attribute("black_pass", str(tonyutsu_dict.get_int("black_pass")))

        extra_boss_event_dict = profile.get_dict("extra_boss_event")
        extra_boss_event = Node.void("extra_boss_event")
        root.add_child(extra_boss_event)
        for i in range(9):
            extra_boss_event.set_attribute(f"orb_{i}", str(extra_boss_event_dict.get_int(f"orb_{i}")))

        # Step up mode
        step_dict = profile.get_dict("step")
        step = Node.void("step")
        root.add_child(step)
        step.set_attribute("enemy_damage", str(step_dict.get_int("enemy_damage")))
        step.set_attribute("progress", str(step_dict.get_int("progress")))
        step.add_child(Node.bool("is_track_ticket", step_dict.get_bool("is_track_ticket")))
        step.set_attribute("sp_level", str(step_dict.get_int("sp_level")))
        step.set_attribute("dp_level", str(step_dict.get_int("dp_level")))
        step.set_attribute("sp_mission_point", str(step_dict.get_int("sp_mission_point")))
        step.set_attribute("dp_mission_point", str(step_dict.get_int("dp_mission_point")))
        step.set_attribute("sp_dj_mission_level", str(step_dict.get_int("sp_dj_mission_level@")))
        step.set_attribute("dp_dj_mission_level", str(step_dict.get_int("dp_dj_mission_level@")))
        step.set_attribute("sp_clear_mission_level", str(step_dict.get_int("sp_clear_mission_level")))
        step.set_attribute("dp_clear_mission_level", str(step_dict.get_int("dp_clear_mission_level")))
        step.set_attribute("sp_dj_mission_clear", str(step_dict.get_int("sp_dj_mission_clear")))
        step.set_attribute("dp_dj_mission_clear", str(step_dict.get_int("dp_dj_mission_clear")))
        step.set_attribute("sp_clear_mission_clear", str(step_dict.get_int("sp_clear_mission_clear")))
        step.set_attribute("dp_clear_mission_clear", str(step_dict.get_int("dp_clear_mission_clear")))
        step.set_attribute("sp_mplay", str(step_dict.get_int("sp_mplay")))
        step.set_attribute("dp_mplay", str(step_dict.get_int("dp_mplay")))
        step.set_attribute("tips_read_list", str(step_dict.get_int("tips_read_list")))

        # Daily recommendations
        entry = self.data.local.game.get_time_sensitive_settings(self.game, self.version, "dailies")
        if entry is not None:
            packinfo = Node.void("packinfo")
            root.add_child(packinfo)

            pack_id = int(entry["start_time"] / 86400)
            packinfo.set_attribute("pack_id", str(pack_id))
            packinfo.set_attribute("music_0", str(entry["music"][0]))
            packinfo.set_attribute("music_1", str(entry["music"][1]))
            packinfo.set_attribute("music_2", str(entry["music"][2]))
        else:
            # No dailies :(
            pack_id = None

        # Tran medals and shit
        achievement_node = Node.void("achievements")
        root.add_child(achievement_node)

        # Dailies
        if pack_id is None:
            achievement_node.set_attribute("pack", "0")
            achievement_node.set_attribute("pack_comp", "0")
        else:
            daily_played = self.data.local.user.get_achievement(self.game, self.version, userid, pack_id, "daily")
            if daily_played is None:
                daily_played = ValidatedDict()
            achievement_node.set_attribute("pack", str(daily_played.get_int("pack_flg")))
            achievement_node.set_attribute("pack_comp", str(daily_played.get_int("pack_comp")))

        # Weeklies
        achievement_node.set_attribute("last_weekly", str(profile.get_int("last_weekly")))
        achievement_node.set_attribute("weekly_num", str(profile.get_int("weekly_num")))

        # Prefecture visit flag
        achievement_node.set_attribute("visit_flg", str(profile.get_int("visit_flg")))

        # Number of rivals beaten
        achievement_node.set_attribute("rival_crush", str(profile.get_int("rival_crush")))

        # Tran medals
        achievement_node.add_child(Node.s64_array("trophy", profile.get_int_array("trophy", 20)))

        # Track deller
        deller = Node.void("deller")
        root.add_child(deller)
        deller.set_attribute("deller", str(profile.get_int("deller")))
        deller.set_attribute("rate", "0")

        # Orb data
        orb_data = Node.void("orb_data")
        root.add_child(orb_data)
        orb_data.set_attribute("rest_orb", str(profile.get_int("orbs")))
        orb_data.set_attribute("present_orb", str(profile.get_int("present_orb")))

        # Expert points
        expert_point = Node.void("expert_point")
        root.add_child(expert_point)
        for rank in achievements:
            if rank.type == "expert_point":
                detail = Node.void("detail")
                expert_point.add_child(detail)
                detail.set_attribute("course_id", str(rank.id))
                detail.set_attribute("n_point", str(rank.data.get_int("normal_points")))
                detail.set_attribute("h_point", str(rank.data.get_int("hyper_points")))
                detail.set_attribute("a_point", str(rank.data.get_int("another_points")))

        nostalgia = Node.void("nostalgia_open")
        root.add_child(nostalgia)

        # Ea app features
        if self.data.triggers.has_broadcast_destination(self.game):
            root.add_child(Node.void("bind_eaappli"))
            pay_per_use = Node.void("pay_per_use")
            root.add_child(pay_per_use)
            pay_per_use.set_attribute("item_num", "99")

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()
        play_stats = self.get_play_statistics(userid)

        # Track play counts
        cltype = int(request.attribute("cltype"))
        if cltype == self.GAME_CLTYPE_SINGLE:
            play_stats.increment_int("single_plays")
        if cltype == self.GAME_CLTYPE_DOUBLE:
            play_stats.increment_int("double_plays")

        # Track DJ points
        play_stats.replace_int("single_dj_points", int(request.attribute("s_achi")))
        play_stats.replace_int("double_dj_points", int(request.attribute("d_achi")))

        # Profile settings
        newprofile.replace_int("sp_opt", int(request.attribute("sp_opt")))
        newprofile.replace_int("dp_opt", int(request.attribute("dp_opt")))
        newprofile.replace_int("dp_opt2", int(request.attribute("dp_opt2")))
        newprofile.replace_int("gpos", int(request.attribute("gpos")))
        newprofile.replace_int("s_sorttype", int(request.attribute("s_sorttype")))
        newprofile.replace_int("d_sorttype", int(request.attribute("d_sorttype")))
        newprofile.replace_int("s_disp_judge", int(request.attribute("s_disp_judge")))
        newprofile.replace_int("d_disp_judge", int(request.attribute("d_disp_judge")))
        newprofile.replace_int("s_pace", int(request.attribute("s_pace")))
        newprofile.replace_int("d_pace", int(request.attribute("d_pace")))
        newprofile.replace_int("s_gno", int(request.attribute("s_gno")))
        newprofile.replace_int("d_gno", int(request.attribute("d_gno")))
        newprofile.replace_int("s_gtype", int(request.attribute("s_gtype")))
        newprofile.replace_int("d_gtype", int(request.attribute("d_gtype")))
        newprofile.replace_int("s_sdlen", int(request.attribute("s_sdlen")))
        newprofile.replace_int("d_sdlen", int(request.attribute("d_sdlen")))
        newprofile.replace_int("s_sdtype", int(request.attribute("s_sdtype")))
        newprofile.replace_int("d_sdtype", int(request.attribute("d_sdtype")))
        newprofile.replace_int("s_timing", int(request.attribute("s_timing")))
        newprofile.replace_int("d_timing", int(request.attribute("d_timing")))
        newprofile.replace_float("s_notes", float(request.attribute("s_notes")))
        newprofile.replace_float("d_notes", float(request.attribute("d_notes")))
        newprofile.replace_int("s_judge", int(request.attribute("s_judge")))
        newprofile.replace_int("d_judge", int(request.attribute("d_judge")))
        newprofile.replace_float("s_hispeed", float(request.attribute("s_hispeed")))
        newprofile.replace_float("d_hispeed", float(request.attribute("d_hispeed")))
        newprofile.replace_int("s_opstyle", int(request.attribute("s_opstyle")))
        newprofile.replace_int("d_opstyle", int(request.attribute("d_opstyle")))
        newprofile.replace_int("s_graph_score", int(request.attribute("s_graph_score")))
        newprofile.replace_int("d_graph_score", int(request.attribute("d_graph_score")))
        newprofile.replace_int("s_auto_scrach", int(request.attribute("s_auto_scrach")))
        newprofile.replace_int("d_auto_scrach", int(request.attribute("d_auto_scrach")))
        newprofile.replace_int("s_gauge_disp", int(request.attribute("s_gauge_disp")))
        newprofile.replace_int("d_gauge_disp", int(request.attribute("d_gauge_disp")))
        newprofile.replace_int("s_lane_brignt", int(request.attribute("s_lane_brignt")))
        newprofile.replace_int("d_lane_brignt", int(request.attribute("d_lane_brignt")))
        newprofile.replace_int("s_camera_layout", int(request.attribute("s_camera_layout")))
        newprofile.replace_int("d_camera_layout", int(request.attribute("d_camera_layout")))
        newprofile.replace_int("s_ghost_score", int(request.attribute("s_ghost_score")))
        newprofile.replace_int("d_ghost_score", int(request.attribute("d_ghost_score")))
        newprofile.replace_int("s_tsujigiri_disp", int(request.attribute("s_tsujigiri_disp")))
        newprofile.replace_int("d_tsujigiri_disp", int(request.attribute("d_tsujigiri_disp")))
        newprofile.replace_int("s_lift", int(request.attribute("s_lift")))
        newprofile.replace_int("d_lift", int(request.attribute("d_lift")))
        newprofile.replace_int("mode", int(request.attribute("mode")))
        newprofile.replace_int("pmode", int(request.attribute("pmode")))
        newprofile.replace_int("rtype", int(request.attribute("rtype")))

        # Update judge window adjustments per-machine
        judge_dict = newprofile.get_dict("machine_judge_adjust")
        machine_judge = judge_dict.get_dict(self.config.machine.pcbid)
        machine_judge.replace_int("single", int(request.attribute("s_judgeAdj")))
        machine_judge.replace_int("double", int(request.attribute("d_judgeAdj")))
        judge_dict.replace_dict(self.config.machine.pcbid, machine_judge)
        newprofile.replace_dict("machine_judge_adjust", judge_dict)

        # Secret flags saving
        game_config = self.get_game_config()
        if not game_config.get_bool("force_unlock_songs"):
            secret = request.child("secret")
            if secret is not None:
                secret_dict = newprofile.get_dict("secret")
                secret_dict.replace_int_array("flg1", 3, secret.child_value("flg1"))
                secret_dict.replace_int_array("flg2", 3, secret.child_value("flg2"))
                secret_dict.replace_int_array("flg3", 3, secret.child_value("flg3"))
                newprofile.replace_dict("secret", secret_dict)

        # Basic achievements
        achievements = request.child("achievements")
        if achievements is not None:
            newprofile.replace_int("visit_flg", int(achievements.attribute("visit_flg")))
            newprofile.replace_int("last_weekly", int(achievements.attribute("last_weekly")))
            newprofile.replace_int("weekly_num", int(achievements.attribute("weekly_num")))

            pack_id = int(achievements.attribute("pack_id"))
            if pack_id > 0:
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    pack_id,
                    "daily",
                    {
                        "pack_flg": int(achievements.attribute("pack_flg")),
                        "pack_comp": int(achievements.attribute("pack_comp")),
                    },
                )

            trophies = achievements.child("trophy")
            if trophies is not None:
                # We only load the first 20 in profile load.
                newprofile.replace_int_array("trophy", 20, trophies.value[:20])

        # Deller saving
        deller = request.child("deller")
        if deller is not None:
            newprofile.replace_int("deller", newprofile.get_int("deller") + int(deller.attribute("deller")))

        # Secret course expert point saving
        expert_point = request.child("expert_point")
        if expert_point is not None:
            courseid = int(expert_point.attribute("course_id"))

            # Update achievement to track expert points
            expert_point_achievement = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                courseid,
                "expert_point",
            )
            if expert_point_achievement is None:
                expert_point_achievement = ValidatedDict()
            expert_point_achievement.replace_int(
                "normal_points",
                int(expert_point.attribute("n_point")),
            )
            expert_point_achievement.replace_int(
                "hyper_points",
                int(expert_point.attribute("h_point")),
            )
            expert_point_achievement.replace_int(
                "another_points",
                int(expert_point.attribute("a_point")),
            )

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                courseid,
                "expert_point",
                expert_point_achievement,
            )

        # Favorites saving
        for favorite in request.children:
            singles = []
            doubles = []
            name = None
            if favorite.name in ["favorite", "extra_favorite"]:
                if favorite.name == "favorite":
                    name = "favorite1"
                elif favorite.name == "extra_favorite":
                    folder = favorite.attribute("folder_id")
                    if folder == "0":
                        name = "favorite2"
                    if folder == "1":
                        name = "favorite3"
                if name is None:
                    continue

                single_music_bin = favorite.child_value("sp_mlist")
                single_chart_bin = favorite.child_value("sp_clist")
                double_music_bin = favorite.child_value("dp_mlist")
                double_chart_bin = favorite.child_value("dp_clist")

                for i in range(self.FAVORITE_LIST_LENGTH):
                    singles.append(
                        {
                            "id": struct.unpack("<L", single_music_bin[(i * 4) : ((i + 1) * 4)])[0],
                            "chart": struct.unpack("B", single_chart_bin[i : (i + 1)])[0],
                        }
                    )
                    doubles.append(
                        {
                            "id": struct.unpack("<L", double_music_bin[(i * 4) : ((i + 1) * 4)])[0],
                            "chart": struct.unpack("B", double_chart_bin[i : (i + 1)])[0],
                        }
                    )

            # Filter out empty charts
            if name is not None:
                singles = [single for single in singles if single["id"] != 0]
                doubles = [double for double in doubles if double["id"] != 0]

                newprofile.replace_dict(
                    name,
                    {
                        "single": singles,
                        "double": doubles,
                    },
                )

        # DJ rank saving
        for dj_rank in request.children:
            if dj_rank.name != "dj_rank":
                continue

            rankid = int(dj_rank.attribute("style"))
            rank = dj_rank.child_value("rank")
            point = dj_rank.child_value("point")

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                rankid,
                "dj_rank",
                {
                    "rank": rank,
                    "point": point,
                },
            )

        # 蜃気楼の図書館(Biblioteca of Mirage) Event Saving
        event1 = request.child("event1")
        if event1 is not None:
            event1_dict = newprofile.get_dict("event1")
            event1_dict.increment_int("event_play_num")
            last_select_map = int(event1.attribute("last_select_map_id"))
            event1_dict.replace_int("play_gift", int(event1.attribute("play_gift")))
            event1_dict.replace_int("fragment_num", int(event1.attribute("fragment_num")))
            event1_dict.replace_int("continuous_correct", int(event1.attribute("continuous_correct")))
            event1_dict.replace_int("bookshelf_release_num", int(event1.attribute("bookshelf_release_num")))
            event1_dict.replace_int("read_tips_list", int(event1.attribute("read_tips_list")))
            event1_dict.replace_bytes("quiz_control_list", event1.child_value("quiz_control_list"))
            # Save any map data, also see if we need to update last_select_map
            for map_data in event1.children:
                if map_data.name != "map_data":
                    continue

                # Update the map's progress in the DB
                mapid = int(map_data.attribute("map_id"))
                play_num = int(map_data.attribute("play_num"))
                is_clear = map_data.child_value("is_clear") or False
                last_select_route_id = int(map_data.attribute("last_select_route_id"))
                bookshelf_release_num = int(map_data.attribute("bookshelf_release_num"))
                map_route_damage = map_data.child_value("map_route_damage")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    mapid,
                    "map_data",
                    {
                        "play_num": play_num,
                        "last_select_route_id": last_select_route_id,
                        "bookshelf_release_num": bookshelf_release_num,
                        "map_route_damage": map_route_damage,
                        "is_clear": is_clear,
                    },
                )

                # If they cleared this map, then we should be at least onto the next one.
                if is_clear:
                    last_select_map = max(last_select_map, mapid + 1)

            event1_dict.replace_int("last_select_map", last_select_map)
            newprofile.replace_dict("event1", event1_dict)

        # DELABITY LABORATORY Event Saving
        event2 = request.child("event2")
        if event2 is not None:
            event2_dict = newprofile.get_dict("event2")
            event2_dict.replace_int("play_num", int(event2.attribute("play_num")))
            event2_dict.replace_int("delabity", int(event2.attribute("delabity")))
            event2_dict.replace_int("floor_0_last_area", int(event2.attribute("floor_0_last_area")))
            event2_dict.replace_int("floor_1_last_area", int(event2.attribute("floor_1_last_area")))
            event2_dict.replace_int("floor_2_last_area", int(event2.attribute("floor_2_last_area")))
            event2_dict.replace_int("floor_3_last_area", int(event2.attribute("floor_3_last_area")))
            event2_dict.replace_int("floor_4_last_area", int(event2.attribute("floor_4_last_area")))
            event2_dict.replace_int("floor_clear_flg_list", int(event2.attribute("floor_clear_flg_list")))
            event2_dict.replace_int("last_select_floor", int(event2.attribute("last_select_floor")))
            event2_dict.replace_int("tips_list", int(event2.attribute("tips_list")))

            for area_data in event2.children:
                if area_data.name != "area_data":
                    continue
                floor_id = int(area_data.attribute("floor_id"))
                area_id = int(area_data.attribute("area_id"))
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    area_id,
                    f"area_data_floor_{floor_id}",  # Save floor_id twice since the game seems to key by both
                    {
                        "floor_id": floor_id,
                        "last_select_note": int(area_data.attribute("last_select_note")),
                        "normal_play_num": int(area_data.attribute("normal_play_num")),
                        "hyper_play_num": int(area_data.attribute("hyper_play_num")),
                        "another_play_num": int(area_data.attribute("another_play_num")),
                        "area_clear_flg_list": int(area_data.attribute("area_clear_flg_list")),
                        "normal_grade_point": int(area_data.attribute("normal_grade_point")),
                        "hyper_grade_point": int(area_data.attribute("hyper_grade_point")),
                        "another_grade_point": int(area_data.attribute("another_grade_point")),
                    },
                )

            newprofile.replace_dict("event2", event2_dict)

        extra_boss_event = request.child("extra_boss_event")
        if extra_boss_event is not None:
            extra_boss_event_dict = newprofile.get_dict("extra_boss_event")
            for i in range(9):
                extra_boss_event_dict.replace_int(f"orb_{i}", int(extra_boss_event.attribute(f"orb_{i}")))
            newprofile.replace_dict("extra_boss_event", extra_boss_event_dict)

        # Step-up mode
        step = request.child("step")
        if step is not None:
            step_dict = newprofile.get_dict("step")
            step_dict.replace_int("enemy_damage", int(step.attribute("enemy_damage")))
            step_dict.replace_int("progress", int(step.attribute("progress")))
            step_dict.replace_bool("is_track_ticket", bool(step.child_value("is_track_ticket")))
            step_dict.replace_int("sp_level", int(step.attribute("sp_level")))
            step_dict.replace_int("dp_level", int(step.attribute("dp_level")))
            step_dict.replace_int("sp_mplay", int(step.attribute("sp_mplay")))
            step_dict.replace_int("dp_mplay", int(step.attribute("dp_mplay")))
            step_dict.replace_int("sp_mission_point", str(step_dict.get_int("sp_mission_point")))
            step_dict.replace_int("dp_mission_point", str(step_dict.get_int("dp_mission_point")))
            step_dict.replace_int("sp_dj_mission_level", str(step_dict.get_int("sp_dj_mission_level@")))
            step_dict.replace_int("dp_dj_mission_level", str(step_dict.get_int("dp_dj_mission_level@")))
            step_dict.replace_int(
                "sp_clear_mission_level",
                str(step_dict.get_int("sp_clear_mission_level")),
            )
            step_dict.replace_int(
                "dp_clear_mission_level",
                str(step_dict.get_int("dp_clear_mission_level")),
            )
            step_dict.replace_int("sp_dj_mission_clear", str(step_dict.get_int("sp_dj_mission_clear")))
            step_dict.replace_int("dp_dj_mission_clear", str(step_dict.get_int("dp_dj_mission_clear")))
            step_dict.replace_int(
                "sp_clear_mission_clear",
                str(step_dict.get_int("sp_clear_mission_clear")),
            )
            step_dict.replace_int(
                "dp_clear_mission_clear",
                str(step_dict.get_int("dp_clear_mission_clear")),
            )
            step_dict.replace_int("tips_read_list", str(step_dict.get_int("tips_read_list")))
            newprofile.replace_dict("step", step_dict)

        # QPro equip in step-up mode
        qpro_equip = request.child("qpro_equip")
        if qpro_equip is not None:
            qpro_dict = newprofile.get_dict("qpro")
            qpro_dict.replace_int("head", int(qpro_equip.attribute("head")))
            qpro_dict.replace_int("hair", int(qpro_equip.attribute("hair")))
            qpro_dict.replace_int("face", int(qpro_equip.attribute("face")))
            qpro_dict.replace_int("hand", int(qpro_equip.attribute("hand")))
            qpro_dict.replace_int("body", int(qpro_equip.attribute("body")))
            newprofile.replace_dict("qpro", qpro_dict)

        # Qpro secret unlocks in step-up mode
        qpro_secret = request.child("qpro_secret")
        if qpro_secret is not None:
            qpro_secret_dict = newprofile.get_dict("qpro_secret")
            qpro_secret_dict.replace_int_array("head", 5, qpro_secret.child_value("head"))
            qpro_secret_dict.replace_int_array("hair", 5, qpro_secret.child_value("hair"))
            qpro_secret_dict.replace_int_array("face", 5, qpro_secret.child_value("face"))
            qpro_secret_dict.replace_int_array("body", 5, qpro_secret.child_value("body"))
            qpro_secret_dict.replace_int_array("hand", 5, qpro_secret.child_value("hand"))
            newprofile.replace_dict("qpro_secret", qpro_secret_dict)

        # Orb data saving
        orb_data = request.child("orb_data")
        if orb_data is not None:
            orbs = newprofile.get_int("orbs")
            orbs = orbs + int(orb_data.attribute("add_orb"))
            if orb_data.child_value("use_vip_pass"):
                orbs = 0
            newprofile.replace_int("orbs", orbs)

        # tonyutsu saving
        tonyutsu = request.child("tonyutsu")
        if tonyutsu is not None:
            tonyutsu_dict = newprofile.get_dict("tonyutsu")
            tonyutsu_dict.replace_int("platinum_pass", tonyutsu.attribute("platinum_pass"))
            tonyutsu_dict.replace_int("black_pass", tonyutsu.attribute("black_pass"))

        # Keep track of play statistics across all mixes
        self.update_play_statistics(userid, play_stats)

        return newprofile
