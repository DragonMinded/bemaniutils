# vim: set fileencoding=utf-8
import random
from typing import Optional, Dict, List, Tuple, Any
from typing_extensions import Final

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.stubs import IIDXLincle

from bemani.common import Profile, ValidatedDict, VersionConstants, Time, ID
from bemani.data import Data, UserID
from bemani.protocol import Node


class IIDXTricoro(IIDXBase):
    name: str = "Beatmania IIDX Tricoro"
    version: int = VersionConstants.IIDX_TRICORO

    GAME_CLTYPE_SINGLE: Final[int] = 0
    GAME_CLTYPE_DOUBLE: Final[int] = 1

    DAN_STAGES_SINGLE: Final[int] = 4
    DAN_STAGES_DOUBLE: Final[int] = 3

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
    GAME_SP_DAN_RANK_KAIDEN: Final[int] = 17

    GAME_DP_DAN_RANK_5_KYU: Final[int] = 0
    GAME_DP_DAN_RANK_4_KYU: Final[int] = 1
    GAME_DP_DAN_RANK_3_KYU: Final[int] = 2
    GAME_DP_DAN_RANK_2_KYU: Final[int] = 3
    GAME_DP_DAN_RANK_1_KYU: Final[int] = 4
    GAME_DP_DAN_RANK_1_DAN: Final[int] = 5
    GAME_DP_DAN_RANK_2_DAN: Final[int] = 6
    GAME_DP_DAN_RANK_3_DAN: Final[int] = 7
    GAME_DP_DAN_RANK_4_DAN: Final[int] = 8
    GAME_DP_DAN_RANK_5_DAN: Final[int] = 9
    GAME_DP_DAN_RANK_6_DAN: Final[int] = 10
    GAME_DP_DAN_RANK_7_DAN: Final[int] = 11
    GAME_DP_DAN_RANK_8_DAN: Final[int] = 12
    GAME_DP_DAN_RANK_9_DAN: Final[int] = 13
    GAME_DP_DAN_RANK_10_DAN: Final[int] = 14
    GAME_DP_DAN_RANK_KAIDEN: Final[int] = 15

    FAVORITE_LIST_LENGTH: Final[int] = 20

    GAME_CHART_TYPE_N7: Final[int] = 0
    GAME_CHART_TYPE_H7: Final[int] = 1
    GAME_CHART_TYPE_A7: Final[int] = 2
    GAME_CHART_TYPE_N14: Final[int] = 3
    GAME_CHART_TYPE_H14: Final[int] = 4
    GAME_CHART_TYPE_A14: Final[int] = 5
    GAME_CHART_TYPE_B7: Final[int] = 6

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXLincle(self.data, self.config, self.model)

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Dict[str, Any]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Insert dailies into the DB.
        """
        events = []
        if data.local.network.should_schedule(
            cls.game, cls.version, "daily_charts", "daily"
        ):
            # Generate a new list of three dailies.
            start_time, end_time = data.local.network.get_schedule_duration("daily")
            all_songs = list(
                set(
                    [
                        song.id
                        for song in data.local.music.get_all_songs(
                            cls.game, cls.version
                        )
                    ]
                )
            )
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
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "daily_charts", "daily"
                )
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
                self.DAN_RANK_KAIDEN: self.GAME_SP_DAN_RANK_KAIDEN,
            }[db_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
                self.DAN_RANK_7_KYU: self.GAME_DP_DAN_RANK_5_KYU,
                self.DAN_RANK_6_KYU: self.GAME_DP_DAN_RANK_5_KYU,
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
                self.GAME_SP_DAN_RANK_KAIDEN: self.DAN_RANK_KAIDEN,
            }[game_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
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

    def handle_shop_getname_request(self, request: Node) -> Node:
        root = Node.void("shop")
        root.set_attribute("cls_opt", "0")
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        root.set_attribute("opname", machine.name)
        root.set_attribute("pid", str(self.get_machine_region()))
        return root

    def handle_shop_savename_request(self, request: Node) -> Node:
        self.update_machine_name(request.attribute("opname"))
        root = Node.void("shop")
        return root

    def handle_shop_sentinfo_request(self, request: Node) -> Node:
        root = Node.void("shop")
        return root

    def handle_shop_getconvention_request(self, request: Node) -> Node:
        root = Node.void("shop")
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            course = self.data.local.machine.get_settings(
                machine.arcade, self.game, self.music_version, "shop_course"
            )
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

    def handle_shop_setconvention_request(self, request: Node) -> Node:
        root = Node.void("shop")
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            course = ValidatedDict()
            course.replace_int("music_0", request.child_value("music_0"))
            course.replace_int("music_1", request.child_value("music_1"))
            course.replace_int("music_2", request.child_value("music_2"))
            course.replace_int("music_3", request.child_value("music_3"))
            course.replace_bool("valid", request.child_value("valid"))
            self.data.local.machine.put_settings(
                machine.arcade, self.game, self.music_version, "shop_course", course
            )

        return root

    def handle_ranking_getranker_request(self, request: Node) -> Node:
        root = Node.void("ranking")
        chart = self.game_to_db_chart(int(request.attribute("clid")))
        if chart not in [
            self.CHART_TYPE_N7,
            self.CHART_TYPE_H7,
            self.CHART_TYPE_A7,
            self.CHART_TYPE_N14,
            self.CHART_TYPE_H14,
            self.CHART_TYPE_A14,
        ]:
            # Chart type 6 is presumably beginner mode, but it crashes the game
            return root

        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            course = self.data.local.machine.get_settings(
                machine.arcade, self.game, self.music_version, "shop_course"
            )
        else:
            course = None

        if course is None:
            course = ValidatedDict()

        if not course.get_bool("valid"):
            # Shop course not enabled or not present
            return root

        convention = Node.void("convention")
        root.add_child(convention)
        convention.set_attribute("clid", str(chart))
        convention.set_attribute("update_date", str(Time.now() * 1000))

        # Grab all scores for each of the four songs, filter out people who haven't
        # set us as their arcade and then return the top 20 scores (adding all 4 songs).
        songids = [
            course.get_int("music_0"),
            course.get_int("music_1"),
            course.get_int("music_2"),
            course.get_int("music_3"),
        ]

        totalscores: Dict[UserID, int] = {}
        profiles: Dict[UserID, Profile] = {}
        for songid in songids:
            scores = self.data.local.music.get_all_scores(
                self.game,
                self.music_version,
                songid=songid,
                songchart=chart,
            )

            for score in scores:
                if score[0] not in totalscores:
                    totalscores[score[0]] = 0
                    profile = self.get_any_profile(score[0])
                    if profile is None:
                        profile = Profile(self.game, self.version, "", 0)
                    profiles[score[0]] = profile

                totalscores[score[0]] += score[1].points

        topscores = sorted(
            [
                (totalscores[userid], profiles[userid])
                for userid in totalscores
                if self.user_joined_arcade(machine, profiles[userid])
            ],
            key=lambda tup: tup[0],
            reverse=True,
        )[:20]

        rank = 0
        for topscore in topscores:
            rank = rank + 1

            detail = Node.void("detail")
            convention.add_child(detail)
            detail.set_attribute("name", topscore[1].get_str("name"))
            detail.set_attribute("rank", str(rank))
            detail.set_attribute("score", str(topscore[0]))
            detail.set_attribute("pid", str(topscore[1].get_int("pid")))

            qpro = topscore[1].get_dict("qpro")
            detail.set_attribute("head", str(qpro.get_int("head")))
            detail.set_attribute("hair", str(qpro.get_int("hair")))
            detail.set_attribute("face", str(qpro.get_int("face")))
            detail.set_attribute("body", str(qpro.get_int("body")))
            detail.set_attribute("hand", str(qpro.get_int("hand")))

        return root

    def handle_music_crate_request(self, request: Node) -> Node:
        root = Node.void("music")
        attempts = self.get_clear_rates()

        all_songs = list(
            set(
                [
                    song.id
                    for song in self.data.local.music.get_all_songs(
                        self.game, self.music_version
                    )
                ]
            )
        )
        for song in all_songs:
            clears = []
            fcs = []

            for chart in [0, 1, 2, 3, 4, 5]:
                placed = False
                if song in attempts and chart in attempts[song]:
                    values = attempts[song][chart]
                    if values["total"] > 0:
                        clears.append(int((100 * values["clears"]) / values["total"]))
                        fcs.append(int((100 * values["fcs"]) / values["total"]))
                        placed = True
                if not placed:
                    clears.append(101)
                    fcs.append(101)

            clearnode = Node.u8_array("c", clears + fcs)
            clearnode.set_attribute("mid", str(song))
            root.add_child(clearnode)

        return root

    def handle_music_getrank_request(self, request: Node) -> Node:
        cltype = int(request.attribute("cltype"))

        root = Node.void("music")
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
                scores = self.data.remote.music.get_scores(
                    self.game, self.music_version, userid
                )

                # Grab score data for user/rival
                scoredata = self.make_score_struct(
                    scores,
                    self.CLEAR_TYPE_SINGLE
                    if cltype == self.GAME_CLTYPE_SINGLE
                    else self.CLEAR_TYPE_DOUBLE,
                    rivalid,
                )
                for s in scoredata:
                    root.add_child(Node.s16_array("m", s))

                # Grab most played for user/rival
                most_played = [
                    play[0]
                    for play in self.data.local.music.get_most_played(
                        self.game, self.music_version, userid, 20
                    )
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

    def handle_music_reg_request(self, request: Node) -> Node:
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
        all_players = {
            uid: prof
            for (uid, prof) in self.get_any_profiles([s[0] for s in all_scores])
        }

        if not global_scores:
            all_scores = [
                score
                for score in all_scores
                if (
                    score[0] == userid
                    or self.user_joined_arcade(machine, all_players[score[0]])
                )
            ]

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
            shopid = ID.parse_machine_id(request.attribute("shopconvid"))

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
        root = Node.void("music")
        root.set_attribute("clid", request.attribute("clid"))
        root.set_attribute("mid", request.attribute("mid"))

        attempts = self.get_clear_rates(musicid, chart)
        count = attempts[musicid][chart]["total"]
        clear = attempts[musicid][chart]["clears"]
        full_combo = attempts[musicid][chart]["fcs"]

        if count > 0:
            root.set_attribute("crate", str(int((100 * clear) / count)))
            root.set_attribute("frate", str(int((100 * full_combo) / count)))
        else:
            root.set_attribute("crate", "0")
            root.set_attribute("frate", "0")

        if userid is not None:
            # Shop ranking
            shopdata = Node.void("shopdata")
            root.add_child(shopdata)
            shopdata.set_attribute(
                "rank", "-1" if oldindex is None else str(oldindex + 1)
            )

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
                all_scores = [
                    score
                    for score in all_scores
                    if (
                        score[0] == userid
                        or self.user_joined_arcade(machine, all_players[score[0]])
                    )
                ]

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
                if "shop_location" in profile:
                    shop_id = profile.get_int("shop_location")
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

    def handle_music_breg_request(self, request: Node) -> Node:
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
        root = Node.void("music")
        return root

    def handle_music_play_request(self, request: Node) -> Node:
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
        root = Node.void("music")
        root.set_attribute("clid", request.attribute("clid"))
        root.set_attribute("mid", request.attribute("mid"))

        attempts = self.get_clear_rates(musicid, chart)
        count = attempts[musicid][chart]["total"]
        clear = attempts[musicid][chart]["clears"]
        full_combo = attempts[musicid][chart]["fcs"]

        if count > 0:
            root.set_attribute("crate", str(int((100 * clear) / count)))
            root.set_attribute("frate", str(int((100 * full_combo) / count)))
        else:
            root.set_attribute("crate", "0")
            root.set_attribute("frate", "0")

        return root

    def handle_music_appoint_request(self, request: Node) -> Node:
        musicid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("clid")))
        ghost_type = int(request.attribute("ctype"))
        extid = int(request.attribute("iidxid"))
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        root = Node.void("music")

        if userid is not None:
            # Try to look up previous ghost for user
            my_score = self.data.remote.music.get_score(
                self.game, self.music_version, userid, musicid, chart
            )
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

    def handle_pc_common_request(self, request: Node) -> Node:
        root = Node.void("pc")
        root.set_attribute("expire", "600")

        # TODO: Hook all of these up to config options I guess?
        ir = Node.void("ir")
        root.add_child(ir)
        ir.set_attribute("beat", "2")

        limit = Node.void("limit")
        root.add_child(limit)
        limit.set_attribute("phase", "24")

        # See if we configured event overrides
        if self.machine_joined_arcade():
            game_config = self.get_game_config()
            omni_events = game_config.get_bool("omnimix_events_enabled")
        else:
            # If we aren't in an arcade, we turn off events
            omni_events = False

        if self.omnimix and (not omni_events):
            boss_phase = 0
        else:
            # TODO: Figure out what these map to
            boss_phase = 0

        boss = Node.void("boss")
        root.add_child(boss)
        boss.set_attribute("phase", str(boss_phase))

        red = Node.void("red")
        root.add_child(red)
        red.set_attribute("phase", "0")

        yellow = Node.void("yellow")
        root.add_child(yellow)
        yellow.set_attribute("phase", "0")

        medal = Node.void("medal")
        root.add_child(medal)
        medal.set_attribute("phase", "1")

        cafe = Node.void("cafe")
        root.add_child(cafe)
        cafe.set_attribute("open", "1")

        tricolettepark = Node.void("tricolettepark")
        root.add_child(tricolettepark)
        tricolettepark.set_attribute("open", "0")

        return root

    def handle_pc_delete_request(self, request: Node) -> Node:
        return Node.void("pc")

    def handle_pc_playstart_request(self, request: Node) -> Node:
        return Node.void("pc")

    def handle_pc_playend_request(self, request: Node) -> Node:
        return Node.void("pc")

    def handle_pc_oldget_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            oldversion = self.previous_version()
            profile = oldversion.get_profile(userid)
        else:
            profile = None

        root = Node.void("pc")
        root.set_attribute("status", "1" if profile is None else "0")
        return root

    def handle_pc_getname_request(self, request: Node) -> Node:
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

        root = Node.void("pc")
        root.set_attribute("name", profile.get_str("name"))
        root.set_attribute("idstr", ID.format_extid(profile.extid))
        root.set_attribute("pid", str(profile.get_int("pid")))
        return root

    def handle_pc_reg_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        name = request.attribute("name")
        pid = int(request.attribute("pid"))
        profile = self.new_profile_by_refid(refid, name, pid)

        root = Node.void("pc")
        if profile is not None:
            root.set_attribute("id", str(profile.extid))
            root.set_attribute("id_str", ID.format_extid(profile.extid))
        return root

    def handle_pc_get_request(self, request: Node) -> Node:
        refid = request.attribute("rid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("pc")
        return root

    def handle_pc_save_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        self.put_profile_by_extid(extid, request)

        root = Node.void("pc")
        return root

    def handle_pc_visit_request(self, request: Node) -> Node:
        root = Node.void("pc")
        root.set_attribute("anum", "0")
        root.set_attribute("snum", "0")
        root.set_attribute("pnum", "0")
        root.set_attribute("aflg", "0")
        root.set_attribute("sflg", "0")
        root.set_attribute("pflg", "0")
        return root

    def handle_pc_shopregister_request(self, request: Node) -> Node:
        extid = int(request.child_value("iidx_id"))
        location = ID.parse_machine_id(request.child_value("location_id"))

        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            profile = self.get_profile(userid)
            if profile is None:
                profile = Profile(self.game, self.version, "", extid)
            profile.replace_int("shop_location", location)
            self.put_profile(userid, profile)

        root = Node.void("pc")
        return root

    def handle_grade_raised_request(self, request: Node) -> Node:
        extid = int(request.attribute("iidxid"))
        cltype = int(request.attribute("gtype"))
        rank = self.game_to_db_rank(int(request.attribute("gid")), cltype)
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            percent = int(request.attribute("achi"))
            stages_cleared = int(request.attribute("cflg"))
            if cltype == self.GAME_CLTYPE_SINGLE:
                max_stages = self.DAN_STAGES_SINGLE
            else:
                max_stages = self.DAN_STAGES_DOUBLE
            cleared = stages_cleared == max_stages

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
        root = Node.void("grade")
        root.set_attribute("pnum", str(len(all_achievements)))
        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("pc")

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
        pcdata.set_attribute("help", str(profile.get_int("help")))
        pcdata.set_attribute("gno", str(profile.get_int("gno")))
        pcdata.set_attribute("gpos", str(profile.get_int("gpos")))
        pcdata.set_attribute("timing", str(profile.get_int("timing")))
        pcdata.set_attribute("sdhd", str(profile.get_int("sdhd")))
        pcdata.set_attribute("sdtype", str(profile.get_int("sdtype")))
        pcdata.set_attribute("notes", str(profile.get_float("notes")))
        pcdata.set_attribute("pase", str(profile.get_int("pase")))
        pcdata.set_attribute("sp_opt", str(profile.get_int("sp_opt")))
        pcdata.set_attribute("dp_opt", str(profile.get_int("dp_opt")))
        pcdata.set_attribute("dp_opt2", str(profile.get_int("dp_opt2")))
        pcdata.set_attribute("mode", str(profile.get_int("mode")))
        pcdata.set_attribute("pmode", str(profile.get_int("pmode")))
        pcdata.set_attribute("liflen", str(profile.get_int("lift")))
        pcdata.set_attribute("judge", str(profile.get_int("judge")))
        pcdata.set_attribute("opstyle", str(profile.get_int("opstyle")))
        pcdata.set_attribute("hispeed", str(profile.get_float("hispeed")))
        pcdata.set_attribute("judgeAdj", str(machine_judge.get_int("adj")))

        # Secret flags (shh!)
        secret_dict = profile.get_dict("secret")
        secret = Node.void("secret")
        root.add_child(secret)
        secret.add_child(Node.s64("flg1", secret_dict.get_int("flg1")))
        secret.add_child(Node.s64("flg2", secret_dict.get_int("flg2")))
        secret.add_child(Node.s64("flg3", secret_dict.get_int("flg3")))

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
        rankings = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        for rank in rankings:
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
            ],
        )
        root.add_child(skin)

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

            # If the user joined a particular shop, let the game know.
            if "shop_location" in other_profile:
                shop_id = other_profile.get_int("shop_location")
                machine = self.get_machine_by_id(shop_id)
                if machine is not None:
                    shop = Node.void("shop")
                    rival.add_child(shop)
                    shop.set_attribute("name", machine.name)

            qprodata = Node.void("qprodata")
            rival.add_child(qprodata)
            qpro = other_profile.get_dict("qpro")
            qprodata.set_attribute("head", str(qpro.get_int("head")))
            qprodata.set_attribute("hair", str(qpro.get_int("hair")))
            qprodata.set_attribute("face", str(qpro.get_int("face")))
            qprodata.set_attribute("body", str(qpro.get_int("body")))
            qprodata.set_attribute("hand", str(qpro.get_int("hand")))

        # If the user joined a particular shop, let the game know.
        if "shop_location" in profile:
            shop_id = profile.get_int("shop_location")
            machine = self.get_machine_by_id(shop_id)
            if machine is not None:
                join_shop = Node.void("join_shop")
                root.add_child(join_shop)
                join_shop.set_attribute("joinflg", "1")
                join_shop.set_attribute("join_cflg", "1")
                join_shop.set_attribute("join_id", ID.format_machine_id(machine.id))
                join_shop.set_attribute("join_name", machine.name)

        # Step up mode
        step_dict = profile.get_dict("step")
        step = Node.void("step")
        root.add_child(step)
        step.set_attribute("sp_ach", str(step_dict.get_int("sp_ach")))
        step.set_attribute("dp_ach", str(step_dict.get_int("dp_ach")))
        step.set_attribute("sp_hdpt", str(step_dict.get_int("sp_hdpt")))
        step.set_attribute("dp_hdpt", str(step_dict.get_int("dp_hdpt")))
        step.set_attribute("sp_level", str(step_dict.get_int("sp_level")))
        step.set_attribute("dp_level", str(step_dict.get_int("dp_level")))
        step.set_attribute("sp_round", str(step_dict.get_int("sp_round")))
        step.set_attribute("dp_round", str(step_dict.get_int("dp_round")))
        step.set_attribute("sp_mplay", str(step_dict.get_int("sp_mplay")))
        step.set_attribute("dp_mplay", str(step_dict.get_int("dp_mplay")))
        step.set_attribute("review", str(step_dict.get_int("review")))
        if "stamp" in step_dict:
            step.add_child(
                Node.binary("stamp", step_dict.get_bytes("stamp", bytes([0] * 36)))
            )
        if "help" in step_dict:
            step.add_child(
                Node.binary("help", step_dict.get_bytes("help", bytes([0] * 6)))
            )

        # Daily recommendations
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "dailies"
        )
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
        achievements = Node.void("achievements")
        root.add_child(achievements)

        # Dailies
        if pack_id is None:
            achievements.set_attribute("pack", "0")
            achievements.set_attribute("pack_comp", "0")
        else:
            daily_played = self.data.local.user.get_achievement(
                self.game, self.version, userid, pack_id, "daily"
            )
            if daily_played is None:
                daily_played = ValidatedDict()
            achievements.set_attribute("pack", str(daily_played.get_int("pack_flg")))
            achievements.set_attribute(
                "pack_comp", str(daily_played.get_int("pack_comp"))
            )

        # Weeklies
        achievements.set_attribute("last_weekly", str(profile.get_int("last_weekly")))
        achievements.set_attribute("weekly_num", str(profile.get_int("weekly_num")))

        # Prefecture visit flag
        achievements.set_attribute("visit_flg", str(profile.get_int("visit_flg")))

        # Number of rivals beaten
        achievements.set_attribute("rival_crush", str(profile.get_int("rival_crush")))

        # Tran medals
        achievements.add_child(
            Node.s64_array("trophy", profile.get_int_array("trophy", 10))
        )

        # Link5 data
        if "link5" in profile:
            # Don't provide link5 if we haven't saved it, so the game can
            # initialize it properly.
            link5_dict = profile.get_dict("link5")
            link5 = Node.void("link5")
            root.add_child(link5)
            for attr in [
                "qpro",
                "glass",
                "treasure",  # not saved
                "beautiful",
                "quaver",
                "castle",
                "flip",
                "titans",
                "exusia",
                "waxing",
                "sampling",
                "beachside",
                "cuvelia",
                "reunion",
                "bad",
                "turii",
                "anisakis",
                "second",
                "whydidyou",
                "china",
                "fallen",
                "broken",
                "summer",
                "sakura",
                "wuv",
                "survival",
                "thunder",
                "qproflg",  # not saved
                "glassflg",  # not saved
                "reflec_data",  # not saved
            ]:
                link5.set_attribute(attr, str(link5_dict.get_int(attr)))

        # Track deller, orbs and baron
        commonboss = Node.void("commonboss")
        root.add_child(commonboss)
        commonboss.set_attribute("deller", str(profile.get_int("deller")))
        commonboss.set_attribute("orb", str(profile.get_int("orbs")))
        commonboss.set_attribute("baron", str(profile.get_int("baron")))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()
        play_stats = self.get_play_statistics(userid)

        # Track play counts, DJ points and options
        cltype = int(request.attribute("cltype"))
        if cltype == self.GAME_CLTYPE_SINGLE:
            play_stats.increment_int("single_plays")
            play_stats.replace_int("single_dj_points", int(request.attribute("achi")))
            newprofile.replace_int("sp_opt", int(request.attribute("opt")))
        if cltype == self.GAME_CLTYPE_DOUBLE:
            play_stats.increment_int("double_plays")
            play_stats.replace_int("double_dj_points", int(request.attribute("achi")))
            newprofile.replace_int("dp_opt", int(request.attribute("opt")))
            newprofile.replace_int("dp_opt2", int(request.attribute("opt2")))

        # Profile settings
        newprofile.replace_int("gno", int(request.attribute("gno")))
        newprofile.replace_int("gpos", int(request.attribute("gpos")))
        newprofile.replace_int("timing", int(request.attribute("timing")))
        newprofile.replace_int("help", int(request.attribute("help")))
        newprofile.replace_int("sdhd", int(request.attribute("sdhd")))
        newprofile.replace_int("sdtype", int(request.attribute("sdtype")))
        newprofile.replace_float("notes", float(request.attribute("notes")))
        newprofile.replace_int("pase", int(request.attribute("pase")))
        newprofile.replace_int("judge", int(request.attribute("judge")))
        newprofile.replace_int("opstyle", int(request.attribute("opstyle")))
        newprofile.replace_float("hispeed", float(request.attribute("hispeed")))
        newprofile.replace_int("mode", int(request.attribute("mode")))
        newprofile.replace_int("pmode", int(request.attribute("pmode")))
        if "lift" in request.attributes:
            newprofile.replace_int("lift", int(request.attribute("lift")))

        # Update judge window adjustments per-machine
        judge_dict = newprofile.get_dict("machine_judge_adjust")
        machine_judge = judge_dict.get_dict(self.config.machine.pcbid)
        machine_judge.replace_int("adj", int(request.attribute("judgeAdj")))
        judge_dict.replace_dict(self.config.machine.pcbid, machine_judge)
        newprofile.replace_dict("machine_judge_adjust", judge_dict)

        # Secret flags saving
        secret = request.child("secret")
        if secret is not None:
            secret_dict = newprofile.get_dict("secret")
            secret_dict.replace_int("flg1", secret.child_value("flg1"))
            secret_dict.replace_int("flg2", secret.child_value("flg2"))
            secret_dict.replace_int("flg3", secret.child_value("flg3"))
            newprofile.replace_dict("secret", secret_dict)

        # Basic achievements
        achievements = request.child("achievements")
        if achievements is not None:
            newprofile.replace_int(
                "visit_flg", int(achievements.attribute("visit_flg"))
            )
            newprofile.replace_int(
                "last_weekly", int(achievements.attribute("last_weekly"))
            )
            newprofile.replace_int(
                "weekly_num", int(achievements.attribute("weekly_num"))
            )

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
                # We only load the first 10 in profile load.
                newprofile.replace_int_array("trophy", 10, trophies.value[:10])

        # Deller and orb saving
        commonboss = request.child("commonboss")
        if commonboss is not None:
            newprofile.replace_int(
                "deller",
                newprofile.get_int("deller") + int(commonboss.attribute("deller")),
            )
            orbs = newprofile.get_int("orbs")
            orbs = orbs + int(commonboss.attribute("orb"))
            newprofile.replace_int("orbs", orbs)

        # Step-up mode
        step = request.child("step")
        if step is not None:
            step_dict = newprofile.get_dict("step")
            if cltype == self.GAME_CLTYPE_SINGLE:
                step_dict.replace_int("sp_ach", int(step.attribute("sp_ach")))
                step_dict.replace_int("sp_hdpt", int(step.attribute("sp_hdpt")))
                step_dict.replace_int("sp_level", int(step.attribute("sp_level")))
                step_dict.replace_int("sp_round", int(step.attribute("sp_round")))
                step_dict.replace_int("sp_mplay", int(step.attribute("sp_mplay")))
            else:
                step_dict.replace_int("dp_ach", int(step.attribute("dp_ach")))
                step_dict.replace_int("dp_hdpt", int(step.attribute("dp_hdpt")))
                step_dict.replace_int("dp_level", int(step.attribute("dp_level")))
                step_dict.replace_int("dp_round", int(step.attribute("dp_round")))
                step_dict.replace_int("dp_mplay", int(step.attribute("dp_mplay")))
            step_dict.replace_int("review", int(step.attribute("review")))

            newprofile.replace_dict("step", step_dict)

        # Link5 data
        link5 = request.child("link5")
        if link5 is not None:
            link5_dict = newprofile.get_dict("link5")
            for attr in [
                "qpro",
                "glass",
                "beautiful",
                "quaver",
                "castle",
                "flip",
                "titans",
                "exusia",
                "waxing",
                "sampling",
                "beachside",
                "cuvelia",
                "reunion",
                "bad",
                "turii",
                "anisakis",
                "second",
                "whydidyou",
                "china",
                "fallen",
                "broken",
                "summer",
                "sakura",
                "wuv",
                "survival",
                "thunder",
            ]:
                link5_dict.replace_int(attr, int(link5.attribute(attr)))
            newprofile.replace_dict("link5", link5_dict)

        # Keep track of play statistics across all mixes
        self.update_play_statistics(userid, play_stats)

        return newprofile
