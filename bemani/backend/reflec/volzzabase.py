from typing import Dict, List, Tuple
from typing_extensions import Final

from bemani.backend.reflec.base import ReflecBeatBase

from bemani.common import ID, Time, Profile
from bemani.data import Attempt, UserID
from bemani.protocol import Node


class ReflecBeatVolzzaBase(ReflecBeatBase):
    # Clear types according to the game
    GAME_CLEAR_TYPE_NO_PLAY: Final[int] = 0
    GAME_CLEAR_TYPE_EARLY_FAILED: Final[int] = 1
    GAME_CLEAR_TYPE_FAILED: Final[int] = 2
    GAME_CLEAR_TYPE_CLEARED: Final[int] = 9
    GAME_CLEAR_TYPE_HARD_CLEARED: Final[int] = 10
    GAME_CLEAR_TYPE_S_HARD_CLEARED: Final[int] = 11

    # Combo types according to the game (actually a bitmask, where bit 0 is
    # full combo status, and bit 2 is just reflec status). But we don't support
    # saving just reflec without full combo, so we downgrade it.
    GAME_COMBO_TYPE_NONE: Final[int] = 0
    GAME_COMBO_TYPE_ALL_JUST: Final[int] = 2
    GAME_COMBO_TYPE_FULL_COMBO: Final[int] = 1
    GAME_COMBO_TYPE_FULL_COMBO_ALL_JUST: Final[int] = 3

    def _db_to_game_clear_type(self, db_status: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_PLAY,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED: self.GAME_CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_HARD_CLEARED: self.GAME_CLEAR_TYPE_HARD_CLEARED,
            self.CLEAR_TYPE_S_HARD_CLEARED: self.GAME_CLEAR_TYPE_S_HARD_CLEARED,
        }[db_status]

    def _game_to_db_clear_type(self, status: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_PLAY: self.CLEAR_TYPE_NO_PLAY,
            self.GAME_CLEAR_TYPE_EARLY_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEARED: self.CLEAR_TYPE_CLEARED,
            self.GAME_CLEAR_TYPE_HARD_CLEARED: self.CLEAR_TYPE_HARD_CLEARED,
            self.GAME_CLEAR_TYPE_S_HARD_CLEARED: self.CLEAR_TYPE_S_HARD_CLEARED,
        }[status]

    def _db_to_game_combo_type(self, db_combo: int) -> int:
        return {
            self.COMBO_TYPE_NONE: self.GAME_COMBO_TYPE_NONE,
            self.COMBO_TYPE_ALMOST_COMBO: self.GAME_COMBO_TYPE_NONE,
            self.COMBO_TYPE_FULL_COMBO: self.GAME_COMBO_TYPE_FULL_COMBO,
            self.COMBO_TYPE_FULL_COMBO_ALL_JUST: self.GAME_COMBO_TYPE_FULL_COMBO_ALL_JUST,
        }[db_combo]

    def _game_to_db_combo_type(self, game_combo: int, miss_count: int) -> int:
        if game_combo in [
            self.GAME_COMBO_TYPE_NONE,
            self.GAME_COMBO_TYPE_ALL_JUST,
        ]:
            if miss_count >= 0 and miss_count <= 2:
                return self.COMBO_TYPE_ALMOST_COMBO
            else:
                return self.COMBO_TYPE_NONE
        if game_combo == self.GAME_COMBO_TYPE_FULL_COMBO:
            return self.COMBO_TYPE_FULL_COMBO
        if game_combo == self.GAME_COMBO_TYPE_FULL_COMBO_ALL_JUST:
            return self.COMBO_TYPE_FULL_COMBO_ALL_JUST
        raise Exception(f"Invalid game_combo value {game_combo}")

    def _add_event_info(self, root: Node) -> None:
        # Overridden in subclasses
        pass

    def _add_shop_score(self, root: Node) -> None:
        shop_score = Node.void("shop_score")
        root.add_child(shop_score)
        today = Node.void("today")
        shop_score.add_child(today)
        yesterday = Node.void("yesterday")
        shop_score.add_child(yesterday)

        all_profiles = self.data.local.user.get_all_profiles(self.game, self.version)
        all_attempts = self.data.local.music.get_all_attempts(
            self.game,
            self.version,
            timelimit=(Time.beginning_of_today() - Time.SECONDS_IN_DAY),
        )
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        if machine.arcade is not None:
            lids = [machine.id for machine in self.data.local.machine.get_all_machines(machine.arcade)]
        else:
            lids = [machine.id]

        relevant_profiles = [profile for profile in all_profiles if profile[1].get_int("lid", -1) in lids]

        for rootnode, timeoffset in [
            (today, 0),
            (yesterday, Time.SECONDS_IN_DAY),
        ]:
            # Grab all attempts made in the relevant day
            relevant_attempts = [
                attempt
                for attempt in all_attempts
                if (
                    attempt[1].timestamp >= (Time.beginning_of_today() - timeoffset)
                    and attempt[1].timestamp <= (Time.end_of_today() - timeoffset)
                )
            ]

            # Calculate scores based on attempt
            scores_by_user: Dict[UserID, Dict[int, Dict[int, Attempt]]] = {}
            for userid, attempt in relevant_attempts:
                if userid not in scores_by_user:
                    scores_by_user[userid] = {}
                if attempt.id not in scores_by_user[userid]:
                    scores_by_user[userid][attempt.id] = {}
                if attempt.chart not in scores_by_user[userid][attempt.id]:
                    # No high score for this yet, just use this attempt
                    scores_by_user[userid][attempt.id][attempt.chart] = attempt
                else:
                    # If this attempt is better than the stored one, replace it
                    if scores_by_user[userid][attempt.id][attempt.chart].points < attempt.points:
                        scores_by_user[userid][attempt.id][attempt.chart] = attempt

            # Calculate points earned by user in the day
            points_by_user: Dict[UserID, int] = {}
            for userid in scores_by_user:
                points_by_user[userid] = 0
                for mid in scores_by_user[userid]:
                    for chart in scores_by_user[userid][mid]:
                        points_by_user[userid] = points_by_user[userid] + scores_by_user[userid][mid][chart].points

            # Output that day's earned points
            for userid, profile in relevant_profiles:
                data = Node.void("data")
                rootnode.add_child(data)
                data.add_child(Node.s16("day_id", int((Time.now() - timeoffset) / Time.SECONDS_IN_DAY)))
                data.add_child(Node.s32("user_id", profile.extid))
                data.add_child(Node.s16("icon_id", profile.get_dict("config").get_int("icon_id")))
                data.add_child(Node.s16("point", min(points_by_user.get(userid, 0), 32767)))
                data.add_child(Node.s32("update_time", Time.now()))
                data.add_child(Node.string("name", profile.get_str("name")))

            rootnode.add_child(Node.s32("time", Time.beginning_of_today() - timeoffset))

    def handle_info_rb5_info_read_request(self, request: Node) -> Node:
        root = Node.void("info")
        self._add_event_info(root)

        return root

    def handle_info_rb5_info_read_hit_chart_request(self, request: Node) -> Node:
        version = request.child_value("ver")

        root = Node.void("info")
        root.add_child(Node.s32("ver", version))
        ranking = Node.void("ranking")
        root.add_child(ranking)

        def add_hitchart(name: str, start: int, end: int, hitchart: List[Tuple[int, int]]) -> None:
            base = Node.void(name)
            ranking.add_child(base)
            base.add_child(Node.s32("bt", start))
            base.add_child(Node.s32("et", end))
            new = Node.void("new")
            base.add_child(new)

            for mid, plays in hitchart:
                d = Node.void("d")
                new.add_child(d)
                d.add_child(Node.s16("mid", mid))
                d.add_child(Node.s32("cnt", plays))

        # Weekly hit chart
        add_hitchart(
            "weekly",
            Time.now() - Time.SECONDS_IN_WEEK,
            Time.now(),
            self.data.local.music.get_hit_chart(self.game, self.version, 1024, 7),
        )

        # Monthly hit chart
        add_hitchart(
            "monthly",
            Time.now() - Time.SECONDS_IN_DAY * 30,
            Time.now(),
            self.data.local.music.get_hit_chart(self.game, self.version, 1024, 30),
        )

        # All time hit chart
        add_hitchart(
            "total",
            Time.now() - Time.SECONDS_IN_DAY * 365,
            Time.now(),
            self.data.local.music.get_hit_chart(self.game, self.version, 1024, 365),
        )

        return root

    def handle_info_rb5_info_read_shop_ranking_request(self, request: Node) -> Node:
        start_music_id = request.child_value("min")
        end_music_id = request.child_value("max")

        root = Node.void("info")
        shop_score = Node.void("shop_score")
        root.add_child(shop_score)
        shop_score.add_child(Node.s32("time", Time.now()))

        profiles: Dict[UserID, Profile] = {}
        for songid in range(start_music_id, end_music_id + 1):
            allscores = self.data.local.music.get_all_scores(
                self.game,
                self.version,
                songid=songid,
            )

            for ng in [
                self.CHART_TYPE_BASIC,
                self.CHART_TYPE_MEDIUM,
                self.CHART_TYPE_HARD,
                self.CHART_TYPE_SPECIAL,
            ]:
                scores = sorted(
                    [score for score in allscores if score[1].chart == ng],
                    key=lambda score: score[1].points,
                    reverse=True,
                )

                for i in range(len(scores)):
                    userid, score = scores[i]
                    if userid not in profiles:
                        profiles[userid] = self.get_any_profile(userid)
                    profile = profiles[userid]

                    data = Node.void("data")
                    shop_score.add_child(data)
                    data.add_child(Node.s32("rank", i + 1))
                    data.add_child(Node.s16("music_id", songid))
                    data.add_child(Node.s8("note_grade", score.chart))
                    data.add_child(
                        Node.s8(
                            "clear_type",
                            self._db_to_game_clear_type(score.data.get_int("clear_type")),
                        )
                    )
                    data.add_child(Node.s32("user_id", profile.extid))
                    data.add_child(Node.s16("icon_id", profile.get_dict("config").get_int("icon_id")))
                    data.add_child(Node.s32("score", score.points))
                    data.add_child(Node.s32("time", score.timestamp))
                    data.add_child(Node.string("name", profile.get_str("name")))

        return root

    def handle_lobby_rb5_lobby_entry_request(self, request: Node) -> Node:
        root = Node.void("lobby")
        root.add_child(Node.s32("interval", 120))
        root.add_child(Node.s32("interval_p", 120))

        # Create a lobby entry for this user
        extid = request.child_value("e/uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            profile = self.get_profile(userid)
            info = self.data.local.lobby.get_play_session_info(self.game, self.version, userid)
            if profile is None or info is None:
                return root

            self.data.local.lobby.put_lobby(
                self.game,
                self.version,
                userid,
                {
                    "mid": request.child_value("e/mid"),
                    "ng": request.child_value("e/ng"),
                    "mopt": request.child_value("e/mopt"),
                    "lid": request.child_value("e/lid"),
                    "sn": request.child_value("e/sn"),
                    "pref": request.child_value("e/pref"),
                    "stg": request.child_value("e/stg"),
                    "pside": request.child_value("e/pside"),
                    "eatime": request.child_value("e/eatime"),
                    "ga": request.child_value("e/ga"),
                    "gp": request.child_value("e/gp"),
                    "la": request.child_value("e/la"),
                    "ver": request.child_value("e/ver"),
                },
            )
            lobby = self.data.local.lobby.get_lobby(
                self.game,
                self.version,
                userid,
            )
            root.add_child(Node.s32("eid", lobby.get_int("id")))
            e = Node.void("e")
            root.add_child(e)
            e.add_child(Node.s32("eid", lobby.get_int("id")))
            e.add_child(Node.u16("mid", lobby.get_int("mid")))
            e.add_child(Node.u8("ng", lobby.get_int("ng")))
            e.add_child(Node.s32("uid", profile.extid))
            e.add_child(Node.s32("uattr", profile.get_int("uattr")))
            e.add_child(Node.string("pn", profile.get_str("name")))
            e.add_child(Node.s32("plyid", info.get_int("id")))
            e.add_child(Node.s16("mg", profile.get_int("mg")))
            e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
            e.add_child(Node.string("lid", lobby.get_str("lid")))
            e.add_child(Node.string("sn", lobby.get_str("sn")))
            e.add_child(Node.u8("pref", lobby.get_int("pref")))
            e.add_child(Node.s8("stg", lobby.get_int("stg")))
            e.add_child(Node.s8("pside", lobby.get_int("pside")))
            e.add_child(Node.s16("eatime", lobby.get_int("eatime")))
            e.add_child(Node.u8_array("ga", lobby.get_int_array("ga", 4)))
            e.add_child(Node.u16("gp", lobby.get_int("gp")))
            e.add_child(Node.u8_array("la", lobby.get_int_array("la", 4)))
            e.add_child(Node.u8("ver", lobby.get_int("ver")))

        return root

    def handle_lobby_rb5_lobby_read_request(self, request: Node) -> Node:
        root = Node.void("lobby")
        root.add_child(Node.s32("interval", 120))
        root.add_child(Node.s32("interval_p", 120))

        # Look up all lobbies matching the criteria specified
        ver = request.child_value("var")
        mg = request.child_value("m_grade")  # noqa: F841
        extid = request.child_value("uid")
        limit = request.child_value("max")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            lobbies = self.data.local.lobby.get_all_lobbies(self.game, self.version)
            for user, lobby in lobbies:
                if limit <= 0:
                    break

                if user == userid:
                    # If we have our own lobby, don't return it
                    continue
                if ver != lobby.get_int("ver"):
                    # Don't return lobby data for different versions
                    continue

                profile = self.get_profile(user)
                info = self.data.local.lobby.get_play_session_info(self.game, self.version, userid)
                if profile is None or info is None:
                    # No profile info, don't return this lobby
                    return root

                e = Node.void("e")
                root.add_child(e)
                e.add_child(Node.s32("eid", lobby.get_int("id")))
                e.add_child(Node.u16("mid", lobby.get_int("mid")))
                e.add_child(Node.u8("ng", lobby.get_int("ng")))
                e.add_child(Node.s32("uid", profile.extid))
                e.add_child(Node.s32("uattr", profile.get_int("uattr")))
                e.add_child(Node.string("pn", profile.get_str("name")))
                e.add_child(Node.s32("plyid", info.get_int("id")))
                e.add_child(Node.s16("mg", profile.get_int("mg")))
                e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
                e.add_child(Node.string("lid", lobby.get_str("lid")))
                e.add_child(Node.string("sn", lobby.get_str("sn")))
                e.add_child(Node.u8("pref", lobby.get_int("pref")))
                e.add_child(Node.s8("stg", lobby.get_int("stg")))
                e.add_child(Node.s8("pside", lobby.get_int("pside")))
                e.add_child(Node.s16("eatime", lobby.get_int("eatime")))
                e.add_child(Node.u8_array("ga", lobby.get_int_array("ga", 4)))
                e.add_child(Node.u16("gp", lobby.get_int("gp")))
                e.add_child(Node.u8_array("la", lobby.get_int_array("la", 4)))
                e.add_child(Node.u8("ver", lobby.get_int("ver")))

                limit = limit - 1

        return root

    def handle_lobby_rb5_lobby_delete_entry_request(self, request: Node) -> Node:
        eid = request.child_value("eid")
        self.data.local.lobby.destroy_lobby(eid)
        return Node.void("lobby")

    def handle_pcb_rb5_pcb_boot_request(self, request: Node) -> Node:
        shop_id = ID.parse_machine_id(request.child_value("lid"))
        machine = self.get_machine_by_id(shop_id)
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

        root = Node.void("pcb")
        sinfo = Node.void("sinfo")
        root.add_child(sinfo)
        sinfo.add_child(Node.string("nm", machine_name))
        sinfo.add_child(Node.bool("cl_enbl", close))
        sinfo.add_child(Node.u8("cl_h", hour))
        sinfo.add_child(Node.u8("cl_m", minute))
        sinfo.add_child(Node.bool("shop_flag", True))
        return root

    def handle_pcb_rb5_pcb_error_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_pcb_rb5_pcb_update_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_shop_rb5_shop_write_setting_request(self, request: Node) -> Node:
        return Node.void("shop")

    def handle_shop_rb5_shop_write_info_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("sinfo/nm"))
        self.update_machine_data(
            {
                "close": request.child_value("sinfo/cl_enbl"),
                "hour": request.child_value("sinfo/cl_h"),
                "minute": request.child_value("sinfo/cl_m"),
                "pref": request.child_value("sinfo/prf"),
            }
        )
        return Node.void("shop")

    def handle_player_rb5_player_start_request(self, request: Node) -> Node:
        root = Node.void("player")

        # Create a new play session based on info from the request
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            self.data.local.lobby.put_play_session_info(
                self.game,
                self.version,
                userid,
                {
                    "ga": request.child_value("ga"),
                    "gp": request.child_value("gp"),
                    "la": request.child_value("la"),
                    "pnid": request.child_value("pnid"),
                },
            )
            info = self.data.local.lobby.get_play_session_info(
                self.game,
                self.version,
                userid,
            )
            if info is not None:
                play_id = info.get_int("id")
            else:
                play_id = 0
        else:
            play_id = 0

        # Session stuff, and resend global defaults
        root.add_child(Node.s32("plyid", play_id))
        root.add_child(Node.u64("start_time", Time.now() * 1000))
        self._add_event_info(root)

        return root

    def handle_player_rb5_player_end_request(self, request: Node) -> Node:
        # Destroy play session based on info from the request
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            # Kill any lingering lobbies by this user
            lobby = self.data.local.lobby.get_lobby(
                self.game,
                self.version,
                userid,
            )
            if lobby is not None:
                self.data.local.lobby.destroy_lobby(lobby.get_int("id"))
            self.data.local.lobby.destroy_play_session_info(self.game, self.version, userid)

        return Node.void("player")

    def handle_player_rb5_player_delete_request(self, request: Node) -> Node:
        return Node.void("player")

    def handle_player_rb5_player_succeed_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            previous_version = self.previous_version()
            profile = previous_version.get_profile(userid)
        else:
            profile = None

        root = Node.void("player")

        if profile is None:
            # Return empty succeed to say this is new
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s32("grd", -1))
            root.add_child(Node.s32("ap", -1))
            root.add_child(Node.s32("uattr", 0))
        else:
            # Return previous profile formatted to say this is data succession
            root.add_child(Node.string("name", profile.get_str("name")))
            root.add_child(Node.s32("grd", profile.get_int("mg")))  # This is a guess
            root.add_child(Node.s32("ap", profile.get_int("ap")))
            root.add_child(Node.s32("uattr", profile.get_int("uattr")))
        return root

    def handle_player_rb5_player_read_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        profile = self.get_profile_by_refid(refid)
        if profile:
            return profile
        return Node.void("player")
