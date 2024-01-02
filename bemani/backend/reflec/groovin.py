from typing import Optional, Dict, Any, List, Tuple
from typing_extensions import Final

from bemani.backend.reflec.base import ReflecBeatBase
from bemani.backend.reflec.colette import ReflecBeatColette

from bemani.common import Profile, ValidatedDict, VersionConstants, ID, Time
from bemani.data import Achievement, Attempt, Score, UserID
from bemani.protocol import Node


class ReflecBeatGroovin(ReflecBeatBase):
    name: str = "REFLEC BEAT groovin'!!"
    version: int = VersionConstants.REFLEC_BEAT_GROOVIN

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

    def previous_version(self) -> Optional[ReflecBeatBase]:
        return ReflecBeatColette(self.data, self.config, self.model)

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
            "ints": [],
        }

    def __db_to_game_clear_type(self, db_status: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_PLAY,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED: self.GAME_CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_HARD_CLEARED: self.GAME_CLEAR_TYPE_HARD_CLEARED,
            self.CLEAR_TYPE_S_HARD_CLEARED: self.GAME_CLEAR_TYPE_S_HARD_CLEARED,
        }[db_status]

    def __game_to_db_clear_type(self, status: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_PLAY: self.CLEAR_TYPE_NO_PLAY,
            self.GAME_CLEAR_TYPE_EARLY_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEARED: self.CLEAR_TYPE_CLEARED,
            self.GAME_CLEAR_TYPE_HARD_CLEARED: self.CLEAR_TYPE_HARD_CLEARED,
            self.GAME_CLEAR_TYPE_S_HARD_CLEARED: self.CLEAR_TYPE_S_HARD_CLEARED,
        }[status]

    def __db_to_game_combo_type(self, db_combo: int) -> int:
        return {
            self.COMBO_TYPE_NONE: self.GAME_COMBO_TYPE_NONE,
            self.COMBO_TYPE_ALMOST_COMBO: self.GAME_COMBO_TYPE_NONE,
            self.COMBO_TYPE_FULL_COMBO: self.GAME_COMBO_TYPE_FULL_COMBO,
            self.COMBO_TYPE_FULL_COMBO_ALL_JUST: self.GAME_COMBO_TYPE_FULL_COMBO_ALL_JUST,
        }[db_combo]

    def __game_to_db_combo_type(self, game_combo: int, miss_count: int) -> int:
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

    def handle_pcb_rb4error_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_pcb_rb4uptime_update_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_pcb_rb4boot_request(self, request: Node) -> Node:
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

    def handle_lobby_rb4entry_request(self, request: Node) -> Node:
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
                    "tension": request.child_value("e/tension"),
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
            e.add_child(Node.s8("tension", lobby.get_int("tension")))

        return root

    def handle_lobby_rb4read_request(self, request: Node) -> Node:
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
                e.add_child(Node.s8("tension", lobby.get_int("tension")))

                limit = limit - 1

        return root

    def handle_lobby_rb4delete_request(self, request: Node) -> Node:
        eid = request.child_value("eid")
        self.data.local.lobby.destroy_lobby(eid)
        return Node.void("lobby")

    def handle_shop_rb4setting_write_request(self, request: Node) -> Node:
        return Node.void("shop")

    def handle_shop_rb4info_write_request(self, request: Node) -> Node:
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

    def __add_event_info(self, root: Node) -> None:
        event_ctrl = Node.void("event_ctrl")
        root.add_child(event_ctrl)
        # Contains zero or more nodes like:
        # <data>
        #     <type __type="s32">any</type>
        #     <index __type="s32">any</phase>
        #     <value __type="s32">any</phase>
        #     <value2 __type="s32">any</phase>
        #     <start_time __type="s32">any</phase>
        #     <end_time __type="s32">any</phase>
        # </data>

        item_lock_ctrl = Node.void("item_lock_ctrl")
        root.add_child(item_lock_ctrl)
        # Contains zero or more nodes like:
        # <item>
        #     <type __type="u8">any</type>
        #     <id __type="u16">any</id>
        #     <param __type="u16">0-3</param>
        # </item>

    def __add_shop_score(self, root: Node) -> None:
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

            rootnode.add_child(Node.s32("timestamp", Time.beginning_of_today() - timeoffset))

    def handle_info_rb4common_request(self, request: Node) -> Node:
        root = Node.void("info")
        self.__add_event_info(root)
        self.__add_shop_score(root)

        return root

    def handle_info_rb4ranking_request(self, request: Node) -> Node:
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

    def handle_info_rb4shop_score_ranking_request(self, request: Node) -> Node:
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
                            self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                        )
                    )
                    data.add_child(Node.s32("user_id", profile.extid))
                    data.add_child(Node.s16("icon_id", profile.get_dict("config").get_int("icon_id")))
                    data.add_child(Node.s32("score", score.points))
                    data.add_child(Node.s32("time", score.timestamp))
                    data.add_child(Node.string("name", profile.get_str("name")))

        return root

    def handle_info_rb4pzlcmt_read_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        locid = ID.parse_machine_id(request.child_value("lid"))
        limit = request.child_value("limit")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        comments = [
            achievement
            for achievement in self.data.local.user.get_all_time_based_achievements(self.game, self.version)
            if achievement[1].type == "puzzle_comment"
        ]
        comments.sort(key=lambda x: x[1].timestamp, reverse=True)
        favorites = [comment for comment in comments if comment[0] == userid]
        locationcomments = [comment for comment in comments if comment[1].data.get_int("locid") == locid]

        # Cap all comment blocks to the limit
        if limit >= 0:
            comments = comments[:limit]
            favorites = favorites[:limit]
            locationcomments = locationcomments[:limit]

        root = Node.void("info")
        comment = Node.void("comment")
        root.add_child(comment)
        comment.add_child(Node.s32("time", Time.now()))

        # Mapping of profiles to userIDs
        uid_mapping = {uid: prof for (uid, prof) in self.get_any_profiles([c[0] for c in comments])}

        # Handle anonymous comments by returning a default profile
        uid_mapping[UserID(0)] = Profile(
            self.game,
            self.version,
            "",
            0,
            {"name": "ＰＬＡＹＥＲ"},
        )

        def add_comments(name: str, selected: List[Tuple[UserID, Achievement]]) -> None:
            for uid, ach in selected:
                cmnt = Node.void(name)
                root.add_child(cmnt)
                cmnt.add_child(Node.s32("uid", uid_mapping[uid].extid))
                cmnt.add_child(Node.string("name", uid_mapping[uid].get_str("name")))
                cmnt.add_child(Node.s16("icon", ach.data.get_int("icon")))
                cmnt.add_child(Node.s8("bln", ach.data.get_int("bln")))
                cmnt.add_child(Node.string("lid", ID.format_machine_id(ach.data.get_int("locid"))))
                cmnt.add_child(Node.s8("pref", ach.data.get_int("prefecture")))
                cmnt.add_child(Node.s32("time", ach.timestamp))
                cmnt.add_child(Node.string("comment", ach.data.get_str("comment")))
                cmnt.add_child(Node.bool("is_tweet", ach.data.get_bool("tweet")))

        # Add all comments
        add_comments("c", comments)

        # Add personal comments (favorites)
        add_comments("cf", favorites)

        # Add location comments
        add_comments("cs", locationcomments)

        return root

    def handle_info_rb4pzlcmt_write_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            # Anonymous comment
            userid = UserID(0)

        icon = request.child_value("icon")
        bln = request.child_value("bln")
        locid = ID.parse_machine_id(request.child_value("lid"))
        prefecture = request.child_value("pref")
        comment = request.child_value("comment")
        is_tweet = request.child_value("is_tweet")

        # Link comment to user's profile
        self.data.local.user.put_time_based_achievement(
            self.game,
            self.version,
            userid,
            0,  # We never have an ID for this, since comments are add-only
            "puzzle_comment",
            {
                "icon": icon,
                "bln": bln,
                "locid": locid,
                "prefecture": prefecture,
                "comment": comment,
                "tweet": is_tweet,
            },
        )

        return Node.void("info")

    def handle_player_rb4start_request(self, request: Node) -> Node:
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
        self.__add_event_info(root)

        return root

    def handle_player_rb4end_request(self, request: Node) -> Node:
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

    def handle_player_rb4readepisode_request(self, request: Node) -> Node:
        extid = request.child_value("user_id")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        else:
            achievements = []

        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)
        episode = Node.void("episode")
        pdata.add_child(episode)

        for achievement in achievements:
            if achievement.type != "episode":
                continue

            info = Node.void("info")
            episode.add_child(info)
            info.add_child(Node.s32("user_id", extid))
            info.add_child(Node.u8("type", achievement.id))
            info.add_child(Node.u16("value0", achievement.data.get_int("value0")))
            info.add_child(Node.u16("value1", achievement.data.get_int("value1")))
            info.add_child(Node.string("text", achievement.data.get_str("text")))
            info.add_child(Node.s32("time", achievement.data.get_int("time")))

        return root

    def handle_player_rb4readscore_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            scores: List[Score] = []
        else:
            scores = self.data.remote.music.get_scores(self.game, self.version, userid)

        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)

        record = Node.void("record")
        pdata.add_child(record)
        record_old = Node.void("record_old")
        pdata.add_child(record_old)

        for score in scores:
            rec = Node.void("rec")
            record.add_child(rec)
            rec.add_child(Node.s16("mid", score.id))
            rec.add_child(Node.s8("ntgrd", score.chart))
            rec.add_child(Node.s32("pc", score.plays))
            rec.add_child(Node.s8("ct", self.__db_to_game_clear_type(score.data.get_int("clear_type"))))
            rec.add_child(Node.s16("ar", score.data.get_int("achievement_rate")))
            rec.add_child(Node.s16("scr", score.points))
            rec.add_child(Node.s16("ms", score.data.get_int("miss_count")))
            rec.add_child(
                Node.s16(
                    "param",
                    self.__db_to_game_combo_type(score.data.get_int("combo_type")) + score.data.get_int("param"),
                )
            )
            rec.add_child(Node.s32("bscrt", score.timestamp))
            rec.add_child(Node.s32("bart", score.data.get_int("best_achievement_rate_time")))
            rec.add_child(Node.s32("bctt", score.data.get_int("best_clear_type_time")))
            rec.add_child(Node.s32("bmst", score.data.get_int("best_miss_count_time")))
            rec.add_child(Node.s32("time", score.data.get_int("last_played_time")))

        return root

    def handle_player_rb4selectscore_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        songid = request.child_value("music_id")
        chart = request.child_value("note_grade")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            score = None
            profile = None
        else:
            score = self.data.remote.music.get_score(self.game, self.version, userid, songid, chart)
            profile = self.get_any_profile(userid)

        root = Node.void("player")
        if score is not None and profile is not None:
            player_select_score = Node.void("player_select_score")
            root.add_child(player_select_score)

            player_select_score.add_child(Node.s32("user_id", extid))
            player_select_score.add_child(Node.string("name", profile.get_str("name")))
            player_select_score.add_child(Node.s32("m_score", score.points))
            player_select_score.add_child(Node.s32("m_scoreTime", score.timestamp))
            player_select_score.add_child(Node.s16("m_iconID", profile.get_dict("config").get_int("icon_id")))
        return root

    def handle_player_rbsvLinkageSave_request(self, request: Node) -> Node:
        # I think this is ReflecBeat/SoundVoltex linkage save, and I
        # am somewhat convinced that PK/BN is for packets/blocks, but
        # whatever.
        root = Node.void("player")
        root.add_child(Node.s32("before_pk_value", -1))
        root.add_child(Node.s32("after_pk_value", -1))
        root.add_child(Node.s32("before_bn_value", -1))
        root.add_child(Node.s32("after_bn_value", -1))
        return root

    def handle_player_rb4total_bestallrank_read_request(self, request: Node) -> Node:
        # This gives us a 6-integer array mapping to user scores for the following:
        # [total score, basic chart score, medium chart score, hard chart score,
        # special chart score, new songs score].
        # It appears to return several 6-array values similar to the following:
        # <score>
        #     <rank __type="s32" __count="6">1 2 3 4 5 6</rank>
        #     <score __type="s32" __count="6">101 102 103 104 105 106</score>
        #     <allrank __type="s32" __count="6">7 8 9 10 11 12</allrank>
        # </score>
        # The first 'rank' is the displayed value for the six categories. The
        # second and third values appear unused in-game. I think this is supposed
        # to give a player the idea of what ranking they are on the server for
        # various scores.
        current_scores = request.child_value("score")

        # First, grab all scores on the network for this version, and all songs
        # available so we know which songs are new to this version of the game.
        all_scores = self.data.remote.music.get_all_scores(self.game, self.version)
        all_songs = self.data.local.music.get_all_songs(self.game, self.version)

        # Figure out what song IDs are new
        new_songs = {song.id for song in all_songs if song.data.get_int("folder", 0) == self.version}

        # Now grab all participating users that had scores
        all_users = {userid for (userid, score) in all_scores}

        # Now, group the scores by user, so we can add up the totals, only including
        # scores where the user at least cleared the song.
        scores_by_user = {
            userid: [
                score
                for (uid, score) in all_scores
                if uid == userid and score.data.get_int("clear_type") >= self.CLEAR_TYPE_CLEARED
            ]
            for userid in all_users
        }

        # Now, sum up the scores into the six categories that the game expects.
        total_scores = sorted(
            [sum([score.points for score in scores]) for userid, scores in scores_by_user.items()],
            reverse=True,
        )
        basic_scores = sorted(
            [
                sum([score.points for score in scores if score.chart == self.CHART_TYPE_BASIC])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        medium_scores = sorted(
            [
                sum([score.points for score in scores if score.chart == self.CHART_TYPE_MEDIUM])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        hard_scores = sorted(
            [
                sum([score.points for score in scores if score.chart == self.CHART_TYPE_HARD])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        special_scores = sorted(
            [
                sum([score.points for score in scores if score.chart == self.CHART_TYPE_SPECIAL])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        new_scores = sorted(
            [
                sum([score.points for score in scores if score.id in new_songs])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )

        # Guarantee that a zero score is at the end of every list, so that it makes
        # the algorithm for figuring out place have no edge case.
        total_scores.append(0)
        basic_scores.append(0)
        medium_scores.append(0)
        hard_scores.append(0)
        special_scores.append(0)
        new_scores.append(0)

        # Now, figure out where we fit based on the scores sent from the game.
        user_place = [1, 1, 1, 1, 1, 1]
        which_score = [
            total_scores,
            basic_scores,
            medium_scores,
            hard_scores,
            special_scores,
            new_scores,
        ]
        for i in range(len(user_place)):
            current_score = current_scores[i]
            scores = which_score[i]
            for score in scores:
                if current_score >= score:
                    break
                user_place[i] = user_place[i] + 1

        root = Node.void("player")
        scorenode = Node.void("score")
        root.add_child(scorenode)
        scorenode.add_child(Node.s32_array("rank", user_place))
        scorenode.add_child(Node.s32_array("score", [0] * 6))
        scorenode.add_child(Node.s32_array("allrank", [len(total_scores)] * 6))
        return root

    def handle_player_rb4delete_request(self, request: Node) -> Node:
        return Node.void("player")

    def handle_player_rb4read_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        profile = self.get_profile_by_refid(refid)
        if profile:
            return profile
        return Node.void("player")

    def handle_player_rb4succeed_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            previous_version = self.previous_version()
            profile = previous_version.get_profile(userid)
            achievements = self.data.local.user.get_achievements(
                previous_version.game, previous_version.version, userid
            )
            scores = self.data.remote.music.get_scores(previous_version.game, previous_version.version, userid)
        else:
            profile = None

        root = Node.void("player")

        if profile is None:
            # Return empty succeed to say this is new
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s16("lv", -1))
            root.add_child(Node.s32("exp", -1))
            root.add_child(Node.s32("grd", -1))
            root.add_child(Node.s32("ap", -1))
            root.add_child(Node.s32("money", -1))
            root.add_child(Node.void("released"))
            root.add_child(Node.void("mrecord"))
        else:
            # Return previous profile formatted to say this is data succession
            root.add_child(Node.string("name", profile.get_str("name")))
            root.add_child(Node.s16("lv", profile.get_int("lvl")))
            root.add_child(Node.s32("exp", profile.get_int("exp")))
            root.add_child(Node.s32("grd", profile.get_int("mg")))  # This is a guess
            root.add_child(Node.s32("ap", profile.get_int("ap")))
            root.add_child(Node.s32("money", 0))

            released = Node.void("released")
            root.add_child(released)
            for item in achievements:
                if item.type != "item_0":
                    continue

                released.add_child(Node.s16("i", item.id))

            mrecord = Node.void("mrecord")
            root.add_child(mrecord)
            for score in scores:
                mrec = Node.void("mrec")
                mrecord.add_child(mrec)
                mrec.add_child(Node.s16("mid", score.id))
                mrec.add_child(Node.s8("ntgrd", score.chart))
                mrec.add_child(Node.s32("pc", score.plays))
                mrec.add_child(
                    Node.s8(
                        "ct",
                        self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                    )
                )
                mrec.add_child(Node.s16("ar", score.data.get_int("achievement_rate")))
                mrec.add_child(Node.s16("scr", score.points))
                mrec.add_child(Node.s16("ms", score.data.get_int("miss_count")))
                mrec.add_child(Node.u16("ver", 0))
                mrec.add_child(Node.s32("bst", score.timestamp))
                mrec.add_child(Node.s32("bat", score.data.get_int("best_achievement_rate_time")))
                mrec.add_child(Node.s32("bct", score.data.get_int("best_clear_type_time")))
                mrec.add_child(Node.s32("bmt", score.data.get_int("best_miss_count_time")))

        return root

    def handle_player_rb4write_request(self, request: Node) -> Node:
        refid = request.child_value("pdata/account/rid")
        profile = self.put_profile_by_refid(refid, request)
        root = Node.void("player")

        if profile is None:
            root.add_child(Node.s32("uid", 0))
        else:
            root.add_child(Node.s32("uid", profile.extid))
        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        statistics = self.get_play_statistics(userid)
        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        links = self.data.local.user.get_links(self.game, self.version, userid)
        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)

        # Account info
        account = Node.void("account")
        pdata.add_child(account)
        account.add_child(Node.s32("usrid", profile.extid))
        account.add_child(Node.s32("tpc", statistics.total_plays))
        account.add_child(Node.s32("dpc", statistics.today_plays))
        account.add_child(Node.s32("crd", 1))
        account.add_child(Node.s32("brd", 1))
        account.add_child(Node.s32("tdc", statistics.total_days))
        account.add_child(Node.s32("intrvld", 0))
        account.add_child(Node.s16("ver", 1))
        account.add_child(Node.u64("pst", 0))
        account.add_child(Node.u64("st", Time.now() * 1000))
        account.add_child(Node.u8("debutVer", 2))

        # Base profile info
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.string("name", profile.get_str("name")))
        base.add_child(Node.s32("exp", profile.get_int("exp")))
        base.add_child(Node.s32("lv", profile.get_int("lvl")))
        base.add_child(Node.s32("mg", profile.get_int("mg")))
        base.add_child(Node.s32("ap", profile.get_int("ap")))
        base.add_child(Node.string("cmnt", ""))
        base.add_child(Node.s32("uattr", profile.get_int("uattr")))
        base.add_child(Node.s32("money", profile.get_int("money")))
        base.add_child(Node.s32("tbs", -1))
        base.add_child(Node.s32("tbs_r", -1))
        base.add_child(Node.s32("tbgs", -1))
        base.add_child(Node.s32("tbgs_r", -1))
        base.add_child(Node.s32("tbms", -1))
        base.add_child(Node.s32("tbms_r", -1))
        base.add_child(Node.s32("qe_win", -1))
        base.add_child(Node.s32("qe_legend", -1))
        base.add_child(Node.s32("qe2_win", -1))
        base.add_child(Node.s32("qe2_legend", -1))
        base.add_child(Node.s32("qe3_win", -1))
        base.add_child(Node.s32("qe3_legend", -1))
        base.add_child(Node.s16_array("mlog", [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1]))
        base.add_child(Node.s32("class", profile.get_int("class")))
        base.add_child(Node.s32("class_ar", profile.get_int("class_ar")))
        base.add_child(Node.s32("getrfl", -1))
        base.add_child(Node.s32("upper_pt", profile.get_int("upper_pt")))

        # Rivals
        rival = Node.void("rival")
        pdata.add_child(rival)
        slotid = 0
        for link in links:
            if link.type != "rival":
                continue

            rprofile = self.get_profile(link.other_userid)
            if rprofile is None:
                continue
            lobbyinfo = self.data.local.lobby.get_play_session_info(self.game, self.version, link.other_userid)
            if lobbyinfo is None:
                lobbyinfo = ValidatedDict()

            r = Node.void("r")
            rival.add_child(r)
            r.add_child(Node.s32("slot_id", slotid))
            r.add_child(Node.s32("id", rprofile.extid))
            r.add_child(Node.string("name", rprofile.get_str("name")))
            r.add_child(Node.s32("icon", profile.get_dict("config").get_int("icon_id")))
            r.add_child(Node.s32("m_level", profile.get_int("mg")))
            r.add_child(Node.s32("class", profile.get_int("class")))
            r.add_child(Node.s32("class_ar", profile.get_int("class_ar")))
            r.add_child(Node.bool("friend", True))
            r.add_child(Node.bool("target", False))
            r.add_child(Node.u32("time", lobbyinfo.get_int("time")))
            r.add_child(Node.u8_array("ga", lobbyinfo.get_int_array("ga", 4)))
            r.add_child(Node.u16("gp", lobbyinfo.get_int("gp")))
            r.add_child(Node.u8_array("ipn", lobbyinfo.get_int_array("la", 4)))
            r.add_child(Node.u8_array("pnid", lobbyinfo.get_int_array("pnid", 16)))
            slotid = slotid + 1

        # Stamps
        stamp = Node.void("stamp")
        stampdict = profile.get_dict("stamp")
        pdata.add_child(stamp)
        stamp.add_child(Node.s32_array("stmpcnt", stampdict.get_int_array("stmpcnt", 10)))
        stamp.add_child(Node.s64("area", stampdict.get_int("area")))
        stamp.add_child(Node.s64("prfvst", stampdict.get_int("prfvst")))

        # Configuration
        configdict = profile.get_dict("config")
        config = Node.void("config")
        pdata.add_child(config)
        config.add_child(Node.u8("msel_bgm", configdict.get_int("msel_bgm")))
        config.add_child(Node.u8("narrowdown_type", configdict.get_int("narrowdown_type")))
        config.add_child(Node.s16("icon_id", configdict.get_int("icon_id")))
        config.add_child(Node.s16("byword_0", configdict.get_int("byword_0")))
        config.add_child(Node.s16("byword_1", configdict.get_int("byword_1")))
        config.add_child(Node.bool("is_auto_byword_0", configdict.get_bool("is_auto_byword_0")))
        config.add_child(Node.bool("is_auto_byword_1", configdict.get_bool("is_auto_byword_1")))
        config.add_child(Node.u8("mrec_type", configdict.get_int("mrec_type")))
        config.add_child(Node.u8("tab_sel", configdict.get_int("tab_sel")))
        config.add_child(Node.u8("card_disp", configdict.get_int("card_disp")))
        config.add_child(Node.u8("score_tab_disp", configdict.get_int("score_tab_disp")))
        config.add_child(Node.s16("last_music_id", configdict.get_int("last_music_id", -1)))
        config.add_child(Node.u8("last_note_grade", configdict.get_int("last_note_grade")))
        config.add_child(Node.u8("sort_type", configdict.get_int("sort_type")))
        config.add_child(Node.u8("rival_panel_type", configdict.get_int("rival_panel_type")))
        config.add_child(Node.u64("random_entry_work", configdict.get_int("random_entry_work")))
        config.add_child(Node.u64("custom_folder_work", configdict.get_int("custom_folder_work")))
        config.add_child(Node.u8("folder_type", configdict.get_int("folder_type")))
        config.add_child(Node.u8("folder_lamp_type", configdict.get_int("folder_lamp_type")))
        config.add_child(Node.bool("is_tweet", configdict.get_bool("is_tweet")))
        config.add_child(Node.bool("is_link_twitter", configdict.get_bool("is_link_twitter")))

        # Customizations
        customdict = profile.get_dict("custom")
        custom = Node.void("custom")
        pdata.add_child(custom)
        custom.add_child(Node.u8("st_shot", customdict.get_int("st_shot")))
        custom.add_child(Node.u8("st_frame", customdict.get_int("st_frame")))
        custom.add_child(Node.u8("st_expl", customdict.get_int("st_expl")))
        custom.add_child(Node.u8("st_bg", customdict.get_int("st_bg")))
        custom.add_child(Node.u8("st_shot_vol", customdict.get_int("st_shot_vol")))
        custom.add_child(Node.u8("st_bg_bri", customdict.get_int("st_bg_bri")))
        custom.add_child(Node.u8("st_obj_size", customdict.get_int("st_obj_size")))
        custom.add_child(Node.u8("st_jr_gauge", customdict.get_int("st_jr_gauge")))
        custom.add_child(Node.u8("st_clr_gauge", customdict.get_int("st_clr_gauge")))
        custom.add_child(Node.u8("st_jdg_disp", customdict.get_int("st_jdg_disp")))
        custom.add_child(Node.u8("st_tm_disp", customdict.get_int("st_tm_disp")))
        custom.add_child(Node.u8("st_rnd", customdict.get_int("st_rnd")))
        custom.add_child(Node.u8("st_hazard", customdict.get_int("st_hazard")))
        custom.add_child(Node.u8("st_clr_cond", customdict.get_int("st_clr_cond")))
        custom.add_child(Node.s16_array("schat_0", customdict.get_int_array("schat_0", 10)))
        custom.add_child(Node.s16_array("schat_1", customdict.get_int_array("schat_1", 10)))
        custom.add_child(Node.u8("cheer_voice", customdict.get_int("cheer_voice")))
        custom.add_child(Node.u8("same_time_note_disp", customdict.get_int("same_time_note_disp")))

        # Unlocks
        released = Node.void("released")
        pdata.add_child(released)

        for item in achievements:
            if item.type[:5] != "item_":
                continue
            itemtype = int(item.type[5:])
            if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                # Don't echo unlocks when we're force unlocking, we'll do it later
                continue

            info = Node.void("info")
            released.add_child(info)
            info.add_child(Node.u8("type", itemtype))
            info.add_child(Node.u16("id", item.id))
            info.add_child(Node.u16("param", item.data.get_int("param")))

        if game_config.get_bool("force_unlock_songs"):
            ids: Dict[int, int] = {}
            songs = self.data.local.music.get_all_songs(self.game, self.version)
            for song in songs:
                if song.id not in ids:
                    ids[song.id] = 0

                if song.data.get_int("difficulty") > 0:
                    ids[song.id] = ids[song.id] | (1 << song.chart)

            for songid in ids:
                if ids[songid] == 0:
                    continue

                info = Node.void("info")
                released.add_child(info)
                info.add_child(Node.u8("type", 0))
                info.add_child(Node.u16("id", songid))
                info.add_child(Node.u16("param", ids[songid]))

        # Announcements
        announce = Node.void("announce")
        pdata.add_child(announce)

        for announcement in achievements:
            if announcement.type[:13] != "announcement_":
                continue
            announcementtype = int(announcement.type[13:])

            info = Node.void("info")
            announce.add_child(info)
            info.add_child(Node.u8("type", announcementtype))
            info.add_child(Node.u16("id", announcement.id))
            info.add_child(Node.u16("param", announcement.data.get_int("param")))
            info.add_child(Node.bool("bneedannounce", announcement.data.get_bool("need")))

        # Dojo ranking return
        dojo = Node.void("dojo")
        pdata.add_child(dojo)

        for entry in achievements:
            if entry.type != "dojo":
                continue

            rec = Node.void("rec")
            dojo.add_child(rec)
            rec.add_child(Node.s32("class", entry.id))
            rec.add_child(Node.s32("clear_type", entry.data.get_int("clear_type")))
            rec.add_child(Node.s32("total_ar", entry.data.get_int("ar")))
            rec.add_child(Node.s32("total_score", entry.data.get_int("score")))
            rec.add_child(Node.s32("play_count", entry.data.get_int("plays")))
            rec.add_child(Node.s32("last_play_time", entry.data.get_int("play_timestamp")))
            rec.add_child(Node.s32("record_update_time", entry.data.get_int("record_timestamp")))
            rec.add_child(Node.s32("rank", 0))

        # Player Parameters
        player_param = Node.void("player_param")
        pdata.add_child(player_param)

        for param in achievements:
            if param.type[:13] != "player_param_":
                continue
            itemtype = int(param.type[13:])

            itemnode = Node.void("item")
            player_param.add_child(itemnode)
            itemnode.add_child(Node.s32("type", itemtype))
            itemnode.add_child(Node.s32("bank", param.id))
            itemnode.add_child(Node.s32_array("data", param.data.get_int_array("data", 256)))

        # Shop score for players
        self.__add_shop_score(pdata)

        # Quest data
        questdict = profile.get_dict("quest")
        quest = Node.void("quest")
        pdata.add_child(quest)
        quest.add_child(Node.s16("eye_color", questdict.get_int("eye_color")))
        quest.add_child(Node.s16("body_color", questdict.get_int("body_color")))
        quest.add_child(Node.s16("item", questdict.get_int("item")))
        quest.add_child(Node.string("comment", ""))

        # Derby settings
        derby = Node.void("derby")
        pdata.add_child(derby)
        derby.add_child(Node.bool("is_open", False))

        # Codebreaking stuff
        codebreaking = Node.void("codebreaking")
        pdata.add_child(codebreaking)
        codebreaking.add_child(Node.s32("cb_id", -1))
        codebreaking.add_child(Node.s32("cb_sub_id", -1))
        codebreaking.add_child(Node.s32("music_id", -1))
        codebreaking.add_child(Node.string("question", ""))

        # Unknown IIDX link crap
        iidx_linkage = Node.void("iidx_linkage")
        pdata.add_child(iidx_linkage)
        iidx_linkage.add_child(Node.s32("linkage_id", -1))
        iidx_linkage.add_child(Node.s32("phase", -1))
        iidx_linkage.add_child(Node.s64("long_bit_0", -1))
        iidx_linkage.add_child(Node.s64("long_bit_1", -1))
        iidx_linkage.add_child(Node.s64("long_bit_2", -1))
        iidx_linkage.add_child(Node.s64("long_bit_3", -1))
        iidx_linkage.add_child(Node.s64("long_bit_4", -1))
        iidx_linkage.add_child(Node.s64("long_bit_5", -1))
        iidx_linkage.add_child(Node.s32("add_0", -1))
        iidx_linkage.add_child(Node.s32("add_1", -1))
        iidx_linkage.add_child(Node.s32("add_2", -1))
        iidx_linkage.add_child(Node.s32("add_3", -1))

        # Unknown event crap
        pue = Node.void("pue")
        pdata.add_child(pue)
        pue.add_child(Node.s32("event_id", -1))
        pue.add_child(Node.s32("point", -1))
        pue.add_child(Node.s32("value0", -1))
        pue.add_child(Node.s32("value1", -1))
        pue.add_child(Node.s32("value2", -1))
        pue.add_child(Node.s32("value3", -1))
        pue.add_child(Node.s32("value4", -1))
        pue.add_child(Node.s32("start_time", -1))
        pue.add_child(Node.s32("end_time", -1))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        game_config = self.get_game_config()
        newprofile = oldprofile.clone()

        # Save base player profile info
        newprofile.replace_int("lid", ID.parse_machine_id(request.child_value("pdata/account/lid")))
        newprofile.replace_str("name", request.child_value("pdata/base/name"))
        newprofile.replace_int("exp", request.child_value("pdata/base/exp"))
        newprofile.replace_int("lvl", request.child_value("pdata/base/lvl"))
        newprofile.replace_int("mg", request.child_value("pdata/base/mg"))
        newprofile.replace_int("ap", request.child_value("pdata/base/ap"))
        newprofile.replace_int("money", request.child_value("pdata/base/money"))
        newprofile.replace_int("class", request.child_value("pdata/base/class"))
        newprofile.replace_int("class_ar", request.child_value("pdata/base/class_ar"))
        newprofile.replace_int("upper_pt", request.child_value("pdata/base/upper_pt"))

        # Save stamps
        stampdict = newprofile.get_dict("stamp")
        stamp = request.child("pdata/stamp")
        if stamp:
            stampdict.replace_int_array("stmpcnt", 10, stamp.child_value("stmpcnt"))
            stampdict.replace_int("area", stamp.child_value("area"))
            stampdict.replace_int("prfvst", stamp.child_value("prfvst"))
        newprofile.replace_dict("stamp", stampdict)

        # Save quest stuff
        questdict = newprofile.get_dict("quest")
        quest = request.child("pdata/quest")
        if quest:
            questdict.replace_int("eye_color", quest.child_value("eye_color"))
            questdict.replace_int("body_color", quest.child_value("body_color"))
            questdict.replace_int("item", quest.child_value("item"))
        newprofile.replace_dict("quest", questdict)

        # Save player dojo
        dojo = request.child("pdata/dojo")
        if dojo:
            dojoid = dojo.child_value("class")
            clear_type = dojo.child_value("clear_type")
            ar = dojo.child_value("t_ar")
            score = dojo.child_value("t_score")

            # Figure out timestamp stuff
            data = (
                self.data.local.user.get_achievement(
                    self.game,
                    self.version,
                    userid,
                    dojoid,
                    "dojo",
                )
                or ValidatedDict()
            )

            if ar >= data.get_int("ar"):
                # We set a new achievement rate, keep the new values
                record_time = Time.now()
            else:
                # We didn't, keep the old values for achievement rate, but
                # override score and clear_type only if they were better.
                record_time = data.get_int("record_timestamp")
                ar = data.get_int("ar")
                score = max(score, data.get_int("score"))
                clear_type = max(clear_type, data.get_int("clear_type"))

            play_time = Time.now()
            plays = data.get_int("plays") + 1

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                dojoid,
                "dojo",
                {
                    "clear_type": clear_type,
                    "ar": ar,
                    "score": score,
                    "plays": plays,
                    "play_timestamp": play_time,
                    "record_timestamp": record_time,
                },
            )

        # Save player config
        configdict = newprofile.get_dict("config")
        config = request.child("pdata/config")
        if config:
            configdict.replace_int("msel_bgm", config.child_value("msel_bgm"))
            configdict.replace_int("narrowdown_type", config.child_value("narrowdown_type"))
            configdict.replace_int("icon_id", config.child_value("icon_id"))
            configdict.replace_int("byword_0", config.child_value("byword_0"))
            configdict.replace_int("byword_1", config.child_value("byword_1"))
            configdict.replace_bool("is_auto_byword_0", config.child_value("is_auto_byword_0"))
            configdict.replace_bool("is_auto_byword_1", config.child_value("is_auto_byword_1"))
            configdict.replace_int("mrec_type", config.child_value("mrec_type"))
            configdict.replace_int("tab_sel", config.child_value("tab_sel"))
            configdict.replace_int("card_disp", config.child_value("card_disp"))
            configdict.replace_int("score_tab_disp", config.child_value("score_tab_disp"))
            configdict.replace_int("last_music_id", config.child_value("last_music_id"))
            configdict.replace_int("last_note_grade", config.child_value("last_note_grade"))
            configdict.replace_int("sort_type", config.child_value("sort_type"))
            configdict.replace_int("rival_panel_type", config.child_value("rival_panel_type"))
            configdict.replace_int("random_entry_work", config.child_value("random_entry_work"))
            configdict.replace_int("custom_folder_work", config.child_value("custom_folder_work"))
            configdict.replace_int("folder_type", config.child_value("folder_type"))
            configdict.replace_int("folder_lamp_type", config.child_value("folder_lamp_type"))
            configdict.replace_bool("is_tweet", config.child_value("is_tweet"))
            configdict.replace_bool("is_link_twitter", config.child_value("is_link_twitter"))
        newprofile.replace_dict("config", configdict)

        # Save player custom settings
        customdict = newprofile.get_dict("custom")
        custom = request.child("pdata/custom")
        if custom:
            customdict.replace_int("st_shot", custom.child_value("st_shot"))
            customdict.replace_int("st_frame", custom.child_value("st_frame"))
            customdict.replace_int("st_expl", custom.child_value("st_expl"))
            customdict.replace_int("st_bg", custom.child_value("st_bg"))
            customdict.replace_int("st_shot_vol", custom.child_value("st_shot_vol"))
            customdict.replace_int("st_bg_bri", custom.child_value("st_bg_bri"))
            customdict.replace_int("st_obj_size", custom.child_value("st_obj_size"))
            customdict.replace_int("st_jr_gauge", custom.child_value("st_jr_gauge"))
            customdict.replace_int("st_clr_gauge", custom.child_value("st_clr_gauge"))
            customdict.replace_int("st_jdg_disp", custom.child_value("st_jdg_disp"))
            customdict.replace_int("st_tm_disp", custom.child_value("st_tm_disp"))
            customdict.replace_int("st_rnd", custom.child_value("st_rnd"))
            customdict.replace_int("st_hazard", custom.child_value("st_hazard"))
            customdict.replace_int("st_clr_cond", custom.child_value("st_clr_cond"))
            customdict.replace_int_array("schat_0", 10, custom.child_value("schat_0"))
            customdict.replace_int_array("schat_1", 10, custom.child_value("schat_1"))
            customdict.replace_int("cheer_voice", custom.child_value("cheer_voice"))
            customdict.replace_int("same_time_note_disp", custom.child_value("same_time_note_disp"))
        newprofile.replace_dict("custom", customdict)

        # Save player parameter info
        params = request.child("pdata/player_param")
        if params:
            for child in params.children:
                if child.name != "item":
                    continue

                item_type = child.child_value("type")
                bank = child.child_value("bank")
                paramdata = child.child_value("data") or []
                while len(paramdata) < 256:
                    paramdata.append(0)
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    bank,
                    f"player_param_{item_type}",
                    {
                        "data": paramdata,
                    },
                )

        # Save player episode info
        episode = request.child("pdata/episode")
        if episode:
            for child in episode.children:
                if child.name != "info":
                    continue

                # I assume this is copypasta, but I want to be sure
                extid = child.child_value("user_id")
                if extid != newprofile.extid:
                    raise Exception(f"Unexpected user ID, got {extid} expecting {newprofile.extid}")

                episode_type = child.child_value("type")
                episode_value0 = child.child_value("value0")
                episode_value1 = child.child_value("value1")
                episode_text = child.child_value("text")
                episode_time = child.child_value("time")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    episode_type,
                    "episode",
                    {
                        "value0": episode_value0,
                        "value1": episode_value1,
                        "text": episode_text,
                        "time": episode_time,
                    },
                )

        # Save released info
        released = request.child("pdata/released")
        if released:
            for child in released.children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                param = child.child_value("param")
                if game_config.get_bool("force_unlock_songs") and item_type == 0:
                    # Don't save unlocks when we're force unlocking
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

        # Save announce info
        announce = request.child("pdata/announce")
        if announce:
            for child in announce.children:
                if child.name != "info":
                    continue

                announce_id = child.child_value("id")
                announce_type = child.child_value("type")
                param = child.child_value("param")
                need = child.child_value("bneedannounce")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    announce_id,
                    f"announcement_{announce_type}",
                    {
                        "param": param,
                        "need": need,
                    },
                )

        # Grab any new rivals added during this play session
        rivalnode = request.child("pdata/rival")
        if rivalnode:
            for child in rivalnode.children:
                if child.name != "r":
                    continue

                extid = child.child_value("id")
                other_userid = self.data.remote.user.from_extid(self.game, self.version, extid)
                if other_userid is None:
                    continue

                self.data.local.user.put_link(
                    self.game,
                    self.version,
                    userid,
                    "rival",
                    other_userid,
                    {},
                )

        # Grab any new records set during this play session
        songplays = request.child("pdata/stglog")
        if songplays:
            for child in songplays.children:
                if child.name != "log":
                    continue

                songid = child.child_value("mid")
                chart = child.child_value("ng")
                clear_type = child.child_value("ct")
                if songid == 0 and chart == 0 and clear_type == -1:
                    # Dummy song save during profile create
                    continue

                points = child.child_value("sc")
                achievement_rate = child.child_value("ar")
                param = child.child_value("param")
                miss_count = child.child_value("jt_ms")

                # Param is some random bits along with the combo type
                combo_type = param & 0x3
                param = param ^ combo_type

                clear_type = self.__game_to_db_clear_type(clear_type)
                combo_type = self.__game_to_db_combo_type(combo_type, miss_count)
                self.update_score(
                    userid,
                    songid,
                    chart,
                    points,
                    achievement_rate,
                    clear_type,
                    combo_type,
                    miss_count,
                    param=param,
                )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
