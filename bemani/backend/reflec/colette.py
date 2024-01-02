from typing import Optional, Dict, List, Tuple, Any
from typing_extensions import Final

from bemani.backend.reflec.base import ReflecBeatBase
from bemani.backend.reflec.limelight import ReflecBeatLimelight

from bemani.common import Profile, ValidatedDict, VersionConstants, ID, Time
from bemani.data import UserID, Achievement
from bemani.protocol import Node


class ReflecBeatColette(ReflecBeatBase):
    name: str = "REFLEC BEAT colette"
    version: int = VersionConstants.REFLEC_BEAT_COLETTE

    # Clear types according to the game
    GAME_CLEAR_TYPE_NO_PLAY: Final[int] = 0
    GAME_CLEAR_TYPE_FAILED: Final[int] = 1
    GAME_CLEAR_TYPE_CLEARED: Final[int] = 2
    GAME_CLEAR_TYPE_ALMOST_COMBO: Final[int] = 3
    GAME_CLEAR_TYPE_FULL_COMBO: Final[int] = 4

    def previous_version(self) -> Optional[ReflecBeatBase]:
        return ReflecBeatLimelight(self.data, self.config, self.model)

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

    def __db_to_game_clear_type(self, db_clear_type: int, db_combo_type: int) -> int:
        if db_clear_type == self.CLEAR_TYPE_NO_PLAY:
            return self.GAME_CLEAR_TYPE_NO_PLAY
        if db_clear_type == self.CLEAR_TYPE_FAILED:
            return self.GAME_CLEAR_TYPE_FAILED
        if db_clear_type in [
            self.CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_HARD_CLEARED,
            self.CLEAR_TYPE_S_HARD_CLEARED,
        ]:
            if db_combo_type == self.COMBO_TYPE_NONE:
                return self.GAME_CLEAR_TYPE_CLEARED
            if db_combo_type == self.COMBO_TYPE_ALMOST_COMBO:
                return self.GAME_CLEAR_TYPE_ALMOST_COMBO
            if db_combo_type in [
                self.COMBO_TYPE_FULL_COMBO,
                self.COMBO_TYPE_FULL_COMBO_ALL_JUST,
            ]:
                return self.GAME_CLEAR_TYPE_FULL_COMBO
            raise Exception(f"Invalid db_combo_type {db_combo_type}")
        raise Exception(f"Invalid db_clear_type {db_clear_type}")

    def __game_to_db_clear_type(self, game_clear_type: int) -> Tuple[int, int]:
        if game_clear_type == self.GAME_CLEAR_TYPE_NO_PLAY:
            return (self.CLEAR_TYPE_NO_PLAY, self.COMBO_TYPE_NONE)
        if game_clear_type == self.GAME_CLEAR_TYPE_FAILED:
            return (self.CLEAR_TYPE_FAILED, self.COMBO_TYPE_NONE)
        if game_clear_type == self.GAME_CLEAR_TYPE_CLEARED:
            return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_NONE)
        if game_clear_type == self.GAME_CLEAR_TYPE_ALMOST_COMBO:
            return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_ALMOST_COMBO)
        if game_clear_type == self.GAME_CLEAR_TYPE_FULL_COMBO:
            return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_FULL_COMBO)

        raise Exception(f"Invalid game_clear_type {game_clear_type}")

    def handle_pcb_error_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_pcb_uptime_update_request(self, request: Node) -> Node:
        return Node.void("pcb")

    def handle_pcb_boot_request(self, request: Node) -> Node:
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
        return root

    def handle_shop_setting_write_request(self, request: Node) -> Node:
        return Node.void("shop")

    def handle_shop_info_write_request(self, request: Node) -> Node:
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

        events: Dict[int, int] = {
            # Tricolette Park unlock event.
            9: 0,
        }

        for eventid, phase in events.items():
            data = Node.void("data")
            event_ctrl.add_child(data)
            data.add_child(Node.s32("type", eventid))
            data.add_child(Node.s32("phase", phase))

        item_lock_ctrl = Node.void("item_lock_ctrl")
        root.add_child(item_lock_ctrl)
        # Contains zero or more nodes like:
        # <item>
        #     <type __type="u8">any</type>
        #     <id __type="u16">any</id>
        #     <param __type="u16">0-3</param>
        # </item>

    def handle_info_common_request(self, request: Node) -> Node:
        root = Node.void("info")
        self.__add_event_info(root)
        return root

    def handle_info_ranking_request(self, request: Node) -> Node:
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

    def handle_info_pzlcmt_read_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        teamid = request.child_value("tid")
        limit = request.child_value("limit")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        comments = [
            achievement
            for achievement in self.data.local.user.get_all_time_based_achievements(self.game, self.version)
            if achievement[1].type == "puzzle_comment"
        ]
        comments.sort(key=lambda x: x[1].timestamp, reverse=True)
        favorites = [comment for comment in comments if comment[0] == userid]
        teamcomments = [comment for comment in comments if comment[1].data.get_int("teamid") == teamid]

        # Cap all comment blocks to the limit
        if limit >= 0:
            comments = comments[:limit]
            favorites = favorites[:limit]
            teamcomments = teamcomments[:limit]

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
                cmnt.add_child(Node.s32("tid", ach.data.get_int("teamid")))
                cmnt.add_child(Node.string("t_name", ach.data.get_str("teamname")))
                cmnt.add_child(Node.s8("pref", ach.data.get_int("prefecture")))
                cmnt.add_child(Node.s32("time", ach.timestamp))
                cmnt.add_child(Node.string("comment", ach.data.get_str("comment")))
                cmnt.add_child(Node.bool("is_tweet", ach.data.get_bool("tweet")))

        # Add all comments
        add_comments("c", comments)

        # Add personal comments (favorites)
        add_comments("cf", favorites)

        # Add team comments
        add_comments("ct", teamcomments)

        return root

    def handle_info_pzlcmt_write_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            # Anonymous comment
            userid = UserID(0)

        icon = request.child_value("icon")
        bln = request.child_value("bln")
        teamid = request.child_value("tid")
        teamname = request.child_value("t_name")
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
                "teamid": teamid,
                "teamname": teamname,
                "prefecture": prefecture,
                "comment": comment,
                "tweet": is_tweet,
            },
        )

        return Node.void("info")

    def handle_jbrbcollabo_save_request(self, request: Node) -> Node:
        jbrbcollabo = Node.void("jbrbcollabo")
        jbrbcollabo.add_child(Node.u16("marathontype", 0))
        jbrbcollabo.add_child(Node.u32("smith_start", 0))
        jbrbcollabo.add_child(Node.u32("pastel_start", 0))
        jbrbcollabo.add_child(Node.u32("smith_run", 0))
        jbrbcollabo.add_child(Node.u32("pastel_run", 0))
        jbrbcollabo.add_child(Node.u16("smith_ouen", 0))
        jbrbcollabo.add_child(Node.u16("pastel_ouen", 0))
        jbrbcollabo.add_child(Node.u32("smith_water_run", 0))
        jbrbcollabo.add_child(Node.u32("pastel_water_run", 0))
        jbrbcollabo.add_child(Node.bool("getwater", False))
        jbrbcollabo.add_child(Node.bool("smith_goal", False))
        jbrbcollabo.add_child(Node.bool("pastel_goal", False))
        jbrbcollabo.add_child(Node.u16("distancetype", 0))
        jbrbcollabo.add_child(Node.bool("run1_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_2_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_2_flg", False))
        jbrbcollabo.add_child(Node.bool("start_flg", False))
        return jbrbcollabo

    def handle_lobby_entry_request(self, request: Node) -> Node:
        root = Node.void("lobby")
        root.add_child(Node.s32("interval", 120))
        root.add_child(Node.s32("interval_p", 120))

        # Create a lobby entry for this user
        extid = request.child_value("e/uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            profile = self.get_profile(userid)
            self.data.local.lobby.put_lobby(
                self.game,
                self.version,
                userid,
                {
                    "mid": request.child_value("e/mid"),
                    "ng": request.child_value("e/ng"),
                    "mopt": request.child_value("e/mopt"),
                    "tid": request.child_value("e/tid"),
                    "tn": request.child_value("e/tn"),
                    "topt": request.child_value("e/topt"),
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
            e.add_child(Node.s16("mg", profile.get_int("mg")))
            e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
            e.add_child(Node.s32("tid", lobby.get_int("tid")))
            e.add_child(Node.string("tn", lobby.get_str("tn")))
            e.add_child(Node.s32("topt", lobby.get_int("topt")))
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

    def handle_lobby_read_request(self, request: Node) -> Node:
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
                if profile is None:
                    # No profile info, don't return this lobby
                    continue

                e = Node.void("e")
                root.add_child(e)
                e.add_child(Node.s32("eid", lobby.get_int("id")))
                e.add_child(Node.u16("mid", lobby.get_int("mid")))
                e.add_child(Node.u8("ng", lobby.get_int("ng")))
                e.add_child(Node.s32("uid", profile.extid))
                e.add_child(Node.s32("uattr", profile.get_int("uattr")))
                e.add_child(Node.string("pn", profile.get_str("name")))
                e.add_child(Node.s16("mg", profile.get_int("mg")))
                e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
                e.add_child(Node.s32("tid", lobby.get_int("tid")))
                e.add_child(Node.string("tn", lobby.get_str("tn")))
                e.add_child(Node.s32("topt", lobby.get_int("topt")))
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

    def handle_lobby_delete_request(self, request: Node) -> Node:
        eid = request.child_value("eid")
        self.data.local.lobby.destroy_lobby(eid)
        return Node.void("lobby")

    def handle_player_start_request(self, request: Node) -> Node:
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

        # Event settings and such
        lincle_link_4 = Node.void("lincle_link_4")
        root.add_child(lincle_link_4)
        lincle_link_4.add_child(Node.u32("qpro", 0))
        lincle_link_4.add_child(Node.u32("glass", 0))
        lincle_link_4.add_child(Node.u32("treasure", 0))
        lincle_link_4.add_child(Node.bool("for_iidx_0_0", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_1", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_2", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_3", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_4", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_5", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0_6", False))
        lincle_link_4.add_child(Node.bool("for_iidx_0", False))
        lincle_link_4.add_child(Node.bool("for_iidx_1", False))
        lincle_link_4.add_child(Node.bool("for_iidx_2", False))
        lincle_link_4.add_child(Node.bool("for_iidx_3", False))
        lincle_link_4.add_child(Node.bool("for_iidx_4", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_0", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_1", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_2", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_3", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_4", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_5", False))
        lincle_link_4.add_child(Node.bool("for_rb_0_6", False))
        lincle_link_4.add_child(Node.bool("for_rb_0", False))
        lincle_link_4.add_child(Node.bool("for_rb_1", False))
        lincle_link_4.add_child(Node.bool("for_rb_2", False))
        lincle_link_4.add_child(Node.bool("for_rb_3", False))
        lincle_link_4.add_child(Node.bool("for_rb_4", False))
        lincle_link_4.add_child(Node.bool("qproflg", False))
        lincle_link_4.add_child(Node.bool("glassflg", False))
        lincle_link_4.add_child(Node.bool("complete", False))

        jbrbcollabo = Node.void("jbrbcollabo")
        root.add_child(jbrbcollabo)
        jbrbcollabo.add_child(Node.bool("run1_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run1_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run2_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_2_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_3_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_4_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_2_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_3_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run3_4_flg", False))
        jbrbcollabo.add_child(Node.u16("marathontype", 0))
        jbrbcollabo.add_child(Node.u32("smith_start", 0))
        jbrbcollabo.add_child(Node.u32("pastel_start", 0))
        jbrbcollabo.add_child(Node.u16("smith_ouen", 0))
        jbrbcollabo.add_child(Node.u16("pastel_ouen", 0))
        jbrbcollabo.add_child(Node.u16("distancetype", 0))
        jbrbcollabo.add_child(Node.bool("smith_goal", False))
        jbrbcollabo.add_child(Node.bool("pastel_goal", False))
        jbrbcollabo.add_child(Node.bool("run4_1_j_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_1_r_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_2_flg", False))
        jbrbcollabo.add_child(Node.bool("run4_2_flg", False))
        jbrbcollabo.add_child(Node.bool("start_flg", False))

        tricolettepark = Node.void("tricolettepark")
        root.add_child(tricolettepark)
        tricolettepark.add_child(Node.s32("open_music", -1))
        tricolettepark.add_child(Node.s32("boss0_damage", -1))
        tricolettepark.add_child(Node.s32("boss1_damage", -1))
        tricolettepark.add_child(Node.s32("boss2_damage", -1))
        tricolettepark.add_child(Node.s32("boss3_damage", -1))
        tricolettepark.add_child(Node.s32("boss0_stun", -1))
        tricolettepark.add_child(Node.s32("boss1_stun", -1))
        tricolettepark.add_child(Node.s32("boss2_stun", -1))
        tricolettepark.add_child(Node.s32("boss3_stun", -1))
        tricolettepark.add_child(Node.s32("magic_gauge", -1))
        tricolettepark.add_child(Node.s32("today_party", -1))
        tricolettepark.add_child(Node.bool("union_magic", False))
        tricolettepark.add_child(Node.bool("is_complete", False))
        tricolettepark.add_child(Node.float("base_attack_rate", 1.0))

        return root

    def handle_player_delete_request(self, request: Node) -> Node:
        return Node.void("player")

    def handle_player_end_request(self, request: Node) -> Node:
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

    def handle_player_succeed_request(self, request: Node) -> Node:
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
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s16("lv", -1))
            root.add_child(Node.s32("exp", -1))
            root.add_child(Node.s32("grd", -1))
            root.add_child(Node.s32("ap", -1))

            root.add_child(Node.void("released"))
            root.add_child(Node.void("mrecord"))
        else:
            root.add_child(Node.string("name", profile.get_str("name")))
            root.add_child(Node.s16("lv", profile.get_int("lvl")))
            root.add_child(Node.s32("exp", profile.get_int("exp")))
            root.add_child(Node.s32("grd", profile.get_int("mg")))  # This is a guess
            root.add_child(Node.s32("ap", profile.get_int("ap")))

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
                        self.__db_to_game_clear_type(
                            score.data.get_int("clear_type"),
                            score.data.get_int("combo_type"),
                        ),
                    )
                )
                mrec.add_child(Node.s16("ar", score.data.get_int("achievement_rate")))
                mrec.add_child(Node.s16("scr", score.points))
                mrec.add_child(Node.s16("cmb", score.data.get_int("combo")))
                mrec.add_child(Node.s16("ms", score.data.get_int("miss_count")))
                mrec.add_child(Node.u16("ver", 0))

        return root

    def handle_player_read_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        profile = self.get_profile_by_refid(refid)
        if profile:
            return profile
        return Node.void("player")

    def handle_player_write_request(self, request: Node) -> Node:
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
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        links = self.data.local.user.get_links(self.game, self.version, userid)
        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)

        account = Node.void("account")
        pdata.add_child(account)
        account.add_child(Node.s32("usrid", profile.extid))
        account.add_child(Node.s32("tpc", statistics.total_plays))
        account.add_child(Node.s32("dpc", statistics.today_plays))
        account.add_child(Node.s32("crd", 1))
        account.add_child(Node.s32("brd", 1))
        account.add_child(Node.s32("tdc", statistics.total_days))
        account.add_child(Node.s32("intrvld", 0))
        account.add_child(Node.s16("ver", 5))
        account.add_child(Node.u64("pst", 0))
        account.add_child(Node.u64("st", Time.now() * 1000))

        # Base account info
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.string("name", profile.get_str("name")))
        base.add_child(Node.s32("exp", profile.get_int("exp")))
        base.add_child(Node.s32("lv", profile.get_int("lvl")))
        base.add_child(Node.s32("mg", profile.get_int("mg")))
        base.add_child(Node.s32("ap", profile.get_int("ap")))
        base.add_child(Node.s32("tid", profile.get_int("team_id", -1)))
        base.add_child(Node.string("tname", profile.get_str("team_name", "")))
        base.add_child(Node.string("cmnt", ""))
        base.add_child(Node.s32("uattr", profile.get_int("uattr")))
        base.add_child(Node.s32_array("hidden_param", profile.get_int_array("hidden_param", 50)))
        base.add_child(Node.s32("tbs", -1))
        base.add_child(Node.s32("tbs_r", -1))

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

            r = Node.void("r")
            rival.add_child(r)
            r.add_child(Node.s32("slot_id", slotid))
            r.add_child(Node.s32("id", rprofile.extid))
            r.add_child(Node.string("name", rprofile.get_str("name")))
            r.add_child(Node.bool("friend", True))
            r.add_child(Node.bool("locked", False))
            r.add_child(Node.s32("rc", 0))
            slotid = slotid + 1

        # Player customizations
        custom = Node.void("custom")
        customdict = profile.get_dict("custom")
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
        custom.add_child(Node.s16_array("schat_0", customdict.get_int_array("schat_0", 9)))
        custom.add_child(Node.s16_array("schat_1", customdict.get_int_array("schat_1", 9)))
        custom.add_child(Node.s16_array("ichat_0", customdict.get_int_array("ichat_0", 6)))
        custom.add_child(Node.s16_array("ichat_1", customdict.get_int_array("ichat_1", 6)))

        # Player external config
        config = Node.void("config")
        configdict = profile.get_dict("config")
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
        config.add_child(Node.u8("folder_lamp_type", configdict.get_int("folder_lamp_type")))
        config.add_child(Node.bool("is_tweet", configdict.get_bool("is_tweet")))
        config.add_child(Node.bool("is_link_twitter", configdict.get_bool("is_link_twitter")))

        # Stamps
        stamp = Node.void("stamp")
        stampdict = profile.get_dict("stamp")
        pdata.add_child(stamp)
        stamp.add_child(Node.s32_array("stmpcnt", stampdict.get_int_array("stmpcnt", 5)))
        stamp.add_child(Node.s32_array("tcktcnt", stampdict.get_int_array("tcktcnt", 5)))
        stamp.add_child(Node.s64("area", stampdict.get_int("area")))
        stamp.add_child(Node.s64("prfvst", stampdict.get_int("prfvst")))
        stamp.add_child(Node.s32("reserve", stampdict.get_int("reserve")))

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

        # Favorite songs
        fav_music_slot = Node.void("fav_music_slot")
        pdata.add_child(fav_music_slot)

        for item in achievements:
            if item.type != "music":
                continue

            slot = Node.void("slot")
            fav_music_slot.add_child(slot)
            slot.add_child(Node.u8("slot_id", item.id))
            slot.add_child(Node.s16("music_id", item.data.get_int("music_id")))

        # Event stuff
        order = Node.void("order")
        pdata.add_child(order)
        order.add_child(Node.s32("exp", profile.get_int("order_exp")))
        for item in achievements:
            if item.type != "order":
                continue

            data = Node.void("d")
            order.add_child(data)
            data.add_child(Node.s16("order", item.id))
            data.add_child(Node.s16("slt", item.data.get_int("slt")))
            data.add_child(Node.s32("ccnt", item.data.get_int("ccnt")))
            data.add_child(Node.s32("fcnt", item.data.get_int("fcnt")))
            data.add_child(Node.s32("fcnt1", item.data.get_int("fcnt1")))
            data.add_child(Node.s32("prm", item.data.get_int("param")))

        seedpod = Node.void("seedpod")
        pdata.add_child(seedpod)
        for item in achievements:
            if item.type != "seedpod":
                continue

            data = Node.void("data")
            seedpod.add_child(data)
            data.add_child(Node.s16("id", item.id))
            data.add_child(Node.s16("pod", item.data.get_int("pod")))

        eqpexp = Node.void("eqpexp")
        pdata.add_child(eqpexp)
        for item in achievements:
            if item.type[:7] != "eqpexp_":
                continue
            stype = int(item.type[7:])

            data = Node.void("data")
            eqpexp.add_child(data)
            data.add_child(Node.s16("id", item.id))
            data.add_child(Node.s32("exp", item.data.get_int("exp")))
            data.add_child(Node.s16("stype", stype))

        eventexp = Node.void("evntexp")
        pdata.add_child(eventexp)
        for item in achievements:
            if item.type != "eventexp":
                continue

            data = Node.void("data")
            eventexp.add_child(data)
            data.add_child(Node.s16("id", item.id))
            data.add_child(Node.s32("exp", item.data.get_int("exp")))

        # Scores
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
            rec.add_child(
                Node.s8(
                    "ct",
                    self.__db_to_game_clear_type(
                        score.data.get_int("clear_type"),
                        score.data.get_int("combo_type"),
                    ),
                )
            )
            rec.add_child(Node.s16("ar", score.data.get_int("achievement_rate")))
            rec.add_child(Node.s16("scr", score.points))
            rec.add_child(Node.s16("cmb", score.data.get_int("combo")))
            rec.add_child(Node.s16("ms", score.data.get_int("miss_count")))
            rec.add_child(Node.s32("bscrt", score.timestamp))
            rec.add_child(Node.s32("bart", score.data.get_int("best_achievement_rate_time")))
            rec.add_child(Node.s32("bctt", score.data.get_int("best_clear_type_time")))
            rec.add_child(Node.s32("bmst", score.data.get_int("best_miss_count_time")))
            rec.add_child(Node.s32("time", score.data.get_int("last_played_time")))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        game_config = self.get_game_config()
        newprofile = oldprofile.clone()

        newprofile.replace_int("lid", ID.parse_machine_id(request.child_value("pdata/account/lid")))
        newprofile.replace_str("name", request.child_value("pdata/base/name"))
        newprofile.replace_int("exp", request.child_value("pdata/base/exp"))
        newprofile.replace_int("lvl", request.child_value("pdata/base/lvl"))
        newprofile.replace_int("mg", request.child_value("pdata/base/mg"))
        newprofile.replace_int("ap", request.child_value("pdata/base/ap"))
        newprofile.replace_int_array("hidden_param", 50, request.child_value("pdata/base/hidden_param"))

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
            configdict.replace_int("folder_lamp_type", config.child_value("folder_lamp_type"))
            configdict.replace_bool("is_tweet", config.child_value("is_tweet"))
            configdict.replace_bool("is_link_twitter", config.child_value("is_link_twitter"))
        newprofile.replace_dict("config", configdict)

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
            customdict.replace_int_array("schat_0", 9, custom.child_value("schat_0"))
            customdict.replace_int_array("schat_1", 9, custom.child_value("schat_1"))
            customdict.replace_int_array("ichat_0", 6, custom.child_value("ichat_0"))
            customdict.replace_int_array("ichat_1", 6, custom.child_value("ichat_1"))
        newprofile.replace_dict("custom", customdict)

        # Stamps
        stampdict = newprofile.get_dict("stamp")
        stamp = request.child("pdata/stamp")
        if stamp:
            stampdict.replace_int_array("stmpcnt", 5, stamp.child_value("stmpcnt"))
            stampdict.replace_int_array("tcktcnt", 5, stamp.child_value("tcktcnt"))
            stampdict.replace_int("area", stamp.child_value("area"))
            stampdict.replace_int("prfvst", stamp.child_value("prfvst"))
            stampdict.replace_int("reserve", stamp.child_value("reserve"))
        newprofile.replace_dict("stamp", stampdict)

        # Unlockable orders
        newprofile.replace_int("order_exp", request.child_value("pdata/order/exp"))
        order = request.child("pdata/order")
        if order:
            for child in order.children:
                if child.name != "d":
                    continue

                orderid = child.child_value("order")
                slt = child.child_value("slt")
                ccnt = child.child_value("ccnt")
                fcnt = child.child_value("fcnt")
                fcnt1 = child.child_value("fcnt1")
                param = child.child_value("prm")

                if slt == -1:
                    # The game doesn't return valid data for this selection
                    # type, so be sure not to accidentally overwrite the
                    # finished flags.
                    continue

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    orderid,
                    "order",
                    {
                        "slt": slt,
                        "ccnt": ccnt,
                        "fcnt": fcnt,
                        "fcnt1": fcnt1,
                        "param": param,
                    },
                )

        # Music unlocks and other stuff
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

        # Favorite music
        fav_music_slot = request.child("pdata/fav_music_slot")
        if fav_music_slot:
            for child in fav_music_slot.children:
                if child.name != "slot":
                    continue

                slot_id = child.child_value("slot_id")
                music_id = child.child_value("music_id")
                if music_id == -1:
                    # Delete this favorite
                    self.data.local.user.destroy_achievement(
                        self.game,
                        self.version,
                        userid,
                        slot_id,
                        "music",
                    )
                else:
                    # Add/update this favorite
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        slot_id,
                        "music",
                        {
                            "music_id": music_id,
                        },
                    )

        # Event stuff
        seedpod = request.child("pdata/seedpod")
        if seedpod:
            for child in seedpod.children:
                if child.name != "data":
                    continue

                seedpod_id = child.child_value("id")
                seedpod_pod = child.child_value("pod")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    seedpod_id,
                    "seedpod",
                    {
                        "pod": seedpod_pod,
                    },
                )

        eventexp = request.child("pdata/evntexp")
        if eventexp:
            for child in eventexp.children:
                if child.name != "data":
                    continue

                eventexp_id = child.child_value("id")
                eventexp_exp = child.child_value("exp")

                # Experience is additive, so load it first and add the updated amount
                data = (
                    self.data.local.user.get_achievement(
                        self.game,
                        self.version,
                        userid,
                        eventexp_id,
                        "eventexp",
                    )
                    or ValidatedDict()
                )

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventexp_id,
                    "eventexp",
                    {
                        "exp": data.get_int("exp") + eventexp_exp,
                    },
                )

        eqpexp = request.child("pdata/eqpexp")
        if eqpexp:
            for child in eqpexp.children:
                if child.name != "data":
                    continue

                eqpexp_id = child.child_value("id")
                eqpexp_exp = child.child_value("exp")
                eqpexp_stype = child.child_value("stype")

                # Experience is additive, so load it first and add the updated amount
                data = (
                    self.data.local.user.get_achievement(
                        self.game,
                        self.version,
                        userid,
                        eqpexp_id,
                        f"eqpexp_{eqpexp_stype}",
                    )
                    or ValidatedDict()
                )

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    eqpexp_id,
                    f"eqpexp_{eqpexp_stype}",
                    {
                        "exp": data.get_int("exp") + eqpexp_exp,
                    },
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
                clear_type, combo_type = self.__game_to_db_clear_type(clear_type)
                combo = child.child_value("cmb")
                miss_count = child.child_value("jt_ms")
                self.update_score(
                    userid,
                    songid,
                    chart,
                    points,
                    achievement_rate,
                    clear_type,
                    combo_type,
                    miss_count,
                    combo=combo,
                )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
