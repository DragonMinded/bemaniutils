from typing import Optional, Dict, Any, Tuple
from typing_extensions import Final

from bemani.backend.reflec.base import ReflecBeatBase
from bemani.backend.reflec.reflecbeat import ReflecBeat

from bemani.common import Profile, VersionConstants, ID, Time
from bemani.data import UserID
from bemani.protocol import Node


class ReflecBeatLimelight(ReflecBeatBase):
    name: str = "REFLEC BEAT limelight"
    version: int = VersionConstants.REFLEC_BEAT_LIMELIGHT

    # Clear types according to the game
    GAME_CLEAR_TYPE_NO_PLAY: Final[int] = 0
    GAME_CLEAR_TYPE_FAILED: Final[int] = 2
    GAME_CLEAR_TYPE_CLEARED: Final[int] = 3
    GAME_CLEAR_TYPE_FULL_COMBO: Final[int] = 4

    # Reflec Beat Limelight requires non-expired profiles to do conversions properly
    supports_expired_profiles: bool = False

    def previous_version(self) -> Optional[ReflecBeatBase]:
        return ReflecBeat(self.data, self.config, self.model)

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
            if db_combo_type in [
                self.COMBO_TYPE_NONE,
                self.COMBO_TYPE_ALMOST_COMBO,
            ]:
                return self.GAME_CLEAR_TYPE_CLEARED
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
        if game_clear_type == self.GAME_CLEAR_TYPE_FULL_COMBO:
            return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_FULL_COMBO)

        raise Exception(f"Invalid game_clear_type {game_clear_type}")

    def handle_log_exception_request(self, request: Node) -> Node:
        return Node.void("log")

    def handle_log_pcb_status_request(self, request: Node) -> Node:
        return Node.void("log")

    def handle_log_opsetting_request(self, request: Node) -> Node:
        return Node.void("log")

    def handle_log_play_request(self, request: Node) -> Node:
        return Node.void("log")

    def handle_pcbinfo_get_request(self, request: Node) -> Node:
        shop_id = ID.parse_machine_id(request.child_value("lid"))
        machine = self.get_machine_by_id(shop_id)
        if machine is not None:
            machine_name = machine.name
            close = machine.data.get_bool("close")
            hour = machine.data.get_int("hour")
            minute = machine.data.get_int("minute")
            pref = machine.data.get_int("pref", self.get_machine_region())
        else:
            machine_name = ""
            close = False
            hour = 0
            minute = 0
            pref = self.get_machine_region()

        root = Node.void("pcbinfo")
        info = Node.void("info")
        root.add_child(info)

        info.add_child(Node.string("name", machine_name))
        info.add_child(Node.s16("pref", pref))
        info.add_child(Node.bool("close", close))
        info.add_child(Node.u8("hour", hour))
        info.add_child(Node.u8("min", minute))

        return root

    def handle_pcbinfo_set_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("info/name"))
        self.update_machine_data(
            {
                "close": request.child_value("info/close"),
                "hour": request.child_value("info/hour"),
                "minute": request.child_value("info/min"),
                "pref": request.child_value("info/pref"),
            }
        )
        return Node.void("pcbinfo")

    def __add_event_info(self, request: Node) -> None:
        events: Dict[int, int] = {}

        for _eventid, _phase in events.items():
            data = Node.void("data")
            request.add_child(data)
            data.add_child(Node.s32("type", -1))
            data.add_child(Node.s32("value", -1))

    def handle_sysinfo_get_request(self, request: Node) -> Node:
        root = Node.void("sysinfo")
        trd = Node.void("trd")
        root.add_child(trd)

        # Add event info
        self.__add_event_info(trd)

        return root

    def handle_ranking_read_request(self, request: Node) -> Node:
        root = Node.void("ranking")

        licenses = Node.void("lic_10")
        root.add_child(licenses)
        originals = Node.void("org_10")
        root.add_child(originals)

        licenses.add_child(Node.time("time", Time.now()))
        originals.add_child(Node.time("time", Time.now()))

        hitchart = self.data.local.music.get_hit_chart(self.game, self.version, 10)
        rank = 1
        for mid, _plays in hitchart:
            record = Node.void("record")
            originals.add_child(record)
            record.add_child(Node.s16("id", mid))
            record.add_child(Node.s16("rank", rank))
            rank = rank + 1

        return root

    def handle_event_r_get_all_request(self, request: Node) -> Node:
        limit = request.child_value("limit")

        comments = [
            achievement
            for achievement in self.data.local.user.get_all_time_based_achievements(self.game, self.version)
            if achievement[1].type == "puzzle_comment"
        ]
        comments.sort(key=lambda x: x[1].timestamp, reverse=True)
        statuses = self.data.local.lobby.get_all_play_session_infos(self.game, self.version)
        statuses.sort(key=lambda x: x[1]["time"], reverse=True)

        # Cap all comment blocks to the limit
        if limit >= 0:
            comments = comments[:limit]
            statuses = statuses[:limit]

        # Mapping of profiles to userIDs
        uid_mapping = {
            uid: prof for (uid, prof) in self.get_any_profiles([c[0] for c in comments] + [s[0] for s in statuses])
        }

        # Mapping of location ID to machine name
        lid_mapping: Dict[int, str] = {}

        root = Node.void("event_r")
        root.add_child(Node.s32("time", Time.now()))
        statusnode = Node.void("status")
        root.add_child(statusnode)
        commentnode = Node.void("comment")
        root.add_child(commentnode)

        for uid, comment in comments:
            lid = ID.parse_machine_id(comment.data.get_str("lid"))

            # Look up external data for the request
            if lid not in lid_mapping:
                machine = self.get_machine_by_id(lid)
                if machine is not None:
                    lid_mapping[lid] = machine.name
                else:
                    lid_mapping[lid] = ""

            c = Node.void("c")
            commentnode.add_child(c)
            c.add_child(Node.s32("uid", uid_mapping[uid].extid))
            c.add_child(Node.string("p_name", uid_mapping[uid].get_str("name")))
            c.add_child(Node.s32("exp", uid_mapping[uid].get_int("exp")))
            c.add_child(Node.s32("customize", comment.data.get_int("customize")))
            c.add_child(Node.s32("tid", comment.data.get_int("teamid")))
            c.add_child(Node.string("t_name", comment.data.get_str("teamname")))
            c.add_child(Node.string("lid", comment.data.get_str("lid")))
            c.add_child(Node.string("s_name", lid_mapping[lid]))
            c.add_child(Node.s8("pref", comment.data.get_int("prefecture")))
            c.add_child(Node.s32("time", comment.timestamp))
            c.add_child(Node.string("comment", comment.data.get_str("comment")))
            c.add_child(Node.bool("is_tweet", comment.data.get_bool("tweet")))

        for uid, status in statuses:
            lid = ID.parse_machine_id(status.get_str("lid"))

            # Look up external data for the request
            if lid not in lid_mapping:
                machine = self.get_machine_by_id(lid)
                if machine is not None:
                    lid_mapping[lid] = machine.name
                else:
                    lid_mapping[lid] = ""

            s = Node.void("s")
            statusnode.add_child(s)
            s.add_child(Node.s32("uid", uid_mapping[uid].extid))
            s.add_child(Node.string("p_name", uid_mapping[uid].get_str("name")))
            s.add_child(Node.s32("exp", uid_mapping[uid].get_int("exp")))
            s.add_child(Node.s32("customize", status.get_int("customize")))
            s.add_child(Node.s32("tid", uid_mapping[uid].get_int("team_id", -1)))
            s.add_child(Node.string("t_name", uid_mapping[uid].get_str("team_name", "")))
            s.add_child(Node.string("lid", status.get_str("lid")))
            s.add_child(Node.string("s_name", lid_mapping[lid]))
            s.add_child(Node.s8("pref", status.get_int("prefecture")))
            s.add_child(Node.s32("time", status.get_int("time")))
            s.add_child(Node.s8("status", status.get_int("status")))
            s.add_child(Node.s8("stage", status.get_int("stage")))
            s.add_child(Node.s32("mid", status.get_int("mid")))
            s.add_child(Node.s8("ng", status.get_int("ng")))

        return root

    def handle_event_w_add_comment_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            # Anonymous comment
            userid = UserID(0)

        customize = request.child_value("customize")
        lid = request.child_value("lid")
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
                "customize": customize,
                "lid": lid,
                "teamid": teamid,
                "teamname": teamname,
                "prefecture": prefecture,
                "comment": comment,
                "tweet": is_tweet,
            },
        )

        return Node.void("event_w")

    def handle_event_w_update_status_request(self, request: Node) -> Node:
        # Update user status so puzzle comments can show it
        extid = request.child_value("uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            customize = request.child_value("customize")
            status = request.child_value("status")
            stage = request.child_value("stage")
            mid = request.child_value("mid")
            ng = request.child_value("ng")
            lid = request.child_value("lid")
            prefecture = request.child_value("pref")

            self.data.local.lobby.put_play_session_info(
                self.game,
                self.version,
                userid,
                {
                    "customize": customize,
                    "status": status,
                    "stage": stage,
                    "mid": mid,
                    "ng": ng,
                    "lid": lid,
                    "prefecture": prefecture,
                },
            )
        return Node.void("event_w")

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
            e.add_child(Node.string("pn", profile.get_str("name")))
            e.add_child(Node.s32("uattr", profile.get_int("uattr")))
            e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
            e.add_child(Node.s16("mg", profile.get_int("mg")))
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

        return root

    def handle_lobby_read_request(self, request: Node) -> Node:
        root = Node.void("lobby")
        root.add_child(Node.s32("interval", 120))
        root.add_child(Node.s32("interval_p", 120))

        # Look up all lobbies matching the criteria specified
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
                e.add_child(Node.string("pn", profile.get_str("name")))
                e.add_child(Node.s32("uattr", profile.get_int("uattr")))
                e.add_child(Node.s32("mopt", lobby.get_int("mopt")))
                e.add_child(Node.s16("mg", profile.get_int("mg")))
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

                limit = limit - 1

        return root

    def handle_lobby_delete_request(self, request: Node) -> Node:
        eid = request.child_value("eid")
        self.data.local.lobby.destroy_lobby(eid)
        return Node.void("lobby")

    def handle_player_start_request(self, request: Node) -> Node:
        # Add a dummy entry into the lobby setup so we can clean up on end play
        refid = request.child_value("rid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            self.data.local.lobby.put_play_session_info(self.game, self.version, userid, {})

        root = Node.void("player")
        root.add_child(Node.bool("is_suc", True))

        unlock_music = Node.void("unlock_music")
        root.add_child(unlock_music)
        unlock_item = Node.void("unlock_item")
        root.add_child(unlock_item)
        item_lock_ctrl = Node.void("item_lock_ctrl")
        root.add_child(item_lock_ctrl)

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

        # Add event info
        self.__add_event_info(root)

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

    def handle_player_read_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        profile = self.get_profile_by_refid(refid)
        if profile:
            return profile
        return Node.void("player")

    def handle_player_write_request(self, request: Node) -> Node:
        refid = request.child_value("rid")
        profile = self.put_profile_by_refid(refid, request)
        root = Node.void("player")

        if profile is None:
            root.add_child(Node.s32("uid", 0))
        else:
            root.add_child(Node.s32("uid", profile.extid))
        root.add_child(Node.s32("time", Time.now()))
        return root

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
            root.add_child(Node.s32("lv", -1))
            root.add_child(Node.s32("exp", -1))
            root.add_child(Node.s32("grade", -1))
            root.add_child(Node.s32("ap", -1))

            root.add_child(Node.void("released"))
            root.add_child(Node.void("mrecord"))
        else:
            root.add_child(Node.string("name", profile.get_str("name")))
            root.add_child(Node.s32("lv", profile.get_int("lvl")))
            root.add_child(Node.s32("exp", profile.get_int("exp")))
            root.add_child(Node.s32("grade", profile.get_int("mg")))  # This is a guess
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
                mrec.add_child(Node.s32("mid", score.id))
                mrec.add_child(Node.s32("ctype", score.chart))
                mrec.add_child(Node.s32("win", score.data.get_dict("stats").get_int("win")))
                mrec.add_child(Node.s32("lose", score.data.get_dict("stats").get_int("win")))
                mrec.add_child(Node.s32("draw", score.data.get_dict("stats").get_int("win")))
                mrec.add_child(Node.s32("score", score.points))
                mrec.add_child(Node.s32("combo", score.data.get_int("combo")))
                mrec.add_child(Node.s32("miss", score.data.get_int("miss_count")))
                mrec.add_child(
                    Node.s32(
                        "grade",
                        self.__db_to_game_clear_type(
                            score.data.get_int("clear_type"),
                            score.data.get_int("combo_type"),
                        ),
                    )
                )
                mrec.add_child(Node.s32("ap", score.data.get_int("achievement_rate")))

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

        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.s32("uid", profile.extid))
        base.add_child(Node.string("name", profile.get_str("name")))
        base.add_child(Node.s16("icon_id", profile.get_int("icon")))
        base.add_child(Node.s16("lv", profile.get_int("lvl")))
        base.add_child(Node.s32("exp", profile.get_int("exp")))
        base.add_child(Node.s16("mg", profile.get_int("mg")))
        base.add_child(Node.s16("ap", profile.get_int("ap")))
        base.add_child(Node.s32("pc", profile.get_int("pc")))
        base.add_child(Node.s32("uattr", profile.get_int("uattr")))

        con = Node.void("con")
        pdata.add_child(con)
        con.add_child(Node.s32("day", statistics.today_plays))
        con.add_child(Node.s32("cnt", statistics.total_plays))
        con.add_child(Node.s32("total_cnt", statistics.total_plays))
        con.add_child(Node.s32("last", statistics.last_play_timestamp))
        con.add_child(Node.s32("now", Time.now()))

        team = Node.void("team")
        pdata.add_child(team)
        team.add_child(Node.s32("id", profile.get_int("team_id", -1)))
        team.add_child(Node.string("name", profile.get_str("team_name", "")))

        custom = Node.void("custom")
        customdict = profile.get_dict("custom")
        pdata.add_child(custom)
        custom.add_child(Node.u8("s_gls", customdict.get_int("s_gls")))
        custom.add_child(Node.u8("bgm_m", customdict.get_int("bgm_m")))
        custom.add_child(Node.u8("st_f", customdict.get_int("st_f")))
        custom.add_child(Node.u8("st_bg", customdict.get_int("st_bg")))
        custom.add_child(Node.u8("st_bg_b", customdict.get_int("st_bg_b")))
        custom.add_child(Node.u8("eff_e", customdict.get_int("eff_e")))
        custom.add_child(Node.u8("se_s", customdict.get_int("se_s")))
        custom.add_child(Node.u8("se_s_v", customdict.get_int("se_s_v")))
        custom.add_child(Node.s16("last_music_id", customdict.get_int("last_music_id")))
        custom.add_child(Node.u8("last_note_grade", customdict.get_int("last_note_grade")))
        custom.add_child(Node.u8("sort_type", customdict.get_int("sort_type")))
        custom.add_child(Node.u8("narrowdown_type", customdict.get_int("narrowdown_type")))
        custom.add_child(Node.bool("is_begginer", customdict.get_bool("is_begginer")))  # Yes, this is spelled right
        custom.add_child(Node.bool("is_tut", customdict.get_bool("is_tut")))
        custom.add_child(Node.s16_array("symbol_chat_0", customdict.get_int_array("symbol_chat_0", 6)))
        custom.add_child(Node.s16_array("symbol_chat_1", customdict.get_int_array("symbol_chat_1", 6)))
        custom.add_child(Node.u8("gauge_style", customdict.get_int("gauge_style")))
        custom.add_child(Node.u8("obj_shade", customdict.get_int("obj_shade")))
        custom.add_child(Node.u8("obj_size", customdict.get_int("obj_size")))
        custom.add_child(Node.s16_array("byword", customdict.get_int_array("byword", 2)))
        custom.add_child(Node.bool_array("is_auto_byword", customdict.get_bool_array("is_auto_byword", 2)))
        custom.add_child(Node.bool("is_tweet", customdict.get_bool("is_tweet")))
        custom.add_child(Node.bool("is_link_twitter", customdict.get_bool("is_link_twitter")))
        custom.add_child(Node.s16("mrec_type", customdict.get_int("mrec_type")))
        custom.add_child(Node.s16("card_disp_type", customdict.get_int("card_disp_type")))
        custom.add_child(Node.s16("tab_sel", customdict.get_int("tab_sel")))
        custom.add_child(Node.s32_array("hidden_param", customdict.get_int_array("hidden_param", 20)))

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

        # Scores
        record = Node.void("record")
        pdata.add_child(record)

        for score in scores:
            rec = Node.void("rec")
            record.add_child(rec)
            rec.add_child(Node.u16("mid", score.id))
            rec.add_child(Node.u8("ng", score.chart))
            rec.add_child(Node.s32("point", score.data.get_dict("stats").get_int("earned_points")))
            rec.add_child(Node.s32("played_time", score.timestamp))

            mrec_0 = Node.void("mrec_0")
            rec.add_child(mrec_0)
            mrec_0.add_child(Node.s32("win", score.data.get_dict("stats").get_int("win")))
            mrec_0.add_child(Node.s32("lose", score.data.get_dict("stats").get_int("lose")))
            mrec_0.add_child(Node.s32("draw", score.data.get_dict("stats").get_int("draw")))
            mrec_0.add_child(
                Node.u8(
                    "ct",
                    self.__db_to_game_clear_type(
                        score.data.get_int("clear_type"),
                        score.data.get_int("combo_type"),
                    ),
                )
            )
            mrec_0.add_child(Node.s16("ar", int(score.data.get_int("achievement_rate") / 10)))
            mrec_0.add_child(Node.s32("bs", score.points))
            mrec_0.add_child(Node.s16("mc", score.data.get_int("combo")))
            mrec_0.add_child(Node.s16("bmc", score.data.get_int("miss_count")))

            mrec_1 = Node.void("mrec_1")
            rec.add_child(mrec_1)
            mrec_1.add_child(Node.s32("win", 0))
            mrec_1.add_child(Node.s32("lose", 0))
            mrec_1.add_child(Node.s32("draw", 0))
            mrec_1.add_child(Node.u8("ct", 0))
            mrec_1.add_child(Node.s16("ar", 0))
            mrec_1.add_child(Node.s32("bs", 0))
            mrec_1.add_child(Node.s16("mc", 0))
            mrec_1.add_child(Node.s16("bmc", -1))

        # Comment (seems unused?)
        pdata.add_child(Node.string("cmnt", ""))

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
            r.add_child(Node.u8("slot_id", slotid))
            r.add_child(Node.string("name", rprofile.get_str("name")))
            r.add_child(Node.s32("id", rprofile.extid))
            r.add_child(Node.bool("friend", True))
            r.add_child(Node.bool("locked", False))
            r.add_child(Node.s32("rc", 0))
            slotid = slotid + 1

        # Glass points
        glass = Node.void("glass")
        pdata.add_child(glass)

        for item in achievements:
            if item.type != "glass":
                continue

            g = Node.void("g")
            glass.add_child(g)
            g.add_child(Node.s32("id", item.id))
            g.add_child(Node.s32("exp", item.data.get_int("exp")))

        # Favorite music
        fav_music_slot = Node.void("fav_music_slot")
        pdata.add_child(fav_music_slot)

        for item in achievements:
            if item.type != "music":
                continue

            slot = Node.void("slot")
            fav_music_slot.add_child(slot)
            slot.add_child(Node.u8("slot_id", item.id))
            slot.add_child(Node.s16("music_id", item.data.get_int("music_id")))

        narrow_down = Node.void("narrow_down")
        pdata.add_child(narrow_down)
        narrow_down.add_child(
            Node.s32_array(
                "adv_param",
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
                ],
            )
        )

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        game_config = self.get_game_config()
        newprofile = oldprofile.clone()

        newprofile.replace_int("lid", ID.parse_machine_id(request.child_value("lid")))
        newprofile.replace_str("name", request.child_value("pdata/base/name"))
        newprofile.replace_int("icon", request.child_value("pdata/base/icon_id"))
        newprofile.replace_int("lvl", request.child_value("pdata/base/lv"))
        newprofile.replace_int("exp", request.child_value("pdata/base/exp"))
        newprofile.replace_int("mg", request.child_value("pdata/base/mg"))
        newprofile.replace_int("ap", request.child_value("pdata/base/ap"))
        newprofile.replace_int("pc", request.child_value("pdata/base/pc"))
        newprofile.replace_int("uattr", request.child_value("pdata/base/uattr"))

        customdict = newprofile.get_dict("custom")
        custom = request.child("pdata/custom")
        if custom:
            customdict.replace_int("s_gls", custom.child_value("s_gls"))
            customdict.replace_int("bgm_m", custom.child_value("bgm_m"))
            customdict.replace_int("st_f", custom.child_value("st_f"))
            customdict.replace_int("st_bg", custom.child_value("st_bg"))
            customdict.replace_int("st_bg_b", custom.child_value("st_bg_b"))
            customdict.replace_int("eff_e", custom.child_value("eff_e"))
            customdict.replace_int("se_s", custom.child_value("se_s"))
            customdict.replace_int("se_s_v", custom.child_value("se_s_v"))
            customdict.replace_int("last_music_id", custom.child_value("last_music_id"))
            customdict.replace_int("last_note_grade", custom.child_value("last_note_grade"))
            customdict.replace_int("sort_type", custom.child_value("sort_type"))
            customdict.replace_int("narrowdown_type", custom.child_value("narrowdown_type"))
            customdict.replace_bool("is_begginer", custom.child_value("is_begginer"))  # Yes, this is spelled right
            customdict.replace_bool("is_tut", custom.child_value("is_tut"))
            customdict.replace_int_array("symbol_chat_0", 6, custom.child_value("symbol_chat_0"))
            customdict.replace_int_array("symbol_chat_1", 6, custom.child_value("symbol_chat_1"))
            customdict.replace_int("gauge_style", custom.child_value("gauge_style"))
            customdict.replace_int("obj_shade", custom.child_value("obj_shade"))
            customdict.replace_int("obj_size", custom.child_value("obj_size"))
            customdict.replace_int_array("byword", 2, custom.child_value("byword"))
            customdict.replace_bool_array("is_auto_byword", 2, custom.child_value("is_auto_byword"))
            customdict.replace_bool("is_tweet", custom.child_value("is_tweet"))
            customdict.replace_bool("is_link_twitter", custom.child_value("is_link_twitter"))
            customdict.replace_int("mrec_type", custom.child_value("mrec_type"))
            customdict.replace_int("card_disp_type", custom.child_value("card_disp_type"))
            customdict.replace_int("tab_sel", custom.child_value("tab_sel"))
            customdict.replace_int_array("hidden_param", 20, custom.child_value("hidden_param"))
        newprofile.replace_dict("custom", customdict)

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

        # Grab any new records set during this play session. Reflec Beat Limelight only sends
        # the top record back for songs that were played at least once during the session.
        # Note that it sends the top record, so if you play the song twice, it will return
        # only one record. Also, if you get a lower score than a previous try, it will return
        # the previous try. So, we must also look at the battle log for the actual play scores,
        # and combine the data if we can.
        savedrecords: Dict[int, Dict[int, Dict[str, int]]] = {}
        songplays = request.child("pdata/record")
        if songplays:
            for child in songplays.children:
                if child.name != "rec":
                    continue

                songid = child.child_value("mid")
                chart = child.child_value("ng")

                # These don't get sent with the battle logs, so we try to construct
                # the values here.
                if songid not in savedrecords:
                    savedrecords[songid] = {}
                savedrecords[songid][chart] = {
                    "achievement_rate": child.child_value("mrec_0/ar") * 10,
                    "points": child.child_value("mrec_0/bs"),
                    "combo": child.child_value("mrec_0/mc"),
                    "miss_count": child.child_value("mrec_0/bmc"),
                    "win": child.child_value("mrec_0/win"),
                    "lose": child.child_value("mrec_0/lose"),
                    "draw": child.child_value("mrec_0/draw"),
                    "earned_points": child.child_value("point"),
                }

        # Now, see the actual battles that were played. If we can, unify the data with a record.
        # We only do that when the record achievement rate and score matches the battle achievement
        # rate and score, so we know for a fact that that record was generated by this battle.
        battlelogs = request.child("pdata/blog")
        if battlelogs:
            for child in battlelogs.children:
                if child.name != "log":
                    continue

                songid = child.child_value("mid")
                chart = child.child_value("ng")

                clear_type = child.child_value("myself/ct")
                achievement_rate = child.child_value("myself/ar") * 10
                points = child.child_value("myself/s")

                clear_type, combo_type = self.__game_to_db_clear_type(clear_type)

                combo = None
                miss_count = -1
                stats = None

                if songid in savedrecords:
                    if chart in savedrecords[songid]:
                        data = savedrecords[songid][chart]

                        if data["achievement_rate"] == achievement_rate and data["points"] == points:
                            # This is the same record! Use the stats from it to update our
                            # internal representation.
                            combo = data["combo"]
                            miss_count = data["miss_count"]
                            stats = {
                                "win": data["win"],
                                "lose": data["lose"],
                                "draw": data["draw"],
                                "earned_points": data["earned_points"],
                            }

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
                    stats=stats,
                )

        # Keep track of glass points so unlocks work
        glass = request.child("pdata/glass")
        if glass:
            for child in glass.children:
                if child.name != "g":
                    continue

                gid = child.child_value("id")
                exp = child.child_value("exp")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    gid,
                    "glass",
                    {
                        "exp": exp,
                    },
                )

        # Keep track of favorite music selections
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

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
