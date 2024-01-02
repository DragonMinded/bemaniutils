from typing import Any, Dict, Tuple
from typing_extensions import Final

from bemani.backend.reflec.base import ReflecBeatBase

from bemani.common import Profile, VersionConstants, ID, Time
from bemani.data import UserID
from bemani.protocol import Node


class ReflecBeat(ReflecBeatBase):
    name: str = "REFLEC BEAT"
    version: int = VersionConstants.REFLEC_BEAT

    # Clear types according to the game
    GAME_CLEAR_TYPE_NO_PLAY: Final[int] = 0
    GAME_CLEAR_TYPE_PLAYED: Final[int] = 2
    GAME_CLEAR_TYPE_FULL_COMBO: Final[int] = 3

    # Reflec Beat has no profile succession
    supports_expired_profiles: bool = False

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
            return self.GAME_CLEAR_TYPE_PLAYED
        if db_clear_type in [
            self.CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_HARD_CLEARED,
            self.CLEAR_TYPE_S_HARD_CLEARED,
        ]:
            if db_combo_type in [
                self.COMBO_TYPE_NONE,
                self.COMBO_TYPE_ALMOST_COMBO,
            ]:
                return self.GAME_CLEAR_TYPE_PLAYED
            if db_combo_type in [
                self.COMBO_TYPE_FULL_COMBO,
                self.COMBO_TYPE_FULL_COMBO_ALL_JUST,
            ]:
                return self.GAME_CLEAR_TYPE_FULL_COMBO

            raise Exception(f"Invalid db_combo_type {db_combo_type}")
        raise Exception(f"Invalid db_clear_type {db_clear_type}")

    def __game_to_db_clear_type(self, game_clear_type: int, game_achievement_rate: int) -> Tuple[int, int]:
        if game_clear_type == self.GAME_CLEAR_TYPE_NO_PLAY:
            return (self.CLEAR_TYPE_NO_PLAY, self.COMBO_TYPE_NONE)
        if game_clear_type == self.GAME_CLEAR_TYPE_PLAYED:
            if game_achievement_rate >= 7000:
                return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_NONE)
            else:
                return (self.CLEAR_TYPE_FAILED, self.COMBO_TYPE_NONE)
        if game_clear_type == self.GAME_CLEAR_TYPE_FULL_COMBO:
            return (self.CLEAR_TYPE_CLEARED, self.COMBO_TYPE_FULL_COMBO)

        raise Exception(f"Invalid game_clear_type {game_clear_type}")

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

    def handle_sysinfo_fan_request(self, request: Node) -> Node:
        sysinfo = Node.void("sysinfo")
        sysinfo.add_child(Node.u8("pref", self.get_machine_region()))
        sysinfo.add_child(Node.string("lid", request.child_value("lid")))
        return sysinfo

    def handle_lobby_entry_request(self, request: Node) -> Node:
        root = Node.void("lobby")

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
                    "lid": request.child_value("e/lid"),
                    "sn": request.child_value("e/sn"),
                    "pref": request.child_value("e/pref"),
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
            e.add_child(Node.s32("exp", profile.get_int("exp")))
            e.add_child(Node.u8("mg", profile.get_int("mg")))
            e.add_child(Node.s32("tid", lobby.get_int("tid")))
            e.add_child(Node.string("tn", lobby.get_str("tn")))
            e.add_child(Node.string("lid", lobby.get_str("lid")))
            e.add_child(Node.string("sn", lobby.get_str("sn")))
            e.add_child(Node.u8("pref", lobby.get_int("pref")))
            e.add_child(Node.u8_array("ga", lobby.get_int_array("ga", 4)))
            e.add_child(Node.u16("gp", lobby.get_int("gp")))
            e.add_child(Node.u8_array("la", lobby.get_int_array("la", 4)))

        return root

    def handle_lobby_read_request(self, request: Node) -> Node:
        root = Node.void("lobby")

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
                e.add_child(Node.s32("exp", profile.get_int("exp")))
                e.add_child(Node.u8("mg", profile.get_int("mg")))
                e.add_child(Node.s32("tid", lobby.get_int("tid")))
                e.add_child(Node.string("tn", lobby.get_str("tn")))
                e.add_child(Node.string("lid", lobby.get_str("lid")))
                e.add_child(Node.string("sn", lobby.get_str("sn")))
                e.add_child(Node.u8("pref", lobby.get_int("pref")))
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

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        statistics = self.get_play_statistics(userid)
        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)

        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.s32("uid", profile.extid))
        base.add_child(Node.string("name", profile.get_str("name")))
        base.add_child(Node.s16("lv", profile.get_int("lvl")))
        base.add_child(Node.s32("exp", profile.get_int("exp")))
        base.add_child(Node.s16("mg", profile.get_int("mg")))
        base.add_child(Node.s16("ap", profile.get_int("ap")))
        base.add_child(Node.s32("flag", profile.get_int("flag")))

        con = Node.void("con")
        pdata.add_child(con)
        con.add_child(Node.s32("day", statistics.today_plays))
        con.add_child(Node.s32("cnt", statistics.total_plays))
        con.add_child(Node.s32("last", statistics.last_play_timestamp))
        con.add_child(Node.s32("now", Time.now()))

        team = Node.void("team")
        pdata.add_child(team)
        team.add_child(Node.s32("id", -1))
        team.add_child(Node.string("name", ""))

        custom = Node.void("custom")
        customdict = profile.get_dict("custom")
        pdata.add_child(custom)
        custom.add_child(Node.u8("bgm_m", customdict.get_int("bgm_m")))
        custom.add_child(Node.u8("st_f", customdict.get_int("st_f")))
        custom.add_child(Node.u8("st_bg", customdict.get_int("st_bg")))
        custom.add_child(Node.u8("st_bg_b", customdict.get_int("st_bg_b")))
        custom.add_child(Node.u8("eff_e", customdict.get_int("eff_e")))
        custom.add_child(Node.u8("se_s", customdict.get_int("se_s")))
        custom.add_child(Node.u8("se_s_v", customdict.get_int("se_s_v")))

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

        if game_config.get_bool("force_unlock_songs"):
            songs = {song.id for song in self.data.local.music.get_all_songs(self.game, self.version)}

            for songid in songs:
                info = Node.void("info")
                released.add_child(info)
                info.add_child(Node.u8("type", 0))
                info.add_child(Node.u16("id", songid))

        # Scores
        record = Node.void("record")
        pdata.add_child(record)

        for score in scores:
            rec = Node.void("rec")
            record.add_child(rec)
            rec.add_child(Node.u16("mid", score.id))
            rec.add_child(Node.u8("ng", score.chart))
            rec.add_child(Node.s32("win", score.data.get_dict("stats").get_int("win")))
            rec.add_child(Node.s32("lose", score.data.get_dict("stats").get_int("lose")))
            rec.add_child(Node.s32("draw", score.data.get_dict("stats").get_int("draw")))
            rec.add_child(
                Node.u8(
                    "ct",
                    self.__db_to_game_clear_type(
                        score.data.get_int("clear_type"),
                        score.data.get_int("combo_type"),
                    ),
                )
            )
            rec.add_child(Node.s16("ar", int(score.data.get_int("achievement_rate") / 10)))
            rec.add_child(Node.s16("bs", score.points))
            rec.add_child(Node.s16("mc", score.data.get_int("combo")))
            rec.add_child(Node.s16("bmc", score.data.get_int("miss_count")))

        # In original ReflecBeat, the entire battle log was returned for each battle.
        # We don't support storing all of that info, so don't return anything here.
        blog = Node.void("blog")
        pdata.add_child(blog)

        # Comment (seems unused?)
        pdata.add_child(Node.string("cmnt", ""))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        game_config = self.get_game_config()
        newprofile = oldprofile.clone()

        newprofile.replace_int("lid", ID.parse_machine_id(request.child_value("lid")))
        newprofile.replace_str("name", request.child_value("pdata/base/name"))
        newprofile.replace_int("lvl", request.child_value("pdata/base/lv"))
        newprofile.replace_int("exp", request.child_value("pdata/base/exp"))
        newprofile.replace_int("mg", request.child_value("pdata/base/mg"))
        newprofile.replace_int("ap", request.child_value("pdata/base/ap"))
        newprofile.replace_int("flag", request.child_value("pdata/base/flag"))

        customdict = newprofile.get_dict("custom")
        custom = request.child("pdata/custom")
        if custom:
            customdict.replace_int("bgm_m", custom.child_value("bgm_m"))
            customdict.replace_int("st_f", custom.child_value("st_f"))
            customdict.replace_int("st_bg", custom.child_value("st_bg"))
            customdict.replace_int("st_bg_b", custom.child_value("st_bg_b"))
            customdict.replace_int("eff_e", custom.child_value("eff_e"))
            customdict.replace_int("se_s", custom.child_value("se_s"))
            customdict.replace_int("se_s_v", custom.child_value("se_s_v"))
        newprofile.replace_dict("custom", customdict)

        # Music unlocks and other stuff
        released = request.child("pdata/released")
        if released:
            for child in released.children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                if game_config.get_bool("force_unlock_songs") and item_type == 0:
                    # Don't save unlocks when we're force unlocking
                    continue

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    item_id,
                    f"item_{item_type}",
                    {},
                )

        # Grab any new records set during this play session. Reflec Beat original only sends
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
                    "achievement_rate": child.child_value("ar") * 10,
                    "points": child.child_value("bs"),
                    "combo": child.child_value("mc"),
                    "miss_count": child.child_value("bmc"),
                    "win": child.child_value("win"),
                    "lose": child.child_value("lose"),
                    "draw": child.child_value("draw"),
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

                clear_type, combo_type = self.__game_to_db_clear_type(clear_type, achievement_rate)

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

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
