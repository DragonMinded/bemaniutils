from typing import Any, Dict, List, Optional

from bemani.backend.reflec.base import ReflecBeatBase
from bemani.backend.reflec.volzzabase import ReflecBeatVolzzaBase
from bemani.backend.reflec.groovin import ReflecBeatGroovin

from bemani.common import Profile, ValidatedDict, VersionConstants, ID, Time
from bemani.data import Score, UserID
from bemani.protocol import Node


class ReflecBeatVolzza(ReflecBeatVolzzaBase):
    name: str = "REFLEC BEAT VOLZZA"
    version: int = VersionConstants.REFLEC_BEAT_VOLZZA

    def previous_version(self) -> Optional[ReflecBeatBase]:
        return ReflecBeatGroovin(self.data, self.config, self.model)

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

    def _add_event_info(self, root: Node) -> None:
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

    def handle_player_rb5_player_read_score_request(self, request: Node) -> Node:
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

        for score in scores:
            rec = Node.void("rec")
            record.add_child(rec)
            rec.add_child(Node.s16("mid", score.id))
            rec.add_child(Node.s8("ntgrd", score.chart))
            rec.add_child(Node.s32("pc", score.plays))
            rec.add_child(
                Node.s8(
                    "ct", self._db_to_game_clear_type(score.data.get_int("clear_type"))
                )
            )
            rec.add_child(Node.s16("ar", score.data.get_int("achievement_rate")))
            rec.add_child(Node.s16("scr", score.points))
            rec.add_child(Node.s16("ms", score.data.get_int("miss_count")))
            rec.add_child(
                Node.s16(
                    "param",
                    self._db_to_game_combo_type(score.data.get_int("combo_type"))
                    + score.data.get_int("param"),
                )
            )
            rec.add_child(Node.s32("bscrt", score.timestamp))
            rec.add_child(
                Node.s32("bart", score.data.get_int("best_achievement_rate_time"))
            )
            rec.add_child(Node.s32("bctt", score.data.get_int("best_clear_type_time")))
            rec.add_child(Node.s32("bmst", score.data.get_int("best_miss_count_time")))
            rec.add_child(Node.s32("time", score.data.get_int("last_played_time")))
            rec.add_child(Node.s32("k_flag", score.data.get_int("kflag")))

        return root

    def handle_player_rb5_player_read_rival_score_request(self, request: Node) -> Node:
        extid = request.child_value("uid")
        songid = request.child_value("music_id")
        chart = request.child_value("note_grade")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            score = None
            profile = None
        else:
            score = self.data.remote.music.get_score(
                self.game, self.version, userid, songid, chart
            )
            profile = self.get_any_profile(userid)

        root = Node.void("player")
        if score is not None and profile is not None:
            player_select_score = Node.void("player_select_score")
            root.add_child(player_select_score)

            player_select_score.add_child(Node.s32("user_id", extid))
            player_select_score.add_child(Node.string("name", profile.get_str("name")))
            player_select_score.add_child(Node.s32("m_score", score.points))
            player_select_score.add_child(Node.s32("m_scoreTime", score.timestamp))
            player_select_score.add_child(
                Node.s16("m_iconID", profile.get_dict("config").get_int("icon_id"))
            )
        return root

    def handle_player_rb5_player_read_rival_ranking_data_request(
        self, request: Node
    ) -> Node:
        extid = request.child_value("uid")
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        root = Node.void("player")
        rival_data = Node.void("rival_data")
        root.add_child(rival_data)

        if userid is not None:
            links = self.data.local.user.get_links(self.game, self.version, userid)
            for link in links:
                if link.type != "rival":
                    continue

                rprofile = self.get_profile(link.other_userid)
                if rprofile is None:
                    continue

                rl = Node.void("rl")
                rival_data.add_child(rl)
                rl.add_child(Node.s32("uid", rprofile.extid))
                rl.add_child(Node.string("nm", rprofile.get_str("name")))
                rl.add_child(
                    Node.s16("ic", rprofile.get_dict("config").get_int("icon_id"))
                )

                scores = self.data.remote.music.get_scores(
                    self.game, self.version, link.other_userid
                )
                scores_by_musicid: Dict[int, List[Score]] = {}
                for score in scores:
                    if score.id not in scores_by_musicid:
                        scores_by_musicid[score.id] = [None, None, None, None]
                    scores_by_musicid[score.id][score.chart] = score

                for mid, scores in scores_by_musicid.items():
                    points = [
                        score.points << 32 if score is not None else 0
                        for score in scores
                    ]
                    timestamps = [
                        score.timestamp if score is not None else 0 for score in scores
                    ]

                    sl = Node.void("sl")
                    rl.add_child(sl)
                    sl.add_child(Node.s16("mid", mid))
                    # Score, but shifted left 32 bits for no reason
                    sl.add_child(Node.u64_array("m", points))
                    # Timestamp of the clear
                    sl.add_child(Node.u64_array("t", timestamps))

        return root

    def handle_player_rb5_player_read_rank_request(self, request: Node) -> Node:
        # This gives us a 6-integer array mapping to user scores for the following:
        # [total score, basic chart score, medium chart score, hard chart score,
        # special chart score]. It also returns the previous rank, but this is
        # not used in-game as far as I can tell.
        current_scores = request.child_value("sc")
        current_minigame_score = request.child_value("mg_sc")

        # First, grab all scores on the network for this version.
        all_scores = self.data.remote.music.get_all_scores(self.game, self.version)

        # Now grab all participating users that had scores
        all_users = {userid for (userid, score) in all_scores}

        # Now, group the scores by user, so we can add up the totals, only including
        # scores where the user at least cleared the song.
        scores_by_user = {
            userid: [
                score
                for (uid, score) in all_scores
                if uid == userid
                and score.data.get_int("clear_type") >= self.CLEAR_TYPE_CLEARED
            ]
            for userid in all_users
        }

        # Now grab all user profiles for this game
        all_profiles = {
            profile[0]: profile[1]
            for profile in self.data.remote.user.get_all_profiles(
                self.game, self.version
            )
        }

        # Now, sum up the scores into the five categories that the game expects.
        total_scores = sorted(
            [
                sum([score.points for score in scores])
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        basic_scores = sorted(
            [
                sum(
                    [
                        score.points
                        for score in scores
                        if score.chart == self.CHART_TYPE_BASIC
                    ]
                )
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        medium_scores = sorted(
            [
                sum(
                    [
                        score.points
                        for score in scores
                        if score.chart == self.CHART_TYPE_MEDIUM
                    ]
                )
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        hard_scores = sorted(
            [
                sum(
                    [
                        score.points
                        for score in scores
                        if score.chart == self.CHART_TYPE_HARD
                    ]
                )
                for userid, scores in scores_by_user.items()
            ],
        )
        special_scores = sorted(
            [
                sum(
                    [
                        score.points
                        for score in scores
                        if score.chart == self.CHART_TYPE_SPECIAL
                    ]
                )
                for userid, scores in scores_by_user.items()
            ],
            reverse=True,
        )
        minigame_scores = sorted(
            [
                all_profiles.get(
                    userid, Profile(self.game, self.version, "", 0)
                ).get_int("mgsc")
                for userid in all_users
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
        minigame_scores.append(0)

        # Now, figure out where we fit based on the scores sent from the game.
        user_place = [1, 1, 1, 1, 1, 1]
        which_score = [
            total_scores,
            basic_scores,
            medium_scores,
            hard_scores,
            special_scores,
            minigame_scores,
        ]
        earned_scores = current_scores + [current_minigame_score]
        for i in range(len(user_place)):
            earned_score = earned_scores[i]
            scores = which_score[i]
            for score in scores:
                if earned_score >= score:
                    break
                user_place[i] = user_place[i] + 1

        # Separate out minigame rank from scores
        minigame_rank = user_place[-1]
        user_place = user_place[:-1]

        root = Node.void("player")

        # Populate current ranking.
        tbs = Node.void("tbs")
        root.add_child(tbs)
        tbs.add_child(Node.s32_array("new_rank", user_place))
        tbs.add_child(Node.s32_array("old_rank", [-1, -1, -1, -1, -1]))

        # Populate current minigame ranking (LOL).
        mng = Node.void("mng")
        root.add_child(mng)
        mng.add_child(Node.s32("new_rank", minigame_rank))
        mng.add_child(Node.s32("old_rank", -1))

        return root

    def handle_player_rb5_player_write_request(self, request: Node) -> Node:
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
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        links = self.data.local.user.get_links(self.game, self.version, userid)
        root = Node.void("player")
        pdata = Node.void("pdata")
        root.add_child(pdata)

        # Previous account info
        previous_version = self.previous_version()
        if previous_version:
            succeeded = previous_version.has_profile(userid)
        else:
            succeeded = False

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
        account.add_child(Node.s16("ver", 0))
        account.add_child(Node.u64("pst", 0))
        account.add_child(Node.u64("st", Time.now() * 1000))
        account.add_child(Node.bool("succeed", succeeded))
        account.add_child(Node.s32("opc", 0))
        account.add_child(Node.s32("lpc", 0))
        account.add_child(Node.s32("cpc", 0))

        # Base profile info
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.string("name", profile.get_str("name")))
        base.add_child(Node.s32("mg", profile.get_int("mg")))
        base.add_child(Node.s32("ap", profile.get_int("ap")))
        base.add_child(Node.string("cmnt", ""))
        base.add_child(Node.s32("uattr", profile.get_int("uattr")))
        base.add_child(Node.s32("money", profile.get_int("money")))
        base.add_child(Node.s32("tbs", -1))
        base.add_child(Node.s32_array("tbgs", [-1, -1, -1, -1]))
        base.add_child(
            Node.s16_array(
                "mlog",
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
                ],
            )
        )
        base.add_child(Node.s32("class", profile.get_int("class")))
        base.add_child(Node.s32("class_ar", profile.get_int("class_ar")))

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
            lobbyinfo = self.data.local.lobby.get_play_session_info(
                self.game, self.version, link.other_userid
            )
            if lobbyinfo is None:
                lobbyinfo = ValidatedDict()

            r = Node.void("r")
            rival.add_child(r)
            r.add_child(Node.s32("slot_id", slotid))
            r.add_child(Node.s32("id", rprofile.extid))
            r.add_child(Node.string("name", rprofile.get_str("name")))
            r.add_child(
                Node.s32("icon", rprofile.get_dict("config").get_int("icon_id"))
            )
            r.add_child(Node.s32("class", rprofile.get_int("class")))
            r.add_child(Node.s32("class_ar", rprofile.get_int("class_ar")))
            r.add_child(Node.bool("friend", True))
            r.add_child(Node.bool("target", False))
            r.add_child(Node.u32("time", lobbyinfo.get_int("time")))
            r.add_child(Node.u8_array("ga", lobbyinfo.get_int_array("ga", 4)))
            r.add_child(Node.u16("gp", lobbyinfo.get_int("gp")))
            r.add_child(Node.u8_array("ipn", lobbyinfo.get_int_array("la", 4)))
            r.add_child(Node.u8_array("pnid", lobbyinfo.get_int_array("pnid", 16)))
            slotid = slotid + 1

        # Configuration
        configdict = profile.get_dict("config")
        config = Node.void("config")
        pdata.add_child(config)
        config.add_child(Node.u8("msel_bgm", configdict.get_int("msel_bgm")))
        config.add_child(
            Node.u8("narrowdown_type", configdict.get_int("narrowdown_type"))
        )
        config.add_child(Node.s16("icon_id", configdict.get_int("icon_id")))
        config.add_child(Node.s16("byword_0", configdict.get_int("byword_0")))
        config.add_child(Node.s16("byword_1", configdict.get_int("byword_1")))
        config.add_child(
            Node.bool("is_auto_byword_0", configdict.get_bool("is_auto_byword_0"))
        )
        config.add_child(
            Node.bool("is_auto_byword_1", configdict.get_bool("is_auto_byword_1"))
        )
        config.add_child(Node.u8("mrec_type", configdict.get_int("mrec_type")))
        config.add_child(Node.u8("tab_sel", configdict.get_int("tab_sel")))
        config.add_child(Node.u8("card_disp", configdict.get_int("card_disp")))
        config.add_child(
            Node.u8("score_tab_disp", configdict.get_int("score_tab_disp"))
        )
        config.add_child(
            Node.s16("last_music_id", configdict.get_int("last_music_id", -1))
        )
        config.add_child(
            Node.u8("last_note_grade", configdict.get_int("last_note_grade"))
        )
        config.add_child(Node.u8("sort_type", configdict.get_int("sort_type")))
        config.add_child(
            Node.u8("rival_panel_type", configdict.get_int("rival_panel_type"))
        )
        config.add_child(
            Node.u64("random_entry_work", configdict.get_int("random_entry_work"))
        )
        config.add_child(
            Node.u64("custom_folder_work", configdict.get_int("custom_folder_work"))
        )
        config.add_child(Node.u8("folder_type", configdict.get_int("folder_type")))
        config.add_child(
            Node.u8("folder_lamp_type", configdict.get_int("folder_lamp_type"))
        )
        config.add_child(Node.bool("is_tweet", configdict.get_bool("is_tweet")))
        config.add_child(
            Node.bool("is_link_twitter", configdict.get_bool("is_link_twitter"))
        )

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
        custom.add_child(Node.u8("st_rnd", customdict.get_int("st_rnd")))
        custom.add_child(Node.u8("st_hazard", customdict.get_int("st_hazard")))
        custom.add_child(Node.u8("st_clr_cond", customdict.get_int("st_clr_cond")))
        custom.add_child(
            Node.u8("same_time_note_disp", customdict.get_int("same_time_note_disp"))
        )
        custom.add_child(
            Node.u8("st_gr_gauge_type", customdict.get_int("st_gr_gauge_type"))
        )
        custom.add_child(
            Node.s16("voice_message_set", customdict.get_int("voice_message_set", -1))
        )
        custom.add_child(
            Node.u8("voice_message_volume", customdict.get_int("voice_message_volume"))
        )

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
            info.add_child(
                Node.bool("bneedannounce", announcement.data.get_bool("need"))
            )

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
            rec.add_child(
                Node.s32("last_play_time", entry.data.get_int("play_timestamp"))
            )
            rec.add_child(
                Node.s32("record_update_time", entry.data.get_int("record_timestamp"))
            )
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
            itemnode.add_child(
                Node.s32_array("data", param.data.get_int_array("data", 256))
            )

        # Shop score for players
        self._add_shop_score(pdata)

        # My List data
        mylist = Node.void("mylist")
        pdata.add_child(mylist)
        listdata = Node.void("list")
        mylist.add_child(listdata)
        listdata.add_child(Node.s16("idx", 0))
        listdata.add_child(
            Node.s16_array("mlst", profile.get_int_array("favorites", 30, [-1] * 30))
        )

        # Minigame settings
        minigame = Node.void("minigame")
        pdata.add_child(minigame)
        minigame.add_child(Node.s8("mgid", profile.get_int("mgid")))
        minigame.add_child(Node.s32("sc", profile.get_int("mgsc")))

        # Derby settings
        derby = Node.void("derby")
        pdata.add_child(derby)
        derby.add_child(Node.bool("is_open", False))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        game_config = self.get_game_config()
        newprofile = oldprofile.clone()

        # Save base player profile info
        newprofile.replace_int(
            "lid", ID.parse_machine_id(request.child_value("pdata/account/lid"))
        )
        newprofile.replace_str("name", request.child_value("pdata/base/name"))
        newprofile.replace_int("mg", request.child_value("pdata/base/mg"))
        newprofile.replace_int("ap", request.child_value("pdata/base/ap"))
        newprofile.replace_int("uattr", request.child_value("pdata/base/uattr"))
        newprofile.replace_int("money", request.child_value("pdata/base/money"))
        newprofile.replace_int("class", request.child_value("pdata/base/class"))
        newprofile.replace_int("class_ar", request.child_value("pdata/base/class_ar"))
        newprofile.replace_int("mgid", request.child_value("pdata/minigame/mgid"))
        newprofile.replace_int("mgsc", request.child_value("pdata/minigame/sc"))
        newprofile.replace_int_array(
            "favorites", 30, request.child_value("pdata/mylist/list/mlst")
        )

        # Save player config
        configdict = newprofile.get_dict("config")
        config = request.child("pdata/config")
        if config:
            configdict.replace_int("msel_bgm", config.child_value("msel_bgm"))
            configdict.replace_int(
                "narrowdown_type", config.child_value("narrowdown_type")
            )
            configdict.replace_int("icon_id", config.child_value("icon_id"))
            configdict.replace_int("byword_0", config.child_value("byword_0"))
            configdict.replace_int("byword_1", config.child_value("byword_1"))
            configdict.replace_bool(
                "is_auto_byword_0", config.child_value("is_auto_byword_0")
            )
            configdict.replace_bool(
                "is_auto_byword_1", config.child_value("is_auto_byword_1")
            )
            configdict.replace_int("mrec_type", config.child_value("mrec_type"))
            configdict.replace_int("tab_sel", config.child_value("tab_sel"))
            configdict.replace_int("card_disp", config.child_value("card_disp"))
            configdict.replace_int(
                "score_tab_disp", config.child_value("score_tab_disp")
            )
            configdict.replace_int("last_music_id", config.child_value("last_music_id"))
            configdict.replace_int(
                "last_note_grade", config.child_value("last_note_grade")
            )
            configdict.replace_int("sort_type", config.child_value("sort_type"))
            configdict.replace_int(
                "rival_panel_type", config.child_value("rival_panel_type")
            )
            configdict.replace_int(
                "random_entry_work", config.child_value("random_entry_work")
            )
            configdict.replace_int(
                "custom_folder_work", config.child_value("custom_folder_work")
            )
            configdict.replace_int("folder_type", config.child_value("folder_type"))
            configdict.replace_int(
                "folder_lamp_type", config.child_value("folder_lamp_type")
            )
            configdict.replace_bool("is_tweet", config.child_value("is_tweet"))
            configdict.replace_bool(
                "is_link_twitter", config.child_value("is_link_twitter")
            )
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
            customdict.replace_int("st_rnd", custom.child_value("st_rnd"))
            customdict.replace_int("st_hazard", custom.child_value("st_hazard"))
            customdict.replace_int("st_clr_cond", custom.child_value("st_clr_cond"))
            customdict.replace_int(
                "same_time_note_disp", custom.child_value("same_time_note_disp")
            )
            customdict.replace_int(
                "st_gr_gauge_type", custom.child_value("st_gr_gauge_type")
            )
            customdict.replace_int(
                "voice_message_set", custom.child_value("voice_message_set")
            )
            customdict.replace_int(
                "voice_message_volume", custom.child_value("voice_message_volume")
            )
        newprofile.replace_dict("custom", customdict)

        # Save player parameter info
        params = request.child("pdata/player_param")
        if params:
            for child in params.children:
                if child.name != "item":
                    continue

                item_type = child.child_value("type")
                bank = child.child_value("bank")
                data = child.child_value("data")
                while len(data) < 256:
                    data.append(0)
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    bank,
                    f"player_param_{item_type}",
                    {
                        "data": data,
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
                    raise Exception(
                        f"Unexpected user ID, got {extid} expecting {newprofile.extid}"
                    )

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

        # Grab any new rivals added during this play session
        rivalnode = request.child("pdata/rival")
        if rivalnode:
            for child in rivalnode.children:
                if child.name != "r":
                    continue

                extid = child.child_value("id")
                other_userid = self.data.remote.user.from_extid(
                    self.game, self.version, extid
                )
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
                k_flag = child.child_value("k_flag")

                # Param is some random bits along with the combo type
                combo_type = param & 0x3
                param = param ^ combo_type

                clear_type = self._game_to_db_clear_type(clear_type)
                combo_type = self._game_to_db_combo_type(combo_type, miss_count)
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
                    kflag=k_flag,
                )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
