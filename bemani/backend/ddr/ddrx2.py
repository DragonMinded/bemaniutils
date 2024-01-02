# vim: set fileencoding=utf-8
from typing import Dict, List, Optional, Tuple
from typing_extensions import Final

from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.stubs import DDRX
from bemani.backend.ddr.common import (
    DDRGameFriendHandler,
    DDRGameLockHandler,
    DDRGameLoadCourseHandler,
    DDRGameLoadHandler,
    DDRGameLogHandler,
    DDRGameMessageHandler,
    DDRGameNewHandler,
    DDRGameOldHandler,
    DDRGameRankingHandler,
    DDRGameSaveCourseHandler,
    DDRGameSaveHandler,
    DDRGameScoreHandler,
    DDRGameShopHandler,
    DDRGameTraceHandler,
)
from bemani.common import Time, VersionConstants, Profile, intish
from bemani.data import Score, UserID
from bemani.protocol import Node


class DDRX2(
    DDRGameFriendHandler,
    DDRGameLockHandler,
    DDRGameLoadCourseHandler,
    DDRGameLoadHandler,
    DDRGameLogHandler,
    DDRGameMessageHandler,
    DDRGameOldHandler,
    DDRGameNewHandler,
    DDRGameRankingHandler,
    DDRGameSaveCourseHandler,
    DDRGameSaveHandler,
    DDRGameScoreHandler,
    DDRGameShopHandler,
    DDRGameTraceHandler,
    DDRBase,
):
    name: str = "DanceDanceRevolution X2"
    version: int = VersionConstants.DDR_X2

    GAME_STYLE_SINGLE: Final[int] = 0
    GAME_STYLE_DOUBLE: Final[int] = 1
    GAME_STYLE_VERSUS: Final[int] = 2

    GAME_RANK_AAA: Final[int] = 1
    GAME_RANK_AA: Final[int] = 2
    GAME_RANK_A: Final[int] = 3
    GAME_RANK_B: Final[int] = 4
    GAME_RANK_C: Final[int] = 5
    GAME_RANK_D: Final[int] = 6
    GAME_RANK_E: Final[int] = 7

    GAME_CHART_SINGLE_BEGINNER: Final[int] = 0
    GAME_CHART_SINGLE_BASIC: Final[int] = 1
    GAME_CHART_SINGLE_DIFFICULT: Final[int] = 2
    GAME_CHART_SINGLE_EXPERT: Final[int] = 3
    GAME_CHART_SINGLE_CHALLENGE: Final[int] = 4
    GAME_CHART_DOUBLE_BASIC: Final[int] = 5
    GAME_CHART_DOUBLE_DIFFICULT: Final[int] = 6
    GAME_CHART_DOUBLE_EXPERT: Final[int] = 7
    GAME_CHART_DOUBLE_CHALLENGE: Final[int] = 8

    GAME_HALO_NONE: Final[int] = 0
    GAME_HALO_FULL_COMBO: Final[int] = 1
    GAME_HALO_PERFECT_COMBO: Final[int] = 2
    GAME_HALO_MARVELOUS_COMBO: Final[int] = 3

    GAME_MAX_SONGS: Final[int] = 600

    def previous_version(self) -> Optional[DDRBase]:
        return DDRX(self.data, self.config, self.model)

    def game_to_db_rank(self, game_rank: int) -> int:
        return {
            self.GAME_RANK_AAA: self.RANK_AAA,
            self.GAME_RANK_AA: self.RANK_AA,
            self.GAME_RANK_A: self.RANK_A,
            self.GAME_RANK_B: self.RANK_B,
            self.GAME_RANK_C: self.RANK_C,
            self.GAME_RANK_D: self.RANK_D,
            self.GAME_RANK_E: self.RANK_E,
        }[game_rank]

    def db_to_game_rank(self, db_rank: int) -> int:
        return {
            self.RANK_AAA: self.GAME_RANK_AAA,
            self.RANK_AA_PLUS: self.GAME_RANK_AA,
            self.RANK_AA: self.GAME_RANK_AA,
            self.RANK_AA_MINUS: self.GAME_RANK_A,
            self.RANK_A_PLUS: self.GAME_RANK_A,
            self.RANK_A: self.GAME_RANK_A,
            self.RANK_A_MINUS: self.GAME_RANK_B,
            self.RANK_B_PLUS: self.GAME_RANK_B,
            self.RANK_B: self.GAME_RANK_B,
            self.RANK_B_MINUS: self.GAME_RANK_C,
            self.RANK_C_PLUS: self.GAME_RANK_C,
            self.RANK_C: self.GAME_RANK_C,
            self.RANK_C_MINUS: self.GAME_RANK_D,
            self.RANK_D_PLUS: self.GAME_RANK_D,
            self.RANK_D: self.GAME_RANK_D,
            self.RANK_E: self.GAME_RANK_E,
        }[db_rank]

    def game_to_db_chart(self, game_chart: int) -> int:
        return {
            self.GAME_CHART_SINGLE_BEGINNER: self.CHART_SINGLE_BEGINNER,
            self.GAME_CHART_SINGLE_BASIC: self.CHART_SINGLE_BASIC,
            self.GAME_CHART_SINGLE_DIFFICULT: self.CHART_SINGLE_DIFFICULT,
            self.GAME_CHART_SINGLE_EXPERT: self.CHART_SINGLE_EXPERT,
            self.GAME_CHART_SINGLE_CHALLENGE: self.CHART_SINGLE_CHALLENGE,
            self.GAME_CHART_DOUBLE_BASIC: self.CHART_DOUBLE_BASIC,
            self.GAME_CHART_DOUBLE_DIFFICULT: self.CHART_DOUBLE_DIFFICULT,
            self.GAME_CHART_DOUBLE_EXPERT: self.CHART_DOUBLE_EXPERT,
            self.GAME_CHART_DOUBLE_CHALLENGE: self.CHART_DOUBLE_CHALLENGE,
        }[game_chart]

    def db_to_game_chart(self, db_chart: int) -> int:
        return {
            self.CHART_SINGLE_BEGINNER: self.GAME_CHART_SINGLE_BEGINNER,
            self.CHART_SINGLE_BASIC: self.GAME_CHART_SINGLE_BASIC,
            self.CHART_SINGLE_DIFFICULT: self.GAME_CHART_SINGLE_DIFFICULT,
            self.CHART_SINGLE_EXPERT: self.GAME_CHART_SINGLE_EXPERT,
            self.CHART_SINGLE_CHALLENGE: self.GAME_CHART_SINGLE_CHALLENGE,
            self.CHART_DOUBLE_BASIC: self.GAME_CHART_DOUBLE_BASIC,
            self.CHART_DOUBLE_DIFFICULT: self.GAME_CHART_DOUBLE_DIFFICULT,
            self.CHART_DOUBLE_EXPERT: self.GAME_CHART_DOUBLE_EXPERT,
            self.CHART_DOUBLE_CHALLENGE: self.GAME_CHART_DOUBLE_CHALLENGE,
        }[db_chart]

    def db_to_game_halo(self, db_halo: int) -> int:
        if db_halo == self.HALO_MARVELOUS_FULL_COMBO:
            combo_type = self.GAME_HALO_MARVELOUS_COMBO
        elif db_halo == self.HALO_PERFECT_FULL_COMBO:
            combo_type = self.GAME_HALO_PERFECT_COMBO
        elif db_halo == self.HALO_GREAT_FULL_COMBO:
            combo_type = self.GAME_HALO_FULL_COMBO
        else:
            combo_type = self.GAME_HALO_NONE
        return combo_type

    def handle_game_common_request(self, request: Node) -> Node:
        game = Node.void("game")
        for flagid in range(256):
            flag = Node.void("flag")
            game.add_child(flag)

            flag.set_attribute("id", str(flagid))
            flag.set_attribute("s2", "0")
            flag.set_attribute("s1", "0")
            flag.set_attribute("t", "0")

        hit_chart = self.data.local.music.get_hit_chart(self.game, self.music_version, self.GAME_MAX_SONGS)
        counts_by_reflink = [0] * self.GAME_MAX_SONGS
        for reflink, plays in hit_chart:
            if reflink >= 0 and reflink < self.GAME_MAX_SONGS:
                counts_by_reflink[reflink] = plays
        game.add_child(Node.u32_array("cnt_music", counts_by_reflink))

        return game

    def handle_game_hiscore_request(self, request: Node) -> Node:
        # This is almost identical to X3 and above, except X3 added a 'code' field
        # that isn't present here. In the interest of correctness, keep a separate
        # implementation here.
        records = self.data.remote.music.get_all_records(self.game, self.music_version)

        sortedrecords: Dict[int, Dict[int, Tuple[UserID, Score]]] = {}
        missing_profiles = []
        for userid, score in records:
            if score.id not in sortedrecords:
                sortedrecords[score.id] = {}
            sortedrecords[score.id][score.chart] = (userid, score)
            missing_profiles.append(userid)
        users = {userid: profile for (userid, profile) in self.get_any_profiles(missing_profiles)}

        game = Node.void("game")
        for song in sortedrecords:
            music = Node.void("music")
            game.add_child(music)
            music.set_attribute("reclink_num", str(song))

            for chart in sortedrecords[song]:
                userid, score = sortedrecords[song][chart]
                try:
                    gamechart = self.db_to_game_chart(chart)
                except KeyError:
                    # Don't support this chart in this game
                    continue
                gamerank = self.db_to_game_rank(score.data.get_int("rank"))
                combo_type = self.db_to_game_halo(score.data.get_int("halo"))

                typenode = Node.void("type")
                music.add_child(typenode)
                typenode.set_attribute("diff", str(gamechart))

                typenode.add_child(Node.string("name", users[userid].get_str("name")))
                typenode.add_child(Node.u32("score", score.points))
                typenode.add_child(Node.u16("area", users[userid].get_int("area", self.get_machine_region())))
                typenode.add_child(Node.u8("rank", gamerank))
                typenode.add_child(Node.u8("combo_type", combo_type))

        return game

    def handle_game_load_m_request(self, request: Node) -> Node:
        extid = intish(request.attribute("code"))
        refid = request.attribute("refid")

        if extid is not None:
            # Rival score loading
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        else:
            # Self score loading
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
        else:
            scores = []

        sortedscores: Dict[int, Dict[int, Score]] = {}
        for score in scores:
            if score.id not in sortedscores:
                sortedscores[score.id] = {}
            sortedscores[score.id][score.chart] = score

        game = Node.void("game")
        for song in sortedscores:
            music = Node.void("music")
            game.add_child(music)
            music.set_attribute("reclink", str(song))

            for chart in sortedscores[song]:
                score = sortedscores[song][chart]
                try:
                    gamechart = self.db_to_game_chart(chart)
                except KeyError:
                    # Don't support this chart in this game
                    continue
                gamerank = self.db_to_game_rank(score.data.get_int("rank"))
                combo_type = self.db_to_game_halo(score.data.get_int("halo"))

                typenode = Node.void("type")
                music.add_child(typenode)
                typenode.set_attribute("diff", str(gamechart))

                typenode.add_child(Node.u32("score", score.points))
                typenode.add_child(Node.u16("count", score.plays))
                typenode.add_child(Node.u8("rank", gamerank))
                typenode.add_child(Node.u8("combo_type", combo_type))

        return game

    def handle_game_save_m_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        songid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("mtype")))

        # Calculate statistics
        data = request.child("data")
        points = int(data.attribute("score"))
        combo = int(data.attribute("combo"))
        rank = self.game_to_db_rank(int(data.attribute("rank")))
        if int(data.attribute("full")) == 0:
            halo = self.HALO_NONE
        elif int(data.attribute("perf")) == 0:
            halo = self.HALO_GREAT_FULL_COMBO
        elif points < 1000000:
            halo = self.HALO_PERFECT_FULL_COMBO
        else:
            halo = self.HALO_MARVELOUS_FULL_COMBO
        trace = request.child_value("trace")

        # Save the score, regardless of whether we have a refid. If we save
        # an anonymous score, it only goes into the DB to count against the
        # number of plays for that song/chart.
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        self.update_score(
            userid,
            songid,
            chart,
            points,
            rank,
            halo,
            combo,
            trace,
        )

        # No response needed
        game = Node.void("game")
        return game

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("game")

        # Look up play stats we bridge to every mix
        play_stats = self.get_play_statistics(userid)

        # Basic game settings
        root.add_child(Node.string("seq", ""))
        root.add_child(Node.u32("code", profile.extid))
        root.add_child(Node.string("name", profile.get_str("name")))
        root.add_child(Node.u8("area", profile.get_int("area", self.get_machine_region())))
        root.add_child(Node.u32("cnt_s", play_stats.get_int("single_plays")))
        root.add_child(Node.u32("cnt_d", play_stats.get_int("double_plays")))
        root.add_child(Node.u32("cnt_b", play_stats.get_int("battle_plays")))  # This could be wrong, its a guess
        root.add_child(Node.u32("cnt_m0", play_stats.get_int("cnt_m0")))
        root.add_child(Node.u32("cnt_m1", play_stats.get_int("cnt_m1")))
        root.add_child(Node.u32("cnt_m2", play_stats.get_int("cnt_m2")))
        root.add_child(Node.u32("cnt_m3", play_stats.get_int("cnt_m3")))
        root.add_child(Node.u32("exp", play_stats.get_int("exp")))
        root.add_child(Node.u32("exp_o", profile.get_int("exp_o")))
        root.add_child(Node.u32("star", profile.get_int("star")))
        root.add_child(Node.u32("star_c", profile.get_int("star_c")))
        root.add_child(Node.u8("combo", profile.get_int("combo", 0)))
        root.add_child(Node.u8("timing_diff", profile.get_int("early_late", 0)))

        # Character stuff
        chara = Node.void("chara")
        root.add_child(chara)
        if "chara" in profile:
            chara.set_attribute("my", str(profile.get_int("chara")))

        root.add_child(Node.u8_array("chara_opt", profile.get_int_array("chara_opt", 96)))

        # Drill rankings
        if "title" in profile:
            title = Node.void("title")
            root.add_child(title)
            titledict = profile.get_dict("title")
            if "t" in titledict:
                title.set_attribute("t", str(titledict.get_int("t")))
            if "s" in titledict:
                title.set_attribute("s", str(titledict.get_int("s")))
            if "d" in titledict:
                title.set_attribute("d", str(titledict.get_int("d")))

        if "title_gr" in profile:
            title_gr = Node.void("title_gr")
            root.add_child(title_gr)
            title_grdict = profile.get_dict("title_gr")
            if "t" in title_grdict:
                title_gr.set_attribute("t", str(title_grdict.get_int("t")))
            if "s" in title_grdict:
                title_gr.set_attribute("s", str(title_grdict.get_int("s")))
            if "d" in title_grdict:
                title_gr.set_attribute("d", str(title_grdict.get_int("d")))

        # Event progrses
        if "event" in profile:
            event = Node.void("event")
            root.add_child(event)
            event_dict = profile.get_dict("event")
            if "diff_sum" in event_dict:
                event.set_attribute("diff_sum", str(event_dict.get_int("diff_sum")))
            if "welcome" in event_dict:
                event.set_attribute("welcome", str(event_dict.get_int("welcome")))
            if "e_flags" in event_dict:
                event.set_attribute("e_flags", str(event_dict.get_int("e_flags")))

        if "e_panel" in profile:
            e_panel = Node.void("e_panel")
            root.add_child(e_panel)
            e_panel_dict = profile.get_dict("e_panel")
            if "play_id" in e_panel_dict:
                e_panel.set_attribute("play_id", str(e_panel_dict.get_int("play_id")))
            e_panel.add_child(Node.u8_array("cell", e_panel_dict.get_int_array("cell", 24)))
            e_panel.add_child(Node.u8_array("panel_state", e_panel_dict.get_int_array("panel_state", 6)))

        if "e_pix" in profile:
            e_pix = Node.void("e_pix")
            root.add_child(e_pix)
            e_pix_dict = profile.get_dict("e_pix")
            if "max_distance" in e_pix_dict:
                e_pix.set_attribute("max_distance", str(e_pix_dict.get_int("max_distance")))
            if "max_planet" in e_pix_dict:
                e_pix.set_attribute("max_planet", str(e_pix_dict.get_int("max_planet")))
            if "total_distance" in e_pix_dict:
                e_pix.set_attribute("total_distance", str(e_pix_dict.get_int("total_distance")))
            if "total_planet" in e_pix_dict:
                e_pix.set_attribute("total_planet", str(e_pix_dict.get_int("total_planet")))
            if "border_character" in e_pix_dict:
                e_pix.set_attribute("border_character", str(e_pix_dict.get_int("border_character")))
            if "border_balloon" in e_pix_dict:
                e_pix.set_attribute("border_balloon", str(e_pix_dict.get_int("border_balloon")))
            if "border_music_aftr" in e_pix_dict:
                e_pix.set_attribute("border_music_aftr", str(e_pix_dict.get_int("border_music_aftr")))
            if "border_music_meii" in e_pix_dict:
                e_pix.set_attribute("border_music_meii", str(e_pix_dict.get_int("border_music_meii")))
            if "border_music_dirt" in e_pix_dict:
                e_pix.set_attribute("border_music_dirt", str(e_pix_dict.get_int("border_music_dirt")))
            if "flags" in e_pix_dict:
                e_pix.set_attribute("flags", str(e_pix_dict.get_int("flags")))

        # Calorie mode
        if "weight" in profile:
            workouts = self.data.local.user.get_time_based_achievements(
                self.game,
                self.version,
                userid,
                achievementtype="workout",
                since=Time.now() - Time.SECONDS_IN_DAY,
            )
            total = sum([w.data.get_int("calories") for w in workouts])
            workout = Node.void("workout")
            root.add_child(workout)
            workout.set_attribute("weight", str(profile.get_int("weight")))
            workout.set_attribute("day", str(total))
            workout.set_attribute("disp", "1")

        # Last cursor settings
        last = Node.void("last")
        root.add_child(last)
        lastdict = profile.get_dict("last")
        last.set_attribute("fri", str(lastdict.get_int("fri")))
        last.set_attribute("style", str(lastdict.get_int("style")))
        last.set_attribute("mode", str(lastdict.get_int("mode")))
        last.set_attribute("cate", str(lastdict.get_int("cate")))
        last.set_attribute("sort", str(lastdict.get_int("sort")))
        last.set_attribute("mid", str(lastdict.get_int("mid")))
        last.set_attribute("mtype", str(lastdict.get_int("mtype")))
        last.set_attribute("cid", str(lastdict.get_int("cid")))
        last.set_attribute("ctype", str(lastdict.get_int("ctype")))
        last.set_attribute("sid", str(lastdict.get_int("sid")))

        # Groove gauge level-ups
        gr_s = Node.void("gr_s")
        root.add_child(gr_s)
        index = 1
        for entry in profile.get_int_array("gr_s", 5):
            gr_s.set_attribute(f"gr{index}", str(entry))
            index = index + 1

        gr_d = Node.void("gr_d")
        root.add_child(gr_d)
        index = 1
        for entry in profile.get_int_array("gr_d", 5):
            gr_d.set_attribute(f"gr{index}", str(entry))
            index = index + 1

        # Options in menus
        root.add_child(Node.s16_array("opt", profile.get_int_array("opt", 16)))
        root.add_child(Node.s16_array("opt_ex", profile.get_int_array("opt_ex", 16)))

        # Unlock flags
        root.add_child(Node.u8_array("flag", profile.get_int_array("flag", 256, [1] * 256)))

        # Ranking display?
        root.add_child(Node.u16_array("rank", profile.get_int_array("rank", 100)))

        # Rivals
        links = self.data.local.user.get_links(self.game, self.version, userid)
        for link in links:
            if link.type[:7] != "friend_":
                continue

            pos = int(link.type[7:])
            friend = self.get_profile(link.other_userid)
            play_stats = self.get_play_statistics(link.other_userid)
            if friend is not None:
                friendnode = Node.void("friend")
                root.add_child(friendnode)
                friendnode.set_attribute("pos", str(pos))
                friendnode.set_attribute("vs", "0")
                friendnode.set_attribute("up", "0")
                friendnode.add_child(Node.u32("code", friend.extid))
                friendnode.add_child(Node.string("name", friend.get_str("name")))
                friendnode.add_child(Node.u8("area", friend.get_int("area", self.get_machine_region())))
                friendnode.add_child(Node.u32("exp", play_stats.get_int("exp")))
                friendnode.add_child(Node.u32("star", friend.get_int("star")))

                # Drill rankings
                if "title" in friend:
                    title = Node.void("title")
                    friendnode.add_child(title)
                    titledict = friend.get_dict("title")
                    if "t" in titledict:
                        title.set_attribute("t", str(titledict.get_int("t")))
                    if "s" in titledict:
                        title.set_attribute("s", str(titledict.get_int("s")))
                    if "d" in titledict:
                        title.set_attribute("d", str(titledict.get_int("d")))

                if "title_gr" in friend:
                    title_gr = Node.void("title_gr")
                    friendnode.add_child(title_gr)
                    title_grdict = friend.get_dict("title_gr")
                    if "t" in title_grdict:
                        title_gr.set_attribute("t", str(title_grdict.get_int("t")))
                    if "s" in title_grdict:
                        title_gr.set_attribute("s", str(title_grdict.get_int("s")))
                    if "d" in title_grdict:
                        title_gr.set_attribute("d", str(title_grdict.get_int("d")))

                # Groove gauge level-ups
                gr_s = Node.void("gr_s")
                friendnode.add_child(gr_s)
                index = 1
                for entry in friend.get_int_array("gr_s", 5):
                    gr_s.set_attribute(f"gr{index}", str(entry))
                    index = index + 1

                gr_d = Node.void("gr_d")
                friendnode.add_child(gr_d)
                index = 1
                for entry in friend.get_int_array("gr_d", 5):
                    gr_d.set_attribute(f"gr{index}", str(entry))
                    index = index + 1

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()
        play_stats = self.get_play_statistics(userid)

        # Grab last node and accessories so we can make decisions based on type
        last = request.child("last")
        lastdict = newprofile.get_dict("last")
        mode = int(last.attribute("mode"))
        style = int(last.attribute("style"))
        is_dp = style == self.GAME_STYLE_DOUBLE

        # Drill rankings
        title = request.child("title")
        title_gr = request.child("title_gr")
        titledict = newprofile.get_dict("title")
        title_grdict = newprofile.get_dict("title_gr")

        # Groove radar level ups
        gr = request.child("gr")

        # Set the correct values depending on if we're single or double play
        if is_dp:
            play_stats.increment_int("double_plays")
            if gr is not None:
                newprofile.replace_int_array(
                    "gr_d",
                    5,
                    [
                        intish(gr.attribute("gr1")),
                        intish(gr.attribute("gr2")),
                        intish(gr.attribute("gr3")),
                        intish(gr.attribute("gr4")),
                        intish(gr.attribute("gr5")),
                    ],
                )
            if title is not None:
                titledict.replace_int("d", title.value)
                newprofile.replace_dict("title", titledict)
            if title_gr is not None:
                title_grdict.replace_int("d", title.value)
                newprofile.replace_dict("title_gr", title_grdict)
        else:
            play_stats.increment_int("single_plays")
            if gr is not None:
                newprofile.replace_int_array(
                    "gr_s",
                    5,
                    [
                        intish(gr.attribute("gr1")),
                        intish(gr.attribute("gr2")),
                        intish(gr.attribute("gr3")),
                        intish(gr.attribute("gr4")),
                        intish(gr.attribute("gr5")),
                    ],
                )
            if title is not None:
                titledict.replace_int("s", title.value)
                newprofile.replace_dict("title", titledict)
            if title_gr is not None:
                title_grdict.replace_int("s", title.value)
                newprofile.replace_dict("title_gr", title_grdict)
        play_stats.increment_int(f"cnt_m{mode}")

        # Update last attributes
        lastdict.replace_int("fri", intish(last.attribute("fri")))
        lastdict.replace_int("style", intish(last.attribute("style")))
        lastdict.replace_int("mode", intish(last.attribute("mode")))
        lastdict.replace_int("cate", intish(last.attribute("cate")))
        lastdict.replace_int("sort", intish(last.attribute("sort")))
        lastdict.replace_int("mid", intish(last.attribute("mid")))
        lastdict.replace_int("mtype", intish(last.attribute("mtype")))
        lastdict.replace_int("cid", intish(last.attribute("cid")))
        lastdict.replace_int("ctype", intish(last.attribute("ctype")))
        lastdict.replace_int("sid", intish(last.attribute("sid")))
        newprofile.replace_dict("last", lastdict)

        # Grab character options
        chara = request.child("chara")
        if chara is not None:
            newprofile.replace_int("chara", intish(chara.attribute("my")))
        newprofile.replace_int_array("chara_opt", 96, request.child_value("chara_opt"))

        # Track event progress
        event = request.child("event")
        if event is not None:
            event_dict = newprofile.get_dict("event")
            event_dict.replace_int("diff_sum", intish(event.attribute("diff_sum")))
            event_dict.replace_int("e_flags", intish(event.attribute("e_flags")))
            event_dict.replace_int("welcome", intish(event.attribute("welcome")))
            newprofile.replace_dict("event", event_dict)

        e_panel = request.child("e_panel")
        if e_panel is not None:
            e_panel_dict = newprofile.get_dict("e_panel")
            e_panel_dict.replace_int("play_id", intish(e_panel.attribute("play_id")))
            e_panel_dict.replace_int_array("cell", 24, e_panel.child_value("cell"))
            e_panel_dict.replace_int_array("panel_state", 6, e_panel.child_value("panel_state"))
            newprofile.replace_dict("e_panel", e_panel_dict)

        e_pix = request.child("e_pix")
        if e_pix is not None:
            e_pix_dict = newprofile.get_dict("e_pix")
            max_distance = e_pix_dict.get_int("max_distance")
            max_planet = e_pix_dict.get_int("max_planet")
            total_distance = e_pix_dict.get_int("total_distance")
            total_planet = e_pix_dict.get_int("total_planet")
            cur_distance = intish(e_pix.attribute("this_distance"))
            cur_planet = intish(e_pix.attribute("this_planet"))
            if cur_distance is not None:
                max_distance = max(max_distance, cur_distance)
                total_distance += cur_distance
            if cur_planet is not None:
                max_planet = max(max_planet, cur_planet)
                total_planet += cur_planet

            e_pix_dict.replace_int("max_distance", max_distance)
            e_pix_dict.replace_int("max_planet", max_planet)
            e_pix_dict.replace_int("total_distance", total_distance)
            e_pix_dict.replace_int("total_planet", total_planet)
            e_pix_dict.replace_int("flags", intish(e_pix.attribute("flags")))
            newprofile.replace_dict("e_pix", e_pix_dict)

        # Options
        opt = request.child("opt")
        if opt is not None:
            # A bug in old versions of AVS returns the wrong number for set
            newprofile.replace_int_array("opt", 16, opt.value[:16])

        # Experience and stars
        exp = request.child_value("exp")
        if exp is not None:
            play_stats.replace_int("exp", play_stats.get_int("exp") + exp)
        star = request.child_value("star")
        if star is not None:
            newprofile.replace_int("star", newprofile.get_int("star") + star)
        star_c = request.child_value("star_c")
        if star_c is not None:
            newprofile.replace_int("star_c", newprofile.get_int("star_c") + exp)

        # Update game flags
        for child in request.children:
            if child.name != "flag":
                continue
            try:
                value = int(child.attribute("data"))
                offset = int(child.attribute("no"))
            except ValueError:
                continue

            flags = newprofile.get_int_array("flag", 256, [1] * 256)
            if offset < 0 or offset >= len(flags):
                continue
            flags[offset] = value
            newprofile.replace_int_array("flag", 256, flags)

        # Workout mode support
        newweight = -1
        oldweight = newprofile.get_int("weight")
        for child in request.children:
            if child.name != "weight":
                continue
            newweight = child.value
        if newweight < 0:
            newweight = oldweight

        # Either update or unset the weight depending on the game
        if newweight == 0:
            # Weight is unset or we declined to use this feature, remove from profile
            if "weight" in newprofile:
                del newprofile["weight"]
        else:
            # Weight has been set or previously retrieved, we should save calories
            newprofile.replace_int("weight", newweight)
            total = 0
            for child in request.children:
                if child.name != "calory":
                    continue
                total += child.value
            self.data.local.user.put_time_based_achievement(
                self.game,
                self.version,
                userid,
                0,
                "workout",
                {
                    "calories": total,
                    "weight": newweight,
                },
            )

        # Look up old friends
        oldfriends: List[Optional[UserID]] = [None] * 10
        links = self.data.local.user.get_links(self.game, self.version, userid)
        for link in links:
            if link.type[:7] != "friend_":
                continue

            pos = int(link.type[7:])
            oldfriends[pos] = link.other_userid

        # Save any rivals that were added/removed/changed
        newfriends = oldfriends[:]
        for child in request.children:
            if child.name != "friend":
                continue

            code = int(child.attribute("code"))
            pos = int(child.attribute("pos"))

            if pos >= 0 and pos < 10:
                if code == 0:
                    # We cleared this friend
                    newfriends[pos] = None
                else:
                    # Try looking up the userid
                    newfriends[pos] = self.data.remote.user.from_extid(self.game, self.version, code)

        # Diff the set of links to determine updates
        for i in range(10):
            if newfriends[i] == oldfriends[i]:
                continue

            if newfriends[i] is None:
                # Kill the rival in this location
                self.data.local.user.destroy_link(
                    self.game,
                    self.version,
                    userid,
                    f"friend_{i}",
                    oldfriends[i],
                )
            elif oldfriends[i] is None:
                # Add rival in this location
                self.data.local.user.put_link(
                    self.game,
                    self.version,
                    userid,
                    f"friend_{i}",
                    newfriends[i],
                    {},
                )
            else:
                # Changed the rival here, kill the old one, add the new one
                self.data.local.user.destroy_link(
                    self.game,
                    self.version,
                    userid,
                    f"friend_{i}",
                    oldfriends[i],
                )
                self.data.local.user.put_link(
                    self.game,
                    self.version,
                    userid,
                    f"friend_{i}",
                    newfriends[i],
                    {},
                )

        # Keep track of play statistics
        self.update_play_statistics(userid, play_stats)

        return newprofile
