# vim: set fileencoding=utf-8
from typing import Dict, List, Optional
from typing_extensions import Final

from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.ddrx3 import DDRX3
from bemani.backend.ddr.common import (
    DDRGameAreaHiscoreHandler,
    DDRGameFriendHandler,
    DDRGameHiscoreHandler,
    DDRGameLoadCourseHandler,
    DDRGameLoadDailyHandler,
    DDRGameLoadHandler,
    DDRGameLockHandler,
    DDRGameLogHandler,
    DDRGameMessageHandler,
    DDRGameNewHandler,
    DDRGameOldHandler,
    DDRGameRankingHandler,
    DDRGameRecorderHandler,
    DDRGameSaveCourseHandler,
    DDRGameSaveHandler,
    DDRGameScoreHandler,
    DDRGameShopHandler,
    DDRGameTaxInfoHandler,
    DDRGameTraceHandler,
)
from bemani.common import VersionConstants, Profile, Time, intish
from bemani.data import Score, UserID
from bemani.protocol import Node


class DDR2013(
    DDRGameAreaHiscoreHandler,
    DDRGameFriendHandler,
    DDRGameHiscoreHandler,
    DDRGameLoadCourseHandler,
    DDRGameLoadDailyHandler,
    DDRGameLoadHandler,
    DDRGameLockHandler,
    DDRGameLogHandler,
    DDRGameMessageHandler,
    DDRGameNewHandler,
    DDRGameOldHandler,
    DDRGameRankingHandler,
    DDRGameRecorderHandler,
    DDRGameSaveCourseHandler,
    DDRGameSaveHandler,
    DDRGameScoreHandler,
    DDRGameShopHandler,
    DDRGameTaxInfoHandler,
    DDRGameTraceHandler,
    DDRBase,
):
    name: str = "DanceDanceRevolution 2013"
    version: int = VersionConstants.DDR_2013

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
    GAME_HALO_GREAT_COMBO: Final[int] = 1
    GAME_HALO_PERFECT_COMBO: Final[int] = 2
    GAME_HALO_MARVELOUS_COMBO: Final[int] = 3
    GAME_HALO_GOOD_COMBO: Final[int] = 4

    GAME_MAX_SONGS: Final[int] = 700

    def previous_version(self) -> Optional[DDRBase]:
        return DDRX3(self.data, self.config, self.model)

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
            combo_type = self.GAME_HALO_GREAT_COMBO
        elif db_halo == self.HALO_GOOD_FULL_COMBO:
            combo_type = self.GAME_HALO_GOOD_COMBO
        else:
            combo_type = self.GAME_HALO_NONE
        return combo_type

    def handle_game_common_request(self, request: Node) -> Node:
        game = Node.void("game")
        for flagid in range(256):
            flag = Node.void("flag")
            game.add_child(flag)

            flag.set_attribute("id", str(flagid))
            flag.set_attribute("t", "0")
            flag.set_attribute("s1", "0")
            flag.set_attribute("s2", "0")
            flag.set_attribute("area", str(self.get_machine_region()))
            flag.set_attribute("is_final", "1")

        hit_chart = self.data.local.music.get_hit_chart(self.game, self.music_version, self.GAME_MAX_SONGS)
        counts_by_reflink = [0] * self.GAME_MAX_SONGS
        for reflink, plays in hit_chart:
            if reflink >= 0 and reflink < self.GAME_MAX_SONGS:
                counts_by_reflink[reflink] = plays
        game.add_child(Node.u32_array("cnt_music", counts_by_reflink))

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
        if points == 1000000:
            halo = self.HALO_MARVELOUS_FULL_COMBO
        elif int(data.attribute("perf_fc")) != 0:
            halo = self.HALO_PERFECT_FULL_COMBO
        elif int(data.attribute("great_fc")) != 0:
            halo = self.HALO_GREAT_FULL_COMBO
        elif int(data.attribute("good_fc")) != 0:
            halo = self.HALO_GOOD_FULL_COMBO
        else:
            halo = self.HALO_NONE
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
        root.add_child(Node.u32("cnt_m4", play_stats.get_int("cnt_m4")))
        root.add_child(Node.u32("cnt_m5", play_stats.get_int("cnt_m5")))
        root.add_child(Node.u32("exp", play_stats.get_int("exp")))
        root.add_child(Node.u32("exp_o", profile.get_int("exp_o")))
        root.add_child(Node.u32("star", profile.get_int("star")))
        root.add_child(Node.u32("star_c", profile.get_int("star_c")))
        root.add_child(Node.u8("combo", profile.get_int("combo", 0)))
        root.add_child(Node.u8("timing_diff", profile.get_int("early_late", 0)))

        # Character stuff
        chara = Node.void("chara")
        root.add_child(chara)
        chara.set_attribute("my", str(profile.get_int("chara", 30)))
        root.add_child(Node.u16_array("chara_opt", profile.get_int_array("chara_opt", 96, [208] * 96)))

        # Drill rankings
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

        # Daily play counts
        daycount = Node.void("daycount")
        root.add_child(daycount)
        daycount.set_attribute("playcount", str(play_stats.today_plays))

        # Daily combo stuff, unknown how this works
        dailycombo = Node.void("dailycombo")
        root.add_child(dailycombo)
        dailycombo.set_attribute("daily_combo", str(0))
        dailycombo.set_attribute("daily_combo_lv", str(0))

        # Last cursor settings
        last = Node.void("last")
        root.add_child(last)
        lastdict = profile.get_dict("last")
        last.set_attribute("rival1", str(lastdict.get_int("rival1", -1)))
        last.set_attribute("rival2", str(lastdict.get_int("rival2", -1)))
        last.set_attribute("rival3", str(lastdict.get_int("rival3", -1)))
        last.set_attribute("fri", str(lastdict.get_int("rival1", -1)))  # This literally goes to the same memory in 2013
        last.set_attribute("style", str(lastdict.get_int("style")))
        last.set_attribute("mode", str(lastdict.get_int("mode")))
        last.set_attribute("cate", str(lastdict.get_int("cate")))
        last.set_attribute("sort", str(lastdict.get_int("sort")))
        last.set_attribute("mid", str(lastdict.get_int("mid")))
        last.set_attribute("mtype", str(lastdict.get_int("mtype")))
        last.set_attribute("cid", str(lastdict.get_int("cid")))
        last.set_attribute("ctype", str(lastdict.get_int("ctype")))
        last.set_attribute("sid", str(lastdict.get_int("sid")))

        # Result stars
        result_star = Node.void("result_star")
        root.add_child(result_star)
        result_stars = profile.get_int_array("result_stars", 9)
        for i in range(9):
            result_star.set_attribute(f"slot{i + 1}", str(result_stars[i]))

        # Target stuff
        target = Node.void("target")
        root.add_child(target)
        target.set_attribute("flag", str(profile.get_int("target_flag")))
        target.set_attribute("setnum", str(profile.get_int("target_setnum")))

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

        # Play area
        areas = profile.get_int_array("play_area", 55)
        play_area = Node.void("play_area")
        root.add_child(play_area)
        for i in range(len(areas)):
            play_area.set_attribute(f"play_cnt{i}", str(areas[i]))

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

        # Result stars
        result_star = request.child("result_star")
        if result_star is not None:
            newprofile.replace_int_array(
                "result_stars",
                9,
                [
                    intish(result_star.attribute("slot1")),
                    intish(result_star.attribute("slot2")),
                    intish(result_star.attribute("slot3")),
                    intish(result_star.attribute("slot4")),
                    intish(result_star.attribute("slot5")),
                    intish(result_star.attribute("slot6")),
                    intish(result_star.attribute("slot7")),
                    intish(result_star.attribute("slot8")),
                    intish(result_star.attribute("slot9")),
                ],
            )

        # Target stuff
        target = request.child("target")
        if target is not None:
            newprofile.replace_int("target_flag", intish(target.attribute("flag")))
            newprofile.replace_int("target_setnum", intish(target.attribute("setnum")))

        # Update last attributes
        lastdict.replace_int("rival1", intish(last.attribute("rival1")))
        lastdict.replace_int("rival2", intish(last.attribute("rival2")))
        lastdict.replace_int("rival3", intish(last.attribute("rival3")))
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
        chara_opt = request.child("chara_opt")
        if chara_opt is not None:
            # A bug in old versions of AVS returns the wrong number for set
            newprofile.replace_int_array("chara_opt", 96, chara_opt.value[:96])

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

        # Play area counter
        shop_area = int(request.attribute("shop_area"))
        if shop_area >= 0 and shop_area < 55:
            areas = newprofile.get_int_array("play_area", 55)
            areas[shop_area] = areas[shop_area] + 1
            newprofile.replace_int_array("play_area", 55, areas)

        # Keep track of play statistics
        self.update_play_statistics(userid, play_stats)

        return newprofile
