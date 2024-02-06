# vim: set fileencoding=utf-8
import base64
import hashlib
import html
from typing import Dict, List, Optional, Tuple

from typing_extensions import Final

from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.ddrsn2.eventinfo import EventInfo
from bemani.backend.ddr.ddrsn2.playerinfo import PlayerInfo
from bemani.backend.ddr.ddrsn2.scoreinfo import ScoreInfo
from bemani.backend.ddr.stubs import DDRSuperNova
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
from bemani.backend.base import Status


class DDRSuperNova2(
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
    name: str = "DanceDanceRevolution SuperNova 2"
    version: int = VersionConstants.DDR_SUPERNOVA_2

    GAME_STYLE_SINGLE: Final[int] = 0
    GAME_STYLE_DOUBLE: Final[int] = 1
    GAME_STYLE_VERSUS: Final[int] = 2

    GAME_RANK_AAA: Final[int] = 0
    GAME_RANK_AA: Final[int] = 1
    GAME_RANK_A: Final[int] = 2
    GAME_RANK_B: Final[int] = 3
    GAME_RANK_C: Final[int] = 4
    GAME_RANK_D: Final[int] = 5
    GAME_RANK_E: Final[int] = 6

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
        return DDRSuperNova(self.data, self.config, self.model)

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

    def sn2_to_db_halo(self, full: int, perf: int) -> int:
        if full == 1 and perf == 1:
            combo_type = self.HALO_PERFECT_FULL_COMBO
        elif full == 1:
            combo_type = self.HALO_GREAT_FULL_COMBO
        else:
            combo_type = self.HALO_NONE
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

    def format_profile_part(self, userid: UserID, profile: Profile, part: str) -> Node:
        root = Node.void("player")
        root.set_attribute("part", part)

        # Look up play stats we bridge to every mix
        play_stats = self.get_play_statistics(userid)

        # Load scoring data
        scores = self.data.local.music.get_scores(self.game, self.version, userid)

        if part == "0":
            payload = bytearray(PlayerInfo.create(play_stats, profile, self.get_machine_region()))
            size = 6144

        elif part == "1":
            payload = bytearray(ScoreInfo.create(scores, 1))
            size = 7200

        else:
            payload = bytearray(ScoreInfo.create(scores, 2))
            size = 7200

        payload += bytearray([0] * (size - len(payload)))

        root.set_attribute("encode", "0")
        root.set_attribute("size", str(size))
        root.set_attribute("md5c", hashlib.md5(payload).hexdigest().upper())

        binary = Node.string("b", base64.b64encode(payload).decode("ascii"))
        root.add_child(binary)

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()
        play_stats = self.get_play_statistics(userid)

        game = request.child("game")
        opt = request.child("opt")

        gr = newprofile.get_int_array("gr_s", 5)

        gr1 = gr[0]
        gr2 = gr[1]
        gr3 = gr[2]
        gr4 = gr[3]
        gr5 = gr[4]

        if game.attribute("gr1"):
            gr1 = intish(game.attribute("gr1"))
        if game.attribute("gr2"):
            gr2 = intish(game.attribute("gr2"))
        if game.attribute("gr3"):
            gr3 = intish(game.attribute("gr3"))
        if game.attribute("gr4"):
            gr4 = intish(game.attribute("gr4"))
        if game.attribute("gr5"):
            gr5 = intish(game.attribute("gr5"))

        newprofile.replace_int_array("gr_s", 5, [gr1, gr2, gr3, gr4, gr5])

        last = newprofile.get_dict("last")
        last.replace_int("cate", intish(game.attribute("cate")))
        last.replace_int("mode", intish(game.attribute("mode")))
        last.replace_int("type", intish(game.attribute("type")))
        last.replace_int("sort", intish(game.attribute("sort")))
        last.replace_int("music", intish(game.attribute("music")))
        newprofile.replace_dict("last", last)

        newprofile.replace_int_array(
            "opt",
            16,
            [
                intish(opt.attribute("op1")),
                intish(opt.attribute("op2")),
                intish(opt.attribute("op3")),
                intish(opt.attribute("op4")),
                intish(opt.attribute("op5")),
                intish(opt.attribute("op6")),
                intish(opt.attribute("op7")),
                intish(opt.attribute("op8")),
                intish(opt.attribute("op9")),
                intish(opt.attribute("op10")),
                intish(opt.attribute("op11")),
                intish(opt.attribute("op12")),
                intish(opt.attribute("op13")),
                intish(opt.attribute("op14")),
                intish(opt.attribute("op15")),
                intish(opt.attribute("op16")),
            ],
        )

        play_stats.increment_int("single_plays")
        play_stats.increment_int(f"cnt_m{game.attribute('mode')}")
        play_stats.replace_int("exp", play_stats.get_int("exp") + intish(game.attribute("exp")))

        if game.attribute("weight"):
            newprofile.replace_int("weight", intish(game.attribute("weight")))

        if game.attribute("calory"):
            if game.attribute("weight"):
                weight = intish(game.attribute("weight"))
            else:
                weight = newprofile.get_int("weight", 0)
            self.data.local.user.put_time_based_achievement(
                self.game,
                self.version,
                userid,
                0,
                "workout",
                {
                    "calories": intish(game.attribute("calory")),
                    "weight": weight,
                },
            )

        # Update game flags
        for child in request.children:
            if child.name != "flag":
                continue
            try:
                value = intish(child.attribute("data"))
                offset = intish(child.attribute("off"))
            except ValueError:
                continue

            flags = newprofile.get_int_array("flag", 256, [1] * 256)
            if offset < 0 or offset >= len(flags):
                continue
            flags[offset] = value
            newprofile.replace_int_array("flag", 256, flags)

        # Keep track of play statistics
        self.update_play_statistics(userid, play_stats)

        # Store song score data
        for child in request.children:
            if child.name != "music":
                continue
            try:
                combo = intish(child.attribute("combo"))
                full = intish(child.attribute("full"))
                id = intish(child.attribute("id"))
                mode = intish(child.attribute("mode"))
                perf = intish(child.attribute("perf"))
                rank = intish(child.attribute("rank"))
                score = intish(child.attribute("score"))
            except:
                continue

            self.update_score(
                userid,
                id,
                self.game_to_db_chart(mode),
                score * 10,
                self.game_to_db_rank(rank),
                self.sn2_to_db_halo(full, perf),
                combo,
            )

        # Event Team Data
        if game.attribute("team_i"):
            newprofile.replace_int("team", intish(game.attribute("team_i")))
            newprofile.replace_int(
                "team_points", intish(game.attribute("team_p")) + newprofile.get_int("team_points", 0)
            )

        return newprofile

    def handle_player_new_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        name = request.attribute("name")
        area = intish(request.attribute("area"))

        formatted_name = html.unescape(name)
        self.new_profile_by_refid(refid, formatted_name, area)

        root = Node.void("player")
        root.add_child(Node.s8("result", 2))

        return root

    def handle_player_get_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        part = request.attribute("part")

        root = self.get_profile_by_refid_and_part(refid, part)
        if root is None:
            root = Node.void("player")
            root.set_attribute("new", "1")
        return root

    def handle_player_set_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")

        self.put_profile_by_refid(refid, request)

        root = Node.void("player")
        root.add_child(Node.s8("result", 2))

        return root

    def handle_info_message_request(self, request: Node) -> Node:
        size = 5772
        message = "hello world"
        payload = message.encode("ascii")

        payload += bytearray([0] * (size - len(payload)))

        b64 = base64.b64encode(payload).decode("ascii")

        root = Node.void("info")

        root.set_attribute("encode", "0")
        root.set_attribute("size", str(size))
        root.set_attribute("md5c", hashlib.md5(payload).hexdigest().upper())

        binary = Node.string("b", b64)
        root.add_child(binary)

        return root

    def handle_player_common_request(self, request: Node) -> Node:
        size = 1920
        payload = bytearray(EventInfo.create())

        payload += bytearray([0] * (size - len(payload)))

        b64 = base64.b64encode(payload).decode("ascii")

        root = Node.void("player")

        root.set_attribute("encode", "0")
        root.set_attribute("size", str(size))
        root.set_attribute("md5c", hashlib.md5(payload).hexdigest().upper())

        binary = Node.string("b", b64)
        root.add_child(binary)

        return root

    def handle_player_touch_request(self, request: Node) -> Node:
        root = Node.void("player")

        root.set_attribute("id", "1234")

        return root

    def handle_info_tenpo_request(self, request: Node) -> Node:
        root = Node.void("tenpo")
        return root
