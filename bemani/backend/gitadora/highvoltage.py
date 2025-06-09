# vim: set fileencoding=utf-8
import copy
from typing_extensions import Final
from typing import Optional, List, Dict

from bemani.backend.gitadora.base import GitadoraBase
from bemani.backend.gitadora.musiclists.highvoltagemusic import (
    MUSICLIST_HIGHVOLTAGE,
    MUSICLIST_HIGHVOLTAGE_OMNIMIX,
)
from bemani.backend.ess import EventLogHandler

from bemani.common import VersionConstants, Profile, Time
from bemani.data import UserID, Score
from bemani.protocol import Node

from bemani.backend.gitadora.nextage import GitadoraNextage


class GitadoraHighVoltage(
    EventLogHandler,
    GitadoraBase,
):
    name = "GITADORA HighVoltage"
    version = VersionConstants.GITADORA_HIGH_VOLTAGE

    GITADORA_GUITARFREAKS: Final[int] = 0
    GITADORA_DRUMMANIA: Final[int] = 1

    CARD_REGISTER: Final[int] = 1
    CARD_USER_USED: Final[int] = 2

    GAME_GRADE_E: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_S: Final[int] = 5
    GAME_GRADE_SS: Final[int] = 6
    GAME_GRADE_EXCELLENT: Final[int] = 7

    GAME_GITUAR_CHART_BASIC: Final[int] = 1
    GAME_GITUAR_CHART_ADVANCE: Final[int] = 2
    GAME_GITUAR_CHART_EXTREME: Final[int] = 3
    GAME_GITUAR_CHART_MASTER: Final[int] = 4

    GAME_DRUM_CHART_BASIC: Final[int] = 1
    GAME_DRUM_CHART_ADVANCE: Final[int] = 2
    GAME_DRUM_CHART_EXTREME: Final[int] = 3
    GAME_DRUM_CHART_MASTER: Final[int] = 4

    GAME_BASS_CHART_BASIC: Final[int] = 5  # gitadora bass part.
    GAME_BASS_CHART_ADVANCE: Final[int] = 6
    GAME_BASS_CHART_EXTREME: Final[int] = 7
    GAME_BASS_CHART_MASTER: Final[int] = 8

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraNextage(self.data, self.config, self.model)

    def __game_to_db_grade(self, grade: int) -> int:
        return {
            self.GAME_GRADE_E: self.GITADORA_GRADE_E,
            self.GAME_GRADE_D: self.GITADORA_GRADE_D,
            self.GAME_GRADE_C: self.GITADORA_GRADE_C,
            self.GAME_GRADE_B: self.GITADORA_GRADE_B,
            self.GAME_GRADE_A: self.GITADORA_GRADE_A,
            self.GAME_GRADE_S: self.GITADORA_GRADE_S,
            self.GAME_GRADE_SS: self.GITADORA_GRADE_SS,
            self.GAME_GRADE_EXCELLENT: self.GITADORA_EXCELLENT,
        }[grade]

    def __db_to_game_grade(self, grade: int) -> int:
        return {
            self.GITADORA_GRADE_E: self.GAME_GRADE_E,
            self.GITADORA_GRADE_D: self.GAME_GRADE_D,
            self.GITADORA_GRADE_C: self.GAME_GRADE_C,
            self.GITADORA_GRADE_B: self.GAME_GRADE_B,
            self.GITADORA_GRADE_A: self.GAME_GRADE_A,
            self.GITADORA_GRADE_S: self.GAME_GRADE_S,
            self.GITADORA_GRADE_SS: self.GAME_GRADE_SS,
            self.GITADORA_GRADE_EXCELLENT: self.GAME_GRADE_EXCELLENT,
        }[grade]

    def game_to_db_chart_drum(self, db_chart: int) -> int:
        return {
            self.GAME_DRUM_CHART_BASIC: self.DRUM_CHART_TYPE_BASIC,
            self.GAME_DRUM_CHART_ADVANCE: self.DRUM_CHART_TYPE_ADVANCE,
            self.GAME_DRUM_CHART_EXTREME: self.DRUM_CHART_TYPE_EXTREME,
            self.GAME_DRUM_CHART_MASTER: self.DRUM_CHART_TYPE_MASTER,
        }[db_chart]

    def game_to_db_chart_gituar(self, db_chart: int) -> int:
        return {
            self.GAME_GITUAR_CHART_BASIC: self.GITUAR_CHART_TYPE_BASIC,
            self.GAME_GITUAR_CHART_ADVANCE: self.GITUAR_CHART_TYPE_ADVANCE,
            self.GAME_GITUAR_CHART_EXTREME: self.GITUAR_CHART_TYPE_EXTREME,
            self.GAME_GITUAR_CHART_MASTER: self.GITUAR_CHART_TYPE_MASTER,
            self.GAME_BASS_CHART_BASIC: self.BASS_CHART_TYPE_BASIC,
            self.GAME_BASS_CHART_ADVANCE: self.BASS_CHART_TYPE_ADVANCE,
            self.GAME_BASS_CHART_EXTREME: self.BASS_CHART_TYPE_EXTREME,
            self.GAME_BASS_CHART_MASTER: self.BASS_CHART_TYPE_MASTER,
        }[db_chart]

    def make_score_struct(self, scores: List[Score], cltype: int) -> List[List[int]]:
        scorestruct: Dict[int, List[int]] = {}

        for score in scores:
            musicid = score.id
            chart = score.chart

            # Filter to only singles/doubles charts
            if cltype == self.GITADORA_GUITARFREAKS:
                if chart not in [
                    self.GITUAR_CHART_TYPE_BASIC,
                    self.GITUAR_CHART_TYPE_ADVANCE,
                    self.GITUAR_CHART_TYPE_EXTREME,
                    self.GITUAR_CHART_TYPE_MASTER,
                    self.BASS_CHART_TYPE_BASIC,
                    self.BASS_CHART_TYPE_ADVANCE,
                    self.BASS_CHART_TYPE_EXTREME,
                    self.BASS_CHART_TYPE_MASTER,
                ]:
                    continue
                chartindex = {
                    self.GITUAR_CHART_TYPE_BASIC: 0,
                    self.GITUAR_CHART_TYPE_ADVANCE: 1,
                    self.GITUAR_CHART_TYPE_EXTREME: 2,
                    self.GITUAR_CHART_TYPE_MASTER: 3,
                    self.BASS_CHART_TYPE_BASIC: 4,
                    self.BASS_CHART_TYPE_ADVANCE: 5,
                    self.BASS_CHART_TYPE_EXTREME: 6,
                    self.BASS_CHART_TYPE_MASTER: 7,
                }[chart]

            if cltype == self.GITADORA_DRUMMANIA:
                if chart not in [
                    self.DRUM_CHART_TYPE_BASIC,
                    self.DRUM_CHART_TYPE_ADVANCE,
                    self.DRUM_CHART_TYPE_EXTREME,
                    self.DRUM_CHART_TYPE_MASTER,
                ]:
                    continue
                chartindex = {
                    self.DRUM_CHART_TYPE_BASIC: 0,
                    self.DRUM_CHART_TYPE_ADVANCE: 1,
                    self.DRUM_CHART_TYPE_EXTREME: 2,
                    self.DRUM_CHART_TYPE_MASTER: 3,
                }[chart]

            if musicid not in scorestruct:
                scorestruct[musicid] = [
                    musicid,  # Music ID!
                    -2,  # guitar/drum basic prec,
                    -2,  # guitar/drum advance prec,
                    -2,  # guitar/drum extreme prec,
                    -2,  # guitar/drum master prec,
                    -2,  # bass basic prec,
                    -2,  # bass advance prec,
                    -2,  # bass extreme prec,
                    -2,  # bass master prec,
                    0,  # guitar/drum basic grade,
                    0,  # guitar/drum advance grade,
                    0,  # guitar/drum extreme grade,
                    0,  # guitar/drum master grade,
                    0,  # bass basic grade,
                    0,  # bass advance grade,
                    0,  # bass extreme grade,
                    0,  # bass master grade,
                    0,  # guitar/drum basic fullcombo,
                    0,  # guitar/drum advance fullcombo,
                    0,  # guitar/drum extreme fullcombo,
                    0,  # guitar/drum master fullcombo,
                    0,  # bass basic fullcombo,
                    0,  # bass advance fullcombo,
                    0,  # bass extreme fullcombo,
                    0,  # bass master fullcombo,
                    0,  # guitar/drum basic excellent,
                    0,  # guitar/drum advance excellent,
                    0,  # guitar/drum extreme excellent,
                    0,  # guitar/drum master excellent,
                    0,  # bass basic excellent,
                    0,  # bass advance excellent,
                    0,  # bass extreme excellent,
                    0,  # bass master excellent,
                    0,  # guitar/drum basic clear,
                    0,  # guitar/drum advance clear,
                    0,  # guitar/drum extreme clear,
                    0,  # guitar/drum master clear,
                    0,  # bass basic clear,
                    0,  # bass advance clear,
                    0,  # bass extreme clear,
                    0,  # bass master clear,
                    0,  # guitar/drum basic points,
                    0,  # guitar/drum advance points,
                    0,  # guitar/drum extreme points,
                    0,  # guitar/drum master points,
                    0,  # bass basic points,
                    0,  # bass advance points,
                    0,  # bass extreme points,
                    0,  # bass master points,
                    0,  # guitar/drum basic meter,
                    0,  # guitar/drum advance meter,
                    0,  # guitar/drum extreme meter,
                    0,  # guitar/drum master meter,
                    0,  # bass basic meter,
                    0,  # bass advance meter,
                    0,  # bass extreme meter,
                    0,  # bass master meter,
                    0,  # guitar/drum basic meter_prog,
                    0,  # guitar/drum advance meter_prog,
                    0,  # guitar/drum extreme meter_prog,
                    0,  # guitar/drum master meter_prog,
                    0,  # bass basic meter_prog,
                    0,  # bass advance meter_prog,
                    0,  # bass extreme meter_prog,
                    0,  # bass master meter_prog,
                ]

            scorestruct[musicid][chartindex + 1] = score.data.get_int("perc") if score.data.get_bool("clear") == True else -1
            scorestruct[musicid][chartindex + 9] = self.__db_to_game_grade(
                score.data.get_int("grade")
            ) if score.data.get_bool("clear") == True else -1
            scorestruct[musicid][chartindex + 17] = score.data.get_bool("fullcombo")
            scorestruct[musicid][chartindex + 25] = score.data.get_bool("excellent")
            scorestruct[musicid][chartindex + 33] = score.data.get_bool("clear")
            scorestruct[musicid][chartindex + 41] = score.points
            scorestruct[musicid][chartindex + 49] = score.data.get_int("meter") if score.data.get_bool("clear") == True else 0
            scorestruct[musicid][chartindex + 57] = score.data.get_int("meter_prog")

        return [scorestruct[s] for s in scorestruct]

    def handle_highvoltage_shopinfo_regist_request(self, request: Node) -> Node:
        """
        For Gitadora has much difference from other game. it has special server system.
        first. we should add almost the whole game request on it.
        1st we should add exclusive shopinfo request.
        """
        root = Node.void("highvoltage_shopinfo")
        # first. add cabid and locationid on it.
        # cabid is the arcade id. locationid means
        machine = self.data.local.machine.get_arcade(self.config.machine.arcade)
        data = Node.void("data")
        root.add_child(data)
        data.add_child(Node.u32("cabid", machine.id))
        data.add_child(Node.string("locationid", str(machine.region)))
        # add temperature and tax phase.
        temperature = Node.void("temperature")
        root.add_child(temperature)
        temperature.add_child(Node.bool("is_send", True))
        tax = Node.void("tax")
        root.add_child(tax)
        tax.add_child(Node.s32("tax_phase", 1))

        return root

    def handle_highvoltage_gameinfo_get_request(self, request: Node) -> Node:
        root = Node.void("highvoltage_gameinfo")
        root.add_child(Node.u64("now_date", Time.now() * 1000))

        # extra music info. extern with omni. extra stage.
        extra_music = [
            2686, # CYCLONICxSTORM
            2687, # Heptagram
            2700, # Saiph
            2706, # LUCID NIGHTMARE
            2740, # Mobius
            2748, # Under The Shades Of The Divine Ray
            2772, # REBELLION
            2812, # THE LAST OF FIREFACE
        ]
        extra = Node.void("extra")
        root.add_child(extra)
        extra.add_child(Node.u8("extra_lv", len(extra_music)))
        extramusic = Node.void("extramusic")
        extra.add_child(extramusic)
        for extra_music_id in extra_music:
            music = Node.void("music")
            extramusic.add_child(music)
            music.add_child(Node.s32("musicid", extra_music_id))
            music.add_child(Node.u8("get_border", 0))

        # infect music
        infectmusic = [
            2110,  # MANDARA
            2111,  # デストロイマーチ
            2112,  # Joyeuse
            2407,  # Our Faith (Faithful MTL Remix)
            2438,  # 準備運動
            2532,  # Knights Assault
        ]
        infect_music = Node.void("infect_music")
        root.add_child(infect_music)
        infect_music.add_child(Node.u8("term", 1))
        for infect_music_id in infectmusic:
            music = Node.void("music")
            infect_music.add_child(music)
            music.add_child(Node.s32("musicid", infect_music_id))

        # unlock challenge. from bemaniwiki.
        # http://bemaniwiki.com/index.php?GITADORA%20NEX%2BAGE/%B1%A3%A4%B7%CD%D7%C1%C7/%B2%F2%B6%D8%A5%A4%A5%D9%A5%F3%A5%C8
        unlockchallenge = [
            2298,  # Just Believe
            2410,  # ギタドライト
            1516,  # ヒコーキ
            2426,  # Perfect World
            2432,  # Durian
            2445,  # ヤオヨロズランズ
            2441,  # Fate of the Furious
            2444,  # PIRATES BANQUET
            2471,  # DUELLA LYRICA
            2476,  # triangulum
            2486,  # MODEL FT4
            2496,  # 煉獄事変
            2497,  # CAPTURING XANADU
            2499,  # Physical Decay
            2424,  # 夢色☆スパイラル!!!!!
            2442,  # 桐一葉
            2461,  # The Kingsroad
            2465,  # Be a Hero!
            2466,  # Navy blue sea
            2462,  # 嘘だらけの僕から出た言葉
            2467,  # 最強ゲームエンド
            2437,  # 一夜のキセキ
            2470,  # Windy Fairy -GITADOROCK ver.-
            2468,  # ノルエピネフリン
            2469,  # ONE DAY
            2472,  # 7th Floor
            2473,  # 紫電一閃
            2474,  # 明日へと続く物語
            1322,  # Forever free
            2484,  # Sweet feelin'
            1513,  # 腐斯偽堕日本
            528,  # Riff Riff Paradise
            2492,
            514,
            2493,
            2490,
            515,
            2494,
            2503,
            2488,
            2502,
            961,
            1522,
            2429,
            2505,
            2504,
            1406,
            2506,
            2507,
            2508,
            2509,
            2510,
            2511,
            2512,  # secret music
        ]
        unlock_challenge = Node.void("unlock_challenge")
        root.add_child(unlock_challenge)
        unlock_challenge.add_child(Node.u8("term", 1))
        for unlock_challenge_id in unlockchallenge:
            music = Node.void("music")
            unlock_challenge.add_child(music)
            music.add_child(Node.s32("musicid", unlock_challenge_id))

        # trbitemdata
        root.add_child(Node.void("trbitemdata"))

        # ctrl_movie
        root.add_child(Node.void("ctrl_movie"))

        # ng_jacket
        root.add_child(Node.void("ng_jacket"))

        # ng_recommend_music
        root.add_child(Node.void("ng_recommend_music"))

        # ranking.
        ranking = Node.void("ranking")
        root.add_child(ranking)
        ranking.add_child(Node.void("skill_0_999"))
        ranking.add_child(Node.void("skill_1000_1499"))
        ranking.add_child(Node.void("skill_1500_1999"))
        ranking.add_child(Node.void("skill_2000_2499"))
        ranking.add_child(Node.void("skill_2500_2999"))
        ranking.add_child(Node.void("skill_3000_3499"))
        ranking.add_child(Node.void("skill_3500_3999"))
        ranking.add_child(Node.void("skill_4000_4499"))
        ranking.add_child(Node.void("skill_4500_4999"))
        ranking.add_child(Node.void("skill_5000_5499"))
        ranking.add_child(Node.void("skill_5500_5999"))
        ranking.add_child(Node.void("skill_6000_6499"))
        ranking.add_child(Node.void("skill_6500_6999"))
        ranking.add_child(Node.void("skill_7000_7499"))
        ranking.add_child(Node.void("skill_7500_7999"))
        ranking.add_child(Node.void("skill_8000_8499"))
        ranking.add_child(Node.void("skill_8500_9999"))
        ranking.add_child(Node.void("total"))
        ranking.add_child(Node.void("original"))
        ranking.add_child(Node.void("bemani"))
        ranking.add_child(Node.void("famous"))
        ranking.add_child(Node.void("anime"))
        ranking.add_child(Node.void("band"))
        ranking.add_child(Node.void("western"))

        # processing_report_state
        root.add_child(Node.u8("processing_report_state", 1))

        # recommendmusic. connect with hitchart.
        recommendmusic = Node.void("recommendmusic")
        root.add_child(recommendmusic)
        recommendmusic_list = []
        for (mid, _plays) in self.data.local.music.get_hit_chart(
            self.game, self.music_version, 41, 30
        ):
            recommendmusic_list.append(mid)
        if recommendmusic_list == []:
            recommendmusic.set_attribute("nr", "0")
        else:
            recommendmusic.set_attribute("nr", str(len(recommendmusic_list)))
            for recommendmusic_id in unlockchallenge:
                music = Node.void("music")
                recommendmusic.add_child(music)
                music.add_child(Node.s32("musicid", recommendmusic_id))

        # battle
        battle = Node.void("battle")
        root.add_child(battle)
        battle.add_child(Node.u8("term", 1))

        # battle_chara
        battle_chara = Node.void("battle_chara")
        root.add_child(battle_chara)
        battle_chara.add_child(Node.u8("term", 1))

        # data_ver_limit
        data_ver_limit = Node.void("data_ver_limit")
        root.add_child(data_ver_limit)
        data_ver_limit.add_child(Node.u8("term", 0)) #fuzzup in s32.

        # ea_pass_propel
        ea_pass_propel = Node.void("ea_pass_propel")
        root.add_child(ea_pass_propel)
        ea_pass_propel.add_child(Node.u8("term", 1))

        # phrase_combo_challenge
        for item in range(1, 21):
            if item == 1:
                phrase_combo_challenge = Node.void("phrase_combo_challenge")
                root.add_child(phrase_combo_challenge)
                phrase_combo_challenge.add_child(Node.u8("term", 0))
                phrase_combo_challenge.add_child(Node.u64("start_date_ms", 0))
                phrase_combo_challenge.add_child(Node.u64("end_date_ms", 0))
            else:
                phrase_combo_challenge = Node.void(f"phrase_combo_challenge_{item}")
                root.add_child(phrase_combo_challenge)
                phrase_combo_challenge.add_child(Node.u8("term", 0))
                phrase_combo_challenge.add_child(Node.u64("start_date_ms", 0))
                phrase_combo_challenge.add_child(Node.u64("end_date_ms", 0))

        # monthly_skill
        monthly_skill = Node.void("monthly_skill")
        root.add_child(monthly_skill)
        monthly_skill.add_child(Node.u8("term", 255))
        monthly_skill.add_child(Node.void("target_music"))

        # rockwave
        rockwave = Node.void("rockwave")
        root.add_child(rockwave)
        # rockwave.add_child(Node.void('event_list'))

        # general_term. event date in-games.
        general_term = Node.void("general_term")
        root.add_child(general_term)
        termdata = Node.void("termdata")
        general_term.add_child(termdata)

        # first. 50th konami logo.
        termdata.add_child(Node.string("type", "general_50th_konami_logo"))
        termdata.add_child(Node.u8("term", 0))
        termdata.add_child(Node.u64("start_date_ms", str(Time.now() * 1000)))
        termdata.add_child(Node.u64("end_date_ms", str((Time.now() + 86400) * 1000)))

        # musicians_road
        musicians_road = Node.void("musicians_road")
        root.add_child(musicians_road)
        musicians_road.add_child(Node.void("ranking_reward_list"))

        # lotterybox
        lotterybox = Node.void("lotterybox")
        root.add_child(lotterybox)
        lotterybox.add_child(Node.u8("term", 0))
        lotterybox.add_child(Node.u64("start_date_ms", Time.now() * 1000))
        lotterybox.add_child(Node.u64("end_date_ms", (Time.now() + 86400) * 1000))
        box_term = Node.void("box_term")
        lotterybox.add_child(box_term)
        box_term.add_child(Node.u8("state", 0))

        # assert_report_state
        root.add_child(Node.u8("assert_report_state", 1))

        # temperature
        temperature = Node.void("temperature")
        root.add_child(temperature)
        temperature.add_child(Node.bool("is_send", True))

        # update_prog
        update_prog = Node.void("update_prog")
        root.add_child(update_prog)
        update_prog.add_child(Node.u8("term", 0))

        return root

    def handle_highvoltage_cardutil_regist_request(self, request: Node) -> Node:
        root = Node.void("highvoltage_cardutil")
        # get player infomation
        refid = request.child_value("player/refid")
        name = request.child_value("player/name")
        previous_profile = self.get_profile_by_refid(refid)
        if previous_profile is not None:
            user_profile = self.get_profile(
                self.data.local.user.from_refid(self.game, self.version, refid)
            )
            player = Node.void("player")
            root.add_child(player)
            player.add_child(Node.bool("is_succession", True))
            player.add_child(Node.s32("did", user_profile.extid))
        else:
            self.new_profile_by_refid(refid, name)
            user_profile = self.get_profile(
                self.data.local.user.from_refid(self.game, self.version, refid)
            )
            player = Node.void("player")
            root.add_child(player)
            player.add_child(Node.bool("is_succession", False))
            player.add_child(Node.s32("did", user_profile.extid))

        return root

    def handle_highvoltage_cardutil_check_request(self, request: Node) -> Node:
        root = Node.void("highvoltage_cardutil")
        # get player infomation
        refid = request.child_value("player/refid")
        userid = self.data.local.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        # judge user profile if is not none.
        player = Node.void("player")
        root.add_child(player)
        player.set_attribute("no", "1")
        if profile is None:
            player.set_attribute("state", str(self.CARD_REGISTER))
        if profile is not None:
            player.set_attribute("state", str(self.CARD_USER_USED))
            player.add_child(Node.string("name", str(profile.get_str("name"))))
            player.add_child(Node.s32("did", profile.extid))
            player.add_child(Node.s32("charaid", profile.get_int("charaid")))
            # skilldata.
            skilldata_dict = profile.get_dict("skilldata")
            skilldata = Node.void("skilldata")
            player.add_child(skilldata)
            if self.model.spec == "A":  # gf
                skilldata.add_child(
                    Node.s32("skill", skilldata_dict.get_int("gf_skill"))
                )
                skilldata.add_child(
                    Node.s32(
                        "all_skill",
                        skilldata_dict.get_int("gf_all_skill")
                        + skilldata_dict.get_int("dm_all_skill"),
                    )
                )
                skilldata.add_child(
                    Node.s32("old_skill", skilldata_dict.get_int("gf_skill"))
                )
                skilldata.add_child(
                    Node.s32(
                        "old_all_skill",
                        skilldata_dict.get_int("gf_all_skill")
                        + skilldata_dict.get_int("dm_all_skill"),
                    )
                )
            if self.model.spec == "B":  # dm
                skilldata.add_child(
                    Node.s32("skill", skilldata_dict.get_int("dm_skill"))
                )
                skilldata.add_child(
                    Node.s32(
                        "all_skill",
                        skilldata_dict.get_int("gf_all_skill")
                        + skilldata_dict.get_int("dm_all_skill"),
                    )
                )
                skilldata.add_child(
                    Node.s32("old_skill", skilldata_dict.get_int("dm_skill"))
                )
                skilldata.add_child(
                    Node.s32(
                        "old_all_skill",
                        skilldata_dict.get_int("gf_all_skill")
                        + skilldata_dict.get_int("dm_all_skill"),
                    )
                )

        return root

    def handle_highvoltage_gametop_request(self, request: Node) -> Node:
        refid = request.child_value("player/refid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("highvoltage_gametop")
        return root

    def handle_highvoltage_gameend_request(self, request: Node) -> Node:
        refid = request.child_value("player/refid")
        # Profile save but you can also save scores here
        if refid is not None:
            userid = self.data.local.user.from_refid(self.game, self.version, refid)
        else:
            userid = None
        if userid is not None:
            oldprofile = self.get_profile(userid)
            newprofile = self.unformat_profile(userid, request, oldprofile)
        else:
            newprofile = None

        if userid is not None and newprofile is not None:
            self.put_profile(userid, newprofile)

        root = self.get_profile_by_refid(refid)
        if root is not None:
            root = Node.void("highvoltage_gameend")
            gamemode = Node.void("gamemode")
            root.add_child(gamemode)
            gamemode.set_attribute("mode", "game_mode")
            player = Node.void("player")
            root.add_child(player)
            player.set_attribute("no", "1")
            skill = Node.void("skill")
            player.add_child(skill)
            skill.add_child(Node.s32("rank", 1))
            skill.add_child(Node.s32("total_nr", 1))
            all_skill = Node.void("all_skill")
            player.add_child(all_skill)
            all_skill.add_child(Node.s32("rank", 1))
            all_skill.add_child(Node.s32("total_nr", 1))
        if root is None:
            root = Node.void("highvoltage_gameend")
        return root

    def handle_bemani_gakuen_request(self, request: Node) -> Node:
        return Node.void("bemani_gakuen")

    # HDD crash
    def handle_highvoltage_assert_report_request(self, request: Node) -> Node:
        root = Node.void("highvoltage_assert_report")
        root.add_child(Node.s8("result", 1))
        return root

    def handle_highvoltage_playablemusic_request(self, request: Node) -> Node:
        # TO DO: wait for final data. update hot music.
        root = Node.void("highvoltage_playablemusic")
        # hot
        hot = Node.void("hot")
        root.add_child(hot)
        hot.add_child(Node.s32("major", 1))
        hot.add_child(Node.s32("minor", 0))

        # musicinfo. should been import the musicdb at first.
        if self.omnimix == True:
            all_songs = MUSICLIST_HIGHVOLTAGE_OMNIMIX
        else:
            all_songs = MUSICLIST_HIGHVOLTAGE

        musicinfo = Node.void("musicinfo")
        root.add_child(musicinfo)
        musicinfo.set_attribute("nr", str(len(all_songs)))
        for music_item in all_songs:
            music = Node.void("music")
            musicinfo.add_child(music)
            music.add_child(Node.s32("id", music_item[0]))
            music.add_child(Node.bool("cont_gf", True))
            music.add_child(Node.bool("cont_dm", True))
            music.add_child(Node.bool("is_secret", False))  # unlock all
            if music_item[1] == 1:
                music.add_child(Node.bool("is_hot", True))
            else:
                music.add_child(Node.bool("is_hot", False))
            music.add_child(Node.s32("data_ver", music_item[2]))
            music.add_child(Node.u16_array("diff", music_item[3]))

        return root

    def handle_highvoltage_processing_report_request(self, request: Node) -> Node:
        return Node.void("highvoltage_processing_report")

    def handle_lobby_request_request(self, request: Node) -> Node:
        root = Node.void("lobby")
        
        # add battle request data.
        lobby_address_ip = str(request.child("lobbydata/address").child_value("ip"))
        lobby_check_attestid = str(request.child("lobbydata/check").child_value("attestid"))
        lobbydata = Node.void("lobbydata")
        root.add_child(lobbydata)
        candidate = Node.void("candidate")
        lobbydata.add_child(candidate)
        address = Node.void("address")
        candidate.add_child(address)
        address.add_child(Node.string("ip",lobby_address_ip))
        check = Node.void("check")
        candidate.add_child(check)
        check.add_child(Node.string("attestid", lobby_check_attestid))
            
        return root
    
    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        # Look up play stats we bridge to every mix
        statistics = self.get_play_statistics(userid)

        root = Node.void("highvoltage_gametop")
        player = Node.void("player")
        root.add_child(player)
        # player.set_attribute('no','1')
        player.add_child(Node.u64("now_date", Time.now() * 1000))
        # add playerboard. enable gitadora custom playerboard in-game.
        # default statement in data/product/xml/trbitem-info.xml.
        # TO DO: when user tying to add the playerboard, the default one is: 1
        playerboard = Node.void("playerboard")
        player.add_child(playerboard)
        if self.model.spec == "A":
            playerboard.add_child(Node.s32("index", self.GITADORA_GUITARFREAKS))
        if self.model.spec == "B":
            playerboard.add_child(Node.s32("index", self.GITADORA_DRUMMANIA))
        playerboard.add_child(Node.bool("is_active", True))
        # get setting from the playerboard.
        # profile should been saving like this:
        # ["sticker":[{"sticker_id": 1,"sticker_pos_x":160.000000,"sticker_pos_y":277.000000,"sticker_scale_x":1.000000,"sticker_scale_y":1.000000,"sticker_rotate":1.000000},]
        # well it should been saved it.
        """
        sticker_dict = profile.get_dict_array('sticker')
        for stickers in sticker_dict:
            sticker = Node.void('sticker')
            playerboard.add_child(sticker)
            #grab stickers from user profile.
            sticker.add_child(Node.s32('id',stickers['sticker_id']))
            sticker.add_child(Node.float('pos_x',stickers['sticker_pos_x']))
            sticker.add_child(Node.float('pos_y',stickers['sticker_pos_y']))
            sticker.add_child(Node.float('scale_x',stickers['sticker_scale_x']))
            sticker.add_child(Node.float('scale_y',stickers['sticker_scale_y']))
            sticker.add_child(Node.float('rotate',stickers['sticker_rotate']))
        """
        sticker_list = [
            {
                "sticker_id": 1,
                "sticker_pos_x": 160.000000,
                "sticker_pos_y": 235.000000,
                "sticker_scale_x": 1.000000,
                "sticker_scale_y": 1.000000,
                "sticker_rotate": 0.000000,
            },
        ]
        for stickers in sticker_list:
            sticker = Node.void("sticker")
            playerboard.add_child(sticker)
            sticker.add_child(Node.s32("id", int(stickers["sticker_id"])))
            sticker.add_child(Node.float("pos_x", stickers["sticker_pos_x"]))
            sticker.add_child(Node.float("pos_y", stickers["sticker_pos_y"]))
            sticker.add_child(Node.float("scale_x", stickers["sticker_scale_x"]))
            sticker.add_child(Node.float("scale_y", stickers["sticker_scale_y"]))
            sticker.add_child(Node.float("rotate", stickers["sticker_rotate"]))

        # player_info
        player_info = Node.void("player_info")
        player.add_child(player_info)
        player_info.add_child(Node.s8("player_type", 1))
        player_info.add_child(Node.s32("did", profile.extid))
        player_info.add_child(Node.string("name", str(profile.get_str("name"))))
        player_info.add_child(Node.string("title", str(profile.get_str("title"))))
        player_info.add_child(Node.s32("charaid", profile.get_int("charaid")))

        # playinfo
        playinfo = Node.void("playinfo")
        player.add_child(playinfo)
        playinfo.add_child(Node.s32("cabid", self.get_machine_id()))
        playinfo.add_child(Node.s32("play", statistics.total_plays))
        playinfo.add_child(Node.s32("playtime", profile.get_int("playtime")))
        playinfo.add_child(Node.s32("playterm", profile.get_int("playterm")))
        playinfo.add_child(Node.s32("session_cnt", profile.get_int("session_cnt")))
        playinfo.add_child(Node.s32("matching_num", profile.get_int("matching_num")))
        playinfo.add_child(Node.s32("extra_stage", profile.get_int("extra_stage")))
        playinfo.add_child(Node.s32("extra_play", profile.get_int("extra_play")))
        playinfo.add_child(Node.s32("extra_clear", profile.get_int("extra_clear")))
        playinfo.add_child(Node.s32("encore_play", profile.get_int("encore_play")))
        playinfo.add_child(Node.s32("encore_clear", profile.get_int("encore_clear")))
        playinfo.add_child(Node.s32("pencore_play", profile.get_int("pencore_play")))
        playinfo.add_child(Node.s32("pencore_clear", profile.get_int("pencore_clear")))
        playinfo.add_child(
            Node.s32("max_clear_diff", profile.get_int("max_clear_diff"))
        )
        playinfo.add_child(Node.s32("max_full_diff", profile.get_int("max_full_diff")))
        playinfo.add_child(Node.s32("max_exce_diff", profile.get_int("max_exce_diff")))
        playinfo.add_child(Node.s32("clear_num", profile.get_int("clear_num")))
        playinfo.add_child(Node.s32("full_num", profile.get_int("full_num")))
        playinfo.add_child(Node.s32("exce_num", profile.get_int("exce_num")))
        playinfo.add_child(Node.s32("no_num", profile.get_int("no_num")))
        playinfo.add_child(Node.s32("e_num", profile.get_int("e_num")))
        playinfo.add_child(Node.s32("d_num", profile.get_int("d_num")))
        playinfo.add_child(Node.s32("c_num", profile.get_int("c_num")))
        playinfo.add_child(Node.s32("b_num", profile.get_int("b_num")))
        playinfo.add_child(Node.s32("a_num", profile.get_int("a_num")))
        playinfo.add_child(Node.s32("s_num", profile.get_int("s_num")))
        playinfo.add_child(Node.s32("ss_num", profile.get_int("ss_num")))
        playinfo.add_child(Node.s32("last_category", profile.get_int("last_category")))
        playinfo.add_child(Node.s32("last_musicid", profile.get_int("last_musicid", -1)))
        playinfo.add_child(Node.s32("last_seq", profile.get_int("last_seq")))
        playinfo.add_child(Node.s32("disp_level", profile.get_int("disp_level")))

        # save custom data.
        customdata_dict = profile.get_dict("customdata")
        customdata = Node.void("customdata")
        player.add_child(customdata)
        customdata.add_child(
            Node.s32_array("playstyle", customdata_dict.get_int_array("playstyle", 50,
                [
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                20,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                2,
                20,
                0])
            )
        )
        customdata.add_child(
            Node.s32_array("custom", customdata_dict.get_int_array("custom", 50))
        )

        # skilldata. add in achievement.
        skilldata_dict = profile.get_dict("skilldata")
        skilldata = Node.void("skilldata")
        player.add_child(skilldata)
        if self.model.spec == "A":  # gf
            skilldata.add_child(Node.s32("skill", skilldata_dict.get_int("gf_skill")))
            skilldata.add_child(
                Node.s32(
                    "all_skill",
                    skilldata_dict.get_int("gf_all_skill")
                    + skilldata_dict.get_int("dm_all_skill"),
                )
            )
            skilldata.add_child(
                Node.s32("old_skill", skilldata_dict.get_int("gf_skill"))
            )
            skilldata.add_child(
                Node.s32(
                    "old_all_skill",
                    skilldata_dict.get_int("gf_all_skill")
                    + skilldata_dict.get_int("dm_all_skill"),
                )
            )
        if self.model.spec == "B":  # dm
            skilldata.add_child(Node.s32("skill", skilldata_dict.get_int("dm_skill")))
            skilldata.add_child(
                Node.s32(
                    "all_skill",
                    skilldata_dict.get_int("gf_all_skill")
                    + skilldata_dict.get_int("dm_all_skill"),
                )
            )
            skilldata.add_child(
                Node.s32("old_skill", skilldata_dict.get_int("dm_skill"))
            )
            skilldata.add_child(
                Node.s32(
                    "old_all_skill",
                    skilldata_dict.get_int("gf_all_skill")
                    + skilldata_dict.get_int("dm_all_skill"),
                )
            )

        # secretmusic
        secretmusic_node = Node.void("secretmusic")
        player.add_child(secretmusic_node)
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        for secretmusic in achievements:
            if secretmusic.type != "secretmusic":
                continue

            music_node = Node.void("music")
            secretmusic_node.add_child(music_node)
            music_node.add_child(Node.s32("musicid", secretmusic.id))
            music_node.add_child(Node.u16("seq", secretmusic.data.get_int("seq")))
            music_node.add_child(Node.s32("kind", secretmusic.data.get_int("kind")))

        # favoritemusic
        favoritemusic_dict = profile.get_dict("favoritemusic")
        favoritemusic = Node.void("favoritemusic")
        player.add_child(favoritemusic)
        favoritemusic.add_child(
            Node.s32_array(
                "list_1", favoritemusic_dict.get_int_array("list_1", 100, [-1] * 100)
            )
        )
        favoritemusic.add_child(
            Node.s32_array(
                "list_2", favoritemusic_dict.get_int_array("list_2", 100, [-1] * 100)
            )
        )
        favoritemusic.add_child(
            Node.s32_array(
                "list_3", favoritemusic_dict.get_int_array("list_3", 100, [-1] * 100)
            )
        )

        # chara_list
        chara_list = Node.void("chara_list")
        player.add_child(chara_list)
        chara = Node.void("chara")
        chara_list.add_child(chara)
        chara.add_child(Node.s32("charaid", 1))

        # title_parts
        player.add_child(Node.void("title_parts"))

        # information
        information_dict = profile.get_dict("information")
        information = Node.void("information")
        player.add_child(information)
        information.add_child(
            Node.u32_array("info", information_dict.get_int_array("info", 50))
        )

        # reward
        reward_dict = profile.get_dict("reward")
        reward = Node.void("reward")
        player.add_child(reward)
        reward.add_child(
            Node.u32_array("status", reward_dict.get_int_array("status", 50))
        )

        # groove
        groove_dict = profile.get_dict("groove")
        groove = Node.void("groove")
        player.add_child(groove)
        groove.add_child(Node.s32("extra_gauge", groove_dict.get_int("extra_gauge")))
        groove.add_child(Node.s32("encore_gauge", groove_dict.get_int("encore_gauge")))
        groove.add_child(Node.s32("encore_cnt", groove_dict.get_int("encore_cnt")))
        groove.add_child(
            Node.s32("encore_success", groove_dict.get_int("encore_success"))
        )
        groove.add_child(Node.s32("unlock_point", groove_dict.get_int("unlock_point")))

        # rivaldata and friend data.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivaldata = Node.void("rivaldata")
        player.add_child(rivaldata)
        for link in links:
            rival_type = None
            if link.type == "gf_rival":
                rival_type = "1"
            elif link.type == "dm_rival":
                rival_type = "2"
            else:
                # No business with this link type
                continue
            other_profile = self.get_profile(link.other_userid)
            if self.model.spec == "A" and rival_type == "1":  # gf
                rival = Node.void("rival")
                rivaldata.add_child(rival)
                rival.add_child(Node.s32("did", other_profile.extid))
                rival.add_child(Node.string("name", other_profile.get_str("name")))
                rival.add_child(Node.s32("active_index", 1))
                rival.add_child(Node.string("refid", other_profile.refid))
            if self.model.spec == "B" and rival_type == "2":  # dm
                rival = Node.void("rival")
                rivaldata.add_child(rival)
                rival.add_child(Node.s32("did", other_profile.extid))
                rival.add_child(Node.string("name", other_profile.get_str("name")))
                rival.add_child(Node.s32("active_index", 1))
                rival.add_child(Node.string("refid", other_profile.refid))
            else:
                continue
        player.add_child(Node.void("frienddata"))
        # TO DO: need to take down all rival on it.

        # skindata
        skindata = Node.void("skindata")
        player.add_child(skindata)
        skindata.add_child(
            Node.u32_array("skin", profile.get_int_array("skin", 100, [255] * 100))
        )

        # tutorial
        tutorial_dict = profile.get_dict("tutorial")
        tutorial = Node.void("tutorial")
        player.add_child(tutorial)
        tutorial.add_child(Node.s32("progress", tutorial_dict.get_int("progress")))
        tutorial.add_child(Node.u32("disp_state", tutorial_dict.get_int("disp_state")))

        # get all records.
        record = Node.void("record")
        player.add_child(record)
        # first gf's record.
        gf_record = profile.get_dict("gf_record")
        gf = Node.void("gf")
        record.add_child(gf)
        max_record = Node.void("max_record")
        gf.add_child(max_record)
        max_record.add_child(Node.s32("skill", gf_record.get_int("skill")))
        max_record.add_child(Node.s32("all_skill", gf_record.get_int("all_skill")))
        max_record.add_child(Node.s32("clear_diff", gf_record.get_int("clear_diff")))
        max_record.add_child(Node.s32("full_diff", gf_record.get_int("full_diff")))
        max_record.add_child(Node.s32("exce_diff", gf_record.get_int("exce_diff")))
        max_record.add_child(
            Node.s32("clear_music_num", gf_record.get_int("clear_music_num"))
        )
        max_record.add_child(
            Node.s32("full_music_num", gf_record.get_int("full_music_num"))
        )
        max_record.add_child(
            Node.s32("exce_music_num", gf_record.get_int("exce_music_num"))
        )
        max_record.add_child(
            Node.s32("clear_seq_num", gf_record.get_int("clear_seq_num"))
        )
        max_record.add_child(
            Node.s32("classic_all_skill", gf_record.get_int("classic_all_skill"))
        )
        diff_record = Node.void("diff_record")
        gf.add_child(diff_record)
        # diff_nr
        diff_record.add_child(Node.s32("diff_100_nr", gf_record.get_int("diff_100_nr")))
        diff_record.add_child(Node.s32("diff_150_nr", gf_record.get_int("diff_150_nr")))
        diff_record.add_child(Node.s32("diff_200_nr", gf_record.get_int("diff_200_nr")))
        diff_record.add_child(Node.s32("diff_250_nr", gf_record.get_int("diff_250_nr")))
        diff_record.add_child(Node.s32("diff_300_nr", gf_record.get_int("diff_300_nr")))
        diff_record.add_child(Node.s32("diff_350_nr", gf_record.get_int("diff_350_nr")))
        diff_record.add_child(Node.s32("diff_400_nr", gf_record.get_int("diff_400_nr")))
        diff_record.add_child(Node.s32("diff_450_nr", gf_record.get_int("diff_450_nr")))
        diff_record.add_child(Node.s32("diff_500_nr", gf_record.get_int("diff_500_nr")))
        diff_record.add_child(Node.s32("diff_550_nr", gf_record.get_int("diff_550_nr")))
        diff_record.add_child(Node.s32("diff_600_nr", gf_record.get_int("diff_600_nr")))
        diff_record.add_child(Node.s32("diff_650_nr", gf_record.get_int("diff_650_nr")))
        diff_record.add_child(Node.s32("diff_700_nr", gf_record.get_int("diff_700_nr")))
        diff_record.add_child(Node.s32("diff_750_nr", gf_record.get_int("diff_750_nr")))
        diff_record.add_child(Node.s32("diff_800_nr", gf_record.get_int("diff_800_nr")))
        diff_record.add_child(Node.s32("diff_850_nr", gf_record.get_int("diff_850_nr")))
        diff_record.add_child(Node.s32("diff_900_nr", gf_record.get_int("diff_900_nr")))
        diff_record.add_child(Node.s32("diff_950_nr", gf_record.get_int("diff_850_nr")))
        # diff_clear
        diff_record.add_child(
            Node.s32_array(
                "diff_100_clear", profile.get_int_array("gf_diff_100_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_150_clear", profile.get_int_array("gf_diff_150_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_200_clear", profile.get_int_array("gf_diff_200_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_250_clear", profile.get_int_array("gf_diff_250_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_300_clear", profile.get_int_array("gf_diff_300_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_350_clear", profile.get_int_array("gf_diff_350_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_400_clear", profile.get_int_array("gf_diff_400_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_450_clear", profile.get_int_array("gf_diff_450_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_500_clear", profile.get_int_array("gf_diff_500_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_550_clear", profile.get_int_array("gf_diff_550_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_600_clear", profile.get_int_array("gf_diff_600_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_650_clear", profile.get_int_array("gf_diff_650_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_700_clear", profile.get_int_array("gf_diff_700_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_750_clear", profile.get_int_array("gf_diff_750_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_800_clear", profile.get_int_array("gf_diff_800_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_850_clear", profile.get_int_array("gf_diff_850_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_900_clear", profile.get_int_array("gf_diff_900_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_950_clear", profile.get_int_array("gf_diff_850_clear", 7)
            )
        )

        # dm's record.
        dm_record = profile.get_dict("dm_record")
        dm = Node.void("dm")
        record.add_child(dm)
        max_record = Node.void("max_record")
        dm.add_child(max_record)
        max_record.add_child(Node.s32("skill", dm_record.get_int("skill")))
        max_record.add_child(Node.s32("all_skill", dm_record.get_int("all_skill")))
        max_record.add_child(Node.s32("clear_diff", dm_record.get_int("clear_diff")))
        max_record.add_child(Node.s32("full_diff", dm_record.get_int("full_diff")))
        max_record.add_child(Node.s32("exce_diff", dm_record.get_int("exce_diff")))
        max_record.add_child(
            Node.s32("clear_music_num", dm_record.get_int("clear_music_num"))
        )
        max_record.add_child(
            Node.s32("full_music_num", dm_record.get_int("full_music_num"))
        )
        max_record.add_child(
            Node.s32("exce_music_num", dm_record.get_int("exce_music_num"))
        )
        max_record.add_child(
            Node.s32("clear_seq_num", dm_record.get_int("clear_seq_num"))
        )
        max_record.add_child(
            Node.s32("classic_all_skill", dm_record.get_int("classic_all_skill"))
        )
        diff_record = Node.void("diff_record")
        dm.add_child(diff_record)
        # diff_nr
        diff_record.add_child(Node.s32("diff_100_nr", dm_record.get_int("diff_100_nr")))
        diff_record.add_child(Node.s32("diff_150_nr", dm_record.get_int("diff_150_nr")))
        diff_record.add_child(Node.s32("diff_200_nr", dm_record.get_int("diff_200_nr")))
        diff_record.add_child(Node.s32("diff_250_nr", dm_record.get_int("diff_250_nr")))
        diff_record.add_child(Node.s32("diff_300_nr", dm_record.get_int("diff_300_nr")))
        diff_record.add_child(Node.s32("diff_350_nr", dm_record.get_int("diff_350_nr")))
        diff_record.add_child(Node.s32("diff_400_nr", dm_record.get_int("diff_400_nr")))
        diff_record.add_child(Node.s32("diff_450_nr", dm_record.get_int("diff_450_nr")))
        diff_record.add_child(Node.s32("diff_500_nr", dm_record.get_int("diff_500_nr")))
        diff_record.add_child(Node.s32("diff_550_nr", dm_record.get_int("diff_550_nr")))
        diff_record.add_child(Node.s32("diff_600_nr", dm_record.get_int("diff_600_nr")))
        diff_record.add_child(Node.s32("diff_650_nr", dm_record.get_int("diff_650_nr")))
        diff_record.add_child(Node.s32("diff_700_nr", dm_record.get_int("diff_700_nr")))
        diff_record.add_child(Node.s32("diff_750_nr", dm_record.get_int("diff_750_nr")))
        diff_record.add_child(Node.s32("diff_800_nr", dm_record.get_int("diff_800_nr")))
        diff_record.add_child(Node.s32("diff_850_nr", dm_record.get_int("diff_850_nr")))
        diff_record.add_child(Node.s32("diff_900_nr", dm_record.get_int("diff_900_nr")))
        diff_record.add_child(Node.s32("diff_950_nr", dm_record.get_int("diff_850_nr")))
        # diff_clear
        diff_record.add_child(
            Node.s32_array(
                "diff_100_clear", profile.get_int_array("dm_diff_100_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_150_clear", profile.get_int_array("dm_diff_150_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_200_clear", profile.get_int_array("dm_diff_200_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_250_clear", profile.get_int_array("dm_diff_250_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_300_clear", profile.get_int_array("dm_diff_300_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_350_clear", profile.get_int_array("dm_diff_350_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_400_clear", profile.get_int_array("dm_diff_400_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_450_clear", profile.get_int_array("dm_diff_450_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_500_clear", profile.get_int_array("dm_diff_500_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_550_clear", profile.get_int_array("dm_diff_550_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_600_clear", profile.get_int_array("dm_diff_600_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_650_clear", profile.get_int_array("dm_diff_650_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_700_clear", profile.get_int_array("dm_diff_700_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_750_clear", profile.get_int_array("dm_diff_750_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_800_clear", profile.get_int_array("dm_diff_800_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_850_clear", profile.get_int_array("dm_diff_850_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_900_clear", profile.get_int_array("dm_diff_900_clear", 7)
            )
        )
        diff_record.add_child(
            Node.s32_array(
                "diff_950_clear", profile.get_int_array("dm_diff_850_clear", 7)
            )
        )

        # battledata
        battledata_dict = profile.get_dict("battledata")
        battledata = Node.void("battledata")
        player.add_child(battledata)
        info = Node.void("info")
        battledata.add_child(info)
        info.add_child(Node.s32("orb", battledata_dict.get_int("orb")))
        info.add_child(
            Node.s32("get_gb_point", battledata_dict.get_int("get_gb_point"))
        )
        info.add_child(
            Node.s32("send_gb_point", battledata_dict.get_int("send_gb_point"))
        )
        # greeting
        greeting = Node.void("greeting")
        battledata.add_child(greeting)
        greeting.add_child(Node.string("greeting_1", "Thanks!"))
        greeting.add_child(Node.string("greeting_2", "Hello!"))
        greeting.add_child(Node.string("greeting_3", "Wait a moment."))
        greeting.add_child(Node.string("greeting_4", "I 'll try my best!"))
        greeting.add_child(
            Node.string("greeting_5", "I 'll go with my favorite songs!")
        )
        greeting.add_child(Node.string("greeting_6", "I go with my favorite songs!"))
        greeting.add_child(Node.string("greeting_7", "I don't feel confident."))
        greeting.add_child(Node.string("greeting_8", "Thank you!"))
        greeting.add_child(Node.string("greeting_9", "See you!"))
        # setting
        setting = Node.void("setting")
        battledata.add_child(setting)
        setting.add_child(Node.s32("matching", battledata_dict.get_int("matching")))
        setting.add_child(Node.s32("info_level", battledata_dict.get_int("info_level")))
        # score
        score = Node.void("score")
        battledata.add_child(score)
        score.add_child(
            Node.s32("battle_class", battledata_dict.get_int("battle_class"))
        )
        score.add_child(
            Node.s32("max_battle_class", battledata_dict.get_int("max_battle_class"))
        )
        score.add_child(
            Node.s32("battle_point", battledata_dict.get_int("battle_point"))
        )
        score.add_child(Node.s32("win", battledata_dict.get_int("win")))
        score.add_child(Node.s32("lose", battledata_dict.get_int("lose")))
        score.add_child(Node.s32("draw", battledata_dict.get_int("draw")))
        score.add_child(
            Node.s32("consecutive_win", battledata_dict.get_int("consecutive_win"))
        )
        score.add_child(
            Node.s32(
                "max_consecutive_win", battledata_dict.get_int("max_consecutive_win")
            )
        )
        score.add_child(
            Node.s32("glorious_win", battledata_dict.get_int("glorious_win"))
        )
        score.add_child(
            Node.s32("max_defeat_skill", battledata_dict.get_int("max_defeat_skill"))
        )
        score.add_child(
            Node.s32("latest_result", battledata_dict.get_int("latest_result"))
        )
        # history
        battledata.add_child(Node.void("history"))

        # free play
        player.add_child(Node.bool("is_free_ok", False))

        # ranking
        # We dont support:
        ranking = Node.void("ranking")
        player.add_child(ranking)
        # TO DO: add current skill ranking and all ranking for each player.
        skill = Node.void("skill")
        ranking.add_child(skill)
        skill.add_child(Node.s32("rank", 1))
        skill.add_child(Node.s32("total_nr", 1))

        all_skill = Node.void("all_skill")
        ranking.add_child(all_skill)
        all_skill.add_child(Node.s32("rank", 1))
        all_skill.add_child(Node.s32("total_nr", 1))

        # stage_result
        stage_result = Node.void("stage_result")
        player.add_child(stage_result)

        # monthly_skill.
        player.add_child(Node.void("monthly_skill"))

        # event skill.
        event_skill_dict = profile.get_dict("event_skill")
        event_skill = Node.void("event_skill")
        player.add_child(event_skill)
        event_skill.add_child(Node.s32("skill", event_skill_dict.get_int("skill")))
        ranking = Node.void("ranking")
        event_skill.add_child(ranking)
        ranking.add_child(Node.s32("rank", event_skill_dict.get_int("rank")))
        ranking.add_child(Node.s32("total_nr", event_skill_dict.get_int("total_nr")))
        event_skill.add_child(Node.void("eventlist"))

        # event_score
        event_score = Node.void("event_score")
        player.add_child(event_score)
        event_score.add_child(Node.void("eventlist"))

        for item in range(1, 21):
            if item == 1:
                phrase_combo_challenge = Node.void("phrase_combo_challenge")
                player.add_child(phrase_combo_challenge)
                phrase_combo_challenge.add_child(Node.s32("point", 0))
            else:
                phrase_combo_challenge = Node.void(f"phrase_combo_challenge_{item}")
                player.add_child(phrase_combo_challenge)
                phrase_combo_challenge.add_child(Node.s32("point", 0))

        # long_otobear_fes_1
        long_otobear_fes_1 = Node.void("long_otobear_fes_1")
        player.add_child(long_otobear_fes_1)
        long_otobear_fes_1.add_child(Node.s32("point", profile.get_int("point")))

        # rockwave
        rockwave = Node.void("rockwave")
        player.add_child(rockwave)
        score_list = Node.void("score_list")
        rockwave.add_child(score_list)
        score = Node.void("score")
        score_list.add_child(score)
        score.add_child(Node.s32("data_id", 0))
        score.add_child(Node.u64("point", 0))
        score.add_child(Node.u64("mtime", 0))
        score.add_child(Node.s32("play_cnt", 0))
        score.add_child(Node.bool("is_clear", False))

        # musicians_road
        musicians_road = Node.void("musicians_road")
        player.add_child(musicians_road)
        musicians_road.add_child(Node.void("score_list"))

        # stage_result. thats user play record.
        # musiclist. its all the score list.
        scores = self.data.remote.music.get_scores(
            self.game, self.music_version, userid
        )
        all_scores = self.make_score_struct(
            scores,
            self.GITADORA_GUITARFREAKS
            if self.model.spec == "A"
            else self.GITADORA_DRUMMANIA,
        )
        musiclist = Node.void("musiclist")
        player.add_child(musiclist)
        musiclist.set_attribute(
            "nr", str(len(all_scores) if len(all_scores) != 0 else 0)
        )
        for s in all_scores:
            mdata = [-1] + s[1:17] + [0, 0, 0]
            flag = [
                int(
                    s[17] * 2
                    + s[18] * 4
                    + s[19] * 8
                    + s[20] * 16
                    + s[21] * 32
                    + s[22] * 64
                    + s[23] * 128
                    + s[24] * 256
                ),
                int(
                    s[25] * 2
                    + s[26] * 4
                    + s[27] * 8
                    + s[28] * 16
                    + s[29] * 32
                    + s[30] * 64
                    + s[31] * 128
                    + s[32] * 256
                ),
                int(
                    s[33] * 2
                    + s[34] * 4
                    + s[35] * 8
                    + s[36] * 16
                    + s[37] * 32
                    + s[38] * 64
                    + s[39] * 128
                    + s[40] * 256
                ),
                0,
                0,
            ]
            sdata = [s[41:49].index(max(s[41:49])), max(s[41:49])]
            meter = s[49:57]
            meter_prog = s[57:65]
            data = Node.void("data")
            stage_result.add_child(data)
            data.add_child(Node.s32("musicid", -1 if len(all_scores) == 0 else s[0]))
            # musiclist.
            musicdata = Node.void("musicdata")
            musiclist.add_child(musicdata)
            musicdata.set_attribute("musicid", str(s[0]))
            musicdata.add_child(Node.s16_array("mdata", mdata))
            musicdata.add_child(Node.u16_array("flag", flag))
            musicdata.add_child(Node.s16_array("sdata", sdata))
            musicdata.add_child(Node.u64_array("meter", meter))
            musicdata.add_child(Node.s16_array("meter_prog", meter_prog))
        # finish
        player.add_child(Node.bool("finish", True))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = copy.deepcopy(oldprofile)
        # Keep track of play statistics
        self.update_play_statistics(userid)

        # save customdata.
        customdata = request.child("player/customdata")
        if customdata is not None:
            customdata_dict = newprofile.get_dict("customdata")
            customdata_dict.replace_int_array(
                "playstyle", 50, customdata.child_value("playstyle")
            )
            customdata_dict.replace_int_array(
                "custom", 50, customdata.child_value("custom")
            )
            newprofile.replace_dict("customdata", customdata_dict)

        # save player info
        playinfo = request.child("player/playinfo")
        if playinfo is not None:
            newprofile.replace_int("playtime", int(playinfo.child_value("playtime")))
            newprofile.replace_int("playterm", int(playinfo.child_value("playterm")))
            newprofile.replace_int(
                "session_cnt", int(playinfo.child_value("session_cnt"))
            )
            newprofile.replace_int(
                "matching_num", int(playinfo.child_value("matching_num"))
            )
            newprofile.replace_int(
                "extra_stage", int(playinfo.child_value("extra_stage"))
            )
            newprofile.replace_int(
                "extra_play", int(playinfo.child_value("extra_play"))
            )
            newprofile.replace_int(
                "extra_clear", int(playinfo.child_value("extra_clear"))
            )
            newprofile.replace_int(
                "encore_play", int(playinfo.child_value("encore_play"))
            )
            newprofile.replace_int(
                "encore_clear", int(playinfo.child_value("encore_clear"))
            )
            newprofile.replace_int(
                "pencore_play", int(playinfo.child_value("pencore_play"))
            )
            newprofile.replace_int(
                "pencore_clear", int(playinfo.child_value("pencore_clear"))
            )
            newprofile.replace_int(
                "max_clear_diff", int(playinfo.child_value("max_clear_diff"))
            )
            newprofile.replace_int(
                "max_full_diff", int(playinfo.child_value("max_full_diff"))
            )
            newprofile.replace_int(
                "max_exce_diff", int(playinfo.child_value("max_exce_diff"))
            )
            newprofile.replace_int("clear_num", int(playinfo.child_value("clear_num")))
            newprofile.replace_int("full_num", int(playinfo.child_value("full_num")))
            newprofile.replace_int("exce_num", int(playinfo.child_value("exce_num")))
            newprofile.replace_int("no_num", int(playinfo.child_value("no_num")))
            newprofile.replace_int("e_num", int(playinfo.child_value("e_num")))
            newprofile.replace_int("d_num", int(playinfo.child_value("d_num")))
            newprofile.replace_int("c_num", int(playinfo.child_value("c_num")))
            newprofile.replace_int("b_num", int(playinfo.child_value("b_num")))
            newprofile.replace_int("a_num", int(playinfo.child_value("a_num")))
            newprofile.replace_int("s_num", int(playinfo.child_value("s_num")))
            newprofile.replace_int("ss_num", int(playinfo.child_value("ss_num")))
            newprofile.replace_int(
                "last_category", int(playinfo.child_value("last_category"))
            )
            newprofile.replace_int(
                "last_musicid", int(playinfo.child_value("last_musicid"))
            )
            newprofile.replace_int("last_seq", int(playinfo.child_value("last_seq")))
            newprofile.replace_int(
                "disp_level", int(playinfo.child_value("disp_level"))
            )

        # save secretmusic
        secretmusic = request.child("player/secretmusic")
        if secretmusic is not None:
            for music in secretmusic.children:
                if music.name != "music":
                    continue

                # save secretmusic in achievements.
                musicid = int(music.child_value("musicid"))
                seq = int(music.child_value("seq"))
                kind = int(music.child_value("kind"))

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    musicid,
                    "secretmusic",
                    {
                        "seq": seq,
                        "kind": kind,
                    },
                )

        # save tutorial.
        tutorial = request.child("player/tutorial")
        if tutorial is not None:
            tutorial_dict = newprofile.get_dict("tutorial")
            tutorial_dict.replace_int("progress", int(tutorial.child_value("progress")))
            tutorial_dict.replace_int(
                "disp_state", int(tutorial.child_value("disp_state"))
            )
            newprofile.replace_dict("tutorial", tutorial_dict)

        # save information.
        information = request.child("player/information")
        if information is not None:
            information_dict = newprofile.get_dict("information")
            information_dict.replace_int_array(
                "info", 50, information.child_value("info")
            )
            newprofile.replace_dict("infomation", information_dict)

        # saved reward.
        reward = request.child("player/reward")
        if reward is not None:
            reward_dict = newprofile.get_dict("reward")
            reward_dict.replace_int_array("status", 50, reward.child_value("status"))
            newprofile.replace_dict("reward", reward_dict)

        # save skilldata.
        skilldata = request.child("player/skilldata")
        if skilldata is not None:
            skilldata_dict = newprofile.get_dict("skilldata")
            if self.model.spec == "A":  # gf
                skilldata_dict.replace_int(
                    "gf_skill", int(skilldata.child_value("skill"))
                )
                skilldata_dict.replace_int(
                    "gf_all_skill", int(skilldata.child_value("all_skill"))
                )
                skilldata_dict.replace_int_array(
                    "gf_exist", 25, skilldata.child_value("exist")
                )
                skilldata_dict.replace_int_array(
                    "gf_new", 25, skilldata.child_value("new")
                )
            if self.model.spec == "B":  # dm
                skilldata_dict.replace_int(
                    "dm_skill", int(skilldata.child_value("skill"))
                )
                skilldata_dict.replace_int(
                    "dm_all_skill", int(skilldata.child_value("all_skill"))
                )
                skilldata_dict.replace_int_array(
                    "dm_exist", 25, skilldata.child_value("exist")
                )
                skilldata_dict.replace_int_array(
                    "dm_new", 25, skilldata.child_value("new")
                )
            newprofile.replace_dict("skilldata", skilldata_dict)

        # save groove
        groove = request.child("player/groove")
        if groove is not None:
            groove_dict = newprofile.get_dict("groove")
            groove_dict.replace_int(
                "extra_gauge", int(groove.child_value("extra_gauge"))
            )
            groove_dict.replace_int(
                "encore_gauge", int(groove.child_value("encore_gauge"))
            )
            groove_dict.replace_int("encore_cnt", int(groove.child_value("encore_cnt")))
            groove_dict.replace_int(
                "encore_success", int(groove.child_value("encore_success"))
            )
            groove_dict.replace_int(
                "unlock_point", int(groove.child_value("unlock_point"))
            )
            newprofile.replace_dict("groove", groove_dict)

        # save record
        record = request.child("player/record")
        if record is not None:
            if self.model.spec == "A":  # gf
                gf_record_dict = newprofile.get_dict("gf_record")
                gf_record_dict.replace_int("skill", record.child_value("max/skill"))
                gf_record_dict.replace_int(
                    "all_skill", record.child_value("max/all_skill")
                )
                gf_record_dict.replace_int(
                    "clear_diff", record.child_value("max/clear_diff")
                )
                gf_record_dict.replace_int(
                    "full_diff", record.child_value("max/full_diff")
                )
                gf_record_dict.replace_int(
                    "exce_diff", record.child_value("max/exce_diff")
                )
                gf_record_dict.replace_int(
                    "clear_music_num", record.child_value("max/clear_music_num")
                )
                gf_record_dict.replace_int(
                    "full_music_num", record.child_value("max/full_music_num")
                )
                gf_record_dict.replace_int(
                    "exce_music_num", record.child_value("max/exce_music_num")
                )
                gf_record_dict.replace_int(
                    "clear_seq_num", record.child_value("max/clear_seq_num")
                )
                gf_record_dict.replace_int(
                    "classic_all_skill", record.child_value("max/classic_all_skill")
                )
                gf_record_dict.replace_int(
                    "diff_100_nr", record.child_value("diff/diff_100_nr")
                )
                gf_record_dict.replace_int(
                    "diff_150_nr", record.child_value("diff/diff_150_nr")
                )
                gf_record_dict.replace_int(
                    "diff_200_nr", record.child_value("diff/diff_200_nr")
                )
                gf_record_dict.replace_int(
                    "diff_250_nr", record.child_value("diff/diff_250_nr")
                )
                gf_record_dict.replace_int(
                    "diff_300_nr", record.child_value("diff/diff_300_nr")
                )
                gf_record_dict.replace_int(
                    "diff_350_nr", record.child_value("diff/diff_350_nr")
                )
                gf_record_dict.replace_int(
                    "diff_400_nr", record.child_value("diff/diff_400_nr")
                )
                gf_record_dict.replace_int(
                    "diff_450_nr", record.child_value("diff/diff_450_nr")
                )
                gf_record_dict.replace_int(
                    "diff_500_nr", record.child_value("diff/diff_500_nr")
                )
                gf_record_dict.replace_int(
                    "diff_550_nr", record.child_value("diff/diff_550_nr")
                )
                gf_record_dict.replace_int(
                    "diff_600_nr", record.child_value("diff/diff_600_nr")
                )
                gf_record_dict.replace_int(
                    "diff_650_nr", record.child_value("diff/diff_650_nr")
                )
                gf_record_dict.replace_int(
                    "diff_700_nr", record.child_value("diff/diff_700_nr")
                )
                gf_record_dict.replace_int(
                    "diff_750_nr", record.child_value("diff/diff_750_nr")
                )
                gf_record_dict.replace_int(
                    "diff_800_nr", record.child_value("diff/diff_800_nr")
                )
                gf_record_dict.replace_int(
                    "diff_850_nr", record.child_value("diff/diff_850_nr")
                )
                gf_record_dict.replace_int(
                    "diff_900_nr", record.child_value("diff/diff_900_nr")
                )
                gf_record_dict.replace_int(
                    "diff_950_nr", record.child_value("diff/diff_950_nr")
                )
                newprofile.replace_dict("gf_record", gf_record_dict)
                # profile saving status.
                newprofile.replace_int_array(
                    "gf_diff_100_clear", 7, record.child_value("diff/diff_100_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_150_clear", 7, record.child_value("diff/diff_150_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_200_clear", 7, record.child_value("diff/diff_200_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_250_clear", 7, record.child_value("diff/diff_250_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_300_clear", 7, record.child_value("diff/diff_300_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_350_clear", 7, record.child_value("diff/diff_350_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_400_clear", 7, record.child_value("diff/diff_400_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_450_clear", 7, record.child_value("diff/diff_450_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_500_clear", 7, record.child_value("diff/diff_500_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_550_clear", 7, record.child_value("diff/diff_550_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_600_clear", 7, record.child_value("diff/diff_600_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_650_clear", 7, record.child_value("diff/diff_650_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_700_clear", 7, record.child_value("diff/diff_700_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_750_clear", 7, record.child_value("diff/diff_750_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_800_clear", 7, record.child_value("diff/diff_800_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_850_clear", 7, record.child_value("diff/diff_850_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_900_clear", 7, record.child_value("diff/diff_900_clear")
                )
                newprofile.replace_int_array(
                    "gf_diff_950_clear", 7, record.child_value("diff/diff_950_clear")
                )
            if self.model.spec == "B":  # dm
                dm_record_dict = newprofile.get_dict("dm_record")
                dm_record_dict.replace_int("skill", record.child_value("max/skill"))
                dm_record_dict.replace_int(
                    "all_skill", record.child_value("max/all_skill")
                )
                dm_record_dict.replace_int(
                    "clear_diff", record.child_value("max/clear_diff")
                )
                dm_record_dict.replace_int(
                    "full_diff", record.child_value("max/full_diff")
                )
                dm_record_dict.replace_int(
                    "exce_diff", record.child_value("max/exce_diff")
                )
                dm_record_dict.replace_int(
                    "clear_music_num", record.child_value("max/clear_music_num")
                )
                dm_record_dict.replace_int(
                    "full_music_num", record.child_value("max/full_music_num")
                )
                dm_record_dict.replace_int(
                    "exce_music_num", record.child_value("max/exce_music_num")
                )
                dm_record_dict.replace_int(
                    "clear_seq_num", record.child_value("max/clear_seq_num")
                )
                dm_record_dict.replace_int(
                    "classic_all_skill", record.child_value("max/classic_all_skill")
                )
                dm_record_dict.replace_int(
                    "diff_100_nr", record.child_value("diff/diff_100_nr")
                )
                dm_record_dict.replace_int(
                    "diff_150_nr", record.child_value("diff/diff_150_nr")
                )
                dm_record_dict.replace_int(
                    "diff_200_nr", record.child_value("diff/diff_200_nr")
                )
                dm_record_dict.replace_int(
                    "diff_250_nr", record.child_value("diff/diff_250_nr")
                )
                dm_record_dict.replace_int(
                    "diff_300_nr", record.child_value("diff/diff_300_nr")
                )
                dm_record_dict.replace_int(
                    "diff_350_nr", record.child_value("diff/diff_350_nr")
                )
                dm_record_dict.replace_int(
                    "diff_400_nr", record.child_value("diff/diff_400_nr")
                )
                dm_record_dict.replace_int(
                    "diff_450_nr", record.child_value("diff/diff_450_nr")
                )
                dm_record_dict.replace_int(
                    "diff_500_nr", record.child_value("diff/diff_500_nr")
                )
                dm_record_dict.replace_int(
                    "diff_550_nr", record.child_value("diff/diff_550_nr")
                )
                dm_record_dict.replace_int(
                    "diff_600_nr", record.child_value("diff/diff_600_nr")
                )
                dm_record_dict.replace_int(
                    "diff_650_nr", record.child_value("diff/diff_650_nr")
                )
                dm_record_dict.replace_int(
                    "diff_700_nr", record.child_value("diff/diff_700_nr")
                )
                dm_record_dict.replace_int(
                    "diff_750_nr", record.child_value("diff/diff_750_nr")
                )
                dm_record_dict.replace_int(
                    "diff_800_nr", record.child_value("diff/diff_800_nr")
                )
                dm_record_dict.replace_int(
                    "diff_850_nr", record.child_value("diff/diff_850_nr")
                )
                dm_record_dict.replace_int(
                    "diff_900_nr", record.child_value("diff/diff_900_nr")
                )
                dm_record_dict.replace_int(
                    "diff_950_nr", record.child_value("diff/diff_950_nr")
                )
                newprofile.replace_dict("dm_record", dm_record_dict)
                # profile saving status.
                newprofile.replace_int_array(
                    "dm_diff_100_clear", 7, record.child_value("diff/diff_100_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_150_clear", 7, record.child_value("diff/diff_150_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_200_clear", 7, record.child_value("diff/diff_200_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_250_clear", 7, record.child_value("diff/diff_250_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_300_clear", 7, record.child_value("diff/diff_300_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_350_clear", 7, record.child_value("diff/diff_350_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_400_clear", 7, record.child_value("diff/diff_400_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_450_clear", 7, record.child_value("diff/diff_450_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_500_clear", 7, record.child_value("diff/diff_500_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_550_clear", 7, record.child_value("diff/diff_550_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_600_clear", 7, record.child_value("diff/diff_600_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_650_clear", 7, record.child_value("diff/diff_650_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_700_clear", 7, record.child_value("diff/diff_700_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_750_clear", 7, record.child_value("diff/diff_750_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_800_clear", 7, record.child_value("diff/diff_800_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_850_clear", 7, record.child_value("diff/diff_850_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_900_clear", 7, record.child_value("diff/diff_900_clear")
                )
                newprofile.replace_int_array(
                    "dm_diff_950_clear", 7, record.child_value("diff/diff_950_clear")
                )

        # battle_data saving
        battledata = request.child("player/battledata")
        if battledata is not None:
            battledata_dict = newprofile.get_dict("battledata")
            battledata_dict.replace_int("orb", int(battledata.child_value("info/orb")))
            battledata_dict.replace_int(
                "get_gb_point", int(battledata.child_value("info/get_gb_point"))
            )
            battledata_dict.replace_int(
                "send_gb_point", int(battledata.child_value("info/send_gb_point"))
            )
            battledata_dict.replace_int(
                "matching", int(battledata.child_value("setting/matching"))
            )
            battledata_dict.replace_int(
                "info_level", int(battledata.child_value("setting/info_level"))
            )
            battledata_dict.replace_int(
                "battle_class", int(battledata.child_value("score/battle_class"))
            )
            battledata_dict.replace_int(
                "max_battle_class",
                int(battledata.child_value("score/max_battle_class")),
            )
            battledata_dict.replace_int(
                "battle_point", int(battledata.child_value("score/battle_point"))
            )
            battledata_dict.replace_int("win", int(battledata.child_value("score/win")))
            battledata_dict.replace_int(
                "lose", int(battledata.child_value("score/lose"))
            )
            battledata_dict.replace_int(
                "draw", int(battledata.child_value("score/draw"))
            )
            battledata_dict.replace_int(
                "consecutive_win", int(battledata.child_value("score/consecutive_win"))
            )
            battledata_dict.replace_int(
                "max_consecutive_win",
                int(battledata.child_value("score/max_consecutive_win")),
            )
            battledata_dict.replace_int(
                "glorious_win", int(battledata.child_value("score/glorious_win"))
            )
            battledata_dict.replace_int(
                "max_defeat_skill",
                int(battledata.child_value("score/max_defeat_skill")),
            )
            battledata_dict.replace_int(
                "latest_result", int(battledata.child_value("score/latest_result"))
            )
            newprofile.replace_dict("battledata", battledata_dict)

        # saving favoritemusic data
        favoritemusic = request.child("player/favoritemusic")
        if favoritemusic is not None:
            favoritemusic_dict = newprofile.get_dict("favoritemusic")
            favoritemusic_dict.replace_int_array(
                "list_1", 100, favoritemusic.child_value("music_list_1")
            )
            favoritemusic_dict.replace_int_array(
                "list_2", 100, favoritemusic.child_value("music_list_2")
            )
            favoritemusic_dict.replace_int_array(
                "list_3", 100, favoritemusic.child_value("music_list_3")
            )
            newprofile.replace_dict("favoritemusic", favoritemusic_dict)

        # saving skindata
        skindata = request.child("player/skindata")
        if skindata is not None:
            skindata_dict = newprofile.get_dict("skindata")
            skindata_dict.replace_int_array("skin", 100, skindata.child_value("skin"))
            newprofile.replace_dict("skindata", skindata_dict)

        # save stage result.
        player = request.child("player")
        for child in player.children:
            if child.name != "stage":
                continue
            else:
                # judge type for saving scores.
                # Required data to send back to the game
                songid = child.child_value("musicid")
                if self.model.spec == "A":  # gf
                    score_type = "gf"
                    game_chart = child.child_value("seq")
                    chart = self.game_to_db_chart_gituar(game_chart)
                if self.model.spec == "B":  # dm
                    score_type = "dm"
                    game_chart = child.child_value("seq")
                    chart = self.game_to_db_chart_drum(game_chart)
                # Timestamp needs to be an integer
                timestamp = child.child_value("date_ms") // 1000
                points = child.child_value(
                    "skill"
                )  # main point must be in skill without the score type.
                game_rank = child.child_value("rank")
                grade = self.__game_to_db_grade(game_rank)
                combo = child.child_value("combo")
                miss = child.child_value("miss")
                perc = child.child_value("perc")
                new_skill = child.child_value("new_skill")
                fullcombo = child.child_value("fullcombo")
                clear = child.child_value("clear")
                excellent = child.child_value("excellent")
                meter = child.child_value("meter")
                meter_prog = child.child_value("meter_prog")
                stats = {
                    "score": child.child_value("score"),
                    "flags": child.child_value("flags"),
                    "medal": child.child_value("medal"),
                    "perfect": child.child_value("perfect"),
                    "perfect_perc": child.child_value("perfect_perc"),
                    "great": child.child_value("great"),
                    "great_perc": child.child_value("great_perc"),
                    "good": child.child_value("good"),
                    "good_perc": child.child_value("good_perc"),
                    "ok": child.child_value("ok"),
                    "ok_perc": child.child_value("ok_perc"),
                    "miss": child.child_value("miss"),
                    "miss_perc": child.child_value("miss_perc"),
                    "phrase_data_num": child.child_value("phrase_data_num"),
                    "phrase_addr": child.child_value("phrase_addr"),
                    "phrase_type": child.child_value("phrase_type"),
                    "phrase_status": child.child_value("phrase_status"),
                    "phrase_end_addr": child.child_value("phrase_end_addr"),
                }
                self.update_score(
                    userid,
                    timestamp,
                    score_type,
                    songid,
                    chart,
                    points,
                    grade,
                    combo,
                    miss,
                    perc,
                    new_skill,
                    fullcombo,
                    clear,
                    excellent,
                    meter,
                    meter_prog,
                    stats,
                )

        return newprofile
