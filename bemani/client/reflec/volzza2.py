import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class ReflecBeatVolzza2(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_pcb_rb5_pcb_boot(self, loc: str) -> None:
        call = self.call_node()

        pcb = Node.void("pcb")
        pcb.set_attribute("method", "rb5_pcb_boot")
        pcb.add_child(Node.string("lid", loc))
        pcb.add_child(Node.string("rno", "MBR-JA-C01"))
        call.add_child(pcb)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcb/sinfo/nm")
        self.assert_path(resp, "response/pcb/sinfo/cl_enbl")
        self.assert_path(resp, "response/pcb/sinfo/cl_h")
        self.assert_path(resp, "response/pcb/sinfo/cl_m")
        self.assert_path(resp, "response/pcb/sinfo/shop_flag")

    def verify_pcb_rb5_pcb_error(self, loc: str) -> None:
        call = self.call_node()

        pcb = Node.void("pcb")
        call.add_child(pcb)
        pcb.set_attribute("method", "rb5_pcb_error")
        pcb.add_child(Node.string("lid", loc))
        pcb.add_child(Node.string("code", "exception"))
        pcb.add_child(Node.string("msg", "exceptionstring"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcb/@status")

    def verify_info_rb5_info_read(self, loc: str) -> None:
        call = self.call_node()

        info = Node.void("info")
        call.add_child(info)
        info.set_attribute("method", "rb5_info_read")
        info.add_child(Node.string("lid", loc))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info/event_ctrl")
        self.assert_path(resp, "response/info/item_lock_ctrl")
        self.assert_path(resp, "response/info/mycourse_ctrl")

    def verify_info_rb5_info_read_shop_ranking(self, loc: str) -> None:
        call = self.call_node()

        info = Node.void("info")
        call.add_child(info)
        info.set_attribute("method", "rb5_info_read_shop_ranking")
        # Arbitrarily chosen based on the song IDs we send in the
        # score section below.
        info.add_child(Node.s16("min", 1))
        info.add_child(Node.s16("max", 10))
        info.add_child(Node.string("lid", loc))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info/shop_score/time")
        self.assert_path(resp, "response/info/shop_score/data/rank")
        self.assert_path(resp, "response/info/shop_score/data/music_id")
        self.assert_path(resp, "response/info/shop_score/data/note_grade")
        self.assert_path(resp, "response/info/shop_score/data/clear_type")
        self.assert_path(resp, "response/info/shop_score/data/user_id")
        self.assert_path(resp, "response/info/shop_score/data/icon_id")
        self.assert_path(resp, "response/info/shop_score/data/score")
        self.assert_path(resp, "response/info/shop_score/data/time")
        self.assert_path(resp, "response/info/shop_score/data/name")

    def verify_info_rb5_info_read_hit_chart(self) -> None:
        call = self.call_node()

        info = Node.void("info")
        info.set_attribute("method", "rb5_info_read_hit_chart")
        info.add_child(Node.s32("ver", 0))
        call.add_child(info)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info/ver")
        self.assert_path(resp, "response/info/ranking/weekly/bt")
        self.assert_path(resp, "response/info/ranking/weekly/et")
        self.assert_path(resp, "response/info/ranking/weekly/new/d/mid")
        self.assert_path(resp, "response/info/ranking/weekly/new/d/cnt")
        self.assert_path(resp, "response/info/ranking/monthly/bt")
        self.assert_path(resp, "response/info/ranking/monthly/et")
        self.assert_path(resp, "response/info/ranking/monthly/new/d/mid")
        self.assert_path(resp, "response/info/ranking/monthly/new/d/cnt")
        self.assert_path(resp, "response/info/ranking/total/bt")
        self.assert_path(resp, "response/info/ranking/total/et")
        self.assert_path(resp, "response/info/ranking/total/new/d/mid")
        self.assert_path(resp, "response/info/ranking/total/new/d/cnt")

    def verify_player_rb5_player_start(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_start")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.u8_array("ga", [127, 0, 0, 1]))
        player.add_child(Node.u16("gp", 10573))
        player.add_child(Node.u8_array("la", [16, 0, 0, 0]))
        player.add_child(Node.u8_array("pnid", [39, 16, 0, 0, 0, 23, 62, 60, 39, 127, 0, 0, 1, 23, 62, 60]))

        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/plyid")
        self.assert_path(resp, "response/player/start_time")
        self.assert_path(resp, "response/player/event_ctrl")
        self.assert_path(resp, "response/player/item_lock_ctrl")
        self.assert_path(resp, "response/player/mycourse_ctrl")

    def verify_player_rb5_player_end(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_end")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player")

    def verify_player_rb5_player_read_rank_5(self) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_read_rank_5")
        player.add_child(Node.s32("uid", 0))
        player.add_child(Node.s32_array("sc", [897, 897, 0, 0, 0]))
        player.add_child(Node.s8("mg_id", 0))
        player.add_child(Node.s32("mg_sc", 220))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/tbs/new_rank")
        self.assert_path(resp, "response/player/tbs/old_rank")
        self.assert_path(resp, "response/player/mng/new_rank")
        self.assert_path(resp, "response/player/mng/old_rank")

    def verify_player_rb5_player_read_rival_score_5(self, extid: int) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_read_rival_score_5")
        player.add_child(Node.s32("uid", extid))
        player.add_child(Node.s32("music_id", 6))
        player.add_child(Node.s8("note_grade", 0))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/@status")

        # Verify that we got a score if the extid is nonzero
        if extid != 0:
            self.assert_path(resp, "response/player/player_select_score/user_id")
            self.assert_path(resp, "response/player/player_select_score/name")
            self.assert_path(resp, "response/player/player_select_score/m_score")
            self.assert_path(resp, "response/player/player_select_score/m_scoreTime")
            self.assert_path(resp, "response/player/player_select_score/m_iconID")

            if resp.child_value("player/player_select_score/name") != self.NAME:
                raise Exception(
                    f'Invalid name {resp.child_value("player/player_select_score/name")} returned on score read!'
                )
            if resp.child_value("player/player_select_score/user_id") != extid:
                raise Exception(
                    f'Invalid name {resp.child_value("player/player_select_score/user_id")} returned on score read!'
                )

    def verify_player_rb5_player_read_rival_ranking_data_5(self, extid: int) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_read_rival_ranking_data_5")
        player.add_child(Node.s32("uid", extid))
        player.add_child(Node.s8("mgid", -1))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/rival_data/rl/uid")
        self.assert_path(resp, "response/player/rival_data/rl/nm")
        self.assert_path(resp, "response/player/rival_data/rl/ic")
        self.assert_path(resp, "response/player/rival_data/rl/sl/mid")
        self.assert_path(resp, "response/player/rival_data/rl/sl/m")
        self.assert_path(resp, "response/player/rival_data/rl/sl/t")
        if resp.child_value("player/rival_data/rl/nm") != self.NAME:
            raise Exception(
                f'Invalid name {resp.child_value("player/rival_data/rl/nm")} returned on rival ranking read!'
            )

    def verify_player_rb5_player_succeed(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_succeed")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/name")
        self.assert_path(resp, "response/player/grd")
        self.assert_path(resp, "response/player/ap")
        self.assert_path(resp, "response/player/uattr")

    def verify_player_rb5_player_read(self, refid: str, cardid: str, location: str) -> Dict[str, Any]:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "rb5_player_read")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.string("lid", location))
        player.add_child(Node.s16("ver", 0))
        player.add_child(Node.string("card_id", cardid))
        player.add_child(Node.s16("card_type", 1))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/pdata/account/usrid")
        self.assert_path(resp, "response/player/pdata/account/tpc")
        self.assert_path(resp, "response/player/pdata/account/dpc")
        self.assert_path(resp, "response/player/pdata/account/crd")
        self.assert_path(resp, "response/player/pdata/account/brd")
        self.assert_path(resp, "response/player/pdata/account/tdc")
        self.assert_path(resp, "response/player/pdata/account/intrvld")
        self.assert_path(resp, "response/player/pdata/account/ver")
        self.assert_path(resp, "response/player/pdata/account/succeed")
        self.assert_path(resp, "response/player/pdata/account/pst")
        self.assert_path(resp, "response/player/pdata/account/st")
        self.assert_path(resp, "response/player/pdata/account/opc")
        self.assert_path(resp, "response/player/pdata/account/lpc")
        self.assert_path(resp, "response/player/pdata/account/cpc")
        self.assert_path(resp, "response/player/pdata/account/mpc")
        self.assert_path(resp, "response/player/pdata/base/name")
        self.assert_path(resp, "response/player/pdata/base/mg")
        self.assert_path(resp, "response/player/pdata/base/ap")
        self.assert_path(resp, "response/player/pdata/base/cmnt")
        self.assert_path(resp, "response/player/pdata/base/uattr")
        self.assert_path(resp, "response/player/pdata/base/money")
        self.assert_path(resp, "response/player/pdata/base/tbs_5")
        self.assert_path(resp, "response/player/pdata/base/tbgs_5")
        self.assert_path(resp, "response/player/pdata/base/mlog")
        self.assert_path(resp, "response/player/pdata/base/class")
        self.assert_path(resp, "response/player/pdata/base/class_ar")
        self.assert_path(resp, "response/player/pdata/base/skill_point")
        self.assert_path(resp, "response/player/pdata/base/meteor_flg")
        self.assert_path(resp, "response/player/pdata/rival")
        self.assert_path(resp, "response/player/pdata/config")
        self.assert_path(resp, "response/player/pdata/custom")
        self.assert_path(resp, "response/player/pdata/released")
        self.assert_path(resp, "response/player/pdata/announce")
        self.assert_path(resp, "response/player/pdata/dojo")
        self.assert_path(resp, "response/player/pdata/player_param")
        self.assert_path(resp, "response/player/pdata/shop_score")
        self.assert_path(resp, "response/player/pdata/minigame")
        self.assert_path(resp, "response/player/pdata/derby/is_open")
        self.assert_path(resp, "response/player/pdata/mylist/list/idx")
        self.assert_path(resp, "response/player/pdata/mylist/list/mlst")
        self.assert_path(resp, "response/player/pdata/mycourse/mycourse_id")
        self.assert_path(resp, "response/player/pdata/mycourse_f")

        if resp.child_value("player/pdata/base/name") != self.NAME:
            raise Exception(f'Invalid name {resp.child_value("player/pdata/base/name")} returned on profile read!')

        mycourse = [
            {
                "music_id": resp.child_value("player/pdata/mycourse/music_id_1"),
                "note_grade": resp.child_value("player/pdata/mycourse/note_grade_1"),
                "score": resp.child_value("player/pdata/mycourse/score_1"),
            },
            {
                "music_id": resp.child_value("player/pdata/mycourse/music_id_2"),
                "note_grade": resp.child_value("player/pdata/mycourse/note_grade_2"),
                "score": resp.child_value("player/pdata/mycourse/score_2"),
            },
            {
                "music_id": resp.child_value("player/pdata/mycourse/music_id_3"),
                "note_grade": resp.child_value("player/pdata/mycourse/note_grade_3"),
                "score": resp.child_value("player/pdata/mycourse/score_3"),
            },
            {
                "music_id": resp.child_value("player/pdata/mycourse/music_id_4"),
                "note_grade": resp.child_value("player/pdata/mycourse/note_grade_4"),
                "score": resp.child_value("player/pdata/mycourse/score_4"),
            },
        ]
        return {
            "mycourse": mycourse,
        }

    def verify_player_rb5_player_read_score_5(self, refid: str, location: str) -> List[Dict[str, int]]:
        call = self.call_node()

        player = Node.void("player")
        call.add_child(player)
        player.set_attribute("method", "rb5_player_read_score_5")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.s16("ver", 1))

        # Swap with server
        resp = self.exchange("", call)

        scores = []
        for child in resp.child("player/pdata/record").children:
            if child.name != "rec":
                continue

            self.assert_path(child, "rec/mid")
            self.assert_path(child, "rec/ntgrd")
            self.assert_path(child, "rec/pc")
            self.assert_path(child, "rec/ct")
            self.assert_path(child, "rec/ar")
            self.assert_path(child, "rec/scr")
            self.assert_path(child, "rec/ms")
            self.assert_path(child, "rec/param")
            self.assert_path(child, "rec/bscrt")
            self.assert_path(child, "rec/bart")
            self.assert_path(child, "rec/bctt")
            self.assert_path(child, "rec/bmst")
            self.assert_path(child, "rec/time")
            self.assert_path(child, "rec/k_flag")

            score = {
                "id": child.child_value("mid"),
                "chart": child.child_value("ntgrd"),
                "clear_type": child.child_value("ct"),
                "combo_type": child.child_value("param"),
                "achievement_rate": child.child_value("ar"),
                "score": child.child_value("scr"),
                "miss_count": child.child_value("ms"),
            }
            scores.append(score)
        return scores

    def verify_player_rb5_player_read_score_old_5(self, refid: str, location: str) -> List[Dict[str, int]]:
        call = self.call_node()

        player = Node.void("player")
        call.add_child(player)
        player.set_attribute("method", "rb5_player_read_score_old_5")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.s16("ver", 1))

        # Swap with server
        resp = self.exchange("", call)

        scores = []
        for child in resp.child("player/pdata/record_old").children:
            if child.name != "rec":
                continue

            self.assert_path(child, "rec/mid")
            self.assert_path(child, "rec/ntgrd")
            self.assert_path(child, "rec/pc")
            self.assert_path(child, "rec/ct")
            self.assert_path(child, "rec/ar")
            self.assert_path(child, "rec/scr")
            self.assert_path(child, "rec/ms")
            self.assert_path(child, "rec/param")
            self.assert_path(child, "rec/bscrt")
            self.assert_path(child, "rec/bart")
            self.assert_path(child, "rec/bctt")
            self.assert_path(child, "rec/bmst")
            self.assert_path(child, "rec/time")
            self.assert_path(child, "rec/k_flag")

            score = {
                "id": child.child_value("mid"),
                "chart": child.child_value("ntgrd"),
                "clear_type": child.child_value("ct"),
                "combo_type": child.child_value("param"),
                "achievement_rate": child.child_value("ar"),
                "score": child.child_value("scr"),
                "miss_count": child.child_value("ms"),
            }
            scores.append(score)
        return scores

    def verify_player_rb5_player_write_5(
        self,
        refid: str,
        loc: str,
        scores: List[Dict[str, int]] = [],
        rivals: List[int] = [],
        mycourse: Optional[List[Dict[str, int]]] = None,
    ) -> int:
        call = self.call_node()

        player = Node.void("player")
        call.add_child(player)
        player.set_attribute("method", "rb5_player_write_5")
        pdata = Node.void("pdata")
        player.add_child(pdata)
        account = Node.void("account")
        pdata.add_child(account)
        account.add_child(Node.s32("usrid", 0))
        account.add_child(Node.s32("plyid", 0))
        account.add_child(Node.s32("tpc", 1))
        account.add_child(Node.s32("dpc", 1))
        account.add_child(Node.s32("crd", 1))
        account.add_child(Node.s32("brd", 1))
        account.add_child(Node.s32("tdc", 1))
        account.add_child(Node.string("rid", refid))
        account.add_child(Node.string("lid", loc))
        account.add_child(Node.u8("wmode", 0))
        account.add_child(Node.u8("gmode", 0))
        account.add_child(Node.s16("ver", 0))
        account.add_child(Node.bool("pp", False))
        account.add_child(Node.bool("ps", False))
        account.add_child(Node.bool("continue", False))
        account.add_child(Node.bool("firstfree", False))
        account.add_child(Node.s16("pay", 0))
        account.add_child(Node.s16("pay_pc", 0))
        account.add_child(Node.u64("st", int(time.time() * 1000)))
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.string("name", self.NAME))
        base.add_child(Node.s32("mg", 0))
        base.add_child(Node.s32("ap", 0))
        base.add_child(Node.s32("uattr", 0))
        base.add_child(Node.s32("money", 0))
        base.add_child(Node.bool("is_tut", False))
        base.add_child(Node.s32("class", -1))
        base.add_child(Node.s32("class_ar", 0))
        base.add_child(Node.s32("skill_point", 0))
        stglog = Node.void("stglog")
        pdata.add_child(stglog)

        index = 0
        for score in scores:
            log = Node.void("log")
            stglog.add_child(log)
            log.add_child(Node.s8("stg", index))
            log.add_child(Node.s16("mid", score["id"]))
            log.add_child(Node.s8("ng", score["chart"]))
            log.add_child(Node.s8("col", 1))
            log.add_child(Node.s8("mt", 0))
            log.add_child(Node.s8("rt", 0))
            log.add_child(Node.s8("ct", score["clear_type"]))
            log.add_child(Node.s16("param", score["combo_type"]))
            log.add_child(Node.s16("grd", 0))
            log.add_child(Node.s16("ar", score["achievement_rate"]))
            log.add_child(Node.s16("sc", score["score"]))
            log.add_child(Node.s16("jt_jst", 0))
            log.add_child(Node.s16("jt_grt", 0))
            log.add_child(Node.s16("jt_gd", 0))
            log.add_child(Node.s16("jt_ms", score["miss_count"]))
            log.add_child(Node.s16("jt_jr", 0))
            log.add_child(Node.s32("r_uid", 0))
            log.add_child(Node.s32("r_plyid", 0))
            log.add_child(Node.s8("r_stg", 0))
            log.add_child(Node.s8("r_ct", -1))
            log.add_child(Node.s16("r_sc", 0))
            log.add_child(Node.s16("r_grd", 0))
            log.add_child(Node.s16("r_ar", 0))
            log.add_child(Node.s8("r_cpuid", -1))
            log.add_child(Node.s32("time", int(time.time())))
            log.add_child(Node.s8("decide", 0))
            log.add_child(Node.s16("g_gauge", 5000))
            log.add_child(Node.s32("k_flag", 0))
            index = index + 1

        rivalnode = Node.void("rival")
        pdata.add_child(rivalnode)
        for rival in rivals:
            r = Node.void("r")
            rivalnode.add_child(r)
            r.add_child(Node.s32("id", rival))
            r.add_child(Node.s8("regist_type", 3))

        if mycourse is not None:
            mycoursenode = Node.void("mycourse")
            pdata.add_child(mycoursenode)
            mycoursenode.add_child(Node.s16("mycourse_id", 1))
            mycoursenode.add_child(Node.s32("music_id_1", mycourse[0]["music_id"]))
            mycoursenode.add_child(Node.s16("note_grade_1", mycourse[0]["note_grade"]))
            mycoursenode.add_child(Node.s32("score_1", mycourse[0]["score"]))
            mycoursenode.add_child(Node.s32("music_id_2", mycourse[1]["music_id"]))
            mycoursenode.add_child(Node.s16("note_grade_2", mycourse[1]["note_grade"]))
            mycoursenode.add_child(Node.s32("score_2", mycourse[1]["score"]))
            mycoursenode.add_child(Node.s32("music_id_3", mycourse[2]["music_id"]))
            mycoursenode.add_child(Node.s16("note_grade_3", mycourse[2]["note_grade"]))
            mycoursenode.add_child(Node.s32("score_3", mycourse[2]["score"]))
            mycoursenode.add_child(Node.s32("music_id_4", mycourse[3]["music_id"]))
            mycoursenode.add_child(Node.s16("note_grade_4", mycourse[3]["note_grade"]))
            mycoursenode.add_child(Node.s32("score_4", mycourse[3]["score"]))
            mycoursenode.add_child(Node.s32("insert_time", -1))
            mycoursenode.add_child(Node.s32("def_music_id_1", -1))
            mycoursenode.add_child(Node.s16("def_note_grade_1", -1))
            mycoursenode.add_child(Node.s32("def_music_id_2", -1))
            mycoursenode.add_child(Node.s16("def_note_grade_2", -1))
            mycoursenode.add_child(Node.s32("def_music_id_3", -1))
            mycoursenode.add_child(Node.s16("def_note_grade_3", -1))
            mycoursenode.add_child(Node.s32("def_music_id_4", -1))
            mycoursenode.add_child(Node.s16("def_note_grade_4", -1))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/uid")
        return resp.child_value("player/uid")

    def verify_lobby_rb5_lobby_read(self, location: str, extid: int) -> None:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "rb5_lobby_read")
        lobby.add_child(Node.s32("uid", extid))
        lobby.add_child(Node.s32("plyid", 0))
        lobby.add_child(Node.u8("m_grade", 255))
        lobby.add_child(Node.string("lid", location))
        lobby.add_child(Node.s32("max", 128))
        lobby.add_child(Node.s32_array("friend", []))
        lobby.add_child(Node.u8("var", 4))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby/interval")
        self.assert_path(resp, "response/lobby/interval_p")

    def verify_lobby_rb5_lobby_entry(self, location: str, extid: int) -> int:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "rb5_lobby_entry")
        e = Node.void("e")
        lobby.add_child(e)
        e.add_child(Node.s32("eid", 0))
        e.add_child(Node.u16("mid", 79))
        e.add_child(Node.u8("ng", 0))
        e.add_child(Node.s32("uid", extid))
        e.add_child(Node.s32("uattr", 0))
        e.add_child(Node.string("pn", self.NAME))
        e.add_child(Node.s32("plyid", 0))
        e.add_child(Node.s16("mg", 255))
        e.add_child(Node.s32("mopt", 0))
        e.add_child(Node.string("lid", location))
        e.add_child(Node.string("sn", ""))
        e.add_child(Node.u8("pref", 51))
        e.add_child(Node.s8("stg", 4))
        e.add_child(Node.s8("pside", 0))
        e.add_child(Node.s16("eatime", 30))
        e.add_child(Node.u8_array("ga", [127, 0, 0, 1]))
        e.add_child(Node.u16("gp", 10007))
        e.add_child(Node.u8_array("la", [16, 0, 0, 0]))
        e.add_child(Node.u8("ver", 2))
        lobby.add_child(Node.s32_array("friend", []))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby/interval")
        self.assert_path(resp, "response/lobby/interval_p")
        self.assert_path(resp, "response/lobby/eid")
        self.assert_path(resp, "response/lobby/e/eid")
        self.assert_path(resp, "response/lobby/e/mid")
        self.assert_path(resp, "response/lobby/e/ng")
        self.assert_path(resp, "response/lobby/e/uid")
        self.assert_path(resp, "response/lobby/e/uattr")
        self.assert_path(resp, "response/lobby/e/pn")
        self.assert_path(resp, "response/lobby/e/plyid")
        self.assert_path(resp, "response/lobby/e/mg")
        self.assert_path(resp, "response/lobby/e/mopt")
        self.assert_path(resp, "response/lobby/e/lid")
        self.assert_path(resp, "response/lobby/e/sn")
        self.assert_path(resp, "response/lobby/e/pref")
        self.assert_path(resp, "response/lobby/e/stg")
        self.assert_path(resp, "response/lobby/e/pside")
        self.assert_path(resp, "response/lobby/e/eatime")
        self.assert_path(resp, "response/lobby/e/ga")
        self.assert_path(resp, "response/lobby/e/gp")
        self.assert_path(resp, "response/lobby/e/la")
        self.assert_path(resp, "response/lobby/e/ver")
        return resp.child_value("lobby/eid")

    def verify_lobby_rb5_lobby_delete_entry(self, eid: int) -> None:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "rb5_lobby_delete_entry")
        lobby.add_child(Node.s32("eid", eid))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby/@status")

    def verify(self, cardid: Optional[str]) -> None:
        # Verify boot sequence is okay
        self.verify_services_get(
            expected_services=[
                "pcbtracker",
                "pcbevent",
                "local",
                "message",
                "facility",
                "cardmng",
                "package",
                "posevent",
                "pkglist",
                "dlstatus",
                "eacoin",
                "lobby",
                "lobby2",
                "ntp",
                "keepalive",
            ]
        )
        paseli_enabled = self.verify_pcbtracker_alive()
        self.verify_message_get()
        self.verify_package_list()
        self.verify_dlstatus_progress()
        location = self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_info_rb5_info_read(location)
        self.verify_pcb_rb5_pcb_boot(location)
        self.verify_pcb_rb5_pcb_error(location)

        # Verify card registration and profile lookup
        if cardid is not None:
            card = cardid
        else:
            card = self.random_card()
            print(f"Generated random card ID {card} for use.")

        if cardid is None:
            self.verify_cardmng_inquire(card, msg_type="unregistered", paseli_enabled=paseli_enabled)
            ref_id = self.verify_cardmng_getrefid(card)
            if len(ref_id) != 16:
                raise Exception(f"Invalid refid '{ref_id}' returned when registering card")
            if ref_id != self.verify_cardmng_inquire(card, msg_type="new", paseli_enabled=paseli_enabled):
                raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

            # Always get a player start, regardless of new profile or not
            self.verify_player_rb5_player_start(ref_id)
            self.verify_player_rb5_player_succeed(ref_id)
            extid = self.verify_player_rb5_player_write_5(
                ref_id,
                location,
            )
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        # Verify lobby functionality
        self.verify_lobby_rb5_lobby_read(location, extid)
        eid = self.verify_lobby_rb5_lobby_entry(location, extid)
        self.verify_lobby_rb5_lobby_delete_entry(eid)

        # Verify we start with empty scores
        scores = self.verify_player_rb5_player_read_score_5(ref_id, location)
        oldscores = self.verify_player_rb5_player_read_score_old_5(ref_id, location)
        if len(scores) > 0 or len(oldscores) > 0:
            raise Exception("Existing scores returned on new card?")
        profile = self.verify_player_rb5_player_read(ref_id, card, location)
        for val in profile["mycourse"]:
            if val["score"] != -1:
                raise Exception("Existing score returned for new card on course?")
            if val["music_id"] != -1:
                raise Exception("Existing score returned for new card on course?")
            if val["note_grade"] != -1:
                raise Exception("Existing score returned for new card on course?")

        if cardid is None:
            # Verify score saving and updating
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 9,
                            "chart": 1,
                            "clear_type": 9,
                            "combo_type": 0,
                            "achievement_rate": 7543,
                            "score": 432,
                            "miss_count": 5,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 9,
                            "chart": 0,
                            "clear_type": 9,
                            "combo_type": 1,
                            "achievement_rate": 9876,
                            "score": 543,
                            "miss_count": 0,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 6,
                            "chart": 2,
                            "clear_type": 9,
                            "combo_type": 0,
                            "achievement_rate": 1234,
                            "score": 123,
                            "miss_count": 54,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 6,
                            "chart": 0,
                            "clear_type": 9,
                            "combo_type": 0,
                            "achievement_rate": 1024,
                            "score": 50,
                            "miss_count": 90,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 9,
                            "chart": 1,
                            "clear_type": 9,
                            "combo_type": 0,
                            "achievement_rate": 8765,
                            "score": 469,
                            "miss_count": 1,
                        },
                        # A worse score on another same chart
                        {
                            "id": 9,
                            "chart": 0,
                            "clear_type": 9,
                            "combo_type": 0,
                            "achievement_rate": 8765,
                            "score": 432,
                            "miss_count": 15,
                            "expected_score": 543,
                            "expected_clear_type": 9,
                            "expected_combo_type": 1,
                            "expected_achievement_rate": 9876,
                            "expected_miss_count": 0,
                        },
                    ]
                self.verify_player_rb5_player_write_5(ref_id, location, scores=dummyscores)

                self.verify_player_rb5_player_read(ref_id, card, location)
                scores = self.verify_player_rb5_player_read_score_5(ref_id, location)
                for expected in dummyscores:
                    actual = None
                    for received in scores:
                        if received["id"] == expected["id"] and received["chart"] == expected["chart"]:
                            actual = received
                            break

                    if actual is None:
                        raise Exception(f"Didn't find song {expected['id']} chart {expected['chart']} in response!")

                    if "expected_score" in expected:
                        expected_score = expected["expected_score"]
                    else:
                        expected_score = expected["score"]
                    if "expected_achievement_rate" in expected:
                        expected_achievement_rate = expected["expected_achievement_rate"]
                    else:
                        expected_achievement_rate = expected["achievement_rate"]
                    if "expected_clear_type" in expected:
                        expected_clear_type = expected["expected_clear_type"]
                    else:
                        expected_clear_type = expected["clear_type"]
                    if "expected_combo_type" in expected:
                        expected_combo_type = expected["expected_combo_type"]
                    else:
                        expected_combo_type = expected["combo_type"]
                    if "expected_miss_count" in expected:
                        expected_miss_count = expected["expected_miss_count"]
                    else:
                        expected_miss_count = expected["miss_count"]

                    if actual["score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got score \'{actual["score"]}\''
                        )
                    if actual["achievement_rate"] != expected_achievement_rate:
                        raise Exception(
                            f'Expected an achievement rate of \'{expected_achievement_rate}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got achievement rate \'{actual["achievement_rate"]}\''
                        )
                    if actual["clear_type"] != expected_clear_type:
                        raise Exception(
                            f'Expected a clear_type of \'{expected_clear_type}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got clear_type \'{actual["clear_type"]}\''
                        )
                    if actual["combo_type"] != expected_combo_type:
                        raise Exception(
                            f'Expected a combo_type of \'{expected_combo_type}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got combo_type \'{actual["combo_type"]}\''
                        )
                    if actual["miss_count"] != expected_miss_count:
                        raise Exception(
                            f'Expected a miss count of \'{expected_miss_count}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got miss count \'{actual["miss_count"]}\''
                        )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

        else:
            print("Skipping score checks for existing card")

        # Verify mycourse saving and updating
        firstcourse = [
            {
                "music_id": 51,
                "note_grade": 1,
                "score": 1086,
            },
            {
                "music_id": 37,
                "note_grade": 1,
                "score": 1041,
            },
            {
                "music_id": 102,
                "note_grade": 1,
                "score": 935,
            },
            {
                "music_id": 58,
                "note_grade": 1,
                "score": 973,
            },
        ]
        self.verify_player_rb5_player_write_5(ref_id, location, mycourse=firstcourse)
        profile = self.verify_player_rb5_player_read(ref_id, card, location)
        for i in range(len(profile["mycourse"])):
            if profile["mycourse"][i]["music_id"] != firstcourse[i]["music_id"]:
                raise Exception(f"invalid music ID for mycourse entry {i}!")
            if profile["mycourse"][i]["note_grade"] != firstcourse[i]["note_grade"]:
                raise Exception(f"invalid chart for mycourse entry {i}!")
            if profile["mycourse"][i]["score"] != firstcourse[i]["score"]:
                raise Exception(f"invalid score for mycourse entry {i}!")

        # Do a worse job on a different course
        secondcourse = [
            {
                "music_id": 2,
                "note_grade": 1,
                "score": 987,
            },
            {
                "music_id": 6,
                "note_grade": 1,
                "score": 234,
            },
            {
                "music_id": 102,
                "note_grade": 1,
                "score": 876,
            },
            {
                "music_id": 58,
                "note_grade": 1,
                "score": 573,
            },
        ]
        self.verify_player_rb5_player_write_5(ref_id, location, mycourse=secondcourse)
        profile = self.verify_player_rb5_player_read(ref_id, card, location)
        for i in range(len(profile["mycourse"])):
            if profile["mycourse"][i]["music_id"] != firstcourse[i]["music_id"]:
                raise Exception(f"invalid music ID for mycourse entry {i}!")
            if profile["mycourse"][i]["note_grade"] != firstcourse[i]["note_grade"]:
                raise Exception(f"invalid chart for mycourse entry {i}!")
            if profile["mycourse"][i]["score"] != firstcourse[i]["score"]:
                raise Exception(f"invalid score for mycourse entry {i}!")

        # Now, do better on our course, and verify it updates
        thirdcourse = [
            {
                "music_id": 51,
                "note_grade": 1,
                "score": 1186,
            },
            {
                "music_id": 37,
                "note_grade": 1,
                "score": 1141,
            },
            {
                "music_id": 102,
                "note_grade": 1,
                "score": 1035,
            },
            {
                "music_id": 58,
                "note_grade": 1,
                "score": 1073,
            },
        ]
        self.verify_player_rb5_player_write_5(ref_id, location, mycourse=thirdcourse)
        profile = self.verify_player_rb5_player_read(ref_id, card, location)
        for i in range(len(profile["mycourse"])):
            if profile["mycourse"][i]["music_id"] != thirdcourse[i]["music_id"]:
                raise Exception(f"invalid music ID for mycourse entry {i}!")
            if profile["mycourse"][i]["note_grade"] != thirdcourse[i]["note_grade"]:
                raise Exception(f"invalid chart for mycourse entry {i}!")
            if profile["mycourse"][i]["score"] != thirdcourse[i]["score"]:
                raise Exception(f"invalid score for mycourse entry {i}!")

        # Verify ending game
        self.verify_player_rb5_player_end(ref_id)

        # Verify empty and non-empty select score
        self.verify_player_rb5_player_read_rival_score_5(0)
        self.verify_player_rb5_player_read_rival_score_5(extid)

        # Verify rival score loading after rivaling ourselves
        self.verify_player_rb5_player_write_5(ref_id, location, rivals=[extid])
        self.verify_player_rb5_player_read_rival_ranking_data_5(extid)

        # Verify high score tables and shop rank
        self.verify_info_rb5_info_read_hit_chart()
        self.verify_info_rb5_info_read_shop_ranking(location)
        self.verify_player_rb5_player_read_rank_5()

        # Verify paseli handling
        if paseli_enabled:
            print("PASELI enabled for this PCBID, executing PASELI checks")
        else:
            print("PASELI disabled for this PCBID, skipping PASELI checks")
            return

        sessid, balance = self.verify_eacoin_checkin(card)
        if balance == 0:
            print("Skipping PASELI consume check because card has 0 balance")
        else:
            self.verify_eacoin_consume(sessid, balance, random.randint(0, balance))
        self.verify_eacoin_checkout(sessid)
