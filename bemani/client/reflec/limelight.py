import random
import time
from typing import Dict, List, Optional

from bemani.common import Time
from bemani.client.base import BaseClient
from bemani.protocol import Node


class ReflecBeatLimelight(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_log_pcb_status(self, loc: str) -> None:
        call = self.call_node()

        pcb = Node.void("log")
        pcb.set_attribute("method", "pcb_status")
        pcb.add_child(Node.string("lid", loc))
        pcb.add_child(Node.s32("cnt", 0))
        call.add_child(pcb)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/log/@status")

    def verify_pcbinfo_get(self, loc: str) -> None:
        call = self.call_node()

        pcb = Node.void("pcbinfo")
        pcb.set_attribute("method", "get")
        pcb.add_child(Node.string("lid", loc))
        call.add_child(pcb)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcbinfo/info/name")
        self.assert_path(resp, "response/pcbinfo/info/pref")
        self.assert_path(resp, "response/pcbinfo/info/close")
        self.assert_path(resp, "response/pcbinfo/info/hour")
        self.assert_path(resp, "response/pcbinfo/info/min")

    def verify_sysinfo_get(self) -> None:
        call = self.call_node()

        info = Node.void("sysinfo")
        info.set_attribute("method", "get")
        call.add_child(info)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/sysinfo/trd")

    def verify_ranking_read(self) -> None:
        call = self.call_node()

        ranking = Node.void("ranking")
        ranking.set_attribute("method", "read")
        call.add_child(ranking)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/ranking/lic_10/time")
        self.assert_path(resp, "response/ranking/org_10/time")

    def verify_player_start(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "start")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.s32("ver", 0))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/is_suc")
        self.assert_path(resp, "response/player/unlock_music")
        self.assert_path(resp, "response/player/unlock_item")
        self.assert_path(resp, "response/player/item_lock_ctrl")
        self.assert_path(resp, "response/player/lincle_link_4/qpro")
        self.assert_path(resp, "response/player/lincle_link_4/glass")
        self.assert_path(resp, "response/player/lincle_link_4/treasure")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_0")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_1")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_2")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_3")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_4")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_5")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0_6")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_0")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_1")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_2")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_3")
        self.assert_path(resp, "response/player/lincle_link_4/for_iidx_4")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_0")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_1")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_2")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_3")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_4")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_5")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0_6")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_0")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_1")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_2")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_3")
        self.assert_path(resp, "response/player/lincle_link_4/for_rb_4")
        self.assert_path(resp, "response/player/lincle_link_4/qproflg")
        self.assert_path(resp, "response/player/lincle_link_4/glassflg")
        self.assert_path(resp, "response/player/lincle_link_4/complete")

    def verify_player_delete(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "delete")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/@status")

    def verify_player_end(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "end")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.s32("status", 4))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player")

    def verify_player_read(self, refid: str, location: str) -> List[Dict[str, int]]:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "read")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.string("lid", location))
        player.add_child(Node.s32("ver", 2))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/pdata/base/uid")
        self.assert_path(resp, "response/player/pdata/base/name")
        self.assert_path(resp, "response/player/pdata/base/icon_id")
        self.assert_path(resp, "response/player/pdata/base/lv")
        self.assert_path(resp, "response/player/pdata/base/exp")
        self.assert_path(resp, "response/player/pdata/base/mg")
        self.assert_path(resp, "response/player/pdata/base/ap")
        self.assert_path(resp, "response/player/pdata/base/pc")
        self.assert_path(resp, "response/player/pdata/base/uattr")
        self.assert_path(resp, "response/player/pdata/con/day")
        self.assert_path(resp, "response/player/pdata/con/cnt")
        self.assert_path(resp, "response/player/pdata/con/total_cnt")
        self.assert_path(resp, "response/player/pdata/con/last")
        self.assert_path(resp, "response/player/pdata/con/now")
        self.assert_path(resp, "response/player/pdata/team/id")
        self.assert_path(resp, "response/player/pdata/team/name")
        self.assert_path(resp, "response/player/pdata/custom/s_gls")
        self.assert_path(resp, "response/player/pdata/custom/bgm_m")
        self.assert_path(resp, "response/player/pdata/custom/st_f")
        self.assert_path(resp, "response/player/pdata/custom/st_bg")
        self.assert_path(resp, "response/player/pdata/custom/st_bg_b")
        self.assert_path(resp, "response/player/pdata/custom/eff_e")
        self.assert_path(resp, "response/player/pdata/custom/se_s")
        self.assert_path(resp, "response/player/pdata/custom/se_s_v")
        self.assert_path(resp, "response/player/pdata/custom/last_music_id")
        self.assert_path(resp, "response/player/pdata/custom/last_note_grade")
        self.assert_path(resp, "response/player/pdata/custom/sort_type")
        self.assert_path(resp, "response/player/pdata/custom/narrowdown_type")
        self.assert_path(resp, "response/player/pdata/custom/is_begginer")
        self.assert_path(resp, "response/player/pdata/custom/is_tut")
        self.assert_path(resp, "response/player/pdata/custom/symbol_chat_0")
        self.assert_path(resp, "response/player/pdata/custom/symbol_chat_1")
        self.assert_path(resp, "response/player/pdata/custom/gauge_style")
        self.assert_path(resp, "response/player/pdata/custom/obj_shade")
        self.assert_path(resp, "response/player/pdata/custom/obj_size")
        self.assert_path(resp, "response/player/pdata/custom/byword")
        self.assert_path(resp, "response/player/pdata/custom/is_auto_byword")
        self.assert_path(resp, "response/player/pdata/custom/is_tweet")
        self.assert_path(resp, "response/player/pdata/custom/is_link_twitter")
        self.assert_path(resp, "response/player/pdata/custom/mrec_type")
        self.assert_path(resp, "response/player/pdata/custom/card_disp_type")
        self.assert_path(resp, "response/player/pdata/custom/tab_sel")
        self.assert_path(resp, "response/player/pdata/custom/hidden_param")
        self.assert_path(resp, "response/player/pdata/released")
        self.assert_path(resp, "response/player/pdata/record")
        self.assert_path(resp, "response/player/pdata/cmnt")
        self.assert_path(resp, "response/player/pdata/rival")
        self.assert_path(resp, "response/player/pdata/glass")
        self.assert_path(resp, "response/player/pdata/fav_music_slot")
        self.assert_path(resp, "response/player/pdata/narrow_down/adv_param")

        if resp.child_value("player/pdata/base/name") != self.NAME:
            raise Exception(f'Invalid name {resp.child_value("player/pdata/base/name")} returned on profile read!')

        scores = []
        for child in resp.child("player/pdata/record").children:
            if child.name != "rec":
                continue

            score = {
                "id": child.child_value("mid"),
                "chart": child.child_value("ng"),
                "clear_type": child.child_value("mrec_0/ct"),
                "achievement_rate": child.child_value("mrec_0/ar"),
                "score": child.child_value("mrec_0/bs"),
                "combo": child.child_value("mrec_0/mc"),
                "miss_count": child.child_value("mrec_0/bmc"),
            }
            scores.append(score)
        return scores

    def verify_player_write(
        self,
        refid: str,
        extid: int,
        loc: str,
        records: List[Dict[str, int]],
        scores: List[Dict[str, int]],
    ) -> int:
        call = self.call_node()

        player = Node.void("player")
        call.add_child(player)
        player.set_attribute("method", "write")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.string("lid", loc))
        player.add_child(Node.u64("begin_time", Time.now() * 1000))
        player.add_child(Node.u64("end_time", Time.now() * 1000))
        pdata = Node.void("pdata")
        player.add_child(pdata)
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.s32("uid", extid))
        base.add_child(Node.string("name", self.NAME))
        base.add_child(Node.s16("icon_id", 0))
        base.add_child(Node.s16("lv", 1))
        base.add_child(Node.s32("exp", 0))
        base.add_child(Node.s16("mg", 0))
        base.add_child(Node.s16("ap", 0))
        base.add_child(Node.s32("pc", 0))
        base.add_child(Node.s32("uattr", 0))
        con = Node.void("con")
        pdata.add_child(con)
        con.add_child(Node.s32("day", 0))
        con.add_child(Node.s32("cnt", 0))
        con.add_child(Node.s32("total_cnt", 0))
        con.add_child(Node.s32("last", 0))
        con.add_child(Node.s32("now", 0))
        custom = Node.void("custom")
        pdata.add_child(custom)
        custom.add_child(Node.u8("s_gls", 0))
        custom.add_child(Node.u8("bgm_m", 0))
        custom.add_child(Node.u8("st_f", 0))
        custom.add_child(Node.u8("st_bg", 0))
        custom.add_child(Node.u8("st_bg_b", 100))
        custom.add_child(Node.u8("eff_e", 0))
        custom.add_child(Node.u8("se_s", 0))
        custom.add_child(Node.u8("se_s_v", 100))
        custom.add_child(Node.s16("last_music_id", 85))
        custom.add_child(Node.u8("last_note_grade", 0))
        custom.add_child(Node.u8("sort_type", 0))
        custom.add_child(Node.u8("narrowdown_type", 0))
        custom.add_child(Node.bool("is_begginer", False))
        custom.add_child(Node.bool("is_tut", False))
        custom.add_child(Node.s16_array("symbol_chat_0", [0, 1, 2, 3, 4, 5]))
        custom.add_child(Node.s16_array("symbol_chat_1", [0, 1, 2, 3, 4, 5]))
        custom.add_child(Node.u8("gauge_style", 0))
        custom.add_child(Node.u8("obj_shade", 0))
        custom.add_child(Node.u8("obj_size", 0))
        custom.add_child(Node.s16_array("byword", [0, 0]))
        custom.add_child(Node.bool_array("is_auto_byword", [True, True]))
        custom.add_child(Node.bool("is_tweet", False))
        custom.add_child(Node.bool("is_link_twitter", False))
        custom.add_child(Node.s16("mrec_type", 0))
        custom.add_child(Node.s16("card_disp_type", 0))
        custom.add_child(Node.s16("tab_sel", 0))
        custom.add_child(
            Node.s32_array(
                "hidden_param",
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0],
            )
        )
        pdata.add_child(Node.void("released"))
        pdata.add_child(Node.void("rival"))
        pdata.add_child(Node.void("glass"))
        pdata.add_child(Node.void("fav_music_slot"))
        lincle_link_4 = Node.void("lincle_link_4")
        pdata.add_child(lincle_link_4)
        lincle_link_4.add_child(Node.u32("qpro_add", 0))
        lincle_link_4.add_child(Node.u32("glass_add", 0))
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

        # First, filter down to only records that are also in the battle log
        def key(thing: Dict[str, int]) -> str:
            return f'{thing["id"]}-{thing["chart"]}'

        updates = [key(score) for score in scores]
        sortedrecords = {key(record): record for record in records if key(record) in updates}

        # Now, see what records need updating and update them
        for score in scores:
            if key(score) in sortedrecords:
                # Had a record, need to merge
                record = sortedrecords[key(score)]
            else:
                # First time playing
                record = {
                    "clear_type": 0,
                    "achievement_rate": 0,
                    "score": 0,
                    "combo": 0,
                    "miss_count": 999999999,
                }

            sortedrecords[key(score)] = {
                "id": score["id"],
                "chart": score["chart"],
                "clear_type": max(record["clear_type"], score["clear_type"]),
                "achievement_rate": max(record["achievement_rate"], score["achievement_rate"]),
                "score": max(record["score"], score["score"]),
                "combo": max(record["combo"], score["combo"]),
                "miss_count": min(record["miss_count"], score["miss_count"]),
            }

        # Finally, send the records and battle logs
        recordnode = Node.void("record")
        pdata.add_child(recordnode)
        blog = Node.void("blog")
        pdata.add_child(blog)

        for _, record in sortedrecords.items():
            rec = Node.void("rec")
            recordnode.add_child(rec)
            rec.add_child(Node.u16("mid", record["id"]))
            rec.add_child(Node.u8("ng", record["chart"]))
            rec.add_child(Node.s32("point", 2))
            rec.add_child(Node.s32("played_time", Time.now()))
            mrec_0 = Node.void("mrec_0")
            rec.add_child(mrec_0)
            mrec_0.add_child(Node.s32("win", 1))
            mrec_0.add_child(Node.s32("lose", 0))
            mrec_0.add_child(Node.s32("draw", 0))
            mrec_0.add_child(Node.u8("ct", record["clear_type"]))
            mrec_0.add_child(Node.s16("ar", record["achievement_rate"]))
            mrec_0.add_child(Node.s32("bs", record["score"]))
            mrec_0.add_child(Node.s16("mc", record["combo"]))
            mrec_0.add_child(Node.s16("bmc", record["miss_count"]))
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

        scoreid = 0
        for score in scores:
            log = Node.void("log")
            blog.add_child(log)
            log.add_child(Node.u8("id", scoreid))
            log.add_child(Node.u16("mid", score["id"]))
            log.add_child(Node.u8("ng", score["chart"]))
            log.add_child(Node.u8("mt", 0))
            log.add_child(Node.u8("rt", 0))
            log.add_child(Node.s32("ruid", 0))
            myself = Node.void("myself")
            log.add_child(myself)
            myself.add_child(Node.s16("mg", 0))
            myself.add_child(Node.s16("ap", 0))
            myself.add_child(Node.u8("ct", score["clear_type"]))
            myself.add_child(Node.s32("s", score["score"]))
            myself.add_child(Node.s16("ar", score["achievement_rate"]))
            rival = Node.void("rival")
            log.add_child(rival)
            rival.add_child(Node.s16("mg", 0))
            rival.add_child(Node.s16("ap", 0))
            rival.add_child(Node.u8("ct", 2))
            rival.add_child(Node.s32("s", 177))
            rival.add_child(Node.s16("ar", 500))
            log.add_child(Node.s32("time", Time.now()))
            scoreid = scoreid + 1

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/uid")
        self.assert_path(resp, "response/player/time")
        return resp.child_value("player/uid")

    def verify_log_play(self, extid: int, loc: str, scores: List[Dict[str, int]]) -> None:
        call = self.call_node()

        log = Node.void("log")
        call.add_child(log)
        log.set_attribute("method", "play")
        log.add_child(Node.s32("uid", extid))
        log.add_child(Node.string("lid", loc))
        play = Node.void("play")
        log.add_child(play)
        play.add_child(Node.s16("stage", len(scores)))
        play.add_child(Node.s32("sec", 700))

        scoreid = 0
        for score in scores:
            rec = Node.void("rec")
            log.add_child(rec)
            rec.add_child(Node.s16("idx", scoreid))
            rec.add_child(Node.s16("mid", score["id"]))
            rec.add_child(Node.s16("grade", score["chart"]))
            rec.add_child(Node.s16("color", 0))
            rec.add_child(Node.s16("match", 0))
            rec.add_child(Node.s16("res", 0))
            rec.add_child(Node.s32("score", score["score"]))
            rec.add_child(Node.s16("mc", score["combo"]))
            rec.add_child(Node.s16("jt_jr", 0))
            rec.add_child(Node.s16("jt_ju", 0))
            rec.add_child(Node.s16("jt_gr", 0))
            rec.add_child(Node.s16("jt_gd", 0))
            rec.add_child(Node.s16("jt_ms", score["miss_count"]))
            rec.add_child(Node.s32("sec", 200))
            scoreid = scoreid + 1

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/log/@status")

    def verify_lobby_read(self, location: str, extid: int) -> None:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "read")
        lobby.add_child(Node.s32("uid", extid))
        lobby.add_child(Node.u8("m_grade", 255))
        lobby.add_child(Node.string("lid", location))
        lobby.add_child(Node.s32("max", 128))
        lobby.add_child(Node.s32_array("friend", []))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby/interval")
        self.assert_path(resp, "response/lobby/interval_p")

    def verify_lobby_entry(self, location: str, extid: int) -> int:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "entry")
        e = Node.void("e")
        lobby.add_child(e)
        e.add_child(Node.s32("eid", 0))
        e.add_child(Node.u16("mid", 79))
        e.add_child(Node.u8("ng", 0))
        e.add_child(Node.s32("uid", extid))
        e.add_child(Node.s32("uattr", 0))
        e.add_child(Node.string("pn", self.NAME))
        e.add_child(Node.s16("mg", 0))
        e.add_child(Node.s32("mopt", 0))
        e.add_child(Node.s32("tid", 0))
        e.add_child(Node.string("tn", ""))
        e.add_child(Node.s32("topt", 0))
        e.add_child(Node.string("lid", location))
        e.add_child(Node.string("sn", ""))
        e.add_child(Node.u8("pref", 51))
        e.add_child(Node.s8("stg", 0))
        e.add_child(Node.s8("pside", 0))
        e.add_child(Node.s16("eatime", 30))
        e.add_child(Node.u8_array("ga", [127, 0, 0, 1]))
        e.add_child(Node.u16("gp", 10007))
        e.add_child(Node.u8_array("la", [16, 0, 0, 0]))
        lobby.add_child(Node.s32_array("friend", []))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby/eid")
        self.assert_path(resp, "response/lobby/interval")
        self.assert_path(resp, "response/lobby/interval_p")
        self.assert_path(resp, "response/lobby/e/eid")
        self.assert_path(resp, "response/lobby/e/mid")
        self.assert_path(resp, "response/lobby/e/ng")
        self.assert_path(resp, "response/lobby/e/uid")
        self.assert_path(resp, "response/lobby/e/pn")
        self.assert_path(resp, "response/lobby/e/uattr")
        self.assert_path(resp, "response/lobby/e/mopt")
        self.assert_path(resp, "response/lobby/e/mg")
        self.assert_path(resp, "response/lobby/e/tid")
        self.assert_path(resp, "response/lobby/e/tn")
        self.assert_path(resp, "response/lobby/e/topt")
        self.assert_path(resp, "response/lobby/e/lid")
        self.assert_path(resp, "response/lobby/e/sn")
        self.assert_path(resp, "response/lobby/e/pref")
        self.assert_path(resp, "response/lobby/e/stg")
        self.assert_path(resp, "response/lobby/e/pside")
        self.assert_path(resp, "response/lobby/e/eatime")
        self.assert_path(resp, "response/lobby/e/ga")
        self.assert_path(resp, "response/lobby/e/gp")
        self.assert_path(resp, "response/lobby/e/la")
        return resp.child_value("lobby/eid")

    def verify_lobby_delete(self, eid: int) -> None:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "delete")
        lobby.add_child(Node.s32("eid", eid))
        call.add_child(lobby)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby")

    def verify_event_w_update_status(self, loc: str, extid: int) -> None:
        call = self.call_node()

        event_w = Node.void("event_w")
        call.add_child(event_w)
        event_w.set_attribute("method", "update_status")
        event_w.add_child(Node.s32("uid", extid))
        event_w.add_child(Node.string("p_name", self.NAME))
        event_w.add_child(Node.s32("exp", 0))
        event_w.add_child(Node.s32("customize", 0))
        event_w.add_child(Node.s32("tid", 0))
        event_w.add_child(Node.string("t_name", ""))
        event_w.add_child(Node.string("lid", loc))
        event_w.add_child(Node.string("s_name", ""))
        event_w.add_child(Node.s8("pref", 51))
        event_w.add_child(Node.s32("time", Time.now()))
        event_w.add_child(Node.s8("status", 1))
        event_w.add_child(Node.s8("stage", 0))
        event_w.add_child(Node.s32("mid", -1))
        event_w.add_child(Node.s8("ng", -1))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/event_w/@status")

    def verify_event_w_add_comment(self, loc: str, extid: int) -> None:
        call = self.call_node()

        event_w = Node.void("event_w")
        call.add_child(event_w)
        event_w.set_attribute("method", "add_comment")
        event_w.add_child(Node.s32("uid", extid))
        event_w.add_child(Node.string("p_name", self.NAME))
        event_w.add_child(Node.s32("exp", 0))
        event_w.add_child(Node.s32("customize", 0))
        event_w.add_child(Node.s32("tid", 0))
        event_w.add_child(Node.string("t_name", ""))
        event_w.add_child(Node.string("lid", loc))
        event_w.add_child(Node.string("s_name", ""))
        event_w.add_child(Node.s8("pref", 51))
        event_w.add_child(Node.s32("time", Time.now()))
        event_w.add_child(Node.string("comment", "アメ〜〜！"))
        event_w.add_child(Node.bool("is_tweet", False))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/event_w/@status")

    def verify_event_r_get_all(self, extid: int) -> None:
        call = self.call_node()

        event_r = Node.void("event_r")
        call.add_child(event_r)
        event_r.set_attribute("method", "get_all")
        event_r.add_child(Node.s32("uid", extid))
        event_r.add_child(Node.s32("time", 0))
        event_r.add_child(Node.s32("limit", 30))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct. We should have at least one
        # comment (the one we just wrote) and one status (because we just
        # called update_status).
        self.assert_path(resp, "response/event_r/time")
        self.assert_path(resp, "response/event_r/status/s/uid")
        self.assert_path(resp, "response/event_r/status/s/p_name")
        self.assert_path(resp, "response/event_r/status/s/exp")
        self.assert_path(resp, "response/event_r/status/s/customize")
        self.assert_path(resp, "response/event_r/status/s/tid")
        self.assert_path(resp, "response/event_r/status/s/t_name")
        self.assert_path(resp, "response/event_r/status/s/lid")
        self.assert_path(resp, "response/event_r/status/s/s_name")
        self.assert_path(resp, "response/event_r/status/s/pref")
        self.assert_path(resp, "response/event_r/status/s/time")
        self.assert_path(resp, "response/event_r/status/s/status")
        self.assert_path(resp, "response/event_r/status/s/stage")
        self.assert_path(resp, "response/event_r/status/s/mid")
        self.assert_path(resp, "response/event_r/status/s/ng")
        self.assert_path(resp, "response/event_r/comment/c/uid")
        self.assert_path(resp, "response/event_r/comment/c/p_name")
        self.assert_path(resp, "response/event_r/comment/c/exp")
        self.assert_path(resp, "response/event_r/comment/c/customize")
        self.assert_path(resp, "response/event_r/comment/c/tid")
        self.assert_path(resp, "response/event_r/comment/c/t_name")
        self.assert_path(resp, "response/event_r/comment/c/lid")
        self.assert_path(resp, "response/event_r/comment/c/s_name")
        self.assert_path(resp, "response/event_r/comment/c/pref")
        self.assert_path(resp, "response/event_r/comment/c/time")
        self.assert_path(resp, "response/event_r/comment/c/comment")
        self.assert_path(resp, "response/event_r/comment/c/is_tweet")

        # Verify we posted our comment earlier
        found = False
        for child in resp.child("event_r/comment").children:
            if child.name != "c":
                continue
            if child.child_value("uid") == extid:
                name = child.child_value("p_name")
                comment = child.child_value("comment")
                if name != self.NAME:
                    raise Exception(f"Invalid name '{name}' returned for comment!")
                if comment != "アメ〜〜！":
                    raise Exception(f"Invalid comment '{comment}' returned for comment!")
                found = True

        if not found:
            raise Exception("Comment we posted was not found!")

        # Verify our status came through
        found = False
        for child in resp.child("event_r/status").children:
            if child.name != "s":
                continue
            if child.child_value("uid") == extid:
                name = child.child_value("p_name")
                if name != self.NAME:
                    raise Exception(f"Invalid name '{name}' returned for status!")
                found = True

        if not found:
            raise Exception("Status was not found!")

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
                "ntp",
                "keepalive",
            ]
        )
        paseli_enabled = self.verify_pcbtracker_alive()
        self.verify_message_get()
        self.verify_package_list()
        location = self.verify_facility_get()
        self.verify_pcbevent_put()

        self.verify_log_pcb_status(location)
        self.verify_pcbinfo_get(location)

        self.verify_sysinfo_get()
        self.verify_ranking_read()

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
            self.verify_player_start(ref_id)
            self.verify_player_delete(ref_id)
            extid = self.verify_player_write(
                ref_id,
                0,
                location,
                [],
                [],
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
        self.verify_lobby_read(location, extid)
        eid = self.verify_lobby_entry(location, extid)
        self.verify_lobby_delete(eid)

        # Verify status updates and puzzle comments
        self.verify_event_w_update_status(location, extid)
        self.verify_event_w_add_comment(location, extid)
        self.verify_event_r_get_all(extid)

        # Limelight is weird and sends only the top record for each song you played,
        # and then a separate battle log. So, emulating that is kinda hard.
        scores: List[Dict[str, int]] = []
        if cardid is None:
            # Verify score saving and updating
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 1,
                            "chart": 1,
                            "clear_type": 2,
                            "achievement_rate": 7543,
                            "score": 432,
                            "combo": 123,
                            "miss_count": 5,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 1,
                            "chart": 0,
                            "clear_type": 3,
                            "achievement_rate": 9876,
                            "score": 543,
                            "combo": 543,
                            "miss_count": 0,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 3,
                            "chart": 2,
                            "clear_type": 2,
                            "achievement_rate": 1234,
                            "score": 123,
                            "combo": 42,
                            "miss_count": 54,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 3,
                            "chart": 0,
                            "clear_type": 2,
                            "achievement_rate": 1024,
                            "score": 50,
                            "combo": 12,
                            "miss_count": 90,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 1,
                            "chart": 1,
                            "clear_type": 3,
                            "achievement_rate": 8765,
                            "score": 469,
                            "combo": 468,
                            "miss_count": 1,
                        },
                        # A worse score on another same chart
                        {
                            "id": 1,
                            "chart": 0,
                            "clear_type": 2,
                            "achievement_rate": 8765,
                            "score": 432,
                            "combo": 321,
                            "miss_count": 15,
                            "expected_score": 543,
                            "expected_clear_type": 3,
                            "expected_achievement_rate": 9876,
                            "expected_combo": 543,
                            "expected_miss_count": 0,
                        },
                    ]
                self.verify_player_write(ref_id, extid, location, scores, dummyscores)
                self.verify_log_play(extid, location, dummyscores)

                scores = self.verify_player_read(ref_id, location)
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
                    if "expected_combo" in expected:
                        expected_combo = expected["expected_combo"]
                    else:
                        expected_combo = expected["combo"]
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
                    if actual["combo"] != expected_combo:
                        raise Exception(
                            f'Expected a combo of \'{expected_combo}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got combo \'{actual["combo"]}\''
                        )
                    if actual["miss_count"] != expected_miss_count:
                        raise Exception(
                            f'Expected a miss count of \'{expected_miss_count}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got miss count \'{actual["miss_count"]}\''
                        )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

        else:
            print("Skipping score checks for existing card")

        # Verify ending game
        self.verify_player_end(ref_id)

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
