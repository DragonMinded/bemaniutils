import random
import time
from typing import Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class ReflecBeatColette(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_pcb_boot(self, loc: str) -> None:
        call = self.call_node()

        pcb = Node.void("pcb")
        pcb.set_attribute("method", "boot")
        pcb.add_child(Node.string("lid", loc))
        call.add_child(pcb)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcb/sinfo/nm")
        self.assert_path(resp, "response/pcb/sinfo/cl_enbl")
        self.assert_path(resp, "response/pcb/sinfo/cl_h")
        self.assert_path(resp, "response/pcb/sinfo/cl_m")

    def verify_info_common(self) -> None:
        call = self.call_node()

        info = Node.void("info")
        info.set_attribute("method", "common")
        call.add_child(info)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info/event_ctrl")
        self.assert_path(resp, "response/info/item_lock_ctrl")

    def verify_info_ranking(self) -> None:
        call = self.call_node()

        info = Node.void("info")
        info.set_attribute("method", "ranking")
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

    def verify_player_start(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "start")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.u8_array("ga", [127, 0, 0, 1]))
        player.add_child(Node.u16("gp", 10573))
        player.add_child(Node.u8_array("la", [16, 0, 0, 0]))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/plyid")
        self.assert_path(resp, "response/player/start_time")
        self.assert_path(resp, "response/player/event_ctrl")
        self.assert_path(resp, "response/player/item_lock_ctrl")
        self.assert_path(resp, "response/player/lincle_link_4")
        self.assert_path(resp, "response/player/jbrbcollabo")
        self.assert_path(resp, "response/player/tricolettepark")

    def verify_player_delete(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "delete")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player")

    def verify_player_end(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "end")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player")

    def verify_player_succeed(self, refid: str) -> None:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "succeed")
        player.add_child(Node.string("rid", refid))
        call.add_child(player)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/name")
        self.assert_path(resp, "response/player/lv")
        self.assert_path(resp, "response/player/exp")
        self.assert_path(resp, "response/player/grd")
        self.assert_path(resp, "response/player/ap")
        self.assert_path(resp, "response/player/released")
        self.assert_path(resp, "response/player/mrecord")

    def verify_player_read(self, refid: str, location: str) -> List[Dict[str, int]]:
        call = self.call_node()

        player = Node.void("player")
        player.set_attribute("method", "read")
        player.add_child(Node.string("rid", refid))
        player.add_child(Node.string("lid", location))
        player.add_child(Node.s16("ver", 5))
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
        self.assert_path(resp, "response/player/pdata/account/pst")
        self.assert_path(resp, "response/player/pdata/account/st")
        self.assert_path(resp, "response/player/pdata/base/name")
        self.assert_path(resp, "response/player/pdata/base/exp")
        self.assert_path(resp, "response/player/pdata/base/lv")
        self.assert_path(resp, "response/player/pdata/base/mg")
        self.assert_path(resp, "response/player/pdata/base/ap")
        self.assert_path(resp, "response/player/pdata/base/tid")
        self.assert_path(resp, "response/player/pdata/base/tname")
        self.assert_path(resp, "response/player/pdata/base/cmnt")
        self.assert_path(resp, "response/player/pdata/base/uattr")
        self.assert_path(resp, "response/player/pdata/base/hidden_param")
        self.assert_path(resp, "response/player/pdata/base/tbs")
        self.assert_path(resp, "response/player/pdata/base/tbs_r")
        self.assert_path(resp, "response/player/pdata/rival")
        self.assert_path(resp, "response/player/pdata/fav_music_slot")
        self.assert_path(resp, "response/player/pdata/custom")
        self.assert_path(resp, "response/player/pdata/config")
        self.assert_path(resp, "response/player/pdata/stamp")
        self.assert_path(resp, "response/player/pdata/released")
        self.assert_path(resp, "response/player/pdata/record")

        if resp.child_value("player/pdata/base/name") != self.NAME:
            raise Exception(
                f'Invalid name {resp.child_value("player/pdata/base/name")} returned on profile read!'
            )

        scores = []
        for child in resp.child("player/pdata/record").children:
            if child.name != "rec":
                continue

            score = {
                "id": child.child_value("mid"),
                "chart": child.child_value("ntgrd"),
                "clear_type": child.child_value("ct"),
                "achievement_rate": child.child_value("ar"),
                "score": child.child_value("scr"),
                "combo": child.child_value("cmb"),
                "miss_count": child.child_value("ms"),
            }
            scores.append(score)
        return scores

    def verify_player_write(
        self, refid: str, loc: str, scores: List[Dict[str, int]]
    ) -> int:
        call = self.call_node()

        player = Node.void("player")
        call.add_child(player)
        player.set_attribute("method", "write")
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
        account.add_child(Node.u8("mode", 0))
        account.add_child(Node.s16("ver", 5))
        account.add_child(Node.bool("pp", True))
        account.add_child(Node.bool("ps", True))
        account.add_child(Node.s16("pay", 0))
        account.add_child(Node.s16("pay_pc", 0))
        account.add_child(Node.u64("st", int(time.time() * 1000)))
        base = Node.void("base")
        pdata.add_child(base)
        base.add_child(Node.string("name", self.NAME))
        base.add_child(Node.s32("exp", 0))
        base.add_child(Node.s32("lv", 1))
        base.add_child(Node.s32("mg", -1))
        base.add_child(Node.s32("ap", -1))
        base.add_child(
            Node.s32_array(
                "hidden_param",
                [
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
                    2,
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
                    0,
                ],
            )
        )
        base.add_child(Node.bool("is_tut", True))
        stglog = Node.void("stglog")
        pdata.add_child(stglog)
        index = 0
        for score in scores:
            log = Node.void("log")
            stglog.add_child(log)
            log.add_child(Node.s8("stg", index))
            log.add_child(Node.s16("mid", score["id"]))
            log.add_child(Node.s8("ng", score["chart"]))
            log.add_child(Node.s8("col", 0))
            log.add_child(Node.s8("mt", 7))
            log.add_child(Node.s8("rt", 0))
            log.add_child(Node.s8("ct", score["clear_type"]))
            log.add_child(Node.s16("grd", 0))
            log.add_child(Node.s16("ar", score["achievement_rate"]))
            log.add_child(Node.s16("sc", score["score"]))
            log.add_child(Node.s16("jt_jst", 0))
            log.add_child(Node.s16("jt_grt", 0))
            log.add_child(Node.s16("jt_gd", 0))
            log.add_child(Node.s16("jt_ms", score["miss_count"]))
            log.add_child(Node.s16("jt_jr", 0))
            log.add_child(Node.s16("cmb", score["combo"]))
            log.add_child(Node.s16("exp", 0))
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
            index = index + 1

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player/uid")
        return resp.child_value("player/uid")

    def verify_lobby_read(self, location: str, extid: int) -> None:
        call = self.call_node()

        lobby = Node.void("lobby")
        lobby.set_attribute("method", "read")
        lobby.add_child(Node.s32("uid", extid))
        lobby.add_child(Node.u8("m_grade", 255))
        lobby.add_child(Node.string("lid", location))
        lobby.add_child(Node.s32("max", 128))
        lobby.add_child(Node.s32_array("friend", []))
        lobby.add_child(Node.u8("var", 5))
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
        e.add_child(Node.s16("mg", 255))
        e.add_child(Node.s32("mopt", 0))
        e.add_child(Node.s32("tid", 0))
        e.add_child(Node.string("tn", ""))
        e.add_child(Node.s32("topt", 0))
        e.add_child(Node.string("lid", location))
        e.add_child(Node.string("sn", ""))
        e.add_child(Node.u8("pref", 51))
        e.add_child(Node.s8("stg", 4))
        e.add_child(Node.s8("pside", 0))
        e.add_child(Node.s16("eatime", 30))
        e.add_child(Node.u8_array("ga", [127, 0, 0, 1]))
        e.add_child(Node.u16("gp", 10007))
        e.add_child(Node.u8_array("la", [16, 0, 0, 0]))
        e.add_child(Node.u8("ver", 5))
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
        self.assert_path(resp, "response/lobby/e/mg")
        self.assert_path(resp, "response/lobby/e/mopt")
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
        self.assert_path(resp, "response/lobby/e/ver")
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

    def verify_pzlcmt_read(self, extid: int) -> None:
        call = self.call_node()

        info = Node.void("info")
        info.set_attribute("method", "pzlcmt_read")
        info.add_child(Node.s32("uid", extid))
        info.add_child(Node.s32("tid", 0))
        info.add_child(Node.s32("time", 0))
        info.add_child(Node.s32("limit", 30))
        call.add_child(info)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info/comment/time")
        self.assert_path(resp, "response/info/c/uid")
        self.assert_path(resp, "response/info/c/name")
        self.assert_path(resp, "response/info/c/icon")
        self.assert_path(resp, "response/info/c/bln")
        self.assert_path(resp, "response/info/c/tid")
        self.assert_path(resp, "response/info/c/t_name")
        self.assert_path(resp, "response/info/c/pref")
        self.assert_path(resp, "response/info/c/time")
        self.assert_path(resp, "response/info/c/comment")
        self.assert_path(resp, "response/info/c/is_tweet")

        # Verify we posted our comment earlier
        found = False
        for child in resp.child("info").children:
            if child.name != "c":
                continue
            if child.child_value("uid") == extid:
                name = child.child_value("name")
                comment = child.child_value("comment")
                if name != self.NAME:
                    raise Exception(f"Invalid name '{name}' returned for comment!")
                if comment != "アメ〜〜！":
                    raise Exception(
                        f"Invalid comment '{comment}' returned for comment!"
                    )
                found = True

        if not found:
            raise Exception("Comment we posted was not found!")

    def verify_pzlcmt_write(self, extid: int) -> None:
        call = self.call_node()

        info = Node.void("info")
        info.set_attribute("method", "pzlcmt_write")
        info.add_child(Node.s32("uid", extid))
        info.add_child(Node.string("name", self.NAME))
        info.add_child(Node.s16("icon", 0))
        info.add_child(Node.s8("bln", 0))
        info.add_child(Node.s32("tid", 0))
        info.add_child(Node.string("t_name", ""))
        info.add_child(Node.s8("pref", 51))
        info.add_child(Node.s32("time", int(time.time())))
        info.add_child(Node.string("comment", "アメ〜〜！"))
        info.add_child(Node.bool("is_tweet", True))
        call.add_child(info)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info")

    def verify_jbrbcollabo_save(self, refid: str) -> None:
        call = self.call_node()

        jbrbcollabo = Node.void("jbrbcollabo")
        jbrbcollabo.set_attribute("method", "save")
        jbrbcollabo.add_child(Node.string("ref_id", refid))
        jbrbcollabo.add_child(Node.u16("cre_count", 0))
        call.add_child(jbrbcollabo)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/jbrbcollabo")

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
        self.verify_pcb_boot(location)
        self.verify_info_common()

        # Verify card registration and profile lookup
        if cardid is not None:
            card = cardid
        else:
            card = self.random_card()
            print(f"Generated random card ID {card} for use.")

        if cardid is None:
            self.verify_cardmng_inquire(
                card, msg_type="unregistered", paseli_enabled=paseli_enabled
            )
            ref_id = self.verify_cardmng_getrefid(card)
            if len(ref_id) != 16:
                raise Exception(
                    f"Invalid refid '{ref_id}' returned when registering card"
                )
            if ref_id != self.verify_cardmng_inquire(
                card, msg_type="new", paseli_enabled=paseli_enabled
            ):
                raise Exception(f"Invalid refid '{ref_id}' returned when querying card")
            # Always get a player start, regardless of new profile or not
            self.verify_player_start(ref_id)
            self.verify_player_delete(ref_id)
            self.verify_player_succeed(ref_id)
            extid = self.verify_player_write(
                ref_id,
                location,
                [
                    {
                        "id": 0,
                        "chart": 0,
                        "clear_type": -1,
                        "achievement_rate": 0,
                        "score": 0,
                        "combo": 0,
                        "miss_count": 0,
                    }
                ],
            )
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(
                card, msg_type="query", paseli_enabled=paseli_enabled
            )

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(
            card, msg_type="query", paseli_enabled=paseli_enabled
        ):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        # Verify lobby functionality
        self.verify_lobby_read(location, extid)
        eid = self.verify_lobby_entry(location, extid)
        self.verify_lobby_delete(eid)

        # Verify puzzle comment read and write
        self.verify_pzlcmt_write(extid)
        self.verify_pzlcmt_read(extid)

        # Verify Jubeat/ReflecBeat collabo save
        self.verify_jbrbcollabo_save(ref_id)

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
                            "clear_type": 4,
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
                            "expected_clear_type": 4,
                            "expected_achievement_rate": 9876,
                            "expected_combo": 543,
                            "expected_miss_count": 0,
                        },
                    ]
                self.verify_player_write(ref_id, location, dummyscores)

                scores = self.verify_player_read(ref_id, location)
                for expected in dummyscores:
                    actual = None
                    for received in scores:
                        if (
                            received["id"] == expected["id"]
                            and received["chart"] == expected["chart"]
                        ):
                            actual = received
                            break

                    if actual is None:
                        raise Exception(
                            f"Didn't find song {expected['id']} chart {expected['chart']} in response!"
                        )

                    if "expected_score" in expected:
                        expected_score = expected["expected_score"]
                    else:
                        expected_score = expected["score"]
                    if "expected_achievement_rate" in expected:
                        expected_achievement_rate = expected[
                            "expected_achievement_rate"
                        ]
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

        # Verify high score tables
        self.verify_info_ranking()

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
