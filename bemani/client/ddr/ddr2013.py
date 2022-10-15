import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class DDR2013Client(BaseClient):
    NAME = "TEST"

    def verify_game_shop(self, loc: str) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "shop")
        game.set_attribute("area", "51")
        game.set_attribute("boot", "34")
        game.set_attribute("close", "0")
        game.set_attribute("close_t", "0")
        game.set_attribute("coin", "02.01.--.--.01.G")
        game.set_attribute("diff", "3")
        game.set_attribute("during", "1")
        game.set_attribute("edit_cnt", "0")
        game.set_attribute("edit_used", "1")
        game.set_attribute("first", "1")
        game.set_attribute("ip", "1.5.7.3")
        game.set_attribute("is_paseli", "1")
        game.set_attribute("loc", loc)
        game.set_attribute("mac", "00:11:22:33:44:55")
        game.set_attribute("machine", "2")
        game.set_attribute("name", "ＴＥＳＴ")
        game.set_attribute("pay", "0")
        game.set_attribute("region", ".")
        game.set_attribute("soft", self.config["model"])
        game.set_attribute("softid", self.pcbid)
        game.set_attribute("stage", "1")
        game.set_attribute("time", "60")
        game.set_attribute("type", "0")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@stop")

    def verify_game_common(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "common")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/flag/@id")
        self.assert_path(resp, "response/game/flag/@s1")
        self.assert_path(resp, "response/game/flag/@s2")
        self.assert_path(resp, "response/game/flag/@t")
        self.assert_path(resp, "response/game/cnt_music")

    def verify_game_hiscore(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "hiscore")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")
        for child in resp.child("game").children:
            self.assert_path(child, "music/@reclink_num")
            self.assert_path(child, "music/type/@diff")
            self.assert_path(child, "music/type/name")
            self.assert_path(child, "music/type/score")
            self.assert_path(child, "music/type/area")
            self.assert_path(child, "music/type/rank")
            self.assert_path(child, "music/type/combo_type")
            self.assert_path(child, "music/type/code")

    def verify_game_area_hiscore(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "area_hiscore")
        game.set_attribute("shop_area", "51")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")
        for child in resp.child("game").children:
            self.assert_path(child, "music/@reclink_num")
            self.assert_path(child, "music/type/@diff")
            self.assert_path(child, "music/type/name")
            self.assert_path(child, "music/type/score")
            self.assert_path(child, "music/type/area")
            self.assert_path(child, "music/type/rank")
            self.assert_path(child, "music/type/combo_type")
            self.assert_path(child, "music/type/code")

    def verify_game_message(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "message")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_ranking(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "ranking")
        game.set_attribute("max", "10")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_log(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "log")
        game.set_attribute("type", "0")
        game.set_attribute("soft", self.config["model"])
        game.set_attribute("softid", self.pcbid)
        game.set_attribute("ver", "2014032400")
        game.set_attribute("boot", "34")
        game.set_attribute("mac", "00:11:22:33:44:55")
        clear = Node.void("clear")
        game.add_child(clear)
        clear.set_attribute("book", "0")
        clear.set_attribute("edit", "0")
        clear.set_attribute("rank", "0")
        clear.set_attribute("set", "0")
        auto = Node.void("auto")
        game.add_child(auto)
        auto.set_attribute("book", "1")
        auto.set_attribute("edit", "1")
        auto.set_attribute("rank", "1")
        auto.set_attribute("set", "1")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_tax_info(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "tax_info")
        game.set_attribute("ver", "2014032400")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/tax_info/@tax_phase")

    def verify_game_recorder(self) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "recorder")
        game.set_attribute("assert_cnt", "0")
        game.set_attribute("assert_info", "")
        game.set_attribute("assert_path", "")
        game.set_attribute("assert_time", "0")
        game.set_attribute("boot_time", "1706151228")
        game.set_attribute("cnt_demo", "1")
        game.set_attribute("cnt_music", "1")
        game.set_attribute("cnt_play", "0")
        game.set_attribute("last_mid", "481")
        game.set_attribute("last_seq", "36")
        game.set_attribute("last_step", "0")
        game.set_attribute("last_time", "1706151235")
        game.set_attribute("softcode", self.config["model"])
        game.set_attribute("temp_seq", "15")
        game.set_attribute("temp_step", "8")
        game.set_attribute("temp_time", "1706151234")
        game.set_attribute("wd_restart", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_lock(self, ref_id: str, play: int) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("refid", ref_id)
        game.set_attribute("method", "lock")
        game.set_attribute("ver", "2014032400")
        game.set_attribute("play", str(play))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@now_login")

    def verify_game_new(self, ref_id: str) -> None:
        # Pad the name to 8 characters
        name = self.NAME[:8]
        while len(name) < 8:
            name = name + " "

        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "new")
        game.set_attribute("ver", "2014032400")
        game.set_attribute("name", name)
        game.set_attribute("area", "51")
        game.set_attribute("old", "0")
        game.set_attribute("refid", ref_id)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_load_daily(self, ref_id: str) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "load_daily")
        game.set_attribute("ver", "2014032400")
        game.set_attribute("refid", ref_id)

        # Swap with server
        resp = self.exchange("", call)

        self.assert_path(resp, "response/game/daycount/@playcount")
        self.assert_path(resp, "response/game/dailycombo/@daily_combo")
        self.assert_path(resp, "response/game/dailycombo/@daily_combo_lv")

    def verify_game_load(self, ref_id: str, msg_type: str) -> Dict[str, Any]:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "load")
        game.set_attribute("ver", "2014032400")
        game.set_attribute("refid", ref_id)

        # Swap with server
        resp = self.exchange("", call)

        if msg_type == "new":
            # Verify that response is correct
            self.assert_path(resp, "response/game/@none")
            return {}
        if msg_type == "existing":
            # Verify existing profile and return info
            self.assert_path(resp, "response/game/seq")
            self.assert_path(resp, "response/game/code")
            self.assert_path(resp, "response/game/name")
            self.assert_path(resp, "response/game/area")
            self.assert_path(resp, "response/game/cnt_s")
            self.assert_path(resp, "response/game/cnt_d")
            self.assert_path(resp, "response/game/cnt_b")
            self.assert_path(resp, "response/game/cnt_m0")
            self.assert_path(resp, "response/game/cnt_m1")
            self.assert_path(resp, "response/game/cnt_m2")
            self.assert_path(resp, "response/game/cnt_m3")
            self.assert_path(resp, "response/game/cnt_m4")
            self.assert_path(resp, "response/game/cnt_m5")
            self.assert_path(resp, "response/game/exp")
            self.assert_path(resp, "response/game/exp_o")
            self.assert_path(resp, "response/game/star")
            self.assert_path(resp, "response/game/star_c")
            self.assert_path(resp, "response/game/combo")
            self.assert_path(resp, "response/game/timing_diff")
            self.assert_path(resp, "response/game/chara")
            self.assert_path(resp, "response/game/chara_opt")
            self.assert_path(resp, "response/game/daycount/@playcount")
            self.assert_path(resp, "response/game/dailycombo/@daily_combo")
            self.assert_path(resp, "response/game/dailycombo/@daily_combo_lv")
            self.assert_path(resp, "response/game/last/@cate")
            self.assert_path(resp, "response/game/last/@cid")
            self.assert_path(resp, "response/game/last/@ctype")
            self.assert_path(resp, "response/game/last/@fri")
            self.assert_path(resp, "response/game/last/@mid")
            self.assert_path(resp, "response/game/last/@mode")
            self.assert_path(resp, "response/game/last/@mtype")
            self.assert_path(resp, "response/game/last/@rival1")
            self.assert_path(resp, "response/game/last/@rival2")
            self.assert_path(resp, "response/game/last/@rival3")
            self.assert_path(resp, "response/game/last/@sid")
            self.assert_path(resp, "response/game/last/@sort")
            self.assert_path(resp, "response/game/last/@style")
            self.assert_path(resp, "response/game/result_star/@slot1")
            self.assert_path(resp, "response/game/result_star/@slot2")
            self.assert_path(resp, "response/game/result_star/@slot3")
            self.assert_path(resp, "response/game/result_star/@slot4")
            self.assert_path(resp, "response/game/result_star/@slot5")
            self.assert_path(resp, "response/game/result_star/@slot6")
            self.assert_path(resp, "response/game/result_star/@slot7")
            self.assert_path(resp, "response/game/result_star/@slot8")
            self.assert_path(resp, "response/game/result_star/@slot9")
            self.assert_path(resp, "response/game/target/@flag")
            self.assert_path(resp, "response/game/target/@setnum")
            self.assert_path(resp, "response/game/gr_s/@gr1")
            self.assert_path(resp, "response/game/gr_s/@gr2")
            self.assert_path(resp, "response/game/gr_s/@gr3")
            self.assert_path(resp, "response/game/gr_s/@gr4")
            self.assert_path(resp, "response/game/gr_s/@gr5")
            self.assert_path(resp, "response/game/gr_d/@gr1")
            self.assert_path(resp, "response/game/gr_d/@gr2")
            self.assert_path(resp, "response/game/gr_d/@gr3")
            self.assert_path(resp, "response/game/gr_d/@gr4")
            self.assert_path(resp, "response/game/gr_d/@gr5")
            self.assert_path(resp, "response/game/opt")
            self.assert_path(resp, "response/game/opt_ex")
            self.assert_path(resp, "response/game/flag")
            self.assert_path(resp, "response/game/rank")
            for i in range(55):
                self.assert_path(resp, f"response/game/play_area/@play_cnt{i}")

            gr_s = resp.child("game/gr_s")
            gr_d = resp.child("game/gr_d")

            return {
                "name": resp.child_value("game/name"),
                "ext_id": resp.child_value("game/code"),
                "single_plays": resp.child_value("game/cnt_s"),
                "double_plays": resp.child_value("game/cnt_d"),
                "groove_single": [
                    int(gr_s.attribute("gr1")),
                    int(gr_s.attribute("gr2")),
                    int(gr_s.attribute("gr3")),
                    int(gr_s.attribute("gr4")),
                    int(gr_s.attribute("gr5")),
                ],
                "groove_double": [
                    int(gr_d.attribute("gr1")),
                    int(gr_d.attribute("gr2")),
                    int(gr_d.attribute("gr3")),
                    int(gr_d.attribute("gr4")),
                    int(gr_d.attribute("gr5")),
                ],
            }

        raise Exception("Unknown load type!")

    def verify_game_load_m(self, ref_id: str) -> Dict[int, Dict[int, Dict[str, Any]]]:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("ver", "2014032400")
        game.set_attribute("all", "1")
        game.set_attribute("refid", ref_id)
        game.set_attribute("method", "load_m")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        scores: Dict[int, Dict[int, Dict[str, Any]]] = {}
        self.assert_path(resp, "response/game")
        for child in resp.child("game").children:
            self.assert_path(child, "music/@reclink")
            reclink = int(child.attribute("reclink"))

            for typenode in child.children:
                self.assert_path(typenode, "type/@diff")
                self.assert_path(typenode, "type/score")
                self.assert_path(typenode, "type/count")
                self.assert_path(typenode, "type/rank")
                self.assert_path(typenode, "type/combo_type")
                chart = int(typenode.attribute("diff"))
                vals = {
                    "score": typenode.child_value("score"),
                    "count": typenode.child_value("count"),
                    "rank": typenode.child_value("rank"),
                    "halo": typenode.child_value("combo_type"),
                }
                if reclink not in scores:
                    scores[reclink] = {}
                scores[reclink][chart] = vals
        return scores

    def verify_game_save(
        self, ref_id: str, style: int, gauge: Optional[List[int]] = None
    ) -> None:
        gauge = gauge or [0, 0, 0, 0, 0]

        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "save")
        game.set_attribute("refid", ref_id)
        game.set_attribute("ver", "2014032400")
        game.set_attribute("shop_area", "51")
        last = Node.void("last")
        game.add_child(last)
        last.set_attribute("mode", "1")
        last.set_attribute("style", str(style))
        gr = Node.void("gr")
        game.add_child(gr)
        gr.set_attribute("gr1", str(gauge[0]))
        gr.set_attribute("gr2", str(gauge[1]))
        gr.set_attribute("gr3", str(gauge[2]))
        gr.set_attribute("gr4", str(gauge[3]))
        gr.set_attribute("gr5", str(gauge[4]))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_score(self, ref_id: str, songid: int, chart: int) -> List[int]:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "score")
        game.set_attribute("mid", str(songid))
        game.set_attribute("refid", ref_id)
        game.set_attribute("ver", "2014032400")
        game.set_attribute("type", str(chart))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@sc1")
        self.assert_path(resp, "response/game/@sc2")
        self.assert_path(resp, "response/game/@sc3")
        self.assert_path(resp, "response/game/@sc4")
        self.assert_path(resp, "response/game/@sc5")
        return [
            int(resp.child("game").attribute("sc1")),
            int(resp.child("game").attribute("sc2")),
            int(resp.child("game").attribute("sc3")),
            int(resp.child("game").attribute("sc4")),
            int(resp.child("game").attribute("sc5")),
        ]

    def verify_game_save_m(
        self, ref_id: str, ext_id: str, score: Dict[str, Any]
    ) -> None:
        call = self.call_node()
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "save_m")
        game.set_attribute("diff", "12345")
        game.set_attribute("mtype", str(score["chart"]))
        game.set_attribute("mid", str(score["id"]))
        game.set_attribute("refid", ref_id)
        game.set_attribute("ver", "2014032400")
        data = Node.void("data")
        game.add_child(data)
        data.set_attribute("score", str(score["score"]))
        data.set_attribute("rank", str(score["rank"]))
        data.set_attribute("shop_area", "0")
        data.set_attribute("playmode", "1")
        data.set_attribute("combo", str(score["combo"]))
        data.set_attribute("phase", "1")
        data.set_attribute("full", "1" if score["halo"] >= 1 else "0")
        data.set_attribute("great_fc", "1" if score["halo"] == 1 else "0")
        data.set_attribute("good_fc", "1" if score["halo"] == 4 else "0")
        data.set_attribute("perf_fc", "1" if score["halo"] == 2 else "0")
        player = Node.void("player")
        game.add_child(player)
        player.set_attribute("playcnt", "123")
        player.set_attribute("code", ext_id)
        option = Node.void("option")
        game.add_child(option)
        option.set_attribute("opt0", "6")
        option.set_attribute("opt6", "1")
        game.add_child(Node.u8_array("trace", [0] * 512))
        game.add_child(Node.u32("size", 512))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

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
        location = self.verify_facility_get("EUC_JP")
        self.verify_pcbevent_put()
        self.verify_game_shop(location)
        self.verify_game_common()
        self.verify_game_hiscore()
        self.verify_game_area_hiscore()
        self.verify_game_message()
        self.verify_game_ranking()
        self.verify_game_log()
        self.verify_game_tax_info()
        self.verify_game_recorder()

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
            # Bishi doesn't read a new profile, it just writes out CSV for a blank one
            self.verify_game_load(ref_id, msg_type="new")
            self.verify_game_new(ref_id)
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

        # Verify locking and unlocking profile ability
        self.verify_game_lock(ref_id, 1)
        self.verify_game_lock(ref_id, 0)

        if cardid is None:
            # Verify empty profile
            profile = self.verify_game_load(ref_id, msg_type="existing")
            ext_id = str(profile["ext_id"])
            if profile["name"] != self.NAME:
                raise Exception("Profile has invalid name associated with it!")
            if profile["single_plays"] != 0:
                raise Exception("Profile has plays on single already!")
            if profile["double_plays"] != 0:
                raise Exception("Profile has plays on double already!")
            if any([g != 0 for g in profile["groove_single"]]):
                raise Exception("Profile has single groove gauge values already!")
            if any([g != 0 for g in profile["groove_double"]]):
                raise Exception("Profile has double groove gauge values already!")

            # Verify empty scores
            scores = self.verify_game_load_m(ref_id)
            if len(scores) > 0:
                raise Exception("Scores exist on new profile!")

            self.verify_game_load_daily(ref_id)

            # Verify profile saving
            self.verify_game_save(ref_id, 0, [1, 2, 3, 4, 5])
            profile = self.verify_game_load(ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception("Profile has invalid name associated with it!")
            if profile["single_plays"] != 1:
                raise Exception("Profile has invalid plays on single!")
            if profile["double_plays"] != 0:
                raise Exception("Profile has invalid plays on double!")
            if profile["groove_single"] != [1, 2, 3, 4, 5]:
                raise Exception("Profile has invalid single groove gauge values!")
            if any([g != 0 for g in profile["groove_double"]]):
                raise Exception("Profile has invalid double groove gauge values!")

            self.verify_game_save(ref_id, 1, [5, 4, 3, 2, 1])
            profile = self.verify_game_load(ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception("Profile has invalid name associated with it!")
            if profile["single_plays"] != 1:
                raise Exception("Profile has invalid plays on single!")
            if profile["double_plays"] != 1:
                raise Exception("Profile has invalid plays on double!")
            if profile["groove_single"] != [1, 2, 3, 4, 5]:
                raise Exception("Profile has invalid single groove gauge values!")
            if profile["groove_double"] != [5, 4, 3, 2, 1]:
                raise Exception("Profile has invalid double groove gauge values!")

            # Now, write some scores and verify saving
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 593,
                            "chart": 3,
                            "score": 800000,
                            "combo": 123,
                            "rank": 4,
                            "halo": 1,
                        },
                        # A good score on an easier chart same song
                        {
                            "id": 593,
                            "chart": 2,
                            "score": 990000,
                            "combo": 321,
                            "rank": 2,
                            "halo": 2,
                        },
                        # A perfect score
                        {
                            "id": 483,
                            "chart": 3,
                            "score": 1000000,
                            "combo": 400,
                            "rank": 1,
                            "halo": 3,
                        },
                        # A bad score
                        {
                            "id": 483,
                            "chart": 2,
                            "score": 100000,
                            "combo": 5,
                            "rank": 7,
                            "halo": 0,
                        },
                        {
                            "id": 483,
                            "chart": 1,
                            "score": 60000,
                            "combo": 5,
                            "rank": 6,
                            "halo": 4,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on a chart
                        {
                            "id": 593,
                            "chart": 3,
                            "score": 850000,
                            "combo": 234,
                            "rank": 3,
                            "halo": 2,
                        },
                        # A worse score on another chart
                        {
                            "id": 593,
                            "chart": 2,
                            "score": 980000,
                            "combo": 300,
                            "rank": 3,
                            "halo": 0,
                            "expected_score": 990000,
                            "expected_rank": 2,
                            "expected_halo": 2,
                        },
                    ]

                # Verify empty scores for starters
                if phase == 1:
                    for score in dummyscores:
                        last_five = self.verify_game_score(
                            ref_id, score["id"], score["chart"]
                        )
                        if any([s != 0 for s in last_five]):
                            raise Exception(
                                "Score already found on song not played yet!"
                            )
                for score in dummyscores:
                    self.verify_game_save_m(ref_id, ext_id, score)
                scores = self.verify_game_load_m(ref_id)
                for score in dummyscores:
                    data = scores.get(score["id"], {}).get(score["chart"], None)
                    if data is None:
                        raise Exception(
                            f'Expected to get score back for song {score["id"]} chart {score["chart"]}!'
                        )

                    # Verify the attributes of the score
                    expected_score = score.get("expected_score", score["score"])
                    expected_rank = score.get("expected_rank", score["rank"])
                    expected_halo = score.get("expected_halo", score["halo"])

                    if data["score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got score \'{data["score"]}\''
                        )
                    if data["rank"] != expected_rank:
                        raise Exception(
                            f'Expected a rank of \'{expected_rank}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got rank \'{data["rank"]}\''
                        )
                    if data["halo"] != expected_halo:
                        raise Exception(
                            f'Expected a halo of \'{expected_halo}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got halo \'{data["halo"]}\''
                        )

                    # Verify that the last score is our score
                    last_five = self.verify_game_score(
                        ref_id, score["id"], score["chart"]
                    )
                    if last_five[0] != score["score"]:
                        raise Exception(
                            f'Invalid score returned for last five scores on song {score["id"]} chart {score["chart"]}!'
                        )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)
        else:
            print("Skipping score checks for existing card")

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
