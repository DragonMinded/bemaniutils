import random
import time
from typing import Any, Dict, Optional, Tuple

from bemani.client.base import BaseClient
from bemani.protocol import Node


class IIDXTricoroClient(BaseClient):
    NAME = "TEST"

    def verify_shop_getname(self, lid: str) -> str:
        call = self.call_node()

        # Construct node
        IIDX21shop = Node.void("shop")
        call.add_child(IIDX21shop)
        IIDX21shop.set_attribute("method", "getname")
        IIDX21shop.set_attribute("lid", lid)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/shop/@opname")
        self.assert_path(resp, "response/shop/@pid")
        self.assert_path(resp, "response/shop/@cls_opt")

        return resp.child("shop").attribute("opname")

    def verify_shop_savename(self, lid: str, name: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21shop = Node.void("shop")
        IIDX21shop.set_attribute("lid", lid)
        IIDX21shop.set_attribute("pid", "51")
        IIDX21shop.set_attribute("method", "savename")
        IIDX21shop.set_attribute("cls_opt", "0")
        IIDX21shop.set_attribute("ccode", "US")
        IIDX21shop.set_attribute("opname", name)
        IIDX21shop.set_attribute("rcode", ".")

        call.add_child(IIDX21shop)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/shop")

    def verify_pc_common(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("method", "common")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pc/ir/@beat")
        self.assert_path(resp, "response/pc/limit/@phase")
        self.assert_path(resp, "response/pc/boss/@phase")
        self.assert_path(resp, "response/pc/red/@phase")
        self.assert_path(resp, "response/pc/yellow/@phase")
        self.assert_path(resp, "response/pc/medal/@phase")
        self.assert_path(resp, "response/pc/tricolettepark/@open")
        self.assert_path(resp, "response/pc/cafe/@open")

    def verify_music_crate(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("music")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("method", "crate")

        # Swap with server
        resp = self.exchange("", call)

        self.assert_path(resp, "response/music")
        for child in resp.child("music").children:
            if child.name != "c":
                raise Exception(f"Invalid node {child} in clear rate response!")
            if len(child.value) != 12:
                raise Exception(f"Invalid node data {child} in clear rate response!")
            for v in child.value:
                if v < 0 or v > 101:
                    raise Exception(f"Invalid clear percent {child} in clear rate response!")

    def verify_shop_getconvention(self, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("shop")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("method", "getconvention")
        IIDX21pc.set_attribute("lid", lid)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/shop/valid")
        self.assert_path(resp, "response/shop/@music_0")
        self.assert_path(resp, "response/shop/@music_1")
        self.assert_path(resp, "response/shop/@music_2")
        self.assert_path(resp, "response/shop/@music_3")

    def verify_pc_visit(self, extid: int, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("iidxid", str(extid))
        IIDX21pc.set_attribute("lid", lid)
        IIDX21pc.set_attribute("method", "visit")
        IIDX21pc.set_attribute("pid", "51")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pc/@aflg")
        self.assert_path(resp, "response/pc/@anum")
        self.assert_path(resp, "response/pc/@pflg")
        self.assert_path(resp, "response/pc/@pnum")
        self.assert_path(resp, "response/pc/@sflg")
        self.assert_path(resp, "response/pc/@snum")

    def verify_ranking_getranker(self, lid: str) -> None:
        for clid in [0, 1, 2, 3, 4, 5, 6]:
            call = self.call_node()

            # Construct node
            IIDX21pc = Node.void("ranking")
            call.add_child(IIDX21pc)
            IIDX21pc.set_attribute("method", "getranker")
            IIDX21pc.set_attribute("lid", lid)
            IIDX21pc.set_attribute("clid", str(clid))

            # Swap with server
            resp = self.exchange("", call)

            # Verify that response is correct
            self.assert_path(resp, "response/ranking")

    def verify_shop_sentinfo(self, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("shop")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("method", "sentinfo")
        IIDX21pc.set_attribute("lid", lid)
        IIDX21pc.set_attribute("bflg", "1")
        IIDX21pc.set_attribute("bnum", "2")
        IIDX21pc.set_attribute("ioid", "0")
        IIDX21pc.set_attribute("tax_phase", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/shop")

    def verify_pc_get(self, ref_id: str, card_id: str, lid: str) -> Dict[str, Any]:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("rid", ref_id)
        IIDX21pc.set_attribute("did", ref_id)
        IIDX21pc.set_attribute("pid", "51")
        IIDX21pc.set_attribute("lid", lid)
        IIDX21pc.set_attribute("cid", card_id)
        IIDX21pc.set_attribute("method", "get")
        IIDX21pc.set_attribute("ctype", "1")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that the response is correct
        self.assert_path(resp, "response/pc/pcdata/@name")
        self.assert_path(resp, "response/pc/pcdata/@pid")
        self.assert_path(resp, "response/pc/pcdata/@id")
        self.assert_path(resp, "response/pc/pcdata/@idstr")
        self.assert_path(resp, "response/pc/packinfo")
        self.assert_path(resp, "response/pc/commonboss/@deller")
        self.assert_path(resp, "response/pc/commonboss/@orb")
        self.assert_path(resp, "response/pc/commonboss/@baron")
        self.assert_path(resp, "response/pc/secret/flg1")
        self.assert_path(resp, "response/pc/secret/flg2")
        self.assert_path(resp, "response/pc/secret/flg3")
        self.assert_path(resp, "response/pc/achievements/trophy")
        self.assert_path(resp, "response/pc/skin")
        self.assert_path(resp, "response/pc/grade")
        self.assert_path(resp, "response/pc/rlist")
        self.assert_path(resp, "response/pc/step")

        name = resp.child("pc/pcdata").attribute("name")
        if name != self.NAME:
            raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

        return {
            "extid": int(resp.child("pc/pcdata").attribute("id")),
            "sp_dan": int(resp.child("pc/grade").attribute("sgid")),
            "dp_dan": int(resp.child("pc/grade").attribute("dgid")),
            "deller": int(resp.child("pc/commonboss").attribute("deller")),
        }

    def verify_music_getrank(self, extid: int) -> Dict[int, Dict[int, Dict[str, int]]]:
        scores: Dict[int, Dict[int, Dict[str, int]]] = {}
        for cltype in [0, 1]:  # singles, doubles
            call = self.call_node()

            # Construct node
            IIDX21music = Node.void("music")
            call.add_child(IIDX21music)
            IIDX21music.set_attribute("method", "getrank")
            IIDX21music.set_attribute("iidxid", str(extid))
            IIDX21music.set_attribute("cltype", str(cltype))

            # Swap with server
            resp = self.exchange("", call)

            self.assert_path(resp, "response/music/style")
            if int(resp.child("music/style").attribute("type")) != cltype:
                raise Exception("Returned wrong clear type for IIDX21music.getrank!")

            for child in resp.child("music").children:
                if child.name == "m":
                    if child.value[0] != -1:
                        raise Exception("Got non-self score back when requesting only our scores!")

                    music_id = child.value[1]
                    normal_clear_status = child.value[2]
                    hyper_clear_status = child.value[3]
                    another_clear_status = child.value[4]
                    normal_ex_score = child.value[5]
                    hyper_ex_score = child.value[6]
                    another_ex_score = child.value[7]
                    normal_miss_count = child.value[8]
                    hyper_miss_count = child.value[9]
                    another_miss_count = child.value[10]

                    if cltype == 0:
                        normal = 0
                        hyper = 1
                        another = 2
                    else:
                        normal = 3
                        hyper = 4
                        another = 5

                    if music_id not in scores:
                        scores[music_id] = {}

                    scores[music_id][normal] = {
                        "clear_status": normal_clear_status,
                        "ex_score": normal_ex_score,
                        "miss_count": normal_miss_count,
                    }
                    scores[music_id][hyper] = {
                        "clear_status": hyper_clear_status,
                        "ex_score": hyper_ex_score,
                        "miss_count": hyper_miss_count,
                    }
                    scores[music_id][another] = {
                        "clear_status": another_clear_status,
                        "ex_score": another_ex_score,
                        "miss_count": another_miss_count,
                    }
                elif child.name == "b":
                    music_id = child.value[0]
                    clear_status = child.value[1]

                    scores[music_id][6] = {
                        "clear_status": clear_status,
                        "ex_score": -1,
                        "miss_count": -1,
                    }

        return scores

    def verify_pc_save(self, extid: int, card: str, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("achi", "449")
        IIDX21pc.set_attribute("opt", "8208")
        IIDX21pc.set_attribute("gpos", "0")
        IIDX21pc.set_attribute("gno", "8")
        IIDX21pc.set_attribute("timing", "0")
        IIDX21pc.set_attribute("help", "0")
        IIDX21pc.set_attribute("sdhd", "0")
        IIDX21pc.set_attribute("sdtype", "0")
        IIDX21pc.set_attribute("notes", "31.484070")
        IIDX21pc.set_attribute("pase", "0")
        IIDX21pc.set_attribute("judge", "0")
        IIDX21pc.set_attribute("opstyle", "1")
        IIDX21pc.set_attribute("hispeed", "5.771802")
        IIDX21pc.set_attribute("mode", "6")
        IIDX21pc.set_attribute("pmode", "0")
        IIDX21pc.set_attribute("lift", "60")
        IIDX21pc.set_attribute("judgeAdj", "0")

        IIDX21pc.set_attribute("method", "save")
        IIDX21pc.set_attribute("iidxid", str(extid))
        IIDX21pc.set_attribute("lid", lid)
        IIDX21pc.set_attribute("cid", card)
        IIDX21pc.set_attribute("cltype", "0")
        IIDX21pc.set_attribute("ctype", "1")

        pyramid = Node.void("pyramid")
        IIDX21pc.add_child(pyramid)
        pyramid.set_attribute("point", "290")
        destiny_catharsis = Node.void("destiny_catharsis")
        IIDX21pc.add_child(destiny_catharsis)
        destiny_catharsis.set_attribute("point", "290")
        bemani_summer_collabo = Node.void("bemani_summer_collabo")
        IIDX21pc.add_child(bemani_summer_collabo)
        bemani_summer_collabo.set_attribute("point", "290")
        deller = Node.void("deller")
        IIDX21pc.add_child(deller)
        deller.set_attribute("deller", "150")

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/pc")

    def verify_music_reg(self, extid: int, lid: str, score: Dict[str, Any]) -> None:
        call = self.call_node()

        # Construct node
        IIDX21music = Node.void("music")
        call.add_child(IIDX21music)
        IIDX21music.set_attribute("convid", "-1")
        IIDX21music.set_attribute("iidxid", str(extid))
        IIDX21music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX21music.set_attribute("pid", "51")
        IIDX21music.set_attribute("rankside", "1")
        IIDX21music.set_attribute("cflg", str(score["clear_status"]))
        IIDX21music.set_attribute("method", "reg")
        IIDX21music.set_attribute("gnum", str(score["gnum"]))
        IIDX21music.set_attribute("clid", str(score["chart"]))
        IIDX21music.set_attribute("mnum", str(score["mnum"]))
        IIDX21music.set_attribute("is_death", "0")
        IIDX21music.set_attribute("theory", "0")
        IIDX21music.set_attribute("shopconvid", lid)
        IIDX21music.set_attribute("mid", str(score["id"]))
        IIDX21music.set_attribute("shopflg", "1")
        IIDX21music.add_child(Node.binary("ghost", bytes([1] * 64)))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/music/shopdata/@rank")
        self.assert_path(resp, "response/music/ranklist/data")

    def verify_music_appoint(self, extid: int, musicid: int, chart: int) -> Tuple[int, bytes]:
        call = self.call_node()

        # Construct node
        IIDX21music = Node.void("music")
        call.add_child(IIDX21music)
        IIDX21music.set_attribute("clid", str(chart))
        IIDX21music.set_attribute("method", "appoint")
        IIDX21music.set_attribute("ctype", "0")
        IIDX21music.set_attribute("iidxid", str(extid))
        IIDX21music.set_attribute("subtype", "")
        IIDX21music.set_attribute("mid", str(musicid))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/music/mydata/@score")

        return (
            int(resp.child("music/mydata").attribute("score")),
            resp.child_value("music/mydata"),
        )

    def verify_pc_reg(self, ref_id: str, card_id: str, lid: str) -> int:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        call.add_child(IIDX21pc)
        IIDX21pc.set_attribute("lid", lid)
        IIDX21pc.set_attribute("pid", "51")
        IIDX21pc.set_attribute("method", "reg")
        IIDX21pc.set_attribute("cid", card_id)
        IIDX21pc.set_attribute("did", ref_id)
        IIDX21pc.set_attribute("rid", ref_id)
        IIDX21pc.set_attribute("name", self.NAME)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/pc/@id")
        self.assert_path(resp, "response/pc/@id_str")

        return int(resp.child("pc").attribute("id"))

    def verify_pc_playstart(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        IIDX21pc.set_attribute("method", "playstart")
        IIDX21pc.set_attribute("side", "1")
        call.add_child(IIDX21pc)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/pc")

    def verify_music_play(self, score: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        IIDX21music = Node.void("music")
        IIDX21music.set_attribute("opt", "64")
        IIDX21music.set_attribute("clid", str(score["chart"]))
        IIDX21music.set_attribute("mid", str(score["id"]))
        IIDX21music.set_attribute("gnum", str(score["gnum"]))
        IIDX21music.set_attribute("cflg", str(score["clear_status"]))
        IIDX21music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX21music.set_attribute("pid", "51")
        IIDX21music.set_attribute("method", "play")
        call.add_child(IIDX21music)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/music/@clid")
        self.assert_path(resp, "response/music/@crate")
        self.assert_path(resp, "response/music/@frate")
        self.assert_path(resp, "response/music/@mid")

    def verify_pc_playend(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX21pc = Node.void("pc")
        IIDX21pc.set_attribute("cltype", "0")
        IIDX21pc.set_attribute("bookkeep", "0")
        IIDX21pc.set_attribute("mode", "1")
        IIDX21pc.set_attribute("method", "playend")
        call.add_child(IIDX21pc)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/pc")

    def verify_music_breg(self, iidxid: int, score: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        IIDX21music = Node.void("music")
        IIDX21music.set_attribute("gnum", str(score["gnum"]))
        IIDX21music.set_attribute("iidxid", str(iidxid))
        IIDX21music.set_attribute("mid", str(score["id"]))
        IIDX21music.set_attribute("method", "breg")
        IIDX21music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX21music.set_attribute("cflg", str(score["clear_status"]))
        call.add_child(IIDX21music)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/music")

    def verify_grade_raised(self, iidxid: int, shop_name: str, dantype: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX21grade = Node.void("grade")
        IIDX21grade.set_attribute("opname", shop_name)
        IIDX21grade.set_attribute("is_mirror", "0")
        IIDX21grade.set_attribute("oppid", "51")
        IIDX21grade.set_attribute("achi", "50")
        IIDX21grade.set_attribute("cflg", "4" if dantype == "sp" else "3")
        IIDX21grade.set_attribute("gid", "5")
        IIDX21grade.set_attribute("iidxid", str(iidxid))
        IIDX21grade.set_attribute("gtype", "0" if dantype == "sp" else "1")
        IIDX21grade.set_attribute("is_ex", "0")
        IIDX21grade.set_attribute("pside", "0")
        IIDX21grade.set_attribute("method", "raised")
        call.add_child(IIDX21grade)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/grade/@pnum")

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
        self.verify_package_list()
        self.verify_message_get()
        lid = self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_shop_getname(lid)
        self.verify_pc_common()
        self.verify_music_crate()
        self.verify_shop_getconvention(lid)
        self.verify_ranking_getranker(lid)
        self.verify_shop_sentinfo(lid)

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
            self.verify_pc_reg(ref_id, card, lid)
            self.verify_pc_get(ref_id, card, lid)
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        if cardid is None:
            # Verify score handling
            profile = self.verify_pc_get(ref_id, card, lid)
            if profile["sp_dan"] != -1:
                raise Exception("Somehow has SP DAN ranking on new profile!")
            if profile["dp_dan"] != -1:
                raise Exception("Somehow has DP DAN ranking on new profile!")
            if profile["deller"] != 0:
                raise Exception("Somehow has deller on new profile!")
            scores = self.verify_music_getrank(profile["extid"])
            if len(scores.keys()) > 0:
                raise Exception("Somehow have scores on a new profile!")

            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 1000,
                            "chart": 2,
                            "clear_status": 4,
                            "pgnum": 123,
                            "gnum": 123,
                            "mnum": 5,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 1000,
                            "chart": 0,
                            "clear_status": 7,
                            "pgnum": 246,
                            "gnum": 0,
                            "mnum": 0,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 1003,
                            "chart": 2,
                            "clear_status": 1,
                            "pgnum": 10,
                            "gnum": 20,
                            "mnum": 50,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 1003,
                            "chart": 0,
                            "clear_status": 1,
                            "pgnum": 2,
                            "gnum": 5,
                            "mnum": 75,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 1000,
                            "chart": 2,
                            "clear_status": 5,
                            "pgnum": 234,
                            "gnum": 234,
                            "mnum": 3,
                        },
                        # A worse score on another same chart
                        {
                            "id": 1000,
                            "chart": 0,
                            "clear_status": 4,
                            "pgnum": 123,
                            "gnum": 123,
                            "mnum": 35,
                            "expected_clear_status": 7,
                            "expected_ex_score": 492,
                            "expected_miss_count": 0,
                        },
                    ]

                for dummyscore in dummyscores:
                    self.verify_music_reg(profile["extid"], lid, dummyscore)
                self.verify_pc_visit(profile["extid"], lid)
                self.verify_pc_save(profile["extid"], card, lid)
                scores = self.verify_music_getrank(profile["extid"])
                for score in dummyscores:
                    data = scores.get(score["id"], {}).get(score["chart"], None)
                    if data is None:
                        raise Exception(f'Expected to get score back for song {score["id"]} chart {score["chart"]}!')

                    if "expected_ex_score" in score:
                        expected_score = score["expected_ex_score"]
                    else:
                        expected_score = (score["pgnum"] * 2) + score["gnum"]
                    if "expected_clear_status" in score:
                        expected_clear_status = score["expected_clear_status"]
                    else:
                        expected_clear_status = score["clear_status"]
                    if "expected_miss_count" in score:
                        expected_miss_count = score["expected_miss_count"]
                    else:
                        expected_miss_count = score["mnum"]

                    if data["ex_score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got score \'{data["ex_score"]}\''
                        )
                    if data["clear_status"] != expected_clear_status:
                        raise Exception(
                            f'Expected a clear status of \'{expected_clear_status}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got clear status \'{data["clear_status"]}\''
                        )
                    if data["miss_count"] != expected_miss_count:
                        raise Exception(
                            f'Expected a miss count of \'{expected_miss_count}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got miss count \'{data["miss_count"]}\''
                        )

                    # Verify we can fetch our own ghost
                    ex_score, ghost = self.verify_music_appoint(profile["extid"], score["id"], score["chart"])
                    if ex_score != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got score \'{data["ex_score"]}\''
                        )

                    if len(ghost) != 64:
                        raise Exception(f"Wrong ghost length {len(ghost)} for ghost!")
                    for g in ghost:
                        if g != 0x01:
                            raise Exception(
                                f'Got back wrong ghost data for song \'{score["id"]}\' chart \'{score["chart"]}\''
                            )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

            # Verify that a player without a card can play
            self.verify_pc_playstart()
            self.verify_music_play(
                {
                    "id": 1000,
                    "chart": 2,
                    "clear_status": 4,
                    "pgnum": 123,
                    "gnum": 123,
                }
            )
            self.verify_pc_playend()

            # Verify shop name change setting
            self.verify_shop_savename(lid, "newname1")
            newname = self.verify_shop_getname(lid)
            if newname != "newname1":
                raise Exception("Invalid shop name returned after change!")
            self.verify_shop_savename(lid, "newname2")
            newname = self.verify_shop_getname(lid)
            if newname != "newname2":
                raise Exception("Invalid shop name returned after change!")

            # Verify beginner score saving
            self.verify_music_breg(
                profile["extid"],
                {
                    "id": 1000,
                    "clear_status": 4,
                    "pgnum": 123,
                    "gnum": 123,
                },
            )
            scores = self.verify_music_getrank(profile["extid"])
            if 1000 not in scores:
                raise Exception(f"Didn't get expected scores back for song {1000} beginner chart!")
            if 6 not in scores[1000]:
                raise Exception(f"Didn't get beginner score back for song {1000}!")
            if scores[1000][6] != {"clear_status": 4, "ex_score": -1, "miss_count": -1}:
                raise Exception("Didn't get correct status back from beginner save!")

            # Verify DAN score saving and loading
            self.verify_grade_raised(profile["extid"], newname, "sp")
            self.verify_grade_raised(profile["extid"], newname, "dp")
            profile = self.verify_pc_get(ref_id, card, lid)
            if profile["sp_dan"] != 5:
                raise Exception("Got wrong DAN score back for SP!")
            if profile["dp_dan"] != 5:
                raise Exception("Got wrong DAN score back for DP!")
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
