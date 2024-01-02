import random
import time
from typing import Any, Dict, Optional, Tuple

from bemani.client.base import BaseClient
from bemani.protocol import Node


class IIDXRootageClient(BaseClient):
    NAME = "TEST"

    def verify_iidx26shop_getname(self, lid: str) -> str:
        call = self.call_node()

        # Construct node
        IIDX26shop = Node.void("IIDX26shop")
        call.add_child(IIDX26shop)
        IIDX26shop.set_attribute("method", "getname")
        IIDX26shop.set_attribute("lid", lid)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26shop/@opname")
        self.assert_path(resp, "response/IIDX26shop/@pid")
        self.assert_path(resp, "response/IIDX26shop/@cls_opt")
        self.assert_path(resp, "response/IIDX26shop/@hr")
        self.assert_path(resp, "response/IIDX26shop/@mi")

        return resp.child("IIDX26shop").attribute("opname")

    def verify_iidx26shop_savename(self, lid: str, name: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26shop = Node.void("IIDX26shop")
        IIDX26shop.set_attribute("lid", lid)
        IIDX26shop.set_attribute("pid", "51")
        IIDX26shop.set_attribute("method", "savename")
        IIDX26shop.set_attribute("cls_opt", "0")
        IIDX26shop.set_attribute("ccode", "US")
        IIDX26shop.set_attribute("opname", name)
        IIDX26shop.set_attribute("rcode", ".")

        call.add_child(IIDX26shop)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26shop")

    def verify_iidx26pc_common(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("method", "common")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26pc/ir/@beat")
        self.assert_path(resp, "response/IIDX26pc/newsong_another/@open")
        self.assert_path(resp, "response/IIDX26pc/boss/@phase")
        self.assert_path(resp, "response/IIDX26pc/event1_phase/@phase")
        self.assert_path(resp, "response/IIDX26pc/event2_phase/@phase")
        self.assert_path(resp, "response/IIDX26pc/extra_boss_event/@phase")
        self.assert_path(resp, "response/IIDX26pc/common_evnet/@flg")

    def verify_iidx26music_crate(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26music")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("method", "crate")

        # Swap with server
        resp = self.exchange("", call)

        self.assert_path(resp, "response/IIDX26music")
        for child in resp.child("IIDX26music").children:
            if child.name != "c":
                raise Exception(f"Invalid node {child} in clear rate response!")
            if len(child.value) != 12:
                raise Exception(f"Invalid node data {child} in clear rate response!")
            for v in child.value:
                if v < 0 or v > 1001:
                    raise Exception(f"Invalid clear percent {child} in clear rate response!")

    def verify_iidx26shop_getconvention(self, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26shop")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("method", "getconvention")
        IIDX26pc.set_attribute("lid", lid)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26shop/valid")
        self.assert_path(resp, "response/IIDX26shop/@music_0")
        self.assert_path(resp, "response/IIDX26shop/@music_1")
        self.assert_path(resp, "response/IIDX26shop/@music_2")
        self.assert_path(resp, "response/IIDX26shop/@music_3")

    def verify_iidx26pc_visit(self, extid: int, lid: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("iidxid", str(extid))
        IIDX26pc.set_attribute("lid", lid)
        IIDX26pc.set_attribute("method", "visit")
        IIDX26pc.set_attribute("pid", "51")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26pc/@aflg")
        self.assert_path(resp, "response/IIDX26pc/@anum")
        self.assert_path(resp, "response/IIDX26pc/@pflg")
        self.assert_path(resp, "response/IIDX26pc/@pnum")
        self.assert_path(resp, "response/IIDX26pc/@sflg")
        self.assert_path(resp, "response/IIDX26pc/@snum")

    def verify_iidx26ranking_getranker(self, lid: str) -> None:
        for clid in [0, 1, 2, 3, 4, 5, 6]:
            call = self.call_node()

            # Construct node
            IIDX26pc = Node.void("IIDX26ranking")
            call.add_child(IIDX26pc)
            IIDX26pc.set_attribute("method", "getranker")
            IIDX26pc.set_attribute("lid", lid)
            IIDX26pc.set_attribute("clid", str(clid))

            # Swap with server
            resp = self.exchange("", call)

            # Verify that response is correct
            self.assert_path(resp, "response/IIDX26ranking")

    def verify_iidx26shop_sentinfo(self, lid: str, shop_name: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26shop")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("method", "sentinfo")
        IIDX26pc.set_attribute("lid", lid)
        IIDX26pc.set_attribute("bflg", "1")
        IIDX26pc.set_attribute("bnum", "2")
        IIDX26pc.set_attribute("ioid", "0")
        IIDX26pc.set_attribute("company_code", "")
        IIDX26pc.set_attribute("consumer_code", "")
        IIDX26pc.set_attribute("location_name", shop_name)
        IIDX26pc.set_attribute("tax_phase", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/IIDX26shop")

    def verify_iidx26pc_get(self, ref_id: str, card_id: str, lid: str) -> Dict[str, Any]:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("rid", ref_id)
        IIDX26pc.set_attribute("did", ref_id)
        IIDX26pc.set_attribute("pid", "51")
        IIDX26pc.set_attribute("lid", lid)
        IIDX26pc.set_attribute("cid", card_id)
        IIDX26pc.set_attribute("method", "get")
        IIDX26pc.set_attribute("ctype", "1")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that the response is correct
        self.assert_path(resp, "response/IIDX26pc/pcdata/@name")
        self.assert_path(resp, "response/IIDX26pc/pcdata/@pid")
        self.assert_path(resp, "response/IIDX26pc/pcdata/@id")
        self.assert_path(resp, "response/IIDX26pc/pcdata/@idstr")
        self.assert_path(resp, "response/IIDX26pc/deller")
        self.assert_path(resp, "response/IIDX26pc/secret/flg1")
        self.assert_path(resp, "response/IIDX26pc/secret/flg2")
        self.assert_path(resp, "response/IIDX26pc/secret/flg3")
        self.assert_path(resp, "response/IIDX26pc/achievements/trophy")
        self.assert_path(resp, "response/IIDX26pc/skin")
        self.assert_path(resp, "response/IIDX26pc/qprodata")
        self.assert_path(resp, "response/IIDX26pc/grade")
        self.assert_path(resp, "response/IIDX26pc/rlist")
        self.assert_path(resp, "response/IIDX26pc/step")
        self.assert_path(resp, "response/IIDX26pc/favorite/sp_mlist")
        self.assert_path(resp, "response/IIDX26pc/favorite/sp_clist")
        self.assert_path(resp, "response/IIDX26pc/favorite/dp_mlist")
        self.assert_path(resp, "response/IIDX26pc/favorite/dp_clist")
        self.assert_path(resp, "response/IIDX26pc/extra_favorite/sp_mlist")
        self.assert_path(resp, "response/IIDX26pc/extra_favorite/sp_clist")
        self.assert_path(resp, "response/IIDX26pc/extra_favorite/dp_mlist")
        self.assert_path(resp, "response/IIDX26pc/extra_favorite/dp_clist")

        name = resp.child("IIDX26pc/pcdata").attribute("name")
        if name != self.NAME:
            raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

        expert_point: Dict[int, Dict[str, int]] = {}
        for child in resp.child("IIDX26pc/expert_point").children:
            if child.name == "detail":
                expert_point[int(child.attribute("course_id"))] = {
                    "n_point": int(child.attribute("n_point")),
                    "h_point": int(child.attribute("h_point")),
                    "a_point": int(child.attribute("a_point")),
                }

        return {
            "extid": int(resp.child("IIDX26pc/pcdata").attribute("id")),
            "sp_dan": int(resp.child("IIDX26pc/grade").attribute("sgid")),
            "dp_dan": int(resp.child("IIDX26pc/grade").attribute("dgid")),
            "deller": int(resp.child("IIDX26pc/deller").attribute("deller")),
            "expert_point": expert_point,
        }

    def verify_iidx26music_getrank(self, extid: int) -> Dict[int, Dict[int, Dict[str, int]]]:
        scores: Dict[int, Dict[int, Dict[str, int]]] = {}
        for cltype in [0, 1]:  # singles, doubles
            call = self.call_node()

            # Construct node
            IIDX26music = Node.void("IIDX26music")
            call.add_child(IIDX26music)
            IIDX26music.set_attribute("method", "getrank")
            IIDX26music.set_attribute("iidxid", str(extid))
            IIDX26music.set_attribute("cltype", str(cltype))

            # Swap with server
            resp = self.exchange("", call)

            self.assert_path(resp, "response/IIDX26music/style")
            if int(resp.child("IIDX26music/style").attribute("type")) != cltype:
                raise Exception("Returned wrong clear type for IIDX26music.getrank!")

            for child in resp.child("IIDX26music").children:
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

    def verify_iidx26pc_save(
        self,
        extid: int,
        card: str,
        lid: str,
        expert_point: Optional[Dict[str, int]] = None,
    ) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("s_disp_judge", "1")
        IIDX26pc.set_attribute("mode", "6")
        IIDX26pc.set_attribute("pmode", "0")
        IIDX26pc.set_attribute("method", "save")
        IIDX26pc.set_attribute("s_sorttype", "0")
        IIDX26pc.set_attribute("s_exscore", "0")
        IIDX26pc.set_attribute("d_notes", "0.000000")
        IIDX26pc.set_attribute("gpos", "0")
        IIDX26pc.set_attribute("s_gno", "8")
        IIDX26pc.set_attribute("s_hispeed", "5.771802")
        IIDX26pc.set_attribute("s_judge", "0")
        IIDX26pc.set_attribute("d_timing", "0")
        IIDX26pc.set_attribute("rtype", "0")
        IIDX26pc.set_attribute("d_graph_score", "0")
        IIDX26pc.set_attribute("d_lift", "60")
        IIDX26pc.set_attribute("s_pace", "0")
        IIDX26pc.set_attribute("d_exscore", "0")
        IIDX26pc.set_attribute("d_sdtype", "0")
        IIDX26pc.set_attribute("s_opstyle", "1")
        IIDX26pc.set_attribute("s_achi", "449")
        IIDX26pc.set_attribute("s_graph_score", "0")
        IIDX26pc.set_attribute("d_gno", "0")
        IIDX26pc.set_attribute("s_lift", "60")
        IIDX26pc.set_attribute("s_notes", "31.484070")
        IIDX26pc.set_attribute("d_tune", "0")
        IIDX26pc.set_attribute("d_sdlen", "0")
        IIDX26pc.set_attribute("d_achi", "4")
        IIDX26pc.set_attribute("d_opstyle", "0")
        IIDX26pc.set_attribute("sp_opt", "8208")
        IIDX26pc.set_attribute("iidxid", str(extid))
        IIDX26pc.set_attribute("lid", lid)
        IIDX26pc.set_attribute("s_judgeAdj", "0")
        IIDX26pc.set_attribute("s_tune", "3")
        IIDX26pc.set_attribute("s_sdtype", "1")
        IIDX26pc.set_attribute("s_gtype", "2")
        IIDX26pc.set_attribute("d_judge", "0")
        IIDX26pc.set_attribute("cid", card)
        IIDX26pc.set_attribute("cltype", "0")
        IIDX26pc.set_attribute("ctype", "1")
        IIDX26pc.set_attribute("bookkeep", "0")
        IIDX26pc.set_attribute("d_hispeed", "0.000000")
        IIDX26pc.set_attribute("d_pace", "0")
        IIDX26pc.set_attribute("d_judgeAdj", "0")
        IIDX26pc.set_attribute("s_timing", "1")
        IIDX26pc.set_attribute("d_disp_judge", "0")
        IIDX26pc.set_attribute("s_sdlen", "121")
        IIDX26pc.set_attribute("dp_opt2", "0")
        IIDX26pc.set_attribute("d_gtype", "0")
        IIDX26pc.set_attribute("d_sorttype", "0")
        IIDX26pc.set_attribute("dp_opt", "0")
        IIDX26pc.set_attribute("s_auto_scrach", "0")
        IIDX26pc.set_attribute("d_auto_scrach", "0")
        IIDX26pc.set_attribute("s_gauge_disp", "0")
        IIDX26pc.set_attribute("d_gauge_disp", "0")
        IIDX26pc.set_attribute("s_lane_brignt", "0")
        IIDX26pc.set_attribute("d_lane_brignt", "0")
        IIDX26pc.set_attribute("s_camera_layout", "0")
        IIDX26pc.set_attribute("d_camera_layout", "0")
        IIDX26pc.set_attribute("s_ghost_score", "0")
        IIDX26pc.set_attribute("d_ghost_score", "0")
        IIDX26pc.set_attribute("s_tsujigiri_disp", "0")
        IIDX26pc.set_attribute("d_tsujigiri_disp", "0")
        deller = Node.void("deller")
        IIDX26pc.add_child(deller)
        deller.set_attribute("deller", "150")

        if expert_point is not None:
            epnode = Node.void("expert_point")
            epnode.set_attribute("h_point", str(expert_point["h_point"]))
            epnode.set_attribute("course_id", str(expert_point["course_id"]))
            epnode.set_attribute("n_point", str(expert_point["n_point"]))
            epnode.set_attribute("a_point", str(expert_point["a_point"]))
            IIDX26pc.add_child(epnode)

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/IIDX26pc")

    def verify_iidx26music_reg(self, extid: int, lid: str, score: Dict[str, Any]) -> None:
        call = self.call_node()

        # Construct node
        IIDX26music = Node.void("IIDX26music")
        call.add_child(IIDX26music)
        IIDX26music.set_attribute("convid", "-1")
        IIDX26music.set_attribute("iidxid", str(extid))
        IIDX26music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX26music.set_attribute("pid", "51")
        IIDX26music.set_attribute("rankside", "1")
        IIDX26music.set_attribute("cflg", str(score["clear_status"]))
        IIDX26music.set_attribute("method", "reg")
        IIDX26music.set_attribute("gnum", str(score["gnum"]))
        IIDX26music.set_attribute("clid", str(score["chart"]))
        IIDX26music.set_attribute("mnum", str(score["mnum"]))
        IIDX26music.set_attribute("is_death", "0")
        IIDX26music.set_attribute("theory", "0")
        IIDX26music.set_attribute("dj_level", "1")
        IIDX26music.set_attribute("location_id", lid)
        IIDX26music.set_attribute("mid", str(score["id"]))
        IIDX26music.add_child(Node.binary("ghost", bytes([1] * 64)))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/IIDX26music/shopdata/@rank")
        self.assert_path(resp, "response/IIDX26music/ranklist/data")

    def verify_iidx26music_appoint(self, extid: int, musicid: int, chart: int) -> Tuple[int, bytes]:
        call = self.call_node()

        # Construct node
        IIDX26music = Node.void("IIDX26music")
        call.add_child(IIDX26music)
        IIDX26music.set_attribute("clid", str(chart))
        IIDX26music.set_attribute("method", "appoint")
        IIDX26music.set_attribute("ctype", "0")
        IIDX26music.set_attribute("iidxid", str(extid))
        IIDX26music.set_attribute("subtype", "")
        IIDX26music.set_attribute("mid", str(musicid))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/IIDX26music/mydata/@score")

        return (
            int(resp.child("IIDX26music/mydata").attribute("score")),
            resp.child_value("IIDX26music/mydata"),
        )

    def verify_iidx26pc_reg(self, ref_id: str, card_id: str, lid: str) -> int:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        call.add_child(IIDX26pc)
        IIDX26pc.set_attribute("lid", lid)
        IIDX26pc.set_attribute("pid", "51")
        IIDX26pc.set_attribute("method", "reg")
        IIDX26pc.set_attribute("cid", card_id)
        IIDX26pc.set_attribute("did", ref_id)
        IIDX26pc.set_attribute("rid", ref_id)
        IIDX26pc.set_attribute("name", self.NAME)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26pc/@id")
        self.assert_path(resp, "response/IIDX26pc/@id_str")

        return int(resp.child("IIDX26pc").attribute("id"))

    def verify_iidx26pc_playstart(self) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        IIDX26pc.set_attribute("method", "playstart")
        IIDX26pc.set_attribute("side", "1")
        call.add_child(IIDX26pc)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26pc")

    def verify_iidx26music_play(self, score: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        IIDX26music = Node.void("IIDX26music")
        IIDX26music.set_attribute("opt", "64")
        IIDX26music.set_attribute("clid", str(score["chart"]))
        IIDX26music.set_attribute("mid", str(score["id"]))
        IIDX26music.set_attribute("gnum", str(score["gnum"]))
        IIDX26music.set_attribute("cflg", str(score["clear_status"]))
        IIDX26music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX26music.set_attribute("pid", "51")
        IIDX26music.set_attribute("method", "play")
        call.add_child(IIDX26music)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26music/@clid")
        self.assert_path(resp, "response/IIDX26music/@crate")
        self.assert_path(resp, "response/IIDX26music/@frate")
        self.assert_path(resp, "response/IIDX26music/@mid")

    def verify_iidx26pc_playend(self, lid: str, shop_name: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26pc = Node.void("IIDX26pc")
        IIDX26pc.set_attribute("cltype", "0")
        IIDX26pc.set_attribute("bookkeep", "0")
        IIDX26pc.set_attribute("mode", "1")
        IIDX26pc.set_attribute("pay_coin", "1")
        IIDX26pc.set_attribute("method", "playend")
        IIDX26pc.set_attribute("company_code", "")
        IIDX26pc.set_attribute("consumer_code", "")
        IIDX26pc.set_attribute("location_name", shop_name)
        IIDX26pc.set_attribute("lid", lid)
        call.add_child(IIDX26pc)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26pc")

    def verify_iidx26music_breg(self, iidxid: int, score: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        IIDX26music = Node.void("IIDX26music")
        IIDX26music.set_attribute("gnum", str(score["gnum"]))
        IIDX26music.set_attribute("iidxid", str(iidxid))
        IIDX26music.set_attribute("mid", str(score["id"]))
        IIDX26music.set_attribute("method", "breg")
        IIDX26music.set_attribute("pgnum", str(score["pgnum"]))
        IIDX26music.set_attribute("cflg", str(score["clear_status"]))
        call.add_child(IIDX26music)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26music")

    def verify_iidx26grade_raised(self, iidxid: int, shop_name: str, dantype: str) -> None:
        call = self.call_node()

        # Construct node
        IIDX26grade = Node.void("IIDX26grade")
        IIDX26grade.set_attribute("opname", shop_name)
        IIDX26grade.set_attribute("is_mirror", "0")
        IIDX26grade.set_attribute("oppid", "51")
        IIDX26grade.set_attribute("achi", "50")
        IIDX26grade.set_attribute("cstage", "4")
        IIDX26grade.set_attribute("gid", "5")
        IIDX26grade.set_attribute("iidxid", str(iidxid))
        IIDX26grade.set_attribute("gtype", "0" if dantype == "sp" else "1")
        IIDX26grade.set_attribute("is_ex", "0")
        IIDX26grade.set_attribute("pside", "0")
        IIDX26grade.set_attribute("method", "raised")
        call.add_child(IIDX26grade)

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/IIDX26grade/@pnum")

    def verify_iidx26music_arenacpu(self) -> None:
        call = self.call_node()
        IIDX26music = Node.void("IIDX26music")
        call.add_child(IIDX26music)
        IIDX26music.set_attribute("method", "arenaCPU")
        music_list = Node.void("music_list")
        IIDX26music.add_child(music_list)
        music_list.add_child(Node.s32("index", 0))
        music_list.add_child(Node.s32("music_id", 26072))
        music_list.add_child(Node.s32("note_style", 0))
        music_list.add_child(Node.s32("note_grade", 2))
        music_list.add_child(Node.s32("total_notes", 1857))
        music_list_1 = Node.void("music_list")
        IIDX26music.add_child(music_list_1)
        music_list_1.add_child(Node.s32("index", 1))
        music_list_1.add_child(Node.s32("music_id", 25020))
        music_list_1.add_child(Node.s32("note_style", 0))
        music_list_1.add_child(Node.s32("note_grade", 0))
        music_list_1.add_child(Node.s32("total_notes", 483))
        music_list_2 = Node.void("music_list")
        IIDX26music.add_child(music_list_2)
        music_list_2.add_child(Node.s32("index", 2))
        music_list_2.add_child(Node.s32("music_id", 2000))
        music_list_2.add_child(Node.s32("note_style", 0))
        music_list_2.add_child(Node.s32("note_grade", 0))
        music_list_2.add_child(Node.s32("total_notes", 360))
        music_list_3 = Node.void("music_list")
        IIDX26music.add_child(music_list_3)
        music_list_3.add_child(Node.s32("index", 3))
        music_list_3.add_child(Node.s32("music_id", 19020))
        music_list_3.add_child(Node.s32("note_style", 0))
        music_list_3.add_child(Node.s32("note_grade", 0))
        music_list_3.add_child(Node.s32("total_notes", 404))
        cpu_list = Node.void("cpu_list")
        IIDX26music.add_child(cpu_list)
        cpu_list.add_child(Node.s32("index", 0))
        cpu_list.add_child(Node.s32("play_style", 0))
        cpu_list.add_child(Node.s32("arena_class", 0))
        cpu_list.add_child(Node.s32("grade_id", -1))
        cpu_list_1 = Node.void("cpu_list")
        IIDX26music.add_child(cpu_list_1)
        cpu_list_1.add_child(Node.s32("index", 1))
        cpu_list_1.add_child(Node.s32("play_style", 0))
        cpu_list_1.add_child(Node.s32("arena_class", 0))
        cpu_list_1.add_child(Node.s32("grade_id", 6))
        cpu_list_2 = Node.void("cpu_list")
        IIDX26music.add_child(cpu_list_2)
        cpu_list_2.add_child(Node.s32("index", 2))
        cpu_list_2.add_child(Node.s32("play_style", 0))
        cpu_list_2.add_child(Node.s32("arena_class", 0))
        cpu_list_2.add_child(Node.s32("grade_id", 6))
        cpu_list_3 = Node.void("cpu_list")
        IIDX26music.add_child(cpu_list_3)
        cpu_list_3.add_child(Node.s32("index", 3))
        cpu_list_3.add_child(Node.s32("play_style", 0))
        cpu_list_3.add_child(Node.s32("arena_class", 0))
        cpu_list_3.add_child(Node.s32("grade_id", 6))
        # Swap with server
        resp = self.exchange("", call)

        self.assert_path(resp, "response/IIDX26music/cpu_score_list/score_list/score")
        self.assert_path(resp, "response/IIDX26music/cpu_score_list/score_list/enable_score")
        self.assert_path(resp, "response/IIDX26music/cpu_score_list/score_list/ghost")
        self.assert_path(resp, "response/IIDX26music/cpu_score_list/score_list/enable_ghost")

    def verify_iidx26gamesystem_systeminfo(self, lid: str) -> None:
        call = self.call_node()
        IIDX26gameSystem = Node.void("IIDX26gameSystem")
        call.add_child(IIDX26gameSystem)
        IIDX26gameSystem.set_attribute("method", "systemInfo")
        IIDX26gameSystem.add_child(Node.s32("ver", 15))
        IIDX26gameSystem.add_child(Node.string("location_id", lid))

        # Swap with server
        resp = self.exchange("", call)

        self.assert_path(resp, "response/IIDX26gameSystem/arena_schedule/phase")

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
        self.verify_iidx26shop_getname(lid)
        self.verify_iidx26pc_common()
        self.verify_iidx26music_crate()
        self.verify_iidx26shop_getconvention(lid)
        self.verify_iidx26ranking_getranker(lid)
        self.verify_iidx26shop_sentinfo(lid, "newname1")
        self.verify_iidx26gamesystem_systeminfo(lid)
        self.verify_iidx26music_arenacpu()

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
            self.verify_iidx26pc_reg(ref_id, card, lid)
            self.verify_iidx26pc_get(ref_id, card, lid)
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
            profile = self.verify_iidx26pc_get(ref_id, card, lid)
            if profile["sp_dan"] != -1:
                raise Exception("Somehow has SP DAN ranking on new profile!")
            if profile["dp_dan"] != -1:
                raise Exception("Somehow has DP DAN ranking on new profile!")
            if profile["deller"] != 0:
                raise Exception("Somehow has deller on new profile!")
            if len(profile["expert_point"].keys()) > 0:
                raise Exception("Somehow has expert point data on new profile!")
            scores = self.verify_iidx26music_getrank(profile["extid"])
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
                    self.verify_iidx26music_reg(profile["extid"], lid, dummyscore)
                self.verify_iidx26pc_visit(profile["extid"], lid)
                self.verify_iidx26pc_save(profile["extid"], card, lid)
                scores = self.verify_iidx26music_getrank(profile["extid"])
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
                    ex_score, ghost = self.verify_iidx26music_appoint(profile["extid"], score["id"], score["chart"])
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

            # Verify that we can save/load expert points
            self.verify_iidx26pc_save(
                profile["extid"],
                card,
                lid,
                {"course_id": 1, "n_point": 0, "h_point": 500, "a_point": 0},
            )
            profile = self.verify_iidx26pc_get(ref_id, card, lid)
            if sorted(profile["expert_point"].keys()) != [1]:
                raise Exception("Got back wrong number of expert course points!")
            if profile["expert_point"][1] != {
                "n_point": 0,
                "h_point": 500,
                "a_point": 0,
            }:
                raise Exception("Got back wrong expert points after saving!")
            self.verify_iidx26pc_save(
                profile["extid"],
                card,
                lid,
                {"course_id": 1, "n_point": 0, "h_point": 1000, "a_point": 0},
            )
            profile = self.verify_iidx26pc_get(ref_id, card, lid)
            if sorted(profile["expert_point"].keys()) != [1]:
                raise Exception("Got back wrong number of expert course points!")
            if profile["expert_point"][1] != {
                "n_point": 0,
                "h_point": 1000,
                "a_point": 0,
            }:
                raise Exception("Got back wrong expert points after saving!")
            self.verify_iidx26pc_save(
                profile["extid"],
                card,
                lid,
                {"course_id": 2, "n_point": 0, "h_point": 0, "a_point": 500},
            )
            profile = self.verify_iidx26pc_get(ref_id, card, lid)
            if sorted(profile["expert_point"].keys()) != [1, 2]:
                raise Exception("Got back wrong number of expert course points!")
            if profile["expert_point"][1] != {
                "n_point": 0,
                "h_point": 1000,
                "a_point": 0,
            }:
                raise Exception("Got back wrong expert points after saving!")
            if profile["expert_point"][2] != {
                "n_point": 0,
                "h_point": 0,
                "a_point": 500,
            }:
                raise Exception("Got back wrong expert points after saving!")

            # Verify that a player without a card can play
            self.verify_iidx26pc_playstart()
            self.verify_iidx26music_play(
                {
                    "id": 1000,
                    "chart": 2,
                    "clear_status": 4,
                    "pgnum": 123,
                    "gnum": 123,
                }
            )
            self.verify_iidx26pc_playend(lid, "newname1")

            # Verify shop name change setting
            self.verify_iidx26shop_savename(lid, "newname1")
            newname = self.verify_iidx26shop_getname(lid)
            if newname != "newname1":
                raise Exception("Invalid shop name returned after change!")
            self.verify_iidx26shop_savename(lid, "newname2")
            newname = self.verify_iidx26shop_getname(lid)
            if newname != "newname2":
                raise Exception("Invalid shop name returned after change!")

            # Verify beginner score saving
            self.verify_iidx26music_breg(
                profile["extid"],
                {
                    "id": 1000,
                    "clear_status": 4,
                    "pgnum": 123,
                    "gnum": 123,
                },
            )
            scores = self.verify_iidx26music_getrank(profile["extid"])
            if 1000 not in scores:
                raise Exception(f"Didn't get expected scores back for song {1000} beginner chart!")
            if 6 not in scores[1000]:
                raise Exception(f"Didn't get beginner score back for song {1000}!")
            if scores[1000][6] != {"clear_status": 4, "ex_score": -1, "miss_count": -1}:
                raise Exception("Didn't get correct status back from beginner save!")

            # Verify DAN score saving and loading
            self.verify_iidx26grade_raised(profile["extid"], newname, "sp")
            self.verify_iidx26grade_raised(profile["extid"], newname, "dp")
            profile = self.verify_iidx26pc_get(ref_id, card, lid)
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
