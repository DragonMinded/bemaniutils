import random
import time
from typing import Any, Dict, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class PopnMusicUsaNekoClient(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_pcb24_boot(self, loc: str) -> None:
        call = self.call_node()

        # Construct node
        pcb24 = Node.void("pcb24")
        call.add_child(pcb24)
        pcb24.set_attribute("method", "boot")
        pcb24.add_child(Node.string("loc_id", loc))
        pcb24.add_child(Node.u8("loc_type", 0))
        pcb24.add_child(Node.string("loc_name", ""))
        pcb24.add_child(Node.string("country", "US"))
        pcb24.add_child(Node.string("region", "."))
        pcb24.add_child(Node.s16("pref", 51))
        pcb24.add_child(Node.string("customer", ""))
        pcb24.add_child(Node.string("company", ""))
        pcb24.add_child(Node.ipv4("gip", "127.0.0.1"))
        pcb24.add_child(Node.u16("gp", 10011))
        pcb24.add_child(Node.string("rom_number", "M39-JB-G01"))
        pcb24.add_child(Node.u64("c_drive", 10028228608))
        pcb24.add_child(Node.u64("d_drive", 47945170944))
        pcb24.add_child(Node.u64("e_drive", 10394677248))
        pcb24.add_child(Node.string("etc", ""))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcb24/@status")

    def __verify_common(self, root: str, resp: Node) -> None:
        self.assert_path(resp, f"response/{root}/phase/event_id")
        self.assert_path(resp, f"response/{root}/phase/phase")

        # Area stuff is only necessary if navikun event is active.
        # self.assert_path(resp, f"response/{root}/area/area_id")
        # self.assert_path(resp, f"response/{root}/area/end_date")
        # self.assert_path(resp, f"response/{root}/area/medal_id")
        # self.assert_path(resp, f"response/{root}/area/is_limit")

        self.assert_path(resp, f"response/{root}/choco/choco_id")
        self.assert_path(resp, f"response/{root}/choco/param")
        self.assert_path(resp, f"response/{root}/goods/item_id")
        self.assert_path(resp, f"response/{root}/goods/item_type")
        self.assert_path(resp, f"response/{root}/goods/price")
        self.assert_path(resp, f"response/{root}/goods/goods_type")

    def verify_info24_common(self, loc: str) -> None:
        call = self.call_node()

        # Construct node
        info24 = Node.void("info24")
        call.add_child(info24)
        info24.set_attribute("loc_id", loc)
        info24.set_attribute("method", "common")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.__verify_common("info24", resp)

    def verify_lobby24_getlist(self, loc: str) -> None:
        call = self.call_node()

        # Construct node
        lobby24 = Node.void("lobby24")
        call.add_child(lobby24)
        lobby24.set_attribute("method", "getList")
        lobby24.add_child(Node.string("location_id", loc))
        lobby24.add_child(Node.u8("net_version", 63))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/lobby24/@status")

    def __verify_profile(self, resp: Node) -> None:
        self.assert_path(resp, "response/player24/account/name")
        self.assert_path(resp, "response/player24/account/g_pm_id")
        self.assert_path(resp, "response/player24/account/tutorial")
        self.assert_path(resp, "response/player24/account/area_id")
        self.assert_path(resp, "response/player24/account/use_navi")
        self.assert_path(resp, "response/player24/account/read_news")
        self.assert_path(resp, "response/player24/account/nice")
        self.assert_path(resp, "response/player24/account/favorite_chara")
        self.assert_path(resp, "response/player24/account/special_area")
        self.assert_path(resp, "response/player24/account/chocolate_charalist")
        self.assert_path(resp, "response/player24/account/chocolate_sp_chara")
        self.assert_path(resp, "response/player24/account/chocolate_pass_cnt")
        self.assert_path(resp, "response/player24/account/chocolate_hon_cnt")
        self.assert_path(resp, "response/player24/account/teacher_setting")
        self.assert_path(resp, "response/player24/account/welcom_pack")
        self.assert_path(resp, "response/player24/account/ranking_node")
        self.assert_path(resp, "response/player24/account/chara_ranking_kind_id")
        self.assert_path(resp, "response/player24/account/navi_evolution_flg")
        self.assert_path(resp, "response/player24/account/ranking_news_last_no")
        self.assert_path(resp, "response/player24/account/power_point")
        self.assert_path(resp, "response/player24/account/player_point")
        self.assert_path(resp, "response/player24/account/power_point_list")
        self.assert_path(resp, "response/player24/account/staff")
        self.assert_path(resp, "response/player24/account/item_type")
        self.assert_path(resp, "response/player24/account/item_id")
        self.assert_path(resp, "response/player24/account/is_conv")
        self.assert_path(resp, "response/player24/account/license_data")
        self.assert_path(resp, "response/player24/account/my_best")
        self.assert_path(resp, "response/player24/account/latest_music")
        self.assert_path(resp, "response/player24/account/total_play_cnt")
        self.assert_path(resp, "response/player24/account/today_play_cnt")
        self.assert_path(resp, "response/player24/account/consecutive_days")
        self.assert_path(resp, "response/player24/account/total_days")
        self.assert_path(resp, "response/player24/account/interval_day")
        self.assert_path(resp, "response/player24/account/active_fr_num")
        self.assert_path(resp, "response/player24/eaappli/relation")
        self.assert_path(resp, "response/player24/info/ep")
        self.assert_path(resp, "response/player24/config")
        self.assert_path(resp, "response/player24/option")
        self.assert_path(resp, "response/player24/custom_cate")
        self.assert_path(resp, "response/player24/navi_data")
        self.assert_path(resp, "response/player24/mission/mission_id")
        self.assert_path(resp, "response/player24/mission/gauge_point")
        self.assert_path(resp, "response/player24/mission/mission_comp")
        self.assert_path(resp, "response/player24/netvs")
        self.assert_path(resp, "response/player24/customize")
        self.assert_path(resp, "response/player24/stamp/stamp_id")
        self.assert_path(resp, "response/player24/stamp/cnt")

    def verify_player24_read(self, ref_id: str, msg_type: str) -> Dict[str, Dict[int, Dict[str, int]]]:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "read")

        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.s8("pref", 51))

        # Swap with server
        resp = self.exchange("", call)

        if msg_type == "new":
            # Verify that response is correct
            self.assert_path(resp, "response/player24/result")
            status = resp.child_value("player24/result")
            if status != 2:
                raise Exception(f"Reference ID '{ref_id}' returned invalid status '{status}'")

            return {
                "items": {},
                "characters": {},
                "points": {},
            }
        elif msg_type == "query":
            # Verify that the response is correct
            self.__verify_profile(resp)

            self.assert_path(resp, "response/player24/result")
            status = resp.child_value("player24/result")
            if status != 0:
                raise Exception(f"Reference ID '{ref_id}' returned invalid status '{status}'")
            name = resp.child_value("player24/account/name")
            if name != self.NAME:
                raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

            # Medals and items
            items: Dict[int, Dict[str, int]] = {}
            charas: Dict[int, Dict[str, int]] = {}
            courses: Dict[int, Dict[str, int]] = {}
            for obj in resp.child("player24").children:
                if obj.name == "item":
                    items[obj.child_value("id")] = {
                        "type": obj.child_value("type"),
                        "param": obj.child_value("param"),
                    }
                elif obj.name == "chara_param":
                    charas[obj.child_value("chara_id")] = {
                        "friendship": obj.child_value("friendship"),
                    }
                elif obj.name == "course_data":
                    courses[obj.child_value("course_id")] = {
                        "clear_type": obj.child_value("clear_type"),
                        "clear_rank": obj.child_value("clear_rank"),
                        "total_score": obj.child_value("total_score"),
                        "count": obj.child_value("update_count"),
                        "sheet_num": obj.child_value("sheet_num"),
                    }

            return {
                "items": items,
                "characters": charas,
                "courses": courses,
                "points": {0: {"points": resp.child_value("player24/account/player_point")}},
            }
        else:
            raise Exception(f"Unrecognized message type '{msg_type}'")

    def verify_player24_read_score(self, ref_id: str) -> Dict[str, Dict[int, Dict[int, int]]]:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "read_score")

        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.s8("pref", 51))

        # Swap with server
        resp = self.exchange("", call)

        # Verify defaults
        self.assert_path(resp, "response/player24/@status")

        # Grab scores
        scores: Dict[int, Dict[int, int]] = {}
        medals: Dict[int, Dict[int, int]] = {}
        ranks: Dict[int, Dict[int, int]] = {}
        for child in resp.child("player24").children:
            if child.name != "music":
                continue

            musicid = child.child_value("music_num")
            chart = child.child_value("sheet_num")
            score = child.child_value("score")
            medal = child.child_value("clear_type")
            rank = child.child_value("clear_rank")

            if musicid not in scores:
                scores[musicid] = {}
            if musicid not in medals:
                medals[musicid] = {}
            if musicid not in ranks:
                ranks[musicid] = {}

            scores[musicid][chart] = score
            medals[musicid][chart] = medal
            ranks[musicid][chart] = rank

        return {
            "scores": scores,
            "medals": medals,
            "ranks": ranks,
        }

    def verify_player24_start(self, ref_id: str, loc: str) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("loc_id", loc)
        player24.set_attribute("ref_id", ref_id)
        player24.set_attribute("method", "start")
        player24.set_attribute("start_type", "0")
        pcb_card = Node.void("pcb_card")
        player24.add_child(pcb_card)
        pcb_card.add_child(Node.s8("card_enable", 1))
        pcb_card.add_child(Node.s8("card_soldout", 0))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.__verify_common("player24", resp)

    def verify_player24_update_ranking(self, ref_id: str, loc: str) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "update_ranking")
        player24.add_child(Node.s16("pref", 51))
        player24.add_child(Node.string("location_id", loc))
        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.string("name", self.NAME))
        player24.add_child(Node.s16("chara_num", 1))
        player24.add_child(Node.s16("course_id", 12345))
        player24.add_child(Node.s32("total_score", 86000))
        player24.add_child(Node.s16("music_num", 1375))
        player24.add_child(Node.u8("sheet_num", 2))
        player24.add_child(Node.u8("clear_type", 7))
        player24.add_child(Node.u8("clear_rank", 5))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player24/all_ranking/name")
        self.assert_path(resp, "response/player24/all_ranking/chara_num")
        self.assert_path(resp, "response/player24/all_ranking/total_score")
        self.assert_path(resp, "response/player24/all_ranking/clear_type")
        self.assert_path(resp, "response/player24/all_ranking/clear_rank")
        self.assert_path(resp, "response/player24/all_ranking/player_count")
        self.assert_path(resp, "response/player24/all_ranking/player_rank")

    def verify_player24_logout(self, ref_id: str) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("ref_id", ref_id)
        player24.set_attribute("method", "logout")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/player24/@status")

    def verify_player24_write(
        self,
        ref_id: str,
        item: Optional[Dict[str, int]] = None,
        character: Optional[Dict[str, int]] = None,
    ) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "write")
        player24.add_child(Node.string("ref_id", ref_id))

        # Add required children
        config = Node.void("config")
        player24.add_child(config)
        config.add_child(Node.s16("chara", 1543))

        if item is not None:
            itemnode = Node.void("item")
            player24.add_child(itemnode)
            itemnode.add_child(Node.u8("type", item["type"]))
            itemnode.add_child(Node.u16("id", item["id"]))
            itemnode.add_child(Node.u16("param", item["param"]))
            itemnode.add_child(Node.bool("is_new", False))
            itemnode.add_child(Node.u64("get_time", 0))

        if character is not None:
            chara_param = Node.void("chara_param")
            player24.add_child(chara_param)
            chara_param.add_child(Node.u16("chara_id", character["id"]))
            chara_param.add_child(Node.u16("friendship", character["friendship"]))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player24/@status")

    def verify_player24_buy(self, ref_id: str, item: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "buy")
        player24.add_child(Node.s32("play_id", 0))
        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.u16("id", item["id"]))
        player24.add_child(Node.u8("type", item["type"]))
        player24.add_child(Node.u16("param", item["param"]))
        player24.add_child(Node.s32("lumina", item["points"]))
        player24.add_child(Node.u16("price", item["price"]))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player24/@status")

    def verify_player24_write_music(self, ref_id: str, score: Dict[str, Any]) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "write_music")
        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.string("data_id", ref_id))
        player24.add_child(Node.string("name", self.NAME))
        player24.add_child(Node.u8("stage", 0))
        player24.add_child(Node.s16("music_num", score["id"]))
        player24.add_child(Node.u8("sheet_num", score["chart"]))
        player24.add_child(Node.u8("clear_type", score["medal"]))
        player24.add_child(Node.s32("score", score["score"]))
        player24.add_child(Node.s16("combo", 0))
        player24.add_child(Node.s16("cool", 0))
        player24.add_child(Node.s16("great", 0))
        player24.add_child(Node.s16("good", 0))
        player24.add_child(Node.s16("bad", 0))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player24/@status")

    def verify_player24_new(self, ref_id: str) -> None:
        call = self.call_node()

        # Construct node
        player24 = Node.void("player24")
        call.add_child(player24)
        player24.set_attribute("method", "new")

        player24.add_child(Node.string("ref_id", ref_id))
        player24.add_child(Node.string("name", self.NAME))
        player24.add_child(Node.s8("pref", 51))

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes
        self.__verify_profile(resp)

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
        self.verify_pcb24_boot(location)
        self.verify_info24_common(location)
        self.verify_lobby24_getlist(location)

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
            self.verify_player24_read(ref_id, msg_type="new")
            self.verify_player24_new(ref_id)
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        # Verify proper handling of basic stuff
        self.verify_player24_read(ref_id, msg_type="query")
        self.verify_player24_start(ref_id, location)
        self.verify_player24_write(ref_id)
        self.verify_player24_logout(ref_id)

        if cardid is None:
            # Verify unlocks/story mode work
            unlocks = self.verify_player24_read(ref_id, msg_type="query")
            for item in unlocks["items"]:
                if item in [1592, 1608]:
                    # Song unlocks after one play
                    continue
                raise Exception("Got nonzero items count on a new card!")
            for _ in unlocks["characters"]:
                raise Exception("Got nonzero characters count on a new card!")
            for _ in unlocks["courses"]:
                raise Exception("Got nonzero course count on a new card!")
            if unlocks["points"][0]["points"] != 300:
                raise Exception("Got wrong default value for points on a new card!")

            self.verify_player24_write(ref_id, item={"id": 4, "type": 2, "param": 69})
            unlocks = self.verify_player24_read(ref_id, msg_type="query")
            if 4 not in unlocks["items"]:
                raise Exception("Expecting to see item ID 4 in items!")
            if unlocks["items"][4]["type"] != 2:
                raise Exception("Expecting to see item ID 4 to have type 2 in items!")
            if unlocks["items"][4]["param"] != 69:
                raise Exception("Expecting to see item ID 4 to have param 69 in items!")

            self.verify_player24_write(ref_id, character={"id": 5, "friendship": 420})
            unlocks = self.verify_player24_read(ref_id, msg_type="query")
            if 5 not in unlocks["characters"]:
                raise Exception("Expecting to see chara ID 5 in characters!")
            if unlocks["characters"][5]["friendship"] != 420:
                raise Exception("Expecting to see chara ID 5 to have type 2 in characters!")

            # Verify purchases work
            self.verify_player24_buy(
                ref_id,
                item={"id": 6, "type": 3, "param": 8, "points": 400, "price": 250},
            )
            unlocks = self.verify_player24_read(ref_id, msg_type="query")
            if 6 not in unlocks["items"]:
                raise Exception("Expecting to see item ID 6 in items!")
            if unlocks["items"][6]["type"] != 3:
                raise Exception("Expecting to see item ID 6 to have type 3 in items!")
            if unlocks["items"][6]["param"] != 8:
                raise Exception("Expecting to see item ID 6 to have param 8 in items!")
            if unlocks["points"][0]["points"] != 150:
                raise Exception(f'Got wrong value for points {unlocks["points"][0]["points"]} after purchase!')

            # Verify course handling
            self.verify_player24_update_ranking(ref_id, location)
            unlocks = self.verify_player24_read(ref_id, msg_type="query")
            if 12345 not in unlocks["courses"]:
                raise Exception("Expecting to see course ID 12345 in courses!")
            if unlocks["courses"][12345]["clear_type"] != 7:
                raise Exception("Expecting to see item ID 12345 to have clear_type 7 in courses!")
            if unlocks["courses"][12345]["clear_rank"] != 5:
                raise Exception("Expecting to see item ID 12345 to have clear_rank 5 in courses!")
            if unlocks["courses"][12345]["total_score"] != 86000:
                raise Exception("Expecting to see item ID 12345 to have total_score 86000 in courses!")
            if unlocks["courses"][12345]["count"] != 1:
                raise Exception("Expecting to see item ID 12345 to have count 1 in courses!")
            if unlocks["courses"][12345]["sheet_num"] != 2:
                raise Exception("Expecting to see item ID 12345 to have sheet_num 2 in courses!")

            # Verify score handling
            scores = self.verify_player24_read_score(ref_id)
            for _ in scores["medals"]:
                raise Exception("Got nonzero medals count on a new card!")
            for _ in scores["scores"]:
                raise Exception("Got nonzero scores count on a new card!")

            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 987,
                            "chart": 2,
                            "medal": 5,
                            "score": 76543,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 987,
                            "chart": 0,
                            "medal": 6,
                            "score": 99999,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 741,
                            "chart": 3,
                            "medal": 2,
                            "score": 45000,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 742,
                            "chart": 1,
                            "medal": 2,
                            "score": 1,
                        },
                    ]
                    # Random score to add in
                    songid = random.randint(907, 950)
                    chartid = random.randint(0, 3)
                    score = random.randint(0, 100000)
                    medal = random.randint(1, 11)
                    dummyscores.append(
                        {
                            "id": songid,
                            "chart": chartid,
                            "medal": medal,
                            "score": score,
                        }
                    )
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 987,
                            "chart": 2,
                            "medal": 6,
                            "score": 98765,
                        },
                        # A worse score on another same chart
                        {
                            "id": 987,
                            "chart": 0,
                            "medal": 3,
                            "score": 12345,
                            "expected_score": 99999,
                            "expected_medal": 6,
                        },
                    ]

                for dummyscore in dummyscores:
                    self.verify_player24_write_music(ref_id, dummyscore)
                scores = self.verify_player24_read_score(ref_id)
                for expected in dummyscores:
                    newscore = scores["scores"][expected["id"]][expected["chart"]]
                    newmedal = scores["medals"][expected["id"]][expected["chart"]]
                    newrank = scores["ranks"][expected["id"]][expected["chart"]]

                    if "expected_score" in expected:
                        expected_score = expected["expected_score"]
                    else:
                        expected_score = expected["score"]
                    if "expected_medal" in expected:
                        expected_medal = expected["expected_medal"]
                    else:
                        expected_medal = expected["medal"]

                    if newscore < 50000:
                        expected_rank = 1
                    elif newscore < 62000:
                        expected_rank = 2
                    elif newscore < 72000:
                        expected_rank = 3
                    elif newscore < 82000:
                        expected_rank = 4
                    elif newscore < 90000:
                        expected_rank = 5
                    elif newscore < 95000:
                        expected_rank = 6
                    elif newscore < 98000:
                        expected_rank = 7
                    else:
                        expected_rank = 8

                    if newscore != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got score \'{newscore}\''
                        )
                    if newmedal != expected_medal:
                        raise Exception(
                            f'Expected a medal of \'{expected_medal}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got medal \'{newmedal}\''
                        )
                    if newrank != expected_rank:
                        raise Exception(
                            f'Expected a rank of \'{expected_rank}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got rank \'{newrank}\''
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
