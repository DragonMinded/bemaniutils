import random
import time
from typing import Optional, Dict, List, Tuple, Any

from bemani.client.base import BaseClient
from bemani.protocol import Node


class PopnMusicSunnyParkClient(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_game_active(self) -> None:
        call = self.call_node()

        # Construct node
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "active")

        # Add minimum amount of stuff so server accepts
        game.add_child(Node.s8("event", 0))

        # Swap with server
        resp = self.exchange("pnm20/game", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@status")

    def verify_game_get(self) -> None:
        call = self.call_node()

        # Construct node
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("location_id", "JP-1")
        game.set_attribute("method", "get")
        game.add_child(Node.s8("event", 0))

        # Swap with server
        resp = self.exchange("pnm20/game", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

        for name in [
            "ir_phase",
            "music_open_phase",
            "collabo_phase",
            "personal_event_phase",
            "shop_event_phase",
            "netvs_phase",
            "card_phase",
            "other_phase",
            "local_matching_enable",
            "n_matching_sec",
            "l_matching_sec",
            "is_check_cpu",
            "week_no",
        ]:
            node = resp.child("game").child(name)

            if node is None:
                raise Exception(f"Missing node '{name}' in response!")
            if node.data_type != "s32":
                raise Exception(f"Node '{name}' has wrong data type!")

        sel_ranking = resp.child("game").child("sel_ranking")
        up_ranking = resp.child("game").child("up_ranking")

        for nodepair in [("sel_ranking", sel_ranking), ("up_ranking", up_ranking)]:
            name = nodepair[0]
            node = nodepair[1]

            if node is None:
                raise Exception(f"Missing node '{name}' in response!")
            if node.data_type != "s16":
                raise Exception(f"Node '{name}' has wrong data type!")
            if not node.is_array:
                raise Exception(f"Node '{name}' is not array!")
            if len(node.value) != 5:
                raise Exception(f"Node '{name}' is wrong array length!")

    def verify_playerdata_get(
        self, ref_id: str, msg_type: str
    ) -> Optional[Dict[str, Any]]:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "get")
        if msg_type == "new":
            playerdata.set_attribute(
                "model", self.config["old_profile_model"].split(":")[0]
            )

        playerdata.add_child(Node.string("ref_id", ref_id))
        playerdata.add_child(Node.string("shop_name", ""))
        playerdata.add_child(Node.s8("pref", 51))
        if msg_type == "new":
            playerdata.add_child(Node.s32("ir_num", 0))
        elif msg_type == "query":
            playerdata.add_child(Node.s32("gakuen", 2))
            playerdata.add_child(Node.s32("zoo", 1))
            playerdata.add_child(Node.s32("floor_infection", 1))
            playerdata.add_child(Node.s32("triple_journey", 1))
            playerdata.add_child(Node.s32("baseball", 1))

        # Swap with server
        resp = self.exchange("pnm20/playerdata", call)

        if msg_type == "new":
            # Verify that response is correct
            self.assert_path(resp, "response/playerdata/@status")

            status = int(resp.child("playerdata").attribute("status"))
            if status != 109:
                raise Exception(
                    f"Reference ID '{ref_id}' returned invalid status '{status}'"
                )

            # No score data
            return None
        elif msg_type == "query":
            # Verify that the response is correct
            self.assert_path(resp, "response/playerdata/base/name")
            self.assert_path(resp, "response/playerdata/base/g_pm_id")
            self.assert_path(resp, "response/playerdata/base/my_best")
            self.assert_path(resp, "response/playerdata/base/latest_music")
            self.assert_path(resp, "response/playerdata/avatar")
            self.assert_path(resp, "response/playerdata/avatar_add")
            self.assert_path(resp, "response/playerdata/netvs")
            self.assert_path(resp, "response/playerdata/sp_data")
            self.assert_path(resp, "response/playerdata/hiscore")

            name = resp.child("playerdata").child("base").child("name").value
            if name != self.NAME:
                raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

            # Extract and return score data
            self.assert_path(resp, "response/playerdata/base/clear_medal")

            def transform_medals(medal: int) -> Tuple[int, int, int, int]:
                return (
                    (medal >> 0) & 0xF,
                    (medal >> 4) & 0xF,
                    (medal >> 8) & 0xF,
                    (medal >> 12) & 0xF,
                )

            medals = [
                transform_medals(medal)
                for medal in resp.child("playerdata")
                .child("base")
                .child("clear_medal")
                .value
            ]

            hiscore = resp.child("playerdata").child("hiscore").value
            hiscores = []
            for i in range(0, len(hiscore) * 8, 17):
                byte_offset = int(i / 8)
                bit_offset = int(i % 8)

                value = hiscore[byte_offset]
                value = value + (hiscore[byte_offset + 1] << 8)
                value = value + (hiscore[byte_offset + 2] << 16)

                value = value >> bit_offset
                hiscores.append(value & 0x1FFFF)

            scores = [
                (hiscores[x], hiscores[x + 1], hiscores[x + 2], hiscores[x + 3])
                for x in range(0, len(hiscores), 4)
            ]

            return {"medals": medals, "scores": scores}

        else:
            raise Exception(f"Unrecognized message type '{msg_type}'")

    def verify_playerdata_set(self, ref_id: str, scores: List[Dict[str, Any]]) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "set")
        playerdata.set_attribute("ref_id", ref_id)
        playerdata.set_attribute("shop_name", "")

        # Add required children
        playerdata.add_child(Node.s16("chara", 1543))

        # Add requested scores
        for score in scores:
            stage = Node.void("stage")
            playerdata.add_child(stage)
            stage.add_child(Node.s16("no", score["id"]))
            stage.add_child(Node.u8("sheet", score["chart"]))
            stage.add_child(
                Node.u16("n_data", (score["medal"] << (4 * score["chart"])))
            )
            stage.add_child(Node.s32("score", score["score"]))

        # Swap with server
        resp = self.exchange("pnm20/playerdata", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/playerdata/name")

        name = resp.child("playerdata").child("name").value
        if name != self.NAME:
            raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

    def verify_playerdata_new(self, ref_id: str) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "new")

        playerdata.add_child(Node.string("ref_id", ref_id))
        playerdata.add_child(Node.string("name", self.NAME))
        playerdata.add_child(Node.string("shop_name", ""))
        playerdata.add_child(Node.s8("pref", 51))
        playerdata.add_child(Node.s8("gakuen", 2))
        playerdata.add_child(Node.s8("zoo", 1))
        playerdata.add_child(Node.s8("floor_infection", 1))
        playerdata.add_child(Node.s8("triple_journey", 1))
        playerdata.add_child(Node.s8("baseball", 1))

        # Swap with server
        resp = self.exchange("pnm20/playerdata", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/playerdata/base")

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
        self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_game_active()
        self.verify_game_get()

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
            self.verify_playerdata_get(ref_id, msg_type="new")
            self.verify_playerdata_new(ref_id)
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

        if cardid is None:
            # Verify score handling
            scores = self.verify_playerdata_get(ref_id, msg_type="query")
            if scores is None:
                raise Exception("Expected to get scores back, didn't get anything!")
            for medal in scores["medals"]:
                for i in range(4):
                    if medal[i] != 0:
                        raise Exception("Got nonzero medals count on a new card!")
            for score in scores["scores"]:
                for i in range(4):
                    if score[i] != 0:
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
                    medal = random.choice([1, 2, 3, 5, 6, 7, 9, 10, 11, 15])
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
                            "medal": 5,
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

                self.verify_playerdata_set(ref_id, dummyscores)
                scores = self.verify_playerdata_get(ref_id, msg_type="query")
                for score in dummyscores:
                    newscore = scores["scores"][score["id"]][score["chart"]]
                    newmedal = scores["medals"][score["id"]][score["chart"]]

                    if "expected_score" in score:
                        expected_score = score["expected_score"]
                    else:
                        expected_score = score["score"]
                    if "expected_medal" in score:
                        expected_medal = score["expected_medal"]
                    else:
                        expected_medal = score["medal"]

                    if newscore != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got score \'{newscore}\''
                        )
                    if newmedal != expected_medal:
                        raise Exception(
                            f'Expected a medal of \'{expected_medal}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got medal \'{newmedal}\''
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
