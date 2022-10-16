import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class PopnMusicLapistoriaClient(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_pcb22_boot(self) -> None:
        call = self.call_node()

        # Construct node
        pcb22 = Node.void("pcb22")
        call.add_child(pcb22)
        pcb22.set_attribute("method", "boot")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/pcb22/@status")

    def verify_info22_common(self) -> None:
        call = self.call_node()

        # Construct node
        info22 = Node.void("info22")
        call.add_child(info22)
        info22.set_attribute("loc_id", "JP-1")
        info22.set_attribute("method", "common")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/info22")

        for name in [
            "phase",
            "story",
        ]:
            node = resp.child("info22").child(name)

            if node is None:
                raise Exception(f"Missing node '{name}' in response!")
            if node.data_type != "void":
                raise Exception(f"Node '{name}' has wrong data type!")

    def verify_player22_read(
        self, ref_id: str, msg_type: str
    ) -> Optional[Dict[str, Any]]:
        call = self.call_node()

        # Construct node
        player22 = Node.void("player22")
        call.add_child(player22)
        player22.set_attribute("method", "read")

        player22.add_child(Node.string("ref_id", value=ref_id))
        player22.add_child(Node.string("shop_name", ""))
        player22.add_child(Node.s8("pref", 51))

        # Swap with server
        resp = self.exchange("", call)

        if msg_type == "new":
            # Verify that response is correct
            self.assert_path(resp, "response/player22/@status")

            status = int(resp.child("player22").attribute("status"))
            if status != 109:
                raise Exception(
                    f"Reference ID '{ref_id}' returned invalid status '{status}'"
                )

            # No score data
            return None
        elif msg_type == "query":
            # Verify that the response is correct
            self.assert_path(resp, "response/player22/account/name")
            self.assert_path(resp, "response/player22/account/g_pm_id")
            self.assert_path(resp, "response/player22/account/my_best")
            self.assert_path(resp, "response/player22/account/latest_music")
            self.assert_path(resp, "response/player22/netvs")
            self.assert_path(resp, "response/player22/config")
            self.assert_path(resp, "response/player22/option")
            self.assert_path(resp, "response/player22/info")
            self.assert_path(resp, "response/player22/custom_cate")
            self.assert_path(resp, "response/player22/customize")

            name = resp.child("player22").child("account").child("name").value
            if name != self.NAME:
                raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

            # Extract and return score data
            medals: Dict[int, List[int]] = {}
            scores: Dict[int, List[int]] = {}
            courses: Dict[int, Dict[str, int]] = {}
            for child in resp.child("player22").children:
                if child.name == "music":
                    songid = child.child_value("music_num")
                    chart = child.child_value("sheet_num")
                    medal = child.child_value("clear_type")
                    points = child.child_value("score")

                    if songid not in medals:
                        medals[songid] = [0, 0, 0, 0]
                    medals[songid][chart] = medal
                    if songid not in scores:
                        scores[songid] = [0, 0, 0, 0]
                    scores[songid][chart] = points

                if child.name == "course":
                    courseid = child.child_value("course_id")
                    medal = child.child_value("clear_medal")
                    combo = child.child_value("max_cmbo")
                    stage1 = child.child_value("stage1_score")
                    stage2 = child.child_value("stage2_score")
                    stage3 = child.child_value("stage3_score")
                    stage4 = child.child_value("stage4_score")
                    total = child.child_value("total_score")
                    courses[courseid] = {
                        "id": courseid,
                        "medal": medal,
                        "combo": combo,
                        "stage1": stage1,
                        "stage2": stage2,
                        "stage3": stage3,
                        "stage4": stage4,
                        "total": total,
                    }

            return {"medals": medals, "scores": scores, "courses": courses}

        else:
            raise Exception(f"Unrecognized message type '{msg_type}'")

    def verify_player22_write(self, ref_id: str, scores: List[Dict[str, Any]]) -> None:
        call = self.call_node()

        # Construct node
        player22 = Node.void("player22")
        call.add_child(player22)
        player22.set_attribute("method", "write")
        player22.add_child(Node.string("ref_id", value=ref_id))

        # Add required children
        config = Node.void("config")
        player22.add_child(config)
        config.add_child(Node.s16("chara", value=1543))

        # Add requested scores
        for score in scores:
            stage = Node.void("stage")
            player22.add_child(stage)
            stage.add_child(Node.s16("no", score["id"]))
            stage.add_child(Node.u8("sheet", score["chart"]))
            stage.add_child(Node.u16("clearmedal", score["medal"]))
            stage.add_child(Node.s32("nscore", score["score"]))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player22/@status")

    def verify_player22_write_music(self, ref_id: str, score: Dict[str, Any]) -> None:
        call = self.call_node()

        # Construct node
        player22 = Node.void("player22")
        call.add_child(player22)
        player22.set_attribute("method", "write_music")
        player22.add_child(Node.string("ref_id", ref_id))
        player22.add_child(Node.string("name", self.NAME))
        player22.add_child(Node.u8("stage", 0))
        player22.add_child(Node.s16("music_num", score["id"]))
        player22.add_child(Node.u8("sheet_num", score["chart"]))
        player22.add_child(Node.u8("clearmedal", score["medal"]))
        player22.add_child(Node.s32("score", score["score"]))
        player22.add_child(Node.s16("combo", 0))
        player22.add_child(Node.s16("cool", 0))
        player22.add_child(Node.s16("great", 0))
        player22.add_child(Node.s16("good", 0))
        player22.add_child(Node.s16("bad", 0))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player22/@status")

    def verify_player22_write_course(self, ref_id: str, course: Dict[str, int]) -> None:
        call = self.call_node()

        # Construct node
        player22 = Node.void("player22")
        call.add_child(player22)
        player22.set_attribute("method", "write_course")
        player22.add_child(Node.s16("pref", 51))
        player22.add_child(Node.string("location_id", "JP-1"))
        player22.add_child(Node.string("ref_id", ref_id))
        player22.add_child(Node.string("data_id", ref_id))
        player22.add_child(Node.string("name", self.NAME))
        player22.add_child(Node.s16("chara_num", 1543))
        player22.add_child(Node.s32("play_id", 0))
        player22.add_child(Node.s16("course_id", course["id"]))
        player22.add_child(Node.s16("stage1_music_num", 148))
        player22.add_child(Node.u8("stage1_sheet_num", 1))
        player22.add_child(Node.s16("stage2_music_num", 550))
        player22.add_child(Node.u8("stage2_sheet_num", 1))
        player22.add_child(Node.s16("stage3_music_num", 1113))
        player22.add_child(Node.u8("stage3_sheet_num", 1))
        player22.add_child(Node.s16("stage4_music_num", 341))
        player22.add_child(Node.u8("stage4_sheet_num", 1))
        player22.add_child(Node.u8("norma_type", 2))
        player22.add_child(Node.s32("norma_1_num", 5))
        player22.add_child(Node.s32("norma_2_num", 0))
        player22.add_child(Node.u8("clear_medal", course["medal"]))
        player22.add_child(Node.u8("clear_norma", 2))
        player22.add_child(Node.s32("total_score", course["total"]))
        player22.add_child(Node.s16("max_combo", course["combo"]))

        for stage, music in enumerate([148, 550, 1113, 341]):
            stagenode = Node.void("stage")
            player22.add_child(stagenode)
            stagenode.add_child(Node.u8("stage", stage))
            stagenode.add_child(Node.s16("music_num", music))
            stagenode.add_child(Node.u8("sheet_num", 1))
            stagenode.add_child(Node.s32("score", course[f"stage{stage + 1}"]))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/player22/@status")

    def verify_player22_new(self, ref_id: str) -> None:
        call = self.call_node()

        # Construct node
        player22 = Node.void("player22")
        call.add_child(player22)
        player22.set_attribute("method", "new")

        player22.add_child(Node.string("ref_id", ref_id))
        player22.add_child(Node.string("name", self.NAME))
        player22.add_child(Node.string("shop_name", ""))
        player22.add_child(Node.s8("pref", 51))

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/player22/account")

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
        self.verify_pcb22_boot()
        self.verify_info22_common()

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
            self.verify_player22_read(ref_id, msg_type="new")
            self.verify_player22_new(ref_id)
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
            scores = self.verify_player22_read(ref_id, msg_type="query")
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
            for _ in scores["courses"]:
                raise Exception("Got nonzero courses count on a new card!")

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

                for dummyscore in dummyscores:
                    self.verify_player22_write_music(ref_id, dummyscore)
                self.verify_player22_write(ref_id, dummyscores)
                scores = self.verify_player22_read(ref_id, msg_type="query")
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

            # Write a random course so we know we can retrieve them.
            course = {
                "id": random.randint(1, 100),
                "medal": 2,
                "combo": random.randint(10, 100),
                "stage1": random.randint(70000, 100000),
                "stage2": random.randint(70000, 100000),
                "stage3": random.randint(70000, 100000),
                "stage4": random.randint(70000, 100000),
            }
            course["total"] = sum(course[f"stage{i + 1}"] for i in range(4))
            self.verify_player22_write_course(ref_id, course)

            # Now, grab the profile one more time and see that it is there.
            scores = self.verify_player22_read(ref_id, msg_type="query")
            if len(scores["courses"]) != 1:
                raise Exception("Did not get a course back after saving!")
            if course["id"] not in scores["courses"]:
                raise Exception("Did not get expected course back after saving!")
            for key in [
                "medal",
                "combo",
                "stage1",
                "stage2",
                "stage3",
                "stage4",
                "total",
            ]:
                if course[key] != scores["courses"][course["id"]][key]:
                    raise Exception(
                        f'Expected a {key} of \'{course[key]}\' but got \'{scores["courses"][course["id"]][key]}\''
                    )
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
