import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class Museca1PlusClient(BaseClient):
    NAME = "TEST"

    def verify_eventlog_write(self, location: str) -> None:
        call = self.call_node()

        # Construct node
        eventlog = Node.void("eventlog")
        call.add_child(eventlog)
        eventlog.set_attribute("method", "write")
        eventlog.add_child(Node.u32("retrycnt", 0))
        data = Node.void("data")
        eventlog.add_child(data)
        data.add_child(Node.string("eventid", "S_PWRON"))
        data.add_child(Node.s32("eventorder", 0))
        data.add_child(Node.u64("pcbtime", int(time.time() * 1000)))
        data.add_child(Node.s64("gamesession", -1))
        data.add_child(Node.string("strdata1", "2.4.0"))
        data.add_child(Node.string("strdata2", ""))
        data.add_child(Node.s64("numdata1", 1))
        data.add_child(Node.s64("numdata2", 0))
        data.add_child(Node.string("locationid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eventlog/gamesession")
        self.assert_path(resp, "response/eventlog/logsendflg")
        self.assert_path(resp, "response/eventlog/logerrlevel")
        self.assert_path(resp, "response/eventlog/evtidnosendflg")

    def verify_game_hiscore(self, location: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        game.set_attribute("ver", "0")
        game.set_attribute("method", "hiscore")
        game.add_child(Node.string("locid", location))
        call.add_child(game)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/hitchart/info/id")
        self.assert_path(resp, "response/game_3/hitchart/info/cnt")
        self.assert_path(resp, "response/game_3/hiscore_allover/info/id")
        self.assert_path(resp, "response/game_3/hiscore_allover/info/type")
        self.assert_path(resp, "response/game_3/hiscore_allover/info/name")
        self.assert_path(resp, "response/game_3/hiscore_allover/info/seq")
        self.assert_path(resp, "response/game_3/hiscore_allover/info/score")
        self.assert_path(resp, "response/game_3/hiscore_location/info/id")
        self.assert_path(resp, "response/game_3/hiscore_location/info/type")
        self.assert_path(resp, "response/game_3/hiscore_location/info/name")
        self.assert_path(resp, "response/game_3/hiscore_location/info/seq")
        self.assert_path(resp, "response/game_3/hiscore_location/info/score")
        self.assert_path(resp, "response/game_3/clear_rate/d/id")
        self.assert_path(resp, "response/game_3/clear_rate/d/type")
        self.assert_path(resp, "response/game_3/clear_rate/d/cr")

    def verify_game_exception(self, location: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "exception")
        game.add_child(Node.string("text", ""))
        game.add_child(Node.string("lid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/@status")

    def verify_game_shop(self, location: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "shop")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("locid", location))
        game.add_child(Node.string("regcode", "."))
        game.add_child(Node.string("locname", ""))
        game.add_child(Node.u8("loctype", 0))
        game.add_child(Node.string("cstcode", ""))
        game.add_child(Node.string("cpycode", ""))
        game.add_child(Node.s32("latde", 0))
        game.add_child(Node.s32("londe", 0))
        game.add_child(Node.u8("accu", 0))
        game.add_child(Node.string("linid", "."))
        game.add_child(Node.u8("linclass", 0))
        game.add_child(Node.ipv4("ipaddr", "0.0.0.0"))
        game.add_child(Node.string("hadid", "00010203040506070809"))
        game.add_child(Node.string("licid", "00010203040506070809"))
        game.add_child(Node.string("actid", self.pcbid))
        game.add_child(Node.s8("appstate", 0))
        game.add_child(Node.s8("c_need", 1))
        game.add_child(Node.s8("c_credit", 2))
        game.add_child(Node.s8("s_credit", 2))
        game.add_child(Node.bool("free_p", True))
        game.add_child(Node.bool("close", False))
        game.add_child(Node.s32("close_t", 1380))
        game.add_child(Node.u32("playc", 0))
        game.add_child(Node.u32("playn", 0))
        game.add_child(Node.u32("playe", 0))
        game.add_child(Node.u32("test_m", 0))
        game.add_child(Node.u32("service", 0))
        game.add_child(Node.bool("paseli", True))
        game.add_child(Node.u32("update", 0))
        game.add_child(Node.string("shopname", ""))
        game.add_child(Node.bool("newpc", False))
        game.add_child(Node.s32("s_paseli", 206))
        game.add_child(Node.s32("monitor", 1))
        game.add_child(Node.string("romnumber", "-"))
        game.add_child(Node.string("etc", "TaxMode:1,BasicRate:100/1,FirstFree:0"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/nxt_time")

    def verify_game_new(self, location: str, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "new")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.string("refid", refid))
        game.add_child(Node.string("name", self.NAME))
        game.add_child(Node.string("locid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_frozen(self, refid: str, time: int) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "frozen")
        game.add_child(Node.string("refid", refid))
        game.add_child(Node.u32("sec", time))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/result")

    def verify_game_save(
        self, location: str, refid: str, packet: int, block: int, blaster_energy: int
    ) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "save")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("refid", refid))
        game.add_child(Node.string("locid", location))
        game.add_child(Node.u8("headphone", 0))
        game.add_child(Node.u16("appeal_id", 1001))
        game.add_child(Node.u16("comment_id", 0))
        game.add_child(Node.s32("music_id", 29))
        game.add_child(Node.u8("music_type", 1))
        game.add_child(Node.u8("sort_type", 1))
        game.add_child(Node.u8("narrow_down", 0))
        game.add_child(Node.u8("gauge_option", 0))
        game.add_child(Node.u32("earned_gamecoin_packet", packet))
        game.add_child(Node.u32("earned_gamecoin_block", block))
        item = Node.void("item")
        game.add_child(item)
        info = Node.void("info")
        item.add_child(info)
        info.add_child(Node.u32("id", 1))
        info.add_child(Node.u32("type", 5))
        info.add_child(Node.u32("param", 333333376))
        info = Node.void("info")
        item.add_child(info)
        info.add_child(Node.u32("id", 1))
        info.add_child(Node.u32("type", 7))
        info.add_child(Node.u32("param", 1))
        info.add_child(Node.s32("diff_param", 1))
        game.add_child(
            Node.s32_array(
                "hidden_param",
                [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
        )
        game.add_child(Node.s16("skill_name_id", -1))
        game.add_child(Node.s32("earned_blaster_energy", blaster_energy))
        game.add_child(Node.u32("blaster_count", 0))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_common(self) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        game.set_attribute("ver", "0")
        game.set_attribute("method", "common")
        call.add_child(game)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/music_limited")
        self.assert_path(resp, "response/game_3/event")

    def verify_game_load(
        self, cardid: str, refid: str, msg_type: str
    ) -> Dict[str, Any]:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "load")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.string("cardid", cardid))
        game.add_child(Node.string("refid", refid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        if msg_type == "new":
            self.assert_path(resp, "response/game_3/result")
            if resp.child_value("game_3/result") != 1:
                raise Exception("Invalid result for new profile!")
            return None

        if msg_type == "existing":
            self.assert_path(resp, "response/game_3/name")
            self.assert_path(resp, "response/game_3/code")
            self.assert_path(resp, "response/game_3/gamecoin_packet")
            self.assert_path(resp, "response/game_3/gamecoin_block")
            self.assert_path(resp, "response/game_3/skill_name_id")
            self.assert_path(resp, "response/game_3/hidden_param")
            self.assert_path(resp, "response/game_3/blaster_energy")
            self.assert_path(resp, "response/game_3/blaster_count")
            self.assert_path(resp, "response/game_3/play_count")
            self.assert_path(resp, "response/game_3/daily_count")
            self.assert_path(resp, "response/game_3/play_chain")
            self.assert_path(resp, "response/game_3/ryusei_festa/ryusei_festa_trigger")
            self.assert_path(resp, "response/game_3/item")

            items: Dict[int, Dict[int, int]] = {}
            for child in resp.child("game_3/item").children:
                if child.name != "info":
                    continue

                itype = child.child_value("type")
                iid = child.child_value("id")
                param = child.child_value("param")

                if itype not in items:
                    items[itype] = {}
                items[itype][iid] = param

            return {
                "name": resp.child_value("game_3/name"),
                "packet": resp.child_value("game_3/gamecoin_packet"),
                "block": resp.child_value("game_3/gamecoin_block"),
                "blaster_energy": resp.child_value("game_3/blaster_energy"),
                "items": items,
            }
        else:
            raise Exception(f"Invalid game load type {msg_type}")

    def verify_game_play_e(self, location: str, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "play_e")
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.s8("mode", 0))
        game.add_child(Node.s16("track_num", 3))
        game.add_child(Node.s32("s_coin", 0))
        game.add_child(Node.s32("s_paseli", 0))
        game.add_child(Node.s16("blaster_count", 0))
        game.add_child(Node.s16("blaster_cartridge", 0))
        game.add_child(Node.string("locid", location))
        game.add_child(Node.u16("drop_frame", 396))
        game.add_child(Node.u16("drop_frame_max", 396))
        game.add_child(Node.u16("drop_count", 1))
        game.add_child(Node.string("etc", "StoryID:0,StoryPrg:0,PrgPrm:0"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_lounge(self) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "lounge")
        game.set_attribute("ver", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/interval")

    def verify_game_load_m(self, refid: str) -> List[Dict[str, int]]:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "load_m")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("dataid", refid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/new")

        scores = []
        for child in resp.child("game_3/new").children:
            if child.name != "music":
                continue

            musicid = child.child_value("music_id")
            chart = child.child_value("music_type")
            clear_type = child.child_value("clear_type")
            score = child.child_value("score")
            grade = child.child_value("score_grade")

            scores.append(
                {
                    "id": musicid,
                    "chart": chart,
                    "clear_type": clear_type,
                    "score": score,
                    "grade": grade,
                }
            )

        return scores

    def verify_game_save_m(
        self, location: str, refid: str, score: Dict[str, int]
    ) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "save_m")
        game.add_child(Node.string("refid", refid))
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.u32("music_id", score["id"]))
        game.add_child(Node.u32("music_type", score["chart"]))
        game.add_child(Node.u32("score", score["score"]))
        game.add_child(Node.u32("clear_type", score["clear_type"]))
        game.add_child(Node.u32("score_grade", score["grade"]))
        game.add_child(Node.u32("max_chain", 0))
        game.add_child(Node.u32("critical", 0))
        game.add_child(Node.u32("near", 0))
        game.add_child(Node.u32("error", 0))
        game.add_child(Node.u32("effective_rate", 100))
        game.add_child(Node.u32("btn_rate", 0))
        game.add_child(Node.u32("long_rate", 0))
        game.add_child(Node.u32("vol_rate", 0))
        game.add_child(Node.u8("mode", 0))
        game.add_child(Node.u8("gauge_type", 0))
        game.add_child(Node.u16("online_num", 0))
        game.add_child(Node.u16("local_num", 0))
        game.add_child(Node.string("locid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

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
        self.verify_eventlog_write(location)
        self.verify_game_common()
        self.verify_game_shop(location)
        self.verify_game_exception(location)

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
            # Museca doesn't read the new profile, it asks for the profile itself after calling new
            self.verify_game_load(card, ref_id, msg_type="new")
            self.verify_game_new(location, ref_id)
            self.verify_game_load(card, ref_id, msg_type="existing")
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

        # Verify account freezing
        self.verify_game_frozen(ref_id, 900)
        self.verify_game_frozen(ref_id, 0)
        self.verify_game_play_e(location, ref_id)

        # Verify lobby functionality
        self.verify_game_lounge()

        if cardid is None:
            # Verify profile loading and saving
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(
                    f'Profile has incorrect name {profile["name"]} associated with it!'
                )
            if profile["packet"] != 0:
                raise Exception("Profile has nonzero blocks associated with it!")
            if profile["block"] != 0:
                raise Exception("Profile has nonzero packets associated with it!")
            if profile["blaster_energy"] != 0:
                raise Exception(
                    "Profile has nonzero blaster energy associated with it!"
                )

            self.verify_game_save(
                location, ref_id, packet=123, block=234, blaster_energy=42
            )
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(
                    f'Profile has incorrect name {profile["name"]} associated with it!'
                )
            if profile["packet"] != 123:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 234:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["blaster_energy"] != 42:
                raise Exception(
                    "Profile has invalid blaster energy associated with it!"
                )

            # Verify empty profile has no scores on it
            scores = self.verify_game_load_m(ref_id)
            if len(scores) > 0:
                raise Exception("Score on an empty profile!")

            # Verify score saving and updating
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 1,
                            "chart": 1,
                            "grade": 3,
                            "clear_type": 2,
                            "score": 765432,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 1,
                            "chart": 0,
                            "grade": 6,
                            "clear_type": 4,
                            "score": 7654321,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 2,
                            "chart": 2,
                            "grade": 1,
                            "clear_type": 1,
                            "score": 12345,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 3,
                            "chart": 0,
                            "grade": 1,
                            "clear_type": 1,
                            "score": 123,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 1,
                            "chart": 1,
                            "grade": 5,
                            "clear_type": 4,
                            "score": 8765432,
                        },
                        # A worse score on another same chart
                        {
                            "id": 1,
                            "chart": 0,
                            "grade": 4,
                            "clear_type": 2,
                            "score": 6543210,
                            "expected_score": 7654321,
                            "expected_clear_type": 4,
                            "expected_grade": 6,
                        },
                    ]
                for dummyscore in dummyscores:
                    self.verify_game_save_m(location, ref_id, dummyscore)

                scores = self.verify_game_load_m(ref_id)
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
                    if "expected_grade" in expected:
                        expected_grade = expected["expected_grade"]
                    else:
                        expected_grade = expected["grade"]
                    if "expected_clear_type" in expected:
                        expected_clear_type = expected["expected_clear_type"]
                    else:
                        expected_clear_type = expected["clear_type"]

                    if actual["score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got score \'{actual["score"]}\''
                        )
                    if actual["grade"] != expected_grade:
                        raise Exception(
                            f'Expected a grade of \'{expected_grade}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got grade \'{actual["grade"]}\''
                        )
                    if actual["clear_type"] != expected_clear_type:
                        raise Exception(
                            f'Expected a clear_type of \'{expected_clear_type}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got clear_type \'{actual["clear_type"]}\''
                        )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

        else:
            print("Skipping score checks for existing card")

        # Verify high score tables
        self.verify_game_hiscore(location)

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
