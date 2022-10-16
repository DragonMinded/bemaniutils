import random
import time
from typing import Any, Dict, List, Optional

from bemani.common import Time
from bemani.client.base import BaseClient
from bemani.protocol import Node


class SoundVoltexBoothClient(BaseClient):
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
        data.add_child(Node.string("strdata1", "1.7.6"))
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

        game = Node.void("game")
        game.set_attribute("locid", location)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "hiscore")
        call.add_child(game)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/ranking/@id")
        self.assert_path(resp, "response/game/hiscore/@type")
        self.assert_path(resp, "response/game/hiscore/music/@id")
        self.assert_path(resp, "response/game/hiscore/music/note/@name")
        self.assert_path(resp, "response/game/hiscore/music/note/@score")
        self.assert_path(resp, "response/game/hiscore/music/note/@type")

    def verify_game_shop(self, location: str) -> None:
        call = self.call_node()

        game = Node.void("game")
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
        game.add_child(Node.bool("close", True))
        game.add_child(Node.s32("close_t", 1380))
        game.add_child(Node.u32("playc", 0))
        game.add_child(Node.u32("playn", 0))
        game.add_child(Node.u32("playe", 0))
        game.add_child(Node.u32("test_m", 0))
        game.add_child(Node.u32("service", 0))
        game.add_child(Node.bool("paseli", True))
        game.add_child(Node.u32("update", 0))
        game.add_child(Node.string("shopname", ""))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/nxt_time")

    def verify_game_new(self, location: str, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("name", self.NAME)
        game.set_attribute("method", "new")
        game.set_attribute("refid", refid)
        game.set_attribute("locid", location)
        game.set_attribute("dataid", refid)
        game.set_attribute("ver", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_frozen(self, refid: str, time: int) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("refid", refid)
        game.set_attribute("method", "frozen")
        game.set_attribute("ver", "0")
        game.add_child(Node.u32("sec", time))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@result")

    def verify_game_save(
        self, location: str, refid: str, packet: int, block: int, exp: int
    ) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "save")
        game.set_attribute("refid", refid)
        game.set_attribute("locid", location)
        game.set_attribute("ver", "0")
        game.add_child(Node.u8("headphone", 0))
        game.add_child(Node.u8("hispeed", 16))
        game.add_child(Node.u16("appeal_id", 19))
        game.add_child(Node.u16("frame0", 0))
        game.add_child(Node.u16("frame1", 0))
        game.add_child(Node.u16("frame2", 0))
        game.add_child(Node.u16("frame3", 0))
        game.add_child(Node.u16("frame4", 0))
        last = Node.void("last")
        game.add_child(last)
        last.set_attribute("music_type", "1")
        last.set_attribute("music_id", "29")
        last.set_attribute("sort_type", "4")
        game.add_child(Node.u32("earned_gamecoin_packet", packet))
        game.add_child(Node.u32("earned_gamecoin_block", block))
        game.add_child(Node.u32("gain_exp", exp))
        game.add_child(Node.u32("m_user_cnt", 0))
        game.add_child(Node.bool_array("have_item", [False] * 512))
        game.add_child(Node.bool_array("have_note", [False] * 512))
        tracking = Node.void("tracking")
        game.add_child(tracking)
        m0 = Node.void("m0")
        tracking.add_child(m0)
        m0.add_child(Node.u8("type", 2))
        m0.add_child(Node.u32("id", 5))
        m0.add_child(Node.u32("score", 774566))
        tracking.add_child(Node.time("p_start", Time.now() - 300))
        tracking.add_child(Node.time("p_end", Time.now()))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_common(self) -> None:
        call = self.call_node()

        game = Node.void("game")
        game.set_attribute("ver", "0")
        game.set_attribute("method", "common")
        call.add_child(game)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/limited")
        self.assert_path(resp, "response/game/event/info/@id")
        self.assert_path(resp, "response/game/catalog/info/@currency")
        self.assert_path(resp, "response/game/catalog/info/@id")
        self.assert_path(resp, "response/game/catalog/info/@price")
        self.assert_path(resp, "response/game/kacinfo/note00")
        self.assert_path(resp, "response/game/kacinfo/note01")
        self.assert_path(resp, "response/game/kacinfo/note02")
        self.assert_path(resp, "response/game/kacinfo/note10")
        self.assert_path(resp, "response/game/kacinfo/note11")
        self.assert_path(resp, "response/game/kacinfo/note12")
        self.assert_path(resp, "response/game/kacinfo/rabbeat0")
        self.assert_path(resp, "response/game/kacinfo/rabbeat1")

    def verify_game_buy(self, refid: str, catalogid: int, success: bool) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("refid", refid)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "buy")
        game.add_child(Node.u32("catalog_id", catalogid))
        game.add_child(Node.u32("earned_gamecoin_packet", 0))
        game.add_child(Node.u32("earned_gamecoin_block", 0))
        game.add_child(Node.u32("open_index", 4))
        game.add_child(Node.u32("currency_type", 1))
        game.add_child(Node.u32("price", 10))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/gamecoin_packet")
        self.assert_path(resp, "response/game/gamecoin_block")
        self.assert_path(resp, "response/game/result")

        if success:
            if resp.child_value("game/result") != 0:
                raise Exception("Failed to purchase!")
        else:
            if resp.child_value("game/result") == 0:
                raise Exception("Purchased when shouldn't have!")

    def verify_game_load(
        self, cardid: str, refid: str, msg_type: str
    ) -> Dict[str, Any]:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("cardid", cardid)
        game.set_attribute("dataid", refid)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "load")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        if msg_type == "new":
            self.assert_path(resp, "response/game/@none")
            return None

        if msg_type == "existing":
            self.assert_path(resp, "response/game/name")
            self.assert_path(resp, "response/game/code")
            self.assert_path(resp, "response/game/gamecoin_packet")
            self.assert_path(resp, "response/game/gamecoin_block")
            self.assert_path(resp, "response/game/exp_point")
            self.assert_path(resp, "response/game/m_user_cnt")
            self.assert_path(resp, "response/game/have_item")
            self.assert_path(resp, "response/game/have_note")
            self.assert_path(resp, "response/game/last/@appeal_id")
            self.assert_path(resp, "response/game/last/@frame0")
            self.assert_path(resp, "response/game/last/@frame1")
            self.assert_path(resp, "response/game/last/@frame2")
            self.assert_path(resp, "response/game/last/@frame3")
            self.assert_path(resp, "response/game/last/@frame4")
            self.assert_path(resp, "response/game/last/@headphone")
            self.assert_path(resp, "response/game/last/@hispeed")
            self.assert_path(resp, "response/game/last/@music_id")
            self.assert_path(resp, "response/game/last/@music_type")
            self.assert_path(resp, "response/game/last/@sort_type")

            return {
                "name": resp.child_value("game/name"),
                "packet": resp.child_value("game/gamecoin_packet"),
                "block": resp.child_value("game/gamecoin_block"),
                "exp": resp.child_value("game/exp_point"),
            }
        else:
            raise Exception(f"Invalid game load type {msg_type}")

    def verify_game_lounge(self) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "lounge")
        game.set_attribute("ver", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/interval")

    def verify_game_entry_s(self) -> int:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "entry_s")
        game.add_child(Node.u8("c_ver", 22))
        game.add_child(Node.u8("p_num", 1))
        game.add_child(Node.u8("p_rest", 1))
        game.add_child(Node.u8("filter", 1))
        game.add_child(Node.u32("mid", 5))
        game.add_child(Node.u32("sec", 45))
        game.add_child(Node.u16("port", 10007))
        game.add_child(Node.fouru8("gip", [127, 0, 0, 1]))
        game.add_child(Node.fouru8("lip", [10, 0, 5, 73]))
        game.add_child(Node.bool("claim", True))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/entry_id")
        return resp.child_value("game/entry_id")

    def verify_game_entry_e(self, eid: int) -> None:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "entry_e")
        game.set_attribute("ver", "0")
        game.add_child(Node.u32("eid", eid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

    def verify_game_load_m(self, refid: str) -> List[Dict[str, int]]:
        call = self.call_node()

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "load_m")
        game.set_attribute("ver", "0")
        game.set_attribute("all", "1")
        game.set_attribute("dataid", refid)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

        scores = []
        for child in resp.child("game").children:
            if child.name != "music":
                continue

            musicid = int(child.attribute("music_id"))
            for typenode in child.children:
                if typenode.name != "type":
                    continue

                chart = int(typenode.attribute("type_id"))
                clear_type = int(typenode.attribute("clear_type"))
                score = int(typenode.attribute("score"))
                grade = int(typenode.attribute("score_grade"))

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

        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "save_m")
        game.set_attribute("max_chain", "0")
        game.set_attribute("clear_type", str(score["clear_type"]))
        game.set_attribute("music_type", str(score["chart"]))
        game.set_attribute("score_grade", str(score["grade"]))
        game.set_attribute("locid", location)
        game.set_attribute("music_id", str(score["id"]))
        game.set_attribute("dataid", refid)
        game.set_attribute("ver", "0")
        game.set_attribute("score", str(score["score"]))

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
        location = self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_eventlog_write(location)
        self.verify_game_shop(location)
        self.verify_game_common()

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
            # SDVX doesn't read the new profile, it asks for the profile itself after calling new
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

        # Verify lobby functionality
        self.verify_game_lounge()
        eid = self.verify_game_entry_s()
        self.verify_game_entry_e(eid)

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
            if profile["exp"] != 0:
                raise Exception("Profile has nonzero exp associated with it!")

            # Verify purchase failure
            self.verify_game_buy(ref_id, 1004, False)

            self.verify_game_save(location, ref_id, packet=123, block=234, exp=42)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(
                    f'Profile has incorrect name {profile["name"]} associated with it!'
                )
            if profile["packet"] != 123:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 234:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["exp"] != 42:
                raise Exception("Profile has invalid exp associated with it!")

            self.verify_game_save(location, ref_id, packet=1, block=2, exp=3)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(
                    f'Profile has incorrect name {profile["name"]} associated with it!'
                )
            if profile["packet"] != 124:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 236:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["exp"] != 45:
                raise Exception("Profile has invalid exp associated with it!")

            # Verify purchase success
            self.verify_game_buy(ref_id, 1004, True)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(
                    f'Profile has incorrect name {profile["name"]} associated with it!'
                )
            if profile["packet"] != 124:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 226:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["exp"] != 45:
                raise Exception("Profile has invalid exp associated with it!")

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
                            "clear_type": 3,
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
                            "clear_type": 3,
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
                            "expected_clear_type": 3,
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
