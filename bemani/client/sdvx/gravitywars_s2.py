import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class SoundVoltexGravityWarsS2Client(BaseClient):
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
        data.add_child(Node.string("strdata1", "2.3.8"))
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
        self.assert_path(resp, "response/game_3/hit/d/id")
        self.assert_path(resp, "response/game_3/hit/d/cnt")
        self.assert_path(resp, "response/game_3/sc/d/id")
        self.assert_path(resp, "response/game_3/sc/d/ty")
        self.assert_path(resp, "response/game_3/sc/d/a_sq")
        self.assert_path(resp, "response/game_3/sc/d/a_nm")
        self.assert_path(resp, "response/game_3/sc/d/a_sc")
        self.assert_path(resp, "response/game_3/sc/d/cr")

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
        game.add_child(Node.string("romnumber", "KFC-JA-B01"))
        game.add_child(Node.string("etc", "TaxMode:1,BasicRate:100/1,FirstFree:0"))
        setting = Node.void("setting")
        game.add_child(setting)
        setting.add_child(Node.s32("coin_slot", 0))
        setting.add_child(Node.s32("game_start", 1))
        setting.add_child(Node.string("schedule", "0,0,0,0,0,0,0"))
        setting.add_child(Node.string("reference", "1,1,1"))
        setting.add_child(Node.string("basic_rate", "100,100,100"))
        setting.add_child(Node.s32("tax_rate", 1))
        setting.add_child(Node.string("time_service", "0,0,0"))
        setting.add_child(Node.string("service_value", "10,10,10"))
        setting.add_child(Node.string("service_limit", "10,10,10"))
        setting.add_child(Node.string("service_time", "07:00-11:00,07:00-11:00,07:00-11:00"))

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

    def verify_game_load(self, cardid: str, refid: str, msg_type: str) -> Dict[str, Any]:
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
            self.assert_path(resp, "response/game_3/skill_level")
            self.assert_path(resp, "response/game_3/hidden_param")
            self.assert_path(resp, "response/game_3/blaster_energy")
            self.assert_path(resp, "response/game_3/blaster_count")
            self.assert_path(resp, "response/game_3/play_count")
            self.assert_path(resp, "response/game_3/daily_count")
            self.assert_path(resp, "response/game_3/play_chain")
            self.assert_path(resp, "response/game_3/item")
            self.assert_path(resp, "response/game_3/skill/course_all")
            self.assert_path(resp, "response/game_3/story")
            self.assert_path(resp, "response/game_3/param")

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

            courses: Dict[int, Dict[int, Dict[str, int]]] = {}
            for child in resp.child("game_3/skill/course_all").children:
                if child.name != "d":
                    continue

                crsid = child.child_value("crsid")
                season = child.child_value("ssnid")
                achievement_rate = child.child_value("ar")
                clear_type = child.child_value("ct")

                if season not in courses:
                    courses[season] = {}
                courses[season][crsid] = {
                    "achievement_rate": achievement_rate,
                    "clear_type": clear_type,
                }

            return {
                "name": resp.child_value("game_3/name"),
                "packet": resp.child_value("game_3/gamecoin_packet"),
                "block": resp.child_value("game_3/gamecoin_block"),
                "blaster_energy": resp.child_value("game_3/blaster_energy"),
                "skill_level": resp.child_value("game_3/skill_level"),
                "items": items,
                "courses": courses,
            }
        else:
            raise Exception(f"Invalid game load type {msg_type}")

    def verify_game_save(self, location: str, refid: str, packet: int, block: int, blaster_energy: int) -> None:
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
        info.add_child(Node.u32("id", 0))
        info.add_child(Node.u32("type", 5))
        info.add_child(Node.u32("param", 600))
        game.add_child(
            Node.s32_array(
                "hidden_param",
                [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
        )
        game.add_child(Node.s16("skill_name_id", -1))
        game.add_child(Node.s32("earned_blaster_energy", blaster_energy))
        game.add_child(Node.u32("blaster_count", 0))
        printn = Node.void("print")
        game.add_child(printn)
        printn.add_child(Node.s32("count", 0))
        ea_shop = Node.void("ea_shop")
        game.add_child(ea_shop)
        ea_shop.add_child(Node.s32("used_packet_booster", 0))
        ea_shop.add_child(Node.s32("used_block_booster", 0))
        game.add_child(Node.s8("start_option", 0))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_common(self, loc: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        game.set_attribute("ver", "0")
        game.set_attribute("method", "common")
        game.add_child(Node.string("locid", loc))
        game.add_child(Node.string("cstcode", ""))
        game.add_child(Node.string("cpycode", ""))
        game.add_child(Node.string("hadid", "1000"))
        game.add_child(Node.string("licid", "1000"))
        game.add_child(Node.string("actid", self.pcbid))
        call.add_child(game)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/music_limited")
        self.assert_path(resp, "response/game_3/event/info/event_id")
        self.assert_path(resp, "response/game_3/skill_course/info/course_id")
        self.assert_path(resp, "response/game_3/skill_course/info/level")
        self.assert_path(resp, "response/game_3/skill_course/info/season_id")
        self.assert_path(resp, "response/game_3/skill_course/info/season_name")
        self.assert_path(resp, "response/game_3/skill_course/info/season_new_flg")
        self.assert_path(resp, "response/game_3/skill_course/info/course_name")
        self.assert_path(resp, "response/game_3/skill_course/info/course_type")
        self.assert_path(resp, "response/game_3/skill_course/info/skill_name_id")
        self.assert_path(resp, "response/game_3/skill_course/info/matching_assist")
        self.assert_path(resp, "response/game_3/skill_course/info/gauge_type")
        self.assert_path(resp, "response/game_3/skill_course/info/paseli_type")
        self.assert_path(resp, "response/game_3/skill_course/info/track/track_no")
        self.assert_path(resp, "response/game_3/skill_course/info/track/music_id")
        self.assert_path(resp, "response/game_3/skill_course/info/track/music_type")

    def verify_game_buy(
        self,
        refid: str,
        catalogtype: int,
        catalogid: int,
        currencytype: int,
        price: int,
        itemtype: int,
        itemid: int,
        param: int,
        success: bool,
    ) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "buy")
        game.add_child(Node.string("refid", refid))
        game.add_child(Node.u8("catalog_type", catalogtype))
        game.add_child(Node.u32("catalog_id", catalogid))
        game.add_child(Node.u32("earned_gamecoin_packet", 0))
        game.add_child(Node.u32("earned_gamecoin_block", 0))
        game.add_child(Node.u32("currency_type", currencytype))
        item = Node.void("item")
        game.add_child(item)
        item.add_child(Node.u32("item_type", itemtype))
        item.add_child(Node.u32("item_id", itemid))
        item.add_child(Node.u32("param", param))
        item.add_child(Node.u32("price", price))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/gamecoin_packet")
        self.assert_path(resp, "response/game_3/gamecoin_block")
        self.assert_path(resp, "response/game_3/result")

        if success:
            if resp.child_value("game_3/result") != 0:
                raise Exception("Failed to purchase!")
        else:
            if resp.child_value("game_3/result") == 0:
                raise Exception("Purchased when shouldn't have!")

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

    def verify_game_entry_s(self) -> int:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "entry_s")
        game.add_child(Node.u8("c_ver", 128))
        game.add_child(Node.u8("p_num", 1))
        game.add_child(Node.u8("p_rest", 1))
        game.add_child(Node.u8("filter", 1))
        game.add_child(Node.u32("mid", 416))
        game.add_child(Node.u32("sec", 45))
        game.add_child(Node.u16("port", 10007))
        game.add_child(Node.fouru8("gip", [127, 0, 0, 1]))
        game.add_child(Node.fouru8("lip", [10, 0, 5, 73]))
        game.add_child(Node.u8("claim", 0))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3/entry_id")
        return resp.child_value("game_3/entry_id")

    def verify_game_entry_e(self, eid: int) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "entry_e")
        game.set_attribute("ver", "0")
        game.add_child(Node.u32("eid", eid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_save_e(self, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "save_e")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("refid", refid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_play_e(self, location: str, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "play_e")
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.s8("mode", 2))
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

    def verify_game_save_m(self, location: str, refid: str, score: Dict[str, int]) -> None:
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

    def verify_game_load_r(self, refid: str) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("method", "load_r")
        game.set_attribute("ver", "0")
        game.add_child(Node.string("dataid", refid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game_3")

    def verify_game_save_c(self, location: str, refid: str, season: int, course: int) -> None:
        call = self.call_node()

        game = Node.void("game_3")
        call.add_child(game)
        game.set_attribute("ver", "0")
        game.set_attribute("method", "save_c")
        game.add_child(Node.string("dataid", refid))
        game.add_child(Node.s16("crsid", course))
        game.add_child(Node.s16("ct", 2))
        game.add_child(Node.s16("ar", 15000))
        game.add_child(Node.s32("ssnid", season))
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
        self.verify_game_common(location)
        self.verify_game_shop(location)

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
            # SDVX doesn't read the new profile, it asks for the profile itself after calling new
            self.verify_game_load(card, ref_id, msg_type="new")
            self.verify_game_new(location, ref_id)
            self.verify_game_load(card, ref_id, msg_type="existing")
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        # Verify rivals node (necessary to return but can hold nothing)
        self.verify_game_load_r(ref_id)

        # Verify account freezing
        self.verify_game_frozen(ref_id, 900)
        self.verify_game_frozen(ref_id, 0)
        self.verify_game_save_e(ref_id)
        self.verify_game_play_e(location, ref_id)

        # Verify lobby functionality
        self.verify_game_lounge()
        eid = self.verify_game_entry_s()
        self.verify_game_entry_e(eid)

        if cardid is None:
            # Verify profile loading and saving
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(f'Profile has incorrect name {profile["name"]} associated with it!')
            if profile["packet"] != 0:
                raise Exception("Profile has nonzero blocks associated with it!")
            if profile["block"] != 0:
                raise Exception("Profile has nonzero packets associated with it!")
            if profile["blaster_energy"] != 0:
                raise Exception("Profile has nonzero blaster energy associated with it!")
            if profile["items"]:
                raise Exception("Profile already has purchased items!")
            if profile["courses"]:
                raise Exception("Profile already has finished courses!")

            # Verify purchase failure, try buying song we can't afford
            self.verify_game_buy(ref_id, 0, 29, 1, 10, 0, 29, 3, False)

            self.verify_game_save(location, ref_id, packet=123, block=234, blaster_energy=42)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(f'Profile has incorrect name {profile["name"]} associated with it!')
            if profile["packet"] != 123:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 234:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["blaster_energy"] != 42:
                raise Exception("Profile has invalid blaster energy associated with it!")
            if 5 not in profile["items"]:
                raise Exception("Profile doesn't have user settings items in it!")
            if profile["courses"]:
                raise Exception("Profile already has finished courses!")

            self.verify_game_save(location, ref_id, packet=1, block=2, blaster_energy=3)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(f'Profile has incorrect name {profile["name"]} associated with it!')
            if profile["packet"] != 124:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 236:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["blaster_energy"] != 45:
                raise Exception("Profile has invalid blaster energy associated with it!")
            if 5 not in profile["items"]:
                raise Exception("Profile doesn't have user settings items in it!")
            if profile["courses"]:
                raise Exception("Profile has invalid finished courses!")

            # Verify purchase success, buy a song we can afford now
            self.verify_game_buy(ref_id, 0, 29, 1, 10, 0, 29, 3, True)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if profile["name"] != self.NAME:
                raise Exception(f'Profile has incorrect name {profile["name"]} associated with it!')
            if profile["packet"] != 124:
                raise Exception("Profile has invalid blocks associated with it!")
            if profile["block"] != 226:
                raise Exception("Profile has invalid packets associated with it!")
            if profile["blaster_energy"] != 45:
                raise Exception("Profile has invalid blaster energy associated with it!")
            if 0 not in profile["items"] or 29 not in profile["items"][0]:
                raise Exception("Purchase didn't add to profile!")
            if profile["items"][0][29] != 3:
                raise Exception("Purchase parameters are wrong!")
            if profile["courses"]:
                raise Exception("Profile has invalid finished courses!")

            # Verify that we can finish skill analyzer courses
            self.verify_game_save_c(location, ref_id, 14, 3)
            profile = self.verify_game_load(card, ref_id, msg_type="existing")
            if 14 not in profile["courses"] or 3 not in profile["courses"][14]:
                raise Exception("Course didn't add to profile!")
            if profile["courses"][14][3]["achievement_rate"] != 15000:
                raise Exception("Course didn't save achievement rate!")
            if profile["courses"][14][3]["clear_type"] != 2:
                raise Exception("Course didn't save clear type!")

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
                        if received["id"] == expected["id"] and received["chart"] == expected["chart"]:
                            actual = received
                            break

                    if actual is None:
                        raise Exception(f"Didn't find song {expected['id']} chart {expected['chart']} in response!")

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
