import random
import time
from typing import Any, Dict, List, Optional

from bemani.client.base import BaseClient
from bemani.common import CardCipher, Time
from bemani.protocol import Node


class JubeatClanClient(BaseClient):
    NAME = "TEST"

    def verify_shopinfo_regist(self) -> None:
        call = self.call_node()

        # Construct node
        shopinfo = Node.void("shopinfo")
        shopinfo.set_attribute("method", "regist")
        call.add_child(shopinfo)
        shop = Node.void("shop")
        shopinfo.add_child(shop)
        shop.add_child(Node.string("name", ""))
        shop.add_child(Node.string("pref", "JP-14"))
        shop.add_child(Node.string("softwareid", ""))
        shop.add_child(Node.string("systemid", self.pcbid))
        shop.add_child(Node.string("hardwareid", "01020304050607080900"))
        shop.add_child(Node.string("locationid", "US-1"))
        shop.add_child(Node.string("monitor", "D26L155             6252     151"))
        testmode = Node.void("testmode")
        shop.add_child(testmode)

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/shopinfo/data/cabid")
        self.assert_path(resp, "response/shopinfo/data/locationid")
        self.assert_path(resp, "response/shopinfo/data/tax_phase")
        self.assert_path(resp, "response/shopinfo/data/facility/exist")
        self.assert_path(resp, "response/shopinfo/data/info/event_info")
        self.assert_path(resp, "response/shopinfo/data/info/share_music")
        self.assert_path(resp, "response/shopinfo/data/info/genre_def_music")
        self.assert_path(resp, "response/shopinfo/data/info/black_jacket_list")
        self.assert_path(resp, "response/shopinfo/data/info/white_music_list")
        self.assert_path(resp, "response/shopinfo/data/info/white_marker_list")
        self.assert_path(resp, "response/shopinfo/data/info/white_theme_list")
        self.assert_path(resp, "response/shopinfo/data/info/open_music_list")
        self.assert_path(resp, "response/shopinfo/data/info/shareable_music_list")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/point")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/emblem/normal/index")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/emblem/premium/index")
        self.assert_path(resp, "response/shopinfo/data/info/born/status")
        self.assert_path(resp, "response/shopinfo/data/info/born/year")
        self.assert_path(resp, "response/shopinfo/data/info/collection/rating_s")
        self.assert_path(resp, "response/shopinfo/data/info/expert_option/is_available")
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/is_available"
        )
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/team/default_flag"
        )
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/team/redbelk_flag"
        )
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/team/cyanttle_flag"
        )
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/team/greenesia_flag"
        )
        self.assert_path(
            resp, "response/shopinfo/data/info/all_music_matching/team/plumpark_flag"
        )
        self.assert_path(resp, "response/shopinfo/data/info/question_list")
        self.assert_path(resp, "response/shopinfo/data/info/drop_list")
        self.assert_path(resp, "response/shopinfo/data/info/daily_bonus_list")
        self.assert_path(resp, "response/shopinfo/data/info/department/pack_list")

    def verify_demodata_get_info(self) -> None:
        call = self.call_node()

        # Construct node
        demodata = Node.void("demodata")
        call.add_child(demodata)
        demodata.set_attribute("method", "get_info")
        pcbinfo = Node.void("pcbinfo")
        demodata.add_child(pcbinfo)
        pcbinfo.set_attribute("client_data_version", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/demodata/data/info/black_jacket_list")

    def verify_demodata_get_news(self) -> None:
        call = self.call_node()

        # Construct node
        demodata = Node.void("demodata")
        call.add_child(demodata)
        demodata.set_attribute("method", "get_news")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/demodata/data/officialnews")

    def verify_demodata_get_jbox_list(self) -> None:
        call = self.call_node()

        # Construct node
        demodata = Node.void("demodata")
        call.add_child(demodata)
        demodata.set_attribute("method", "get_jbox_list")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/demodata/@status")

    def __verify_profile(self, resp: Node) -> int:
        self.assert_path(resp, "response/gametop/data/info/event_info")
        self.assert_path(resp, "response/gametop/data/info/share_music")
        self.assert_path(resp, "response/gametop/data/info/genre_def_music")
        self.assert_path(resp, "response/gametop/data/info/black_jacket_list")
        self.assert_path(resp, "response/gametop/data/info/white_music_list")
        self.assert_path(resp, "response/gametop/data/info/white_marker_list")
        self.assert_path(resp, "response/gametop/data/info/white_theme_list")
        self.assert_path(resp, "response/gametop/data/info/open_music_list")
        self.assert_path(resp, "response/gametop/data/info/shareable_music_list")
        self.assert_path(resp, "response/gametop/data/info/jbox/point")
        self.assert_path(resp, "response/gametop/data/info/jbox/emblem/normal/index")
        self.assert_path(resp, "response/gametop/data/info/jbox/emblem/premium/index")
        self.assert_path(resp, "response/gametop/data/info/born/status")
        self.assert_path(resp, "response/gametop/data/info/born/year")
        self.assert_path(resp, "response/gametop/data/info/collection/rating_s")
        self.assert_path(resp, "response/gametop/data/info/expert_option/is_available")
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/is_available"
        )
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/team/default_flag"
        )
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/team/redbelk_flag"
        )
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/team/cyanttle_flag"
        )
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/team/greenesia_flag"
        )
        self.assert_path(
            resp, "response/gametop/data/info/all_music_matching/team/plumpark_flag"
        )
        self.assert_path(resp, "response/gametop/data/info/question_list")
        self.assert_path(resp, "response/gametop/data/info/drop_list")
        self.assert_path(resp, "response/gametop/data/info/daily_bonus_list")
        self.assert_path(resp, "response/gametop/data/info/department/pack_list")

        for item in [
            "tune_cnt",
            "save_cnt",
            "saved_cnt",
            "fc_cnt",
            "ex_cnt",
            "clear_cnt",
            "match_cnt",
            "beat_cnt",
            "mynews_cnt",
            "bonus_tune_points",
            "is_bonus_tune_played",
            "inherit",
            "mtg_entry_cnt",
            "mtg_hold_cnt",
            "mtg_result",
        ]:
            self.assert_path(resp, f"response/gametop/data/player/info/{item}")

        for item in [
            "music_list",
            "secret_list",
            "theme_list",
            "marker_list",
            "title_list",
            "parts_list",
            "emblem_list",
            "commu_list",
            "new/secret_list",
            "new/theme_list",
            "new/marker_list",
        ]:
            self.assert_path(resp, f"response/gametop/data/player/item/{item}")

        for item in [
            "play_time",
            "shopname",
            "areaname",
            "music_id",
            "seq_id",
            "sort",
            "category",
            "expert_option",
        ]:
            self.assert_path(resp, f"response/gametop/data/player/last/{item}")

        for item in [
            "marker",
            "theme",
            "title",
            "parts",
            "rank_sort",
            "combo_disp",
            "emblem",
            "matching",
            "hard",
            "hazard",
        ]:
            self.assert_path(resp, f"response/gametop/data/player/last/settings/{item}")

        # Misc stuff
        self.assert_path(resp, "response/gametop/data/player/session_id")
        self.assert_path(resp, "response/gametop/data/player/event_flag")

        # Profile settings
        self.assert_path(resp, "response/gametop/data/player/name")
        self.assert_path(resp, "response/gametop/data/player/jid")

        # Required nodes for events and stuff
        self.assert_path(resp, "response/gametop/data/player/history")
        self.assert_path(resp, "response/gametop/data/player/lab_edit_seq")
        self.assert_path(resp, "response/gametop/data/player/event_info")
        self.assert_path(resp, "response/gametop/data/player/navi/flag")
        self.assert_path(
            resp, "response/gametop/data/player/fc_challenge/today/music_id"
        )
        self.assert_path(resp, "response/gametop/data/player/fc_challenge/today/state")
        self.assert_path(
            resp, "response/gametop/data/player/fc_challenge/whim/music_id"
        )
        self.assert_path(resp, "response/gametop/data/player/fc_challenge/whim/state")
        self.assert_path(resp, "response/gametop/data/player/official_news/news_list")
        self.assert_path(resp, "response/gametop/data/player/rivallist")
        self.assert_path(
            resp, "response/gametop/data/player/free_first_play/is_available"
        )
        self.assert_path(resp, "response/gametop/data/player/jbox/point")
        self.assert_path(resp, "response/gametop/data/player/jbox/emblem/normal/index")
        self.assert_path(resp, "response/gametop/data/player/jbox/emblem/premium/index")
        self.assert_path(resp, "response/gametop/data/player/new_music")
        self.assert_path(resp, "response/gametop/data/player/gift_list")
        self.assert_path(resp, "response/gametop/data/player/born/status")
        self.assert_path(resp, "response/gametop/data/player/question_list")
        self.assert_path(resp, "response/gametop/data/player/jubility/@param")
        self.assert_path(
            resp, "response/gametop/data/player/jubility/target_music_list"
        )
        self.assert_path(resp, "response/gametop/data/player/team/@id")
        self.assert_path(resp, "response/gametop/data/player/team/section")
        self.assert_path(resp, "response/gametop/data/player/team/street")
        self.assert_path(resp, "response/gametop/data/player/team/house_number_1")
        self.assert_path(resp, "response/gametop/data/player/team/house_number_2")
        self.assert_path(resp, "response/gametop/data/player/team/move/@house_number_1")
        self.assert_path(resp, "response/gametop/data/player/team/move/@house_number_2")
        self.assert_path(resp, "response/gametop/data/player/team/move/@id")
        self.assert_path(resp, "response/gametop/data/player/team/move/@section")
        self.assert_path(resp, "response/gametop/data/player/team/move/@street")
        self.assert_path(resp, "response/gametop/data/player/union_battle/@id")
        self.assert_path(resp, "response/gametop/data/player/union_battle/power")
        self.assert_path(resp, "response/gametop/data/player/server")
        self.assert_path(resp, "response/gametop/data/player/eamuse_gift_list")
        self.assert_path(resp, "response/gametop/data/player/clan_course_list")
        self.assert_path(resp, "response/gametop/data/player/category_list")
        self.assert_path(resp, "response/gametop/data/player/drop_list/drop/@id")
        self.assert_path(resp, "response/gametop/data/player/drop_list/drop/exp")
        self.assert_path(resp, "response/gametop/data/player/drop_list/drop/flag")
        self.assert_path(
            resp, "response/gametop/data/player/drop_list/drop/item_list/item/@id"
        )
        self.assert_path(
            resp, "response/gametop/data/player/drop_list/drop/item_list/item/num"
        )
        self.assert_path(
            resp, "response/gametop/data/player/fill_in_category/no_gray_flag_list"
        )
        self.assert_path(
            resp, "response/gametop/data/player/fill_in_category/all_yellow_flag_list"
        )
        self.assert_path(
            resp, "response/gametop/data/player/fill_in_category/full_combo_flag_list"
        )
        self.assert_path(
            resp, "response/gametop/data/player/fill_in_category/excellent_flag_list"
        )
        self.assert_path(resp, "response/gametop/data/player/daily_bonus_list")
        self.assert_path(resp, "response/gametop/data/player/ticket_list")

        # Return the jid
        return resp.child_value("gametop/data/player/jid")

    def verify_gameend_regist(
        self,
        ref_id: str,
        jid: int,
        scores: List[Dict[str, Any]],
    ) -> None:
        call = self.call_node()

        # Construct node
        gameend = Node.void("gameend")
        call.add_child(gameend)
        gameend.set_attribute("method", "regist")
        gameend.add_child(Node.s32("retry", 0))
        pcbinfo = Node.void("pcbinfo")
        gameend.add_child(pcbinfo)
        pcbinfo.set_attribute("client_data_version", "0")
        data = Node.void("data")
        gameend.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.string("refid", ref_id))
        player.add_child(Node.s32("jid", jid))
        player.add_child(Node.string("name", self.NAME))
        result = Node.void("result")
        data.add_child(result)
        result.set_attribute("count", str(len(scores)))

        # Send scores
        scoreid = 0
        for score in scores:
            # Always played
            bits = 0x1
            if score["clear"]:
                bits |= 0x2
            if score["fc"]:
                bits |= 0x4
            if score["ex"]:
                bits |= 0x8

            # Intentionally starting at 1 because that's what the game does
            scoreid = scoreid + 1
            tune = Node.void("tune")
            result.add_child(tune)
            tune.set_attribute("id", str(scoreid))
            tune.add_child(Node.s32("music", score["id"]))
            tune.add_child(Node.s64("timestamp", Time.now() * 1000))
            player_1 = Node.void("player")
            tune.add_child(player_1)
            player_1.set_attribute("rank", "1")
            scorenode = Node.s32("score", score["score"])
            player_1.add_child(scorenode)
            scorenode.set_attribute("seq", str(score["chart"]))
            scorenode.set_attribute("clear", str(bits))
            scorenode.set_attribute("combo", "69")
            player_1.add_child(
                Node.u8_array(
                    "mbar",
                    [
                        239,
                        175,
                        170,
                        170,
                        190,
                        234,
                        187,
                        158,
                        153,
                        230,
                        170,
                        90,
                        102,
                        170,
                        85,
                        150,
                        150,
                        102,
                        85,
                        234,
                        171,
                        169,
                        157,
                        150,
                        170,
                        101,
                        230,
                        90,
                        214,
                        255,
                    ],
                )
            )

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/gameend/data/player/session_id")

    def verify_gameend_final(
        self,
        ref_id: str,
        jid: int,
    ) -> None:
        call = self.call_node()

        # Construct node
        gameend = Node.void("gameend")
        call.add_child(gameend)
        gameend.set_attribute("method", "final")
        gameend.add_child(Node.s32("retry", 0))
        pcbinfo = Node.void("pcbinfo")
        gameend.add_child(pcbinfo)
        pcbinfo.set_attribute("client_data_version", "0")
        data = Node.void("data")
        gameend.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.string("refid", ref_id))
        player.add_child(Node.s32("jid", jid))
        jbox = Node.void("jbox")
        player.add_child(jbox)
        jbox.add_child(Node.s32("point", 0))
        emblem = Node.void("emblem")
        jbox.add_child(emblem)
        emblem.add_child(Node.u8("type", 0))
        emblem.add_child(Node.s16("index", 0))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/gameend/@status")

    def verify_gametop_regist(self, card_id: str, ref_id: str) -> int:
        call = self.call_node()

        # Construct node
        gametop = Node.void("gametop")
        call.add_child(gametop)
        gametop.set_attribute("method", "regist")
        data = Node.void("data")
        gametop.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.string("refid", ref_id))
        player.add_child(Node.string("datid", ref_id))
        player.add_child(Node.string("uid", card_id))
        player.add_child(Node.bool("inherit", True))
        player.add_child(Node.string("name", self.NAME))

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        return self.__verify_profile(resp)

    def verify_gametop_get_pdata(self, card_id: str, ref_id: str) -> int:
        call = self.call_node()

        # Construct node
        gametop = Node.void("gametop")
        call.add_child(gametop)
        gametop.set_attribute("method", "get_pdata")
        retry = Node.s32("retry", 0)
        gametop.add_child(retry)
        data = Node.void("data")
        gametop.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.string("refid", ref_id))
        player.add_child(Node.string("datid", ref_id))
        player.add_child(Node.string("uid", card_id))
        player.add_child(Node.string("card_no", CardCipher.encode(card_id)))

        # Swap with server
        resp = self.exchange("", call)

        # Verify nodes that cause crashes if they don't exist
        return self.__verify_profile(resp)

    def verify_gametop_get_mdata(self, jid: int) -> Dict[str, List[Dict[str, Any]]]:
        ret = {}
        for ver in [1, 2, 3]:
            # Construct node
            call = self.call_node()
            gametop = Node.void("gametop")
            call.add_child(gametop)
            gametop.set_attribute("method", "get_mdata")
            retry = Node.s32("retry", 0)
            gametop.add_child(retry)
            data = Node.void("data")
            gametop.add_child(data)
            player = Node.void("player")
            data.add_child(player)
            player.add_child(Node.s32("jid", jid))
            player.add_child(Node.s8("mdata_ver", ver))
            player.add_child(Node.bool("rival", False))

            # Swap with server
            resp = self.exchange("", call)

            # Parse out scores
            self.assert_path(resp, "response/gametop/data/player/mdata_list")

            for musicdata in resp.child("gametop/data/player/mdata_list").children:
                if musicdata.name != "musicdata":
                    raise Exception("Unexpected node in playdata!")

                music_id = musicdata.attribute("music_id")
                scores_by_chart: List[Dict[str, int]] = [{}, {}, {}]

                def extract_cnts(name: str, val: List[int]) -> None:
                    scores_by_chart[0][name] = val[0]
                    scores_by_chart[1][name] = val[1]
                    scores_by_chart[2][name] = val[2]

                extract_cnts("plays", musicdata.child_value("play_cnt"))
                extract_cnts("clears", musicdata.child_value("clear_cnt"))
                extract_cnts("full_combos", musicdata.child_value("fc_cnt"))
                extract_cnts("excellents", musicdata.child_value("ex_cnt"))
                extract_cnts("score", musicdata.child_value("score"))
                extract_cnts("medal", musicdata.child_value("clear"))
                ret[music_id] = scores_by_chart

        return ret

    def verify_gametop_get_meeting(self, jid: int) -> None:
        call = self.call_node()

        # Construct node
        gametop = Node.void("gametop")
        call.add_child(gametop)
        gametop.set_attribute("method", "get_meeting")
        gametop.add_child(Node.s32("retry", 0))
        data = Node.void("data")
        gametop.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.s32("jid", jid))
        pcbinfo = Node.void("pcbinfo")
        gametop.add_child(pcbinfo)
        pcbinfo.set_attribute("client_data_version", "0")

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/gametop/data/meeting/single/@count")
        self.assert_path(resp, "response/gametop/data/meeting/tag/@count")
        self.assert_path(resp, "response/gametop/data/reward/total")
        self.assert_path(resp, "response/gametop/data/reward/point")

    def verify_recommend_get_recommend(self, jid: int) -> None:
        call = self.call_node()

        # Construct node
        recommend = Node.void("recommend")
        call.add_child(recommend)
        recommend.set_attribute("method", "get_recommend")
        recommend.add_child(Node.s32("retry", 0))
        player = Node.void("player")
        recommend.add_child(player)
        player.add_child(Node.s32("jid", jid))
        player.add_child(Node.void("music_list"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/recommend/data/player/music_list")

    def verify_demodata_get_hitchart(self) -> None:
        call = self.call_node()

        # Construct node
        gametop = Node.void("demodata")
        call.add_child(gametop)
        gametop.set_attribute("method", "get_hitchart")

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/demodata/data/update")
        self.assert_path(resp, "response/demodata/data/hitchart_lic")
        self.assert_path(resp, "response/demodata/data/hitchart_org")

    def verify_jbox_get_list(self, jid: int) -> None:
        call = self.call_node()

        # Construct node
        jbox = Node.void("jbox")
        call.add_child(jbox)
        jbox.set_attribute("method", "get_list")
        data = Node.void("data")
        jbox.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.s32("jid", jid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/jbox/selection_list")

    def verify_jbox_get_agreement(self, jid: int) -> None:
        call = self.call_node()

        # Construct node
        jbox = Node.void("jbox")
        call.add_child(jbox)
        jbox.set_attribute("method", "get_agreement")
        data = Node.void("data")
        jbox.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.s32("jid", jid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/jbox/is_agreement")

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
        paseli_enabled = self.verify_pcbtracker_alive(ecflag=3)
        self.verify_package_list()
        self.verify_message_get()
        self.verify_facility_get(encoding="Shift-JIS")
        self.verify_pcbevent_put()
        self.verify_shopinfo_regist()
        self.verify_demodata_get_info()
        self.verify_demodata_get_news()
        self.verify_demodata_get_jbox_list()
        self.verify_demodata_get_hitchart()

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
            self.verify_gametop_regist(card, ref_id)
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
            jid = self.verify_gametop_get_pdata(card, ref_id)
            self.verify_recommend_get_recommend(jid)
            scores = self.verify_gametop_get_mdata(jid)
            self.verify_gametop_get_meeting(jid)
            if scores is None:
                raise Exception("Expected to get scores back, didn't get anything!")
            if len(scores) > 0:
                raise Exception("Got nonzero score count on a new card!")

            # Verify end of game behavior
            self.verify_jbox_get_list(jid)
            self.verify_jbox_get_agreement(jid)
            self.verify_gameend_final(ref_id, jid)

            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 40000059,
                            "chart": 2,
                            "clear": True,
                            "fc": False,
                            "ex": False,
                            "score": 800000,
                            "expected_medal": 0x3,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 40000059,
                            "chart": 1,
                            "clear": True,
                            "fc": True,
                            "ex": False,
                            "score": 990000,
                            "expected_medal": 0x5,
                        },
                        # A perfect score on an easiest chart of the same song
                        {
                            "id": 40000059,
                            "chart": 0,
                            "clear": True,
                            "fc": True,
                            "ex": True,
                            "score": 1000000,
                            "expected_medal": 0x9,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 30000024,
                            "chart": 2,
                            "clear": False,
                            "fc": False,
                            "ex": False,
                            "score": 400000,
                            "expected_medal": 0x1,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 50000045,
                            "chart": 0,
                            "clear": False,
                            "fc": False,
                            "ex": False,
                            "score": 100000,
                            "expected_medal": 0x1,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 50000045,
                            "chart": 0,
                            "clear": True,
                            "fc": False,
                            "ex": False,
                            "score": 850000,
                            "expected_medal": 0x3,
                        },
                        # A worse score on another same chart
                        {
                            "id": 40000059,
                            "chart": 1,
                            "clear": True,
                            "fc": False,
                            "ex": False,
                            "score": 925000,
                            "expected_score": 990000,
                            "expected_medal": 0x7,
                        },
                    ]

                self.verify_gameend_regist(ref_id, jid, dummyscores)
                jid = self.verify_gametop_get_pdata(card, ref_id)
                scores = self.verify_gametop_get_mdata(jid)

                for score in dummyscores:
                    newscore = scores[str(score["id"])][score["chart"]]

                    if "expected_score" in score:
                        expected_score = score["expected_score"]
                    else:
                        expected_score = score["score"]

                    if newscore["score"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got score \'{newscore["score"]}\''
                        )

                    if newscore["medal"] != score["expected_medal"]:
                        raise Exception(
                            f'Expected a medal of \'{score["expected_medal"]}\' for song \'{score["id"]}\' chart \'{score["chart"]}\' but got medal \'{newscore["medal"]}\''
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
