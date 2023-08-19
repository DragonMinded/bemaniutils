import random
import time
from typing import Optional, Dict, List, Tuple, Any

from bemani.client.base import BaseClient
from bemani.common import CardCipher
from bemani.protocol import Node


class JubeatPropClient(BaseClient):
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
        self.assert_path(resp, "response/shopinfo/data/info/bonus_music")
        self.assert_path(resp, "response/shopinfo/data/info/only_now_music")
        self.assert_path(
            resp, "response/shopinfo/data/info/fc_challenge/today/music_id"
        )
        self.assert_path(resp, "response/shopinfo/data/info/white_music_list")
        self.assert_path(resp, "response/shopinfo/data/info/open_music_list")
        self.assert_path(resp, "response/shopinfo/data/info/cabinet_survey/id")
        self.assert_path(resp, "response/shopinfo/data/info/cabinet_survey/status")
        self.assert_path(
            resp, "response/shopinfo/data/info/kaitou_bisco/remaining_days"
        )
        self.assert_path(resp, "response/shopinfo/data/info/league/status")
        self.assert_path(resp, "response/shopinfo/data/info/bistro/bistro_id")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/point")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/emblem/normal/index")
        self.assert_path(resp, "response/shopinfo/data/info/jbox/emblem/premium/index")

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

    def __verify_profile(self, resp: Node) -> int:
        self.assert_path(resp, "response/gametop/data/info/event_info")
        self.assert_path(resp, "response/gametop/data/info/share_music")
        self.assert_path(resp, "response/gametop/data/info/bonus_music")
        self.assert_path(resp, "response/gametop/data/info/only_now_music")
        self.assert_path(resp, "response/gametop/data/info/fc_challenge/today/music_id")
        self.assert_path(resp, "response/gametop/data/info/white_music_list")
        self.assert_path(resp, "response/gametop/data/info/open_music_list")
        self.assert_path(resp, "response/gametop/data/info/cabinet_survey/id")
        self.assert_path(resp, "response/gametop/data/info/cabinet_survey/status")
        self.assert_path(resp, "response/gametop/data/info/kaitou_bisco/remaining_days")
        self.assert_path(resp, "response/gametop/data/info/league/status")
        self.assert_path(resp, "response/gametop/data/info/bistro/bistro_id")
        self.assert_path(resp, "response/gametop/data/info/jbox/point")
        self.assert_path(resp, "response/gametop/data/info/jbox/emblem/normal/index")
        self.assert_path(resp, "response/gametop/data/info/jbox/emblem/premium/index")

        for item in [
            "jubility",
            "jubility_yday",
            "tune_cnt",
            "save_cnt",
            "saved_cnt",
            "fc_cnt",
            "ex_cnt",
            "clear_cnt",
            "pf_cnt",
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
            "new/secret_list",
            "new/theme_list",
            "new/marker_list",
        ]:
            self.assert_path(resp, f"response/gametop/data/player/item/{item}")

        for item in [
            "play_time",
            "shopname",
            "areaname",
            "expert_option",
            "category",
            "sort",
            "music_id",
            "seq_id",
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
            "hazard",
            "hard",
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
        self.assert_path(resp, "response/gametop/data/player/cabinet_survey/read_flag")
        self.assert_path(resp, "response/gametop/data/player/kaitou_bisco/read_flag")
        self.assert_path(resp, "response/gametop/data/player/navi/flag")
        self.assert_path(
            resp, "response/gametop/data/player/fc_challenge/today/music_id"
        )
        self.assert_path(resp, "response/gametop/data/player/fc_challenge/today/state")
        self.assert_path(
            resp, "response/gametop/data/player/fc_challenge/whim/music_id"
        )
        self.assert_path(resp, "response/gametop/data/player/fc_challenge/whim/state")
        self.assert_path(resp, "response/gametop/data/player/news/checked")
        self.assert_path(resp, "response/gametop/data/player/news/checked_flag")
        self.assert_path(resp, "response/gametop/data/player/rivallist")
        self.assert_path(
            resp, "response/gametop/data/player/free_first_play/is_available"
        )
        self.assert_path(resp, "response/gametop/data/player/free_first_play/point")
        self.assert_path(
            resp, "response/gametop/data/player/free_first_play/point_used"
        )
        self.assert_path(
            resp, "response/gametop/data/player/free_first_play/come_come_jbox/is_valid"
        )
        self.assert_path(
            resp,
            "response/gametop/data/player/free_first_play/come_come_jbox/end_time_if_paired",
        )
        self.assert_path(resp, "response/gametop/data/player/jbox/point")
        self.assert_path(resp, "response/gametop/data/player/jbox/emblem/normal/index")
        self.assert_path(resp, "response/gametop/data/player/jbox/emblem/premium/index")
        self.assert_path(resp, "response/gametop/data/player/career/level")
        self.assert_path(resp, "response/gametop/data/player/career/point")
        self.assert_path(resp, "response/gametop/data/player/career/param")
        self.assert_path(resp, "response/gametop/data/player/career/is_unlocked")
        self.assert_path(resp, "response/gametop/data/player/league/is_first_play")
        self.assert_path(resp, "response/gametop/data/player/league/class")
        self.assert_path(resp, "response/gametop/data/player/league/subclass")
        self.assert_path(resp, "response/gametop/data/player/new_music")
        self.assert_path(
            resp, "response/gametop/data/player/eapass_privilege/emblem_list"
        )
        self.assert_path(resp, "response/gametop/data/player/bonus_music/music")
        self.assert_path(resp, "response/gametop/data/player/bonus_music/event_id")
        self.assert_path(resp, "response/gametop/data/player/bonus_music/till_time")
        self.assert_path(resp, "response/gametop/data/player/bistro/chef/id")
        self.assert_path(resp, "response/gametop/data/player/bistro/carry_over")
        self.assert_path(
            resp, "response/gametop/data/player/bistro/route_list/route_count"
        )
        self.assert_path(resp, "response/gametop/data/player/bistro/extension")
        self.assert_path(resp, "response/gametop/data/player/gift_list")

        # Return the jid
        return resp.child_value("gametop/data/player/jid")

    def verify_gameend_regist(
        self,
        ref_id: str,
        jid: int,
        scores: List[Dict[str, Any]],
        course: Dict[str, Any],
        league: Optional[Tuple[int, Tuple[int, int, int]]],
    ) -> None:
        call = self.call_node()

        # Construct node
        gameend = Node.void("gameend")
        call.add_child(gameend)
        gameend.set_attribute("method", "regist")
        gameend.add_child(Node.s32("retry", 0))
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
            tune.set_attribute("count", "0")
            tune.add_child(Node.s32("music", score["id"]))
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

        if len(course) > 0:
            coursenode = Node.void("course")
            player.add_child(coursenode)
            coursenode.add_child(Node.s32("course_id", course["course_id"]))
            coursenode.add_child(Node.u8("rating", course["rating"]))
            index = 0
            for coursescore in course["scores"]:
                music = Node.void("music")
                coursenode.add_child(music)
                music.set_attribute("index", str(index))
                music.add_child(Node.s32("score", coursescore))
                index = index + 1

        if league is not None:
            leaguenode = Node.void("league")
            player.add_child(leaguenode)
            leaguenode.add_child(Node.s32("league_id", league[0]))
            leaguenode.add_child(Node.bool("is_first_play", False))
            leaguenode.add_child(Node.bool("is_checked", True))

            index = 0
            for leaguescore in league[1]:
                musicnode = Node.void("music")
                leaguenode.add_child(musicnode)
                musicnode.set_attribute("index", str(index))
                index = index + 1

                scorenode = Node.s32("score", leaguescore)
                musicnode.add_child(scorenode)
                scorenode.set_attribute("clear", "3")

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/gameend/data/player/session_id")

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

    def verify_gametop_get_course(self, jid: int) -> List[Dict[str, Any]]:
        call = self.call_node()

        # Construct node
        gametop = Node.void("gametop")
        call.add_child(gametop)
        gametop.set_attribute("method", "get_course")
        gametop.add_child(Node.s32("retry", 0))
        data = Node.void("data")
        gametop.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.s32("jid", jid))

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/gametop/data/course_list")
        self.assert_path(resp, "response/gametop/data/player_list")
        self.assert_path(resp, "response/gametop/data/last_course_id")

        playernode = None
        for player in resp.child("gametop/data/player_list").children:
            if player.child_value("jid") == jid:
                playernode = player
                break

        if playernode is None:
            raise Exception(f"Didn't find any scores for ExtID {jid}")

        ret = []
        for result in playernode.child("result_list").children:
            if result.name != "result":
                raise Exception("Unexpected node in result_list!")

            course_id = result.child_value("id")
            rating = result.child_value("rating")
            scores = result.child_value("score")

            ret.append({"course_id": course_id, "rating": rating, "scores": scores})

        return ret

    def verify_gametop_get_league(self, jid: int) -> Tuple[int, Tuple[int, int, int]]:
        call = self.call_node()

        # Construct node
        gametop = Node.void("gametop")
        call.add_child(gametop)
        gametop.set_attribute("method", "get_league")
        gametop.add_child(Node.s32("retry", 0))
        data = Node.void("data")
        gametop.add_child(data)
        player = Node.void("player")
        data.add_child(player)
        player.add_child(Node.s32("jid", jid))
        player.add_child(Node.s32_array("rival_jid", [0] * 3))

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/gametop/data/league_list/league/player_list")
        self.assert_path(resp, "response/gametop/data/last_class")
        self.assert_path(resp, "response/gametop/data/last_subclass")
        self.assert_path(resp, "response/gametop/data/is_checked")

        leagueid = resp.child_value("gametop/data/league_list/league/id")
        playernode = None
        for player in resp.child(
            "gametop/data/league_list/league/player_list"
        ).children:
            if player.child_value("jid") == jid:
                playernode = player
                break

        if playernode is None:
            raise Exception(f"Didn't find any scores for ExtID {jid}")

        result = playernode.child_value("result/score")
        if result is not None:
            return (leagueid, (result[0], result[1], result[2]))
        else:
            return (leagueid, (0, 0, 0))

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

        # Swap with server
        resp = self.exchange("", call)

        # Verify expected nodes
        self.assert_path(resp, "response/gametop/data/meeting/single")
        self.assert_path(resp, "response/gametop/data/meeting/tag")
        self.assert_path(resp, "response/gametop/data/reward/total")
        self.assert_path(resp, "response/gametop/data/reward/point")

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
        self.verify_shopinfo_regist()
        self.verify_demodata_get_news()
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
            scores = self.verify_gametop_get_mdata(jid)
            courses = self.verify_gametop_get_course(jid)
            league = self.verify_gametop_get_league(jid)
            self.verify_gametop_get_meeting(jid)
            if scores is None:
                raise Exception("Expected to get scores back, didn't get anything!")
            if courses is None:
                raise Exception("Expected to get courses back, didn't get anything!")
            if league is None:
                raise Exception("Expected to get league back, didn't get anything!")
            if len(scores) > 0:
                raise Exception("Got nonzero score count on a new card!")
            if len(courses) > 0:
                raise Exception("Got nonzero course count on a new card!")
            if league[1][0] != 0 or league[1][1] != 0 or league[1][2] != 0:
                raise Exception("Got nonzero league score on a new card!")

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

                self.verify_gameend_regist(ref_id, jid, dummyscores, {}, None)
                jid = self.verify_gametop_get_pdata(card, ref_id)
                scores = self.verify_gametop_get_mdata(jid)
                courses = self.verify_gametop_get_course(jid)
                league = self.verify_gametop_get_league(jid)
                if len(courses) > 0:
                    raise Exception(
                        "Got nonzero course count without playing any courses!"
                    )
                if league[1][0] != 0 or league[1][1] != 0 or league[1][2] != 0:
                    raise Exception(
                        "Got nonzero league count without playing any league!"
                    )

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

            for phase in [1, 2]:
                dummycourses: List[Dict[str, Any]] = []
                if phase == 1:
                    dummycourses.extend(
                        [
                            {
                                "course_id": 1,
                                "rating": 1,
                                "scores": [123456, 123457, 123458, 123459, 123460],
                            },
                            {
                                "course_id": 2,
                                "rating": 2,
                                "scores": [123456, 123457, 123458, 123459, 123460],
                            },
                        ]
                    )
                else:
                    dummycourses.extend(
                        [
                            {
                                "course_id": 1,
                                "rating": 2,
                                "scores": [223456, 223457, 223458, 223459, 223460],
                            },
                            {
                                "course_id": 2,
                                "rating": 1,
                                "expected_rating": 2,
                                "scores": [23456, 23457, 23458, 23459, 23460],
                                "expected_scores": [
                                    123456,
                                    123457,
                                    123458,
                                    123459,
                                    123460,
                                ],
                            },
                        ]
                    )

                for course in dummycourses:
                    self.verify_gameend_regist(ref_id, jid, [], course, None)
                jid = self.verify_gametop_get_pdata(card, ref_id)
                courses = self.verify_gametop_get_course(jid)

                for course in dummycourses:
                    # Find the course
                    foundcourses = [
                        c for c in courses if c["course_id"] == course["course_id"]
                    ]

                    if len(foundcourses) == 0:
                        raise Exception(
                            f"Didn't find course by ID {course['course_id']}"
                        )
                    foundcourse = foundcourses[0]

                    if "expected_rating" in course:
                        expected_rating = course["expected_rating"]
                    else:
                        expected_rating = course["rating"]

                    if "expected_scores" in course:
                        expected_scores = course["expected_scores"]
                    else:
                        expected_scores = course["scores"]

                    if foundcourse["course_id"] != course["course_id"]:
                        raise Exception("Logic error!")

                    if foundcourse["rating"] != expected_rating:
                        raise Exception(
                            f'Expected a rating of \'{expected_rating}\' for course \'{course["course_id"]}\' but got rating \'{foundcourse["rating"]}\''
                        )

                    for i in range(len(expected_scores)):
                        if foundcourse["scores"][i] != expected_scores[i]:
                            raise Exception(
                                f'Expected a score of \'{expected_scores[i]}\' for course \'{course["course_id"]}\' song number \'{i}\' but got score \'{foundcourse["scores"][i]}\''
                            )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)

            # Play a league course, save the score
            self.verify_gameend_regist(
                ref_id, jid, [], {}, (league[0], (123456, 234567, 345678))
            )
            jid = self.verify_gametop_get_pdata(card, ref_id)
            league = self.verify_gametop_get_league(jid)

            if (
                league[1][0] != 123456
                or league[1][1] != 234567
                or league[1][2] != 345678
            ):
                raise Exception(
                    f"League score didn\t save! Got wrong values {league[1][0]}, {league[1][1]}, {league[1][2]} back!"
                )

            # Play a league course, do worse, make sure it doesn't overwrite
            self.verify_gameend_regist(
                ref_id, jid, [], {}, (league[0], (12345, 23456, 34567))
            )
            jid = self.verify_gametop_get_pdata(card, ref_id)
            league = self.verify_gametop_get_league(jid)

            if (
                league[1][0] != 123456
                or league[1][1] != 234567
                or league[1][2] != 345678
            ):
                raise Exception(
                    f"League score got overwritten! Got wrong values {league[1][0]}, {league[1][1]}, {league[1][2]} back!"
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
