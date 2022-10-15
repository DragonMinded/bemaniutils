import random
import time
from typing import Optional, Dict, List, Tuple, Any

from bemani.client.base import BaseClient
from bemani.protocol import Node


class PopnMusicTuneStreetClient(BaseClient):
    NAME = "ＴＥＳＴ"

    def verify_game_active(self) -> None:
        call = self.call_node()

        # Construct node
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "active")

        # Add what Pop'n 19 would add after full unlock
        game.set_attribute("eacoin_price", "200,260,200,200,10")
        game.set_attribute("event", "0")
        game.set_attribute("shop_name_facility", ".")
        game.set_attribute("name", "")
        game.set_attribute("location_id", "JP-1")
        game.set_attribute("shop_addr", "127.0.0.1  10000")
        game.set_attribute("card_use", "0")
        game.set_attribute("testmode", "0,1,1,4,0,-1,2,1,2,100,0,0,80513,0,92510336")
        game.set_attribute("eacoin_available", "1")
        game.set_attribute("pref", "0")
        game.set_attribute("shop_name", "")

        # Swap with server
        resp = self.exchange("pnm/game", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game/@status")

    def verify_game_get(self) -> None:
        call = self.call_node()

        # Construct node
        game = Node.void("game")
        call.add_child(game)
        game.set_attribute("method", "get")

        # Swap with server
        resp = self.exchange("pnm/game", call)

        # Verify that response is correct
        self.assert_path(resp, "response/game")

        for name in [
            "game_phase",
            "boss_battle_point",
            "boss_diff",
            "card_phase",
            "event_phase",
            "gfdm_phase",
            "ir_phase",
            "jubeat_phase",
            "local_matching_enable",
            "matching_sec",
            "netvs_phase",
        ]:
            if name not in resp.child("game").attributes:
                raise Exception(f"Missing attribute '{name}' in response!")

    def verify_playerdata_get(
        self, ref_id: str, msg_type: str
    ) -> Optional[Dict[str, Any]]:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "get")
        playerdata.set_attribute("pref", "50")
        playerdata.set_attribute("shop_name", "")
        playerdata.set_attribute("ref_id", ref_id)

        if msg_type == "new":
            playerdata.set_attribute(
                "model", self.config["old_profile_model"].split(":")[0]
            )

        # Swap with server
        resp = self.exchange("pnm/playerdata", call)

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
            self.assert_path(resp, "response/playerdata/b")
            self.assert_path(resp, "response/playerdata/hiscore")
            self.assert_path(resp, "response/playerdata/town")

            name = (
                resp.child("playerdata")
                .child("b")
                .value[0:12]
                .decode("SHIFT_JIS")
                .replace("\x00", "")
            )
            if name != self.NAME:
                raise Exception(f"Invalid name '{name}' returned for Ref ID '{ref_id}'")

            medals = resp.child("playerdata").child("b").value[108:]
            medals = [
                (medals[x] + (medals[x + 1] << 8)) for x in range(0, len(medals), 2)
            ]

            # Extract and return score data
            def transform_medals(medal: int) -> Tuple[int, int, int, int]:
                return (
                    (medal >> 0) & 0x3,
                    (medal >> 2) & 0x3,
                    (medal >> 4) & 0x3,
                    (medal >> 6) & 0x3,
                )

            medals = [transform_medals(medal) for medal in medals]

            hiscore = resp.child("playerdata").child("hiscore").value
            hiscores = []
            for i in range(0, len(hiscore) * 8, 17):
                byte_offset = int(i / 8)
                bit_offset = int(i % 8)

                try:
                    value = hiscore[byte_offset]
                    value = value + (hiscore[byte_offset + 1] << 8)
                    value = value + (hiscore[byte_offset + 2] << 16)

                    value = value >> bit_offset
                    hiscores.append(value & 0x1FFFF)
                except IndexError:
                    # We indexed poorly above, so we ran into an odd value
                    pass

            scores = [
                (
                    hiscores[x + 1],
                    hiscores[x + 2],
                    hiscores[x + 0],
                    hiscores[x + 3],
                )
                for x in range(0, len(hiscores), 7)
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
        playerdata.set_attribute("last_play_flag", "0")
        playerdata.set_attribute("play_mode", "3")
        playerdata.set_attribute("music_num", "550")
        playerdata.set_attribute("category_num", "14")
        playerdata.set_attribute("norma_point", "0")
        playerdata.set_attribute("medal_and_friend", "0")
        playerdata.set_attribute("option", "131072")
        playerdata.set_attribute("color_3p_flg", "0,0")
        playerdata.set_attribute("sheet_num", "1")
        playerdata.set_attribute("skin_sd_bgm", "0")
        playerdata.set_attribute("read_news_no_max", "0")
        playerdata.set_attribute("shop_name", "")
        playerdata.set_attribute("skin_sd_se", "0")
        playerdata.set_attribute("start_type", "2")
        playerdata.set_attribute("skin_tex_note", "0")
        playerdata.set_attribute("ref_id", ref_id)
        playerdata.set_attribute("chara_num", "12")
        playerdata.set_attribute("jubeat_collabo", "0")
        playerdata.set_attribute("pref", "50")
        playerdata.set_attribute("skin_tex_cmn", "0")

        # Add requested scores
        for score in scores:
            music = Node.void("music")
            playerdata.add_child(music)
            music.set_attribute("norma_r", "0")
            music.set_attribute(
                "data",
                str(
                    {
                        0: ((score["medal"] & 0x3) << 0) | 0x0800,
                        1: ((score["medal"] & 0x3) << 2) | 0x1000,
                        2: ((score["medal"] & 0x3) << 4) | 0x2000,
                        3: ((score["medal"] & 0x3) << 6) | 0x4000,
                    }[score["chart"]]
                ),
            )
            music.set_attribute("select_count", "1")
            music.set_attribute("music_num", str(score["id"]))
            music.set_attribute("norma_l", "0")
            music.set_attribute("score", str(score["score"]))
            music.set_attribute("sheet_num", str(score["chart"]))

        # Swap with server
        self.exchange("pnm/playerdata", call)

    def verify_playerdata_new(self, card_id: str, ref_id: str) -> None:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "new")
        playerdata.set_attribute("ref_id", ref_id)
        playerdata.set_attribute("card_id", card_id)
        playerdata.set_attribute("name", self.NAME)
        playerdata.set_attribute("shop_name", "")
        playerdata.set_attribute("pref", "50")

        # Swap with server
        resp = self.exchange("pnm/playerdata", call)

        # Verify nodes that cause crashes if they don't exist
        self.assert_path(resp, "response/playerdata/b")
        self.assert_path(resp, "response/playerdata/hiscore")
        self.assert_path(resp, "response/playerdata/town")

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
            self.verify_playerdata_new(card, ref_id)
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
                            "medal": 2,
                            "score": 76543,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 987,
                            "chart": 0,
                            "medal": 3,
                            "score": 99999,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 741,
                            "chart": 3,
                            "medal": 1,
                            "score": 45000,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 742,
                            "chart": 1,
                            "medal": 0,
                            "score": 1,
                        },
                    ]
                    # Random score to add in
                    songid = random.randint(907, 950)
                    chartid = random.randint(0, 3)
                    score = random.randint(0, 100000)
                    medal = random.choice([0, 1, 2, 3])
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
                            "medal": 3,
                            "score": 98765,
                        },
                        # A worse score on another same chart
                        {
                            "id": 987,
                            "chart": 0,
                            "medal": 2,
                            "score": 12345,
                            "expected_score": 99999,
                            "expected_medal": 3,
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
