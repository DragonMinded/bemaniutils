import random
import base64
from typing import List, Optional

from bemani.backend.ddr.ddrsn2 import PlayerInfoStruct, ScoreInfoStruct
from bemani.client import BaseClient
from bemani.protocol import Node

class DDRSN2MusicRecord:
    def __init__(self, combo_length: int, full_combo: bool, song_id: int, mode: int, perfect_combo: bool, rank: int, score: int) -> None:
        self.combo_length = combo_length
        self.full_combo = full_combo
        self.song_id = song_id
        self.mode = mode
        self.perfect_combo = perfect_combo
        self.rank = rank
        self.score = score

    def to_node(self) -> Node:
        music = Node.void("music")
        music.set_attribute("combo", str(self.combo_length))
        music.set_attribute("full", "1" if self.full_combo else "0")
        music.set_attribute("id", str(self.song_id))
        music.set_attribute("mode", str(self.mode))
        music.set_attribute("perf", "1" if self.perfect_combo else "0")
        music.set_attribute("rank", str(self.rank))
        music.set_attribute("score", str(self.score // 10))

        return music

class DDRSN2GameRecord:
    def __init__(self, calories: int, exp: int, gr1: int, gr2: int, gr3: int, gr4: int, gr5: int, mode: int, music: int, sort: int, type: int, weight: int):
        self.calories = calories
        self.exp = exp
        self.gr1 = gr1
        self.gr2 = gr2
        self.gr3 = gr3
        self.gr4 = gr4
        self.gr5 = gr5
        self.mode = mode
        self.music = music
        self.sort = sort
        self.type = type
        self.weight = weight

    def to_node(self) -> Node:
        game = Node.void("game")
        game.set_attribute("calories", str(self.calories))
        game.set_attribute("cate", "0")
        game.set_attribute("cpos", "0")
        game.set_attribute("ctype", "0")
        game.set_attribute("exp", str(self.exp))
        game.set_attribute("gr1", str(self.gr1))
        game.set_attribute("gr2", str(self.gr2))
        game.set_attribute("gr3", str(self.gr3))
        game.set_attribute("gr4", str(self.gr4))
        game.set_attribute("gr5", str(self.gr5))
        game.set_attribute("mode", str(self.mode))
        game.set_attribute("music", str(self.music))
        game.set_attribute("npos", "0")
        game.set_attribute("ntype", "0")
        game.set_attribute("sort", str(self.sort))
        game.set_attribute("type", str(self.type))
        game.set_attribute("weight", str(self.weight))

        return game



class DDRSN2Client(BaseClient):
    NAME = "TEST"

    def verify_info_tenpo(self):
        call = self.call_node()
        info = Node.void('info')
        call.add_child(info)
        info.set_attribute('area', '0')
        info.set_attribute('coin', '02.01.--.--.01.')
        info.set_attribute('diff', '3')
        info.set_attribute('during', '1')
        info.set_attribute('first', '1')
        info.set_attribute('ip', '192.0.2.100')
        info.set_attribute('lancher', '2.4.1:20070608-0')
        info.set_attribute('loc', 'US-1')
        info.set_attribute('mac', '00:00:00:00:00:00')
        info.set_attribute('method', 'tenpo')
        info.set_attribute('name', '.')
        info.set_attribute('netid', '014014000001030405D8')
        info.set_attribute('pcbid', self.pcbid)
        info.set_attribute('region', '')
        info.set_attribute('shop', '００Ｍｉ')
        info.set_attribute('soft', self.config["model"])
        info.set_attribute('stage', '3')
        info.set_attribute('ver', '1')

        resp = self.exchange("core/info", call)
        self.assert_path(resp, "response/tenpo/@status")

    def verify_info_message(self):
        call = self.call_node()
        info = Node.void('info')
        call.add_child(info)
        info.set_attribute("method", "message")
        info.set_attribute("ver", "1")

        resp = self.exchange("core/info", call)
        self.assert_path(resp, "response/info/@md5c")
        self.assert_path(resp, "response/info/b")

    def verify_info_ranking(self):
        call = self.call_node()
        info = Node.void('info')
        call.add_child(info)
        info.set_attribute("method", "ranking")
        info.set_attribute("ver", "1")

        resp = self.exchange("core/info", call)
        self.assert_path(resp, "response/ranking")

    def verify_player_common(self):
        call = self.call_node()
        player = Node.void('player')
        call.add_child(player)
        player.set_attribute("event", "1")
        player.set_attribute("method", "common")
        player.set_attribute("pcbid", self.pcbid)
        player.set_attribute("ver", "1")

        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@md5c")
        self.assert_path(resp, "response/player/b")

    def verify_player_new(self, ref_id: str) -> None:
        call = self.call_node()
        player = Node.void('player')
        call.add_child(player)
        player.set_attribute('area', '11')
        player.set_attribute('method', 'new')
        player.set_attribute('name', f'{self.NAME}&#32;&#32;&#32;&#32;')
        player.set_attribute('pcbid', self.pcbid)
        player.set_attribute('ref_id', ref_id)
        player.set_attribute('ver', '1')

        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@status")
        self.assert_path(resp, "response/player/result")

    def verify_player_get(self, ref_id: str) -> (PlayerInfoStruct, ScoreInfoStruct, ScoreInfoStruct):
        call = self.call_node()
        player = Node.void('player')
        call.add_child(player)
        player.set_attribute('method', 'get')
        player.set_attribute('part', '0')
        player.set_attribute('ref_id', ref_id)
        player.set_attribute('ver', '1')

        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@md5c")
        self.assert_path(resp, "response/player/b")
        chunk0 = base64.b64decode(resp.child_value("player/b"))

        player.set_attribute('part', '1')
        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@md5c")
        self.assert_path(resp, "response/player/b")
        chunk1 = base64.b64decode(resp.child_value("player/b"))

        player.set_attribute('part', '2')
        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@md5c")
        self.assert_path(resp, "response/player/b")
        chunk2 = base64.b64decode(resp.child_value("player/b"))

        player_info = PlayerInfoStruct.from_buffer_copy(chunk0)
        score_info_part_1 = ScoreInfoStruct.from_buffer_copy(chunk1)
        score_info_part_2 = ScoreInfoStruct.from_buffer_copy(chunk2)

        return player_info, score_info_part_1, score_info_part_2

    def verify_player_touch(self):
        call = self.call_node()
        player = Node.void('player')
        call.add_child(player)
        player.set_attribute('err', '0')
        player.set_attribute('method', 'touch')
        player.set_attribute('mode', '2')
        player.set_attribute('pcbid', self.pcbid)
        player.set_attribute('style', '0')
        player.set_attribute('type', '1')
        player.set_attribute('ver', '1')

        resp = self.exchange("core/player", call)
        self.assert_path(resp, "response/player/@status")

    def verify_player_set(self, ref_id: str, music_records: List[DDRSN2MusicRecord], game_record: DDRSN2GameRecord) -> None:
        call = self.call_node()
        player = Node.void('player')
        call.add_child(player)
        player.set_attribute('method', 'set')
        player.set_attribute("pcbid", self.pcbid)
        player.set_attribute("ref_id", ref_id)
        player.set_attribute("ver", "1")

        for m in music_records:
            player.add_child(m.to_node())

        player.add_child(game_record.to_node())

        opt = Node.void('opt')
        player.add_child(opt)
        opt.set_attribute("opt1", "3")
        opt.set_attribute("opt2", "0")
        opt.set_attribute("opt3", "0")
        opt.set_attribute("opt4", "0")
        opt.set_attribute("opt5", "0")
        opt.set_attribute("opt6", "0")
        opt.set_attribute("opt7", "0")
        opt.set_attribute("opt8", "0")
        opt.set_attribute("opt9", "1")
        opt.set_attribute("opt10", "1")
        opt.set_attribute("opt11", "0")
        opt.set_attribute("opt12", "2")
        opt.set_attribute("opt13", "2")
        opt.set_attribute("opt14", "0")
        opt.set_attribute("opt15", "0")
        opt.set_attribute("opt16", "0")

        flag = Node.void('flag')
        player.add_child(flag)
        flag.set_attribute("off", "48")

        resp = self.exchange("core/player", call)

        self.assert_path(resp, "response/player/@status")
        self.assert_path(resp, "response/player/result")

    def verify(self, cardid: Optional[str]) -> None:

        self.verify_services_get(
            expected_services=[
                "cardmng",
                "dlstatus",
                "eacoin",
                "facility",
                "lobby",
                "local",
                "message",
                "package",
                "pcbevent",
                "pcbtracker",
                "pkglist",
                "posevent",
                "local2",
                "ntp",
                "keepalive"
            ]
        )

        paseli_enabled = self.verify_pcbtracker_alive()
        self.verify_message_get()
        self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_info_tenpo()
        self.verify_info_message()
        self.verify_info_ranking()
        self.verify_player_common()

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
            self.verify_player_new(ref_id)
            self.verify_player_get(ref_id)

        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)
            self.verify_player_get(ref_id)

        self.verify_player_touch()
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        if cardid is None:
            # Verify empty profile
            (player_info, scores1, scores2) = self.verify_player_get(ref_id)
            if player_info is None:
                raise Exception(f"Player info should not be None")
            if player_info.name.decode("euc-jp").strip() != self.NAME:
                raise Exception(f"Player info name should be {self.NAME} not {player_info.name}")
            if player_info.count != 0:
                raise Exception("Player info has plays on single already!")
            if player_info.count_b != 0:
                raise Exception("Player info has plays on battle already!")
            if any([g != 0 for g in player_info.groove_radar]):
                raise Exception("Player info has groove radar values already!")

            for s in scores1.records:
                if s.beginner.score != 0 or s.beginner.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.basic.score != 0 or s.basic.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.difficult.score != 0 or s.difficult.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.expert.score != 0 or s.expert.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.challenge.score != 0 or s.challenge.lo_score != 0:
                    raise Exception("Player info has scores already!")

            for s in scores2.records:
                if s.beginner.score != 0 or s.beginner.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.basic.score != 0 or s.basic.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.difficult.score != 0 or s.difficult.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.expert.score != 0 or s.expert.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.challenge.score != 0 or s.challenge.lo_score != 0:
                    raise Exception("Player info has scores already!")


            # Write scores and verify saving
            music_records = [DDRSN2MusicRecord(78, False, 316, 2, False, 3, 751030),
                             DDRSN2MusicRecord(34, False, 305, 2, False, 4, 625140),
                             DDRSN2MusicRecord(64, False, 2, 2, False, 4, 716040)]

            game_record = DDRSN2GameRecord(32837, 56, 2583, 1012, 680, 239, 181, 2, 2, 1, 2, 333)

            self.verify_player_set(ref_id, music_records, game_record)

            (player_info, scores1, scores2) = self.verify_player_get(ref_id)
            if player_info is None:
                raise Exception(f"Player info should not be None")
            if player_info.name.decode("euc-jp").strip() != self.NAME:
                raise Exception(f"Player info name should be {self.NAME} not {player_info.name}")
            if player_info.count != 1:
                raise Exception("Player info should have incremented count!")
            if player_info.count_b != 0:
                raise Exception("Player info has plays on battle!")
            if player_info.groove_radar[0] != 2583:
                raise Exception("Player info has unexpected groove radar!")
            if player_info.groove_radar[1] != 1012:
                raise Exception("Player info has unexpected groove radar!")
            if player_info.groove_radar[2] != 680:
                raise Exception("Player info has unexpected groove radar!")
            if player_info.groove_radar[3] != 239:
                raise Exception("Player info has unexpected groove radar!")
            if player_info.groove_radar[4] != 181:
                raise Exception("Player info has unexpected groove radar!")

            # Verify score set
            if scores2.records[116].difficult.score == 0 or scores2.records[105].difficult.score == 0 or scores1.records[2].difficult.score == 0:
                raise Exception("Player info has unexpected scores!")

            # Verify other scores unset
            for i, s in enumerate(scores1.records):
                if i == 2:
                    continue
                if s.beginner.score != 0 or s.beginner.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.basic.score != 0 or s.basic.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.difficult.score != 0 or s.difficult.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.expert.score != 0 or s.expert.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.challenge.score != 0 or s.challenge.lo_score != 0:
                    raise Exception("Player info has scores already!")

            for i, s in enumerate(scores2.records):
                if i == 116 or i == 105:
                    continue
                if s.beginner.score != 0 or s.beginner.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.basic.score != 0 or s.basic.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.difficult.score != 0 or s.difficult.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.expert.score != 0 or s.expert.lo_score != 0:
                    raise Exception("Player info has scores already!")
                if s.challenge.score != 0 or s.challenge.lo_score != 0:
                    raise Exception("Player info has scores already!")

        else:
            print("Skipping score checks for existing card")

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




