import random
import time
from typing import Any, Dict, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class GitadoraNextageClient(BaseClient):
    NAME = 'ＴＥＳＴ'

    def verify_nextage_shopinfo_regist_request(self) -> None:
        call = self.call_node()

        nextage_shopinfo = Node.void('nextage_shopinfo')
        call.add_child(nextage_shopinfo)
        nextage_shopinfo.set_attribute('method', 'regist')
        
        shop = Node.void('shop')
        nextage_shopinfo.add_child(shop)
        shop.add_child(Node.void('name', 'TEST'))
        shop.add_child(Node.s8('pref', 13))
        shop.add_child(Node.string('systemid', self.pcbid))
        shop.add_child(Node.string('softwareid', '04040000000000000000'))
        shop.add_child(Node.string('hardwareid', '0100DEADBEEF'))
        shop.add_child(Node.string('locationid', 'JP-1'))
        testmode = Node.void('testmode')
        nextage_shopinfo.add_child(testmode)
        sound_option = Node.void('sound_option')
        testmode.add_child(sound_option)
        sound_option.add_child(Node.s32('volume_bgm', 20))
        sound_option.add_child(Node.s32('volume_se_myself', 20))
        sound_option.add_child(Node.s32('volume_woofer', 80))
        sound_option.add_child(Node.s32('volume_se_partner', 90))
        sound_option.add_child(Node.s32('volume_in_attract', 100))
        game_option = Node.void('game_option')
        testmode.add_child(game_option)
        stand_alone = Node.void('stand_alone')
        game_option.add_child(stand_alone)
        stand_alone.add_child(Node.s32('difficulty', 3))
        stand_alone.add_child(Node.s32('eventmode_playstage', 3))
        session = Node.void('session')
        game_option.add_child(session)
        session.add_child(Node.s32('difficulty', 3))
        session.add_child(Node.s32('eventmode_playstage', 3))
        session.add_child(Node.s32('joining_period', 15))
        game = Node.void('game')
        game_option.add_child(game)
        game.add_child(Node.s32('close_set', 0))
        game.add_child(Node.s32('close_time', 0))
        display = Node.void('display')
        game_option.add_child(display)
        display.add_child(Node.s32('display_type', 0))
        coin_option = Node.void('coin_option')
        testmode.add_child(coin_option)
        coin_option.add_child(Node.s32('free_play', 0))
        coin_option.add_child(Node.s32('coin_slot', 8))
        coin_option.add_child(Node.s32('start_light_play', 1))
        coin_option.add_child(Node.s32('first_play_free', 1))
        bookkeeping = Node.void('bookkeeping')
        testmode.add_child(bookkeeping)
        bookkeeping.add_child(Node.s32('enable', 0))
        clock = Node.void('clock')
        testmode.add_child(clock)
        clock.add_child(Node.s32('enable', 0))
        clock.add_child(Node.s32('offset', 0))
        virtual_coin = Node.void('virtual_coin')
        testmode.add_child(virtual_coin)
        tax = Node.void('tax')
        virtual_coin.add_child(tax)
        tax.add_child(Node.s32('tax_phase', 2))
        tax.add_child(Node.s32('tax_mode', 1))
        pattern1 = Node.void('pattern1')
        virtual_coin.add_child(pattern1)
        pattern1.add_child(Node.s32('basic_rate', 1000))
        pattern1.add_child(Node.s32('balance_of_credit', 1))
        pattern1.add_child(Node.s32('is_premium_start', 0))
        pattern1.add_child(Node.s32('service_value', 10))
        pattern1.add_child(Node.s32('service_limit', 10))
        pattern1.add_child(Node.s32('service_time_start_h', 7))
        pattern1.add_child(Node.s32('service_time_start_m', 0))
        pattern1.add_child(Node.s32('service_time_end_h', 11))
        pattern1.add_child(Node.s32('service_time_end_m', 0))
        pattern2 = Node.void('pattern2')
        virtual_coin.add_child(pattern2)
        pattern2.add_child(Node.s32('basic_rate', 1000))
        pattern2.add_child(Node.s32('balance_of_credit', 1))
        pattern2.add_child(Node.s32('is_premium_start', 0))
        pattern2.add_child(Node.s32('service_value', 10))
        pattern2.add_child(Node.s32('service_limit', 10))
        pattern2.add_child(Node.s32('service_time_start_h', 7))
        pattern2.add_child(Node.s32('service_time_start_m', 0))
        pattern2.add_child(Node.s32('service_time_end_h', 11))
        pattern2.add_child(Node.s32('service_time_end_m', 0))
        pattern3 = Node.void('pattern3')
        virtual_coin.add_child(pattern3)
        pattern3.add_child(Node.s32('basic_rate', 1000))
        pattern3.add_child(Node.s32('balance_of_credit', 1))
        pattern3.add_child(Node.s32('is_premium_start', 0))
        pattern3.add_child(Node.s32('service_value', 10))
        pattern3.add_child(Node.s32('service_limit', 10))
        pattern3.add_child(Node.s32('service_time_start_h', 7))
        pattern3.add_child(Node.s32('service_time_start_m', 0))
        pattern3.add_child(Node.s32('service_time_end_h', 11))
        pattern3.add_child(Node.s32('service_time_end_m', 0))
        schedule = Node.void('schedule')
        virtual_coin.add_child(schedule)
        schedule.add_child(Node.s32('mon', 1))
        schedule.add_child(Node.s32('tue', 1))
        schedule.add_child(Node.s32('wed', 1))
        schedule.add_child(Node.s32('thu', 1))
        schedule.add_child(Node.s32('fri', 1))
        schedule.add_child(Node.s32('sat', 1))
        schedule.add_child(Node.s32('sun', 1))
        schedule.add_child(Node.s32('holi', 1))

        # Swap with server
        resp = self.exchange('', call)

        # Verify that response is correct
        self.assert_path(resp, "response/nextage_shopinfo/data/cabid")
        self.assert_path(resp, "response/nextage_shopinfo/data/locationid")
        self.assert_path(resp, "response/nextage_shopinfo/temperature/is_send")
        self.assert_path(resp, "response/nextage_shopinfo/tax/tax_phase")

    def verify_nextage_gameinfo_get(self) -> None:
        call = self.call_node()

        nextage_gameinfo = Node.void('nextage_gameinfo')
        call.add_child(nextage_gameinfo)
        nextage_gameinfo.set_attribute('method', 'get')

        shop = Node.void('shop')
        nextage_gameinfo.add_child(shop)
        shop.add_child(Node.string('locationid', 'JP-146'))
        shop.add_child(Node.u32('cabid', 1))
        shop.add_child(Node.s32('data_version', 158))
        temperature = Node.void('temperature')
        nextage_gameinfo.add_child(temperature)
        temperature.add_child(Node.bool('is_send', False))
        online_update = Node.void('online_update')
        nextage_gameinfo.add_child(online_update)
        online_update.add_child(Node.s32('nr_package', 0))
        online_update.add_child(Node.s32('nr_done_package', 0))
        online_update.add_child(Node.s32('progress', 0))
        online_update.add_child(Node.bool('is_onlineupdate_ready', False))

        # Swap with server
        resp = self.exchange('', call)

        # Verify that response is correct
        self.assert_path(resp, "response/nextage_gameinfo/now_date")
        self.assert_path(resp, "response/nextage_gameinfo/extra")
        self.assert_path(resp, "response/nextage_gameinfo/infect_music")
        self.assert_path(resp, "response/nextage_gameinfo/unlock_challenge")
        self.assert_path(resp, "response/nextage_gameinfo/ranking")
        self.assert_path(resp, "response/nextage_gameinfo/recommendmusic")
        self.assert_path(resp, "response/nextage_gameinfo/demomusic")
        self.assert_path(resp, "response/nextage_gameinfo/general_term")
        self.assert_path(resp, "response/nextage_gameinfo/lotterybox")
        self.assert_path(resp, "response/nextage_gameinfo/assert_report_state")

    def verify_nextage_playablemusic(self) -> None:
        call = self.call_node()

        nextage_playablemusic = Node.void('nextage_playablemusic')
        call.add_child(nextage_playablemusic)
        nextage_playablemusic.set_attribute('method', 'get')

        nextage_playablemusic.add_child(Node.s32('data_version', 158))
        data = Node.void('data')
        nextage_playablemusic.add_child(data)
        data.add_child(Node.bool('flag', True))

        # Swap with server
        resp = self.exchange('', call)

        # Verify that response is correct
        self.assert_path(resp, "response/nextage_playablemusic/hot")
        self.assert_path(resp, "response/nextage_playablemusic/musicinfo")

    def verify_nextage_gametop(self) -> None:
        call = self.call_node()

        nextage_gametop = Node.void('nextage_gametop')
        nextage_gametop.set_attribute('method', 'get')
        player = Node.void('player')
        nextage_gametop.add_child(player)
        player.set_attribute('no', '1')
        player.add_child(Node.string('refid', '7C2DB3AE506A966E'))
        player.add_child(Node.s32('cabid', 1))
        player.add_child(Node.bool('is_rival', False))
        request = Node.void('request')
        player.add_child(request)
        request.add_child(Node.u8('kind', 0))
        request.add_child(Node.u16('offset', 0))
        request.add_child(Node.u16('music_nr', 1500))

        # Swap with server
        resp = self.exchange('', call)

        # Verify that response is correct
        self.assert_path(resp, "response/nextage_gametop/player/playerboard")
        self.assert_path(resp, "response/nextage_gametop/player/player_info")
        self.assert_path(resp, "response/nextage_gametop/player/playinfo")
        self.assert_path(resp, "response/nextage_gametop/player/customdata")
        self.assert_path(resp, "response/nextage_gametop/player/skilldata")
        self.assert_path(resp, "response/nextage_gametop/player/favoritemusic")
        self.assert_path(resp, "response/nextage_gametop/player/chara_list")
        self.assert_path(resp, "response/nextage_gametop/player/title_parts")
        self.assert_path(resp, "response/nextage_gametop/player/information")
        self.assert_path(resp, "response/nextage_gametop/player/player_info")
        self.assert_path(resp, "response/nextage_gametop/player/groove")
        self.assert_path(resp, "response/nextage_gametop/player/reward")
        self.assert_path(resp, "response/nextage_gametop/player/skindata")
        self.assert_path(resp, "response/nextage_gametop/player/tutorial")
        self.assert_path(resp, "response/nextage_gametop/player/rivaldata")
        self.assert_path(resp, "response/nextage_gametop/player/frienddata")
        self.assert_path(resp, "response/nextage_gametop/player/tutorial")
        self.assert_path(resp, "response/nextage_gametop/player/record/gf")
        self.assert_path(resp, "response/nextage_gametop/player/record/dm")
        self.assert_path(resp, "response/nextage_gametop/player/battledata")
        self.assert_path(resp, "response/nextage_gametop/player/is_free_ok")
        self.assert_path(resp, "response/nextage_gametop/player/ranking")
        self.assert_path(resp, "response/nextage_gametop/player/stage_result")
        self.assert_path(resp, "response/nextage_gametop/player/musiclist")

    def verify_nextage_cardutil_check(self, card_id: str) -> None:
        call = self.call_node()

        nextage_cardutil = Node.void('nextage_nextage_cardutil')
        nextage_cardutil.set_attribute('method', 'check')
        data_version = Node.s32('data_version', 158)
        nextage_cardutil.add_child(data_version)
        player = Node.void('player')
        player.set_attribute('no', '1')
        nextage_cardutil.add_child(player)
        refid = Node.string('refid', card_id)
        player.add_child(refid)

        # Swap with server
        resp = self.exchange('', call)

        self.assert_path(resp, "response/nextage_cardutil")

    def verify(self, cardid: Optional[str]) -> None:
        # Verify boot sequence is okay
        self.verify_services_get(
            expected_services=[
                "pcbtracker",
                "pcbevent",
                "message",
                "facility",
                "cardmng",
                "package",
                "posevent",
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
        self.verify_pcbevent_put()
        self.verify_facility_get()
        self.verify_nextage_gameinfo_get()
        self.verify_nextage_shopinfo_regist_request()
        self.verify_nextage_playablemusic()
        self.verify_nextage_gametop()

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
            self.verify_nextage_cardutil_check(card)
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(
                card, msg_type="query", paseli_enabled=paseli_enabled
            )

        # Verify paseli handling
        if paseli_enabled:
            print("PASELI enabled for this PCBID, executing PASELI checks")
        else:
            print("PASELI disabled for this PCBID, skipping PASELI checks")
            return

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(
            card, msg_type="query", paseli_enabled=paseli_enabled
        ):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

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
