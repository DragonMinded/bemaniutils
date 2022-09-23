import random
import time
from typing import Any, Dict, Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class GitadoraNextageClient(BaseClient):
    NAME = 'ＴＥＳＴ'

    def verify_nextage_shopinfo_regist_request(self, srcid: str) -> None:
        call = self.call_node()

        nextage_shopinfo = Node.void('nextage_shopinfo')
        call.add_child(nextage_shopinfo)
        nextage_shopinfo.set_attribute('method', 'regist')
        
        shop = Node.void('shop')
        nextage_shopinfo.add_child(shop)
        shop.add_child(Node.void('name', 'TEST'))
        shop.add_child(Node.s8('pref', 13))
        shop.add_child(Node.string('systemid', srcid))
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
        self.assert_path(resp, "response/nextage_shopinfo/@status")
        self.assert_path(resp, "response/nextage_shopinfo/data/@cabid")
        self.assert_path(resp, "response/nextage_shopinfo/data/@locationid")
        self.assert_path(resp, "response/nextage_shopinfo/temperature/@is_send")
        self.assert_path(resp, "response/nextage_shopinfo/tax/@tax_phase")

    
        
