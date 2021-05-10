import binascii
import copy
import base64
from collections import Iterable
from typing import Optional, Any, Dict, List, Sequence, Union, Tuple

from bemani.backend.dm.base import DrummaniaBase
from bemani.backend.ess import EventLogHandler
from bemani.common import ValidatedDict, GameConstants, VersionConstants, Time, ID, intish
from bemani.data import UserID, Score, Data
from bemani.protocol import Node

from bemani.backend.dm.stubs import DrummaniaV7

class DrummaniaV8(
    EventLogHandler,
    DrummaniaBase,
):

    name = "Drummania V8"
    version = VersionConstants.DRUMMANIA_V8

    GAME_LIMITED_LOCKED = 1
    GAME_LIMITED_UNLOCKED = 2

    GAME_CURRENCY_PACKETS = 0
    GAME_CURRENCY_BLOCKS = 1

    GAME_CLEAR_TYPE_NO_CLEAR = 1
    GAME_CLEAR_TYPE_CLEAR = 2
    GAME_CLEAR_TYPE_FULL_COMBO = 3

    GAME_CHART_TYPE_BEGINNER = 0
    GAME_CHART_TYPE_BASIC = 1
    GAME_CHART_TYPE_ADVANCED = 2
    GAME_CHART_TYPE_EXTREME = 3

    GAME_GRADE_NO_PLAY = 0
    GAME_GRADE_D = 1
    GAME_GRADE_C = 2
    GAME_GRADE_B = 3
    GAME_GRADE_A = 4
    GAME_GRADE_AA = 5
    GAME_GRADE_AAA = 6
    GAME_GRADE_S = 7

    @classmethod

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV7(self.data, self.config, self.model)

    def db_to_game_chart(self, db_chart: int) -> int:
        return {
            self.CHART_TYPE_BEGINNER: self.GAME_CHART_TYPE_BEGINNER,
            self.CHART_TYPE_BASIC: self.GAME_CHART_TYPE_BASIC,
            self.CHART_TYPE_ADVANCED: self.GAME_CHART_TYPE_ADVANCED,
            self.CHART_TYPE_EXTREME: self.GAME_CHART_TYPE_EXTREME,
        }[db_chart]

    def handle_shopinfo_regist_request(self, request: Node) -> Node:
        # fuck
        self.update_machine_name(request.child_value('shop/name'))

        shopinfo = Node.void('shopinfo')

        data = Node.void('data')
        shopinfo.add_child(data)
        data.add_child(Node.u32('cabid', 1))
        data.add_child(Node.string('locationid', 'LOCATION'))
        data.add_child(Node.u8('is_send', 1))

        return shopinfo

    def handle_demodata_get_request(self, request: Node) -> Node:
        root = Node.void('demodata')
        mode = Node.u8('mode', 1)
        root.add_child(mode)

        hitchart = Node.void('hitchart')
        root.add_child(hitchart)
        hitchart.set_attribute('nr', '0')

        hitchart.add_child(Node.string('start', "0"))
        hitchart.add_child(Node.string('end', "0"))


        bossdata = Node.void('bossdata')
        root.add_child(bossdata)

        bossdata.add_child(Node.u8('division', 15))
        border = Node.u8_array(
            'border',
            [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]

        )

        bossdata.add_child(border)
        bossdata.add_child(Node.u8('extra_border', 90))
        bossdata.add_child(Node.u8('bsc_encore_border', 90))
        bossdata.add_child(Node.u8('adv_encore_border', 91))
        bossdata.add_child(Node.u8('ext_encore_border', 92))
        bossdata.add_child(Node.u8('bsc_premium_border', 93))
        bossdata.add_child(Node.u8('adv_premium_border', 93))
        bossdata.add_child(Node.u8('ext_premium_border', 93))

        info = Node.void('info')
        root.add_child(info)

        info.add_child(Node.string('message', "Brought to you by PhaseII! Hosted on phaseii.iidxfan.xyz. Login today!"))

        assert_report_state = Node.u8('assert_report_state', 0)
        root.add_child(assert_report_state)

        return root

    def handle_gameinfo_get_request(self, request: Node) -> Node:
        root = Node.void('gameinfo')

        mode = Node.u8('mode', 0)
        root.add_child(mode)

        free_music = Node.u32('free_music', 262143)
        root.add_child(free_music)
        
        key = Node.void('key')
        root.add_child(key)

        key.add_child(Node.s32('musicid', -1))

        limit_gdp = Node.u32('limit_gdp', 40000)
        root.add_child(limit_gdp)


        free_chara = Node.u32('free_chara', 1824)
        root.add_child(free_chara)

        tag = Node.u8('tag', 177)
        root.add_child(tag)

        bossdata = Node.void('bossdata')
        root.add_child(bossdata)

        bossdata.add_child(Node.u8('division', 15))
        border = Node.u8_array(
            'border',
            [
                0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]

        )

        bossdata.add_child(border)
        bossdata.add_child(Node.u8('extra_border', 90))
        bossdata.add_child(Node.u8('bsc_encore_border', 90))
        bossdata.add_child(Node.u8('adv_encore_border', 91))
        bossdata.add_child(Node.u8('ext_encore_border', 92))
        bossdata.add_child(Node.u8('bsc_premium_border', 93))
        bossdata.add_child(Node.u8('adv_premium_border', 93))
        bossdata.add_child(Node.u8('ext_premium_border', 93))


        battledata = Node.void('battledata')
        root.add_child(battledata)

        battle_music_level = Node.u8_array(
            'battle_music_level',
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]

        )

        battledata.add_child(battle_music_level)

        standard_skill = Node.s32_array(
            'standard_skill',
            [
                0, 0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        battledata.add_child(standard_skill)

        border_skill = Node.s32_array(
            'border_skill',
            [
                0, 0,
                0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        battledata.add_child(border_skill)





        quest = Node.void('quest')
        root.add_child(quest)

        quest.add_child(Node.u8('division', 1))
        quest.add_child(Node.u8('border', 1))

        qdata = Node.u32_array(
            'qdata',
            [
                0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(qdata)

        play_0 = Node.u32_array(
            'play_0',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_0)

        play_1 = Node.u32_array(
            'play_1',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_1)

        play_2 = Node.u32_array(
            'play_2',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_2)

        play_3 = Node.u32_array(
            'play_3',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_3)

        play_4 = Node.u32_array(
            'play_4',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_4)

        play_5 = Node.u32_array(
            'play_5',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_5)

        play_6 = Node.u32_array(
            'play_6',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_6)

        play_7 = Node.u32_array(
            'play_7',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_7)

        play_8 = Node.u32_array(
            'play_8',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        )

        quest.add_child(play_8)

        play_9 = Node.u32_array(
            'play_9',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_9)

        play_10 = Node.u32_array(
            'play_10',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_10)

        play_11 = Node.u32_array(
            'play_11',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_11)

        play_12 = Node.u32_array(
            'play_12',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(play_12)

        clear_0 = Node.u32_array(
            'clear_0',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_0)

        clear_1 = Node.u32_array(
            'clear_1',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_1)

        clear_2 = Node.u32_array(
            'clear_2',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_2)

        clear_3 = Node.u32_array(
            'clear_3',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_3)

        clear_4 = Node.u32_array(
            'clear_4',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_4)

        clear_5 = Node.u32_array(
            'clear_5',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]
        )

        quest.add_child(clear_5)

        clear_6 = Node.u32_array(
            'clear_6',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_6)

        clear_7 = Node.u32_array(
            'clear_7',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_7)

        clear_8 = Node.u32_array(
            'clear_8',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_8)

        clear_9 = Node.u32_array(
            'clear_9',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_9)

        clear_10 = Node.u32_array(
            'clear_10',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_10)

        clear_11 = Node.u32_array(
            'clear_11',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_11)

        clear_12 = Node.u32_array(
            'clear_12',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]

        )

        quest.add_child(clear_12)

        campaign = Node.void('campaign')
        root.add_child(campaign)

        campaign.add_child(Node.u8('campaign', 1))




        return root

    def handle_cardutil_regist_request(self, request: Node) -> Node:

        data = request.child('data')

        refid = data.child_value('refid')
        name = data.child_value('name')
        gdp = 0
        skill = 0
        all_skill = 0
        syogo = [0, 0,]
        penalty = 0
        chara = data.child_value('chara')
        uid = data.child_value('uid')
        cabid = data.child_value('cabid')
        is_succession = data.child_value('is_succession')
        lastmode = 0

        if refid is None:
            return None

        if name is None:
            name = 'なし'

        # First, create and save the default profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        defaultprofile = ValidatedDict({
            'name': name,
            'gdp': gdp,
            'skill': skill,
            'all_skill': all_skill,
            'chara': chara,
            'syogo': syogo,
            'penalty': penalty,
            'uid': uid,
            'cabid': cabid,
            'is_succession': is_succession,
            'lastmode': lastmode,
        })

        self.put_profile(userid, defaultprofile)


        root = Node.void('cardutil')
        return root

    def handle_cardutil_check_request(self, request: Node) -> Node:

        card = request.child('card')

        refid = card.child_value('refid')

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)


        root = Node.void('cardutil')

        cardret = Node.void('card')
        cardret.set_attribute('no', "1")
        cardret.set_attribute('state', "2")

        root.add_child(cardret)

        kind = Node.s8('kind', 0)
        cardret.add_child(kind)

        name = Node.string('name', profile.get_str('name'))
        cardret.add_child(name)

        gdp = Node.u32('gdp', profile.get_int('gdp'))
        cardret.add_child(gdp)

        skill = Node.s32('skill', profile.get_int('skill'))
        cardret.add_child(skill)

        all_skill = Node.s32('all_skill', profile.get_int('all_skill'))
        cardret.add_child(all_skill)

        chara = Node.u8('chara', profile.get_int('chara'))
        cardret.add_child(chara)

        syogo = Node.s16_array('syogo', profile.get_int_array('syogo', 2))
        cardret.add_child(syogo)

        penalty = Node.u8('penalty', 0)
        cardret.add_child(penalty)

        return root

    
    def handle_gametop_get_request(self, request: Node) -> Node:

        root = Node.void('gametop')

        playergt = request.child('player')
        refid = playergt.child_value('refid')

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        




        
        player = Node.void('player')
        player.set_attribute('no', "1")

        root.add_child(player)

        player.add_child(Node.u8('player_type', 0))
        player.add_child(Node.string('my_rival_id', "0"))
        player.add_child(Node.u8('mode', profile.get_int('playmode')))

        #oh god oh fuck

        player.add_child(Node.s16_array('syogo_list', [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,]))
        player.add_child(Node.s16_array('badge_list', [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,]))


        player.add_child(Node.s16_array('favorite_music', [ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,]))
        player.add_child(Node.s16_array('favorite_music_2', [ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,]))
        player.add_child(Node.s16_array('favorite_music_3', [ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,]))

        secret_music = Node.u16_array (
            'secret_music',
            [
                0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ]
        )
        player.add_child(secret_music)

        player.add_child(Node.u32('style', profile.get_int('styles', 0)))
        player.add_child(Node.u32('style_2', profile.get_int('styles_2', 0)))

        player.add_child(Node.u32('shutter_list', profile.get_int('shutter_list', 0)))
        player.add_child(Node.u32('judge_logo_list', profile.get_int('judge_logo_list', 0)))
        player.add_child(Node.u32('skin_list', profile.get_int('skin_list', 0)))
        player.add_child(Node.u32('movie_list', profile.get_int('movie_list', 0)))
        player.add_child(Node.u32('attack_effect_list', profile.get_int('attack_effect_list', 0)))
        
        player.add_child(Node.u32('idle_screen', profile.get_int('idle_screen', 0)))

        player.add_child(Node.s32('chance_point', profile.get_int('chance_point', 0)))

        player.add_child(Node.s32('failed_cnt', profile.get_int('failed_cnt', 0)))

        player.add_child(Node.u32('secret_chara', profile.get_int('secret_chara', 0)))


        player.add_child(Node.u16('mode_beginner', 0))
        player.add_child(Node.u16('mode_standard', 1))
        player.add_child(Node.u16('mode_battle_global', 0))
        player.add_child(Node.u16('mode_battle_local', 0))
        player.add_child(Node.u16('mode_quest', 0))

        player.add_child(Node.s32('v3_skill', -1))
        player.add_child(Node.s32('v4_skill', -1))
        player.add_child(Node.s32('old_ver_skill', -1))


        customize = Node.void('customize')
        player.add_child(customize)

        customize.add_child(Node.u8('shutter', profile.get_int('cust_shutter', 0)))
        customize.add_child(Node.u8('info_level', profile.get_int('cust_info_level', 0)))
        customize.add_child(Node.u8('name_disp', profile.get_int('cust_name_disp', 0)))
        customize.add_child(Node.u8('auto', profile.get_int('cust_auto', 0)))
        customize.add_child(Node.u8('random', profile.get_int('cust_random', 0)))
        customize.add_child(Node.u32('judge_logo', profile.get_int('cust_judge_logo', 0)))
        customize.add_child(Node.u32('skin', profile.get_int('cust_skin', 0)))
        customize.add_child(Node.u32('movie', profile.get_int('cust_movie', 0)))
        customize.add_child(Node.u32('attack_effect', profile.get_int('cust_attack_effect', 0)))
        customize.add_child(Node.u8('layout', profile.get_int('cust_layout', 0)))
        customize.add_child(Node.u8('target_skill', profile.get_int('cust_target_skill', 0)))
        customize.add_child(Node.u8('comparison', profile.get_int('cust_comparison', 0)))
        customize.add_child(Node.u8_array('meter_custom', profile.get_int_array('cust_meter_custom', 3)))

        player.add_child(Node.u8('tag', 190))


        battledata = Node.void('battledata')
        player.add_child(battledata)

        battledata.add_child(Node.u32('bp', profile.get_int('bp', 0)))
        battledata.add_child(Node.s32('battle_rate', 0))
        battledata.add_child(Node.u8('battle_class', 0))
        battledata.add_child(Node.s16('point', 0))
        battledata.add_child(Node.u16('rensyo', 0))
        battledata.add_child(Node.u32('win', 0))
        battledata.add_child(Node.u32('lose', 0))
        battledata.add_child(Node.u8('score_type', 0))
        battledata.add_child(Node.s16('strategy_item', 0))
        battledata.add_child(Node.s16('production_item', 0))
        battledata.add_child(Node.u32('draw', 0))
        battledata.add_child(Node.u8('max_class', 0))
        battledata.add_child(Node.u16('max_rensyo', 0))
        battledata.add_child(Node.u16('vip_rensyo', 0))
        battledata.add_child(Node.s32('max_defeat_skill', 0))
        battledata.add_child(Node.s32('max_defeat_battle_rate', 0))
        battledata.add_child(Node.u32('gold_star', 0))
        battledata.add_child(Node.u32('random_select', 0))
        battledata.add_child(Node.u8('enable_bonus_bp', 0))
        battledata.add_child(Node.u32('type_normal', 0))
        battledata.add_child(Node.u32('type_perfect', 0))
        battledata.add_child(Node.u32('type_combo', 0))

        battle_aniv = Node.void('battle_aniv')
        battledata.add_child(battle_aniv)

        get = Node.void('get')
        battle_aniv.add_child(get)

        category_ver = Node.u16_array (
            'category_ver',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )

        get.add_child(category_ver)
        category_genre = Node.u16_array (
            'category_genre',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )
        get.add_child(category_genre)

        battledata.add_child(Node.u8_array('area_id_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))
        battledata.add_child(Node.u32_array('area_win_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))
        battledata.add_child(Node.u32_array('area_lose_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))

        battledata.add_child(Node.u32('perfect', profile.get_int('perfect', 0)))
        battledata.add_child(Node.u32('great', profile.get_int('great', 0)))
        battledata.add_child(Node.u32('good', profile.get_int('good', 0)))
        battledata.add_child(Node.u32('poor', profile.get_int('poor', 0)))
        battledata.add_child(Node.u32('miss', profile.get_int('miss', 0)))

        history = Node.void('history')
        battledata.add_child(history)

        round_before = Node.void('round')
        round_before.set_attribute('before', "0")
        history.add_child(round_before)

        round_before.add_child(Node.s8('defeat_class', 0))
        round_before.add_child(Node.s8('rival_type', 0))
        round_before.add_child(Node.string('name', "0"))
        round_before.add_child(Node.string('shopname', "0"))
        round_before.add_child(Node.u8('chara_icon', 0))
        round_before.add_child(Node.u8('pref', 0))
        round_before.add_child(Node.s32('skill', 0))
        round_before.add_child(Node.s32('battle_rate', 0))
        round_before.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before.add_child(Node.s8('result', 0))
        round_before.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before.add_child(Node.u32_array('flags', [0, 0,]))
        round_before.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before.add_child(Node.s16_array('item', [0, 0,]))
        round_before.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before.add_child(Node.u8('gold_star_hist', 0))

        round_before2 = Node.void('round')
        round_before2.set_attribute('before', "0")
        history.add_child(round_before2)

        round_before2.add_child(Node.s8('defeat_class', 0))
        round_before2.add_child(Node.s8('rival_type', 0))
        round_before2.add_child(Node.string('name', "0"))
        round_before2.add_child(Node.string('shopname', "0"))
        round_before2.add_child(Node.u8('chara_icon', 0))
        round_before2.add_child(Node.u8('pref', 0))
        round_before2.add_child(Node.s32('skill', 0))
        round_before2.add_child(Node.s32('battle_rate', 0))
        round_before2.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before2.add_child(Node.s8('result', 0))
        round_before2.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before2.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before2.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before2.add_child(Node.u32_array('flags', [0, 0,]))
        round_before2.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before2.add_child(Node.s16_array('item', [0, 0,]))
        round_before2.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before2.add_child(Node.u8('gold_star_hist', 0))

        round_before3 = Node.void('round')
        round_before3.set_attribute('before', "0")
        history.add_child(round_before3)

        round_before3.add_child(Node.s8('defeat_class', 0))
        round_before3.add_child(Node.s8('rival_type', 0))
        round_before3.add_child(Node.string('name', "0"))
        round_before3.add_child(Node.string('shopname', "0"))
        round_before3.add_child(Node.u8('chara_icon', 0))
        round_before3.add_child(Node.u8('pref', 0))
        round_before3.add_child(Node.s32('skill', 0))
        round_before3.add_child(Node.s32('battle_rate', 0))
        round_before3.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before3.add_child(Node.s8('result', 0))
        round_before3.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before3.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before3.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before3.add_child(Node.u32_array('flags', [0, 0,]))
        round_before3.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before3.add_child(Node.s16_array('item', [0, 0,]))
        round_before3.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before3.add_child(Node.u8('gold_star_hist', 0))

        round_before4 = Node.void('round')
        round_before4.set_attribute('before', "0")
        history.add_child(round_before4)

        round_before4.add_child(Node.s8('defeat_class', 0))
        round_before4.add_child(Node.s8('rival_type', 0))
        round_before4.add_child(Node.string('name', "0"))
        round_before4.add_child(Node.string('shopname', "0"))
        round_before4.add_child(Node.u8('chara_icon', 0))
        round_before4.add_child(Node.u8('pref', 0))
        round_before4.add_child(Node.s32('skill', 0))
        round_before4.add_child(Node.s32('battle_rate', 0))
        round_before4.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before4.add_child(Node.s8('result', 0))
        round_before4.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before4.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before4.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before4.add_child(Node.u32_array('flags', [0, 0,]))
        round_before4.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before4.add_child(Node.s16_array('item', [0, 0,]))
        round_before4.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before4.add_child(Node.u8('gold_star_hist', 0))

        round_before5 = Node.void('round')
        round_before5.set_attribute('before', "0")
        history.add_child(round_before5)

        round_before5.add_child(Node.s8('defeat_class', 0))
        round_before5.add_child(Node.s8('rival_type', 0))
        round_before5.add_child(Node.string('name', "0"))
        round_before5.add_child(Node.string('shopname', "0"))
        round_before5.add_child(Node.u8('chara_icon', 0))
        round_before5.add_child(Node.u8('pref', 0))
        round_before5.add_child(Node.s32('skill', 0))
        round_before5.add_child(Node.s32('battle_rate', 0))
        round_before5.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before5.add_child(Node.s8('result', 0))
        round_before5.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before5.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before5.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before5.add_child(Node.u32_array('flags', [0, 0,]))
        round_before5.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before5.add_child(Node.s16_array('item', [0, 0,]))
        round_before5.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before5.add_child(Node.u8('gold_star_hist', 0))

        round_before6 = Node.void('round')
        round_before6.set_attribute('before', "0")
        history.add_child(round_before6)

        round_before6.add_child(Node.s8('defeat_class', 0))
        round_before6.add_child(Node.s8('rival_type', 0))
        round_before6.add_child(Node.string('name', "0"))
        round_before6.add_child(Node.string('shopname', "0"))
        round_before6.add_child(Node.u8('chara_icon', 0))
        round_before6.add_child(Node.u8('pref', 0))
        round_before6.add_child(Node.s32('skill', 0))
        round_before6.add_child(Node.s32('battle_rate', 0))
        round_before6.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before6.add_child(Node.s8('result', 0))
        round_before6.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before6.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before6.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before6.add_child(Node.u32_array('flags', [0, 0,]))
        round_before6.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before6.add_child(Node.s16_array('item', [0, 0,]))
        round_before6.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before6.add_child(Node.u8('gold_star_hist', 0))

        round_before7 = Node.void('round')
        round_before7.set_attribute('before', "0")
        history.add_child(round_before7)

        round_before7.add_child(Node.s8('defeat_class', 0))
        round_before7.add_child(Node.s8('rival_type', 0))
        round_before7.add_child(Node.string('name', "0"))
        round_before7.add_child(Node.string('shopname', "0"))
        round_before7.add_child(Node.u8('chara_icon', 0))
        round_before7.add_child(Node.u8('pref', 0))
        round_before7.add_child(Node.s32('skill', 0))
        round_before7.add_child(Node.s32('battle_rate', 0))
        round_before7.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before7.add_child(Node.s8('result', 0))
        round_before7.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before7.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before7.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before7.add_child(Node.u32_array('flags', [0, 0,]))
        round_before7.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before7.add_child(Node.s16_array('item', [0, 0,]))
        round_before7.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before7.add_child(Node.u8('gold_star_hist', 0))

        round_before8 = Node.void('round')
        round_before8.set_attribute('before', "0")
        history.add_child(round_before8)

        round_before8.add_child(Node.s8('defeat_class', 0))
        round_before8.add_child(Node.s8('rival_type', 0))
        round_before8.add_child(Node.string('name', "0"))
        round_before8.add_child(Node.string('shopname', "0"))
        round_before8.add_child(Node.u8('chara_icon', 0))
        round_before8.add_child(Node.u8('pref', 0))
        round_before8.add_child(Node.s32('skill', 0))
        round_before8.add_child(Node.s32('battle_rate', 0))
        round_before8.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before8.add_child(Node.s8('result', 0))
        round_before8.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before8.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before8.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before8.add_child(Node.u32_array('flags', [0, 0,]))
        round_before8.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before8.add_child(Node.s16_array('item', [0, 0,]))
        round_before8.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before8.add_child(Node.u8('gold_star_hist', 0))

        round_before9 = Node.void('round')
        round_before9.set_attribute('before', "0")
        history.add_child(round_before9)

        round_before9.add_child(Node.s8('defeat_class', 0))
        round_before9.add_child(Node.s8('rival_type', 0))
        round_before9.add_child(Node.string('name', "0"))
        round_before9.add_child(Node.string('shopname', "0"))
        round_before9.add_child(Node.u8('chara_icon', 0))
        round_before9.add_child(Node.u8('pref', 0))
        round_before9.add_child(Node.s32('skill', 0))
        round_before9.add_child(Node.s32('battle_rate', 0))
        round_before9.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before9.add_child(Node.s8('result', 0))
        round_before9.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before9.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before9.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before9.add_child(Node.u32_array('flags', [0, 0,]))
        round_before9.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before9.add_child(Node.s16_array('item', [0, 0,]))
        round_before9.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before9.add_child(Node.u8('gold_star_hist', 0))

        round_before10 = Node.void('round')
        round_before10.set_attribute('before', "0")
        history.add_child(round_before10)

        round_before10.add_child(Node.s8('defeat_class', 0))
        round_before10.add_child(Node.s8('rival_type', 0))
        round_before10.add_child(Node.string('name', "0"))
        round_before10.add_child(Node.string('shopname', "0"))
        round_before10.add_child(Node.u8('chara_icon', 0))
        round_before10.add_child(Node.u8('pref', 0))
        round_before10.add_child(Node.s32('skill', 0))
        round_before10.add_child(Node.s32('battle_rate', 0))
        round_before10.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before10.add_child(Node.s8('result', 0))
        round_before10.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before10.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before10.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before10.add_child(Node.u32_array('flags', [0, 0,]))
        round_before10.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before10.add_child(Node.s16_array('item', [0, 0,]))
        round_before10.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before10.add_child(Node.u8('gold_star_hist', 0))


        music_hist = Node.void('music_hist')
        battledata.add_child(music_hist)

        round_before1 = Node.void('round')
        round_before1.set_attribute('before', "0")
        music_hist.add_child(round_before1)

        round_before1.add_child(Node.s16('point', 0))
        round_before1.add_child(Node.s32('my_select_musicid', 0))
        round_before1.add_child(Node.s8('my_select_result', 0))
        round_before1.add_child(Node.s32('rival_select_musicid', 0))
        round_before1.add_child(Node.s8('rival_select_result', 0))

        round_before2 = Node.void('round')
        round_before2.set_attribute('before', "0")
        music_hist.add_child(round_before2)

        round_before2.add_child(Node.s16('point', 0))
        round_before2.add_child(Node.s32('my_select_musicid', 0))
        round_before2.add_child(Node.s8('my_select_result', 0))
        round_before2.add_child(Node.s32('rival_select_musicid', 0))
        round_before2.add_child(Node.s8('rival_select_result', 0))

        round_before3 = Node.void('round')
        round_before3.set_attribute('before', "0")
        music_hist.add_child(round_before3)

        round_before3.add_child(Node.s16('point', 0))
        round_before3.add_child(Node.s32('my_select_musicid', 0))
        round_before3.add_child(Node.s8('my_select_result', 0))
        round_before3.add_child(Node.s32('rival_select_musicid', 0))
        round_before3.add_child(Node.s8('rival_select_result', 0))

        round_before4 = Node.void('round')
        round_before4.set_attribute('before', "0")
        music_hist.add_child(round_before4)

        round_before4.add_child(Node.s16('point', 0))
        round_before4.add_child(Node.s32('my_select_musicid', 0))
        round_before4.add_child(Node.s8('my_select_result', 0))
        round_before4.add_child(Node.s32('rival_select_musicid', 0))
        round_before4.add_child(Node.s8('rival_select_result', 0))

        round_before5 = Node.void('round')
        round_before5.set_attribute('before', "0")
        music_hist.add_child(round_before5)

        round_before5.add_child(Node.s16('point', 0))
        round_before5.add_child(Node.s32('my_select_musicid', 0))
        round_before5.add_child(Node.s8('my_select_result', 0))
        round_before5.add_child(Node.s32('rival_select_musicid', 0))
        round_before5.add_child(Node.s8('rival_select_result', 0))

        round_before6 = Node.void('round')
        round_before6.set_attribute('before', "0")
        music_hist.add_child(round_before6)

        round_before6.add_child(Node.s16('point', 0))
        round_before6.add_child(Node.s32('my_select_musicid', 0))
        round_before6.add_child(Node.s8('my_select_result', 0))
        round_before6.add_child(Node.s32('rival_select_musicid', 0))
        round_before6.add_child(Node.s8('rival_select_result', 0))

        round_before7 = Node.void('round')
        round_before7.set_attribute('before', "0")
        music_hist.add_child(round_before7)

        round_before7.add_child(Node.s16('point', 0))
        round_before7.add_child(Node.s32('my_select_musicid', 0))
        round_before7.add_child(Node.s8('my_select_result', 0))
        round_before7.add_child(Node.s32('rival_select_musicid', 0))
        round_before7.add_child(Node.s8('rival_select_result', 0))

        round_before8 = Node.void('round')
        round_before8.set_attribute('before', "0")
        music_hist.add_child(round_before8)

        round_before8.add_child(Node.s16('point', 0))
        round_before8.add_child(Node.s32('my_select_musicid', 0))
        round_before8.add_child(Node.s8('my_select_result', 0))
        round_before8.add_child(Node.s32('rival_select_musicid', 0))
        round_before8.add_child(Node.s8('rival_select_result', 0))

        round_before9 = Node.void('round')
        round_before9.set_attribute('before', "0")
        music_hist.add_child(round_before9)

        round_before9.add_child(Node.s16('point', 0))
        round_before9.add_child(Node.s32('my_select_musicid', 0))
        round_before9.add_child(Node.s8('my_select_result', 0))
        round_before9.add_child(Node.s32('rival_select_musicid', 0))
        round_before9.add_child(Node.s8('rival_select_result', 0))

        round_before10 = Node.void('round')
        round_before10.set_attribute('before', "0")
        music_hist.add_child(round_before10)

        round_before10.add_child(Node.s16('point', 0))
        round_before10.add_child(Node.s32('my_select_musicid', 0))
        round_before10.add_child(Node.s8('my_select_result', 0))
        round_before10.add_child(Node.s32('rival_select_musicid', 0))
        round_before10.add_child(Node.s8('rival_select_result', 0))

        round_before11 = Node.void('round')
        round_before11.set_attribute('before', "0")
        music_hist.add_child(round_before11)

        round_before11.add_child(Node.s16('point', 0))
        round_before11.add_child(Node.s32('my_select_musicid', 0))
        round_before11.add_child(Node.s8('my_select_result', 0))
        round_before11.add_child(Node.s32('rival_select_musicid', 0))
        round_before11.add_child(Node.s8('rival_select_result', 0))

        round_before12 = Node.void('round')
        round_before12.set_attribute('before', "0")
        music_hist.add_child(round_before12)

        round_before12.add_child(Node.s16('point', 0))
        round_before12.add_child(Node.s32('my_select_musicid', 0))
        round_before12.add_child(Node.s8('my_select_result', 0))
        round_before12.add_child(Node.s32('rival_select_musicid', 0))
        round_before12.add_child(Node.s8('rival_select_result', 0))

        round_before13 = Node.void('round')
        round_before13.set_attribute('before', "0")
        music_hist.add_child(round_before13)

        round_before13.add_child(Node.s16('point', 0))
        round_before13.add_child(Node.s32('my_select_musicid', 0))
        round_before13.add_child(Node.s8('my_select_result', 0))
        round_before13.add_child(Node.s32('rival_select_musicid', 0))
        round_before13.add_child(Node.s8('rival_select_result', 0))

        round_before14 = Node.void('round')
        round_before14.set_attribute('before', "0")
        music_hist.add_child(round_before14)

        round_before14.add_child(Node.s16('point', 0))
        round_before14.add_child(Node.s32('my_select_musicid', 0))
        round_before14.add_child(Node.s8('my_select_result', 0))
        round_before14.add_child(Node.s32('rival_select_musicid', 0))
        round_before14.add_child(Node.s8('rival_select_result', 0))

        round_before15 = Node.void('round')
        round_before15.set_attribute('before', "0")
        music_hist.add_child(round_before15)

        round_before15.add_child(Node.s16('point', 0))
        round_before15.add_child(Node.s32('my_select_musicid', 0))
        round_before15.add_child(Node.s8('my_select_result', 0))
        round_before15.add_child(Node.s32('rival_select_musicid', 0))
        round_before15.add_child(Node.s8('rival_select_result', 0))

        round_before16 = Node.void('round')
        round_before16.set_attribute('before', "0")
        music_hist.add_child(round_before16)

        round_before16.add_child(Node.s16('point', 0))
        round_before16.add_child(Node.s32('my_select_musicid', 0))
        round_before16.add_child(Node.s8('my_select_result', 0))
        round_before16.add_child(Node.s32('rival_select_musicid', 0))
        round_before16.add_child(Node.s8('rival_select_result', 0))

        round_before17 = Node.void('round')
        round_before17.set_attribute('before', "0")
        music_hist.add_child(round_before17)

        round_before17.add_child(Node.s16('point', 0))
        round_before17.add_child(Node.s32('my_select_musicid', 0))
        round_before17.add_child(Node.s8('my_select_result', 0))
        round_before17.add_child(Node.s32('rival_select_musicid', 0))
        round_before17.add_child(Node.s8('rival_select_result', 0))

        round_before18 = Node.void('round')
        round_before18.set_attribute('before', "0")
        music_hist.add_child(round_before18)

        round_before18.add_child(Node.s16('point', 0))
        round_before18.add_child(Node.s32('my_select_musicid', 0))
        round_before18.add_child(Node.s8('my_select_result', 0))
        round_before18.add_child(Node.s32('rival_select_musicid', 0))
        round_before18.add_child(Node.s8('rival_select_result', 0))

        round_before19 = Node.void('round')
        round_before19.set_attribute('before', "0")
        music_hist.add_child(round_before19)

        round_before19.add_child(Node.s16('point', 0))
        round_before19.add_child(Node.s32('my_select_musicid', 0))
        round_before19.add_child(Node.s8('my_select_result', 0))
        round_before19.add_child(Node.s32('rival_select_musicid', 0))
        round_before19.add_child(Node.s8('rival_select_result', 0))

        round_before20 = Node.void('round')
        round_before20.set_attribute('before', "0")
        music_hist.add_child(round_before20)

        round_before20.add_child(Node.s16('point', 0))
        round_before20.add_child(Node.s32('my_select_musicid', 0))
        round_before20.add_child(Node.s8('my_select_result', 0))
        round_before20.add_child(Node.s32('rival_select_musicid', 0))
        round_before20.add_child(Node.s8('rival_select_result', 0))



        battle_aniv2 = Node.void('battle_aniv')
        player.add_child(battle_aniv)

        get2 = Node.void('get')
        battle_aniv2.add_child(get)

        category_ver2 = Node.u16_array (
            'category_ver',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )

        get2.add_child(category_ver2)
        category_genre2 = Node.u16_array (
            'category_genre',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )
        get2.add_child(category_genre2)

        info = Node.void('info')
        player.add_child(info)
        info.add_child(Node.u32('mode', profile.get_int('info_mode', 0)))
        info.add_child(Node.u32('boss', profile.get_int('info_boss', 0)))
        info.add_child(Node.u32('battle_aniv', profile.get_int('info_battle_aniv', 0)))
        info.add_child(Node.u32('free_music', profile.get_int('info_free_music', 0)))
        info.add_child(Node.u32('free_chara', profile.get_int('info_free_chara', 0)))
        info.add_child(Node.u32('event', profile.get_int('info_event', 0)))
        info.add_child(Node.u32('battle_event', profile.get_int('info_battle_event', 0)))
        info.add_child(Node.u32('champ', profile.get_int('info_champ', 0)))
        info.add_child(Node.u32('item', profile.get_int('info_item', 0)))
        info.add_child(Node.u32('quest', profile.get_int('info_quest', 0)))
        info.add_child(Node.u32('campaign', profile.get_int('info_campaign', 0)))
        info.add_child(Node.u32('gdp', profile.get_int('info_gdp', 0)))
        info.add_child(Node.u32('v7', profile.get_int('info_v7', 0)))



        quest = Node.void('quest')
        player.add_child(quest)
        
        quest.add_child(Node.u8('quest_rank', 0))
        quest.add_child(Node.u32('star', 0))
        quest.add_child(Node.u64('fan', 0))
        qdata = Node.u32_array (
            'qdata',
            [
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
            ]
        )
        quest.add_child(qdata)
        test_data = Node.u32_array (
            'test_data',
            [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )
        quest.add_child(test_data)

        championship = Node.void('championship')
        player.add_child(championship)

        playable = Node.s32_array (
            'playable',
            [
                0,
                0,
                0,
                0,
            ]
        )
        championship.add_child(playable)

        ranking = Node.void('ranking')
        player.add_child(ranking)

        ranking.add_child(Node.s32('skill_rank', 0))

        #rivals are not implemented currently.
        player.add_child(Node.string('rival_id_1', "0"))
        player.add_child(Node.string('rival_id_2', "0"))
        player.add_child(Node.string('rival_id_3', "0"))




        champ_result = Node.u32_array (
            'champ_result',
            [
                0,
                0,
            ]
        )
        #info.add_child(champ_result)



        #no idea what this does lol
        #EDIT: this is where i load scores
        scores = self.get_scores_by_refid(refid)
        player.add_child(scores)


        #we're done here
        player.add_child(Node.u8('finish', 1))




        return root

    def handle_gametop_get_rival_request(self, request: Node) -> Node:
        root = Node.void('gametop')

        player = Node.void('player')
        root.add_child(player)
        player.set_attribute('no', "1")

        pdata = Node.void('pdata')
        player.add_child(pdata)
        
        pdata.set_attribute('rival_id', "0")

        pdata.add_child(Node.string("name", "NONE"))
        pdata.add_child(Node.u8("chara", 0))
        pdata.add_child(Node.s32("skill", 0))
        pdata.add_child(Node.s16_array("syogo", [0, 0,]))
        pdata.add_child(Node.u8('info_level', 0))

        bdata = Node.void('bdata')
        pdata.add_child(bdata)

        bdata.add_child(Node.s32('battle_rate', 0))
        bdata.add_child(Node.u8('battle_class', 0))
        bdata.add_child(Node.s16('point', 0))
        bdata.add_child(Node.u16('rensyo', 0))
        bdata.add_child(Node.u32('win', 0))
        bdata.add_child(Node.u32('lose', 0))
        bdata.add_child(Node.u32('draw', 0))

        quest = Node.void('quest')
        pdata.add_child(quest)

        quest.add_child(Node.u8('quest_rank', 0))
        quest.add_child(Node.u32('star', 0))
        quest.add_child(Node.u64('fan', 0))
        quest.add_child(Node.u32_array('qdata', [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))
        quest.add_child(Node.u32_array('test_data', [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ]))

        standard = Node.void('standard')
        player.add_child(standard)

        standard.set_attribute('nr', "0")

        player.add_child(Node.u8('finish', 1))

        return root
    

    def handle_gameend_regist_request(self, request: Node) -> Node:
        root = Node.void('gameend')

        # get base song info
        modedata = request.child('modedata')
        playedmode = modedata.attribute('mode')


        # get player stats
        player1 = request.child('player')
        usecard = player1.attribute('card')
        playernum = player1.attribute('no')

        playerinfo = player1.child('playerinfo')

        refid = playerinfo.child_value('refid')
        gdp = playerinfo.child_value('gdp')
        total_skill_point = playerinfo.child_value('total_skill_point')
        chara = playerinfo.child_value('chara')
        secret_chara = playerinfo.child_value('secret_chara')
        syogo = playerinfo.child_value('syogo')
        failed_cnt = playerinfo.child_value('failed_cnt')
        perfect = playerinfo.child_value('perfect')
        great = playerinfo.child_value('great')
        good = playerinfo.child_value('good')
        poor = playerinfo.child_value('poor')
        miss = playerinfo.child_value('miss')
        time = playerinfo.child_value('time')

        #add player stats to the DB
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        old_profile = self.get_profile(userid)
        new_profile = self.unformat_profile(userid, request, old_profile)

        self.put_profile(userid, new_profile)

        #fix this later
        playcnt = 1
        sesscnt = 1

        #give the game the data it wants
        gamemode = Node.void('gamemode')
        root.add_child(gamemode)

        gamemode.set_attribute('mode', playedmode)

        player_ret = Node.void('player')
        root.add_child(player_ret)

        player_ret.set_attribute('card', usecard)
        player_ret.set_attribute('no', playernum)

        skill = Node.void('skill')
        player_ret.add_child(skill)

        skill.add_child(Node.s32('point', 0))
        skill.add_child(Node.u32('rank', 1))
        skill.add_child(Node.u32('total_nr', 1))
        skill.add_child(Node.s32('all_point', 0))
        skill.add_child(Node.u32('all_rank', 1))
        skill.add_child(Node.u32('all_total_nr', 1))

        player_ret.add_child(Node.u32('registered_other_num', 0))
        player_ret.add_child(Node.u32('xg_play_cnt', 0))
        player_ret.add_child(Node.u32('play_cnt', playcnt))
        player_ret.add_child(Node.u32('sess_cnt', sesscnt))
        player_ret.add_child(Node.u32('encore_play', 0))
        player_ret.add_child(Node.u32('premium_play', 0))
        #player_ret.add_child(Node.u32('now_time', 0))
        player_ret.add_child(Node.u32('kikan_event', 0))
        player_ret.add_child(Node.u16('vip_rensyo', 0))
        player_ret.add_child(Node.u8('all_play_mode', 0))
        player_ret.add_child(Node.u8('play_shop_num', 0))
        player_ret.add_child(Node.u32('judge_perfect', 0))
        player_ret.add_child(Node.u8('is_v5_goodplayer', 0))
        player_ret.add_child(Node.s8('max_clear_difficulty', 0))
        player_ret.add_child(Node.s8('max_fullcombo_difficulty', 0))
        player_ret.add_child(Node.s8('max_excellent_difficulty', 0))
        player_ret.add_child(Node.void('rival_data'))

        battledata = Node.void('battledata')
        player_ret.add_child(battledata)

        battledata.add_child(Node.u32('bp', 0))
        battledata.add_child(Node.s32('battle_rate', 0))
        battledata.add_child(Node.u8('battle_class', 0))
        battledata.add_child(Node.s16('point', 0))
        battledata.add_child(Node.u16('rensyo', 0))
        battledata.add_child(Node.u32('win', 0))
        battledata.add_child(Node.u32('lose', 0))
        battledata.add_child(Node.u8('score_type', 0))
        battledata.add_child(Node.s16('strategy_item', 0))
        battledata.add_child(Node.s16('production_item', 0))
        battledata.add_child(Node.u32('draw', 0))
        battledata.add_child(Node.u8('max_class', 0))
        battledata.add_child(Node.u16('max_rensyo', 0))
        battledata.add_child(Node.u16('vip_rensyo', 0))
        battledata.add_child(Node.s32('max_defeat_skill', 0))
        battledata.add_child(Node.s32('max_defeat_battle_rate', 0))
        battledata.add_child(Node.u32('gold_star', 0))
        battledata.add_child(Node.u32('random_select', 0))
        battledata.add_child(Node.u8('enable_bonus_bp', 0))
        battledata.add_child(Node.u32('type_normal', 0))
        battledata.add_child(Node.u32('type_perfect', 0))
        battledata.add_child(Node.u32('type_combo', 0))

        battle_aniv = Node.void('battle_aniv')
        battledata.add_child(battle_aniv)

        get = Node.void('get')
        battle_aniv.add_child(get)

        category_ver = Node.u16_array (
            'category_ver',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )

        get.add_child(category_ver)
        category_genre = Node.u16_array (
            'category_genre',
            [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
            ]
        )
        get.add_child(category_genre)

        battledata.add_child(Node.u8_array('area_id_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))
        battledata.add_child(Node.u32_array('area_win_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))
        battledata.add_child(Node.u32_array('area_lose_list', [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]))

        battledata.add_child(Node.u32('perfect', 0))
        battledata.add_child(Node.u32('great', 0))
        battledata.add_child(Node.u32('good', 0))
        battledata.add_child(Node.u32('poor', 0))
        battledata.add_child(Node.u32('miss', 0))

        history = Node.void('history')
        battledata.add_child(history)

        round_before = Node.void('round')
        round_before.set_attribute('before', "0")
        history.add_child(round_before)

        round_before.add_child(Node.s8('defeat_class', 0))
        round_before.add_child(Node.s8('rival_type', 0))
        round_before.add_child(Node.string('name', "0"))
        round_before.add_child(Node.string('shopname', "0"))
        round_before.add_child(Node.u8('chara_icon', 0))
        round_before.add_child(Node.u8('pref', 0))
        round_before.add_child(Node.s32('skill', 0))
        round_before.add_child(Node.s32('battle_rate', 0))
        round_before.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before.add_child(Node.s8('result', 0))
        round_before.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before.add_child(Node.u32_array('flags', [0, 0,]))
        round_before.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before.add_child(Node.s16_array('item', [0, 0,]))
        round_before.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before.add_child(Node.u8('gold_star_hist', 0))

        round_before2 = Node.void('round')
        round_before2.set_attribute('before', "0")
        history.add_child(round_before2)

        round_before2.add_child(Node.s8('defeat_class', 0))
        round_before2.add_child(Node.s8('rival_type', 0))
        round_before2.add_child(Node.string('name', "0"))
        round_before2.add_child(Node.string('shopname', "0"))
        round_before2.add_child(Node.u8('chara_icon', 0))
        round_before2.add_child(Node.u8('pref', 0))
        round_before2.add_child(Node.s32('skill', 0))
        round_before2.add_child(Node.s32('battle_rate', 0))
        round_before2.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before2.add_child(Node.s8('result', 0))
        round_before2.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before2.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before2.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before2.add_child(Node.u32_array('flags', [0, 0,]))
        round_before2.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before2.add_child(Node.s16_array('item', [0, 0,]))
        round_before2.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before2.add_child(Node.u8('gold_star_hist', 0))

        round_before3 = Node.void('round')
        round_before3.set_attribute('before', "0")
        history.add_child(round_before3)

        round_before3.add_child(Node.s8('defeat_class', 0))
        round_before3.add_child(Node.s8('rival_type', 0))
        round_before3.add_child(Node.string('name', "0"))
        round_before3.add_child(Node.string('shopname', "0"))
        round_before3.add_child(Node.u8('chara_icon', 0))
        round_before3.add_child(Node.u8('pref', 0))
        round_before3.add_child(Node.s32('skill', 0))
        round_before3.add_child(Node.s32('battle_rate', 0))
        round_before3.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before3.add_child(Node.s8('result', 0))
        round_before3.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before3.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before3.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before3.add_child(Node.u32_array('flags', [0, 0,]))
        round_before3.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before3.add_child(Node.s16_array('item', [0, 0,]))
        round_before3.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before3.add_child(Node.u8('gold_star_hist', 0))

        round_before4 = Node.void('round')
        round_before4.set_attribute('before', "0")
        history.add_child(round_before4)

        round_before4.add_child(Node.s8('defeat_class', 0))
        round_before4.add_child(Node.s8('rival_type', 0))
        round_before4.add_child(Node.string('name', "0"))
        round_before4.add_child(Node.string('shopname', "0"))
        round_before4.add_child(Node.u8('chara_icon', 0))
        round_before4.add_child(Node.u8('pref', 0))
        round_before4.add_child(Node.s32('skill', 0))
        round_before4.add_child(Node.s32('battle_rate', 0))
        round_before4.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before4.add_child(Node.s8('result', 0))
        round_before4.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before4.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before4.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before4.add_child(Node.u32_array('flags', [0, 0,]))
        round_before4.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before4.add_child(Node.s16_array('item', [0, 0,]))
        round_before4.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before4.add_child(Node.u8('gold_star_hist', 0))

        round_before5 = Node.void('round')
        round_before5.set_attribute('before', "0")
        history.add_child(round_before5)

        round_before5.add_child(Node.s8('defeat_class', 0))
        round_before5.add_child(Node.s8('rival_type', 0))
        round_before5.add_child(Node.string('name', "0"))
        round_before5.add_child(Node.string('shopname', "0"))
        round_before5.add_child(Node.u8('chara_icon', 0))
        round_before5.add_child(Node.u8('pref', 0))
        round_before5.add_child(Node.s32('skill', 0))
        round_before5.add_child(Node.s32('battle_rate', 0))
        round_before5.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before5.add_child(Node.s8('result', 0))
        round_before5.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before5.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before5.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before5.add_child(Node.u32_array('flags', [0, 0,]))
        round_before5.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before5.add_child(Node.s16_array('item', [0, 0,]))
        round_before5.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before5.add_child(Node.u8('gold_star_hist', 0))

        round_before6 = Node.void('round')
        round_before6.set_attribute('before', "0")
        history.add_child(round_before6)

        round_before6.add_child(Node.s8('defeat_class', 0))
        round_before6.add_child(Node.s8('rival_type', 0))
        round_before6.add_child(Node.string('name', "0"))
        round_before6.add_child(Node.string('shopname', "0"))
        round_before6.add_child(Node.u8('chara_icon', 0))
        round_before6.add_child(Node.u8('pref', 0))
        round_before6.add_child(Node.s32('skill', 0))
        round_before6.add_child(Node.s32('battle_rate', 0))
        round_before6.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before6.add_child(Node.s8('result', 0))
        round_before6.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before6.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before6.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before6.add_child(Node.u32_array('flags', [0, 0,]))
        round_before6.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before6.add_child(Node.s16_array('item', [0, 0,]))
        round_before6.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before6.add_child(Node.u8('gold_star_hist', 0))

        round_before7 = Node.void('round')
        round_before7.set_attribute('before', "0")
        history.add_child(round_before7)

        round_before7.add_child(Node.s8('defeat_class', 0))
        round_before7.add_child(Node.s8('rival_type', 0))
        round_before7.add_child(Node.string('name', "0"))
        round_before7.add_child(Node.string('shopname', "0"))
        round_before7.add_child(Node.u8('chara_icon', 0))
        round_before7.add_child(Node.u8('pref', 0))
        round_before7.add_child(Node.s32('skill', 0))
        round_before7.add_child(Node.s32('battle_rate', 0))
        round_before7.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before7.add_child(Node.s8('result', 0))
        round_before7.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before7.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before7.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before7.add_child(Node.u32_array('flags', [0, 0,]))
        round_before7.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before7.add_child(Node.s16_array('item', [0, 0,]))
        round_before7.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before7.add_child(Node.u8('gold_star_hist', 0))

        round_before8 = Node.void('round')
        round_before8.set_attribute('before', "0")
        history.add_child(round_before8)

        round_before8.add_child(Node.s8('defeat_class', 0))
        round_before8.add_child(Node.s8('rival_type', 0))
        round_before8.add_child(Node.string('name', "0"))
        round_before8.add_child(Node.string('shopname', "0"))
        round_before8.add_child(Node.u8('chara_icon', 0))
        round_before8.add_child(Node.u8('pref', 0))
        round_before8.add_child(Node.s32('skill', 0))
        round_before8.add_child(Node.s32('battle_rate', 0))
        round_before8.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before8.add_child(Node.s8('result', 0))
        round_before8.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before8.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before8.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before8.add_child(Node.u32_array('flags', [0, 0,]))
        round_before8.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before8.add_child(Node.s16_array('item', [0, 0,]))
        round_before8.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before8.add_child(Node.u8('gold_star_hist', 0))

        round_before9 = Node.void('round')
        round_before9.set_attribute('before', "0")
        history.add_child(round_before9)

        round_before9.add_child(Node.s8('defeat_class', 0))
        round_before9.add_child(Node.s8('rival_type', 0))
        round_before9.add_child(Node.string('name', "0"))
        round_before9.add_child(Node.string('shopname', "0"))
        round_before9.add_child(Node.u8('chara_icon', 0))
        round_before9.add_child(Node.u8('pref', 0))
        round_before9.add_child(Node.s32('skill', 0))
        round_before9.add_child(Node.s32('battle_rate', 0))
        round_before9.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before9.add_child(Node.s8('result', 0))
        round_before9.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before9.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before9.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before9.add_child(Node.u32_array('flags', [0, 0,]))
        round_before9.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before9.add_child(Node.s16_array('item', [0, 0,]))
        round_before9.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before9.add_child(Node.u8('gold_star_hist', 0))

        round_before10 = Node.void('round')
        round_before10.set_attribute('before', "0")
        history.add_child(round_before10)

        round_before10.add_child(Node.s8('defeat_class', 0))
        round_before10.add_child(Node.s8('rival_type', 0))
        round_before10.add_child(Node.string('name', "0"))
        round_before10.add_child(Node.string('shopname', "0"))
        round_before10.add_child(Node.u8('chara_icon', 0))
        round_before10.add_child(Node.u8('pref', 0))
        round_before10.add_child(Node.s32('skill', 0))
        round_before10.add_child(Node.s32('battle_rate', 0))
        round_before10.add_child(Node.s16_array('syogo', [0, 0,]))
        round_before10.add_child(Node.s8('result', 0))
        round_before10.add_child(Node.s8_array('seqmode', [0, 0,]))
        round_before10.add_child(Node.s8_array('score_type', [0, 0,]))
        round_before10.add_child(Node.s32_array('musicid', [0, 0,]))
        round_before10.add_child(Node.u32_array('flags', [0, 0,]))
        round_before10.add_child(Node.s32_array('score_diff', [0, 0,]))
        round_before10.add_child(Node.s16_array('item', [0, 0,]))
        round_before10.add_child(Node.s8_array('select_type', [0, 0,]))
        round_before10.add_child(Node.u8('gold_star_hist', 0))


        music_hist = Node.void('music_hist')
        battledata.add_child(music_hist)

        round_before1 = Node.void('round')
        round_before1.set_attribute('before', "0")
        music_hist.add_child(round_before1)

        round_before1.add_child(Node.s16('point', 0))
        round_before1.add_child(Node.s32('my_select_musicid', 0))
        round_before1.add_child(Node.s8('my_select_result', 0))
        round_before1.add_child(Node.s32('rival_select_musicid', 0))
        round_before1.add_child(Node.s8('rival_select_result', 0))

        round_before2 = Node.void('round')
        round_before2.set_attribute('before', "0")
        music_hist.add_child(round_before2)

        round_before2.add_child(Node.s16('point', 0))
        round_before2.add_child(Node.s32('my_select_musicid', 0))
        round_before2.add_child(Node.s8('my_select_result', 0))
        round_before2.add_child(Node.s32('rival_select_musicid', 0))
        round_before2.add_child(Node.s8('rival_select_result', 0))

        round_before3 = Node.void('round')
        round_before3.set_attribute('before', "0")
        music_hist.add_child(round_before3)

        round_before3.add_child(Node.s16('point', 0))
        round_before3.add_child(Node.s32('my_select_musicid', 0))
        round_before3.add_child(Node.s8('my_select_result', 0))
        round_before3.add_child(Node.s32('rival_select_musicid', 0))
        round_before3.add_child(Node.s8('rival_select_result', 0))

        round_before4 = Node.void('round')
        round_before4.set_attribute('before', "0")
        music_hist.add_child(round_before4)

        round_before4.add_child(Node.s16('point', 0))
        round_before4.add_child(Node.s32('my_select_musicid', 0))
        round_before4.add_child(Node.s8('my_select_result', 0))
        round_before4.add_child(Node.s32('rival_select_musicid', 0))
        round_before4.add_child(Node.s8('rival_select_result', 0))

        round_before5 = Node.void('round')
        round_before5.set_attribute('before', "0")
        music_hist.add_child(round_before5)

        round_before5.add_child(Node.s16('point', 0))
        round_before5.add_child(Node.s32('my_select_musicid', 0))
        round_before5.add_child(Node.s8('my_select_result', 0))
        round_before5.add_child(Node.s32('rival_select_musicid', 0))
        round_before5.add_child(Node.s8('rival_select_result', 0))

        round_before6 = Node.void('round')
        round_before6.set_attribute('before', "0")
        music_hist.add_child(round_before6)

        round_before6.add_child(Node.s16('point', 0))
        round_before6.add_child(Node.s32('my_select_musicid', 0))
        round_before6.add_child(Node.s8('my_select_result', 0))
        round_before6.add_child(Node.s32('rival_select_musicid', 0))
        round_before6.add_child(Node.s8('rival_select_result', 0))

        round_before7 = Node.void('round')
        round_before7.set_attribute('before', "0")
        music_hist.add_child(round_before7)

        round_before7.add_child(Node.s16('point', 0))
        round_before7.add_child(Node.s32('my_select_musicid', 0))
        round_before7.add_child(Node.s8('my_select_result', 0))
        round_before7.add_child(Node.s32('rival_select_musicid', 0))
        round_before7.add_child(Node.s8('rival_select_result', 0))

        round_before8 = Node.void('round')
        round_before8.set_attribute('before', "0")
        music_hist.add_child(round_before8)

        round_before8.add_child(Node.s16('point', 0))
        round_before8.add_child(Node.s32('my_select_musicid', 0))
        round_before8.add_child(Node.s8('my_select_result', 0))
        round_before8.add_child(Node.s32('rival_select_musicid', 0))
        round_before8.add_child(Node.s8('rival_select_result', 0))

        round_before9 = Node.void('round')
        round_before9.set_attribute('before', "0")
        music_hist.add_child(round_before9)

        round_before9.add_child(Node.s16('point', 0))
        round_before9.add_child(Node.s32('my_select_musicid', 0))
        round_before9.add_child(Node.s8('my_select_result', 0))
        round_before9.add_child(Node.s32('rival_select_musicid', 0))
        round_before9.add_child(Node.s8('rival_select_result', 0))

        round_before10 = Node.void('round')
        round_before10.set_attribute('before', "0")
        music_hist.add_child(round_before10)

        round_before10.add_child(Node.s16('point', 0))
        round_before10.add_child(Node.s32('my_select_musicid', 0))
        round_before10.add_child(Node.s8('my_select_result', 0))
        round_before10.add_child(Node.s32('rival_select_musicid', 0))
        round_before10.add_child(Node.s8('rival_select_result', 0))

        round_before11 = Node.void('round')
        round_before11.set_attribute('before', "0")
        music_hist.add_child(round_before11)

        round_before11.add_child(Node.s16('point', 0))
        round_before11.add_child(Node.s32('my_select_musicid', 0))
        round_before11.add_child(Node.s8('my_select_result', 0))
        round_before11.add_child(Node.s32('rival_select_musicid', 0))
        round_before11.add_child(Node.s8('rival_select_result', 0))

        round_before12 = Node.void('round')
        round_before12.set_attribute('before', "0")
        music_hist.add_child(round_before12)

        round_before12.add_child(Node.s16('point', 0))
        round_before12.add_child(Node.s32('my_select_musicid', 0))
        round_before12.add_child(Node.s8('my_select_result', 0))
        round_before12.add_child(Node.s32('rival_select_musicid', 0))
        round_before12.add_child(Node.s8('rival_select_result', 0))

        round_before13 = Node.void('round')
        round_before13.set_attribute('before', "0")
        music_hist.add_child(round_before13)

        round_before13.add_child(Node.s16('point', 0))
        round_before13.add_child(Node.s32('my_select_musicid', 0))
        round_before13.add_child(Node.s8('my_select_result', 0))
        round_before13.add_child(Node.s32('rival_select_musicid', 0))
        round_before13.add_child(Node.s8('rival_select_result', 0))

        round_before14 = Node.void('round')
        round_before14.set_attribute('before', "0")
        music_hist.add_child(round_before14)

        round_before14.add_child(Node.s16('point', 0))
        round_before14.add_child(Node.s32('my_select_musicid', 0))
        round_before14.add_child(Node.s8('my_select_result', 0))
        round_before14.add_child(Node.s32('rival_select_musicid', 0))
        round_before14.add_child(Node.s8('rival_select_result', 0))

        round_before15 = Node.void('round')
        round_before15.set_attribute('before', "0")
        music_hist.add_child(round_before15)

        round_before15.add_child(Node.s16('point', 0))
        round_before15.add_child(Node.s32('my_select_musicid', 0))
        round_before15.add_child(Node.s8('my_select_result', 0))
        round_before15.add_child(Node.s32('rival_select_musicid', 0))
        round_before15.add_child(Node.s8('rival_select_result', 0))

        round_before16 = Node.void('round')
        round_before16.set_attribute('before', "0")
        music_hist.add_child(round_before16)

        round_before16.add_child(Node.s16('point', 0))
        round_before16.add_child(Node.s32('my_select_musicid', 0))
        round_before16.add_child(Node.s8('my_select_result', 0))
        round_before16.add_child(Node.s32('rival_select_musicid', 0))
        round_before16.add_child(Node.s8('rival_select_result', 0))

        round_before17 = Node.void('round')
        round_before17.set_attribute('before', "0")
        music_hist.add_child(round_before17)

        round_before17.add_child(Node.s16('point', 0))
        round_before17.add_child(Node.s32('my_select_musicid', 0))
        round_before17.add_child(Node.s8('my_select_result', 0))
        round_before17.add_child(Node.s32('rival_select_musicid', 0))
        round_before17.add_child(Node.s8('rival_select_result', 0))

        round_before18 = Node.void('round')
        round_before18.set_attribute('before', "0")
        music_hist.add_child(round_before18)

        round_before18.add_child(Node.s16('point', 0))
        round_before18.add_child(Node.s32('my_select_musicid', 0))
        round_before18.add_child(Node.s8('my_select_result', 0))
        round_before18.add_child(Node.s32('rival_select_musicid', 0))
        round_before18.add_child(Node.s8('rival_select_result', 0))

        round_before19 = Node.void('round')
        round_before19.set_attribute('before', "0")
        music_hist.add_child(round_before19)

        round_before19.add_child(Node.s16('point', 0))
        round_before19.add_child(Node.s32('my_select_musicid', 0))
        round_before19.add_child(Node.s8('my_select_result', 0))
        round_before19.add_child(Node.s32('rival_select_musicid', 0))
        round_before19.add_child(Node.s8('rival_select_result', 0))

        round_before20 = Node.void('round')
        round_before20.set_attribute('before', "0")
        music_hist.add_child(round_before20)

        round_before20.add_child(Node.s16('point', 0))
        round_before20.add_child(Node.s32('my_select_musicid', 0))
        round_before20.add_child(Node.s8('my_select_result', 0))
        round_before20.add_child(Node.s32('rival_select_musicid', 0))
        round_before20.add_child(Node.s8('rival_select_result', 0))

        quest = Node.void('quest')
        player_ret.add_child(quest)
        
        quest.add_child(Node.u8('quest_rank', 0))
        quest.add_child(Node.u32('star', 0))
        quest.add_child(Node.u64('fan', 0))
        qdata = Node.u32_array (
            'qdata',
            [
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
                0, 0, 0,
            ]
        )
        quest.add_child(qdata)
        test_data = Node.u32_array (
            'test_data',
            [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )
        quest.add_child(test_data)

        championship = Node.void('championship')
        player_ret.add_child(championship)

        playable = Node.s32_array (
            'playable',
            [
                0,
                0,
                0,
                0,
            ]
        )
        championship.add_child(playable)


        return root
    
    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)

        # get base song info
        modedata = request.child('modedata')
        playedmode = modedata.attribute('mode')

        if playedmode == "standard" :
            lastmode = 1
            newprofile.replace_int('playmode', lastmode)
        elif playedmode == "battle" :
            lastmode = 3
            newprofile.replace_int('playmode', lastmode)
        else :
            lastmode = 0
            newprofile.replace_int('playmode', lastmode)




        # get player stats
        player1 = request.child('player')
        usecard = player1.attribute('card')
        playernum = player1.attribute('no')

        #pull the base player info. even though it's mostly useless, the game still wants it.
        playerinfo = player1.child('playerinfo')

        gdp = playerinfo.child_value('gdp')
        total_skill_point = playerinfo.child_value('total_skill_point')
        styles = playerinfo.child_value('styles')
        styles2 = playerinfo.child_value('styles_2')
        chara = playerinfo.child_value('chara')
        #secret_chara = playerinfo.child_value('secret_chara')
        secret_chara = 0
        syogo = playerinfo.child_value('syogo')
        shutter_list = playerinfo.child_value('shutter_list')
        judge_logo_list = playerinfo.child_value('judge_logo_list')
        skin_list = playerinfo.child_value('skin_list')
        movie_list = playerinfo.child_value('movie_list')
        attack_effect_list = playerinfo.child_value('attack_effect_list')
        idle_screen = playerinfo.child_value('idle_screen')
        chance_point = playerinfo.child_value('chance_point')
        failed_cnt = playerinfo.child_value('failed_cnt')
        perfect = playerinfo.child_value('perfect')
        great = playerinfo.child_value('great')
        good = playerinfo.child_value('good')
        poor = playerinfo.child_value('poor')
        miss = playerinfo.child_value('miss')
        time = playerinfo.child_value('time')

        #pull battle shit
        bp = playerinfo.child_value('bp')
        reserv_item_list = playerinfo.child_value('reserv_item_list')


        #pull user info
        info = playerinfo.child('info')

        info_mode = info.child_value('mode')
        info_boss = info.child_value('boss')
        info_battle_aniv = info.child_value('battle_aniv')
        info_free_music = info.child_value('free_music')
        info_free_chara = info.child_value('free_chara')
        info_event = info.child_value('event')
        info_battle_event = info.child_value('battle_event')
        info_champ = info.child_value('champ')
        info_item = info.child_value('item')
        info_quest = info.child_value('quest')
        info_campaign = info.child_value('campaign')
        info_gdp = info.child_value('gdp')
        info_v7 = info.child_value('v7')
        info_champ_result = info.child_value('champ_result')

        #pull user customizations
        customize = playerinfo.child('customize')

        cust_shutter = customize.child_value('shutter')
        cust_info_level = customize.child_value('info_level')
        cust_name_disp = customize.child_value('name_disp')
        cust_auto = customize.child_value('auto')
        cust_random = customize.child_value('random')
        cust_judge_logo = customize.child_value('judge_logo')
        cust_skin = customize.child_value('skin')
        cust_movie = customize.child_value('movie')
        cust_attack_effect = customize.child_value('attack_effect')
        cust_layout = customize.child_value('layout')
        cust_target_skill = customize.child_value('target_skill')
        cust_comparison = customize.child_value('comparison')
        cust_meter_custom = customize.child_value('meter_custom')


        #save it all!!!!
        
        #first, we'll save the generic profile stuff
        newprofile.replace_int('gdp', gdp)
        newprofile.replace_int('styles', styles)
        newprofile.replace_int('styles_2', styles2)
        newprofile.replace_int('chara', chara)
        newprofile.replace_int('secret_chara', secret_chara)
        newprofile.replace_int('all_skill', total_skill_point)
        newprofile.replace_int_array('syogo', 2, syogo)
        newprofile.replace_int('shutter_list', shutter_list)
        newprofile.replace_int('judge_logo_list', judge_logo_list)
        newprofile.replace_int('skin_list', skin_list)
        newprofile.replace_int('movie_list', movie_list)
        newprofile.replace_int('attack_effect_list', attack_effect_list)
        newprofile.replace_int('idle_screen', idle_screen)
        newprofile.replace_int('chance_point', chance_point)
        newprofile.replace_int('failed_cnt', failed_cnt)
        newprofile.replace_int('great', great)
        newprofile.replace_int('perfect', perfect)
        newprofile.replace_int('good', good)
        newprofile.replace_int('poor', poor)
        newprofile.replace_int('miss', miss)
        newprofile.replace_int('time', time)

        # now save battle shit
        newprofile.replace_int('bp', bp)
        newprofile.replace_int_array('reserv_item_list', 200, reserv_item_list)

        # save user info
        newprofile.replace_int('info_mode', info_mode)
        newprofile.replace_int('info_boss', info_boss)
        newprofile.replace_int('info_battle_aniv', info_battle_aniv)
        newprofile.replace_int('info_free_music', info_free_music)
        newprofile.replace_int('info_free_chara', info_free_chara)
        newprofile.replace_int('info_event', info_event)
        newprofile.replace_int('info_battle_event', info_battle_event)
        newprofile.replace_int('info_champ', info_champ)
        newprofile.replace_int('info_item', info_item)
        newprofile.replace_int('info_quest', info_quest)
        newprofile.replace_int('info_campaign', info_campaign)
        newprofile.replace_int('info_gdp', info_gdp)
        newprofile.replace_int('info_v7', info_v7)
        newprofile.replace_int_array('info_champ_result', 2, info_champ_result)

        #save user settings
        newprofile.replace_int('cust_shutter', cust_shutter)
        newprofile.replace_int('cust_info_level', cust_info_level)
        newprofile.replace_int('cust_name_disp', cust_name_disp)
        newprofile.replace_int('cust_auto', cust_auto)
        newprofile.replace_int('cust_random', cust_random)
        newprofile.replace_int('cust_judge_logo', cust_judge_logo)
        newprofile.replace_int('cust_skin', cust_skin)
        newprofile.replace_int('cust_movie', cust_movie)
        newprofile.replace_int('cust_attack_effect', cust_attack_effect)
        newprofile.replace_int('cust_layout', cust_layout)
        newprofile.replace_int('cust_target_skill', cust_target_skill)
        newprofile.replace_int('cust_comparison', cust_comparison)
        newprofile.replace_int_array('cust_meter_custom', 3, cust_meter_custom)


        # Grab songdata and save
        stages = {}
        if modedata is not None:
            for stage in modedata.children:
                if stage.name != 'stage':
                    continue
                stages[stage.child_value('no')] = stage.child_value('musicid')
        if player1 is not None:
            for playdata in player1.children:
                if playdata.name != 'playdata':
                    continue
                songid = stages[playdata.child_value('no')]
                seqmode = playdata.child_value('seqmode')
                clear = playdata.child_value('clear')
                autoclear = playdata.child_value('autoclear')
                score = playdata.child_value('score')
                fullcombo = playdata.child_value('fullcombo')
                excellent = playdata.child_value('excellent')
                combo = playdata.child_value('combo')
                skill_point = playdata.child_value('skill_point')
                skill_perc = playdata.child_value('skill_perc')
                result_rank = playdata.child_value('result_rank')
                difficulty = playdata.child_value('difficulty')
                combo_rate = playdata.child_value('combo_rate')
                perfect_rate = playdata.child_value('perfect_rate')



                self.update_score(userid, songid, seqmode, clear, autoclear, score, fullcombo, excellent, combo, skill_point, skill_perc, result_rank, combo_rate, perfect_rate, difficulty)

        return newprofile

    def format_scores(self, userid: UserID, profile: ValidatedDict, scores: List[Score]) -> Node:
        scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)

        standard = Node.void('standard')

        easy = 0
        basic = 1
        advanced = 2
        extreme = 3

        combined_scores = {}
        for score in scores:
            song_id = score.id
            if song_id not in combined_scores:
                combined_scores[song_id] = {}

            combined_scores[song_id][score.chart] = score

        for key in combined_scores:
            scores = combined_scores[key]

            bsc_data = ValidatedDict()
            adv_data = ValidatedDict()
            ext_data = ValidatedDict()

            if basic in scores:
                bsc_data = ValidatedDict(scores[basic].data)
            if advanced in scores:
                adv_data = ValidatedDict(scores[advanced].data)
            if extreme in scores:
                ext_data = ValidatedDict(scores[extreme].data)

            # Basic
            bsc_clear = bsc_data.get_int('clear', 0)
            bsc_fullcombo = bsc_data.get_int('fullcombo', 0)
            bsc_excellent = bsc_data.get_int('excellent', 0)
            bsc_skill_points = bsc_data.get_int('skill_points', 0)
            bsc_skill_perc = bsc_data.get_int('skill_perc', -2)
            bsc_result_rank = bsc_data.get_int('result_rank', -2)
            bsc_combo_rate = bsc_data.get_int('combo_rate', 0)
            bsc_perfect_rate = bsc_data.get_int('perfect_rate', 0)

            # Advanced
            adv_clear = adv_data.get_int('clear', 0)
            adv_fullcombo = adv_data.get_int('fullcombo', 0)
            adv_excellent = adv_data.get_int('excellent', 0)
            adv_skill_points = adv_data.get_int('skill_points', 0)
            adv_skill_perc = adv_data.get_int('skill_perc', -2)
            adv_result_rank = adv_data.get_int('result_rank', -2)
            adv_combo_rate = adv_data.get_int('combo_rate', 0)
            adv_perfect_rate = adv_data.get_int('perfect_rate', 0)

            # Extreme
            ext_clear = ext_data.get_int('clear', 0)
            ext_fullcombo = ext_data.get_int('fullcombo', 0)
            ext_excellent = ext_data.get_int('excellent', 0)
            ext_skill_points = ext_data.get_int('skill_points', 0)
            ext_skill_perc = ext_data.get_int('skill_perc', -2)
            ext_result_rank = ext_data.get_int('result_rank', -2)
            ext_combo_rate = ext_data.get_int('combo_rate', 0)
            ext_perfect_rate = ext_data.get_int('perfect_rate', 0)


            cleared = -1
            if bsc_clear == 1 or adv_clear == 1 or ext_clear == 1:
                cleared = 0

            load_skill_points = 0
            if bsc_skill_points != 0:
                load_skill_points = bsc_skill_points
            elif adv_skill_points != 0:
                load_skill_points = adv_skill_points
            elif ext_skill_points != 0:
                load_skill_points = ext_skill_points

            flags = [0,0,0,0]
            flags[2] = flags[2] | bsc_clear << 1
            flags[2] = flags[2] | adv_clear << 2
            flags[2] = flags[2] | ext_clear << 3
            flags[0] = flags[0] | bsc_fullcombo << 1
            flags[0] = flags[0] | adv_fullcombo << 2
            flags[0] = flags[0] | ext_fullcombo << 3
            flags[1] = flags[1] | bsc_excellent << 1
            flags[1] = flags[1] | adv_excellent << 2
            flags[1] = flags[1] | ext_excellent << 3

            musicdata = Node.void('musicdata')
            standard.add_child(musicdata)
            musicdata.set_attribute('musicid', str(key))

            musicdata.add_child(Node.s16_array('mdata', [cleared, -1, bsc_skill_perc, adv_skill_perc, ext_skill_perc, -2, -2, -2, -2, -2, -2, bsc_result_rank, adv_result_rank, ext_result_rank, -2, -2, -2, -2, -2, -2,]))
            musicdata.add_child(Node.u16_array('flag', flags))
            musicdata.add_child(Node.s16_array('sdata', [0, load_skill_points, 2,]))
            musicdata.add_child(Node.s32_array('bdata', [0, 0,]))

        standard.set_attribute('nr', str(len(combined_scores)))

        return standard