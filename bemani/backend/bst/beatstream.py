import copy
import random
import struct
from typing import Optional, Dict, Any, List, Tuple
import time

from bemani.backend.bst.base import BSTBase

from bemani.common import Profile, ValidatedDict, VersionConstants, ID, Time
from bemani.backend.ess import EventLogHandler
from bemani.data import Data, UserID, Score
from bemani.protocol import Node

class Beatstream(EventLogHandler, BSTBase):
    name = "BeatStream"
    version = VersionConstants.BEATSTREAM
    #TODO: Beatstream 1 support

    GRADE_AAA = 1
    GRADE_AA = 2
    GRADE_A = 3
    GRADE_B = 4
    GRADE_C = 5
    GRADE_D = 6

    MEDAL_NOPLAY = 0
    MEDAL_FAILED = 1
    MEDAL_SAVED = 2
    MEDAL_CLEAR = 3
    MEDAL_FC = 4
    MEDAL_PERFECT = 5
    
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            'bools': [
                {
                    'name': 'Enable Local Matching',
                    'tip': 'Enable local matching between games.',
                    'category': 'game_config',
                    'setting': 'enable_local_match',
                },
                {
                    'name': 'Enable Global Matching',
                    'tip': 'Enable global matching between games.',
                    'category': 'game_config',
                    'setting': 'enable_global_match',
                },
            ]
        }

    def get_events(self) -> Node:
        root = super().get_events()
        game_config = self.get_game_config()
        
        # Campaign
        data = Node.void('data')
        data.add_child(Node.s32('type', 0))
        data.add_child(Node.s32('phase', 18))
        root.add_child(data)
        
        # Beast crissis
        data = Node.void('data')
        data.add_child(Node.s32('type', 1))
        data.add_child(Node.s32('phase', 4))
        root.add_child(data)

        # 5th KAC screen on the demo reel
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 1))
        root.add_child(data)
        
        # Eamuse app screenshots
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 2))
        root.add_child(data)
        
        # Enables continues
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 3))
        root.add_child(data)

        # Allows 3 stage with paseli
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 4))
        root.add_child(data)
        
        # Local matching at start of credit enable
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 7))
        if game_config.get_bool('enable_local_match'):
            root.add_child(data)
        
        # Controlls floor infection on attract screen ONLY
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 8))
        root.add_child(data)
        
        # Global matching during song loading enable
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 12))
        if game_config.get_bool('enable_global_match'):
            root.add_child(data)

        # Unlocks the bemani rockin fes songs
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 13))
        root.add_child(data) 

        # Enables Illil partner addition
        data = Node.void('data')
        data.add_child(Node.s32('type', 3))
        data.add_child(Node.s32('phase', 16))
        root.add_child(data)

        # Controls notifs when carding in      
        data = Node.void('data')
        data.add_child(Node.s32('type', 4))
        data.add_child(Node.s32('phase', 31))
        root.add_child(data)
        
        # Courses
        # 1 = 1-12, 2 = 13 and 14, 3 = 15, 4 = kami
        # any other value disables courses
        # need to set 1-4 to enable all courses
        for x in range(1,5):
            data = Node.void('data')
            data.add_child(Node.s32('type', 7))
            data.add_child(Node.s32('phase', x))
            root.add_child(data)
        
        # Beast Hacker
        data = Node.void('data')
        data.add_child(Node.s32('type', 8))
        data.add_child(Node.s32('phase', 10)) # Phase 1 - 9, plus unused 10th
        root.add_child(data)
        
        # First play free
        data = Node.void('data')
        data.add_child(Node.s32('type', 1100))
        data.add_child(Node.s32('phase', 2))
        root.add_child(data)
        
        return root

    # Helper method to unformat the player profile into a ValidatedDict for the DB
    def unformat_player_profile(self, profile: Node) -> Profile:
        userid = self.data.local.user.from_extid(self.game, self.version, profile.child_value('account/usrid'))
        ret = Profile(self.game, self.version, profile.child_value('account/rid'), profile.child_value('account/usrid'))

        # Account
        next_tpc = int(profile.child_value('account/tpc')) + 1
        ret.replace_int('usrid', int(profile.child_value('account/usrid')))
        ret.replace_int('tpc', next_tpc)
        ret.replace_int('dpc', int(profile.child_value('account/dpc')))
        ret.replace_int('crd', int(profile.child_value('account/crd')))
        ret.replace_int('brd', int(profile.child_value('account/brd')))
        ret.replace_int('tdc', int(profile.child_value('account/tdc')))
        ret.replace_str('lid', profile.child_value('account/lid'))
        ret.replace_int('ver', int(profile.child_value('account/ver')))

        # Base
        ret.replace_str('name', profile.child_value('base/name'))
        ret.replace_int('brnk', int(profile.child_value('base/brnk')))
        ret.replace_int('bcnum', int(profile.child_value('base/bcnum')))
        ret.replace_int('lcnum', int(profile.child_value('base/lcnum')))
        ret.replace_int('volt', int(profile.child_value('base/volt')))
        ret.replace_int('gold', int(profile.child_value('base/gold')))
        ret.replace_int('lmid', int(profile.child_value('base/lmid')))
        ret.replace_int('lgrd', int(profile.child_value('base/lgrd')))
        ret.replace_int('lsrt', int(profile.child_value('base/lsrt')))
        ret.replace_int('ltab', int(profile.child_value('base/ltab')))
        ret.replace_int('splv', int(profile.child_value('base/splv')))
        ret.replace_int('pref', int(profile.child_value('base/pref')))

        # Base2
        ret.replace_int('lcid', int(profile.child_value('base2/lcid')))
        ret.replace_int('hat', int(profile.child_value('base2/hat')))

        # Items stored as achievements
        items = profile.child('item')
        if items is not None and int(profile.child_value('account/usrid')) != 0:
            for i in items.children:
                self.data.local.user.put_achievement(self.game, self.version, userid, i.child_value('id'), 
                f"item_{i.child_value('type')}", {"type": i.child_value('type'), "param": i.child_value('param'), 
                "count": i.child_value('count')})

        # Customize
        custom = profile.child_value('customize/custom')
        if custom is not None:
            customize = []
            for i in custom:
                customize.append(i)
            ret.replace_int_array('custom', 16, custom)

        # Tips
        ret.replace_int('last_tips', profile.child_value('tips/last_tips'))

        # Beast hacker
        hacker = profile.child("hacker")
        for x in hacker.children:
            self.data.local.user.put_achievement(self.game, self.version, userid, x.child_value("id"), "hacker", {
                "state0": x.child_value("state0"), "state1": x.child_value("state1"), "state2": x.child_value("state2"), 
                "state3": x.child_value("state3"), "state4": x.child_value("state4")
            })
        return ret

    def handle_info_stagedata_write_request(self, request: Node) -> Node:
        userid = request.child_value('user_id')
        musicid = request.child_value('select_music_id')
        chartid = request.child_value('select_grade')
        location = self.get_machine_id()
        points = request.child_value('result_score')
        gauge = request.child_value('result_clear_gauge')
        max_combo = request.child_value('result_max_combo')
        grade = request.child_value('result_grade')
        medal = request.child_value('result_medal')
        fantastic_count = request.child_value('result_fanta')
        great_count = request.child_value('result_great')
        fine_count = request.child_value('result_fine')
        miss_count = request.child_value('result_miss')

        self.update_score(userid, musicid, chartid, location, points, gauge, 
        max_combo, grade, medal, fantastic_count, great_count, fine_count, miss_count)
        
        return Node.void('player')

    def handle_pcb_boot_request(self, request: Node) -> Node:
        machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
        arcade = self.data.local.machine.get_arcade(machine.arcade)
        pcb2 = Node.void('pcb')
        pcb2.set_attribute('status', '0')
        sinfo = Node.void('sinfo')
        pcb2.add_child(sinfo)
        
        sinfo_nm = Node.string('nm', arcade.name)
        sinfo_cl_enbl = Node.bool('cl_enbl', False)
        sinfo_cl_h = Node.u8('cl_h', 0)
        sinfo_cl_m = Node.u8('cl_m', 0)
        sinfo_shop_flag = Node.bool('shop_flag', True)

        sinfo.add_child(sinfo_nm)
        sinfo.add_child(sinfo_cl_enbl)
        sinfo.add_child(sinfo_cl_h)
        sinfo.add_child(sinfo_cl_m)
        sinfo.add_child(sinfo_shop_flag)

        return pcb2
    
    def handle_info_common_request(self, request: Node) -> Node:
        info2 = Node.void('info')
        info2.set_attribute('status', '0')

        event_ctrl = self.get_events()
        info2.add_child(event_ctrl)

        return info2

    # Called after settings_write, not sure what it does
    def handle_info_music_count_read_request(self, request: Node) -> Node:
        info2 = Node.void('info')
        record = Node.void('record')
        record.add_child(Node.void('rec'))
        record.add_child(Node.void('rate'))
        info2.add_child(record)
        return info2
    
    # Called after music_count_read. Might have something to do with song popularity?
    def handle_info_music_ranking_read_request(self, Request: Node) -> Node:
        info2 = Node.void('info')
        ranking = Node.void('ranking')
        ranking.add_child(Node.void('count'))
        info2.add_child(ranking)
        return info2

    # First call when somebody cards in, returns the status of a few crossover events
    def handle_player_start_request(self, request: Node) -> Node:
        userid = self.data.local.user.from_refid(self.game, self.version, request.child_value('rid'))
        profile = self.data.local.user.get_profile(self.game, self.version, userid)
        player = Node.void('player')

        plytime = Node.s32('plyid', 0)
        if profile is not None:
            plytime = Node.s32('plyid', profile.get_int("plyid", 1))
            
        player.add_child(plytime)

        start_time = Node.u64('start_time', Time.now() * 1000)
        player.add_child(start_time)

        return player
    
    def handle_lobby_entry_request(self, request: Node) -> Node:
        lobby = Node.void('lobby')
        lobby.add_child(Node.s32('interval', 120))
        lobby.add_child(Node.s32('interval_p', 120))
        selected_lobby = None
        userid = 0

        sessions = self.data.local.lobby.get_all_play_session_infos(self.game, self.version)
        requested_lobby_id = request.child_value('e/eid')
        
        # Beatstream always sends a uid of 0 in testing, so this is how we have to pull the UserID
        for usr, sesh in sessions:
            if sesh.get_str('pcbid') == self.config.machine.pcbid:
                userid = usr
                break

        if requested_lobby_id > 0:
            # Get the detales of the requested lobby
            for l in self.data.local.lobby.get_all_lobbies(self.game, self.version) or []:
                if l[1].get_int('id') == requested_lobby_id:
                    selected_lobby = l
                    break

        else:
            # Make a new lobby
            extid = self.data.local.user.get_extid(self.game, self.version, userid)
            self.data.local.lobby.put_lobby(
                self.game,
                self.version,
                userid,
                {
                    'ver': request.child_value('e/ver'),
                    'mid': request.child_value('e/mid'),
                    'rest': request.child_value('e/rest'),
                    'uid': extid,
                    'mmode': request.child_value('e/mmode'),
                    'mg': request.child_value('e/mg'),
                    'mopt': request.child_value('e/mopt'),
                    'lid': request.child_value('e/lid'),
                    'sn': request.child_value('e/sn'),
                    'pref': request.child_value('e/pref'),
                    'eatime': request.child_value('e/eatime'),
                    'ga': request.child_value('e/ga'),
                    'gp': request.child_value('e/gp'),
                    'la': request.child_value('e/la'),
                }
            )

            selected_lobby = self.data.local.lobby.get_lobby(self.game, self.version, userid)

        lobby.add_child(Node.s32('eid', selected_lobby.get_int('id')))
        e = Node.void('e')
        lobby.add_child(e)
        e.add_child(Node.s32('eid', selected_lobby.get_int('id')))
        e.add_child(Node.u8('ver', selected_lobby.get_int('ver')))
        e.add_child(Node.u16('mid', selected_lobby.get_int('mid')))
        e.add_child(Node.u8('rest', selected_lobby.get_int('rest')))
        e.add_child(Node.s32('uid', selected_lobby.get_int('uid')))
        e.add_child(Node.s32('mmode', selected_lobby.get_int('mmode')))
        e.add_child(Node.s16('mg', selected_lobby.get_int('mg')))
        e.add_child(Node.s32('mopt', selected_lobby.get_int('mopt')))        
        e.add_child(Node.string('lid', selected_lobby.get_str('lid')))
        e.add_child(Node.string('sn', selected_lobby.get_str('sn')))
        e.add_child(Node.u8('pref', selected_lobby.get_int('pref')))
        e.add_child(Node.s16('eatime', selected_lobby.get_int('eatime')))
        e.add_child(Node.u8_array('ga', selected_lobby.get_int_array('ga', 4)))
        e.add_child(Node.u16('gp', selected_lobby.get_int('gp')))
        e.add_child(Node.u8_array('la', selected_lobby.get_int_array('la', 4)))
        
        return lobby

    def handle_shop_setting_write_request(self, request: Node) -> Node:
        shop2 = Node.void('shop')
        #TODO: shop settings saving
        return shop2
    
    def handle_player_end_request(self, request: Node) -> Node:
        self.data.local.lobby.destroy_play_session_info(self.game, self.version, 
            self.data.local.user.from_refid(self.game, self.version, request.child_value("rid")))
        return Node.void('player')
    
    # Called either when carding out or creating a new profile
    def handle_player_write_request(self, request: Node) -> Node:
        refid = request.child_value('pdata/account/rid')
        extid = request.child_value('pdata/account/usrid')
        pdata = request.child('pdata')
        reply = Node.void('player')

        profile = self.unformat_player_profile(pdata)
        userid = self.data.remote.user.from_refid(self.game, self.version, refid) # Get the userid for the refid

        # The game always wants the extid sent back, so we only have to look it up if it's 0
        if extid == 0:            
            extid = self.data.local.user.get_extid(self.game, self.version, userid) # Get the extid for the profile we just saved
            profile.replace_int('usrid', extid) # Replace the extid in the profile with the one generated by butils
        
        self.put_profile(userid, profile) # Save the profile
        
        node_uid = Node.s32('uid', extid) # Send it back as a node
        reply.add_child(node_uid)

        return reply

    def handle_info_matching_data_write(self, request: Node) -> Node:
        return Node.void("info")
