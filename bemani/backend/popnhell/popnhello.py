# vim: set fileencoding=utf-8
import binascii
import copy
import base64
from collections import Iterable
from typing import Any, Dict, List, Sequence, Union

from bemani.backend.popnhell.base import PopnHelloBase
from bemani.backend.ess import EventLogHandler
from bemani.common import ValidatedDict, GameConstants, VersionConstants, Time
from bemani.data import UserID
from bemani.protocol import Node

class HelloPopnMusic(
    EventLogHandler,
    PopnHelloBase,
):
    name = "Hello! Pop'n Music"
    version = VersionConstants.HELLO_POPN_MUSIC

    @classmethod
    def handle_game_common_request(self, request: Node) -> Node:
        #game_common
        root = Node.void('game')

        flag = Node.void('flag')
        root.add_child(flag)

        flag.set_attribute(id, '1')
        flag.set_attribute(s1, '1')
        flag.set_attribute(s2, '1')
        flag.set_attribute(t, '1')

        root.add_child(Node.u32(cnt_music, 36))
        

        return root
    
    def handle_game_shop_request(self, request: Node) -> Node:
        #game_shop
        root = Node.void('game')

        return root

    def handle_game_new_request(self, request: Node) -> Node:
        #game_new
        root = Node.void('game')
        name = "0"
        chara = "0"
        last_music = "0"
        level = "0"
        style = "0"
        
        refid = request.attribute('refid')

        if refid is None:
            return None

        if name is None:
            name = "NONAME"

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        defaultprofile = ValidatedDict({
            'name': name,
            'chara': chara,
            'last_music': last_music,
            'level': level,
            'style': style
        })

        self.put_profile(userid, defaultprofile)

        return root

    def handle_game_load_request(self, request: Node) -> Node:
        #game_load
        root = Node.void('game')

        refid = request.attribute('refid')

        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)

        last = Node.void('last')
        root.add_child(last)
        last.set_attribute('chara', profile.get_str('chara'))
        last.set_attribute('level', profile.get_str('level'))
        last.set_attribute('music_id', profile.get_str('last_music'))
        last.set_attribute('style', profile.get_str('style'))


        return root

    def handle_game_load_m_request(self, request: Node) -> Node:
        #game_load_m
        root = Node.void('game')

        return root

    def handle_game_save_request(self, request: Node) -> Node:
        #game_save
        root = Node.void('game')

        refid = request.attribute('refid')
        last = request.child('last')
        last_chara = last.attribute('chara')
        last_level = last.attribute('level')
        last_love = last.attribute('love')
        last_music_id = last.attribute('music_id')
        last_style = last.attribute('style')

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        oldprofile = self.get_profile(userid)

        newprofile = copy.deepcopy(oldprofile)

        newprofile.replace_str('chara', last_chara)
        newprofile.replace_str('level', last_level)
        newprofile.replace_str('music_id', last_music_id)
        newprofile.replace_str('style', last_style)
        newprofile.replace_str('love', last_love)

        self.put_profile(userid, newprofile)

        return root

    def handle_game_save_m_request(self, request: Node) -> Node:
        #game_save_m
        root = Node.void('game')

        

        return root