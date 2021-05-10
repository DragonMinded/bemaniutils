# vim: set fileencoding=utf-8
import binascii
import copy
import base64
from collections import Iterable
from typing import Any, Dict, List, Sequence, Union

from bemani.backend.popnhell.base import PopnHelloBase
from bemani.backend.ess import EventLogHandler
from bemani.common import ValidatedDict, GameConstants, VersionConstants, Time
from bemani.data import UserID, Score
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

        flag.set_attribute("id", '1')
        flag.set_attribute("s1", '1')
        flag.set_attribute("s2", '1')
        flag.set_attribute("t", '1')

        root.add_child(Node.u32("cnt_music", 36))
        

        return root
    
    def handle_game_shop_request(self, request: Node) -> Node:
        #game_shop
        root = Node.void('game')

        return root

    def handle_game_new_request(self, request: Node) -> Node:
        #game_new
        root = Node.void('game')
        


        userid = self.data.remote.user.from_refid(self.game, self.version, request.attribute('refid'))

        defaultprofile = ValidatedDict({
            'name': "NONAME",
            'chara': "0",
            'music_id': "0",
            'level': "0",
            'style': "0",
            'love': "0"
        })

        self.put_profile(userid, defaultprofile)

        return root

    def handle_game_load_request(self, request: Node) -> Node:
        #game_load
        root = Node.void('game')


        userid = self.data.remote.user.from_refid(self.game, self.version, request.attribute('refid'))
        profile = self.get_profile(userid)

        for n in range(12):
            chara = Node.void('chara')
            chara.set_attribute('id', str(n))
            chara.set_attribute('love', "5")
            root.add_child(chara)

        last = Node.void('last')
        root.add_child(last)
        last.set_attribute('chara', profile.get_str('chara'))
        last.set_attribute('level', profile.get_str('level'))
        last.set_attribute('music_id', profile.get_str('music_id'))
        last.set_attribute('style', profile.get_str('style'))


        return root

    def handle_game_load_m_request(self, request: Node) -> Node:
        #game_load_m
        userid = self.data.remote.user.from_refid(self.game, self.version, request.attribute('refid'))

        #get scores
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)

        root = Node.void('game')

        sortedscores: Dict[int, Dict[int, Score]] = {}
        for score in scores:
            if score.id not in sortedscores:
                sortedscores[score.id] = {}
            sortedscores[score.id][score.chart] = score
        
        for song in sortedscores:

            for chart in sortedscores[song]:
                score = sortedscores[song][chart]

                music = Node.void('music')
                root.add_child(music)
                music.set_attribute('music_id', str(score.chart))

                style = Node.void('style')
                music.add_child(style)
                style.set_attribute('id', str(score.id))

                level = Node.void('level')
                style.add_child(level)

                level.set_attribute('id', str(score.id))
                level.set_attribute('score', str(score.points))
                level.set_attribute('clear_type', str(score.data.get_int('clear_type')))


        return root

    def handle_game_save_request(self, request: Node) -> Node:
        #game_save
        root = Node.void('game')

        userid = self.data.remote.user.from_refid(self.game, self.version, request.attribute('refid'))
        oldprofile = self.get_profile(userid)

        newprofile = copy.deepcopy(oldprofile)

        last = request.child('last')
        newprofile.replace_str('chara', last.attribute('chara'))
        newprofile.replace_str('level', last.attribute('level'))
        newprofile.replace_str('music_id', last.attribute('music_id'))
        newprofile.replace_str('style', last.attribute('style'))
        newprofile.replace_str('love', last.attribute('love'))

        self.put_profile(userid, newprofile)

        return root

    def handle_game_save_m_request(self, request: Node) -> Node:
        #game_save_m

        clear_type = int(request.attribute('clear_type'))
        level = int(request.attribute('level'))
        songid = int(request.attribute('music_id'))
        refid = request.attribute('refid')
        points = int(request.attribute('score'))

        #userid
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        

        #pull old score
        oldscore = self.data.local.music.get_score(
            self.game,
            self.version,
            userid,
            songid,
            level,
        )

        history = ValidatedDict({})
        oldpoints = points

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict({})
            raised = True
            highscore = True
        else:
            # Set the score to any new record achieved
            raised = points > oldscore.points
            highscore = points >= oldscore.points
            points = max(oldscore.points, points)
            scoredata = oldscore.data
        
        #how did we clear the song?
        scoredata.replace_int('clear_type', max(scoredata.get_int('clear_type'), clear_type))
        history.replace_int('clear_type', clear_type)

        # Look up where this score was earned
        lid = self.get_machine_id()


        # Write the new score back
        self.data.local.music.put_score(
            self.game,
            self.version,
            userid,
            songid,
            level,
            lid,
            points,
            scoredata,
            highscore,
        )

        # Save the history of this score too
        self.data.local.music.put_attempt(
            self.game,
            self.version,
            userid,
            songid,
            level,
            lid,
            points,
            history,
            highscore,
        )
        
        root = Node.void('game')

        return root