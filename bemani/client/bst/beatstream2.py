from typing import Optional

from bemani.client.base import BaseClient
from bemani.common.constants import GameConstants, VersionConstants
from bemani.common.time import Time
from bemani.common.validateddict import Profile
from bemani.data import Song
from bemani.protocol import Node

class Beatstream2Client(BaseClient):
    name = 'TEST'

    def verify_player2_start(self, refid: str) -> int:
        call = self.call_node()

        player2 = Node.void("player2")
        player2.set_attribute('method', 'start')
        player2.add_child(Node.string("rid", refid))
        player2.add_child(Node.u8_array("ga", [192, 168, 1, 2]))
        player2.add_child(Node.u16("gp", 1234))
        player2.add_child(Node.u8_array("la", [192, 168, 1, 2]))

        call.add_child(player2)

        resp = self.exchange('', call)

        self.assert_path(resp, "response/player2/plyid")

        return resp.child_value("player2/plyid")
    
    def verify_player2_read(self, refid: str) -> Profile:
        call = self.call_node()

        player2 = Node.void("player2")
        player2.set_attribute('method', 'read')
        player2.add_child(Node.string("rid", refid))
        player2.add_child(Node.string("lid", "JP-1"))
        player2.add_child(Node.s16("ver", 0))

        call.add_child(player2)

        resp = self.exchange('', call)        

        self.assert_path(resp, "response/player2/pdata/account/usrid")
        self.assert_path(resp, "response/player2/pdata/base/name")

        profile = resp.child("player2/pdata")

        ret = Profile("bst", 2, refid, profile.child_value('account/usrid'))

        ret.replace_int('usrid', int(profile.child_value('account/usrid')))
        ret.replace_int('is_takeover', int(profile.child_value('account/is_takeover')))
        ret.replace_int('tpc', profile.child_value('account/tpc'))
        ret.replace_int('dpc', int(profile.child_value('account/dpc')))
        ret.replace_int('crd', int(profile.child_value('account/crd')))
        ret.replace_int('brd', int(profile.child_value('account/brd')))
        ret.replace_int('tdc', int(profile.child_value('account/tdc')))
        ret.replace_str('lid', profile.child_value('account/lid'))
        ret.replace_int('ver', int(profile.child_value('account/ver')))
        ret.replace_int('st', int(profile.child_value('account/st')))

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
        ret.replace_int('lcid', int(profile.child_value('base/lcid')))
        ret.replace_int('hat', int(profile.child_value('base/hat')))

        custom = profile.child_value('customize/custom')
        if custom is not None:
            customize = []
            for i in custom:
                customize.append(i)
            ret.replace_int_array('custom', 16, custom)


        ret.replace_int('last_tips', profile.child_value('tips/last_tips'))

        return ret
    
    def verify_player2_stagedata_write(self,  profile: Profile, song: Song, sid: int) -> None:
        call = self.call_node()
        player2 = Node.void("player2")
        player2.set_attribute('method', 'stagedata_write')

        player2.add_child(Node.s32('play_id', sid))
        player2.add_child(Node.s32('continue_count', 0))
        player2.add_child(Node.s32('stage_no', 0))
        player2.add_child(Node.s32('user_id', profile.get_int('usrid')))
        player2.add_child(Node.string('location_id', "JP-1"))
        player2.add_child(Node.s32('select_music_id', song.id))
        player2.add_child(Node.s32('select_grade', song.chart))
        player2.add_child(Node.s32('result_clear_gauge', 1000))
        player2.add_child(Node.s32('result_score', 888392))
        player2.add_child(Node.s32('result_max_combo', 114))
        player2.add_child(Node.s32('result_grade', 0))
        player2.add_child(Node.s32('result_medal', 3))
        player2.add_child(Node.s32('result_fanta', 68))
        player2.add_child(Node.s32('result_great', 35))
        player2.add_child(Node.s32('result_fine', 7))
        player2.add_child(Node.s32('result_miss', 2))

        call.add_child(player2)
        resp = self.exchange('', call)
        self.assert_path(resp, "response/player2/@status")

    def verify_player2_write(self, profile: Profile, sid: int) -> None:
        call = self.call_node()

        player2 = Node.void("player2")
        player2.set_attribute('method', 'write')

        pdata = Node.void('pdata')
        player2.add_child(pdata)
        
        account = Node.void('account')
        account.add_child(Node.s32('usrid', profile.get_int("usrid")))
        account.add_child(Node.s32('is_takeover', profile.get_int("is_takeover")))
        account.add_child(Node.s32('plyid', sid))
        account.add_child(Node.s32('continue_cnt', 0))
        account.add_child(Node.s32('tpc', profile.get_int("tpc")))
        account.add_child(Node.s32('dpc', profile.get_int("dpc")))
        account.add_child(Node.s32('crd', profile.get_int("crd")))
        account.add_child(Node.s32('brd', profile.get_int("brd")))
        account.add_child(Node.s32('tdc', profile.get_int("tdc")))
        account.add_child(Node.string('rid', profile.refid))
        account.add_child(Node.string('lid', "JP-1"))
        account.add_child(Node.s32('intrvld', profile.get_int("intrvld")))
        account.add_child(Node.s16('ver', profile.get_int("ver")))
        account.add_child(Node.u64('pst', profile.get_int("pst")))
        account.add_child(Node.u64('st', Time.now() * 1000))
        account.add_child(Node.bool('ea', profile.get_int("ea", True)))
        pdata.add_child(account)

        base = Node.void('base')
        base.add_child(Node.string('name', profile.get_str('name')))
        base.add_child(Node.s8('brnk', profile.get_int('brnk')))
        base.add_child(Node.s8('bcnum', profile.get_int('bcnum')))
        base.add_child(Node.s8('lcnum', profile.get_int('lcnum')))
        base.add_child(Node.s32('volt', profile.get_int('volt')))
        base.add_child(Node.s32('gold', profile.get_int('gold')))
        base.add_child(Node.s32('lmid', profile.get_int('lmid')))
        base.add_child(Node.s8('lgrd', profile.get_int('lgrd')))
        base.add_child(Node.s8('lsrt', profile.get_int('lsrt')))
        base.add_child(Node.s8('ltab', profile.get_int('ltab')))        
        base.add_child(Node.s8('splv', profile.get_int('splv')))
        base.add_child(Node.s8('pref', profile.get_int('pref')))
        base.add_child(Node.s32('lcid', profile.get_int('lcid')))
        base.add_child(Node.s32('hat', profile.get_int('hat')))
        pdata.add_child(base)

        pdata.add_child(Node.void("item"))

        customize = Node.void('customize')
        customize.add_child(Node.u16_array('custom', profile.get_int_array('custom', 16)))
        pdata.add_child(customize)

        tips = Node.void('tips')
        tips.add_child(Node.s32('last_tips', profile.get_int('last_tips')))
        pdata.add_child(tips)

        pdata.add_child(Node.void("hacker"))

        play_log = Node.void("play_log")

        crisis = Node.void("crysis")
        crisis.add_child(Node.s32("id", 0))
        crisis.add_child(Node.s32("stage_no", 0))
        crisis.add_child(Node.s8("step", 0))
        crisis.add_child(Node.s32("r_gauge", 95))
        crisis.add_child(Node.s8("r_state", 0))
        play_log.add_child(crisis)

        crisis = Node.void("crysis")
        crisis.add_child(Node.s32("id", 0))
        crisis.add_child(Node.s32("stage_no", 1))
        crisis.add_child(Node.s8("step", 1))
        crisis.add_child(Node.s32("r_gauge", 192))
        crisis.add_child(Node.s8("r_state", 1))
        play_log.add_child(crisis)
        
        crisis = Node.void("crysis")
        crisis.add_child(Node.s32("id", 0))
        crisis.add_child(Node.s32("stage_no", 2))
        crisis.add_child(Node.s8("step", 1))
        crisis.add_child(Node.s32("r_gauge", 214))
        crisis.add_child(Node.s8("r_state", 0))
        play_log.add_child(crisis)

        pdata.add_child(play_log)

        call.add_child(player2)

        resp = self.exchange('', call)
        self.assert_path(resp, "response/player2/uid")

    def verify_info2_result_image_write(self, profile: Profile, song: Song, sid: int) -> None:
        call = self.call_node()
        info2 = Node.void("info2")
        info2.set_attribute('method', 'result_image_write')

        info2.add_child(Node.s32("play_id", sid))
        info2.add_child(Node.s32("continue_no", 0))
        info2.add_child(Node.s32("stage_no", 0))
        info2.add_child(Node.string("ref_id", profile.refid))
        info2.add_child(Node.s32("beast_rank", 0))
        info2.add_child(Node.string("player_name", profile.get_str("name")))
        info2.add_child(Node.s32("music_id", song.id))
        info2.add_child(Node.s32("music_grade", 0))
        info2.add_child(Node.s32("music_level", song.chart))
        info2.add_child(Node.string("music_title", song.name))
        info2.add_child(Node.string("artist_name", song.artist))
        info2.add_child(Node.s32("gauge", 995))
        info2.add_child(Node.s32("grade", 0))
        info2.add_child(Node.s32("score", 820567))
        info2.add_child(Node.s32("best_score", 0))
        info2.add_child(Node.s32("medal", 3))
        info2.add_child(Node.bool("is_new_record", False))
        info2.add_child(Node.s32("fanta", 81))
        info2.add_child(Node.s32("great", 29))
        info2.add_child(Node.s32("fine", 23))
        info2.add_child(Node.s32("miss", 8))

        call.add_child(info2)
        resp = self.exchange('', call)
        self.assert_path(resp, "response/info2/@status")
        
    def verify_player2_end(self, refid: str) -> None:
        call = self.call_node()
        player2 = Node.void("player2")
        player2.set_attribute('method', 'end')
        player2.add_child(Node.string("rid", refid))
        call.add_child(player2)
        resp = self.exchange('', call)
        self.assert_path(resp, "response/player2/@status")

    def verify(self, cardid: Optional[str]) -> None:
        # Make sure we can card in properly
        refid = self.verify_cardmng_inquire(cardid, "query", True)
        sid = self.verify_player2_start(refid)
        profile = self.verify_player2_read(refid)

        # Make sure courses, songs, and scorecards save properly
        test_song = Song(GameConstants.BST, VersionConstants.BEATSTREAM_2,
        129, 0, "チョコレートスマイル", "ちよこれえとすまいる", "", {})
        
        self.verify_info2_result_image_write(profile, test_song, sid)
        self.verify_player2_stagedata_write(profile, test_song, sid)

        # Make sure profile saves properly, and game ends gracefully
        self.verify_player2_write(profile, sid)
        self.verify_player2_end(refid)
