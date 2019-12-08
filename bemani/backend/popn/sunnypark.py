# vim: set fileencoding=utf-8
import copy
from typing import Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.fantasia import PopnMusicFantasia

from bemani.backend.base import Status
from bemani.common import ValidatedDict, VersionConstants, Time, ID
from bemani.data import UserID
from bemani.protocol import Node


class PopnMusicSunnyPark(PopnMusicBase):

    name = "Pop'n Music Sunny Park"
    version = VersionConstants.POPN_MUSIC_SUNNY_PARK

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY = 0
    GAME_CHART_TYPE_NORMAL = 1
    GAME_CHART_TYPE_HYPER = 2
    GAME_CHART_TYPE_EX = 3

    # Chart type, as packed into a hiscore binary
    GAME_CHART_TYPE_EASY_POSITION = 0
    GAME_CHART_TYPE_NORMAL_POSITION = 1
    GAME_CHART_TYPE_HYPER_POSITION = 2
    GAME_CHART_TYPE_EX_POSITION = 3

    # Medal type, as returned from the game
    GAME_PLAY_MEDAL_CIRCLE_FAILED = 1
    GAME_PLAY_MEDAL_DIAMOND_FAILED = 2
    GAME_PLAY_MEDAL_STAR_FAILED = 3
    GAME_PLAY_MEDAL_CIRCLE_CLEARED = 5
    GAME_PLAY_MEDAL_DIAMOND_CLEARED = 6
    GAME_PLAY_MEDAL_STAR_CLEARED = 7
    GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO = 9
    GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO = 10
    GAME_PLAY_MEDAL_STAR_FULL_COMBO = 11
    GAME_PLAY_MEDAL_PERFECT = 15

    # Maximum music ID for this game
    GAME_MAX_MUSIC_ID = 1350

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicFantasia(self.data, self.config, self.model)

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        root = Node.void('playerdata')

        # Set up the base profile
        base = Node.void('base')
        root.add_child(base)
        base.add_child(Node.string('name', profile.get_str('name', 'なし')))
        base.add_child(Node.string('g_pm_id', ID.format_extid(profile.get_int('extid'))))
        base.add_child(Node.u8('mode', profile.get_int('mode', 0)))
        base.add_child(Node.s8('button', profile.get_int('button', 0)))
        base.add_child(Node.s8('last_play_flag', profile.get_int('last_play_flag', -1)))
        base.add_child(Node.u8('medal_and_friend', profile.get_int('medal_and_friend', 0)))
        base.add_child(Node.s8('category', profile.get_int('category', -1)))
        base.add_child(Node.s8('sub_category', profile.get_int('sub_category', -1)))
        base.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        base.add_child(Node.s8('chara_category', profile.get_int('chara_category', -1)))
        base.add_child(Node.u8('collabo', 255))
        base.add_child(Node.u8('sheet', profile.get_int('sheet', 0)))
        base.add_child(Node.s8('tutorial', profile.get_int('tutorial', 0)))
        base.add_child(Node.s8('music_open_pt', profile.get_int('music_open_pt', 0)))
        base.add_child(Node.s8('is_conv', -1))
        base.add_child(Node.s32('option', profile.get_int('option', 0)))
        base.add_child(Node.s16('music', profile.get_int('music', -1)))
        base.add_child(Node.u16('ep', profile.get_int('ep', 0)))
        base.add_child(Node.s32_array('sp_color_flg', profile.get_int_array('sp_color_flg', 2)))
        base.add_child(Node.s32('read_news', profile.get_int('read_news', 0)))
        base.add_child(Node.s16('consecutive_days_coupon', profile.get_int('consecutive_days_coupon', 0)))
        base.add_child(Node.s8('staff', 0))
        # These are probably from an old event, but if they aren't present and defaulted,
        # then different songs show up in the Zoo event.
        base.add_child(Node.u16_array('gitadora_point', profile.get_int_array('gitadora_point', 3, [2000, 2000, 2000])))
        base.add_child(Node.u8('gitadora_select', profile.get_int('gitadora_select', 2)))

        # Statistics section and scores section
        statistics = self.get_play_statistics(userid)
        last_play_date = statistics.get_int_array('last_play_date', 3)
        today_play_date = Time.todays_date()
        if (
            last_play_date[0] == today_play_date[0] and
            last_play_date[1] == today_play_date[1] and
            last_play_date[2] == today_play_date[2]
        ):
            today_count = statistics.get_int('today_plays', 0)
        else:
            today_count = 0
        base.add_child(Node.u8('active_fr_num', 0))  # TODO: Hook up rivals code?
        base.add_child(Node.s32('total_play_cnt', statistics.get_int('total_plays', 0)))
        base.add_child(Node.s16('today_play_cnt', today_count))
        base.add_child(Node.s16('consecutive_days', statistics.get_int('consecutive_days', 0)))

        last_played = [x[0] for x in self.data.local.music.get_last_played(self.game, self.version, userid, 3)]
        most_played = [x[0] for x in self.data.local.music.get_most_played(self.game, self.version, userid, 20)]
        while len(last_played) < 3:
            last_played.append(-1)
        while len(most_played) < 20:
            most_played.append(-1)

        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)
        clear_medal = [0] * self.GAME_MAX_MUSIC_ID
        clear_medal_sub = [0] * self.GAME_MAX_MUSIC_ID

        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue

            points = score.points
            medal = {
                self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,  # Map approximately
                self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
            }[score.data.get_int('medal')]
            clear_medal[score.id] = clear_medal[score.id] | (medal << (score.chart * 4))

            hiscore_index = (score.id * 4) + {
                self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
            }[score.chart]
            hiscore_byte_pos = int((hiscore_index * 17) / 8)
            hiscore_bit_pos = int((hiscore_index * 17) % 8)
            hiscore_value = points << hiscore_bit_pos
            hiscore_array[hiscore_byte_pos] = hiscore_array[hiscore_byte_pos] | (hiscore_value & 0xFF)
            hiscore_array[hiscore_byte_pos + 1] = hiscore_array[hiscore_byte_pos + 1] | ((hiscore_value >> 8) & 0xFF)
            hiscore_array[hiscore_byte_pos + 2] = hiscore_array[hiscore_byte_pos + 2] | ((hiscore_value >> 16) & 0xFF)

        hiscore = bytes(hiscore_array)

        base.add_child(Node.s16_array('my_best', most_played))
        base.add_child(Node.s16_array('latest_music', last_played))
        base.add_child(Node.u16_array('clear_medal', clear_medal))
        base.add_child(Node.u8_array('clear_medal_sub', clear_medal_sub))

        # Goes outside of base for some reason
        root.add_child(Node.binary('hiscore', hiscore))

        # Avatar section
        avatar_dict = profile.get_dict('avatar')
        avatar = Node.void('avatar')
        root.add_child(avatar)
        avatar.add_child(Node.u8('hair', avatar_dict.get_int('hair', 0)))
        avatar.add_child(Node.u8('face', avatar_dict.get_int('face', 0)))
        avatar.add_child(Node.u8('body', avatar_dict.get_int('body', 0)))
        avatar.add_child(Node.u8('effect', avatar_dict.get_int('effect', 0)))
        avatar.add_child(Node.u8('object', avatar_dict.get_int('object', 0)))
        avatar.add_child(Node.u8_array('comment', avatar_dict.get_int_array('comment', 2)))
        avatar.add_child(Node.s32_array('get_hair', avatar_dict.get_int_array('get_hair', 2)))
        avatar.add_child(Node.s32_array('get_face', avatar_dict.get_int_array('get_face', 2)))
        avatar.add_child(Node.s32_array('get_body', avatar_dict.get_int_array('get_body', 2)))
        avatar.add_child(Node.s32_array('get_effect', avatar_dict.get_int_array('get_effect', 2)))
        avatar.add_child(Node.s32_array('get_object', avatar_dict.get_int_array('get_object', 2)))
        avatar.add_child(Node.s32_array('get_comment_over', avatar_dict.get_int_array('get_comment_over', 3)))
        avatar.add_child(Node.s32_array('get_comment_under', avatar_dict.get_int_array('get_comment_under', 3)))

        # Avatar add section
        avatar_add_dict = profile.get_dict('avatar_add')
        avatar_add = Node.void('avatar_add')
        root.add_child(avatar_add)
        avatar_add.add_child(Node.s32_array('get_hair', avatar_add_dict.get_int_array('get_hair', 2)))
        avatar_add.add_child(Node.s32_array('get_face', avatar_add_dict.get_int_array('get_face', 2)))
        avatar_add.add_child(Node.s32_array('get_body', avatar_add_dict.get_int_array('get_body', 2)))
        avatar_add.add_child(Node.s32_array('get_effect', avatar_add_dict.get_int_array('get_effect', 2)))
        avatar_add.add_child(Node.s32_array('get_object', avatar_add_dict.get_int_array('get_object', 2)))
        avatar_add.add_child(Node.s32_array('get_comment_over', avatar_add_dict.get_int_array('get_comment_over', 2)))
        avatar_add.add_child(Node.s32_array('get_comment_under', avatar_add_dict.get_int_array('get_comment_under', 2)))
        avatar_add.add_child(Node.s32_array('new_hair', avatar_add_dict.get_int_array('new_hair', 2)))
        avatar_add.add_child(Node.s32_array('new_face', avatar_add_dict.get_int_array('new_face', 2)))
        avatar_add.add_child(Node.s32_array('new_body', avatar_add_dict.get_int_array('new_body', 2)))
        avatar_add.add_child(Node.s32_array('new_effect', avatar_add_dict.get_int_array('new_effect', 2)))
        avatar_add.add_child(Node.s32_array('new_object', avatar_add_dict.get_int_array('new_object', 2)))
        avatar_add.add_child(Node.s32_array('new_comment_over', avatar_add_dict.get_int_array('new_comment_over', 2)))
        avatar_add.add_child(Node.s32_array('new_comment_under', avatar_add_dict.get_int_array('new_comment_under', 2)))

        # Net VS section
        netvs = Node.void('netvs')
        root.add_child(netvs)
        netvs.add_child(Node.s32('rank_point', 0))
        netvs.add_child(Node.s16_array('record', [0, 0, 0, 0, 0, 0]))
        netvs.add_child(Node.u8('rank', 0))
        netvs.add_child(Node.s8('vs_rank_old', 0))
        netvs.add_child(Node.s8_array('ojama_condition', [0] * 74))
        netvs.add_child(Node.s8_array('set_ojama', [0, 0, 0]))
        netvs.add_child(Node.s8_array('set_recommend', [0, 0, 0]))
        netvs.add_child(Node.u8('netvs_play_cnt', 0))
        for dialog in [0, 1, 2, 3, 4, 5]:
            # TODO: Configure this, maybe?
            netvs.add_child(Node.string('dialog', 'dialog#{}'.format(dialog)))

        sp_data = Node.void('sp_data')
        root.add_child(sp_data)
        sp_data.add_child(Node.s32('sp', profile.get_int('sp', 0)))

        gakuen = Node.void('gakuen_data')
        root.add_child(gakuen)
        gakuen.add_child(Node.s32('music_list', -1))

        saucer = Node.void('flying_saucer')
        root.add_child(saucer)
        saucer.add_child(Node.s32('music_list', -1))
        saucer.add_child(Node.s32('tune_count', -1))
        saucer.add_child(Node.u32('clear_norma', 0))
        saucer.add_child(Node.u32('clear_norma_add', 0))

        zoo_dict = profile.get_dict('zoo')
        zoo = Node.void('zoo')
        root.add_child(zoo)
        zoo.add_child(Node.u16_array('point', zoo_dict.get_int_array('point', 5)))
        zoo.add_child(Node.s32_array('music_list', zoo_dict.get_int_array('music_list', 2)))
        zoo.add_child(Node.s8_array('today_play_flag', zoo_dict.get_int_array('today_play_flag', 4)))

        triple = Node.void('triple_journey')
        root.add_child(triple)
        triple.add_child(Node.s32('music_list', -1))
        triple.add_child(Node.s32_array('boss_damage', [65534, 65534, 65534, 65534]))
        triple.add_child(Node.s32_array('boss_stun', [0, 0, 0, 0]))
        triple.add_child(Node.s32('magic_gauge', 0))
        triple.add_child(Node.s32('today_party', 0))
        triple.add_child(Node.bool('union_magic', False))
        triple.add_child(Node.float('base_attack_rate', 1.0))
        triple.add_child(Node.s32('iidx_play_num', 0))
        triple.add_child(Node.s32('reflec_play_num', 0))
        triple.add_child(Node.s32('voltex_play_num', 0))
        triple.add_child(Node.bool('iidx_play_flg', True))
        triple.add_child(Node.bool('reflec_play_flg', True))
        triple.add_child(Node.bool('voltex_play_flg', True))

        ios = Node.void('ios')
        root.add_child(ios)
        ios.add_child(Node.s32('continueRightAnswer', 30))
        ios.add_child(Node.s32('totalRightAnswer', 30))

        kac2013 = Node.void('kac2013')
        root.add_child(kac2013)
        kac2013.add_child(Node.s8('music_num', 0))
        kac2013.add_child(Node.s16('music', 0))
        kac2013.add_child(Node.u8('sheet', 0))

        baseball = Node.void('baseball_data')
        root.add_child(baseball)
        baseball.add_child(Node.s64('music_list', -1))

        for id in [3, 5, 7]:
            node = Node.void('floor_infection')
            root.add_child(node)
            node.add_child(Node.s32('infection_id', id))
            node.add_child(Node.s32('music_list', -1))

        return root

    def format_conversion(self, userid: UserID, profile: ValidatedDict) -> Node:
        # Circular import, ugh
        from bemani.backend.popn.lapistoria import PopnMusicLapistoria

        root = Node.void('playerdata')

        root.add_child(Node.string('name', profile.get_str('name', 'なし')))
        root.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        root.add_child(Node.s32('option', profile.get_int('option', 0)))
        root.add_child(Node.s8('result', 1))

        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue

            points = score.points
            medal = score.data.get_int('medal')

            music = Node.void('music')
            root.add_child(music)
            music.add_child(Node.s16('music_num', score.id))
            music.add_child(Node.u8('sheet_num', {
                self.CHART_TYPE_EASY: PopnMusicLapistoria.GAME_CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL: PopnMusicLapistoria.GAME_CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER: PopnMusicLapistoria.GAME_CHART_TYPE_HYPER,
                self.CHART_TYPE_EX: PopnMusicLapistoria.GAME_CHART_TYPE_EX,
            }[score.chart]))
            music.add_child(Node.s16('cnt', score.plays))
            music.add_child(Node.s32('score', 0))
            music.add_child(Node.u8('clear_type', 0))
            music.add_child(Node.s32('old_score', points))
            music.add_child(Node.u8('old_clear_type', {
                self.PLAY_MEDAL_CIRCLE_FAILED: PopnMusicLapistoria.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                self.PLAY_MEDAL_DIAMOND_FAILED: PopnMusicLapistoria.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                self.PLAY_MEDAL_STAR_FAILED: PopnMusicLapistoria.GAME_PLAY_MEDAL_STAR_FAILED,
                self.PLAY_MEDAL_EASY_CLEAR: PopnMusicLapistoria.GAME_PLAY_MEDAL_EASY_CLEAR,
                self.PLAY_MEDAL_CIRCLE_CLEARED: PopnMusicLapistoria.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                self.PLAY_MEDAL_DIAMOND_CLEARED: PopnMusicLapistoria.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                self.PLAY_MEDAL_STAR_CLEARED: PopnMusicLapistoria.GAME_PLAY_MEDAL_STAR_CLEARED,
                self.PLAY_MEDAL_CIRCLE_FULL_COMBO: PopnMusicLapistoria.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                self.PLAY_MEDAL_DIAMOND_FULL_COMBO: PopnMusicLapistoria.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                self.PLAY_MEDAL_STAR_FULL_COMBO: PopnMusicLapistoria.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                self.PLAY_MEDAL_PERFECT: PopnMusicLapistoria.GAME_PLAY_MEDAL_PERFECT,
            }[medal]))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)
        newprofile.replace_int('option', request.child_value('option'))
        newprofile.replace_int('chara', request.child_value('chara'))
        newprofile.replace_int('mode', request.child_value('mode'))
        newprofile.replace_int('button', request.child_value('button'))
        newprofile.replace_int('music', request.child_value('music'))
        newprofile.replace_int('sheet', request.child_value('sheet'))
        newprofile.replace_int('last_play_flag', request.child_value('last_play_flag'))
        newprofile.replace_int('category', request.child_value('category'))
        newprofile.replace_int('sub_category', request.child_value('sub_category'))
        newprofile.replace_int('chara_category', request.child_value('chara_category'))
        newprofile.replace_int('medal_and_friend', request.child_value('medal_and_friend'))
        newprofile.replace_int('ep', request.child_value('ep'))
        newprofile.replace_int_array('sp_color_flg', 2, request.child_value('sp_color_flg'))
        newprofile.replace_int('read_news', request.child_value('read_news'))
        newprofile.replace_int('consecutive_days_coupon', request.child_value('consecutive_days_coupon'))
        newprofile.replace_int('tutorial', request.child_value('tutorial'))
        newprofile.replace_int('music_open_pt', request.child_value('music_open_pt'))
        newprofile.replace_int_array('gitadora_point', 3, request.child_value('gitadora_point'))
        newprofile.replace_int('gitadora_select', request.child_value('gitadora_select'))

        sp_node = request.child('sp_data')
        if sp_node is not None:
            newprofile.replace_int('sp', sp_node.child_value('sp'))

        zoo_dict = newprofile.get_dict('zoo')
        zoo_node = request.child('zoo')
        if zoo_node is not None:
            zoo_dict.replace_int_array('point', 5, zoo_node.child_value('point'))
            zoo_dict.replace_int_array('music_list', 2, zoo_node.child_value('music_list'))
            zoo_dict.replace_int_array('today_play_flag', 4, zoo_node.child_value('today_play_flag'))
        newprofile.replace_dict('zoo', zoo_dict)

        avatar_dict = newprofile.get_dict('avatar')
        avatar_dict.replace_int('hair', request.child_value('hair'))
        avatar_dict.replace_int('face', request.child_value('face'))
        avatar_dict.replace_int('body', request.child_value('body'))
        avatar_dict.replace_int('effect', request.child_value('effect'))
        avatar_dict.replace_int('object', request.child_value('object'))
        avatar_dict.replace_int_array('comment', 2, request.child_value('comment'))
        avatar_dict.replace_int_array('get_hair', 2, request.child_value('get_hair'))
        avatar_dict.replace_int_array('get_face', 2, request.child_value('get_face'))
        avatar_dict.replace_int_array('get_body', 2, request.child_value('get_body'))
        avatar_dict.replace_int_array('get_effect', 2, request.child_value('get_effect'))
        avatar_dict.replace_int_array('get_object', 2, request.child_value('get_object'))
        avatar_dict.replace_int_array('get_comment_over', 3, request.child_value('get_comment_over'))
        avatar_dict.replace_int_array('get_comment_under', 3, request.child_value('get_comment_under'))
        newprofile.replace_dict('avatar', avatar_dict)

        avatar_add_dict = newprofile.get_dict('avatar_add')
        avatar_add_node = request.child('avatar_add')
        if avatar_add_node is not None:
            avatar_add_dict.replace_int_array('get_hair', 2, avatar_add_node.child_value('get_hair'))
            avatar_add_dict.replace_int_array('get_face', 2, avatar_add_node.child_value('get_face'))
            avatar_add_dict.replace_int_array('get_body', 2, avatar_add_node.child_value('get_body'))
            avatar_add_dict.replace_int_array('get_effect', 2, avatar_add_node.child_value('get_effect'))
            avatar_add_dict.replace_int_array('get_object', 2, avatar_add_node.child_value('get_object'))
            avatar_add_dict.replace_int_array('get_comment_over', 2, avatar_add_node.child_value('get_comment_over'))
            avatar_add_dict.replace_int_array('get_comment_under', 2, avatar_add_node.child_value('get_comment_under'))
            avatar_add_dict.replace_int_array('new_hair', 2, avatar_add_node.child_value('new_hair'))
            avatar_add_dict.replace_int_array('new_face', 2, avatar_add_node.child_value('new_face'))
            avatar_add_dict.replace_int_array('new_body', 2, avatar_add_node.child_value('new_body'))
            avatar_add_dict.replace_int_array('new_effect', 2, avatar_add_node.child_value('new_effect'))
            avatar_add_dict.replace_int_array('new_object', 2, avatar_add_node.child_value('new_object'))
            avatar_add_dict.replace_int_array('new_comment_over', 2, avatar_add_node.child_value('new_comment_over'))
            avatar_add_dict.replace_int_array('new_comment_under', 2, avatar_add_node.child_value('new_comment_under'))
        newprofile.replace_dict('avatar_add', avatar_add_dict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract scores
        for node in request.children:
            if node.name == 'stage':
                songid = node.child_value('no')
                chart = {
                    self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
                    self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                    self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                    self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
                }[node.child_value('sheet')]
                medal = (node.child_value('n_data') >> (chart * 4)) & 0x000F
                medal = {
                    self.GAME_PLAY_MEDAL_CIRCLE_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
                    self.GAME_PLAY_MEDAL_DIAMOND_FAILED: self.PLAY_MEDAL_DIAMOND_FAILED,
                    self.GAME_PLAY_MEDAL_STAR_FAILED: self.PLAY_MEDAL_STAR_FAILED,
                    self.GAME_PLAY_MEDAL_CIRCLE_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
                    self.GAME_PLAY_MEDAL_DIAMOND_CLEARED: self.PLAY_MEDAL_DIAMOND_CLEARED,
                    self.GAME_PLAY_MEDAL_STAR_CLEARED: self.PLAY_MEDAL_STAR_CLEARED,
                    self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_STAR_FULL_COMBO: self.PLAY_MEDAL_STAR_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_PERFECT: self.PLAY_MEDAL_PERFECT,
                }[medal]
                points = node.child_value('score')
                self.update_score(userid, songid, chart, points, medal)

        return newprofile

    def handle_game_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'get':
            # TODO: Hook these up to config so we can change this
            root = Node.void('game')
            root.add_child(Node.s32('ir_phase', 0))
            root.add_child(Node.s32('music_open_phase', 8))
            root.add_child(Node.s32('collabo_phase', 8))
            root.add_child(Node.s32('personal_event_phase', 10))
            root.add_child(Node.s32('shop_event_phase', 6))
            root.add_child(Node.s32('netvs_phase', 0))
            root.add_child(Node.s32('card_phase', 9))
            root.add_child(Node.s32('other_phase', 9))
            root.add_child(Node.s32('local_matching_enable', 1))
            root.add_child(Node.s32('n_matching_sec', 60))
            root.add_child(Node.s32('l_matching_sec', 60))
            root.add_child(Node.s32('is_check_cpu', 0))
            root.add_child(Node.s32('week_no', 0))
            root.add_child(Node.s16_array('sel_ranking', [-1, -1, -1, -1, -1]))
            root.add_child(Node.s16_array('up_ranking', [-1, -1, -1, -1, -1]))
            return root

        if method == 'active':
            # Update the name of this cab for admin purposes
            self.update_machine_name(request.child_value('shop_name'))
            return Node.void('game')

        if method == 'taxphase':
            return Node.void('game')

        # Invalid method
        return None

    def handle_playerdata_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'expire':
            return Node.void('playerdata')

        elif method == 'logout':
            return Node.void('playerdata')

        elif method == 'get':
            modelstring = request.attribute('model')
            refid = request.child_value('ref_id')
            root = self.get_profile_by_refid(
                refid,
                self.NEW_PROFILE_ONLY if modelstring is None else self.OLD_PROFILE_ONLY,
            )
            if root is None:
                root = Node.void('playerdata')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'conversion':
            refid = request.child_value('ref_id')
            name = request.child_value('name')
            chara = request.child_value('chara')
            root = self.new_profile_by_refid(refid, name, chara)
            if root is None:
                root = Node.void('playerdata')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'new':
            refid = request.child_value('ref_id')
            name = request.child_value('name')
            root = self.new_profile_by_refid(refid, name)
            if root is None:
                root = Node.void('playerdata')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'set':
            refid = request.attribute('ref_id')

            root = Node.void('playerdata')
            root.add_child(Node.s8('pref', -1))
            if refid is None:
                return root

            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                return root

            oldprofile = self.get_profile(userid) or ValidatedDict()
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)
                root.add_child(Node.string('name', newprofile['name']))

            return root

        # Invalid method
        return None
