# vim: set fileencoding=utf-8
import copy
from typing import Dict, List, Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.tunestreet import PopnMusicTuneStreet

from bemani.backend.base import Status
from bemani.common import Profile, VersionConstants, Time, ID
from bemani.data import Score, Link, UserID
from bemani.protocol import Node


class PopnMusicFantasia(PopnMusicBase):

    name = "Pop'n Music fantasia"
    version = VersionConstants.POPN_MUSIC_FANTASIA

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY = 2
    GAME_CHART_TYPE_NORMAL = 0
    GAME_CHART_TYPE_HYPER = 1
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
    GAME_MAX_MUSIC_ID = 1150

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicTuneStreet(self.data, self.config, self.model)

    def __format_medal_for_score(self, score: Score) -> int:
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
        position = {
            self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
            self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
            self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
            self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
        }[score.chart]
        return medal << (position * 4)

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void('playerdata')

        # Set up the base profile
        base = Node.void('base')
        root.add_child(base)
        base.add_child(Node.string('name', profile.get_str('name', 'なし')))
        base.add_child(Node.string('g_pm_id', ID.format_extid(profile.extid)))
        base.add_child(Node.u8('mode', profile.get_int('mode', 0)))
        base.add_child(Node.s8('button', profile.get_int('button', 0)))
        base.add_child(Node.s8('last_play_flag', profile.get_int('last_play_flag', -1)))
        base.add_child(Node.u8('medal_and_friend', profile.get_int('medal_and_friend', 0)))
        base.add_child(Node.s8('category', profile.get_int('category', -1)))
        base.add_child(Node.s8('sub_category', profile.get_int('sub_category', -1)))
        base.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        base.add_child(Node.s8('chara_category', profile.get_int('chara_category', -1)))
        base.add_child(Node.u8('collabo', profile.get_int('collabo', 255)))
        base.add_child(Node.u8('sheet', profile.get_int('sheet', 0)))
        base.add_child(Node.s8('tutorial', profile.get_int('tutorial', 0)))
        base.add_child(Node.s32('music_open_pt', profile.get_int('music_open_pt', 0)))
        base.add_child(Node.s8('is_conv', -1))
        base.add_child(Node.s32('option', profile.get_int('option', 0)))
        base.add_child(Node.s16('music', profile.get_int('music', -1)))
        base.add_child(Node.u16('ep', profile.get_int('ep', 0)))
        base.add_child(Node.s32_array('sp_color_flg', profile.get_int_array('sp_color_flg', 2)))
        base.add_child(Node.s32('read_news', profile.get_int('read_news', 0)))
        base.add_child(Node.s16('consecutive_days_coupon', profile.get_int('consecutive_days_coupon', 0)))
        base.add_child(Node.s8('staff', 0))

        # Player card section
        player_card_dict = profile.get_dict('player_card')
        player_card = Node.void('player_card')
        root.add_child(player_card)
        player_card.add_child(Node.u8_array('title', player_card_dict.get_int_array('title', 2, [0, 1])))
        player_card.add_child(Node.u8('frame', player_card_dict.get_int('frame')))
        player_card.add_child(Node.u8('base', player_card_dict.get_int('base')))
        player_card.add_child(Node.u8_array('seal', player_card_dict.get_int_array('seal', 2)))
        player_card.add_child(Node.s32_array('get_title', player_card_dict.get_int_array('get_title', 4)))
        player_card.add_child(Node.s32('get_frame', player_card_dict.get_int('get_frame')))
        player_card.add_child(Node.s32('get_base', player_card_dict.get_int('get_base')))
        player_card.add_child(Node.s32_array('get_seal', player_card_dict.get_int_array('get_seal', 2)))

        # Player card EX section
        player_card_ex = Node.void('player_card_ex')
        root.add_child(player_card_ex)
        player_card_ex.add_child(Node.s32('get_title_ex', player_card_dict.get_int('get_title_ex')))
        player_card_ex.add_child(Node.s32('get_frame_ex', player_card_dict.get_int('get_frame_ex')))
        player_card_ex.add_child(Node.s32('get_base_ex', player_card_dict.get_int('get_base_ex')))
        player_card_ex.add_child(Node.s32('get_seal_ex', player_card_dict.get_int('get_seal_ex')))

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
        base.add_child(Node.s32('total_play_cnt', statistics.get_int('total_plays', 0)))
        base.add_child(Node.s16('today_play_cnt', today_count))
        base.add_child(Node.s16('consecutive_days', statistics.get_int('consecutive_days', 0)))

        # Number of rivals that are active for this version.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivalcount = 0
        for link in links:
            if link.type != 'rival':
                continue

            if not self.has_profile(link.other_userid):
                continue

            # This profile is valid.
            rivalcount += 1
        base.add_child(Node.u8('active_fr_num', rivalcount))

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
            clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)

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

        player_card.add_child(Node.s16_array('best_music', most_played[0:3]))
        base.add_child(Node.s16_array('my_best', most_played))
        base.add_child(Node.s16_array('latest_music', last_played))
        base.add_child(Node.u16_array('clear_medal', clear_medal))
        base.add_child(Node.u8_array('clear_medal_sub', clear_medal_sub))

        # Goes outside of base for some reason
        root.add_child(Node.binary('hiscore', hiscore))

        # Net VS section
        netvs = Node.void('netvs')
        root.add_child(netvs)
        netvs.add_child(Node.s32_array('get_ojama', [0, 0]))
        netvs.add_child(Node.s32('rank_point', 0))
        netvs.add_child(Node.s32('play_point', 0))
        netvs.add_child(Node.s16_array('record', [0, 0, 0, 0, 0, 0]))
        netvs.add_child(Node.u8('rank', 0))
        netvs.add_child(Node.s8_array('ojama_condition', [0] * 74))
        netvs.add_child(Node.s8_array('set_ojama', [0, 0, 0]))
        netvs.add_child(Node.s8_array('set_recommend', [0, 0, 0]))
        netvs.add_child(Node.s8_array('jewelry', [0] * 15))
        for dialog in [0, 1, 2, 3, 4, 5]:
            # TODO: Configure this, maybe?
            netvs.add_child(Node.string('dialog', f'dialog#{dialog}'))

        sp_data = Node.void('sp_data')
        root.add_child(sp_data)
        sp_data.add_child(Node.s32('sp', profile.get_int('sp', 0)))

        reflec_data = Node.void('reflec_data')
        root.add_child(reflec_data)
        reflec_data.add_child(Node.s8_array('reflec', profile.get_int_array('reflec', 2)))

        # Navigate section
        navigate_dict = profile.get_dict('navigate')
        navigate = Node.void('navigate')
        root.add_child(navigate)
        navigate.add_child(Node.s8('genre', navigate_dict.get_int('genre')))
        navigate.add_child(Node.s8('image', navigate_dict.get_int('image')))
        navigate.add_child(Node.s8('level', navigate_dict.get_int('level')))
        navigate.add_child(Node.s8('ojama', navigate_dict.get_int('ojama')))
        navigate.add_child(Node.s16('limit_num', navigate_dict.get_int('limit_num')))
        navigate.add_child(Node.s8('button', navigate_dict.get_int('button')))
        navigate.add_child(Node.s8('life', navigate_dict.get_int('life')))
        navigate.add_child(Node.s16('progress', navigate_dict.get_int('progress')))

        return root

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void('playerdata')

        root.add_child(Node.string('name', profile.get_str('name', 'なし')))
        root.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        root.add_child(Node.s32('option', profile.get_int('option', 0)))
        root.add_child(Node.u8('version', 0))
        root.add_child(Node.u8('kind', 0))
        root.add_child(Node.u8('season', 0))

        clear_medal = [0] * self.GAME_MAX_MUSIC_ID

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

            clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)

        root.add_child(Node.u16_array('clear_medal', clear_medal))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        # For some reason, Pop'n 20 sends us two profile saves, one with 'not done yet'
        # so we only want to process the done yet node. The 'not gameover' save has
        # jubeat collabo stuff set in it, but we don't use that so it doesn't matter.
        if request.child_value('is_not_gameover') == 1:
            return oldprofile

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
        newprofile.replace_int('collabo', request.child_value('collabo'))

        sp_node = request.child('sp_data')
        if sp_node is not None:
            newprofile.replace_int('sp', sp_node.child_value('sp'))

        reflec_node = request.child('reflec_data')
        if reflec_node is not None:
            newprofile.replace_int_array('reflec', 2, reflec_node.child_value('reflec'))

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract player card stuff
        player_card_dict = newprofile.get_dict('player_card')
        player_card_dict.replace_int_array('title', 2, request.child_value('title'))
        player_card_dict.replace_int('frame', request.child_value('frame'))
        player_card_dict.replace_int('base', request.child_value('base'))
        player_card_dict.replace_int_array('seal', 2, request.child_value('seal'))
        player_card_dict.replace_int_array('get_title', 4, request.child_value('get_title'))
        player_card_dict.replace_int('get_frame', request.child_value('get_frame'))
        player_card_dict.replace_int('get_base', request.child_value('get_base'))
        player_card_dict.replace_int_array('get_seal', 2, request.child_value('get_seal'))

        player_card_ex = request.child('player_card_ex')
        if player_card_ex is not None:
            player_card_dict.replace_int('get_title_ex', player_card_ex.child_value('get_title_ex'))
            player_card_dict.replace_int('get_frame_ex', player_card_ex.child_value('get_frame_ex'))
            player_card_dict.replace_int('get_base_ex', player_card_ex.child_value('get_base_ex'))
            player_card_dict.replace_int('get_seal_ex', player_card_ex.child_value('get_seal_ex'))
        newprofile.replace_dict('player_card', player_card_dict)

        # Extract navigate stuff
        navigate_dict = newprofile.get_dict('navigate')
        navigate = request.child('navigate')
        if navigate is not None:
            navigate_dict.replace_int('genre', navigate.child_value('genre'))
            navigate_dict.replace_int('image', navigate.child_value('image'))
            navigate_dict.replace_int('level', navigate.child_value('level'))
            navigate_dict.replace_int('ojama', navigate.child_value('ojama'))
            navigate_dict.replace_int('limit_num', navigate.child_value('limit_num'))
            navigate_dict.replace_int('button', navigate.child_value('button'))
            navigate_dict.replace_int('life', navigate.child_value('life'))
            navigate_dict.replace_int('progress', navigate.child_value('progress'))
        newprofile.replace_dict('navigate', navigate_dict)

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

            oldprofile = self.get_profile(userid) or Profile(self.game, self.version, refid, 0)
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)
                root.add_child(Node.string('name', newprofile['name']))

            return root

        elif method == 'friend':
            refid = request.attribute('ref_id')
            root = Node.void('playerdata')

            # Look up our own user ID based on the RefID provided.
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                root.set_attribute('status', str(Status.NO_PROFILE))
                return root

            # Grab the links that we care about.
            links = self.data.local.user.get_links(self.game, self.version, userid)
            profiles: Dict[UserID, Profile] = {}
            rivals: List[Link] = []
            for link in links:
                if link.type != 'rival':
                    continue

                other_profile = self.get_profile(link.other_userid)
                if other_profile is None:
                    continue
                profiles[link.other_userid] = other_profile
                rivals.append(link)

            for rival in links[:2]:
                rivalid = rival.other_userid
                rivalprofile = profiles[rivalid]
                scores = self.data.remote.music.get_scores(self.game, self.version, rivalid)

                # First, output general profile info.
                friend = Node.void('friend')
                root.add_child(friend)

                # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
                # ranking numbers disappear and the player icon show a questionmark.
                friend.add_child(Node.s8('open', 1))

                # Set up some sane defaults.
                friend.add_child(Node.string('name', rivalprofile.get_str('name', 'なし')))
                friend.add_child(Node.string('g_pm_id', ID.format_extid(rivalprofile.extid)))
                friend.add_child(Node.s16('chara', rivalprofile.get_int('chara', -1)))

                # Perform hiscore/medal conversion.
                hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)
                clear_medal = [0] * self.GAME_MAX_MUSIC_ID
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
                    clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)

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
                friend.add_child(Node.u16_array('clear_medal', clear_medal))
                friend.add_child(Node.binary('hiscore', hiscore))

            return root

        # Invalid method
        return None

    def handle_game_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'get':
            # TODO: Hook these up to config so we can change this
            root = Node.void('game')
            root.add_child(Node.s32('game_phase', 2))
            root.add_child(Node.s32('ir_phase', 0))
            root.add_child(Node.s32('event_phase', 5))
            root.add_child(Node.s32('netvs_phase', 0))
            root.add_child(Node.s32('card_phase', 6))
            root.add_child(Node.s32('illust_phase', 2))
            root.add_child(Node.s32('psp_phase', 5))
            root.add_child(Node.s32('other_phase', 1))
            root.add_child(Node.s32('jubeat_phase', 1))
            root.add_child(Node.s32('public_phase', 3))
            root.add_child(Node.s32('kac_phase', 2))
            root.add_child(Node.s32('local_matching', 1))
            root.add_child(Node.s32('n_matching_sec', 60))
            root.add_child(Node.s32('l_matching_sec', 60))
            root.add_child(Node.s32('is_check_cpu', 0))
            root.add_child(Node.s32('week_no', 0))
            root.add_child(Node.s32_array('ng_illust', [0] * 10))
            root.add_child(Node.s16_array('sel_ranking', [-1] * 10))
            root.add_child(Node.s16_array('up_ranking', [-1] * 10))
            return root

        if method == 'active':
            # Update the name of this cab for admin purposes
            self.update_machine_name(request.child_value('shop_name'))
            return Node.void('game')

        if method == 'taxphase':
            return Node.void('game')

        # Invalid method
        return None

    def handle_lobby_request(self, request: Node) -> Optional[Node]:
        # Stub out the entire lobby service
        return Node.void('lobby')
