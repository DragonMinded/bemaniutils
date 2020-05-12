# vim: set fileencoding=utf-8
import copy
from typing import Dict, List, Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.sunnypark import PopnMusicSunnyPark

from bemani.backend.base import Status
from bemani.common import ValidatedDict, VersionConstants, Time, ID
from bemani.data import UserID, Link
from bemani.protocol import Node


class PopnMusicLapistoria(PopnMusicBase):

    name = "Pop'n Music ラピストリア"
    version = VersionConstants.POPN_MUSIC_LAPISTORIA

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY = 0
    GAME_CHART_TYPE_NORMAL = 1
    GAME_CHART_TYPE_HYPER = 2
    GAME_CHART_TYPE_EX = 3

    # Medal type, as returned from the game
    GAME_PLAY_MEDAL_CIRCLE_FAILED = 1
    GAME_PLAY_MEDAL_DIAMOND_FAILED = 2
    GAME_PLAY_MEDAL_STAR_FAILED = 3
    GAME_PLAY_MEDAL_EASY_CLEAR = 4
    GAME_PLAY_MEDAL_CIRCLE_CLEARED = 5
    GAME_PLAY_MEDAL_DIAMOND_CLEARED = 6
    GAME_PLAY_MEDAL_STAR_CLEARED = 7
    GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO = 8
    GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO = 9
    GAME_PLAY_MEDAL_STAR_FULL_COMBO = 10
    GAME_PLAY_MEDAL_PERFECT = 11

    # Max valud music ID for conversions and stuff
    GAME_MAX_MUSIC_ID = 1422

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicSunnyPark(self.data, self.config, self.model)

    def handle_info22_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'common':
            # TODO: Hook these up to config so we can change this
            phases = {
                # Unknown event
                0: 0,
                # Unknown event
                1: 0,
                # Pop'n Aura, max 10 (remov all aura requirements)
                2: 10,
                # Story
                3: 1,
                # BEMANI ruins Discovery!
                4: 0,
                # Unknown event
                5: 0,
                # Unknown event
                6: 0,
                # Unknown event
                7: 0,
                # Unknown event
                8: 0,
                # Unknown event
                9: 0,
                # Unknown event
                10: 0,
                # Unknown event
                11: 0,
                # Unknown event
                12: 0,
                # Unknown event
                13: 0,
                # Unknown event
                14: 0,
                # Unknown event
                15: 0,
                # Unknown event
                16: 0,
                # Unknown event
                17: 0,
                # Unknown event
                18: 0,
                # Unknown event
                19: 0,
            }
            stories = list(range(173))

            root = Node.void('info22')
            for phaseid in phases:
                phase = Node.void('phase')
                root.add_child(phase)
                phase.add_child(Node.s16('event_id', phaseid))
                phase.add_child(Node.s16('phase', phases[phaseid]))

            for storyid in stories:
                story = Node.void('story')
                root.add_child(story)
                story.add_child(Node.u32('story_id', storyid))
                story.add_child(Node.bool('is_limited', False))
                story.add_child(Node.u64('limit_date', 0))

            return root

        # Invalid method
        return None

    def handle_pcb22_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'boot':
            return Node.void('pcb22')
        elif method == 'error':
            return Node.void('pcb22')
        elif method == 'write':
            # Update the name of this cab for admin purposes
            self.update_machine_name(request.child_value('pcb_setting/name'))
            return Node.void('pcb22')

        # Invalid method
        return None

    def handle_lobby22_request(self, request: Node) -> Optional[Node]:
        # Stub out the entire lobby22 service
        return Node.void('lobby22')

    def handle_player22_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'read':
            refid = request.child_value('ref_id')
            # Pop'n Music 22 doesn't send a modelstring to load old profiles,
            # it just expects us to know. So always look for old profiles in
            # Pop'n 22 land.
            root = self.get_profile_by_refid(refid, self.OLD_PROFILE_FALLTHROUGH)
            if root is None:
                root = Node.void('player22')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'new':
            refid = request.child_value('ref_id')
            name = request.child_value('name')
            root = self.new_profile_by_refid(refid, name)
            if root is None:
                root = Node.void('player22')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'start':
            return Node.void('player22')

        elif method == 'logout':
            return Node.void('player22')

        elif method == 'write':
            refid = request.child_value('ref_id')

            root = Node.void('player22')
            if refid is None:
                return root

            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                return root

            oldprofile = self.get_profile(userid) or ValidatedDict()
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)

            return root

        elif method == 'friend':
            refid = request.attribute('ref_id')
            no = int(request.attribute('no', '-1'))

            root = Node.void('player22')
            if no < 0:
                root.add_child(Node.s8('result', 2))
                return root

            # Look up our own user ID based on the RefID provided.
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                root.add_child(Node.s8('result', 2))
                return root

            # Grab the links that we care about.
            links = self.data.local.user.get_links(self.game, self.version, userid)
            profiles: Dict[UserID, ValidatedDict] = {}
            rivals: List[Link] = []
            for link in links:
                if link.type != 'rival':
                    continue

                other_profile = self.get_profile(link.other_userid)
                if other_profile is None:
                    continue
                profiles[link.other_userid] = other_profile
                rivals.append(link)

            # Somehow requested an invalid profile.
            if no >= len(rivals):
                root.add_child(Node.s8('result', 2))
                return root
            rivalid = links[no].other_userid
            rivalprofile = profiles[rivalid]
            scores = self.data.remote.music.get_scores(self.game, self.version, rivalid)

            # First, output general profile info.
            friend = Node.void('friend')
            root.add_child(friend)
            friend.add_child(Node.s16('no', no))
            friend.add_child(Node.string('g_pm_id', ID.format_extid(rivalprofile.get_int('extid'))))
            friend.add_child(Node.string('name', rivalprofile.get_str('name', 'なし')))
            friend.add_child(Node.s16('chara', rivalprofile.get_int('chara', -1)))
            # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
            # ranking numbers disappear and the player icon show a questionmark.
            friend.add_child(Node.s8('is_open', 1))

            for score in scores:
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
                friend.add_child(music)
                music.set_attribute('music_num', str(score.id))
                music.set_attribute('sheet_num', str({
                    self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                    self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                    self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                    self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                }[score.chart]))
                music.set_attribute('score', str(points))
                music.set_attribute('clearmedal', str({
                    self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                    self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                    self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                    self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                    self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                    self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                    self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                    self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                    self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                    self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                    self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                }[medal]))

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

        elif method == 'write_music':
            refid = request.child_value('ref_id')

            root = Node.void('player22')
            if refid is None:
                return root

            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                return root

            songid = request.child_value('music_num')
            chart = {
                self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
                self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
            }[request.child_value('sheet_num')]
            medal = request.child_value('clearmedal')
            points = request.child_value('score')
            combo = request.child_value('combo')
            stats = {
                'cool': request.child_value('cool'),
                'great': request.child_value('great'),
                'good': request.child_value('good'),
                'bad': request.child_value('bad')
            }
            medal = {
                self.GAME_PLAY_MEDAL_CIRCLE_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
                self.GAME_PLAY_MEDAL_DIAMOND_FAILED: self.PLAY_MEDAL_DIAMOND_FAILED,
                self.GAME_PLAY_MEDAL_STAR_FAILED: self.PLAY_MEDAL_STAR_FAILED,
                self.GAME_PLAY_MEDAL_EASY_CLEAR: self.PLAY_MEDAL_EASY_CLEAR,
                self.GAME_PLAY_MEDAL_CIRCLE_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
                self.GAME_PLAY_MEDAL_DIAMOND_CLEARED: self.PLAY_MEDAL_DIAMOND_CLEARED,
                self.GAME_PLAY_MEDAL_STAR_CLEARED: self.PLAY_MEDAL_STAR_CLEARED,
                self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
                self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
                self.GAME_PLAY_MEDAL_STAR_FULL_COMBO: self.PLAY_MEDAL_STAR_FULL_COMBO,
                self.GAME_PLAY_MEDAL_PERFECT: self.PLAY_MEDAL_PERFECT,
            }[medal]
            self.update_score(userid, songid, chart, points, medal, combo=combo, stats=stats)
            return root

        # Invalid method
        return None

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        root = Node.void('player22')

        # Result
        root.add_child(Node.s8('result', 0))

        # Set up account
        account = Node.void('account')
        root.add_child(account)
        account.add_child(Node.string('name', profile.get_str('name', 'なし')))
        account.add_child(Node.string('g_pm_id', ID.format_extid(profile.get_int('extid'))))
        account.add_child(Node.s8('tutorial', profile.get_int('tutorial', -1)))
        account.add_child(Node.s16('read_news', profile.get_int('read_news', 0)))
        account.add_child(Node.s8('staff', 0))
        account.add_child(Node.s8('is_conv', 0))
        account.add_child(Node.s16('item_type', 0))
        account.add_child(Node.s16('item_id', 0))
        account.add_child(Node.s16_array('license_data', [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1]))

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
        account.add_child(Node.s16('total_play_cnt', statistics.get_int('total_plays', 0)))
        account.add_child(Node.s16('today_play_cnt', today_count))
        account.add_child(Node.s16('consecutive_days', statistics.get_int('consecutive_days', 0)))
        account.add_child(Node.s16('total_days', statistics.get_int('total_days', 0)))
        account.add_child(Node.s16('interval_day', 0))

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
        account.add_child(Node.u8('active_fr_num', rivalcount))

        # Add scores section
        last_played = [x[0] for x in self.data.local.music.get_last_played(self.game, self.version, userid, 5)]
        most_played = [x[0] for x in self.data.local.music.get_most_played(self.game, self.version, userid, 10)]
        while len(last_played) < 5:
            last_played.append(-1)
        while len(most_played) < 10:
            most_played.append(-1)

        account.add_child(Node.s16_array('my_best', most_played))
        account.add_child(Node.s16_array('latest_music', last_played))

        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
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
                self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
            }[score.chart]))
            music.add_child(Node.s16('cnt', score.plays))
            music.add_child(Node.s32('score', points))
            music.add_child(Node.u8('clear_type', {
                self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
            }[medal]))
            music.add_child(Node.s32('old_score', 0))
            music.add_child(Node.u8('old_clear_type', 0))

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
        netvs.add_child(Node.u32('netvs_play_cnt', 0))
        for dialog in [0, 1, 2, 3, 4, 5]:
            # TODO: Configure this, maybe?
            netvs.add_child(Node.string('dialog', f'dialog#{dialog}'))

        # Set up config
        config = Node.void('config')
        root.add_child(config)
        config.add_child(Node.u8('mode', profile.get_int('mode', 0)))
        config.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        config.add_child(Node.s16('music', profile.get_int('music', -1)))
        config.add_child(Node.u8('sheet', profile.get_int('sheet', 0)))
        config.add_child(Node.s8('category', profile.get_int('category', 1)))
        config.add_child(Node.s8('sub_category', profile.get_int('sub_category', -1)))
        config.add_child(Node.s8('chara_category', profile.get_int('chara_category', -1)))
        config.add_child(Node.s16('story_id', profile.get_int('story_id', -1)))
        config.add_child(Node.s16('course_id', profile.get_int('course_id', -1)))
        config.add_child(Node.s8('course_folder', profile.get_int('course_folder', -1)))
        config.add_child(Node.s8('story_folder', profile.get_int('story_folder', -1)))
        config.add_child(Node.s8('ms_banner_disp', profile.get_int('ms_banner_disp')))
        config.add_child(Node.s8('ms_down_info', profile.get_int('ms_down_info')))
        config.add_child(Node.s8('ms_side_info', profile.get_int('ms_side_info')))
        config.add_child(Node.s8('ms_raise_type', profile.get_int('ms_raise_type')))
        config.add_child(Node.s8('ms_rnd_type', profile.get_int('ms_rnd_type')))

        # Set up option
        option_dict = profile.get_dict('option')
        option = Node.void('option')
        root.add_child(option)
        option.add_child(Node.s16('hispeed', option_dict.get_int('hispeed', 10)))
        option.add_child(Node.u8('popkun', option_dict.get_int('popkun', 0)))
        option.add_child(Node.bool('hidden', option_dict.get_bool('hidden', False)))
        option.add_child(Node.s16('hidden_rate', option_dict.get_int('hidden_rate', -1)))
        option.add_child(Node.bool('sudden', option_dict.get_bool('sudden', False)))
        option.add_child(Node.s16('sudden_rate', option_dict.get_int('sudden_rate', -1)))
        option.add_child(Node.s8('randmir', option_dict.get_int('randmir', 0)))
        option.add_child(Node.s8('gauge_type', option_dict.get_int('gauge_type', 0)))
        option.add_child(Node.u8('ojama_0', option_dict.get_int('ojama_0', 0)))
        option.add_child(Node.u8('ojama_1', option_dict.get_int('ojama_1', 0)))
        option.add_child(Node.bool('forever_0', option_dict.get_bool('forever_0', False)))
        option.add_child(Node.bool('forever_1', option_dict.get_bool('forever_1', False)))
        option.add_child(Node.bool('full_setting', option_dict.get_bool('full_setting', False)))

        # Set up info
        info = Node.void('info')
        root.add_child(info)
        info.add_child(Node.u16('ep', profile.get_int('ep', 0)))
        info.add_child(Node.u16('ap', profile.get_int('ap', 0)))

        # Set up custom_cate
        custom_cate = Node.void('custom_cate')
        root.add_child(custom_cate)
        custom_cate.add_child(Node.s8('valid', 0))
        custom_cate.add_child(Node.s8('lv_min', -1))
        custom_cate.add_child(Node.s8('lv_max', -1))
        custom_cate.add_child(Node.s8('medal_min', -1))
        custom_cate.add_child(Node.s8('medal_max', -1))
        custom_cate.add_child(Node.s8('friend_no', -1))
        custom_cate.add_child(Node.s8('score_flg', -1))

        # Set up customize
        customize_dict = profile.get_dict('customize')
        customize = Node.void('customize')
        root.add_child(customize)
        customize.add_child(Node.u16('effect', customize_dict.get_int('effect')))
        customize.add_child(Node.u16('hukidashi', customize_dict.get_int('hukidashi')))
        customize.add_child(Node.u16('font', customize_dict.get_int('font')))
        customize.add_child(Node.u16('comment_1', customize_dict.get_int('comment_1')))
        customize.add_child(Node.u16('comment_2', customize_dict.get_int('comment_2')))

        # Set up achievements
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        for achievement in achievements:
            if achievement.type == 'item':
                itemtype = achievement.data.get_int('type')
                param = achievement.data.get_int('param')

                item = Node.void('item')
                root.add_child(item)
                item.add_child(Node.u8('type', itemtype))
                item.add_child(Node.u16('id', achievement.id))
                item.add_child(Node.u16('param', param))
                item.add_child(Node.bool('is_new', False))

            elif achievement.type == 'achievement':
                count = achievement.data.get_int('count')

                ach_node = Node.void('achievement')
                root.add_child(ach_node)
                ach_node.add_child(Node.u8('type', achievement.id))
                ach_node.add_child(Node.u32('count', count))

            elif achievement.type == 'chara':
                friendship = achievement.data.get_int('friendship')

                chara = Node.void('chara_param')
                root.add_child(chara)
                chara.add_child(Node.u16('chara_id', achievement.id))
                chara.add_child(Node.u16('friendship', friendship))

            elif achievement.type == 'story':
                chapter = achievement.data.get_int('chapter')
                gauge = achievement.data.get_int('gauge')
                cleared = achievement.data.get_bool('cleared')
                clear_chapter = achievement.data.get_int('clear_chapter')

                story = Node.void('story')
                root.add_child(story)
                story.add_child(Node.u32('story_id', achievement.id))
                story.add_child(Node.u32('chapter_id', chapter))
                story.add_child(Node.u16('gauge_point', gauge))
                story.add_child(Node.bool('is_cleared', cleared))
                story.add_child(Node.u32('clear_chapter', clear_chapter))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)

        account = request.child('account')
        if account is not None:
            newprofile.replace_int('tutorial', account.child_value('tutorial'))
            newprofile.replace_int('read_news', account.child_value('read_news'))

        info = request.child('info')
        if info is not None:
            newprofile.replace_int('ep', info.child_value('ep'))
            newprofile.replace_int('ap', info.child_value('ap'))

        config = request.child('config')
        if config is not None:
            newprofile.replace_int('mode', config.child_value('mode'))
            newprofile.replace_int('chara', config.child_value('chara'))
            newprofile.replace_int('music', config.child_value('music'))
            newprofile.replace_int('sheet', config.child_value('sheet'))
            newprofile.replace_int('category', config.child_value('category'))
            newprofile.replace_int('sub_category', config.child_value('sub_category'))
            newprofile.replace_int('chara_category', config.child_value('chara_category'))
            newprofile.replace_int('story_id', config.child_value('story_id'))
            newprofile.replace_int('course_id', config.child_value('course_id'))
            newprofile.replace_int('course_folder', config.child_value('course_folder'))
            newprofile.replace_int('story_folder', config.child_value('story_folder'))
            newprofile.replace_int('ms_banner_disp', config.child_value('ms_banner_disp'))
            newprofile.replace_int('ms_down_info', config.child_value('ms_down_info'))
            newprofile.replace_int('ms_side_info', config.child_value('ms_side_info'))
            newprofile.replace_int('ms_raise_type', config.child_value('ms_raise_type'))
            newprofile.replace_int('ms_rnd_type', config.child_value('ms_rnd_type'))

        option_dict = newprofile.get_dict('option')
        option = request.child('option')
        if option is not None:
            option_dict.replace_int('hispeed', option.child_value('hispeed'))
            option_dict.replace_int('popkun', option.child_value('popkun'))
            option_dict.replace_bool('hidden', option.child_value('hidden'))
            option_dict.replace_bool('sudden', option.child_value('sudden'))
            option_dict.replace_int('hidden_rate', option.child_value('hidden_rate'))
            option_dict.replace_int('sudden_rate', option.child_value('sudden_rate'))
            option_dict.replace_int('randmir', option.child_value('randmir'))
            option_dict.replace_int('gauge_type', option.child_value('gauge_type'))
            option_dict.replace_int('ojama_0', option.child_value('ojama_0'))
            option_dict.replace_int('ojama_1', option.child_value('ojama_1'))
            option_dict.replace_bool('forever_0', option.child_value('forever_0'))
            option_dict.replace_bool('forever_1', option.child_value('forever_1'))
            option_dict.replace_bool('full_setting', option.child_value('full_setting'))
        newprofile.replace_dict('option', option_dict)

        customize_dict = newprofile.get_dict('customize')
        customize = request.child('customize')
        if customize is not None:
            customize_dict.replace_int('effect', customize.child_value('effect'))
            customize_dict.replace_int('hukidashi', customize.child_value('hukidashi'))
            customize_dict.replace_int('font', customize.child_value('font'))
            customize_dict.replace_int('comment_1', customize.child_value('comment_1'))
            customize_dict.replace_int('comment_2', customize.child_value('comment_2'))
        newprofile.replace_dict('customize', customize_dict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract achievements
        for node in request.children:
            if node.name == 'item':
                if not node.child_value('is_new'):
                    # No need to save this one
                    continue

                itemid = node.child_value('id')
                itemtype = node.child_value('type')
                param = node.child_value('param')

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    'item',
                    {
                        'type': itemtype,
                        'param': param,
                    },
                )

            elif node.name == 'achievement':
                achievementid = node.child_value('type')
                count = node.child_value('count')

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    achievementid,
                    'achievement',
                    {
                        'count': count,
                    },
                )

            elif node.name == 'chara_param':
                charaid = node.child_value('chara_id')
                friendship = node.child_value('friendship')

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    charaid,
                    'chara',
                    {
                        'friendship': friendship,
                    },
                )

            elif node.name == 'story':
                storyid = node.child_value('story_id')
                chapter = node.child_value('chapter_id')
                gauge = node.child_value('gauge_point')
                cleared = node.child_value('is_cleared')
                clear_chapter = node.child_value('clear_chapter')

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    storyid,
                    'story',
                    {
                        'chapter': chapter,
                        'gauge': gauge,
                        'cleared': cleared,
                        'clear_chapter': clear_chapter,
                    },
                )

        return newprofile

    def format_conversion(self, userid: UserID, profile: ValidatedDict) -> Node:
        # Circular import, ugh
        from bemani.backend.popn.eclale import PopnMusicEclale

        root = Node.void('player23')
        root.add_child(Node.string('name', profile.get_str('name', 'なし')))
        root.add_child(Node.s16('chara', profile.get_int('chara', -1)))
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
                self.CHART_TYPE_EASY: PopnMusicEclale.GAME_CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL: PopnMusicEclale.GAME_CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER: PopnMusicEclale.GAME_CHART_TYPE_HYPER,
                self.CHART_TYPE_EX: PopnMusicEclale.GAME_CHART_TYPE_EX,
            }[score.chart]))
            music.add_child(Node.s32('score', points))
            music.add_child(Node.u8('clear_type', {
                self.PLAY_MEDAL_CIRCLE_FAILED: PopnMusicEclale.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                self.PLAY_MEDAL_DIAMOND_FAILED: PopnMusicEclale.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                self.PLAY_MEDAL_STAR_FAILED: PopnMusicEclale.GAME_PLAY_MEDAL_STAR_FAILED,
                self.PLAY_MEDAL_EASY_CLEAR: PopnMusicEclale.GAME_PLAY_MEDAL_EASY_CLEAR,
                self.PLAY_MEDAL_CIRCLE_CLEARED: PopnMusicEclale.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                self.PLAY_MEDAL_DIAMOND_CLEARED: PopnMusicEclale.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                self.PLAY_MEDAL_STAR_CLEARED: PopnMusicEclale.GAME_PLAY_MEDAL_STAR_CLEARED,
                self.PLAY_MEDAL_CIRCLE_FULL_COMBO: PopnMusicEclale.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                self.PLAY_MEDAL_DIAMOND_FULL_COMBO: PopnMusicEclale.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                self.PLAY_MEDAL_STAR_FULL_COMBO: PopnMusicEclale.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                self.PLAY_MEDAL_PERFECT: PopnMusicEclale.GAME_PLAY_MEDAL_PERFECT,
            }[medal]))
            music.add_child(Node.s16('cnt', score.plays))

        return root
