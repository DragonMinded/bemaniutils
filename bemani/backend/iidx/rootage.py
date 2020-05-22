# vim: set fileencoding=utf-8
import copy
import struct
from typing import Optional, Dict, Any

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.sinobuz import IIDXSinobuz
from bemani.backend.iidx.cannonballers import IIDXCannonBallers

from bemani.common import ValidatedDict, Model, VersionConstants, Time, ID, intish
from bemani.data import Data, UserID
from bemani.protocol import Node

# todo: clear '?' mark
class IIDXRootage(IIDXBase):

    name = 'Beatmania IIDX ROOTAGE'
    version = VersionConstants.IIDX_ROOTAGE
    sinobuz = None

    # todo: concurrency?
    def s(self) -> IIDXSinobuz:
        if self.sinobuz is None:
            self.sinobuz = IIDXSinobuz(self.data, self.config, self.model)
        return self.sinobuz


    # proxied: sinobuz.py
    def db_to_game_status(self, db_status: int) -> int:
        return self.s().db_to_game_status(db_status)
    def game_to_db_status(self, game_status: int) -> int:
        return self.s().game_to_db_status(game_status)
    def db_to_game_rank(self, db_dan: int, cltype: int) -> int:
        return self.s().db_to_game_rank(db_dan, cltype)
    def game_to_db_rank(self, game_dan: int, cltype: int) -> int:
        return self.s().game_to_db_rank(game_dan, cltype)


    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXCannonBallers(self.data, self.config, self.model)


    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        # modified from sinobuz.py
        root = Node.void('IIDX26pc')

        # Look up play stats we bridge to every mix
        play_stats = self.get_play_statistics(userid)

        # Look up judge window adjustments
        judge_dict = profile.get_dict('machine_judge_adjust')
        machine_judge = judge_dict.get_dict(self.config['machine']['pcbid'])

        # Profile data
        pcdata = Node.void('pcdata')
        pcdata.set_attribute('id', str(profile.get_int('extid')))
        pcdata.set_attribute('idstr', ID.format_extid(profile.get_int('extid')))
        pcdata.set_attribute('name', profile.get_str('name'))
        pcdata.set_attribute('pid', str(profile.get_int('pid')))
        pcdata.set_attribute('spnum', str(play_stats.get_int('single_plays')))
        pcdata.set_attribute('dpnum', str(play_stats.get_int('double_plays')))
        pcdata.set_attribute('sach', str(play_stats.get_int('single_dj_points')))
        pcdata.set_attribute('dach', str(play_stats.get_int('double_dj_points')))
        pcdata.set_attribute('mode', str(profile.get_int('mode')))
        pcdata.set_attribute('pmode', str(profile.get_int('pmode')))
        pcdata.set_attribute('rtype', str(profile.get_int('rtype')))
        pcdata.set_attribute('sp_opt', str(profile.get_int('sp_opt')))
        pcdata.set_attribute('dp_opt', str(profile.get_int('dp_opt')))
        pcdata.set_attribute('dp_opt2', str(profile.get_int('dp_opt2')))
        pcdata.set_attribute('gpos', str(profile.get_int('gpos')))
        pcdata.set_attribute('s_sorttype', str(profile.get_int('s_sorttype')))
        pcdata.set_attribute('d_sorttype', str(profile.get_int('d_sorttype')))
        pcdata.set_attribute('s_pace', str(profile.get_int('s_pace')))
        pcdata.set_attribute('d_pace', str(profile.get_int('d_pace')))
        pcdata.set_attribute('s_gno', str(profile.get_int('s_gno')))
        pcdata.set_attribute('d_gno', str(profile.get_int('d_gno')))
        pcdata.set_attribute('s_gtype', str(profile.get_int('s_gtype')))
        pcdata.set_attribute('d_gtype', str(profile.get_int('d_gtype')))
        pcdata.set_attribute('s_sdlen', str(profile.get_int('s_sdlen')))
        pcdata.set_attribute('d_sdlen', str(profile.get_int('d_sdlen')))
        pcdata.set_attribute('s_sdtype', str(profile.get_int('s_sdtype')))
        pcdata.set_attribute('d_sdtype', str(profile.get_int('d_sdtype')))
        pcdata.set_attribute('s_timing', str(profile.get_int('s_timing')))
        pcdata.set_attribute('d_timing', str(profile.get_int('d_timing')))
        pcdata.set_attribute('s_notes', str(profile.get_float('s_notes')))
        pcdata.set_attribute('d_notes', str(profile.get_float('d_notes')))
        pcdata.set_attribute('s_judge', str(profile.get_int('s_judge')))
        pcdata.set_attribute('d_judge', str(profile.get_int('d_judge')))
        pcdata.set_attribute('s_judgeAdj', str(machine_judge.get_int('single')))
        pcdata.set_attribute('d_judgeAdj', str(machine_judge.get_int('double')))
        pcdata.set_attribute('s_hispeed', str(profile.get_float('s_hispeed')))
        pcdata.set_attribute('d_hispeed', str(profile.get_float('d_hispeed')))
        pcdata.set_attribute('s_liflen', str(profile.get_int('s_lift')))
        pcdata.set_attribute('d_liflen', str(profile.get_int('d_lift')))
        pcdata.set_attribute('s_disp_judge', str(profile.get_int('s_disp_judge')))
        pcdata.set_attribute('d_disp_judge', str(profile.get_int('d_disp_judge')))
        pcdata.set_attribute('s_opstyle', str(profile.get_int('s_opstyle')))
        pcdata.set_attribute('d_opstyle', str(profile.get_int('d_opstyle')))
        pcdata.set_attribute('s_graph_score', str(profile.get_int('s_graph_score')))
        pcdata.set_attribute('d_graph_score', str(profile.get_int('d_graph_score')))
        pcdata.set_attribute('s_auto_scrach', str(profile.get_int('s_auto_scrach')))
        pcdata.set_attribute('d_auto_scrach', str(profile.get_int('d_auto_scrach')))
        pcdata.set_attribute('s_gauge_disp', str(profile.get_int('s_gauge_disp')))
        pcdata.set_attribute('d_gauge_disp', str(profile.get_int('d_gauge_disp')))
        pcdata.set_attribute('s_lane_brignt', str(profile.get_int('s_lane_brignt')))
        pcdata.set_attribute('d_lane_brignt', str(profile.get_int('d_lane_brignt')))
        pcdata.set_attribute('s_camera_layout', str(profile.get_int('s_camera_layout')))
        pcdata.set_attribute('d_camera_layout', str(profile.get_int('d_camera_layout')))
        pcdata.set_attribute('s_ghost_score', str(profile.get_int('s_ghost_score')))
        pcdata.set_attribute('d_ghost_score', str(profile.get_int('d_ghost_score')))
        pcdata.set_attribute('s_tsujigiri_disp', str(profile.get_int('s_tsujigiri_disp')))
        pcdata.set_attribute('d_tsujigiri_disp', str(profile.get_int('d_tsujigiri_disp')))
        root.add_child(pcdata)

        # weekly_achieve?

        spdp_rival = Node.void('spdp_rival')
        spdp_rival.set_attribute('flg', str(profile.get_int('spdp_rival_flag')))
        root.add_child(spdp_rival)

        # bind_eaappli?

        root.add_child(Node.void('ea_premium_course'))

        root.add_child(Node.void('enable_qr_reward'))

        # kac_entry_info?

        root.add_child(Node.void('leggendaria_open'))

        # Song unlock flags
        secret_dict = profile.get_dict('secret')
        secret = Node.void('secret')
        secret.add_child(Node.s64_array('flg1', secret_dict.get_int_array('flg1', 3)))
        secret.add_child(Node.s64_array('flg2', secret_dict.get_int_array('flg2', 3)))
        secret.add_child(Node.s64_array('flg3', secret_dict.get_int_array('flg3', 3)))
        root.add_child(secret)

        # Favorites
        for folder in ['favorite1', 'favorite2', 'favorite3']:
            favorite_dict = profile.get_dict(folder)
            sp_mlist = b''
            sp_clist = b''
            singles_list = favorite_dict['single'] if 'single' in favorite_dict else []
            for single in singles_list:
                sp_mlist = sp_mlist + struct.pack('<L', single['id'])
                sp_clist = sp_clist + struct.pack('B', single['chart'])
            while len(sp_mlist) < (4 * self.s().FAVORITE_LIST_LENGTH):
                sp_mlist = sp_mlist + b'\x00\x00\x00\x00'
            while len(sp_clist) < self.s().FAVORITE_LIST_LENGTH:
                sp_clist = sp_clist + b'\x00'

            dp_mlist = b''
            dp_clist = b''
            doubles_list = favorite_dict['double'] if 'double' in favorite_dict else []
            for double in doubles_list:
                dp_mlist = dp_mlist + struct.pack('<L', double['id'])
                dp_clist = dp_clist + struct.pack('B', double['chart'])
            while len(dp_mlist) < (4 * self.s().FAVORITE_LIST_LENGTH):
                dp_mlist = dp_mlist + b'\x00\x00\x00\x00'
            while len(dp_clist) < self.s().FAVORITE_LIST_LENGTH:
                dp_clist = dp_clist + b'\x00'

            if folder == 'favorite1':
                favorite = Node.void('favorite')
            elif folder == 'favorite2':
                favorite = Node.void('extra_favorite')
                favorite.set_attribute('folder_id', '0')
            elif folder == 'favorite3':
                favorite = Node.void('extra_favorite')
                favorite.set_attribute('folder_id', '1')
            favorite.add_child(Node.binary('sp_mlist', sp_mlist))
            favorite.add_child(Node.binary('sp_clist', sp_clist))
            favorite.add_child(Node.binary('dp_mlist', dp_mlist))
            favorite.add_child(Node.binary('dp_clist', dp_clist))
            root.add_child(favorite)

        # playlist?

        # Qpro secret data from step-up mode
        qpro_secrete_dict = profile.get_dict('qpro_secret')
        qpro_secret = Node.void('qpro_secret')
        qpro_secret.add_child(Node.s64_array('head', qpro_secrete_dict.get_int_array('head', 5)))
        qpro_secret.add_child(Node.s64_array('hair', qpro_secrete_dict.get_int_array('hair', 5)))
        qpro_secret.add_child(Node.s64_array('face', qpro_secrete_dict.get_int_array('face', 5)))
        qpro_secret.add_child(Node.s64_array('body', qpro_secrete_dict.get_int_array('body', 5)))
        qpro_secret.add_child(Node.s64_array('hand', qpro_secrete_dict.get_int_array('hand', 5)))
        root.add_child(qpro_secret)

        # DAN rankings
        grade = Node.void('grade')
        grade.set_attribute('sgid', str(self.s().db_to_game_rank(profile.get_int(self.DAN_RANKING_SINGLE, -1), self.s().GAME_CLTYPE_SINGLE)))
        grade.set_attribute('dgid', str(self.s().db_to_game_rank(profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.s().GAME_CLTYPE_DOUBLE)))
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        for rank in achievements:
            if rank.type == self.DAN_RANKING_SINGLE:
                grade.add_child(Node.u8_array('g', [
                    self.s().GAME_CLTYPE_SINGLE,
                    self.s().db_to_game_rank(rank.id, self.s().GAME_CLTYPE_SINGLE),
                    rank.data.get_int('stages_cleared'),
                    rank.data.get_int('percent'),
                ]))
            if rank.type == self.DAN_RANKING_DOUBLE:
                grade.add_child(Node.u8_array('g', [
                    self.s().GAME_CLTYPE_DOUBLE,
                    self.s().db_to_game_rank(rank.id, self.s().GAME_CLTYPE_DOUBLE),
                    rank.data.get_int('stages_cleared'),
                    rank.data.get_int('percent'),
                ]))
        root.add_child(grade)

        # User settings
        settings_dict = profile.get_dict('settings')
        skin = Node.s16_array(
            'skin',
            [
                settings_dict.get_int('frame'),
                settings_dict.get_int('turntable'),
                settings_dict.get_int('burst'),
                settings_dict.get_int('bgm'),
                settings_dict.get_int('flags'),
                settings_dict.get_int('towel'),
                settings_dict.get_int('judge_pos'),
                settings_dict.get_int('voice'),
                settings_dict.get_int('noteskin'),
                settings_dict.get_int('full_combo'),
                settings_dict.get_int('beam'),
                settings_dict.get_int('judge'),
                0,
                settings_dict.get_int('disable_song_preview'),
                settings_dict.get_int('pacemaker'),
                settings_dict.get_int('effector_lock'),
                settings_dict.get_int('effector_preset'),
            ],
        )
        root.add_child(skin)

        # Qpro data
        qpro_dict = profile.get_dict('qpro')
        root.add_child(Node.u32_array(
            'qprodata',
            [
                qpro_dict.get_int('head'),
                qpro_dict.get_int('hair'),
                qpro_dict.get_int('face'),
                qpro_dict.get_int('hand'),
                qpro_dict.get_int('body'),
            ],
        ))

        # Rivals
        rlist = Node.void('rlist')
        links = self.data.local.user.get_links(self.game, self.version, userid)
        for link in links:
            rival_type = None
            if link.type == 'sp_rival':
                rival_type = '1'
            elif link.type == 'dp_rival':
                rival_type = '2'
            else:
                # No business with this link type
                continue

            other_profile = self.get_profile(link.other_userid)
            if other_profile is None:
                continue
            other_play_stats = self.get_play_statistics(link.other_userid)

            rival = Node.void('rival')
            rival.set_attribute('spdp', rival_type)
            rival.set_attribute('id', str(other_profile.get_int('extid')))
            rival.set_attribute('id_str', ID.format_extid(other_profile.get_int('extid')))
            rival.set_attribute('djname', other_profile.get_str('name'))
            rival.set_attribute('pid', str(other_profile.get_int('pid')))
            rival.set_attribute('sg', str(self.s().db_to_game_rank(other_profile.get_int(self.DAN_RANKING_SINGLE, -1), self.s().GAME_CLTYPE_SINGLE)))
            rival.set_attribute('dg', str(self.s().db_to_game_rank(other_profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.s().GAME_CLTYPE_DOUBLE)))
            rival.set_attribute('sa', str(other_play_stats.get_int('single_dj_points')))
            rival.set_attribute('da', str(other_play_stats.get_int('double_dj_points')))
            rival.add_child(Node.bool('is_robo', False))

            qprodata = Node.void('qprodata')
            qpro = other_profile.get_dict('qpro')
            qprodata.set_attribute('head', str(qpro.get_int('head')))
            qprodata.set_attribute('hair', str(qpro.get_int('hair')))
            qprodata.set_attribute('face', str(qpro.get_int('face')))
            qprodata.set_attribute('hand', str(qpro.get_int('hand')))
            qprodata.set_attribute('body', str(qpro.get_int('body')))
            rival.add_child(qprodata)

            # challenge?

            # comment?

            # If the user joined a particular shop, let the game know.
            if 'shop_location' in other_profile:
                shop_id = other_profile.get_int('shop_location')
                machine = self.get_machine_by_id(shop_id)
                if machine is not None:
                    shop = Node.void('shop')
                    shop.set_attribute('name', machine.name)
                    rival.add_child(shop)

            rlist.add_child(rival)
        root.add_child(rlist)

        # rival_course?

        # original_course?

        # random_course?

        # follow_data?

        # Expert courses
        ir_data = Node.void('ir_data')
        for course in achievements:
            if course.type == self.COURSE_TYPE_INTERNET_RANKING:
                courseid, coursechart = self.id_and_chart_from_courseid(course.id)
                ir_data.add_child(Node.s32_array('e', [
                    courseid,  # course ID
                    coursechart,  # course chart
                    self.db_to_game_status(course.data.get_int('clear_status')),  # course clear status
                    course.data.get_int('pgnum'),  # flashing great count
                    course.data.get_int('gnum'),  # great count
                ]))
        root.add_child(ir_data)

        secret_course_data = Node.void('secret_course_data')
        for course in achievements:
            if course.type == self.COURSE_TYPE_SECRET:
                courseid, coursechart = self.id_and_chart_from_courseid(course.id)
                secret_course_data.add_child(Node.s32_array('e', [
                    courseid,  # course ID
                    coursechart,  # course chart
                    self.db_to_game_status(course.data.get_int('clear_status')),  # course clear status
                    course.data.get_int('pgnum'),  # flashing great count
                    course.data.get_int('gnum'),  # great count
                ]))
        root.add_child(secret_course_data)

        classic_course_data = Node.void('classic_course_data')
        for course in achievements:
            if course.type == self.COURSE_TYPE_CLASSIC:
                courseid, playstyle = self.id_and_chart_from_courseid(course.id)
                score_data = Node.void('score_data')
                classic_course_data.add_child(score_data)
                score_data.set_attribute('play_style', str(playstyle))
                score_data.set_attribute('course_id', str(courseid))
                score_data.set_attribute('score', str(course.data.get_int('pgnum') * 2 + course.data.get_int('gnum')))
                score_data.set_attribute('pgnum', str(course.data.get_int('pgnum')))
                score_data.set_attribute('gnum', str(course.data.get_int('gnum')))
                score_data.set_attribute('cflg', str(self.db_to_game_status(course.data.get_int('clear_status'))))
        root.add_child(classic_course_data)

        # convention_course?

        # dj_rank?
        # dj_rank_ranking?
        # season_dj_rank?

        # tonjyutsu?

        # shitei?

        # extra_boss_event?

        # weekly?
        # weekly_score?

        # If the user joined a particular shop, let the game know.
        if 'shop_location' in profile:
            shop_id = profile.get_int('shop_location')
            machine = self.get_machine_by_id(shop_id)
            if machine is not None:
                join_shop = Node.void('join_shop')
                join_shop.set_attribute('joinflg', '1')
                join_shop.set_attribute('join_cflg', '1')
                join_shop.set_attribute('join_id', ID.format_machine_id(machine.id))
                join_shop.set_attribute('join_name', machine.name)
                root.add_child(join_shop)

        # visitor?

        # step? <- differes from sinobuze

        # Daily recommendations
        entry = self.data.local.game.get_time_sensitive_settings(self.game, self.version, 'dailies')
        if entry is not None:
            packinfo = Node.void('packinfo')
            pack_id = int(entry['start_time'] / 86400)
            packinfo.set_attribute('pack_id', str(pack_id))
            packinfo.set_attribute('music_0', str(entry['music'][0]))
            packinfo.set_attribute('music_1', str(entry['music'][1]))
            packinfo.set_attribute('music_2', str(entry['music'][2]))
            root.add_child(packinfo)
        else:
            # No dailies :(
            pack_id = None

        # Tran medals and shit
        achievement_node = Node.void('achievements')
        # Dailies
        if pack_id is None:
            achievement_node.set_attribute('pack', '0')
            achievement_node.set_attribute('pack_comp', '0')
        else:
            daily_played = self.data.local.user.get_achievement(self.game, self.version, userid, pack_id, 'daily')
            if daily_played is None:
                daily_played = ValidatedDict()
            achievement_node.set_attribute('pack', str(daily_played.get_int('pack_flg')))
            achievement_node.set_attribute('pack_comp', str(daily_played.get_int('pack_comp')))
        # Weeklies
        achievement_node.set_attribute('last_weekly', str(profile.get_int('last_weekly')))
        achievement_node.set_attribute('weekly_num', str(profile.get_int('weekly_num')))
        # Prefecture visit flag
        achievement_node.set_attribute('visit_flg', str(profile.get_int('visit_flg')))
        # Number of rivals beaten
        achievement_node.set_attribute('rival_crush', str(profile.get_int('rival_crush')))
        # Tran medals
        achievement_node.add_child(Node.s64_array('trophy', profile.get_int_array('trophy', 10)))
        root.add_child(achievement_node)

        # Track deller
        deller = Node.void('deller')
        deller.set_attribute('deller', str(profile.get_int('deller')))
        deller.set_attribute('rate', '0')
        root.add_child(deller)

        # Orb data
        orb_data = Node.void('orb_data')
        orb_data.set_attribute('rest_orb', str(profile.get_int('orbs')))
        orb_data.set_attribute('present_orb', '0') # present_orb?
        root.add_child(orb_data)

        # Expert points
        expert_point = Node.void('expert_point')
        for rank in achievements:
            if rank.type == 'expert_point':
                detail = Node.void('detail')
                expert_point.add_child(detail)
                detail.set_attribute('course_id', str(rank.id))
                detail.set_attribute('n_point', str(rank.data.get_int('normal_points')))
                detail.set_attribute('h_point', str(rank.data.get_int('hyper_points')))
                detail.set_attribute('a_point', str(rank.data.get_int('another_points')))
        root.add_child(expert_point)

        # pay_per_use_item?
        # present_pay_per_use_item?
        
        # qpro_ticket?

        # old_linkage_secret_flg?

        # leggendaria_semi_open?
        # konami_style?
    
        # arena_data?
        # arena_penalty?

        # tsujigiri?

        # weekly_result?

        # skin_customize_flg?

        # event1? <- differes from sinobuz, of course
        # event1_assist?
        # event2?
        # floor_infection3?
        # anniv20_event?

        # bemani_vote?
        # player_compe?

        return root


    # todo: need further tests
    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        # modified from sinobuz.py
        newprofile = copy.deepcopy(oldprofile)
        play_stats = self.get_play_statistics(userid)

        # Track play counts
        cltype = int(request.attribute('cltype'))
        if cltype == self.s().GAME_CLTYPE_SINGLE:
            play_stats.increment_int('single_plays')
        if cltype == self.s().GAME_CLTYPE_DOUBLE:
            play_stats.increment_int('double_plays')

        # Track DJ points
        play_stats.replace_int('single_dj_points', int(request.attribute('s_achi')))
        play_stats.replace_int('double_dj_points', int(request.attribute('d_achi')))

        # Profile settings
        newprofile.replace_int('mode', int(request.attribute('mode')))
        newprofile.replace_int('pmode', int(request.attribute('pmode')))
        newprofile.replace_int('rtype', int(request.attribute('rtype')))
        newprofile.replace_int('s_lift', int(request.attribute('s_lift')))
        newprofile.replace_int('d_lift', int(request.attribute('d_lift')))
        newprofile.replace_int('sp_opt', int(request.attribute('sp_opt')))
        newprofile.replace_int('dp_opt', int(request.attribute('dp_opt')))
        newprofile.replace_int('dp_opt2', int(request.attribute('dp_opt2')))
        newprofile.replace_int('gpos', int(request.attribute('gpos')))
        newprofile.replace_int('s_sorttype', int(request.attribute('s_sorttype')))
        newprofile.replace_int('d_sorttype', int(request.attribute('d_sorttype')))
        newprofile.replace_int('s_pace', int(request.attribute('s_pace')))
        newprofile.replace_int('d_pace', int(request.attribute('d_pace')))
        newprofile.replace_int('s_gno', int(request.attribute('s_gno')))
        newprofile.replace_int('d_gno', int(request.attribute('d_gno')))
        newprofile.replace_int('s_gtype', int(request.attribute('s_gtype')))
        newprofile.replace_int('d_gtype', int(request.attribute('d_gtype')))
        newprofile.replace_int('s_sdlen', int(request.attribute('s_sdlen')))
        newprofile.replace_int('d_sdlen', int(request.attribute('d_sdlen')))
        newprofile.replace_int('s_sdtype', int(request.attribute('s_sdtype')))
        newprofile.replace_int('d_sdtype', int(request.attribute('d_sdtype')))
        newprofile.replace_int('s_timing', int(request.attribute('s_timing')))
        newprofile.replace_int('d_timing', int(request.attribute('d_timing')))
        newprofile.replace_float('s_notes', float(request.attribute('s_notes')))
        newprofile.replace_float('d_notes', float(request.attribute('d_notes')))
        newprofile.replace_int('s_judge', int(request.attribute('s_judge')))
        newprofile.replace_int('d_judge', int(request.attribute('d_judge')))
        newprofile.replace_float('s_hispeed', float(request.attribute('s_hispeed')))
        newprofile.replace_float('d_hispeed', float(request.attribute('d_hispeed')))
        newprofile.replace_int('s_disp_judge', int(request.attribute('s_disp_judge')))
        newprofile.replace_int('d_disp_judge', int(request.attribute('d_disp_judge')))
        newprofile.replace_int('s_opstyle', int(request.attribute('s_opstyle')))
        newprofile.replace_int('d_opstyle', int(request.attribute('d_opstyle')))
        newprofile.replace_int('s_graph_score', int(request.attribute('s_graph_score')))
        newprofile.replace_int('d_graph_score', int(request.attribute('d_graph_score')))
        newprofile.replace_int('s_auto_scrach', int(request.attribute('s_auto_scrach')))
        newprofile.replace_int('d_auto_scrach', int(request.attribute('d_auto_scrach')))
        newprofile.replace_int('s_gauge_disp', int(request.attribute('s_gauge_disp')))
        newprofile.replace_int('d_gauge_disp', int(request.attribute('d_gauge_disp')))
        newprofile.replace_int('s_lane_brignt', int(request.attribute('s_lane_brignt')))
        newprofile.replace_int('d_lane_brignt', int(request.attribute('d_lane_brignt')))
        newprofile.replace_int('s_camera_layout', int(request.attribute('s_camera_layout')))
        newprofile.replace_int('d_camera_layout', int(request.attribute('d_camera_layout')))
        newprofile.replace_int('s_ghost_score', int(request.attribute('s_ghost_score')))
        newprofile.replace_int('d_ghost_score', int(request.attribute('d_ghost_score')))
        newprofile.replace_int('s_tsujigiri_disp', int(request.attribute('s_tsujigiri_disp')))
        newprofile.replace_int('d_tsujigiri_disp', int(request.attribute('d_tsujigiri_disp')))

        # Update judge window adjustments per-machine
        judge_dict = newprofile.get_dict('machine_judge_adjust')
        machine_judge = judge_dict.get_dict(self.config['machine']['pcbid'])
        machine_judge.replace_int('single', int(request.attribute('s_judgeAdj')))
        machine_judge.replace_int('double', int(request.attribute('d_judgeAdj')))
        judge_dict.replace_dict(self.config['machine']['pcbid'], machine_judge)
        newprofile.replace_dict('machine_judge_adjust', judge_dict)

        # Secret flags saving
        secret = request.child('secret')
        if secret is not None:
            secret_dict = newprofile.get_dict('secret')
            secret_dict.replace_int_array('flg1', 3, secret.child_value('flg1'))
            secret_dict.replace_int_array('flg2', 3, secret.child_value('flg2'))
            secret_dict.replace_int_array('flg3', 3, secret.child_value('flg3'))
            newprofile.replace_dict('secret', secret_dict)

        # Basic achievements
        achievements = request.child('achievements')
        if achievements is not None:
            newprofile.replace_int('visit_flg', int(achievements.attribute('visit_flg')))
            newprofile.replace_int('last_weekly', int(achievements.attribute('last_weekly')))
            newprofile.replace_int('weekly_num', int(achievements.attribute('weekly_num')))

            pack_id = int(achievements.attribute('pack_id'))
            if pack_id > 0:
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    pack_id,
                    'daily',
                    {
                        'pack_flg': int(achievements.attribute('pack_flg')),
                        'pack_comp': int(achievements.attribute('pack_comp')),
                    },
                )

            trophies = achievements.child('trophy')
            if trophies is not None:
                # We only load the first 10 in profile load.
                newprofile.replace_int_array('trophy', 10, trophies.value[:10])

        # Deller saving
        deller = request.child('deller')
        if deller is not None:
            newprofile.replace_int('deller', newprofile.get_int('deller') + int(deller.attribute('deller')))

        # Secret course expert point saving
        expert_point = request.child('expert_point')
        if expert_point is not None:
            courseid = int(expert_point.attribute('course_id'))

            # Update achievement to track expert points
            expert_point_achievement = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                courseid,
                'expert_point',
            )
            if expert_point_achievement is None:
                expert_point_achievement = ValidatedDict()
            expert_point_achievement.replace_int(
                'normal_points',
                int(expert_point.attribute('n_point')),
            )
            expert_point_achievement.replace_int(
                'hyper_points',
                int(expert_point.attribute('h_point')),
            )
            expert_point_achievement.replace_int(
                'another_points',
                int(expert_point.attribute('a_point')),
            )

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                courseid,
                'expert_point',
                expert_point_achievement,
            )

        # Favorites saving
        for favorite in request.children:
            singles = []
            doubles = []
            name = None
            if favorite.name in ['favorite', 'extra_favorite']:
                if favorite.name == 'favorite':
                    name = 'favorite1'
                elif favorite.name == 'extra_favorite':
                    folder = favorite.attribute('folder_id')
                    if folder == '0':
                        name = 'favorite2'
                    if folder == '1':
                        name = 'favorite3'
                if name is None:
                    continue

                single_music_bin = favorite.child_value('sp_mlist')
                single_chart_bin = favorite.child_value('sp_clist')
                double_music_bin = favorite.child_value('dp_mlist')
                double_chart_bin = favorite.child_value('dp_clist')

                for i in range(self.FAVORITE_LIST_LENGTH):
                    singles.append({
                        'id': struct.unpack('<L', single_music_bin[(i * 4):((i + 1) * 4)])[0],
                        'chart': struct.unpack('B', single_chart_bin[i:(i + 1)])[0],
                    })
                    doubles.append({
                        'id': struct.unpack('<L', double_music_bin[(i * 4):((i + 1) * 4)])[0],
                        'chart': struct.unpack('B', double_chart_bin[i:(i + 1)])[0],
                    })

            # Filter out empty charts
            singles = [single for single in singles if single['id'] != 0]
            doubles = [double for double in doubles if double['id'] != 0]

            newprofile.replace_dict(
                name,
                {
                    'single': singles,
                    'double': doubles,
                },
            )

        # QPro equip in step-up mode
        qpro_equip = request.child('qpro_equip')
        if qpro_equip is not None:
            qpro_dict = newprofile.get_dict('qpro')
            qpro_dict.replace_int('head', int(qpro_equip.attribute('head')))
            qpro_dict.replace_int('hair', int(qpro_equip.attribute('hair')))
            qpro_dict.replace_int('face', int(qpro_equip.attribute('face')))
            qpro_dict.replace_int('hand', int(qpro_equip.attribute('hand')))
            qpro_dict.replace_int('body', int(qpro_equip.attribute('body')))
            newprofile.replace_dict('qpro', qpro_dict)

        # Qpro secret unlocks in step-up mode
        qpro_secret = request.child('qpro_secret')
        if qpro_secret is not None:
            qpro_secret_dict = newprofile.get_dict('qpro_secret')
            qpro_secret_dict.replace_int_array('head', 5, qpro_secret.child_value('head'))
            qpro_secret_dict.replace_int_array('hair', 5, qpro_secret.child_value('hair'))
            qpro_secret_dict.replace_int_array('face', 5, qpro_secret.child_value('face'))
            qpro_secret_dict.replace_int_array('body', 5, qpro_secret.child_value('body'))
            qpro_secret_dict.replace_int_array('hand', 5, qpro_secret.child_value('hand'))
            newprofile.replace_dict('qpro_secret', qpro_secret_dict)

        # Orb data saving
        orb_data = request.child('orb_data')
        if orb_data is not None:
            orbs = newprofile.get_int('orbs')
            orbs = orbs + int(orb_data.attribute('add_orb'))
            if orb_data.child_value('use_vip_pass'):
                orbs = 0
            newprofile.replace_int('orbs', orbs)
            # present_orb?

        # Keep track of play statistics across all mixes
        self.update_play_statistics(userid, play_stats)

        # dj_rank?
        # pay_money_data?
        # music_history?
        # play_log?

        return newprofile


    # 0x1803DF520
    def handle_IIDX26pc_request(self, request: Node) -> Node:
        method = request.attribute('method')
        root = Node.void('IIDX26pc')

        # 0x18067BC70
        if method == 'get':
            # from sinobuz.py
            refid = request.attribute('rid')
            profile = self.get_profile_by_refid(refid)

            if profile is not None:
                root = profile
        
        # 0x18067BCA0
        if method == 'reg':
            # from sinobuz.py
            refid = request.attribute('rid')
            name = request.attribute('name')
            pid = int(request.attribute('pid'))
            profile = self.new_profile_by_refid(refid, name, pid)

            if profile is not None:
                root.set_attribute('id', str(profile.get_int('extid')))
                root.set_attribute('id_str', ID.format_extid(profile.get_int('extid')))
        
        # 0x18067BD90
        if method == 'common':
            # expire
            root.set_attribute('expire', '600')

            # fixme: monthly_mranking, total_mranking
            # todo: internet ranking (i cannot find any infomation about this)
            # todo: cm, what is it

            # KONAMI Arcade Championship 8th
            root.add_child(Node.string('kac_mid', '26033'))
            root.add_child(Node.string('kac_clid', str(self.CHART_TYPE_A7))) # not sure :/

            # others are from sinobuz.py, ignored omnimix
            ir = Node.void('ir')
            ir.set_attribute('beat', '2')
            root.add_child(ir)

            expert = Node.void('expert')
            expert.set_attribute('phase', '1')
            root.add_child(expert)

            expert_random_select = Node.void('expert_random_select')
            expert_random_select.set_attribute('phase', '1')
            root.add_child(expert_random_select)

            event_phase = self.get_game_config().get_int('event_phase') if self.machine_joined_arcade() else 0
            if event_phase == 0:
                boss_phase = 0
                event1 = 0
                event2 = 0
            elif event_phase in [1, 2, 3]:
                boss_phase = 1
                event1 = event_phase - 1
                event2 = 0
            elif event_phase == 4:
                boss_phase = 2
                event1 = 0
                event2 = 2
            
            boss = Node.void('boss')
            boss.set_attribute('phase', str(boss_phase))
            root.add_child(boss)

            extra_boss_event = Node.void('extra_boss_event')
            extra_boss_event.set_attribute('phase', '1')
            root.add_child(extra_boss_event)

            root.add_child(Node.void('vip_pass_black'))

            deller_bonus = Node.void('deller_bonus')
            deller_bonus.set_attribute('open', '1')
            root.add_child(deller_bonus)

            newsong_another = Node.void('newsong_another')
            newsong_another.set_attribute('open', '1')
            root.add_child(newsong_another)

            # pcb_check?

            expert_full = Node.void('expert_secret_full_open')
            root.add_child(expert_full)

            # eaorder_phase?

            common_evnet = Node.void('common_evnet')
            common_evnet.set_attribute('flg', '0')
            root.add_child(common_evnet)

            event1_phase = Node.void('event1_phase')
            event1_phase.set_attribute('phase', str(event1))
            root.add_child(event1_phase)

            event2_phase = Node.void('event2_phase')
            event2_phase.set_attribute('phase', str(event2))
            root.add_child(event2_phase)

            # system_voice_phase?

            # anniv20_phase?

        # 0x18067BE80
        if method == 'visit':
            # from sinobuz.py
            root.set_attribute('anum', '0')
            root.set_attribute('snum', '0')
            root.set_attribute('pnum', '0')
            root.set_attribute('aflg', '0')
            root.set_attribute('sflg', '0')
            root.set_attribute('pflg', '0')

        # 0x18067BD00
        if method == 'save':
            # from sinobuz.py
            extid = int(request.attribute('iidxid'))
            self.put_profile_by_extid(extid, request)

        return root


    # 0x1803E7590
    def handle_IIDX26music_request(self, request: Node) -> Node:
        method = request.attribute('method')
        root = Node.void('IIDX26music')

        # 0x18067C4B0
        if method == 'getrank':
            # from sinobuz.py
            cltype = int(request.attribute('cltype'))

            style = Node.void('style')
            style.set_attribute('type', str(cltype))
            root.add_child(style)

            for rivalid in [-1, 0, 1, 2, 3, 4]:
                if rivalid == -1:
                    attr = 'iidxid'
                else:
                    attr = f'iidxid{rivalid}'

                try:
                    extid = int(request.attribute(attr))
                except Exception:
                    # Invalid extid
                    continue
                userid = self.data.remote.user.from_extid(self.game, self.version, extid)
                if userid is not None:
                    scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)

                    # Grab score data for user/rival
                    scoredata = self.make_score_struct(
                        scores,
                        self.CLEAR_TYPE_SINGLE if cltype == self.s().GAME_CLTYPE_SINGLE else self.s().CLEAR_TYPE_DOUBLE,
                        rivalid,
                    )
                    for s in scoredata:
                        root.add_child(Node.s16_array('m', s))

                    # Grab most played for user/rival
                    most_played = [
                        play[0] for play in
                        self.data.local.music.get_most_played(self.game, self.music_version, userid, 20)
                    ]
                    # top?
                    if len(most_played) < 20:
                        most_played.extend([0] * (20 - len(most_played)))
                    best = Node.u16_array('best', most_played)
                    best.set_attribute('rno', str(rivalid))
                    root.add_child(best)

                    if rivalid == -1:
                        # Grab beginner statuses for user only
                        beginnerdata = self.make_beginner_struct(scores)
                        for b in beginnerdata:
                            root.add_child(Node.u16_array('b', b))

        # 0x18067C5A0
        if method == 'crate':
            # from sinobuz.py
            attempts = self.get_clear_rates()

            all_songs = list(set([song.id for song in self.data.local.music.get_all_songs(self.game, self.music_version)]))
            for song in all_songs:
                clears = []
                fcs = []

                for chart in [0, 1, 2, 3, 4, 5]:
                    placed = False
                    if song in attempts and chart in attempts[song]:
                        values = attempts[song][chart]
                        if values['total'] > 0:
                            clears.append(int((1000 * values['clears']) / values['total']))
                            fcs.append(int((1000 * values['fcs']) / values['total']))
                            placed = True
                    if not placed:
                        clears.append(1001)
                        fcs.append(1001)

                clearnode = Node.s32_array('c', clears + fcs)
                clearnode.set_attribute('mid', str(song))
                root.add_child(clearnode)

        # 0x18067C570
        if method == 'breg':
            # from sinobuz; only store log
            extid = int(request.attribute('iidxid'))
            musicid = int(request.attribute('mid'))
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

            if userid is not None:
                clear_status = self.game_to_db_status(int(request.attribute('cflg')))
                pgreats = int(request.attribute('pgnum'))
                greats = int(request.attribute('gnum'))

            self.update_score(
                userid,
                musicid,
                self.CHART_TYPE_B7,
                clear_status,
                pgreats,
                greats,
                -1,
                b'',
                None,
            )

        # 0x18067C540
        if method == 'reg':
            # from sinobuz.py
            extid = int(request.attribute('iidxid'))
            musicid = int(request.attribute('mid'))
            chart = int(request.attribute('clid'))
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

            # See if we need to report global or shop scores
            if self.machine_joined_arcade():
                game_config = self.get_game_config()
                global_scores = game_config.get_bool('global_shop_ranking')
                machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            else:
                # If we aren't in an arcade, we can only show global scores
                global_scores = True
                machine = None

            # First, determine our current ranking before saving the new score
            all_scores = sorted(
                self.data.remote.music.get_all_scores(game=self.game, version=self.music_version, songid=musicid, songchart=chart),
                key=lambda s: (s[1].points, s[1].timestamp),
                reverse=True,
            )
            all_players = {
                uid: prof for (uid, prof) in
                self.get_any_profiles([s[0] for s in all_scores])
            }

            if not global_scores:
                all_scores = [
                    score for score in all_scores
                    if (
                        score[0] == userid or
                        self.user_joined_arcade(machine, all_players[score[0]])
                    )
                ]

            # Find our actual index
            oldindex = None
            for i in range(len(all_scores)):
                if all_scores[i][0] == userid:
                    oldindex = i
                    break

            if userid is not None:
                clear_status = self.game_to_db_status(int(request.attribute('cflg')))
                pgreats = int(request.attribute('pgnum'))
                greats = int(request.attribute('gnum'))
                miss_count = int(request.attribute('mnum'))
                ghost = request.child_value('ghost')
                shopid = ID.parse_machine_id(request.attribute('location_id'))

                # todo: other info, e.g. is_deatch
                self.update_score(
                    userid,
                    musicid,
                    chart,
                    clear_status,
                    pgreats,
                    greats,
                    miss_count,
                    ghost,
                    shopid,
                )

            # Calculate and return statistics about this song
            root.set_attribute('mid', request.attribute('mid'))
            root.set_attribute('clid', request.attribute('clid'))

            attempts = self.get_clear_rates(musicid, chart)
            count = attempts[musicid][chart]['total']
            clear = attempts[musicid][chart]['clears']
            full_combo = attempts[musicid][chart]['fcs']

            if count > 0:
                root.set_attribute('crate', str(int((1000 * clear) / count)))
                root.set_attribute('frate', str(int((1000 * full_combo) / count)))
            else:
                root.set_attribute('crate', '0')
                root.set_attribute('frate', '0')
            root.set_attribute('rankside', '0')

            # weekly_score?

            if userid is not None:
                # Grab the rank of some other players on this song
                ranklist = Node.void('ranklist')
                root.add_child(ranklist)

                # Shop ranking
                shopdata = Node.void('shopdata')
                shopdata.set_attribute('rank', '-1' if oldindex is None else str(oldindex + 1))
                root.add_child(shopdata)

                all_scores = sorted(
                    self.data.remote.music.get_all_scores(game=self.game, version=self.music_version, songid=musicid, songchart=chart),
                    key=lambda s: (s[1].points, s[1].timestamp),
                    reverse=True,
                )
                missing_players = [
                    uid for (uid, _) in all_scores
                    if uid not in all_players
                ]
                for (uid, prof) in self.get_any_profiles(missing_players):
                    all_players[uid] = prof

                if not global_scores:
                    all_scores = [
                        score for score in all_scores
                        if (
                            score[0] == userid or
                            self.user_joined_arcade(machine, all_players[score[0]])
                        )
                    ]

                # Find our actual index
                ourindex = None
                for i in range(len(all_scores)):
                    if all_scores[i][0] == userid:
                        ourindex = i
                        break
                if ourindex is None:
                    raise Exception('Cannot find our own score after saving to DB!')
                start = ourindex - 4
                end = ourindex + 4
                if start < 0:
                    start = 0
                if end >= len(all_scores):
                    end = len(all_scores) - 1
                relevant_scores = all_scores[start:(end + 1)]

                record_num = start + 1
                for score in relevant_scores:
                    profile = all_players[score[0]]

                    data = Node.void('data')
                    data.set_attribute('iidx_id', str(profile.get_int('extid')))
                    data.set_attribute('name', profile.get_str('name'))

                    machine_name = ''
                    if 'shop_location' in profile:
                        shop_id = profile.get_int('shop_location')
                        machine = self.get_machine_by_id(shop_id)
                        if machine is not None:
                            machine_name = machine.name
                    data.set_attribute('opname', machine_name)
                    data.set_attribute('rnum', str(record_num))
                    data.set_attribute('score', str(score[1].points))
                    data.set_attribute('clflg', str(self.db_to_game_status(score[1].data.get_int('clear_status'))))
                    data.set_attribute('pid', str(profile.get_int('pid')))

                    data.set_attribute('sgrade', str(
                        self.db_to_game_rank(profile.get_int(self.DAN_RANKING_SINGLE, -1), self.s().GAME_CLTYPE_SINGLE),
                    ))
                    data.set_attribute('dgrade', str(
                        self.db_to_game_rank(profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.s().GAME_CLTYPE_DOUBLE),
                    ))
                    # achieve?

                    qpro = profile.get_dict('qpro')
                    data.set_attribute('head', str(qpro.get_int('head')))
                    data.set_attribute('hair', str(qpro.get_int('hair')))
                    data.set_attribute('face', str(qpro.get_int('face')))
                    data.set_attribute('body', str(qpro.get_int('body')))
                    data.set_attribute('hand', str(qpro.get_int('hand')))
                    data.set_attribute('myFlg', '1' if score[0] == userid else '0')

                    ranklist.add_child(data)
                    record_num = record_num + 1
            
            # player_compe?

        return root


    # 0x1803EA8D0
    def handle_IIDX26shop_request(self, request: Node) -> Node:
        method = request.attribute('method')
        root = Node.void('IIDX26shop')

        # 0x18067D020
        if method == 'sentinfo':
            pass # ignore

        # 0x18067D0B0
        if method == 'getname':
            # from sinobuz.py
            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine is not None:
                machine_name = machine.name
                close = machine.data.get_bool('close')
                hour = machine.data.get_int('hour')
                minute = machine.data.get_int('minute')
            else:
                machine_name = ''
                close = False
                hour = 0
                minute = 0

            root.set_attribute('opname', machine_name)
            root.set_attribute('pid', '51')
            root.set_attribute('cls_opt', '1' if close else '0')
            root.set_attribute('hr', str(hour))
            root.set_attribute('mi', str(minute))

        # 0x18067D110
        if method == 'getconvention':
            # from sinobuz.py
            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine.arcade is not None:
                course = self.data.local.machine.get_settings(machine.arcade, self.game, self.music_version, 'shop_course')
            else:
                course = None

            if course is None:
                course = ValidatedDict()

            # rootage music?
            root.set_attribute('music_0', str(course.get_int('music_0', 20032)))
            root.set_attribute('music_1', str(course.get_int('music_1', 20009)))
            root.set_attribute('music_2', str(course.get_int('music_2', 20015)))
            root.set_attribute('music_3', str(course.get_int('music_3', 20064)))
            # start_time?
            # end_time? <- fixme: important, otherwise iidx will reject the response

            root.add_child(Node.bool('valid', course.get_bool('valid')))

        # 0x18067D170
        if method == 'sendescapepackageinfo':
            # from sinobuz.py
            root.set_attribute('expire', str((Time.now() + 86400 * 365) * 1000))

        return root


    # 0x1803EA120
    def handle_IIDX26ranking_request(self, request: Node) -> Node:
        method = request.attribute('method')
        root = Node.void('IIDX26ranking')

        # 0x18067C9B0
        if method == 'getranker':
            # from sinobuz.py
            chart = int(request.attribute('clid'))
            if chart not in [
                self.CHART_TYPE_N7,
                self.CHART_TYPE_H7,
                self.CHART_TYPE_A7,
                self.CHART_TYPE_N14,
                self.CHART_TYPE_H14,
                self.CHART_TYPE_A14,
            ]:
                # Chart type 6 is presumably beginner mode, but it crashes the game
                return root

            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine.arcade is not None:
                course = self.data.local.machine.get_settings(machine.arcade, self.game, self.music_version, 'shop_course')
            else:
                course = None

            if course is None:
                course = ValidatedDict()

            if not course.get_bool('valid'):
                # Shop course not enabled or not present
                return root

            convention = Node.void('convention')
            convention.set_attribute('clid', str(chart))
            convention.set_attribute('update_date', str(Time.now() * 1000))
            root.add_child(convention)

            # Grab all scores for each of the four songs, filter out people who haven't
            # set us as their arcade and then return the top 20 scores (adding all 4 songs).
            songids = [
                course.get_int('music_0'),
                course.get_int('music_1'),
                course.get_int('music_2'),
                course.get_int('music_3'),
            ]

            totalscores: Dict[UserID, int] = {}
            profiles: Dict[UserID, ValidatedDict] = {}
            for songid in songids:
                scores = self.data.local.music.get_all_scores(
                    self.game,
                    self.music_version,
                    songid=songid,
                    songchart=chart,
                )

                for score in scores:
                    if score[0] not in totalscores:
                        totalscores[score[0]] = 0
                        profile = self.get_any_profile(score[0])
                        if profile is None:
                            profile = ValidatedDict()
                        profiles[score[0]] = profile

                    totalscores[score[0]] += score[1].points

            topscores = sorted(
                [
                    (totalscores[userid], profiles[userid])
                    for userid in totalscores
                    if self.user_joined_arcade(machine, profiles[userid])
                ],
                key=lambda tup: tup[0],
                reverse=True,
            )[:20]

            rank = 0
            for topscore in topscores:
                rank = rank + 1

                detail = Node.void('detail')
                detail.set_attribute('name', topscore[1].get_str('name'))
                detail.set_attribute('rank', str(rank))
                detail.set_attribute('score', str(topscore[0]))
                detail.set_attribute('pid', str(topscore[1].get_int('pid')))
                qpro = topscore[1].get_dict('qpro')
                detail.set_attribute('head', str(qpro.get_int('head')))
                detail.set_attribute('hair', str(qpro.get_int('hair')))
                detail.set_attribute('face', str(qpro.get_int('face')))
                detail.set_attribute('body', str(qpro.get_int('body')))
                detail.set_attribute('hand', str(qpro.get_int('hand')))

                convention.add_child(detail)

        return root


    # 0x1803EBD30
    def handle_IIDX26gameSystem_request(self, request: Node) -> Node:
        method = request.attribute('method')
        root = Node.void('IIDX26gameSystem')

        # 0x18067DFB0
        if method == 'systemInfo':
            # arena_schedule?
            # arena_reword? -> means reward i guess?
            # arena_music_difficult?
            # arena_cpu_define?
            # maching_class_range?
            # arena_force_music?
            # event1_audience_answer?
            # event1_hide_quiz_control?
            pass
    
        return root
