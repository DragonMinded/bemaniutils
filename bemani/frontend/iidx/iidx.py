# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, Optional, Tuple, List

from flask_caching import Cache  # type: ignore

from bemani.backend.iidx import IIDXFactory, IIDXBase
from bemani.common import ValidatedDict, GameConstants
from bemani.data import Attempt, Data, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class IIDXFrontend(FrontendBase):

    game = GameConstants.IIDX

    valid_charts = [
        IIDXBase.CHART_TYPE_N7,
        IIDXBase.CHART_TYPE_H7,
        IIDXBase.CHART_TYPE_A7,
        IIDXBase.CHART_TYPE_N14,
        IIDXBase.CHART_TYPE_H14,
        IIDXBase.CHART_TYPE_A14,
    ]

    valid_rival_types = [
        'sp_rival',
        'dp_rival',
    ]

    def __init__(self, data: Data, config: Dict[str, Any], cache: Cache) -> None:
        super().__init__(data, config, cache)
        self.machines: Dict[int, str] = {}

    def all_games(self) -> Iterator[Tuple[str, int, str]]:
        yield from IIDXFactory.all_games()

    def get_duplicate_id(self, musicid: int, chart: int) -> Optional[Tuple[int, int]]:
        modern_to_legacy_map = {
            23066: 4213,
            22068: 9203,
            22052: 10203,
            22039: 12201,
            21201: 12204,
            21064: 12206,
            23077: 13215,
            22025: 14202,
            21068: 14210,
            22069: 14211,
            23070: 14214,
            23069: 15202,
            21063: 15204,
            21065: 15205,
            22028: 15207,
            22049: 15208,
            22043: 15209,
            23060: 15211,
            21062: 15215,
            21067: 16207,
            23062: 16209,
            21066: 16212,
            23030: 22096,
            23051: 22097,
            11101: 21214,
            14101: 21221,
            15104: 21225,
            15102: 21226,
            15101: 21231,
            15103: 21237,
            16105: 21240,
            16104: 21242,
            16103: 21253,
            16102: 21258,
            16101: 21262,
            14100: 21220,
        }
        # Some charts were changed, and others kept the same on these
        if chart in [0, 1, 2]:
            modern_to_legacy_map[23065] = 9206
        oldid = modern_to_legacy_map.get(musicid)
        oldchart = chart
        if oldid == 12204:
            if oldchart == 1:
                oldchart = 2
            elif oldchart == 2:
                oldchart = 1
        if oldid is not None:
            return (oldid, oldchart)
        else:
            return None

    def format_dan_rank(self, rank: int) -> str:
        if rank == -1:
            return '--'

        return {
            IIDXBase.DAN_RANK_7_KYU: '七級',
            IIDXBase.DAN_RANK_6_KYU: '六級',
            IIDXBase.DAN_RANK_5_KYU: '五級',
            IIDXBase.DAN_RANK_4_KYU: '四級',
            IIDXBase.DAN_RANK_3_KYU: '三級',
            IIDXBase.DAN_RANK_2_KYU: '二級',
            IIDXBase.DAN_RANK_1_KYU: '一級',
            IIDXBase.DAN_RANK_1_DAN: '初段',
            IIDXBase.DAN_RANK_2_DAN: '二段',
            IIDXBase.DAN_RANK_3_DAN: '三段',
            IIDXBase.DAN_RANK_4_DAN: '四段',
            IIDXBase.DAN_RANK_5_DAN: '五段',
            IIDXBase.DAN_RANK_6_DAN: '六段',
            IIDXBase.DAN_RANK_7_DAN: '七段',
            IIDXBase.DAN_RANK_8_DAN: '八段',
            IIDXBase.DAN_RANK_9_DAN: '九段',
            IIDXBase.DAN_RANK_10_DAN: '十段',
            IIDXBase.DAN_RANK_CHUDEN: '中伝',
            IIDXBase.DAN_RANK_KAIDEN: '皆伝',
        }[rank]

    def format_flags(self, settings_dict: ValidatedDict) -> Dict[str, Any]:
        flags = settings_dict.get_int('flags')
        return {
            'grade': (flags & 0x001) != 0,
            'status': (flags & 0x002) != 0,
            'difficulty': (flags & 0x004) != 0,
            'alphabet': (flags & 0x008) != 0,
            'rival_played': (flags & 0x010) != 0,
            'rival_win_lose': (flags & 0x040) != 0,
            'rival_info': (flags & 0x080) != 0,
            'hide_play_count': (flags & 0x100) != 0,
            'disable_graph_cutin': (flags & 0x200) != 0,
            'classic_hispeed': (flags & 0x400) != 0,
            'hide_iidx_id': (flags & 0x1000) != 0,
            'disable_song_preview': settings_dict.get_int('disable_song_preview') != 0,
            'effector_lock': settings_dict.get_int('effector_lock') != 0,
            'disable_hcn_color': settings_dict.get_int('disable_hcn_color') != 0,
        }

    def format_settings(self, settings_dict: ValidatedDict) -> Dict[str, Any]:
        return {
            'frame': settings_dict.get_int('frame'),
            'turntable': settings_dict.get_int('turntable'),
            'burst': settings_dict.get_int('burst'),
            'bgm': settings_dict.get_int('bgm'),
            'towel': settings_dict.get_int('towel'),
            'judge_pos': settings_dict.get_int('judge_pos'),
            'voice': settings_dict.get_int('voice'),
            'noteskin': settings_dict.get_int('noteskin'),
            'full_combo': settings_dict.get_int('full_combo'),
            'beam': settings_dict.get_int('beam'),
            'judge': settings_dict.get_int('judge'),
            'pacemaker': settings_dict.get_int('pacemaker'),
            'effector_preset': settings_dict.get_int('effector_preset'),
            'explosion_size': settings_dict.get_int('explosion_size'),
            'note_preview': settings_dict.get_int('note_preview'),
        }

    def format_qpro(self, qpro_dict: ValidatedDict) -> Dict[str, Any]:
        return {
            'body': qpro_dict.get_int('body'),
            'face': qpro_dict.get_int('face'),
            'hair': qpro_dict.get_int('hair'),
            'hand': qpro_dict.get_int('hand'),
            'head': qpro_dict.get_int('head'),
        }

    def get_all_items(self, versions: list) -> Dict[str, List[Dict[str, Any]]]:
        result = {}
        for version in versions:
            qpro = self.__format_iidx_extras(version)
            result[version] = qpro['qpros']
        return result

    def __format_iidx_extras(self, version: int) -> Dict[str, List[Dict[str, Any]]]:
        # Gotta look up the unlock catalog
        items = self.data.local.game.get_items(self.game, version)

        return {
            "qpros": [
                {
                    "identifier": item.data.get_str("identifier"),
                    "id": str(item.id),
                    "name": item.data.get_str("name"),
                    "type": item.type[3:],
                }
                for item in items
                if item.type in ['qp_body', 'qp_face', 'qp_hair', 'qp_hand', 'qp_head']
            ],
        }

    def format_profile(self, profile: ValidatedDict, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile.update({
            'arcade': "",
            'prefecture': profile.get_int('pid', 51),
            'settings': self.format_settings(profile.get_dict('settings')),
            'flags': self.format_flags(profile.get_dict('settings')),
            'sdjp': playstats.get_int('single_dj_points'),
            'ddjp': playstats.get_int('double_dj_points'),
            'sp': playstats.get_int('single_plays'),
            'dp': playstats.get_int('double_plays'),
            'sdan': self.format_dan_rank(profile.get_int('sgrade', -1)),
            'ddan': self.format_dan_rank(profile.get_int('dgrade', -1)),
            'srank': profile.get_int('sgrade', -1),
            'drank': profile.get_int('dgrade', -1),
            'qpro': self.format_qpro(profile.get_dict('qpro')),
        })
        if 'shop_location' in profile:
            shop_id = profile.get_int('shop_location')
            if shop_id in self.machines:
                formatted_profile['arcade'] = self.machines[shop_id]
            else:
                pcbid = self.data.local.machine.from_machine_id(shop_id)
                if pcbid is not None:
                    machine = self.data.local.machine.get_machine(pcbid)
                    self.machines[shop_id] = machine.name
                    formatted_profile['arcade'] = machine.name
        return formatted_profile

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['miss_count'] = score.data.get_int('miss_count')
        formatted_score['lamp'] = score.data.get_int('clear_status')
        formatted_score['status'] = {
            IIDXBase.CLEAR_STATUS_NO_PLAY: 'NO PLAY',
            IIDXBase.CLEAR_STATUS_FAILED: 'FAILED',
            IIDXBase.CLEAR_STATUS_ASSIST_CLEAR: 'ASSIST CLEAR',
            IIDXBase.CLEAR_STATUS_EASY_CLEAR: 'EASY CLEAR',
            IIDXBase.CLEAR_STATUS_CLEAR: 'CLEAR',
            IIDXBase.CLEAR_STATUS_HARD_CLEAR: 'HARD CLEAR',
            IIDXBase.CLEAR_STATUS_EX_HARD_CLEAR: 'EX HARD CLEAR',
            IIDXBase.CLEAR_STATUS_FULL_COMBO: 'FULL COMBO',
        }.get(score.data.get_int('clear_status'), 'NO PLAY')
        return formatted_score

    def format_top_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['miss_count'] = score.data.get_int('miss_count')
        formatted_score['lamp'] = score.data.get_int('clear_status')
        formatted_score['ghost'] = [x for x in (score.data.get_bytes('ghost') or b'')]
        formatted_score['status'] = {
            IIDXBase.CLEAR_STATUS_NO_PLAY: 'NO PLAY',
            IIDXBase.CLEAR_STATUS_FAILED: 'FAILED',
            IIDXBase.CLEAR_STATUS_ASSIST_CLEAR: 'ASSIST CLEAR',
            IIDXBase.CLEAR_STATUS_EASY_CLEAR: 'EASY CLEAR',
            IIDXBase.CLEAR_STATUS_CLEAR: 'CLEAR',
            IIDXBase.CLEAR_STATUS_HARD_CLEAR: 'HARD CLEAR',
            IIDXBase.CLEAR_STATUS_EX_HARD_CLEAR: 'EX HARD CLEAR',
            IIDXBase.CLEAR_STATUS_FULL_COMBO: 'FULL COMBO',
        }.get(score.data.get_int('clear_status'), 'NO PLAY')
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt['miss_count'] = attempt.data.get_int('miss_count')
        formatted_attempt['status'] = {
            IIDXBase.CLEAR_STATUS_NO_PLAY: 'NO PLAY',
            IIDXBase.CLEAR_STATUS_FAILED: 'FAILED',
            IIDXBase.CLEAR_STATUS_ASSIST_CLEAR: 'ASSIST CLEAR',
            IIDXBase.CLEAR_STATUS_EASY_CLEAR: 'EASY CLEAR',
            IIDXBase.CLEAR_STATUS_CLEAR: 'CLEAR',
            IIDXBase.CLEAR_STATUS_HARD_CLEAR: 'HARD CLEAR',
            IIDXBase.CLEAR_STATUS_EX_HARD_CLEAR: 'EX HARD CLEAR',
            IIDXBase.CLEAR_STATUS_FULL_COMBO: 'FULL COMBO',
        }.get(attempt.data.get_int('clear_status'), 'NO PLAY')
        return formatted_attempt

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0, 0, 0]
        notecounts = [0, 0, 0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int('difficulty', 13)
        notecounts[song.chart] = song.data.get_int('notecount', 5730)

        formatted_song = super().format_song(song)
        formatted_song['bpm_min'] = song.data.get_int('bpm_min', 120)
        formatted_song['bpm_max'] = song.data.get_int('bpm_max', 120)
        formatted_song['difficulties'] = difficulties
        formatted_song['notecounts'] = notecounts
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if (
            existing['difficulties'][new.chart] == 0 or
            existing['notecounts'][new.chart] == 0
        ):
            new_song['difficulties'][new.chart] = new.data.get_int('difficulty', 13)
            new_song['notecounts'][new.chart] = new.data.get_int('notecount', 5730)
        return new_song
