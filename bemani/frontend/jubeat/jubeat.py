# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from bemani.backend.jubeat import JubeatFactory, JubeatBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants
from bemani.data import Attempt, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class JubeatFrontend(FrontendBase):

    game: GameConstants = GameConstants.JUBEAT

    valid_charts: List[int] = [
        JubeatBase.CHART_TYPE_BASIC,
        JubeatBase.CHART_TYPE_ADVANCED,
        JubeatBase.CHART_TYPE_EXTREME,
        JubeatBase.CHART_TYPE_HARD_BASIC,
        JubeatBase.CHART_TYPE_HARD_ADVANCED,
        JubeatBase.CHART_TYPE_HARD_EXTREME,
    ]

    valid_rival_types: List[str] = ['rival']

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from JubeatFactory.all_games()

    def sanitized_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        mapping = {
            VersionConstants.JUBEAT: 1,
            VersionConstants.JUBEAT_RIPPLES: 2,
            VersionConstants.JUBEAT_KNIT: 3,
            VersionConstants.JUBEAT_COPIOUS: 4,
            VersionConstants.JUBEAT_SAUCER: 5,
            VersionConstants.JUBEAT_PROP: 6,
            VersionConstants.JUBEAT_QUBELL: 7,
            VersionConstants.JUBEAT_CLAN: 8,
            VersionConstants.JUBEAT_FESTO: 9,
        }

        for (game, version, name) in self.all_games():
            if version in mapping:
                yield (game, mapping[version], name)

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['combo'] = score.data.get_int('combo', -1)
        formatted_score['music_rate'] = score.data.get_int('music_rate', -1)
        if formatted_score['music_rate'] >= 0:
            formatted_score['music_rate'] /= 10
        formatted_score['medal'] = score.data.get_int('medal')
        formatted_score['status'] = {
            JubeatBase.PLAY_MEDAL_FAILED: "FAILED",
            JubeatBase.PLAY_MEDAL_CLEARED: "CLEARED",
            JubeatBase.PLAY_MEDAL_NEARLY_FULL_COMBO: "NEARLY FULL COMBO",
            JubeatBase.PLAY_MEDAL_FULL_COMBO: "FULL COMBO",
            JubeatBase.PLAY_MEDAL_NEARLY_EXCELLENT: "NEARLY EXCELLENT",
            JubeatBase.PLAY_MEDAL_EXCELLENT: "EXCELLENT",
        }.get(score.data.get_int('medal'), 'NO PLAY')
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt['combo'] = attempt.data.get_int('combo', -1)
        formatted_attempt['medal'] = attempt.data.get_int('medal')
        formatted_attempt['music_rate'] = attempt.data.get_int('music_rate', -1)
        if formatted_attempt['music_rate'] >= 0:
            formatted_attempt['music_rate'] /= 10
        formatted_attempt['status'] = {
            JubeatBase.PLAY_MEDAL_FAILED: "FAILED",
            JubeatBase.PLAY_MEDAL_CLEARED: "CLEARED",
            JubeatBase.PLAY_MEDAL_NEARLY_FULL_COMBO: "NEARLY FULL COMBO",
            JubeatBase.PLAY_MEDAL_FULL_COMBO: "FULL COMBO",
            JubeatBase.PLAY_MEDAL_NEARLY_EXCELLENT: "NEARLY EXCELLENT",
            JubeatBase.PLAY_MEDAL_EXCELLENT: "EXCELLENT",
        }.get(attempt.data.get_int('medal'), 'NO PLAY')
        return formatted_attempt

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile['plays'] = playstats.get_int('total_plays')
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        difficulties[song.chart] = song.data.get_float('difficulty', 13)
        if difficulties[song.chart] == 13.0:
            difficulties[song.chart] = float(song.data.get_int('difficulty', 13))

        formatted_song = super().format_song(song)
        formatted_song['bpm_min'] = song.data.get_int('bpm_min', 120)
        formatted_song['bpm_max'] = song.data.get_int('bpm_max', 120)
        formatted_song['difficulties'] = difficulties
        formatted_song['version'] = {
            VersionConstants.JUBEAT: 1,
            VersionConstants.JUBEAT_RIPPLES: 2,
            VersionConstants.JUBEAT_RIPPLES_APPEND: 2,
            VersionConstants.JUBEAT_KNIT: 3,
            VersionConstants.JUBEAT_KNIT_APPEND: 3,
            VersionConstants.JUBEAT_COPIOUS: 4,
            VersionConstants.JUBEAT_COPIOUS_APPEND: 4,
            VersionConstants.JUBEAT_SAUCER: 5,
            VersionConstants.JUBEAT_SAUCER_FULFILL: 5,
            VersionConstants.JUBEAT_PROP: 6,
            VersionConstants.JUBEAT_QUBELL: 7,
            VersionConstants.JUBEAT_CLAN: 8,
            VersionConstants.JUBEAT_FESTO: 9,
        }.get(song.data.get_int('version', 1), 1)
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing['difficulties'][new.chart] == 0.0:
            new_song['difficulties'][new.chart] = new.data.get_float('difficulty', 13)
            if new_song['difficulties'][new.chart] == 13.0:
                new_song['difficulties'][new.chart] = float(new.data.get_int('difficulty', 13))
        return new_song
