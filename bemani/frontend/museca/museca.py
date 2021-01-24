# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, Tuple

from flask_caching import Cache  # type: ignore

from bemani.backend.museca import MusecaFactory, MusecaBase
from bemani.common import GameConstants, VersionConstants, DBConstants, ValidatedDict
from bemani.data import Attempt, Data, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class MusecaFrontend(FrontendBase):

    game = GameConstants.MUSECA

    valid_charts = [
        MusecaBase.CHART_TYPE_GREEN,
        MusecaBase.CHART_TYPE_ORANGE,
        MusecaBase.CHART_TYPE_RED,
    ]

    def __init__(self, data: Data, config: Dict[str, Any], cache: Cache) -> None:
        super().__init__(data, config, cache)

    def all_games(self) -> Iterator[Tuple[str, int, str]]:
        yield from MusecaFactory.all_games()
        yield (
            GameConstants.MUSECA,
            VersionConstants.MUSECA_1_PLUS + DBConstants.OMNIMIX_VERSION_BUMP,
            'MÚSECA PLUS',
        )  # Hard code entry for MÚSECA PLUS since entries will go in blank category otherwise

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['combo'] = score.data.get_int('combo', -1)
        formatted_score['grade'] = {
            MusecaBase.GRADE_DEATH: 'Death (没)',
            MusecaBase.GRADE_POOR: 'Poor (拙)',
            MusecaBase.GRADE_MEDIOCRE: 'Mediocre (凡)',
            MusecaBase.GRADE_GOOD: 'Good (佳)',
            MusecaBase.GRADE_GREAT: 'Great (良)',
            MusecaBase.GRADE_EXCELLENT: 'Excellent (優)',
            MusecaBase.GRADE_SUPERB: 'Superb (秀)',
            MusecaBase.GRADE_MASTERPIECE: 'Masterpiece (傑)',
            MusecaBase.GRADE_PERFECT: 'Perfect (傑)',
        }.get(score.data.get_int('grade'), 'No Play')
        formatted_score['clear_type'] = {
            MusecaBase.CLEAR_TYPE_FAILED: 'Failed',
            MusecaBase.CLEAR_TYPE_CLEARED: 'Cleared',
            MusecaBase.CLEAR_TYPE_FULL_COMBO: 'Full Combo',
        }.get(score.data.get_int('clear_type'), 'Failed')
        formatted_score['medal'] = score.data.get_int('clear_type')
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt['combo'] = attempt.data.get_int('combo', -1)
        formatted_attempt['grade'] = {
            MusecaBase.GRADE_DEATH: 'Death (没)',
            MusecaBase.GRADE_POOR: 'Poor (拙)',
            MusecaBase.GRADE_MEDIOCRE: 'Mediocre (凡)',
            MusecaBase.GRADE_GOOD: 'Good (佳)',
            MusecaBase.GRADE_GREAT: 'Great (良)',
            MusecaBase.GRADE_EXCELLENT: 'Excellent (優)',
            MusecaBase.GRADE_SUPERB: 'Superb (秀)',
            MusecaBase.GRADE_MASTERPIECE: 'Masterpiece (傑)',
            MusecaBase.GRADE_PERFECT: 'Perfect (傑)',
        }.get(attempt.data.get_int('grade'), 'No Play')
        formatted_attempt['clear_type'] = {
            MusecaBase.CLEAR_TYPE_FAILED: 'Failed',
            MusecaBase.CLEAR_TYPE_CLEARED: 'Cleared',
            MusecaBase.CLEAR_TYPE_FULL_COMBO: 'Full Combo',
        }.get(attempt.data.get_int('clear_type'), 'Failed')
        formatted_attempt['medal'] = attempt.data.get_int('clear_type')
        return formatted_attempt

    def format_profile(self, profile: ValidatedDict, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile['plays'] = playstats.get_int('total_plays')
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0]
        difficulties[song.chart] = song.data.get_int('difficulty', 21)

        formatted_song = super().format_song(song)
        formatted_song['difficulties'] = difficulties
        formatted_song['category'] = song.version
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing['difficulties'][new.chart] == 0:
            new_song['difficulties'][new.chart] = new.data.get_int('difficulty', 21)
        # Set the category to the earliest seen version of this song
        if existing['category'] > new.version:
            new_song['category'] = new.version
        return new_song
