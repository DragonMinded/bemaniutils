# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from flask_caching import Cache

from bemani.backend.sdvx import SoundVoltexFactory, SoundVoltexBase
from bemani.common import GameConstants, Profile, ValidatedDict
from bemani.data import Attempt, Data, Config, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class SoundVoltexFrontend(FrontendBase):
    game: GameConstants = GameConstants.SDVX

    valid_charts: List[int] = [
        SoundVoltexBase.CHART_TYPE_NOVICE,
        SoundVoltexBase.CHART_TYPE_ADVANCED,
        SoundVoltexBase.CHART_TYPE_EXHAUST,
        SoundVoltexBase.CHART_TYPE_INFINITE,
        SoundVoltexBase.CHART_TYPE_MAXIMUM,
    ]

    valid_rival_types: List[str] = [
        "rival",
    ]

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        super().__init__(data, config, cache)

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from SoundVoltexFactory.all_games()

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo", -1)
        formatted_score["grade"] = {
            SoundVoltexBase.GRADE_NO_PLAY: "-",
            SoundVoltexBase.GRADE_D: "D",
            SoundVoltexBase.GRADE_C: "C",
            SoundVoltexBase.GRADE_B: "B",
            SoundVoltexBase.GRADE_A: "A",
            SoundVoltexBase.GRADE_A_PLUS: "A+",
            SoundVoltexBase.GRADE_AA: "AA",
            SoundVoltexBase.GRADE_AA_PLUS: "AA+",
            SoundVoltexBase.GRADE_AAA: "AAA",
            SoundVoltexBase.GRADE_AAA_PLUS: "AAA+",
            SoundVoltexBase.GRADE_S: "S",
        }.get(score.data.get_int("grade"), "No Play")
        formatted_score["clear_type"] = {
            SoundVoltexBase.CLEAR_TYPE_NO_PLAY: "NO PLAY",
            SoundVoltexBase.CLEAR_TYPE_FAILED: "FAILED",
            SoundVoltexBase.CLEAR_TYPE_CLEAR: "CLEARED",
            SoundVoltexBase.CLEAR_TYPE_HARD_CLEAR: "HARD CLEARED",
            SoundVoltexBase.CLEAR_TYPE_ULTIMATE_CHAIN: "ULTIMATE CHAIN",
            SoundVoltexBase.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: "PERFECT ULTIMATE CHAIN",
        }.get(score.data.get_int("clear_type"), "FAILED")
        formatted_score["medal"] = score.data.get_int("clear_type")
        formatted_score["stats"] = score.data.get_dict("stats")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo", -1)
        formatted_attempt["grade"] = {
            SoundVoltexBase.GRADE_NO_PLAY: "-",
            SoundVoltexBase.GRADE_D: "D",
            SoundVoltexBase.GRADE_C: "C",
            SoundVoltexBase.GRADE_B: "B",
            SoundVoltexBase.GRADE_A: "A",
            SoundVoltexBase.GRADE_A_PLUS: "A+",
            SoundVoltexBase.GRADE_AA: "AA",
            SoundVoltexBase.GRADE_AA_PLUS: "AA+",
            SoundVoltexBase.GRADE_AAA: "AAA",
            SoundVoltexBase.GRADE_AAA_PLUS: "AAA+",
            SoundVoltexBase.GRADE_S: "S",
        }.get(attempt.data.get_int("grade"), "No Play")
        formatted_attempt["clear_type"] = {
            SoundVoltexBase.CLEAR_TYPE_NO_PLAY: "NO PLAY",
            SoundVoltexBase.CLEAR_TYPE_FAILED: "FAILED",
            SoundVoltexBase.CLEAR_TYPE_CLEAR: "CLEARED",
            SoundVoltexBase.CLEAR_TYPE_HARD_CLEAR: "HARD CLEARED",
            SoundVoltexBase.CLEAR_TYPE_ULTIMATE_CHAIN: "ULTIMATE CHAIN",
            SoundVoltexBase.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: "PERFECT ULTIMATE CHAIN",
        }.get(attempt.data.get_int("clear_type"), "FAILED")
        formatted_attempt["medal"] = attempt.data.get_int("clear_type")
        formatted_attempt["stats"] = attempt.data.get_dict("stats")
        return formatted_attempt

    def format_profile(
        self, profile: Profile, playstats: ValidatedDict
    ) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int("difficulty", 21)

        formatted_song = super().format_song(song)
        formatted_song["difficulties"] = difficulties
        formatted_song["category"] = song.version
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0:
            new_song["difficulties"][new.chart] = new.data.get_int("difficulty", 21)
        # Set the category to the earliest seen version of this song
        if existing["category"] > new.version:
            new_song["category"] = new.version
        return new_song
