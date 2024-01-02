# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from flask_caching import Cache

from bemani.backend.reflec import ReflecBeatFactory, ReflecBeatBase
from bemani.common import GameConstants, Profile, ValidatedDict
from bemani.data import Attempt, Data, Config, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class ReflecBeatFrontend(FrontendBase):
    game: GameConstants = GameConstants.REFLEC_BEAT

    version: int = 0  # We use a virtual version for ReflecBeat to tie charts together

    valid_charts: List[int] = [
        ReflecBeatBase.CHART_TYPE_BASIC,
        ReflecBeatBase.CHART_TYPE_MEDIUM,
        ReflecBeatBase.CHART_TYPE_HARD,
        ReflecBeatBase.CHART_TYPE_SPECIAL,
    ]

    valid_rival_types: List[str] = [
        "rival",
    ]

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        super().__init__(data, config, cache)

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from ReflecBeatFactory.all_games()

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo", -1)
        formatted_score["achievement_rate"] = score.data.get_int("achievement_rate", -1)
        formatted_score["miss_count"] = score.data.get_int("miss_count", -1)
        formatted_score["clear_type"] = {
            ReflecBeatBase.CLEAR_TYPE_NO_PLAY: "NO PLAY",
            ReflecBeatBase.CLEAR_TYPE_FAILED: "FAILED",
            ReflecBeatBase.CLEAR_TYPE_CLEARED: "CLEARED",
            ReflecBeatBase.CLEAR_TYPE_HARD_CLEARED: "HARD CLEARED",
            ReflecBeatBase.CLEAR_TYPE_S_HARD_CLEARED: "S-HARD CLEARED",
        }.get(score.data.get_int("clear_type"), "FAILED")
        formatted_score["combo_type"] = {
            ReflecBeatBase.COMBO_TYPE_NONE: "",
            ReflecBeatBase.COMBO_TYPE_ALMOST_COMBO: "ALMOST FULL COMBO",
            ReflecBeatBase.COMBO_TYPE_FULL_COMBO: "FULL COMBO",
            ReflecBeatBase.COMBO_TYPE_FULL_COMBO_ALL_JUST: "FULL COMBO + ALL JUST",
        }.get(score.data.get_int("combo_type"), "")
        formatted_score["medal"] = score.data.get_int("combo_type") * 1000 + score.data.get_int("clear_type")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo", -1)
        formatted_attempt["achievement_rate"] = attempt.data.get_int("achievement_rate", -1)
        formatted_attempt["miss_count"] = attempt.data.get_int("miss_count", -1)
        formatted_attempt["clear_type"] = {
            ReflecBeatBase.CLEAR_TYPE_NO_PLAY: "NO PLAY",
            ReflecBeatBase.CLEAR_TYPE_FAILED: "FAILED",
            ReflecBeatBase.CLEAR_TYPE_CLEARED: "CLEARED",
            ReflecBeatBase.CLEAR_TYPE_HARD_CLEARED: "HARD CLEARED",
            ReflecBeatBase.CLEAR_TYPE_S_HARD_CLEARED: "S-HARD CLEARED",
        }.get(attempt.data.get_int("clear_type"), "FAILED")
        formatted_attempt["combo_type"] = {
            ReflecBeatBase.COMBO_TYPE_NONE: "",
            ReflecBeatBase.COMBO_TYPE_ALMOST_COMBO: "ALMOST FULL COMBO",
            ReflecBeatBase.COMBO_TYPE_FULL_COMBO: "FULL COMBO",
            ReflecBeatBase.COMBO_TYPE_FULL_COMBO_ALL_JUST: "FULL COMBO + ALL JUST",
        }.get(attempt.data.get_int("combo_type"), "")
        formatted_attempt["medal"] = attempt.data.get_int("combo_type") * 1000 + attempt.data.get_int("clear_type")
        return formatted_attempt

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int("difficulty", 16)

        formatted_song = super().format_song(song)
        formatted_song["difficulties"] = difficulties
        formatted_song["category"] = song.data.get_int("folder", 1)
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0:
            new_song["difficulties"][new.chart] = new.data.get_int("difficulty", 16)
        if existing["category"] == 0:
            new_song["category"] = new.data.get_int("folder", 1)
        return new_song
