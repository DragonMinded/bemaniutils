# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from bemani.backend.popn import PopnMusicFactory, PopnMusicBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants
from bemani.data import Attempt, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class PopnMusicFrontend(FrontendBase):
    game: GameConstants = GameConstants.POPN_MUSIC

    valid_charts: List[int] = [
        PopnMusicBase.CHART_TYPE_EASY,
        PopnMusicBase.CHART_TYPE_NORMAL,
        PopnMusicBase.CHART_TYPE_HYPER,
        PopnMusicBase.CHART_TYPE_EX,
    ]

    valid_rival_types: List[str] = ["rival"]

    max_active_rivals: Dict[int, int] = {
        # Technically there is support for Rivals in Tune Street but I
        # couldn't get it booting anymore to test.
        VersionConstants.POPN_MUSIC_TUNE_STREET: 0,
        VersionConstants.POPN_MUSIC_FANTASIA: 2,
        VersionConstants.POPN_MUSIC_SUNNY_PARK: 2,
        VersionConstants.POPN_MUSIC_LAPISTORIA: 2,
        VersionConstants.POPN_MUSIC_ECLALE: 4,
        VersionConstants.POPN_MUSIC_USANEKO: 4,
    }

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from PopnMusicFactory.all_games()
        yield (
            GameConstants.POPN_MUSIC,
            0,
            "CS and Licenses",
        )  # Folder that doesn't belong to any specific game

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo", -1)
        formatted_score["medal"] = score.data.get_int("medal")
        formatted_score["stats"] = score.data.get_dict("stats")
        formatted_score["status"] = {
            PopnMusicBase.PLAY_MEDAL_NO_PLAY: "NO PLAY",
            PopnMusicBase.PLAY_MEDAL_CIRCLE_FAILED: "○ FAILED",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_FAILED: "◇ FAILED",
            PopnMusicBase.PLAY_MEDAL_STAR_FAILED: "☆ FAILED",
            PopnMusicBase.PLAY_MEDAL_EASY_CLEAR: "EASY CLEAR",
            PopnMusicBase.PLAY_MEDAL_CIRCLE_CLEARED: "○ CLEARED",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_CLEARED: "◇ CLEARED",
            PopnMusicBase.PLAY_MEDAL_STAR_CLEARED: "☆ CLEARED",
            PopnMusicBase.PLAY_MEDAL_CIRCLE_FULL_COMBO: "○ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_FULL_COMBO: "◇ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_STAR_FULL_COMBO: "☆ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_PERFECT: "PERFECT",
        }.get(score.data.get_int("medal"), "NO PLAY")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo", -1)
        formatted_attempt["medal"] = attempt.data.get_int("medal")
        formatted_attempt["stats"] = attempt.data.get_dict("stats")
        formatted_attempt["status"] = {
            PopnMusicBase.PLAY_MEDAL_CIRCLE_FAILED: "○ FAILED",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_FAILED: "◇ FAILED",
            PopnMusicBase.PLAY_MEDAL_STAR_FAILED: "☆ FAILED",
            PopnMusicBase.PLAY_MEDAL_EASY_CLEAR: "EASY CLEAR",
            PopnMusicBase.PLAY_MEDAL_CIRCLE_CLEARED: "○ CLEARED",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_CLEARED: "◇ CLEARED",
            PopnMusicBase.PLAY_MEDAL_STAR_CLEARED: "☆ CLEARED",
            PopnMusicBase.PLAY_MEDAL_CIRCLE_FULL_COMBO: "○ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_DIAMOND_FULL_COMBO: "◇ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_STAR_FULL_COMBO: "☆ FULL COMBO",
            PopnMusicBase.PLAY_MEDAL_PERFECT: "PERFECT",
        }.get(attempt.data.get_int("medal"), "NO PLAY")
        return formatted_attempt

    def format_profile(
        self, profile: Profile, playstats: ValidatedDict
    ) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int("difficulty", 51)

        formatted_song = super().format_song(song)
        formatted_song["category"] = song.data.get_str("category")
        formatted_song["difficulties"] = difficulties
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0:
            new_song["difficulties"][new.chart] = new.data.get_int("difficulty", 51)
        return new_song
