# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from bemani.backend.danevo import DanceEvolutionFactory, DanceEvolutionBase
from bemani.common import Profile, ValidatedDict, GameConstants
from bemani.data import Attempt, Link, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class DanceEvolutionFrontend(FrontendBase):
    game: GameConstants = GameConstants.DANCE_EVOLUTION

    valid_charts: List[int] = [
        DanceEvolutionBase.CHART_TYPE_LIGHT,
        DanceEvolutionBase.CHART_TYPE_STANDARD,
        DanceEvolutionBase.CHART_TYPE_EXTREME,
        DanceEvolutionBase.CHART_TYPE_STEALTH,
        DanceEvolutionBase.CHART_TYPE_MASTER,
    ]

    valid_rival_types: List[str] = ["dancemate"]

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from DanceEvolutionFactory.all_games()

    def get_all_songs(self, force_db_load: bool = False) -> Dict[int, Dict[str, Any]]:
        def is_valid(data: Dict[str, Any]) -> bool:
            if "levels" not in data:
                return False
            levels = data["levels"]
            if not isinstance(levels, list):
                return False

            for x in levels:
                if x == 0:
                    return False
            return True

        songs = super().get_all_songs(force_db_load)
        filtered_songs = {sid: contents for sid, contents in songs.items() if is_valid(contents)}
        return filtered_songs

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo")
        formatted_score["full_combo"] = score.data.get_bool("full_combo")
        formatted_score["medal"] = score.data.get_int("grade")
        formatted_score["grade"] = {
            DanceEvolutionBase.GRADE_FAILED: "FAILED",
            DanceEvolutionBase.GRADE_E: "E",
            DanceEvolutionBase.GRADE_D: "D",
            DanceEvolutionBase.GRADE_C: "C",
            DanceEvolutionBase.GRADE_B: "B",
            DanceEvolutionBase.GRADE_A: "A",
            DanceEvolutionBase.GRADE_AA: "AA",
            DanceEvolutionBase.GRADE_AAA: "AAA",
        }.get(score.data.get_int("grade"), "NO PLAY")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo")
        formatted_attempt["full_combo"] = attempt.data.get_bool("full_combo")
        formatted_attempt["medal"] = attempt.data.get_int("grade")
        formatted_attempt["grade"] = {
            DanceEvolutionBase.GRADE_FAILED: "FAILED",
            DanceEvolutionBase.GRADE_E: "E",
            DanceEvolutionBase.GRADE_D: "D",
            DanceEvolutionBase.GRADE_C: "C",
            DanceEvolutionBase.GRADE_B: "B",
            DanceEvolutionBase.GRADE_A: "A",
            DanceEvolutionBase.GRADE_AA: "AA",
            DanceEvolutionBase.GRADE_AAA: "AAA",
        }.get(attempt.data.get_int("grade"), "NO PLAY")
        return formatted_attempt

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        formatted_profile["player_class"] = profile.get_int("class")
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        levels = [0, 0, 0, 0, 0]
        levels[song.chart] = song.data.get_int("level")

        formatted_song = super().format_song(song)
        formatted_song["levels"] = levels
        formatted_song["bpm_min"] = song.data.get_int("bpm_min")
        formatted_song["bpm_max"] = song.data.get_int("bpm_max")
        formatted_song["kcal"] = song.data.get_float("kcal")
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["levels"][new.chart] == 0:
            new_song["levels"][new.chart] = new.data.get_int("level")
        return new_song

    def format_rival(self, link: Link, profile: Profile) -> Dict[str, Any]:
        return {
            "userid": str(link.other_userid),
            "last_played": link.data.get_int("last_played"),
        }
