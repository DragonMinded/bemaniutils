# vim: set fileencoding=utf-8
import copy
from typing import Any, Dict, Iterator, List, Tuple

from bemani.backend.ddr import DDRFactory, DDRBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants
from bemani.data import Attempt, Link, RemoteUser, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class DDRFrontend(FrontendBase):
    game: GameConstants = GameConstants.DDR

    version: int = 0  # We use a virtual version for DDR to tie charts together

    valid_charts: List[int] = [
        DDRBase.CHART_SINGLE_BEGINNER,
        DDRBase.CHART_SINGLE_BASIC,
        DDRBase.CHART_SINGLE_DIFFICULT,
        DDRBase.CHART_SINGLE_EXPERT,
        DDRBase.CHART_SINGLE_CHALLENGE,
        DDRBase.CHART_DOUBLE_BASIC,
        DDRBase.CHART_DOUBLE_DIFFICULT,
        DDRBase.CHART_DOUBLE_EXPERT,
        DDRBase.CHART_DOUBLE_CHALLENGE,
    ]

    valid_rival_types: List[str] = [f"friend_{i}" for i in range(10)]

    max_active_rivals: Dict[int, int] = {
        VersionConstants.DDR_X2: 1,
        VersionConstants.DDR_X3_VS_2NDMIX: 3,
        VersionConstants.DDR_2013: 3,
        VersionConstants.DDR_2014: 3,
        VersionConstants.DDR_ACE: 3,
        VersionConstants.DDR_A20: 3,
    }

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from DDRFactory.all_games()

    def update_name(self, profile: Profile, name: str) -> Profile:
        newprofile = copy.deepcopy(profile)
        newprofile.replace_str("name", name)
        return newprofile

    def update_weight(self, profile: Profile, weight: int, enabled: bool) -> Profile:
        newprofile = copy.deepcopy(profile)
        if newprofile.version in (VersionConstants.DDR_ACE, VersionConstants.DDR_A20):
            if enabled:
                newprofile.replace_int("weight", weight)
                newprofile.replace_bool("workout_mode", True)
            else:
                newprofile.replace_int("weight", 0)
                newprofile.replace_bool("workout_mode", False)
        else:
            if enabled:
                newprofile.replace_int("weight", weight)
            else:
                if "weight" in newprofile:
                    del newprofile["weight"]
        return newprofile

    def update_early_late(self, profile: Profile, display_early_late: bool) -> Profile:
        newprofile = copy.deepcopy(profile)
        newprofile.replace_int("early_late", 1 if display_early_late else 0)
        return newprofile

    def update_background_combo(self, profile: Profile, background_combo: bool) -> Profile:
        newprofile = copy.deepcopy(profile)
        newprofile.replace_int("combo", 1 if background_combo else 0)
        return newprofile

    def update_settings(self, profile: Profile, new_settings: Dict[str, Any]) -> Profile:
        newprofile = copy.deepcopy(profile)
        if newprofile.version in (VersionConstants.DDR_ACE, VersionConstants.DDR_A20):
            newprofile.replace_int("arrowskin", new_settings["arrowskin"])
            newprofile.replace_int("guidelines", new_settings["guidelines"])
            newprofile.replace_int("filter", new_settings["filter"])
            newprofile.replace_int("character", new_settings["character"])
        else:
            # No other versions have extra options yet.
            pass
        return newprofile

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        if profile.version in (VersionConstants.DDR_ACE, VersionConstants.DDR_A20):
            formatted_profile.update(
                {
                    "sp": playstats.get_int("single_plays"),
                    "dp": playstats.get_int("double_plays"),
                    "early_late": profile.get_int("early_late") != 0,
                    "background_combo": profile.get_int("combo") != 0,
                    "workout_mode": profile.get_bool("workout_mode"),
                    "weight": profile.get_int("weight"),
                    "settings": {
                        "arrowskin": profile.get_int("arrowskin"),
                        "guidelines": profile.get_int("guidelines"),
                        "filter": profile.get_int("filter"),
                        "character": profile.get_int("character"),
                    },
                }
            )
        else:
            formatted_profile.update(
                {
                    "sp": playstats.get_int("single_plays"),
                    "dp": playstats.get_int("double_plays"),
                    "early_late": profile.get_int("early_late") != 0,
                    "background_combo": profile.get_int("combo") != 0,
                    "workout_mode": "weight" in profile,
                    "weight": profile.get_int("weight"),
                }
            )
        return formatted_profile

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo", -1)
        formatted_score["lamp"] = score.data.get_int("halo")
        formatted_score["halo"] = {
            DDRBase.HALO_NONE: None,
            DDRBase.HALO_GOOD_FULL_COMBO: "GOOD FULL COMBO",
            DDRBase.HALO_GREAT_FULL_COMBO: "GREAT FULL COMBO",
            DDRBase.HALO_PERFECT_FULL_COMBO: "PERFECT FULL COMBO",
            DDRBase.HALO_MARVELOUS_FULL_COMBO: "MARVELOUS FULL COMBO",
        }.get(score.data.get_int("halo"))
        formatted_score["status"] = score.data.get_int("rank")
        formatted_score["rank"] = {
            DDRBase.RANK_AAA: "AAA",
            DDRBase.RANK_AA_PLUS: "AA+",
            DDRBase.RANK_AA: "AA",
            DDRBase.RANK_AA_MINUS: "AA-",
            DDRBase.RANK_A_PLUS: "A+",
            DDRBase.RANK_A: "A",
            DDRBase.RANK_A_MINUS: "A-",
            DDRBase.RANK_B_PLUS: "B+",
            DDRBase.RANK_B: "B",
            DDRBase.RANK_B_MINUS: "B-",
            DDRBase.RANK_C_PLUS: "C+",
            DDRBase.RANK_C: "C",
            DDRBase.RANK_C_MINUS: "C-",
            DDRBase.RANK_D_PLUS: "D+",
            DDRBase.RANK_D: "D",
            DDRBase.RANK_E: "E",
        }.get(score.data.get_int("rank"), "NO PLAY")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo", -1)
        formatted_attempt["halo"] = {
            DDRBase.HALO_NONE: None,
            DDRBase.HALO_GOOD_FULL_COMBO: "GOOD FULL COMBO",
            DDRBase.HALO_GREAT_FULL_COMBO: "GREAT FULL COMBO",
            DDRBase.HALO_PERFECT_FULL_COMBO: "PERFECT FULL COMBO",
            DDRBase.HALO_MARVELOUS_FULL_COMBO: "MARVELOUS FULL COMBO",
        }.get(attempt.data.get_int("halo"))
        formatted_attempt["rank"] = {
            DDRBase.RANK_AAA: "AAA",
            DDRBase.RANK_AA_PLUS: "AA+",
            DDRBase.RANK_AA: "AA",
            DDRBase.RANK_AA_MINUS: "AA-",
            DDRBase.RANK_A_PLUS: "A+",
            DDRBase.RANK_A: "A",
            DDRBase.RANK_A_MINUS: "A-",
            DDRBase.RANK_B_PLUS: "B+",
            DDRBase.RANK_B: "B",
            DDRBase.RANK_B_MINUS: "B-",
            DDRBase.RANK_C_PLUS: "C+",
            DDRBase.RANK_C: "C",
            DDRBase.RANK_C_MINUS: "C-",
            DDRBase.RANK_D_PLUS: "D+",
            DDRBase.RANK_D: "D",
            DDRBase.RANK_E: "E",
        }.get(attempt.data.get_int("rank"), "NO PLAY")
        return formatted_attempt

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0] * 10
        difficulties[song.chart] = song.data.get_int("difficulty", 20)

        formatted_song = super().format_song(song)
        formatted_song["bpm_min"] = song.data.get_int("bpm_min", 120)
        formatted_song["bpm_max"] = song.data.get_int("bpm_max", 120)
        formatted_song["category"] = song.data.get_int("category", 0)
        formatted_song["groove"] = song.data.get_dict(
            "groove",
            {
                "voltage": 0,
                "stream": 0,
                "air": 0,
                "chaos": 0,
                "freeze": 0,
            },
        )
        formatted_song["difficulties"] = difficulties
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0:
            new_song["difficulties"][new.chart] = new.data.get_int("difficulty", 20)
        return new_song

    def activate_rival(self, profile: Profile, position: int) -> Profile:
        newprofile = copy.deepcopy(profile)
        if newprofile.version == VersionConstants.DDR_X2:
            # X2 only has one active rival
            lastdict = newprofile.get_dict("last")
            lastdict.replace_int("fri", position + 1)
            newprofile.replace_dict("last", lastdict)
        elif newprofile.version in [
            VersionConstants.DDR_X3_VS_2NDMIX,
            VersionConstants.DDR_2013,
            VersionConstants.DDR_2014,
            VersionConstants.DDR_ACE,
            VersionConstants.DDR_A20,
        ]:
            # X3 has 3 active rivals, put this in the first open slot
            lastdict = newprofile.get_dict("last")
            if lastdict.get_int("rival1") < 1:
                lastdict.replace_int("rival1", position + 1)
            elif lastdict.get_int("rival2") < 1:
                lastdict.replace_int("rival2", position + 1)
            elif lastdict.get_int("rival3") < 1:
                lastdict.replace_int("rival3", position + 1)
            newprofile.replace_dict("last", lastdict)
        return newprofile

    def deactivate_rival(self, profile: Profile, position: int) -> Profile:
        newprofile = copy.deepcopy(profile)
        if newprofile.version == VersionConstants.DDR_X2:
            # X2 only has one active rival
            lastdict = newprofile.get_dict("last")
            if lastdict.get_int("fri") == position + 1:
                lastdict.replace_int("fri", 0)
            newprofile.replace_dict("last", lastdict)
        elif newprofile.version in [
            VersionConstants.DDR_X3_VS_2NDMIX,
            VersionConstants.DDR_2013,
            VersionConstants.DDR_2014,
            VersionConstants.DDR_ACE,
            VersionConstants.DDR_A20,
        ]:
            # X3 has 3 active rivals, put this in the first open slot
            lastdict = newprofile.get_dict("last")
            if lastdict.get_int("rival1") == position + 1:
                lastdict.replace_int("rival1", 0)
            elif lastdict.get_int("rival2") == position + 1:
                lastdict.replace_int("rival2", 0)
            elif lastdict.get_int("rival3") == position + 1:
                lastdict.replace_int("rival3", 0)
            newprofile.replace_dict("last", lastdict)
        return newprofile

    def format_rival(self, link: Link, profile: Profile) -> Dict[str, Any]:
        pos = int(link.type[7:])
        if profile.version == VersionConstants.DDR_X2:
            active = pos == (profile.get_dict("last").get_int("fri") - 1)
        elif profile.version in {
            VersionConstants.DDR_X3_VS_2NDMIX,
            VersionConstants.DDR_2013,
            VersionConstants.DDR_2014,
            VersionConstants.DDR_ACE,
            VersionConstants.DDR_A20,
        }:
            actives = [
                profile.get_dict("last").get_int("rival1") - 1,
                profile.get_dict("last").get_int("rival2") - 1,
                profile.get_dict("last").get_int("rival3") - 1,
            ]
            active = pos in actives
        else:
            active = False
        return {
            "position": pos,
            "active": active,
            "userid": str(link.other_userid),
            "remote": RemoteUser.is_remote(link.other_userid),
        }
