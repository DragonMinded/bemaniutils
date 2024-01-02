# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Optional, Tuple

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

    valid_rival_types: List[str] = ["rival"]

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

        for game, version, name in self.all_games():
            if version in mapping:
                yield (game, mapping[version], name)

    def get_duplicate_id(self, musicid: int, chart: int) -> Optional[Tuple[int, int]]:
        # In qubell and clan omnimix, PPAP and Bonjour the world are placed
        # at this arbitrary songid since they weren't assigned one originally
        # In jubeat festo, these songs were given proper songids so we need to account for this
        legacy_to_modern_map = {
            71000001: 70000124,  # PPAP
            71000002: 70000154,  # Bonjour the world
            50000020: 80000037,  # 千本桜 was removed and then revived in clan
            60000063: 70000100,  # Khamen break sdvx had the first id for prop(never released officially)
        }
        oldid = legacy_to_modern_map.get(musicid)
        oldchart = chart
        if oldid is not None:
            return (oldid, oldchart)
        else:
            return None

    def get_all_items(self, versions: list) -> Dict[str, List[Dict[str, Any]]]:
        result = {}
        for version in versions:
            emblem = self.__format_jubeat_extras(version)
            result[version] = emblem["emblems"]
        return result

    def __format_jubeat_extras(self, version: int) -> Dict[str, List[Dict[str, Any]]]:
        # Gotta look up the unlock catalog
        items = self.data.local.game.get_items(self.game, version)

        # Format it depending on the version
        if version in {
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
            VersionConstants.JUBEAT_FESTO,
        }:
            return {
                "emblems": [
                    {
                        "index": str(item.id),
                        "song": item.data.get_int("music_id"),
                        "layer": item.data.get_int("layer"),
                        "evolved": item.data.get_int("evolved"),
                        "rarity": item.data.get_int("rarity"),
                        "name": item.data.get_str("name"),
                    }
                    for item in items
                    if item.type == "emblem"
                ],
            }
        else:
            return {"emblems": []}

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["combo"] = score.data.get_int("combo", -1)
        formatted_score["music_rate"] = score.data.get_int("music_rate", -1)
        if formatted_score["music_rate"] >= 0:
            formatted_score["music_rate"] /= 10
        formatted_score["medal"] = score.data.get_int("medal")
        formatted_score["status"] = {
            JubeatBase.PLAY_MEDAL_FAILED: "FAILED",
            JubeatBase.PLAY_MEDAL_CLEARED: "CLEARED",
            JubeatBase.PLAY_MEDAL_NEARLY_FULL_COMBO: "NEARLY FULL COMBO",
            JubeatBase.PLAY_MEDAL_FULL_COMBO: "FULL COMBO",
            JubeatBase.PLAY_MEDAL_NEARLY_EXCELLENT: "NEARLY EXCELLENT",
            JubeatBase.PLAY_MEDAL_EXCELLENT: "EXCELLENT",
        }.get(score.data.get_int("medal"), "NO PLAY")
        formatted_score["clear_cnt"] = score.data.get_int("clear_count", 0)
        formatted_score["stats"] = score.data.get_dict("stats")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["combo"] = attempt.data.get_int("combo", -1)
        formatted_attempt["medal"] = attempt.data.get_int("medal")
        formatted_attempt["music_rate"] = attempt.data.get_int("music_rate", -1)
        if formatted_attempt["music_rate"] >= 0:
            formatted_attempt["music_rate"] /= 10
        formatted_attempt["status"] = {
            JubeatBase.PLAY_MEDAL_FAILED: "FAILED",
            JubeatBase.PLAY_MEDAL_CLEARED: "CLEARED",
            JubeatBase.PLAY_MEDAL_NEARLY_FULL_COMBO: "NEARLY FULL COMBO",
            JubeatBase.PLAY_MEDAL_FULL_COMBO: "FULL COMBO",
            JubeatBase.PLAY_MEDAL_NEARLY_EXCELLENT: "NEARLY EXCELLENT",
            JubeatBase.PLAY_MEDAL_EXCELLENT: "EXCELLENT",
        }.get(attempt.data.get_int("medal"), "NO PLAY")
        formatted_attempt["stats"] = attempt.data.get_dict("stats")
        return formatted_attempt

    def format_emblem(self, emblem: list) -> Dict[str, Any]:
        return {
            "background": emblem[0],
            "main": emblem[1],
            "ornament": emblem[2],
            "effect": emblem[3],
            "speech_bubble": emblem[4],
        }

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        # Grab achievements for both jubility in festo, as well as emblem parts in
        # prop onward.
        userid = self.data.local.user.from_refid(profile.game, profile.version, profile.refid)
        if userid is not None:
            achievements = self.data.local.user.get_achievements(profile.game, profile.version, userid)
        else:
            achievements = []

        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        formatted_profile["emblem"] = self.format_emblem(profile.get_dict("last").get_int_array("emblem", 5))
        formatted_profile["owned_emblems"] = [str(ach.id) for ach in achievements if ach.type == "emblem"]
        formatted_profile["jubility"] = (
            profile.get_int("jubility")
            if profile.version
            not in {
                VersionConstants.JUBEAT_PROP,
                VersionConstants.JUBEAT_QUBELL,
                VersionConstants.JUBEAT_FESTO,
            }
            else 0
        )
        formatted_profile["pick_up_jubility"] = (
            profile.get_float("pick_up_jubility") if profile.version == VersionConstants.JUBEAT_FESTO else 0
        )
        formatted_profile["common_jubility"] = (
            profile.get_float("common_jubility") if profile.version == VersionConstants.JUBEAT_FESTO else 0
        )
        if profile.version == VersionConstants.JUBEAT_FESTO:
            # Only reason this is a dictionary of dictionaries is because ValidatedDict doesn't support a list of dictionaries.
            # Probably intentionally lol. Just listify the pickup/common charts.
            formatted_profile["pick_up_chart"] = list(profile.get_dict("pick_up_chart").values())
            formatted_profile["common_chart"] = list(profile.get_dict("common_chart").values())
        elif profile.version == VersionConstants.JUBEAT_CLAN:
            # Look up achievements which is where jubility was stored. This is a bit of a hack
            # due to the fact that this could be formatting remote profiles, but then they should
            # have no achievements.
            jubeat_entries: List[ValidatedDict] = []
            for achievement in achievements:
                if achievement.type != "jubility":
                    continue

                # Figure out for each song, what's the highest value jubility and
                # keep that.
                bestentry = ValidatedDict()
                for chart in [0, 1, 2]:
                    entry = achievement.data.get_dict(str(chart))
                    if entry.get_int("value") >= bestentry.get_int("value"):
                        bestentry = entry.clone()
                        bestentry.replace_int("songid", achievement.id)
                        bestentry.replace_int("chart", chart)
                jubeat_entries.append(bestentry)
            jubeat_entries = sorted(jubeat_entries, key=lambda entry: entry.get_int("value"), reverse=True)[:30]
            formatted_profile["chart"] = jubeat_entries

        formatted_profile["ex_count"] = profile.get_int("ex_cnt")
        formatted_profile["fc_count"] = profile.get_int("fc_cnt")
        return formatted_profile

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        difficulties[song.chart] = song.data.get_float("difficulty", 13)
        if difficulties[song.chart] == 13.0:
            difficulties[song.chart] = float(song.data.get_int("difficulty", 13))

        formatted_song = super().format_song(song)
        formatted_song["bpm_min"] = song.data.get_int("bpm_min", 120)
        formatted_song["bpm_max"] = song.data.get_int("bpm_max", 120)
        formatted_song["difficulties"] = difficulties
        version = song.data.get_int("version", 0)
        if version == 0:
            # The default here is a nasty hack for installations that existed prior to importing
            # version using read.py. This ensures that not importing again won't break existing
            # installations.
            formatted_song["version"] = int(song.id / 10000000)
        else:
            formatted_song["version"] = {
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
            }[version]
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0.0:
            new_song["difficulties"][new.chart] = new.data.get_float("difficulty", 13)
            if new_song["difficulties"][new.chart] == 13.0:
                new_song["difficulties"][new.chart] = float(new.data.get_int("difficulty", 13))
        return new_song
