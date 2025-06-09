# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from flask_caching import Cache  # type: ignore

from bemani.backend.gitadora import GitadoraFactory, GitadoraBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants, DBConstants
from bemani.data import Attempt, Data, Config, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class GitadoraFrontend(FrontendBase):
    game: GameConstants = GameConstants.GITADORA

    version: int = 0  # We use a virtual version for gitadora to tie charts together

    valid_charts: List[int] = [
        0,
        GitadoraBase.GITUAR_CHART_TYPE_BASIC,
        GitadoraBase.GITUAR_CHART_TYPE_ADVANCE,
        GitadoraBase.GITUAR_CHART_TYPE_EXTREME,
        GitadoraBase.GITUAR_CHART_TYPE_MASTER,
        0,
        GitadoraBase.DRUM_CHART_TYPE_BASIC,
        GitadoraBase.DRUM_CHART_TYPE_ADVANCE,
        GitadoraBase.DRUM_CHART_TYPE_EXTREME,
        GitadoraBase.DRUM_CHART_TYPE_MASTER,
        0,
        GitadoraBase.BASS_CHART_TYPE_BASIC,
        GitadoraBase.BASS_CHART_TYPE_ADVANCE,
        GitadoraBase.BASS_CHART_TYPE_EXTREME,
        GitadoraBase.BASS_CHART_TYPE_MASTER,
    ]

    valid_rival_types: List[str] = [
        "gf_rival",
        "dm_rival",
    ]

    gitadora_chart: Dict[int, str] = {
        0: "NONE",
        GitadoraBase.GITUAR_CHART_TYPE_BASIC: "G.BSC",
        GitadoraBase.GITUAR_CHART_TYPE_ADVANCE: "G.ADV",
        GitadoraBase.GITUAR_CHART_TYPE_EXTREME: "G.EXT",
        GitadoraBase.GITUAR_CHART_TYPE_MASTER: "G.MST",
        5: "NONE",
        GitadoraBase.DRUM_CHART_TYPE_BASIC: "D.BSC",
        GitadoraBase.DRUM_CHART_TYPE_ADVANCE: "D.ADV",
        GitadoraBase.DRUM_CHART_TYPE_EXTREME: "D.EXT",
        GitadoraBase.DRUM_CHART_TYPE_MASTER: "D.MST",
        10: "NONE",
        GitadoraBase.BASS_CHART_TYPE_BASIC: "B.BSC",
        GitadoraBase.BASS_CHART_TYPE_ADVANCE: "B.ADV",
        GitadoraBase.BASS_CHART_TYPE_EXTREME: "B.EXT",
        GitadoraBase.BASS_CHART_TYPE_MASTER: "B.MST",
    }

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        super().__init__(data, config, cache)

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from GitadoraFactory.all_games()

    def get_all_items(self, versions: list) -> Dict[str, List[Dict[str, Any]]]:
        result = {}
        for version in versions:
            trbitem = self.__format_gitadora_extras(version)
            result[version] = trbitem["trbitem"]
        return result

    def __format_gitadora_extras(self, version: int) -> Dict[str, List[Dict[str, Any]]]:
        # Gotta look up the unlock catalog
        items = self.data.local.game.get_items(self.game, version)

        # Format it depending on the version
        if version >= VersionConstants.GITADORA_MATIXX:
            return {
                "trbitem": [
                    {
                        "index": str(item.id),
                        "name": item.data.get_str("name"),
                    }
                    for item in items
                    if item.type == "trbitem"
                ],
            }
        else:
            return {"trbitem": []}

    def format_trbitem(self, trbitem: list) -> Dict[str, Any]:
        return {
            "trbitem": trbitem,
        }

    def format_skills(
        self,
        game: GameConstants,
        userid: UserID,
        version: int,
        skill_list: list,
        option_type: str,
    ) -> List[Dict[str, Any]]:
        chart_indices = {
            "dm": [6, 7, 8, 9],
            "gf": [1, 2, 3, 4, 11, 12, 13, 14],
        }

        # Determine the chart index type based on option_type
        if "dm" in option_type:
            chart_key = "dm"
            chart_base = 6
        elif "gf" in option_type:
            chart_key = "gf"
            chart_base = 1

        skill_list = list(filter(lambda x: x != -1, skill_list))
        skills = []

        for songid in skill_list:
            skill_index = []
            skill_prec_index = []

            # Get music data for both the original version and OMNIMIX
            music_base = self.data.local.music.get_song(
                game, version, songid, songchart=chart_base
            )
            music_omni = self.data.local.music.get_song(
                game, version + DBConstants.OMNIMIX_VERSION_BUMP, songid, songchart=chart_base
            )

            # If both music_base and music_omni exist, merge their attributes
            def merge_music_objects(base, omni):
                # If one of them is None, return the other
                if not base:
                    return omni
                if not omni:
                    return base

                # Merge by creating a new object that takes attributes from both
                merged_music = base  # Start with the base music object
                # Override attributes from omni if they exist
                for attr in vars(omni):
                    if getattr(omni, attr) is not None:
                        setattr(merged_music, attr, getattr(omni, attr))
                return merged_music

            # Merge music_base and music_omni
            music = merge_music_objects(music_base, music_omni)

            # Loop through the chart indices
            for index in chart_indices[chart_key]:
                # Get score for both base version and OMNIMIX
                score_base = self.data.local.music.get_score(game, version, userid, songid, index)
                score_omni = self.data.local.music.get_score(game, version + DBConstants.OMNIMIX_VERSION_BUMP, userid, songid, index)

                # Merge score data
                score = score_omni if score_omni else score_base
                
                # Append score points and percentage
                if score:
                    skill_index.append(score.points)
                    skill_prec_index.append(score.data.get_int("perc"))
                else:
                    skill_index.append(0)
                    skill_prec_index.append(-1)

            # Find the maximum values
            max_skill_index = max(skill_index)
            max_prec_index = max(skill_prec_index)

            # Get the index of the maximum skill point and percentage
            skill_index_info = [skill_index.index(max_skill_index), max_skill_index]
            skill_prec_info = [skill_prec_index.index(max_prec_index), max_prec_index]

            # Determine the chart for gf
            if chart_key == "gf":
                if 0 <= skill_index_info[0] <= 3:
                    chart = skill_index_info[0] + 1
                elif 3 < skill_index_info[0] <= 7:
                    chart = skill_index_info[0] + 7
            else:
                chart = skill_index_info[0] + 6
                
            music_difficuities = self.data.local.music.get_song(game, version, songid, chart).data.get_int("difficulty")

            # Append the skill data to the list
            skills.append({
                "music_name": music.name if music else "Unknown",  # Access attribute with dot notation
                "music_difficulties": music_difficuities,
                "music_id": songid,
                "chart": GitadoraFrontend.gitadora_chart.get(chart),
                "skills_point": skill_index_info[1],
                "perc": skill_prec_info[1],
            })
        
        return skills

    def format_profile(
        self, profile: Profile, playstats: ValidatedDict
    ) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile["plays"] = playstats.get_int("total_plays")
        formatted_profile["title"] = profile.get_str("title")
        # music clear details. skill, all_skills, classic skills, clear num, full combo num, exec num, highest clear lv, highest fc lv,highest exec lv,
        formatted_profile["gf_skills"] = profile.get_dict("skilldata").get_int(
            "gf_skill"
        )
        formatted_profile["dm_skills"] = profile.get_dict("skilldata").get_int(
            "dm_skill"
        )
        formatted_profile["gf_all_skills"] = profile.get_dict("skilldata").get_int(
            "gf_all_skill"
        )
        formatted_profile["dm_all_skills"] = profile.get_dict("skilldata").get_int(
            "dm_all_skill"
        )
        formatted_profile["gf_classic_all_skills"] = profile.get_dict(
            "gf_record"
        ).get_int("classic_all_skill")
        formatted_profile["dm_classic_all_skills"] = profile.get_dict(
            "dm_record"
        ).get_int("classic_all_skill")
        formatted_profile["gf_clear_music_num"] = profile.get_dict("gf_record").get_int(
            "clear_music_num"
        )
        formatted_profile["gf_full_music_num"] = profile.get_dict("gf_record").get_int(
            "full_music_num"
        )
        formatted_profile["gf_exce_music_num"] = profile.get_dict("gf_record").get_int(
            "exce_music_num"
        )
        formatted_profile["gf_clear_diff"] = profile.get_dict("gf_record").get_int(
            "clear_diff"
        )
        formatted_profile["gf_full_diff"] = profile.get_dict("gf_record").get_int(
            "full_diff"
        )
        formatted_profile["gf_exce_diff"] = profile.get_dict("gf_record").get_int(
            "exce_diff"
        )
        formatted_profile["dm_clear_music_num"] = profile.get_dict("dm_record").get_int(
            "clear_music_num"
        )
        formatted_profile["dm_full_music_num"] = profile.get_dict("dm_record").get_int(
            "full_music_num"
        )
        formatted_profile["dm_exce_music_num"] = profile.get_dict("dm_record").get_int(
            "exce_music_num"
        )
        formatted_profile["dm_clear_diff"] = profile.get_dict("dm_record").get_int(
            "clear_diff"
        )
        formatted_profile["dm_full_diff"] = profile.get_dict("dm_record").get_int(
            "full_diff"
        )
        formatted_profile["dm_exce_diff"] = profile.get_dict("dm_record").get_int(
            "exce_diff"
        )
        # skilldata. because gitadora has id=0 songs thus make sure that default array all in [-1] * 25.
        formatted_profile["dm_exist"] = profile.get_dict("skilldata").get_int_array(
            "dm_exist", 25, [-1] * 25
        )
        formatted_profile["dm_new"] = profile.get_dict("skilldata").get_int_array(
            "dm_new", 25, [-1] * 25
        )
        formatted_profile["gf_exist"] = profile.get_dict("skilldata").get_int_array(
            "gf_exist", 25, [-1] * 25
        )
        formatted_profile["gf_new"] = profile.get_dict("skilldata").get_int_array(
            "gf_new", 25, [-1] * 25
        )
        return formatted_profile

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["type"] = score.data.get_str("score_type")
        formatted_score["skill"] = score.points
        formatted_score["perc"] = score.data.get_int("perc")
        formatted_score["miss"] = score.data.get_int("miss")
        formatted_score["combo"] = score.data.get_int("combo")
        formatted_score["status"] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(score.data.get_int("grade"), "NO PLAY")
        formatted_score["stats"] = score.data.get_dict("stats")
        return formatted_score

    def format_top_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score["type"] = score.data.get_str("score_type")
        formatted_score["skill"] = score.points
        formatted_score["perc"] = score.data.get_int("perc")
        formatted_score["miss"] = score.data.get_int("miss")
        formatted_score["combo"] = score.data.get_int("combo")
        formatted_score["status"] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(score.data.get_int("grade"), "NO PLAY")
        formatted_score["stats"] = score.data.get_dict("stats")
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt["type"] = attempt.data.get_str("score_type")
        formatted_attempt["skill"] = attempt.points
        formatted_attempt["perc"] = attempt.data.get_int("perc")
        formatted_attempt["miss"] = attempt.data.get_int("miss")
        formatted_attempt["combo"] = attempt.data.get_int("combo")
        formatted_attempt["status"] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(attempt.data.get_int("grade"), "NO PLAY")
        formatted_attempt["stats"] = attempt.data.get_dict("stats")
        return formatted_attempt

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int("difficulty")
        for change_item in range(6, 10):
            difficulties[change_item], difficulties[change_item + 5] = (
                difficulties[change_item + 5],
                difficulties[change_item],
            )

        formatted_song = super().format_song(song)
        formatted_song["bpm2"] = song.data.get_int("bpm2", 120)
        formatted_song["bpm"] = song.data.get_int("bpm", 120)
        formatted_song["difficulties"] = difficulties
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing["difficulties"][new.chart] == 0:
            new_song["difficulties"][new.chart] = new.data.get_int("difficulty")
        return new_song
