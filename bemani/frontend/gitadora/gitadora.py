# vim: set fileencoding=utf-8
from typing import Any, Dict, Iterator, List, Tuple

from flask_caching import Cache

from bemani.backend.gitadora import GitadoraFactory, GitadoraBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants
from bemani.data import Attempt, Data, Config, Score, Song, UserID
from bemani.frontend.base import FrontendBase


class GitadoraFrontend(FrontendBase):

    game: GameConstants = GameConstants.GITADORA

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
        'gf_rival',
        'dm_rival',
    ]

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        super().__init__(data, config, cache)

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from GitadoraFactory.all_games()

    def get_all_items(self, versions: list) -> Dict[str, List[Dict[str, Any]]]:
        result = {}
        for version in versions:
            trbitem = self.__format_gitadora_extras(version)
            result[version] = trbitem['trbitem']
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
            'trbitem': trbitem,
        }

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        formatted_profile = super().format_profile(profile, playstats)
        formatted_profile['plays'] = playstats.get_int('total_plays')
        formatted_profile['gf_skills'] = profile.get_dict('skilldata').get_int('gf_skill')
        formatted_profile['dm_skills'] = profile.get_dict('skilldata').get_int('dm_skill')
        formatted_profile['title'] = profile.get_str('title')
        return formatted_profile    

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['type'] = score.data.get_str('score_type')
        formatted_score['skill'] = score.points
        formatted_score['perc'] = score.data.get_int('perc')
        formatted_score['miss'] = score.data.get_int('miss')
        formatted_score['combo'] = score.data.get_int('combo')
        formatted_score['status'] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(score.data.get_int('grade'), 'NO PLAY')
        formatted_score['stats'] = score.data.get_dict('stats')
        return formatted_score
    
    def format_top_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        formatted_score = super().format_score(userid, score)
        formatted_score['type'] = score.data.get_str('score_type')
        formatted_score['skill'] = score.points
        formatted_score['perc'] = score.data.get_int('perc')
        formatted_score['miss'] = score.data.get_int('miss')
        formatted_score['combo'] = score.data.get_int('combo')
        formatted_score['status'] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(score.data.get_int('grade'), 'NO PLAY')
        formatted_score['stats'] = score.data.get_dict('stats')
        return formatted_score

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        formatted_attempt = super().format_attempt(userid, attempt)
        formatted_attempt['type'] = attempt.data.get_str('score_type')
        formatted_attempt['skill'] = attempt.points
        formatted_attempt['perc'] = attempt.data.get_int('perc')
        formatted_attempt['miss'] = attempt.data.get_int('miss')
        formatted_attempt['combo'] = attempt.data.get_int('combo')
        formatted_attempt['status'] = {
            GitadoraBase.GITADORA_GRADE_C: "C",
            GitadoraBase.GITADORA_GRADE_B: "B",
            GitadoraBase.GITADORA_GRADE_A: "A",
            GitadoraBase.GITADORA_GRADE_S: "S",
            GitadoraBase.GITADORA_GRADE_SS: "SS",
        }.get(attempt.data.get_int('grade'), 'NO PLAY')
        formatted_attempt['stats'] = attempt.data.get_dict('stats')
        return formatted_attempt

    def format_song(self, song: Song) -> Dict[str, Any]:
        difficulties = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        difficulties[song.chart] = song.data.get_int('difficulty')
        for change_item in range(6,10):
            difficulties[change_item], difficulties[change_item+5] = difficulties[change_item+5], difficulties[change_item]

        formatted_song = super().format_song(song)
        formatted_song['bpm2'] = song.data.get_int('bpm2', 120)
        formatted_song['bpm'] = song.data.get_int('bpm', 120)
        formatted_song['difficulties'] = difficulties
        return formatted_song

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        new_song = super().merge_song(existing, new)
        if existing['difficulties'][new.chart] == 0:
            new_song['difficulties'][new.chart] = new.data.get_int('difficulty')
        return new_song
