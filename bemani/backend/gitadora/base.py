# vim: set fileencoding=utf-8
from typing import Optional, Dict, List, Any
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import (
    Profile,
    ValidatedDict,
    Model,
    GameConstants,
    DBConstants,
    Parallel,
)
from bemani.data import Config, Data, Score, UserID
from bemani.protocol import Node


class GitadoraBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Gitadora versions. Handles common functionality for
    getting profiles based on refid, creating new profiles, looking up and saving
    scores.
    """

    game = GameConstants.GITADORA

    CHART_TYPE_GF: Final[int] = 1
    CHART_TYPE_DM: Final[int] = 2
    # Bass is the same score as GF thus do been divide it.

    # gitadora clear types. ["NO PLAY","FAILED","CLEAR","FULL COMBO EXCELLENT"]
    GITADORA_NO_PLAY: Final[int] = DBConstants.GITADORA_CLEAR_TYPE_NO_PLAY
    GITADORA_FAILED: Final[int] = DBConstants.GITADORA_CLEAR_TYPE_FAILED
    GITADORA_CLEAR: Final[int] = DBConstants.GITADORA_CLEAR_TYPE_CLEAR
    GITADORA_FULL_COMBO: Final[int] = DBConstants.GITADORA_CLEAR_TYPE_FULL_COMBO
    GITADORA_EXCELLENT: Final[int] = DBConstants.GITADORA_CLEAR_TYPE_EXCELLENT

    # gitadora grade type["C","B","A","S","SS","EXCELLENT"]
    GITADORA_GRADE_E: Final[int] = DBConstants.GITADORA_GRADE_E
    GITADORA_GRADE_D: Final[int] = DBConstants.GITADORA_GRADE_D
    GITADORA_GRADE_C: Final[int] = DBConstants.GITADORA_GRADE_C
    GITADORA_GRADE_B: Final[int] = DBConstants.GITADORA_GRADE_B
    GITADORA_GRADE_A: Final[int] = DBConstants.GITADORA_GRADE_A
    GITADORA_GRADE_S: Final[int] = DBConstants.GITADORA_GRADE_S
    GITADORA_GRADE_SS: Final[int] = DBConstants.GITADORA_GRADE_SS
    GITADORA_GRADE_EXCELLENT: Final[int] = DBConstants.GITADORA_GRADE_EXCELLENT

    # gitadora chart types. ["BASIC","ADVANCE","EXTREME","MASTER"]
    GITUAR_CHART_TYPE_BASIC: Final[int] = 1
    GITUAR_CHART_TYPE_ADVANCE: Final[int] = 2
    GITUAR_CHART_TYPE_EXTREME: Final[int] = 3
    GITUAR_CHART_TYPE_MASTER: Final[int] = 4
    DRUM_CHART_TYPE_BASIC: Final[int] = 6
    DRUM_CHART_TYPE_ADVANCE: Final[int] = 7
    DRUM_CHART_TYPE_EXTREME: Final[int] = 8
    DRUM_CHART_TYPE_MASTER: Final[int] = 9
    BASS_CHART_TYPE_BASIC: Final[int] = 11
    BASS_CHART_TYPE_ADVANCE: Final[int] = 12
    BASS_CHART_TYPE_EXTREME: Final[int] = 13
    BASS_CHART_TYPE_MASTER: Final[int] = 14

    def __init__(self, data: Data, config: Config, model: Model) -> None:
        # only divide omnimix in here.
        # model.spec == 'A': gf;
        # model.spec == 'B': dm.
        # and the only difference is the saving score and the record.
        super().__init__(data, config, model)
        if model.rev == "X":
            self.omnimix = True
        else:
            self.omnimix = False

    @property
    def music_version(self) -> int:
        if self.omnimix:
            return DBConstants.OMNIMIX_VERSION_BUMP + self.version
        return self.version

    def previous_version(self) -> Optional["GitadoraBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        """
        Base handler for a profile. Given a userid and a profile dictionary,
        return a Node representing a profile. Should be overridden.
        """
        return Node.void("gametop")

    def format_scores(
        self, userid: UserID, profile: Profile, scores: List[Score]
    ) -> Node:
        """
        Base handler for a score list. Given a userid, profile and a score list,
        return a Node representing a score list. Should be overridden.
        """
        return Node.void("gametop")

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        """
        Base handler for profile parsing. Given a request and an old profile,
        return a new profile that's been updated with the contents of the request.
        Should be overridden.
        """
        return oldprofile

    def get_profile_by_refid(self, refid: Optional[str]) -> Optional[Node]:
        """
        Given a RefID, return a formatted profile node. Basically every game
        needs a profile lookup, even if it handles where that happens in
        a different request. This is provided for code deduplication.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            # User doesn't exist but should at this point
            return None

        # Trying to import from current version
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_profile(userid, profile)

    def new_profile_by_refid(
        self, refid: Optional[str], name: Optional[str]
    ) -> Profile:
        """
        Given a RefID and an optional name, create a profile and then return
        that newly created profile.
        """
        if refid is None:
            return None

        if name is None:
            name = "NONAME"

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        defaultprofile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
            },
        )
        self.put_profile(userid, defaultprofile)
        profile = self.get_profile(userid)
        return profile

    def get_scores_by_refid(self, refid: Optional[str]) -> Optional[Node]:
        """
        Given an RefID, return a formatted score node. Similar rationale to
        get_profile_by_refid.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        if scores is None:
            return None
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_scores(userid, profile, scores)

    def get_clear_rates(self) -> Dict[int, Dict[int, Dict[str, int]]]:
        """
        Returns a dictionary similar to the following:

        {
            musicid: {
                chart: {
                    total: total plays,
                    clears: total clears,
                    average: average score,
                },
            },
        }
        """
        all_attempts, remote_attempts = Parallel.execute(
            [
                lambda: self.data.local.music.get_music_crate(
                    game=self.game,
                    version=self.music_version,
                ),
                lambda: self.data.remote.music.get_clear_rates(
                    game=self.game,
                    version=self.music_version,
                ),
            ]
        )
        attempts: Dict[int, Dict[int, Dict[str, int]]] = {}
        for (_, attempt) in all_attempts:
            # Terrible temporary structure is terrible.
            if attempt.id not in attempts:
                attempts[attempt.id] = {}
            if attempt.chart not in attempts[attempt.id]:
                attempts[attempt.id][attempt.chart] = {
                    "total": 0,
                    "clears": 0,
                    "average": 0,
                }

            # We saw an attempt, keep the total attempts in sync.
            attempts[attempt.id][attempt.chart]["average"] = int(
                (
                    (
                        attempts[attempt.id][attempt.chart]["average"]
                        * attempts[attempt.id][attempt.chart]["total"]
                    )
                    + attempt.points
                )
                / (attempts[attempt.id][attempt.chart]["total"] + 1)
            )
            attempts[attempt.id][attempt.chart]["total"] += 1

            if attempt.data.get_int("clear_type", self.GITADORA_NO_PLAY) in [
                self.GITADORA_NO_PLAY,
                self.GITADORA_FAILED,
            ]:
                # This attempt was a failure, so don't count it against clears of full combos
                continue

            # It was at least a clear
            attempts[attempt.id][attempt.chart]["clears"] += 1

        # Merge in remote attempts
        for songid in remote_attempts:
            if songid not in attempts:
                attempts[songid] = {}

            for songchart in remote_attempts[songid]:
                if songchart not in attempts[songid]:
                    attempts[songid][songchart] = {
                        "total": 0,
                        "clears": 0,
                        "average": 0,
                    }

                attempts[songid][songchart]["total"] += remote_attempts[songid][
                    songchart
                ]["plays"]
                attempts[songid][songchart]["clears"] += remote_attempts[songid][
                    songchart
                ]["clears"]

        return attempts

    # i think gitadora score struct it similiar to the sdvx score struct type.
    # {"score_type": "dm", "miss": 0, "perc": 9139, "skill": 8225, "new_skill": 8225, "fullcombo": true, "clear": true, "excellent": false, "meter": 18446744073709551615, "meter_prog": 64, "grade": 600, "combo": 354, "stats": {"score": 932330, "flags": 134217728, "perfect": 298, "perfect_perc": 84, "great": 49, "great_perc": 14, "good": 7, "good_perc": 2, "ok": 0, "ok_perc": 0, "miss": 0, "miss_perc": 0, "phrase_data_num": 7, "phrase_addr": [0, 3272, 8509, 13745, 18327, 23563, 26836, 30791, 0, 0, 0, 0, 0, 0, 0, 0, 0], "phrase_type": [1, 9, 2, 3, 10, 4, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "phrase_status": [2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "phrase_end_addr": 30791}}
    def update_score(
        self,
        userid: Optional[UserID],
        timestamp: int,
        score_type: str,
        songid: int,
        chart: int,
        points: int,
        grade: int,
        combo: int,
        miss: int,
        perc: int,
        new_skill: int,
        fullcombo: bool,
        clear: bool,
        excellent: bool,
        meter: int,
        meter_prog: int,
        stats: Optional[Dict[str, int]] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in SDVX series can expect
        the same attributes in a score.
        """
        if grade not in [
            self.GITADORA_GRADE_E,
            self.GITADORA_GRADE_D,
            self.GITADORA_GRADE_C,
            self.GITADORA_GRADE_B,
            self.GITADORA_GRADE_A,
            self.GITADORA_GRADE_S,
            self.GITADORA_GRADE_SS,
            self.GITADORA_GRADE_EXCELLENT,
        ]:
            raise Exception(f"Invalid rank value {grade}")

        if userid is not None:
            oldscore = self.data.local.music.get_score(
                self.game,
                self.music_version,
                userid,
                songid,
                chart,
            )
        else:
            oldscore = None

        # Score history is verbatum, instead of highest score
        history = ValidatedDict(
            {
                "score_type": score_type,
                "miss": miss,
                "perc": perc,
                "new_skill": new_skill,
                "fullcombo": fullcombo,
                "clear": clear,
                "excellent": excellent,
                "meter": meter,
                "meter_prog": meter_prog,
            }
        )
        oldpoints = points

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict(
                {
                    "score_type": score_type,
                    "miss": miss,
                    "perc": perc,
                    "skill": points,
                    "new_skill": new_skill,
                    "fullcombo": fullcombo,
                    "clear": clear,
                    "excellent": excellent,
                    "meter": meter,
                    "meter_prog": meter_prog,
                }
            )
            raised = True
            highscore = True
        else:
            # Set the score to any new record achieved
            raised = points > oldscore.points
            highscore = points >= oldscore.points
            points = max(oldscore.points, points)
            scoredata = oldscore.data

        # Replace clear type and grade
        scoredata.replace_int("grade", max(scoredata.get_int("grade"), grade))
        history.replace_int("grade", grade)
        scoredata.replace_int("miss", min(scoredata.get_int("miss"), miss))
        history.replace_int("miss", miss)
        scoredata.replace_int("perc", max(scoredata.get_int("perc"), perc))
        history.replace_int("perc", perc)
        scoredata.replace_bool(
            "fullcombo", max(scoredata.get_bool("fullcombo"), fullcombo)
        )
        history.replace_bool("fullcombo", fullcombo)
        scoredata.replace_bool("clear", max(scoredata.get_bool("clear"), clear))
        history.replace_bool("clear", clear)
        scoredata.replace_bool(
            "excellent", max(scoredata.get_bool("excellent"), excellent)
        )
        history.replace_bool("excellent", excellent)

        # If we have a combo, replace it
        scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))
        history.replace_int("combo", combo)

        # If we have play stats, replace it
        if stats is not None:
            if raised:
                # We have stats, and there's a new high score, update the stats
                scoredata.replace_int("skill", points)
                scoredata.replace_int("new_skill", new_skill)
                scoredata.replace_int("meter", meter)
                scoredata.replace_int("meter_prog", meter_prog)
                scoredata.replace_dict("stats", stats)
            history.replace_dict("stats", stats)

        # Look up where this score was earned
        lid = self.get_machine_id()

        if userid is not None:
            # Write the new score back
            self.data.local.music.put_score(
                self.game,
                self.music_version,
                userid,
                songid,
                chart,
                lid,
                points,
                scoredata,
                highscore,
                timestamp=timestamp,
            )

        # Save the history of this score too
        self.data.local.music.put_attempt(
            self.game,
            self.music_version,
            userid,
            songid,
            chart,
            lid,
            oldpoints,
            history,
            raised,
            timestamp=timestamp,
        )
