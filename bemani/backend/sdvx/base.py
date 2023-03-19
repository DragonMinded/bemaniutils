# vim: set fileencoding=utf-8
from typing import Dict, Optional
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import Profile, ValidatedDict, GameConstants, DBConstants, Parallel
from bemani.data import UserID
from bemani.protocol import Node


class SoundVoltexBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Sound Voltex version that we support.
    """

    game: GameConstants = GameConstants.SDVX

    CLEAR_TYPE_NO_PLAY: Final[int] = DBConstants.SDVX_CLEAR_TYPE_NO_PLAY
    CLEAR_TYPE_FAILED: Final[int] = DBConstants.SDVX_CLEAR_TYPE_FAILED
    CLEAR_TYPE_CLEAR: Final[int] = DBConstants.SDVX_CLEAR_TYPE_CLEAR
    CLEAR_TYPE_HARD_CLEAR: Final[int] = DBConstants.SDVX_CLEAR_TYPE_HARD_CLEAR
    CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = DBConstants.SDVX_CLEAR_TYPE_ULTIMATE_CHAIN
    CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[
        int
    ] = DBConstants.SDVX_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN

    GRADE_NO_PLAY: Final[int] = DBConstants.SDVX_GRADE_NO_PLAY
    GRADE_D: Final[int] = DBConstants.SDVX_GRADE_D
    GRADE_C: Final[int] = DBConstants.SDVX_GRADE_C
    GRADE_B: Final[int] = DBConstants.SDVX_GRADE_B
    GRADE_A: Final[int] = DBConstants.SDVX_GRADE_A
    GRADE_A_PLUS: Final[int] = DBConstants.SDVX_GRADE_A_PLUS
    GRADE_AA: Final[int] = DBConstants.SDVX_GRADE_AA
    GRADE_AA_PLUS: Final[int] = DBConstants.SDVX_GRADE_AA_PLUS
    GRADE_AAA: Final[int] = DBConstants.SDVX_GRADE_AAA
    GRADE_AAA_PLUS: Final[int] = DBConstants.SDVX_GRADE_AAA_PLUS
    GRADE_S: Final[int] = DBConstants.SDVX_GRADE_S

    CHART_TYPE_NOVICE: Final[int] = 0
    CHART_TYPE_ADVANCED: Final[int] = 1
    CHART_TYPE_EXHAUST: Final[int] = 2
    CHART_TYPE_INFINITE: Final[int] = 3
    CHART_TYPE_MAXIMUM: Final[int] = 4

    def previous_version(self) -> Optional["SoundVoltexBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def get_profile_by_refid(self, refid: Optional[str]) -> Optional[Node]:
        """
        Given a RefID, return a formatted profile node. Basically every game
        needs a profile lookup, even if it handles where that happens in
        a different request. This is provided for code deduplication.
        """
        if refid is None:
            return None

        # First try to load the actual profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        if profile is None:
            return None

        # Now, return it
        return self.format_profile(userid, profile)

    def new_profile_by_refid(
        self, refid: Optional[str], name: Optional[str], locid: Optional[int]
    ) -> Node:
        """
        Given a RefID and an optional name, create a profile and then return
        a formatted profile node. Similar rationale to get_profile_by_refid.
        """
        if refid is None:
            return None

        if name is None:
            name = "NONAME"

        # First, create and save the default profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
                "loc": locid,
            },
        )
        self.put_profile(userid, profile)
        return self.format_profile(userid, profile)

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        """
        Base handler for a profile. Given a userid and a profile dictionary,
        return a Node representing a profile. Should be overridden.
        """
        return Node.void("game")

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        """
        Base handler for profile parsing. Given a request and an old profile,
        return a new profile that's been updated with the contents of the request.
        Should be overridden.
        """
        return oldprofile

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
                lambda: self.data.local.music.get_all_attempts(
                    game=self.game,
                    version=self.version,
                ),
                lambda: self.data.remote.music.get_clear_rates(
                    game=self.game,
                    version=self.version,
                ),
            ]
        )
        attempts: Dict[int, Dict[int, Dict[str, int]]] = {}
        for _, attempt in all_attempts:
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

            if attempt.data.get_int("clear_type", self.CLEAR_TYPE_NO_PLAY) in [
                self.CLEAR_TYPE_NO_PLAY,
                self.CLEAR_TYPE_FAILED,
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

    def update_score(
        self,
        userid: Optional[UserID],
        songid: int,
        chart: int,
        points: int,
        clear_type: int,
        grade: int,
        combo: int,
        stats: Optional[Dict[str, int]] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in SDVX series can expect
        the same attributes in a score.
        """
        # Range check clear type
        if clear_type not in [
            self.CLEAR_TYPE_NO_PLAY,
            self.CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEAR,
            self.CLEAR_TYPE_HARD_CLEAR,
            self.CLEAR_TYPE_ULTIMATE_CHAIN,
            self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        ]:
            raise Exception(f"Invalid clear type value {clear_type}")

        #  Range check grade
        if grade not in [
            self.GRADE_NO_PLAY,
            self.GRADE_D,
            self.GRADE_C,
            self.GRADE_B,
            self.GRADE_A,
            self.GRADE_A_PLUS,
            self.GRADE_AA,
            self.GRADE_AA_PLUS,
            self.GRADE_AAA,
            self.GRADE_AAA_PLUS,
            self.GRADE_S,
        ]:
            raise Exception(f"Invalid clear type value {grade}")

        if userid is not None:
            oldscore = self.data.local.music.get_score(
                self.game,
                self.version,
                userid,
                songid,
                chart,
            )
        else:
            oldscore = None

        # Score history is verbatum, instead of highest score
        history = ValidatedDict({})
        oldpoints = points

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict({})
            raised = True
            highscore = True
        else:
            # Set the score to any new record achieved
            raised = points > oldscore.points
            highscore = points >= oldscore.points
            points = max(oldscore.points, points)
            scoredata = oldscore.data

        # Replace clear type and grade
        scoredata.replace_int(
            "clear_type", max(scoredata.get_int("clear_type"), clear_type)
        )
        history.replace_int("clear_type", clear_type)
        scoredata.replace_int("grade", max(scoredata.get_int("grade"), grade))
        history.replace_int("grade", grade)

        # If we have a combo, replace it
        scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))
        history.replace_int("combo", combo)

        # If we have play stats, replace it
        if stats is not None:
            if raised:
                # We have stats, and there's a new high score, update the stats
                scoredata.replace_dict("stats", stats)
            history.replace_dict("stats", stats)

        # Look up where this score was earned
        lid = self.get_machine_id()

        if userid is not None:
            # Write the new score back
            self.data.local.music.put_score(
                self.game,
                self.version,
                userid,
                songid,
                chart,
                lid,
                points,
                scoredata,
                highscore,
            )

        # Save the history of this score too
        self.data.local.music.put_attempt(
            self.game,
            self.version,
            userid,
            songid,
            chart,
            lid,
            oldpoints,
            history,
            raised,
        )
