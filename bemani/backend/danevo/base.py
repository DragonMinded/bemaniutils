# vim: set fileencoding=utf-8
from typing import Optional
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import DBConstants, GameConstants, ValidatedDict
from bemani.data import UserID


class DanceEvolutionBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Dance Evolution version that we support.
    """

    game: GameConstants = GameConstants.DANCE_EVOLUTION

    CHART_TYPE_LIGHT: Final[int] = 0
    CHART_TYPE_STANDARD: Final[int] = 1
    CHART_TYPE_EXTREME: Final[int] = 2
    CHART_TYPE_STEALTH: Final[int] = 3
    CHART_TYPE_MASTER: Final[int] = 4
    CHART_TYPE_PLAYTRACKING: Final[int] = 5

    GRADE_FAILED: Final[int] = DBConstants.DANEVO_GRADE_FAILED
    GRADE_E: Final[int] = DBConstants.DANEVO_GRADE_E
    GRADE_D: Final[int] = DBConstants.DANEVO_GRADE_D
    GRADE_C: Final[int] = DBConstants.DANEVO_GRADE_C
    GRADE_B: Final[int] = DBConstants.DANEVO_GRADE_B
    GRADE_A: Final[int] = DBConstants.DANEVO_GRADE_A
    GRADE_AA: Final[int] = DBConstants.DANEVO_GRADE_AA
    GRADE_AAA: Final[int] = DBConstants.DANEVO_GRADE_AAA

    def previous_version(self) -> Optional["DanceEvolutionBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def update_score(
        self,
        userid: UserID,
        songid: int,
        chart: int,
        points: int,
        grade: int,
        combo: int,
        full_combo: bool,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score.
        """
        if chart not in {
            self.CHART_TYPE_LIGHT,
            self.CHART_TYPE_STANDARD,
            self.CHART_TYPE_EXTREME,
            self.CHART_TYPE_STEALTH,
            self.CHART_TYPE_MASTER,
        }:
            raise Exception(f"Invalid chart {chart}")
        if grade not in {
            self.GRADE_FAILED,
            self.GRADE_E,
            self.GRADE_D,
            self.GRADE_C,
            self.GRADE_B,
            self.GRADE_A,
            self.GRADE_AA,
            self.GRADE_AAA,
        }:
            raise Exception(f"Invalid grade {grade}")

        oldscore = self.data.local.music.get_score(
            self.game,
            self.version,
            userid,
            songid,
            chart,
        )

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict({})
            highscore = True
        else:
            # Set the score to any new record achieved
            highscore = points >= oldscore.points
            points = max(oldscore.points, points)
            scoredata = oldscore.data

        # Save combo
        scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))

        # Save grade
        scoredata.replace_int("grade", max(scoredata.get_int("grade"), grade))

        # Save full combo indicator.
        scoredata.replace_bool("full_combo", scoredata.get_bool("full_combo") or full_combo)

        # Look up where this score was earned
        lid = self.get_machine_id()

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
