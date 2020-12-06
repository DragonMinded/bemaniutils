# vim: set fileencoding=utf-8
from typing import Dict, Optional, Any

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import ValidatedDict, GameConstants, DBConstants, Parallel, Model
from bemani.data import UserID, Data
from bemani.protocol import Node


class MusecaBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Museca version that we support.
    """

    game = GameConstants.MUSECA

    CHART_TYPE_GREEN = 0
    CHART_TYPE_ORANGE = 1
    CHART_TYPE_RED = 2

    GRADE_DEATH = DBConstants.MUSECA_GRADE_DEATH
    GRADE_POOR = DBConstants.MUSECA_GRADE_POOR
    GRADE_MEDIOCRE = DBConstants.MUSECA_GRADE_MEDIOCRE
    GRADE_GOOD = DBConstants.MUSECA_GRADE_GOOD
    GRADE_GREAT = DBConstants.MUSECA_GRADE_GREAT
    GRADE_EXCELLENT = DBConstants.MUSECA_GRADE_EXCELLENT
    GRADE_SUPERB = DBConstants.MUSECA_GRADE_SUPERB
    GRADE_MASTERPIECE = DBConstants.MUSECA_GRADE_MASTERPIECE
    GRADE_PERFECT = DBConstants.MUSECA_GRADE_PERFECT

    CLEAR_TYPE_FAILED = DBConstants.MUSECA_CLEAR_TYPE_FAILED
    CLEAR_TYPE_CLEARED = DBConstants.MUSECA_CLEAR_TYPE_CLEARED
    CLEAR_TYPE_FULL_COMBO = DBConstants.MUSECA_CLEAR_TYPE_FULL_COMBO

    def __init__(self, data: Data, config: Dict[str, Any], model: Model) -> None:
        super().__init__(data, config, model)
        if model.rev == 'X':
            self.omnimix = True
        else:
            self.omnimix = False

    @property
    def music_version(self) -> int:
        if self.omnimix:
            return DBConstants.OMNIMIX_VERSION_BUMP + self.version
        return self.version

    def previous_version(self) -> Optional['MusecaBase']:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def game_to_db_clear_type(self, clear_type: int) -> int:
        # Given a game clear type, return the canonical database identifier.
        raise Exception('Implement in subclass!')

    def db_to_game_clear_type(self, clear_type: int) -> int:
        # Given a database clear type, return the game's identifier.
        raise Exception('Implement in subclass!')

    def game_to_db_grade(self, grade: int) -> int:
        # Given a game grade, return the canonical database identifier.
        raise Exception('Implement in subclass!')

    def db_to_game_grade(self, grade: int) -> int:
        # Given a database grade, return the game's identifier.
        raise Exception('Implement in subclass!')

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

    def new_profile_by_refid(self, refid: Optional[str], name: Optional[str], locid: Optional[int]) -> Node:
        """
        Given a RefID and an optional name, create a profile and then return
        a formatted profile node. Similar rationale to get_profile_by_refid.
        """
        if refid is None:
            return None

        if name is None:
            name = 'NONAME'

        # First, create and save the default profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        defaultprofile = ValidatedDict({
            'name': name,
            'loc': locid,
        })
        self.put_profile(userid, defaultprofile)

        # Now, reload and format the profile, looking up the has old version flag
        profile = self.get_profile(userid)
        return self.format_profile(userid, profile)

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        """
        Base handler for a profile. Given a userid and a profile dictionary,
        return a Node representing a profile. Should be overridden.
        """
        return Node.void('game')

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
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
                },
            },
        }
        """
        all_attempts, remote_attempts = Parallel.execute([
            lambda: self.data.local.music.get_all_attempts(
                game=self.game,
                version=self.music_version,
            ),
            lambda: self.data.remote.music.get_clear_rates(
                game=self.game,
                version=self.music_version,
            )
        ])
        attempts: Dict[int, Dict[int, Dict[str, int]]] = {}
        for (_, attempt) in all_attempts:
            # Terrible temporary structure is terrible.
            if attempt.id not in attempts:
                attempts[attempt.id] = {}
            if attempt.chart not in attempts[attempt.id]:
                attempts[attempt.id][attempt.chart] = {
                    'total': 0,
                    'clears': 0,
                }

            # We saw an attempt, keep the total attempts in sync.
            attempts[attempt.id][attempt.chart]['total'] = attempts[attempt.id][attempt.chart]['total'] + 1

            if attempt.data.get_int('clear_type', self.CLEAR_TYPE_FAILED) != self.CLEAR_TYPE_FAILED:
                # This attempt was a failure, so don't count it against clears of full combos
                continue

            # It was at least a clear
            attempts[attempt.id][attempt.chart]['clears'] = attempts[attempt.id][attempt.chart]['clears'] + 1

        # Merge in remote attempts
        for songid in remote_attempts:
            if songid not in attempts:
                attempts[songid] = {}

            for songchart in remote_attempts[songid]:
                if songchart not in attempts[songid]:
                    attempts[songid][songchart] = {
                        'total': 0,
                        'clears': 0,
                    }

                attempts[songid][songchart]['total'] += remote_attempts[songid][songchart]['plays']
                attempts[songid][songchart]['clears'] += remote_attempts[songid][songchart]['clears']

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
        stats: Optional[Dict[str, int]]=None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in SDVX series can expect
        the same attributes in a score.
        """
        # Range check clear type
        if clear_type not in [
            self.CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_FULL_COMBO,
        ]:
            raise Exception(f"Invalid clear type value {clear_type}")

        # Range check grade
        if grade not in [
            self.GRADE_DEATH,
            self.GRADE_POOR,
            self.GRADE_MEDIOCRE,
            self.GRADE_GOOD,
            self.GRADE_GREAT,
            self.GRADE_EXCELLENT,
            self.GRADE_SUPERB,
            self.GRADE_MASTERPIECE,
            self.GRADE_PERFECT,
        ]:
            raise Exception(f"Invalid grade value {grade}")

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

        # Replace grade and clear type
        scoredata.replace_int('clear_type', max(scoredata.get_int('clear_type'), clear_type))
        history.replace_int('clear_type', clear_type)
        scoredata.replace_int('grade', max(scoredata.get_int('grade'), grade))
        history.replace_int('grade', grade)

        # If we have a combo, replace it
        scoredata.replace_int('combo', max(scoredata.get_int('combo'), combo))
        history.replace_int('combo', combo)

        # If we have play stats, replace it
        if stats is not None:
            if raised:
                # We have stats, and there's a new high score, update the stats
                scoredata.replace_dict('stats', stats)
            history.replace_dict('stats', stats)

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
        )
