# vim: set fileencoding=utf-8
from typing import Optional, List
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import (
    Model,
    Profile,
    ValidatedDict,
    GameConstants,
    DBConstants,
    Time,
)
from bemani.data import Config, Data, Score, UserID, ScoreSaveException
from bemani.protocol import Node


class DDRBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all DDR versions. Handles common functionality for getting
    profiles based on refid, creating new profiles, looking up and saving scores.
    """

    game: GameConstants = GameConstants.DDR

    HALO_NONE: Final[int] = DBConstants.DDR_HALO_NONE
    HALO_GOOD_FULL_COMBO: Final[int] = DBConstants.DDR_HALO_GOOD_FULL_COMBO
    HALO_GREAT_FULL_COMBO: Final[int] = DBConstants.DDR_HALO_GREAT_FULL_COMBO
    HALO_PERFECT_FULL_COMBO: Final[int] = DBConstants.DDR_HALO_PERFECT_FULL_COMBO
    HALO_MARVELOUS_FULL_COMBO: Final[int] = DBConstants.DDR_HALO_MARVELOUS_FULL_COMBO

    RANK_E: Final[int] = DBConstants.DDR_RANK_E
    RANK_D: Final[int] = DBConstants.DDR_RANK_D
    RANK_D_PLUS: Final[int] = DBConstants.DDR_RANK_D_PLUS
    RANK_C_MINUS: Final[int] = DBConstants.DDR_RANK_C_MINUS
    RANK_C: Final[int] = DBConstants.DDR_RANK_C
    RANK_C_PLUS: Final[int] = DBConstants.DDR_RANK_C_PLUS
    RANK_B_MINUS: Final[int] = DBConstants.DDR_RANK_B_MINUS
    RANK_B: Final[int] = DBConstants.DDR_RANK_B
    RANK_B_PLUS: Final[int] = DBConstants.DDR_RANK_B_PLUS
    RANK_A_MINUS: Final[int] = DBConstants.DDR_RANK_A_MINUS
    RANK_A: Final[int] = DBConstants.DDR_RANK_A
    RANK_A_PLUS: Final[int] = DBConstants.DDR_RANK_A_PLUS
    RANK_AA_MINUS: Final[int] = DBConstants.DDR_RANK_AA_MINUS
    RANK_AA: Final[int] = DBConstants.DDR_RANK_AA
    RANK_AA_PLUS: Final[int] = DBConstants.DDR_RANK_AA_PLUS
    RANK_AAA: Final[int] = DBConstants.DDR_RANK_AAA

    # These constants must agree with read.py for importing charts from the game.
    CHART_SINGLE_BEGINNER: Final[int] = 0
    CHART_SINGLE_BASIC: Final[int] = 1
    CHART_SINGLE_DIFFICULT: Final[int] = 2
    CHART_SINGLE_EXPERT: Final[int] = 3
    CHART_SINGLE_CHALLENGE: Final[int] = 4
    CHART_DOUBLE_BEGINNER: Final[int] = 5
    CHART_DOUBLE_BASIC: Final[int] = 6
    CHART_DOUBLE_DIFFICULT: Final[int] = 7
    CHART_DOUBLE_EXPERT: Final[int] = 8
    CHART_DOUBLE_CHALLENGE: Final[int] = 9

    # Return the local2 service so that DDR Ace will send certain packets.
    extra_services: List[str] = [
        "local2",
    ]

    def __init__(self, data: Data, config: Config, model: Model) -> None:
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

    def game_to_db_rank(self, game_rank: int) -> int:
        """
        Given a game's rank constant, return the rank as defined above.
        """
        raise Exception("Implement in sub-class!")

    def db_to_game_rank(self, db_rank: int) -> int:
        """
        Given a rank as defined above, return the game's rank constant.
        """
        raise Exception("Implement in sub-class!")

    def game_to_db_chart(self, game_chart: int) -> int:
        """
        Given a game's chart for a song, return the chart as defined above.
        """
        raise Exception("Implement in sub-class!")

    def db_to_game_chart(self, db_chart: int) -> int:
        """
        Given a chart as defined above, return the game's chart constant.
        """
        raise Exception("Implement in sub-class!")

    def game_to_db_halo(self, game_halo: int) -> int:
        """
        Given a game's halo constant, return the halo as defined above.
        """
        raise Exception("Implement in sub-class!")

    def db_to_game_halo(self, db_halo: int) -> int:
        """
        Given a halo as defined above, return the game's halo constant.
        """
        raise Exception("Implement in sub-class!")

    def previous_version(self) -> Optional["DDRBase"]:
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
        return Node.void("game")

    def format_scores(self, userid: UserID, profile: Profile, scores: List[Score]) -> Node:
        """
        Base handler for a score list. Given a userid, profile and a score list,
        return a Node representing a score list. Should be overridden.
        """
        return Node.void("game")

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
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

        # First try to load the actual profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        if profile is None:
            return None

        # Now, return it
        return self.format_profile(userid, profile)

    def new_profile_by_refid(self, refid: Optional[str], name: Optional[str], area: Optional[int]) -> None:
        """
        Given a RefID and a name/area, create a new profile.
        """
        if refid is None:
            return
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return

        defaultprofile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
                "area": area,
            },
        )
        self.put_profile(userid, defaultprofile)

    def put_profile_by_refid(self, refid: Optional[str], request: Node) -> None:
        """
        Given a RefID and a request node, unformat the profile and save it.
        """
        if refid is None:
            return
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return

        oldprofile = self.get_profile(userid)
        newprofile = self.unformat_profile(userid, request, oldprofile)
        if newprofile is not None:
            self.put_profile(userid, newprofile)

    def update_score(
        self,
        userid: Optional[UserID],
        songid: int,
        chart: int,
        points: int,
        rank: int,
        halo: int,
        combo: int,
        trace: Optional[List[int]] = None,
        ghost: Optional[str] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in DDR series can expect
        the same attributes in a score.
        """
        if chart not in [
            self.CHART_SINGLE_BEGINNER,
            self.CHART_SINGLE_BASIC,
            self.CHART_SINGLE_DIFFICULT,
            self.CHART_SINGLE_EXPERT,
            self.CHART_SINGLE_CHALLENGE,
            self.CHART_DOUBLE_BEGINNER,
            self.CHART_DOUBLE_BASIC,
            self.CHART_DOUBLE_DIFFICULT,
            self.CHART_DOUBLE_EXPERT,
            self.CHART_DOUBLE_CHALLENGE,
        ]:
            raise Exception(f"Invalid chart {chart}")
        if halo not in [
            self.HALO_NONE,
            self.HALO_GOOD_FULL_COMBO,
            self.HALO_GREAT_FULL_COMBO,
            self.HALO_PERFECT_FULL_COMBO,
            self.HALO_MARVELOUS_FULL_COMBO,
        ]:
            raise Exception(f"Invalid halo {halo}")
        if rank not in [
            self.RANK_E,
            self.RANK_D,
            self.RANK_D_PLUS,
            self.RANK_C_MINUS,
            self.RANK_C,
            self.RANK_C_PLUS,
            self.RANK_B_MINUS,
            self.RANK_B,
            self.RANK_B_PLUS,
            self.RANK_A_MINUS,
            self.RANK_A,
            self.RANK_A_PLUS,
            self.RANK_AA_MINUS,
            self.RANK_AA,
            self.RANK_AA_PLUS,
            self.RANK_AAA,
        ]:
            raise Exception(f"Invalid rank {rank}")

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
        now = Time.now()
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

        # Save combo
        history.replace_int("combo", combo)
        scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))

        # Save halo
        history.replace_int("halo", halo)
        scoredata.replace_int("halo", max(scoredata.get_int("halo"), halo))

        # Save rank
        history.replace_int("rank", rank)
        scoredata.replace_int("rank", max(scoredata.get_int("rank"), rank))

        # Save ghost steps
        if trace is not None:
            history.replace_int_array("trace", len(trace), trace)
            if raised:
                scoredata.replace_int_array("trace", len(trace), trace)
        if ghost is not None:
            history.replace_str("ghost", ghost)
            if raised:
                scoredata.replace_str("ghost", ghost)

        # Look up where this score was earned
        lid = self.get_machine_id()

        # DDR sometimes happens to send all songs that were played by a player
        # at the end of the round. It sends timestamps for the songs, but as of
        # Colette they were identical for each song in the round. So, if a user
        # plays the same song/chart# more than once in a round, we will end up
        # failing to store the attempt since we don't allow two of the same
        # attempt at the same time for the same user and song/chart. So, bump
        # the timestamp by one second and retry well past the maximum number of
        # songs.
        for bump in range(10):
            timestamp = now + bump

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

            try:
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
            except ScoreSaveException:
                # Try again one second in the future
                continue

            # We saved successfully
            break
