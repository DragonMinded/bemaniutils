# vim: set fileencoding=utf-8
from typing import Dict, List, Optional
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import Profile, ValidatedDict, GameConstants, DBConstants, Time
from bemani.data import Machine, ScoreSaveException, UserID
from bemani.protocol import Node


class ReflecBeatBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Reflec Beat version that we support.
    """

    game: GameConstants = GameConstants.REFLEC_BEAT

    # Chart types, as stored in the DB
    CHART_TYPE_BASIC: Final[int] = 0
    CHART_TYPE_MEDIUM: Final[int] = 1
    CHART_TYPE_HARD: Final[int] = 2
    CHART_TYPE_SPECIAL: Final[int] = 3

    # Clear types, as saved/loaded from the DB
    CLEAR_TYPE_NO_PLAY: Final[int] = DBConstants.REFLEC_BEAT_CLEAR_TYPE_NO_PLAY
    CLEAR_TYPE_FAILED: Final[int] = DBConstants.REFLEC_BEAT_CLEAR_TYPE_FAILED
    CLEAR_TYPE_CLEARED: Final[int] = DBConstants.REFLEC_BEAT_CLEAR_TYPE_CLEARED
    CLEAR_TYPE_HARD_CLEARED: Final[int] = DBConstants.REFLEC_BEAT_CLEAR_TYPE_HARD_CLEARED
    CLEAR_TYPE_S_HARD_CLEARED: Final[int] = DBConstants.REFLEC_BEAT_CLEAR_TYPE_S_HARD_CLEARED

    # Combo types, as saved/loaded from the DB
    COMBO_TYPE_NONE: Final[int] = DBConstants.REFLEC_BEAT_COMBO_TYPE_NONE
    COMBO_TYPE_ALMOST_COMBO: Final[int] = DBConstants.REFLEC_BEAT_COMBO_TYPE_ALMOST_COMBO
    COMBO_TYPE_FULL_COMBO: Final[int] = DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO
    COMBO_TYPE_FULL_COMBO_ALL_JUST: Final[int] = DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO_ALL_JUST

    # Return the local2 and lobby2 service so that matching will work on newer
    # Reflec Beat games.
    extra_services: List[str] = [
        "local2",
        "lobby2",
    ]

    def previous_version(self) -> Optional["ReflecBeatBase"]:
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
        return Node.void("pc")

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

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            # User doesn't exist but should at this point
            return None

        # Trying to import from current version
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_profile(userid, profile)

    def put_profile_by_refid(self, refid: Optional[str], request: Node) -> Optional[Profile]:
        """
        Given a RefID and a request node, unformat the profile and save it.
        """
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return None

        oldprofile = self.get_profile(userid)
        if oldprofile is None:
            # Create one so we can get refid/extid
            oldprofile = Profile(self.game, self.version, refid, 0)
            self.put_profile(userid, oldprofile)
        newprofile = self.unformat_profile(userid, request, oldprofile)
        if newprofile is not None:
            self.put_profile(userid, newprofile)
            return newprofile
        else:
            return oldprofile

    def get_machine_by_id(self, shop_id: int) -> Optional[Machine]:
        pcbid = self.data.local.machine.from_machine_id(shop_id)
        if pcbid is not None:
            return self.data.local.machine.get_machine(pcbid)
        else:
            return None

    def update_score(
        self,
        userid: UserID,
        songid: int,
        chart: int,
        points: int,
        achievement_rate: int,
        clear_type: int,
        combo_type: int,
        miss_count: int,
        combo: Optional[int] = None,
        stats: Optional[Dict[str, int]] = None,
        param: Optional[int] = None,
        kflag: Optional[int] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in Reflec series can expect
        the same attributes in a score. Note that the clear_types passed here are
        expected to be converted from game identifier to our internal identifier,
        so that any game in the series may convert them back.
        """
        # Range check clear type
        if clear_type not in [
            self.CLEAR_TYPE_NO_PLAY,
            self.CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_HARD_CLEARED,
            self.CLEAR_TYPE_S_HARD_CLEARED,
        ]:
            raise Exception(f"Invalid clear_type value {clear_type}")

        # Range check combo type
        if combo_type not in [
            self.COMBO_TYPE_NONE,
            self.COMBO_TYPE_ALMOST_COMBO,
            self.COMBO_TYPE_FULL_COMBO,
            self.COMBO_TYPE_FULL_COMBO_ALL_JUST,
        ]:
            raise Exception(f"Invalid combo_type value {combo_type}")

        oldscore = self.data.local.music.get_score(
            self.game,
            self.version,
            userid,
            songid,
            chart,
        )

        # Score history is verbatum, instead of highest score
        now = Time.now()
        history = ValidatedDict({})
        oldpoints = points

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict({})
            highscore = True
        else:
            # Set the score to any new record achieved
            highscore = points >= oldscore.points
            points = max(points, oldscore.points)
            scoredata = oldscore.data

        # Update the last played time
        scoredata.replace_int("last_played_time", now)

        # Replace clear type with highest value and timestamps
        if clear_type >= scoredata.get_int("clear_type"):
            scoredata.replace_int("clear_type", max(scoredata.get_int("clear_type"), clear_type))
            scoredata.replace_int("best_clear_type_time", now)
        history.replace_int("clear_type", clear_type)

        # Replace combo type with highest value and timestamps
        if combo_type >= scoredata.get_int("combo_type"):
            scoredata.replace_int("combo_type", max(scoredata.get_int("combo_type"), combo_type))
            scoredata.replace_int("best_clear_type_time", now)
        history.replace_int("combo_type", combo_type)

        # Update the combo for this song
        if combo is not None:
            scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))
            history.replace_int("combo", combo)

        # Update the param for this song
        if param is not None:
            scoredata.replace_int("param", max(scoredata.get_int("param"), param))
            history.replace_int("param", param)

        # Update the kflag for this song
        if kflag is not None:
            scoredata.replace_int("kflag", max(scoredata.get_int("kflag"), kflag))
            history.replace_int("kflag", kflag)

        # Update win/lost/draw stats for this song
        if stats is not None:
            scoredata.replace_dict("stats", stats)
            history.replace_dict("stats", stats)

        # Update the achievement rate with timestamps
        if achievement_rate >= scoredata.get_int("achievement_rate"):
            scoredata.replace_int(
                "achievement_rate",
                max(scoredata.get_int("achievement_rate"), achievement_rate),
            )
            scoredata.replace_int("best_achievement_rate_time", now)
        history.replace_int("achievement_rate", achievement_rate)

        # Update the miss count with timestamps, either if it was lowered, or if the old value was blank.
        # If the new value is -1 (we didn't get a miss count this time), never update the old value.
        if miss_count >= 0:
            if miss_count <= scoredata.get_int("miss_count", 999999) or scoredata.get_int("miss_count") == -1:
                scoredata.replace_int(
                    "miss_count",
                    min(scoredata.get_int("miss_count", 999999), miss_count),
                )
                scoredata.replace_int("best_miss_count_time", now)
        history.replace_int("miss_count", miss_count)

        # Look up where this score was earned
        lid = self.get_machine_id()

        # Reflec Beat happens to send all songs that were played by a player
        # at the end of the round. It sends timestamps for the songs, but as of
        # Colette they were identical for each song in the round. So, if a user
        # plays the same song/chart# more than once in a round, we will end up
        # failing to store the attempt since we don't allow two of the same
        # attempt at the same time for the same user and song/chart. So, bump
        # the timestamp by one second and retry well past the maximum number of
        # songs.
        for bump in range(10):
            timestamp = now + bump

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
                timestamp=timestamp,
            )

            try:
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
                    highscore,
                    timestamp=timestamp,
                )
            except ScoreSaveException:
                # Try again one second in the future
                continue

            # We saved successfully
            break
