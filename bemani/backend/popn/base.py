# vim: set fileencoding=utf-8
from typing import Dict, Optional, Sequence
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import (
    Profile,
    ValidatedDict,
    Time,
    GameConstants,
    DBConstants,
    BroadcastConstants,
    Model,
)
from bemani.data import UserID, Achievement, ScoreSaveException, Config, Data
from bemani.protocol import Node


class PopnMusicBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Pop'n Music versions. Handles common functionality for
    getting profiles based on refid, creating new profiles, looking up and saving
    scores.
    """

    game: GameConstants = GameConstants.POPN_MUSIC

    # Play medals, as saved into/loaded from the DB
    PLAY_MEDAL_NO_PLAY: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_NO_PLAY
    PLAY_MEDAL_CIRCLE_FAILED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED
    PLAY_MEDAL_DIAMOND_FAILED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FAILED
    PLAY_MEDAL_STAR_FAILED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FAILED
    PLAY_MEDAL_EASY_CLEAR: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_EASY_CLEAR
    PLAY_MEDAL_CIRCLE_CLEARED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_CLEARED
    PLAY_MEDAL_DIAMOND_CLEARED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_CLEARED
    PLAY_MEDAL_STAR_CLEARED: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_CLEARED
    PLAY_MEDAL_CIRCLE_FULL_COMBO: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FULL_COMBO
    PLAY_MEDAL_DIAMOND_FULL_COMBO: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FULL_COMBO
    PLAY_MEDAL_STAR_FULL_COMBO: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FULL_COMBO
    PLAY_MEDAL_PERFECT: Final[int] = DBConstants.POPN_MUSIC_PLAY_MEDAL_PERFECT

    # Chart type, as saved into/loaded from the DB, and returned to game
    CHART_TYPE_EASY: Final[int] = 0
    CHART_TYPE_NORMAL: Final[int] = 1
    CHART_TYPE_HYPER: Final[int] = 2
    CHART_TYPE_EX: Final[int] = 3

    # Old profile lookup type, for loading profile by ID
    NEW_PROFILE_ONLY: Final[int] = 0
    OLD_PROFILE_ONLY: Final[int] = 1
    OLD_PROFILE_FALLTHROUGH: Final[int] = 2

    # Pop'n Music in particular requires non-expired profiles to do conversions
    # properly.
    supports_expired_profiles: bool = False

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

    def previous_version(self) -> Optional["PopnMusicBase"]:
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
        return Node.void("playerdata")

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        """
        Base handler for profile conversion. Given a userid and a profile
        dictionary, return a node which represents the converted profile for
        the next version of this game. Games will call previous_version to get
        a game class of their previous game version, and then will call
        format_conversion on that previous version to get the profile to
        migrate.
        """
        return Node.void("playerdata")

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        """
        Base handler for profile parsing. Given a request and an old profile,
        return a new profile that's been updated with the contents of the request.
        Should be overridden.
        """
        return oldprofile

    def get_profile_by_refid(self, refid: Optional[str], load_mode: int) -> Optional[Node]:
        """
        Given a RefID, return a formatted profile node. Basically every game
        needs a profile lookup, even if it handles where that happens in
        a different request. This is provided for code deduplication. This
        method handles delegating to either format_profile, or looking up
        the previous game and calling format_conversion, whenever necessary.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            # User doesn't exist but should at this point
            return None

        if load_mode == self.OLD_PROFILE_ONLY:
            # Trying to import from older version
            oldversion = self.previous_version()
            profile = oldversion.get_profile(userid)
            if profile is None:
                return None
            return self.format_conversion(userid, profile)
        elif load_mode == self.NEW_PROFILE_ONLY:
            # Trying to import from current version
            profile = self.get_profile(userid)
            if profile is None:
                return None
            return self.format_profile(userid, profile)
        elif load_mode == self.OLD_PROFILE_FALLTHROUGH:
            # Try to load from current, if that fails try to load previous
            profile = self.get_profile(userid)
            if profile is not None:
                return self.format_profile(userid, profile)
            oldversion = self.previous_version()
            oldprofile = oldversion.get_profile(userid)
            if oldprofile is not None:
                return self.format_conversion(userid, oldprofile)
            return None
        else:
            # Unknown value
            raise Exception("Unrecognized value for get profile!")

    def new_profile_by_refid(
        self,
        refid: Optional[str],
        name: Optional[str],
        chara: Optional[int] = None,
        achievements: Sequence[Achievement] = (),
    ) -> Node:
        """
        Given a RefID and an optional name, create a profile and then return
        a formatted profile node. Similar rationale to get_profile_by_refid.
        """
        if refid is None:
            return None

        if name is None:
            name = "なし"

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            raise Exception("Logic error! Didn't find user to tie profile to!")
        profile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
            },
        )
        if chara is not None:
            profile.replace_int("chara", chara)
        self.put_profile(userid, profile)
        for achievement in achievements:
            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                achievement.id,
                achievement.type,
                achievement.data,
            )
        return self.format_profile(userid, profile)

    def update_score(
        self,
        userid: UserID,
        songid: int,
        chart: int,
        points: int,
        medal: int,
        combo: Optional[int] = None,
        stats: Optional[Dict[str, int]] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in Pop'n series can expect
        the same attributes in a score. Note that the medals passed here are
        expected to be converted from game identifier to our internal identifier,
        so that any game in the series may convert them back. In this way, a song
        played on Pop'n 22 that exists in Pop'n 19 will still have scores/medals
        going back all versions.
        """
        # Range check medals
        if medal not in [
            self.PLAY_MEDAL_NO_PLAY,
            self.PLAY_MEDAL_CIRCLE_FAILED,
            self.PLAY_MEDAL_DIAMOND_FAILED,
            self.PLAY_MEDAL_STAR_FAILED,
            self.PLAY_MEDAL_EASY_CLEAR,
            self.PLAY_MEDAL_CIRCLE_CLEARED,
            self.PLAY_MEDAL_DIAMOND_CLEARED,
            self.PLAY_MEDAL_STAR_CLEARED,
            self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
            self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
            self.PLAY_MEDAL_STAR_FULL_COMBO,
            self.PLAY_MEDAL_PERFECT,
        ]:
            raise Exception(f"Invalid medal value {medal}")

        oldscore = self.data.local.music.get_score(
            self.game,
            self.music_version,
            userid,
            songid,
            chart,
        )

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
            points = max(points, oldscore.points)
            scoredata = oldscore.data

        # Replace medal with highest value
        scoredata.replace_int("medal", max(scoredata.get_int("medal"), medal))
        history.replace_int("medal", medal)

        if stats is not None:
            if raised:
                # We have stats, and there's a new high score, update the stats
                scoredata.replace_dict("stats", stats)
            history.replace_dict("stats", stats)

        if combo is not None:
            # If we have a combo, replace it
            scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))
            history.replace_int("combo", combo)

        # Look up where this score was earned
        lid = self.get_machine_id()

        # Pop'n Music for all versions before Lapistoria sends all of the songs
        # a player played at the end of the round. It doesn't send timestamps
        # for those songs (Jubeat does). So, if a user plays the same song/chart
        # more than once in a round, we will end up failing to store the attempt
        # since we don't allow two of the same attempt at the same time for the
        # same user and song/chart. So, bump the timestamp by one second and retry
        # well past the maximum number of songs.
        now = Time.now()
        for bump in range(10):
            timestamp = now + bump

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

    def broadcast_score(
        self,
        userid: UserID,
        songid: int,
        chart: int,
        medal: int,
        points: int,
        combo: int,
        stats: Dict[str, int],
    ) -> None:
        # Generate scorecard
        profile = self.get_profile(userid)
        song = self.data.local.music.get_song(self.game, self.music_version, songid, chart)

        card_medal = {
            self.PLAY_MEDAL_CIRCLE_FAILED: "Failed",
            self.PLAY_MEDAL_DIAMOND_FAILED: "Failed",
            self.PLAY_MEDAL_STAR_FAILED: "Failed",
            self.PLAY_MEDAL_EASY_CLEAR: "Cleared",
            self.PLAY_MEDAL_CIRCLE_CLEARED: "Cleared",
            self.PLAY_MEDAL_DIAMOND_CLEARED: "Cleared",
            self.PLAY_MEDAL_STAR_CLEARED: "Cleared",
            self.PLAY_MEDAL_CIRCLE_FULL_COMBO: "Full Combo",
            self.PLAY_MEDAL_DIAMOND_FULL_COMBO: "Full Combo",
            self.PLAY_MEDAL_STAR_FULL_COMBO: "Full Combo",
            self.PLAY_MEDAL_PERFECT: "Perfect",
        }[medal]

        card_chart = {
            self.CHART_TYPE_EASY: "Easy",
            self.CHART_TYPE_NORMAL: "Normal",
            self.CHART_TYPE_HYPER: "Hyper",
            self.CHART_TYPE_EX: "Ex",
        }[chart]

        # Construct the dictionary for the broadcast
        card_data = {
            BroadcastConstants.PLAYER_NAME: profile.get_str("name", "なし"),
            BroadcastConstants.SONG_NAME: song.name,
            BroadcastConstants.ARTIST_NAME: song.artist,
            BroadcastConstants.DIFFICULTY: card_chart,
            BroadcastConstants.SCORE: str(points),
            BroadcastConstants.MEDAL: card_medal,
            BroadcastConstants.COOLS: str(stats["cool"]),
            BroadcastConstants.GREATS: str(stats["great"]),
            BroadcastConstants.GOODS: str(stats["good"]),
            BroadcastConstants.BADS: str(stats["bad"]),
            BroadcastConstants.COMBO: str(combo),
        }

        # Try to broadcast out the score to our webhook(s)
        self.data.triggers.broadcast_score(card_data, self.game, song)
