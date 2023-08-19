# vim: set fileencoding=utf-8
import random
import struct
from typing import Dict, Iterable, List, Optional, Set, Tuple
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import DBConstants, GameConstants, ValidatedDict, Model, Profile
from bemani.data import Data, Score, UserID, Config
from bemani.protocol import Node


class JubeatBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Jubeat versions. Handles common functionality for getting
    profiles based on refid, creating new profiles, looking up and saving scores.
    """

    game: GameConstants = GameConstants.JUBEAT

    GAME_FLAG_BIT_PLAYED: Final[int] = 0x1
    GAME_FLAG_BIT_CLEARED: Final[int] = 0x2
    GAME_FLAG_BIT_FULL_COMBO: Final[int] = 0x4
    GAME_FLAG_BIT_EXCELLENT: Final[int] = 0x8
    GAME_FLAG_BIT_NEARLY_FULL_COMBO: Final[int] = 0x10
    GAME_FLAG_BIT_NEARLY_EXCELLENT: Final[int] = 0x20
    GAME_FLAG_BIT_NO_GRAY: Final[int] = 0x40
    GAME_FLAG_BIT_NO_YELLOW: Final[int] = 0x80

    PLAY_MEDAL_FAILED: Final[int] = DBConstants.JUBEAT_PLAY_MEDAL_FAILED
    PLAY_MEDAL_CLEARED: Final[int] = DBConstants.JUBEAT_PLAY_MEDAL_CLEARED
    PLAY_MEDAL_NEARLY_FULL_COMBO: Final[
        int
    ] = DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_FULL_COMBO
    PLAY_MEDAL_FULL_COMBO: Final[int] = DBConstants.JUBEAT_PLAY_MEDAL_FULL_COMBO
    PLAY_MEDAL_NEARLY_EXCELLENT: Final[
        int
    ] = DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_EXCELLENT
    PLAY_MEDAL_EXCELLENT: Final[int] = DBConstants.JUBEAT_PLAY_MEDAL_EXCELLENT

    CHART_TYPE_BASIC: Final[int] = 0
    CHART_TYPE_ADVANCED: Final[int] = 1
    CHART_TYPE_EXTREME: Final[int] = 2
    CHART_TYPE_HARD_BASIC: Final[int] = 3
    CHART_TYPE_HARD_ADVANCED: Final[int] = 4
    CHART_TYPE_HARD_EXTREME: Final[int] = 5

    def __init__(self, data: Data, config: Config, model: Model) -> None:
        super().__init__(data, config, model)
        if model.rev == "X" or model.rev == "Y":
            self.omnimix = True
        else:
            self.omnimix = False

    @property
    def music_version(self) -> int:
        if self.omnimix:
            return DBConstants.OMNIMIX_VERSION_BUMP + self.version
        return self.version

    def previous_version(self) -> Optional["JubeatBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def put_profile(self, userid: UserID, profile: Profile) -> None:
        """
        Save a new profile for this user given a game/version. Overrides but calls
        the same functionality in Base, to ensure we don't save calculated values.

        Parameters:
            userid - The user ID we are saving the profile for.
            profile - A dictionary that should be looked up later using get_profile.
        """
        if "has_old_version" in profile:
            del profile["has_old_version"]
        super().put_profile(userid, profile)

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

        # First try to load the actual profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        if profile is None:
            return None

        # Now try to find out if the profile is new or old
        oldversion = self.previous_version()
        oldprofile = oldversion.get_profile(userid)
        profile["has_old_version"] = oldprofile is not None

        # Now, return it
        return self.format_profile(userid, profile)

    def new_profile_by_refid(self, refid: Optional[str], name: Optional[str]) -> Node:
        """
        Given a RefID and an optional name, create a profile and then return
        a formatted profile node. Similar rationale to get_profile_by_refid.
        """
        if refid is None:
            return None

        if name is None:
            name = "なし"

        # First, create and save the default profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
            },
        )
        self.put_profile(userid, profile)

        # Now, reload and format the profile, looking up the has old version flag
        oldversion = self.previous_version()
        oldprofile = oldversion.get_profile(userid)
        profile["has_old_version"] = oldprofile is not None

        return self.format_profile(userid, profile)

    def get_scores_by_extid(
        self, extid: Optional[int], partition: int, total_partitions: int
    ) -> Optional[Node]:
        """
        Given an ExtID, return a formatted score node. Similar rationale to
        get_profile_by_refid. Note that this takes into account the game's
        desire to partition scores into separate fetches to ensure that we
        don't make any one request too long. We handle the logic for that here.
        """
        if extid is None:
            return None

        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        profile = self.get_profile(userid)
        if profile is None:
            return None

        cache_key = f"get_scores_by_extid-{extid}"
        score: Optional[List[Score]]

        if partition == 1:
            # We fetch all scores on the first partition and then divy up
            # the scores across total_partitions fetches. If it is small
            # enough, we don't bother.
            scores = self.data.remote.music.get_scores(
                self.game, self.music_version, userid
            )
        else:
            # We will want to fetch the remaining scores that were in our
            # cache.
            scores = self.cache.get(cache_key)  # type: ignore

        if len(scores) < 50:
            # We simply return the whole amount for this, and cache nothing.
            rest = []
        else:
            groups = (total_partitions - partition) + 1
            pivot = len(scores) // groups

            rest = scores[pivot:]
            scores = scores[:pivot]

        # Cache the rest of the scores for next iteration, unless we're on the
        # last iteration.
        if partition == total_partitions:
            if rest:
                raise Exception(
                    "Logic error, should not have gotten additional scores to cache on last iteration!"
                )
            self.cache.delete(cache_key)
        else:
            self.cache.set(cache_key, rest, timeout=60)

        # Format the chunk of scores we have to send back to the client.
        return self.format_scores(userid, profile, scores)

    def update_score(
        self,
        userid: UserID,
        timestamp: int,
        songid: int,
        chart: int,
        points: int,
        medal: int,
        combo: int,
        ghost: Optional[List[int]] = None,
        stats: Optional[Dict[str, int]] = None,
        music_rate: Optional[int] = None,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in Jubeat series can expect
        the same attributes in a score.
        """
        # Range check medals
        if medal not in [
            self.PLAY_MEDAL_FAILED,
            self.PLAY_MEDAL_CLEARED,
            self.PLAY_MEDAL_NEARLY_FULL_COMBO,
            self.PLAY_MEDAL_FULL_COMBO,
            self.PLAY_MEDAL_NEARLY_EXCELLENT,
            self.PLAY_MEDAL_EXCELLENT,
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
            points = max(oldscore.points, points)
            scoredata = oldscore.data

        # Replace medal with highest value
        scoredata.replace_int("medal", max(scoredata.get_int("medal"), medal))
        history.replace_int("medal", medal)

        # Increment counters based on medal
        if medal == self.PLAY_MEDAL_CLEARED:
            scoredata.increment_int("clear_count")
        if medal == self.PLAY_MEDAL_FULL_COMBO:
            scoredata.increment_int("full_combo_count")
        if medal == self.PLAY_MEDAL_EXCELLENT:
            scoredata.increment_int("excellent_count")

        # If we have a combo, replace it
        scoredata.replace_int("combo", max(scoredata.get_int("combo"), combo))
        history.replace_int("combo", combo)

        if stats is not None:
            if raised:
                # We have stats, and there's a new high score, update the stats
                scoredata.replace_dict("stats", stats)
            history.replace_dict("stats", stats)

        if ghost is not None:
            # Update the ghost regardless, but don't bother with it in history
            scoredata.replace_int_array("ghost", len(ghost), ghost)

        if music_rate is not None:
            if oldscore is not None:
                if music_rate > oldscore.data.get_int("music_rate"):
                    scoredata.replace_int("music_rate", music_rate)
            else:
                scoredata.replace_int("music_rate", music_rate)
            history.replace_int("music_rate", music_rate)

        # Look up where this score was earned
        lid = self.get_machine_id()

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

    def default_select_jbox(self) -> Set[int]:
        gameitems = self.data.local.game.get_items(self.game, self.version)
        default_main: Set[int] = set()

        for gameitem in gameitems:
            if gameitem.type == "emblem":
                if (
                    gameitem.data.get_int("layer") == 2
                    and gameitem.data.get_int("rarity") == 1
                ):
                    default_main.add(gameitem.id)

        return default_main

    def random_select_jbox(self, owned_emblems: Set[int]) -> Tuple[int, int]:
        gameitems = self.data.local.game.get_items(self.game, self.version)
        normalemblems: Set[int] = set()
        premiumemblems: Set[int] = set()
        for gameitem in gameitems:
            if gameitem.type == "emblem":
                if gameitem.id in owned_emblems:
                    # We don't want to give out random emblems that are already owned.
                    continue

                if gameitem.data.get_int("rarity") in {1, 2, 3}:
                    normalemblems.add(gameitem.id)
                if gameitem.data.get_int("rarity") in {4, 5}:
                    premiumemblems.add(gameitem.id)

        # If they've earned all the premium emblems, give them normal emblems instead.
        if normalemblems and not premiumemblems:
            premiumemblems = normalemblems

        # Now, try to default to the default emblem, in the case that the person
        # has earned every single part (unlikely).
        if not normalemblems:
            normalemblems = self.default_select_jbox()
        if not premiumemblems:
            premiumemblems = self.default_select_jbox()

        # Default to some hand-picked emblems in case the catalog is not available.
        normalindex = 2
        premiumindex = 1
        if normalemblems:
            normalindex = random.sample(normalemblems, 1)[0]
        if premiumemblems:
            premiumindex = random.sample(premiumemblems, 1)[0]

        return normalindex, premiumindex

    def calculate_owned_items(self, item_list: List[int]) -> Set[int]:
        owned_items: Set[int] = set()

        for index in range(len(item_list) * 32):
            offset = 1 << (index % 32)
            bucket = index // 32

            if (item_list[bucket] & offset) != 0:
                owned_items.add(index)

        return owned_items

    def create_owned_items(self, items: Iterable[int], size: int) -> List[int]:
        items_list = [0] * size

        for index in items:
            offset = 1 << (index % 32)
            bucket = index // 32

            items_list[bucket] |= offset

        return [struct.unpack("i", struct.pack("I", item))[0] for item in items_list]
