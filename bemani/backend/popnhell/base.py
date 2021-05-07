from typing import Optional

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import GameConstants
from bemani.backend.ess import EventLogHandler
from bemani.data import UserID, Score, Data
from bemani.protocol import Node


class PopnHelloBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all one Bishi Bashi version that we support (lol).
    In theory we could add support for Bishi Bashi Channel, but that never
    happened.
    """

    game = GameConstants.POPN_HELLO

    def previous_version(self) -> Optional['PopnHelloBase']:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

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

    def get_scores_by_refid(self, refid: Optional[int]) -> Optional[Node]:
        """
        Given a RefID, return a formatted score node. Similar rationale to
        get_profile_by_extid.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
        if scores is None:
            return None
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_scores(userid, profile, scores)
