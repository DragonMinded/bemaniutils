# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import GameConstants


class BishiBashiBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all one Bishi Bashi version that we support (lol).
    In theory we could add support for Bishi Bashi Channel, but that never
    happened.
    """

    game: GameConstants = GameConstants.BISHI_BASHI

    def previous_version(self) -> Optional["BishiBashiBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None
