# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import GameConstants


class MetalGearArcadeBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for Metal Gear Arcade.
    """

    game: GameConstants = GameConstants.MGA

    def previous_version(self) -> Optional["MetalGearArcadeBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None
