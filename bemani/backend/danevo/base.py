# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import (
    GameConstants,
)


class DanceEvolutionBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Dance Evolution version that we support.
    """

    game: GameConstants = GameConstants.DANCE_EVOLUTION

    def previous_version(self) -> Optional["DanceEvolutionBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None
