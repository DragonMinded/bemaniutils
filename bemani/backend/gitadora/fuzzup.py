# vim: set fileencoding=utf-8
import copy
from typing_extensions import Final
from typing import Optional, List, Dict

from bemani.backend.gitadora.base import GitadoraBase
from bemani.backend.gitadora.musiclists.fuzzupmusic import (
    MUSICLIST_FUZZUP,
    MUSICLIST_FUZZUP_OMNIMIX,
)
from bemani.backend.ess import EventLogHandler

from bemani.common import VersionConstants, Profile, Time
from bemani.data import UserID, Score
from bemani.protocol import Node

from bemani.backend.gitadora.highvoltage import GitadoraHighVoltage


class GitadoraFuzzUp(
    EventLogHandler,
    GitadoraBase,
):
    name = "GITADORA Fuzz Up"
    version = VersionConstants.GITADORA_FUZZUP

    GITADORA_GUITARFREAKS: Final[int] = 0
    GITADORA_DRUMMANIA: Final[int] = 1

    CARD_REGISTER: Final[int] = 1
    CARD_USER_USED: Final[int] = 2

    GAME_GRADE_E: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_S: Final[int] = 5
    GAME_GRADE_SS: Final[int] = 6
    GAME_GRADE_EXCELLENT: Final[int] = 7

    GAME_GITUAR_CHART_BASIC: Final[int] = 1
    GAME_GITUAR_CHART_ADVANCE: Final[int] = 2
    GAME_GITUAR_CHART_EXTREME: Final[int] = 3
    GAME_GITUAR_CHART_MASTER: Final[int] = 4

    GAME_DRUM_CHART_BASIC: Final[int] = 1
    GAME_DRUM_CHART_ADVANCE: Final[int] = 2
    GAME_DRUM_CHART_EXTREME: Final[int] = 3
    GAME_DRUM_CHART_MASTER: Final[int] = 4

    GAME_BASS_CHART_BASIC: Final[int] = 5  # gitadora bass part.
    GAME_BASS_CHART_ADVANCE: Final[int] = 6
    GAME_BASS_CHART_EXTREME: Final[int] = 7
    GAME_BASS_CHART_MASTER: Final[int] = 8

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraHighVoltage(self.data, self.config, self.model)
