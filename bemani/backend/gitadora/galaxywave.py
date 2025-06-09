# vim: set fileencoding=utf-8
import copy
from typing_extensions import Final
from typing import Optional, List, Dict

from bemani.backend.gitadora.base import GitadoraBase
from bemani.backend.gitadora.musiclists.galaxywavemusic import (
    MUSICLIST_GALAXYWAVE,
    MUSICLIST_GALAXYWAVE_OMNIMIX,
)
from bemani.backend.ess import EventLogHandler

from bemani.common import VersionConstants, Profile, Time
from bemani.data import UserID, Score
from bemani.protocol import Node

from bemani.backend.gitadora.fuzzup import GitadoraFuzzUp


class GitadoraGalaxyWave(
    EventLogHandler,
    GitadoraBase,
):
    name = "GITADORA GALAXY WAVE"
    version = VersionConstants.GITADORA_GALAXYWAVE
    