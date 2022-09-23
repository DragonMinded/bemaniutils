# vim: set fileencoding=utf-8
from typing import Optional
from bemani.backend.gitadora.base import GitadoraBase
from bemani.backend.ess import EventLogHandler
from bemani.common import VersionConstants

from bemani.backend.gitadora.nextage import GitadoraNextage

class GitadoraHighVoltage(
    EventLogHandler,
    GitadoraBase,
):

    name = 'GITADORA HighVoltage'
    version = VersionConstants.GITADORA_HIGH_VOLTAGE

    def previous_version(self) -> Optional[GitadoraBase]:
        return GitadoraNextage(self.data, self.config, self.model)
