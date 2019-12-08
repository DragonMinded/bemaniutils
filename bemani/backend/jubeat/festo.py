# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.clan import JubeatClan

from bemani.common import VersionConstants


class JubeatFesto(JubeatBase):

    name = 'Jubeat Festo'
    version = VersionConstants.JUBEAT_FESTO

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatClan(self.data, self.config, self.model)
