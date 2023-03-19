# vim: set fileencoding=utf-8
from typing import Optional
from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.festo import JubeatFesto

from bemani.common import VersionConstants


class JubeatAvenue(JubeatBase):
    name: str = "Jubeat Avenue"
    version: int = VersionConstants.JUBEAT_AVENUE

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatFesto(self.data, self.config, self.model)
