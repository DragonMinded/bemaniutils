# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.jubeat.base import JubeatBase
from bemani.common import VersionConstants


class Jubeat(JubeatBase):
    name: str = "Jubeat"
    version: int = VersionConstants.JUBEAT


class JubeatRipples(JubeatBase):
    name: str = "Jubeat Ripples"
    version: int = VersionConstants.JUBEAT_RIPPLES

    def previous_version(self) -> Optional[JubeatBase]:
        return Jubeat(self.data, self.config, self.model)


class JubeatRipplesAppend(JubeatBase):
    name: str = "Jubeat Ripples Append"
    version: int = VersionConstants.JUBEAT_RIPPLES_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatRipples(self.data, self.config, self.model)


class JubeatKnit(JubeatBase):
    name: str = "Jubeat Knit"
    version: int = VersionConstants.JUBEAT_KNIT

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatRipplesAppend(self.data, self.config, self.model)


class JubeatKnitAppend(JubeatBase):
    name: str = "Jubeat Knit Append"
    version: int = VersionConstants.JUBEAT_KNIT_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatKnit(self.data, self.config, self.model)


class JubeatCopious(JubeatBase):
    name: str = "Jubeat Copious"
    version: int = VersionConstants.JUBEAT_COPIOUS

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatKnitAppend(self.data, self.config, self.model)


class JubeatCopiousAppend(JubeatBase):
    name: str = "Jubeat Copious Append"
    version: int = VersionConstants.JUBEAT_COPIOUS_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatCopious(self.data, self.config, self.model)
