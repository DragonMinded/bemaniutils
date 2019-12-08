# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.jubeat.base import JubeatBase
from bemani.common import VersionConstants


class Jubeat(JubeatBase):

    name = 'Jubeat'
    version = VersionConstants.JUBEAT


class JubeatRipples(JubeatBase):

    name = 'Jubeat Ripples'
    version = VersionConstants.JUBEAT_RIPPLES

    def previous_version(self) -> Optional[JubeatBase]:
        return Jubeat(self.data, self.config, self.model)


class JubeatRipplesAppend(JubeatBase):

    name = 'Jubeat Ripples Append'
    version = VersionConstants.JUBEAT_RIPPLES_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatRipples(self.data, self.config, self.model)


class JubeatKnit(JubeatBase):

    name = 'Jubeat Knit'
    version = VersionConstants.JUBEAT_KNIT

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatRipplesAppend(self.data, self.config, self.model)


class JubeatKnitAppend(JubeatBase):

    name = 'Jubeat Knit Append'
    version = VersionConstants.JUBEAT_KNIT_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatKnit(self.data, self.config, self.model)


class JubeatCopious(JubeatBase):

    name = 'Jubeat Copious'
    version = VersionConstants.JUBEAT_COPIOUS

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatKnitAppend(self.data, self.config, self.model)


class JubeatCopiousAppend(JubeatBase):

    name = 'Jubeat Copious Append'
    version = VersionConstants.JUBEAT_COPIOUS_APPEND

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatCopious(self.data, self.config, self.model)
