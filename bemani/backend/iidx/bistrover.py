# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.heroicverse import IIDXHeroicVerse
from bemani.common import VersionConstants


class IIDXBistrover(IIDXBase):

    name = 'Beatmania IIDX BISTROVER'
    version = VersionConstants.IIDX_BISTROVER

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXHeroicVerse(self.data, self.config, self.model)
