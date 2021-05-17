# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.rootage import IIDXRootage
from bemani.common import VersionConstants


class IIDXHeroicVerse(IIDXBase):

    name = 'Beatmania IIDX HEROIC VERSE'
    version = VersionConstants.IIDX_HEROIC_VERSE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXRootage(self.data, self.config, self.model)
