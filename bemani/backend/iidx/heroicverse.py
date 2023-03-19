# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.rootage import IIDXRootage
from bemani.common import VersionConstants


class IIDXHeroicVerse(IIDXBase):
    name: str = "Beatmania IIDX HEROIC VERSE"
    version: int = VersionConstants.IIDX_HEROIC_VERSE

    requires_extended_regions: bool = True

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXRootage(self.data, self.config, self.model)
