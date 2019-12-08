# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.sinobuz import IIDXSinobuz
from bemani.common import VersionConstants


class IIDXCannonBallers(IIDXBase):

    name = 'Beatmania IIDX CANNON BALLERS'
    version = VersionConstants.IIDX_CANNON_BALLERS

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXSinobuz(self.data, self.config, self.model)
