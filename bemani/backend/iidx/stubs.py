# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.iidx.base import IIDXBase
from bemani.common import VersionConstants


class IIDX1stStyle(IIDXBase):

    name = 'Beatmania IIDX 1st style & substream'
    version = VersionConstants.IIDX


class IIDX2ndStyle(IIDXBase):

    name = 'Beatmania IIDX 2nd style'
    version = VersionConstants.IIDX_2ND_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX1stStyle(self.data, self.config, self.model)


class IIDX3rdStyle(IIDXBase):

    name = 'Beatmania IIDX 3rd style'
    version = VersionConstants.IIDX_3RD_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX2ndStyle(self.data, self.config, self.model)


class IIDX4thStyle(IIDXBase):

    name = 'Beatmania IIDX 4th style'
    version = VersionConstants.IIDX_4TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX3rdStyle(self.data, self.config, self.model)


class IIDX5thStyle(IIDXBase):

    name = 'Beatmania IIDX 5th style'
    version = VersionConstants.IIDX_5TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX4thStyle(self.data, self.config, self.model)


class IIDX6thStyle(IIDXBase):

    name = 'Beatmania IIDX 6th style'
    version = VersionConstants.IIDX_6TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX5thStyle(self.data, self.config, self.model)


class IIDX7thStyle(IIDXBase):

    name = 'Beatmania IIDX 7th style'
    version = VersionConstants.IIDX_7TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX6thStyle(self.data, self.config, self.model)


class IIDX8thStyle(IIDXBase):

    name = 'Beatmania IIDX 8th style'
    version = VersionConstants.IIDX_8TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX7thStyle(self.data, self.config, self.model)


class IIDX9thStyle(IIDXBase):

    name = 'Beatmania IIDX 9th style'
    version = VersionConstants.IIDX_9TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX8thStyle(self.data, self.config, self.model)


class IIDX10thStyle(IIDXBase):

    name = 'Beatmania IIDX 10th style'
    version = VersionConstants.IIDX_10TH_STYLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX9thStyle(self.data, self.config, self.model)


class IIDXRed(IIDXBase):

    name = 'Beatmania IIDX RED'
    version = VersionConstants.IIDX_RED

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDX10thStyle(self.data, self.config, self.model)


class IIDXHappySky(IIDXBase):

    name = 'Beatmania IIDX HAPPY SKY'
    version = VersionConstants.IIDX_HAPPY_SKY

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXRed(self.data, self.config, self.model)


class IIDXDistorted(IIDXBase):

    name = 'Beatmania IIDX DistorteD'
    version = VersionConstants.IIDX_DISTORTED

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXHappySky(self.data, self.config, self.model)


class IIDXGold(IIDXBase):

    name = 'Beatmania IIDX GOLD'
    version = VersionConstants.IIDX_GOLD

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXDistorted(self.data, self.config, self.model)


class IIDXDJTroopers(IIDXBase):

    name = 'Beatmania IIDX DJ TROOPERS'
    version = VersionConstants.IIDX_DJ_TROOPERS

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXGold(self.data, self.config, self.model)


class IIDXEmpress(IIDXBase):

    name = 'Beatmania IIDX EMPRESS'
    version = VersionConstants.IIDX_EMPRESS

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXDJTroopers(self.data, self.config, self.model)


class IIDXSirius(IIDXBase):

    name = 'Beatmania IIDX SIRIUS'
    version = VersionConstants.IIDX_SIRIUS

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXEmpress(self.data, self.config, self.model)


class IIDXResortAnthem(IIDXBase):

    name = 'Beatmania IIDX Resort Anthem'
    version = VersionConstants.IIDX_RESORT_ANTHEM

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXSirius(self.data, self.config, self.model)


class IIDXLincle(IIDXBase):

    name = 'Beatmania IIDX Lincle'
    version = VersionConstants.IIDX_LINCLE

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXResortAnthem(self.data, self.config, self.model)
