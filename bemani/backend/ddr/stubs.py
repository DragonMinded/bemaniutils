# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.ddr.base import DDRBase
from bemani.common import VersionConstants


class DDRX(DDRBase):

    name = 'DanceDanceRevolution X'
    version = VersionConstants.DDR_X

    def previous_version(self) -> Optional[DDRBase]:
        return DDRSuperNova2(self.data, self.config, self.model)


class DDRSuperNova2(DDRBase):

    name = 'DanceDanceRevolution SuperNova 2'
    version = VersionConstants.DDR_SUPERNOVA_2

    def previous_version(self) -> Optional[DDRBase]:
        return DDRSuperNova(self.data, self.config, self.model)


class DDRSuperNova(DDRBase):

    name = 'DanceDanceRevolution SuperNova'
    version = VersionConstants.DDR_SUPERNOVA

    def previous_version(self) -> Optional[DDRBase]:
        return DDRExtreme(self.data, self.config, self.model)


class DDRExtreme(DDRBase):

    name = 'DanceDanceRevolution Extreme'
    version = VersionConstants.DDR_EXTREME

    def previous_version(self) -> Optional[DDRBase]:
        return DDR7thMix(self.data, self.config, self.model)


class DDR7thMix(DDRBase):

    name = 'DanceDanceRevolution 7thMix'
    version = VersionConstants.DDR_7THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR6thMix(self.data, self.config, self.model)


class DDR6thMix(DDRBase):

    name = 'DanceDanceRevolution 6thMix'
    version = VersionConstants.DDR_6THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR5thMix(self.data, self.config, self.model)


class DDR5thMix(DDRBase):

    name = 'DanceDanceRevolution 5thMix'
    version = VersionConstants.DDR_5THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR4thMix(self.data, self.config, self.model)


class DDR4thMix(DDRBase):

    name = 'DanceDanceRevolution 4thMix'
    version = VersionConstants.DDR_4THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR3rdMix(self.data, self.config, self.model)


class DDR3rdMix(DDRBase):

    name = 'DanceDanceRevolution 3rdMix'
    version = VersionConstants.DDR_3RDMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR2ndMix(self.data, self.config, self.model)


class DDR2ndMix(DDRBase):

    name = 'DanceDanceRevolution 2ndMix'
    version = VersionConstants.DDR_2NDMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR1stMix(self.data, self.config, self.model)


class DDR1stMix(DDRBase):

    name = 'DanceDanceRevolution 1stMix'
    version = VersionConstants.DDR_1STMIX
