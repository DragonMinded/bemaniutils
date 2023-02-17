# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.ddr.base import DDRBase
from bemani.common import VersionConstants


class DDRX(DDRBase):
    name: str = "DanceDanceRevolution X"
    version: int = VersionConstants.DDR_X

    def previous_version(self) -> Optional[DDRBase]:
        return DDRSuperNova2(self.data, self.config, self.model)


class DDRSuperNova2(DDRBase):
    name: str = "DanceDanceRevolution SuperNova 2"
    version: int = VersionConstants.DDR_SUPERNOVA_2

    def previous_version(self) -> Optional[DDRBase]:
        return DDRSuperNova(self.data, self.config, self.model)


class DDRSuperNova(DDRBase):
    name: str = "DanceDanceRevolution SuperNova"
    version: int = VersionConstants.DDR_SUPERNOVA

    def previous_version(self) -> Optional[DDRBase]:
        return DDRExtreme(self.data, self.config, self.model)


class DDRExtreme(DDRBase):
    name: str = "DanceDanceRevolution Extreme"
    version: int = VersionConstants.DDR_EXTREME

    def previous_version(self) -> Optional[DDRBase]:
        return DDR7thMix(self.data, self.config, self.model)


class DDR7thMix(DDRBase):
    name: str = "DanceDanceRevolution 7thMix"
    version: int = VersionConstants.DDR_7THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR6thMix(self.data, self.config, self.model)


class DDR6thMix(DDRBase):
    name: str = "DanceDanceRevolution 6thMix"
    version: int = VersionConstants.DDR_6THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR5thMix(self.data, self.config, self.model)


class DDR5thMix(DDRBase):
    name: str = "DanceDanceRevolution 5thMix"
    version: int = VersionConstants.DDR_5THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR4thMix(self.data, self.config, self.model)


class DDR4thMix(DDRBase):
    name: str = "DanceDanceRevolution 4thMix"
    version: int = VersionConstants.DDR_4THMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR3rdMix(self.data, self.config, self.model)


class DDR3rdMix(DDRBase):
    name: str = "DanceDanceRevolution 3rdMix"
    version: int = VersionConstants.DDR_3RDMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR2ndMix(self.data, self.config, self.model)


class DDR2ndMix(DDRBase):
    name: str = "DanceDanceRevolution 2ndMix"
    version: int = VersionConstants.DDR_2NDMIX

    def previous_version(self) -> Optional[DDRBase]:
        return DDR1stMix(self.data, self.config, self.model)


class DDR1stMix(DDRBase):
    name: str = "DanceDanceRevolution 1stMix"
    version: int = VersionConstants.DDR_1STMIX
