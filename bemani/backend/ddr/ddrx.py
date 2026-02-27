from typing import Optional

from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.ddrsn2 import DDRSuperNova2
from bemani.common import VersionConstants


class DDRX(DDRBase):
    name: str = "DanceDanceRevolution X"
    version: int = VersionConstants.DDR_X

    def previous_version(self) -> Optional[DDRBase]:
        return DDRSuperNova2(self.data, self.config, self.model)
