# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.ddrace import DDRAce
from bemani.common import VersionConstants


class DDRA20(
    DDRBase,
):

    name = 'DanceDanceRevolution A20'
    version = VersionConstants.DDR_A20

    def previous_version(self) -> Optional[DDRBase]:
        return DDRAce(self.data, self.config, self.model)

    def supports_paseli(self) -> bool:
        if self.model.dest != 'J':
            # DDR Ace in USA mode doesn't support PASELI properly.
            # When in Asia mode it shows PASELI but won't let you select it.
            return False
        else:
            # All other modes should work with PASELI.
            return True
