from typing import Optional

from bemani.backend.gf.base import GuitarFreaksBase
from bemani.common import VersionConstants



class GuitarFreaksV7(GuitarFreaksBase):

    name = 'GuitarFreaks V7'
    version = VersionConstants.GUITARFREAKS_V7

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV6(self.data, self.config, self.model)


class GuitarFreaksV6(GuitarFreaksBase):

    name = 'GuitarFreaks V6'
    version = VersionConstants.GUITARFREAKS_V6

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV5(self.data, self.config, self.model)


class GuitarFreaksV5(GuitarFreaksBase):

    name = 'GuitarFreaks V5'
    version = VersionConstants.GUITARFREAKS_V5

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV4(self.data, self.config, self.model)


class GuitarFreaksV4(GuitarFreaksBase):

    name = 'GuitarFreaks V4'
    version = VersionConstants.GUITARFREAKS_V4

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV4(self.data, self.config, self.model)


class GuitarFreaksV3(GuitarFreaksBase):

    name = 'GuitarFreaks V3'
    version = VersionConstants.GUITARFREAKS_V3

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV2(self.data, self.config, self.model)


class GuitarFreaksV2(GuitarFreaksBase):

    name = 'GuitarFreaks V2'
    version = VersionConstants.GUITARFREAKS_V2

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaksV(self.data, self.config, self.model)


class GuitarFreaksV(GuitarFreaksBase):

    name = 'GuitarFreaks V'
    version = VersionConstants.GUITARFREAKS_V

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks11th(self.data, self.config, self.model)


class GuitarFreaks11th(GuitarFreaksBase):

    name = 'GuitarFreaks 10thMix'
    version = VersionConstants.GUITARFREAKS_11TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks10th(self.data, self.config, self.model)

class GuitarFreaks10th(GuitarFreaksBase):

    name = 'GuitarFreaks 10thMix'
    version = VersionConstants.GUITARFREAKS_10TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks9th(self.data, self.config, self.model)


class GuitarFreaks9th(GuitarFreaksBase):

    name = 'GuitarFreaks 9thMix'
    version = VersionConstants.GUITARFREAKS_9TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks8th(self.data, self.config, self.model)


class GuitarFreaks8th(GuitarFreaksBase):

    name = 'GuitarFreaks 8thMix'
    version = VersionConstants.GUITARFREAKS_8TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks7th(self.data, self.config, self.model)


class GuitarFreaks7th(GuitarFreaksBase):

    name = 'GuitarFreaks 7thMix'
    version = VersionConstants.GUITARFREAKS_7TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks6th(self.data, self.config, self.model)


class GuitarFreaks6th(GuitarFreaksBase):

    name = 'GuitarFreaks 6thMix'
    version = VersionConstants.GUITARFREAKS_6TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks5th(self.data, self.config, self.model)


class GuitarFreaks5th(GuitarFreaksBase):

    name = 'GuitarFreaks 5thMix'
    version = VersionConstants.GUITARFREAKS_5TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks4th(self.data, self.config, self.model)


class GuitarFreaks4th(GuitarFreaksBase):

    name = 'GuitarFreaks 4thMix'
    version = VersionConstants.GUITARFREAKS_4TH

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks3rd(self.data, self.config, self.model)


class GuitarFreaks3rd(GuitarFreaksBase):

    name = 'GuitarFreaks 3rdMix'
    version = VersionConstants.GUITARFREAKS_3RD

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks2nd(self.data, self.config, self.model)


class GuitarFreaks2nd(GuitarFreaksBase):

    name = 'GuitarFreaks 2ndMix'
    version = VersionConstants.GUITARFREAKS_2ND

    def previous_version(self) -> Optional[GuitarFreaksBase]:
        return GuitarFreaks1st(self.data, self.config, self.model)


class GuitarFreaks1st(GuitarFreaksBase):

    name = 'GuitarFreaks 1stMix'
    version = VersionConstants.GUITARFREAKS_1ST
