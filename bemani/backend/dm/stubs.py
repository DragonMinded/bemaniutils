from typing import Optional

from bemani.backend.dm.base import DrummaniaBase
from bemani.common import VersionConstants



class DrummaniaV7(DrummaniaBase):

    name = 'Drummania V7'
    version = VersionConstants.DRUMMANIA_V7

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV6(self.data, self.config, self.model)


class DrummaniaV6(DrummaniaBase):

    name = 'Drummania V6'
    version = VersionConstants.DRUMMANIA_V6

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV5(self.data, self.config, self.model)


class DrummaniaV5(DrummaniaBase):

    name = 'Drummania V5'
    version = VersionConstants.DRUMMANIA_V5

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV4(self.data, self.config, self.model)


class DrummaniaV4(DrummaniaBase):

    name = 'Drummania V4'
    version = VersionConstants.DRUMMANIA_V4

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV4(self.data, self.config, self.model)


class DrummaniaV3(DrummaniaBase):

    name = 'Drummania V3'
    version = VersionConstants.DRUMMANIA_V3

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV2(self.data, self.config, self.model)


class DrummaniaV2(DrummaniaBase):

    name = 'Drummania V2'
    version = VersionConstants.DRUMMANIA_V2

    def previous_version(self) -> Optional[DrummaniaBase]:
        return DrummaniaV(self.data, self.config, self.model)


class DrummaniaV(DrummaniaBase):

    name = 'Drummania V'
    version = VersionConstants.DRUMMANIA_V

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania10th(self.data, self.config, self.model)



class Drummania10th(DrummaniaBase):

    name = 'Drummania 10thMix'
    version = VersionConstants.DRUMMANIA_10TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania9th(self.data, self.config, self.model)


class Drummania9th(DrummaniaBase):

    name = 'Drummania 9thMix'
    version = VersionConstants.DRUMMANIA_9TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania8th(self.data, self.config, self.model)


class Drummania8th(DrummaniaBase):

    name = 'Drummania 8thMix'
    version = VersionConstants.DRUMMANIA_8TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania7th(self.data, self.config, self.model)


class Drummania7th(DrummaniaBase):

    name = 'Drummania 7thMix'
    version = VersionConstants.DRUMMANIA_7TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania6th(self.data, self.config, self.model)


class Drummania6th(DrummaniaBase):

    name = 'Drummania 6thMix'
    version = VersionConstants.DRUMMANIA_6TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania5th(self.data, self.config, self.model)


class Drummania5th(DrummaniaBase):

    name = 'Drummania 5thMix'
    version = VersionConstants.DRUMMANIA_5TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania4th(self.data, self.config, self.model)


class Drummania4th(DrummaniaBase):

    name = 'Drummania 4thMix'
    version = VersionConstants.DRUMMANIA_4TH

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania3rd(self.data, self.config, self.model)


class Drummania3rd(DrummaniaBase):

    name = 'Drummania 3rdMix'
    version = VersionConstants.DRUMMANIA_3RD

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania2nd(self.data, self.config, self.model)


class Drummania2nd(DrummaniaBase):

    name = 'Drummania 2ndMix'
    version = VersionConstants.DRUMMANIA_2ND

    def previous_version(self) -> Optional[DrummaniaBase]:
        return Drummania1st(self.data, self.config, self.model)


class Drummania1st(DrummaniaBase):

    name = 'Drummania 1stMix'
    version = VersionConstants.DRUMMANIA_1ST
