# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.common import VersionConstants


class PopnMusic(PopnMusicBase):

    name = "Pop'n Music"
    version = VersionConstants.POPN_MUSIC


class PopnMusic2(PopnMusicBase):

    name = "Pop'n Music 2"
    version = VersionConstants.POPN_MUSIC_2

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic(self.data, self.config, self.model)


class PopnMusic3(PopnMusicBase):

    name = "Pop'n Music 3"
    version = VersionConstants.POPN_MUSIC_3

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic2(self.data, self.config, self.model)


class PopnMusic4(PopnMusicBase):

    name = "Pop'n Music 4"
    version = VersionConstants.POPN_MUSIC_4

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic3(self.data, self.config, self.model)


class PopnMusic5(PopnMusicBase):

    name = "Pop'n Music 5"
    version = VersionConstants.POPN_MUSIC_5

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic4(self.data, self.config, self.model)


class PopnMusic6(PopnMusicBase):

    name = "Pop'n Music 6"
    version = VersionConstants.POPN_MUSIC_6

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic5(self.data, self.config, self.model)


class PopnMusic7(PopnMusicBase):

    name = "Pop'n Music 7"
    version = VersionConstants.POPN_MUSIC_7

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic6(self.data, self.config, self.model)


class PopnMusic8(PopnMusicBase):

    name = "Pop'n Music 8"
    version = VersionConstants.POPN_MUSIC_8

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic7(self.data, self.config, self.model)


class PopnMusic9(PopnMusicBase):

    name = "Pop'n Music 9"
    version = VersionConstants.POPN_MUSIC_9

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic8(self.data, self.config, self.model)


class PopnMusic10(PopnMusicBase):

    name = "Pop'n Music 10"
    version = VersionConstants.POPN_MUSIC_10

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic9(self.data, self.config, self.model)


class PopnMusic11(PopnMusicBase):

    name = "Pop'n Music 11"
    version = VersionConstants.POPN_MUSIC_11

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic10(self.data, self.config, self.model)


class PopnMusicIroha(PopnMusicBase):

    name = "Pop'n Music いろは"
    version = VersionConstants.POPN_MUSIC_IROHA

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusic11(self.data, self.config, self.model)


class PopnMusicCarnival(PopnMusicBase):

    name = "Pop'n Music カーニバル"
    version = VersionConstants.POPN_MUSIC_CARNIVAL

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicIroha(self.data, self.config, self.model)


class PopnMusicFever(PopnMusicBase):

    name = "Pop'n Music FEVER!"
    version = VersionConstants.POPN_MUSIC_FEVER

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicCarnival(self.data, self.config, self.model)


class PopnMusicAdventure(PopnMusicBase):

    name = "Pop'n Music ADVENTURE"
    version = VersionConstants.POPN_MUSIC_ADVENTURE

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicFever(self.data, self.config, self.model)


class PopnMusicParty(PopnMusicBase):

    name = "Pop'n Music Party♪"
    version = VersionConstants.POPN_MUSIC_PARTY

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicAdventure(self.data, self.config, self.model)


class PopnMusicTheMovie(PopnMusicBase):

    name = "Pop'n Music THE MOVIE"
    version = VersionConstants.POPN_MUSIC_THE_MOVIE

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicParty(self.data, self.config, self.model)


class PopnMusicSengokuRetsuden(PopnMusicBase):

    name = "Pop'n Music せんごく列伝"
    version = VersionConstants.POPN_MUSIC_SENGOKU_RETSUDEN

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicTheMovie(self.data, self.config, self.model)
