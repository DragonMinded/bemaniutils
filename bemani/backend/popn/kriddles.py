# vim: set fileencoding=utf-8
from typing import Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.peace import PopnMusicPeace
from bemani.common import VersionConstants


class PopnMusicKRiddles(PopnMusicBase):

    name = "Pop'n Music 解明リドルズ"
    version = VersionConstants.POPN_MUSIC_KRIDDLES

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicPeace(self.data, self.config, self.model)
