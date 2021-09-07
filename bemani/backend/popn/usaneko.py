# vim: set fileencoding=utf-8
from typing import Dict

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.common import PopnMusicModernBase
from bemani.backend.popn.eclale import PopnMusicEclale
from bemani.common import VersionConstants


class PopnMusicUsaNeko(PopnMusicModernBase):

    name = "Pop'n Music うさぎと猫と少年の夢"
    version = VersionConstants.POPN_MUSIC_USANEKO

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID = 1704

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicEclale(self.data, self.config, self.model)

    def get_phases(self) -> Dict[int, int]:
        # Event phases
        # TODO: Hook event mode settings up to the front end.
        return {
            # Default song phase availability (0-11)
            0: 11,
            # Unknown event (0-2)
            1: 0, #Same holiday event as peace, will move to front end along with peace's
            # Unknown event (0-2)
            2: 2,
            # Unknown event (0-4)
            3: 4,
            # Unknown event (0-1)
            4: 1,
            # Enable Net Taisen, including win/loss display on song select (0-1)
            5: 1,
            # Enable NAVI-kun shunkyoku toujou, allows song 1608 to be unlocked (0-1)
            6: 1,
            # Unknown event (0-1)
            7: 1,
            # Unknown event (0-2)
            8: 2,
            # Daily Mission (0-2)
            9: 2,
            # NAVI-kun Song phase availability (0-15)
            10: 15,
            # Unknown event (0-1)
            11: 1,
            # Unknown event (0-2)
            12: 2,
            # Enable Pop'n Peace preview song (0-1)
            13: 1,
        }
