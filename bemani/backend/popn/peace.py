# vim: set fileencoding=utf-8
from typing import Dict, Tuple

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.common import PopnMusicModernBase
from bemani.backend.popn.usaneko import PopnMusicUsaNeko
from bemani.common import VersionConstants


class PopnMusicPeace(PopnMusicModernBase):

    name: str = "Pop'n Music peace"
    version: int = VersionConstants.POPN_MUSIC_PEACE

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: int = 1877

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicUsaNeko(self.data, self.config, self.model)

    def get_common_config(self) -> Tuple[Dict[int, int], bool]:
        # Event phases
        # TODO: Hook event mode settings up to the front end.
        return (
            {
                # Default song phase availability (0-23)
                0: 23,
                # Unknown event (0-2)
                1: 2,
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
                # NAVI-kun Song phase availability (0-30)
                10: 30,
                # Unknown event (0-1)
                11: 1,
                # Unknown event (0-2)
                12: 2,
                # Enable Pop'n Peace preview song (0-1)
                13: 1,
                # Unknown event (0-39)
                14: 39,
                # Unknown event (0-2)
                15: 2,
                # Unknown event (0-3)
                16: 3,
                # Unknown event (0-8)
                17: 8,
                # Unknown event (0-1)
                28: 1,
                # Unknown event (0-1)
                19: 1,
                # Unknown event (0-13)
                20: 13,
                # Pop'n event archive song phase availability (0-20)
                21: 20,
                # Unknown event (0-2)
                22: 2,
                # Unknown event (0-1)
                23: 1,
                # Unknown event (0-1)
                24: 1,
            },
            False,
        )
