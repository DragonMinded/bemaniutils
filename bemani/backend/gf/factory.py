from typing import Dict, Optional, Any

from bemani.backend.base import Base, Factory
from bemani.backend.gf.gfv8 import GuitarFreaksV8
from bemani.backend.gf.gfv7 import GuitarFreaksV7
from bemani.backend.gf.gfv6 import GuitarFreaksV6
from bemani.backend.gf.gfv5 import GuitarFreaksV5
from bemani.backend.gf.gfv4 import GuitarFreaksV4

from bemani.backend.gf.stubs import (
    GuitarFreaks1st,
    GuitarFreaks2nd,
    GuitarFreaks3rd,
    GuitarFreaks4th,
    GuitarFreaks5th,
    GuitarFreaks6th,
    GuitarFreaks7th,
    GuitarFreaks8th,
    GuitarFreaks9th,
    GuitarFreaks10th,
    GuitarFreaks11th,
    GuitarFreaksV,
    GuitarFreaksV2,
    GuitarFreaksV3,
)
from bemani.common import Model, VersionConstants
from bemani.data import Data


class GuitarFreaksFactory(Factory):

    MANAGED_CLASSES = [
        GuitarFreaks1st,
        GuitarFreaks2nd,
        GuitarFreaks3rd,
        GuitarFreaks4th,
        GuitarFreaks5th,
        GuitarFreaks6th,
        GuitarFreaks7th,
        GuitarFreaks8th,
        GuitarFreaks9th,
        GuitarFreaks10th,
        GuitarFreaks11th,
        GuitarFreaksV,
        GuitarFreaksV2,
        GuitarFreaksV3,
        GuitarFreaksV4,
        GuitarFreaksV5,
        GuitarFreaksV6,
        GuitarFreaksV7,
        GuitarFreaksV8,
    ]

    @classmethod
    def register_all(cls) -> None:
        for game in ['E03', 'F03', 'F33', 'G33', 'H33', 'I33', 'J33', 'K33']:
            Base.register(game, GuitarFreaksFactory)

    @classmethod
    def create(cls, data: Data, config: Dict[str, Any], model: Model, parentmodel: Optional[Model]=None) -> Optional[Base]:
        if model.game == 'E03':
            return GuitarFreaksV(data, config, model)
        if model.game == 'F03':
            return GuitarFreaksV2(data, config, model)
        if model.game == 'F33':
            return GuitarFreaksV3(data, config, model)
        if model.game == 'G33':
            return GuitarFreaksV4(data, config, model)
        if model.game == 'H33':
            return GuitarFreaksV5(data, config, model)
        if model.game == 'I33':
            return GuitarFreaksV6(data, config, model)
        if model.game == 'J33':
            return GuitarFreaksV7(data, config, model)
        if model.game == 'K33':
            return GuitarFreaksV8(data, config, model)

        # Unknown game
        return None
