from typing import Dict, Optional, Any

from bemani.backend.base import Base, Factory
from bemani.backend.dm.dmv8 import DrummaniaV8
from bemani.backend.dm.dmv7 import DrummaniaV7
from bemani.backend.dm.dmv6 import DrummaniaV6
from bemani.backend.dm.dmv5 import DrummaniaV5
from bemani.backend.dm.dmv4 import DrummaniaV4

from bemani.backend.dm.stubs import (
    Drummania1st,
    Drummania2nd,
    Drummania3rd,
    Drummania4th,
    Drummania5th,
    Drummania6th,
    Drummania7th,
    Drummania8th,
    Drummania9th,
    Drummania10th,
    DrummaniaV,
    DrummaniaV2,
    DrummaniaV3,
)
from bemani.common import Model, VersionConstants
from bemani.data import Data


class DrummaniaFactory(Factory):

    MANAGED_CLASSES = [
        Drummania1st,
        Drummania2nd,
        Drummania3rd,
        Drummania4th,
        Drummania5th,
        Drummania6th,
        Drummania7th,
        Drummania8th,
        Drummania9th,
        Drummania10th,
        DrummaniaV,
        DrummaniaV2,
        DrummaniaV3,
        DrummaniaV4,
        DrummaniaV5,
        DrummaniaV6,
        DrummaniaV7,
        DrummaniaV8,
    ]

    @classmethod
    def register_all(cls) -> None:
        for game in ['E02', 'F02', 'F32', 'G32', 'H32', 'I32', 'J32', 'K32']:
            Base.register(game, DrummaniaFactory)

    @classmethod
    def create(cls, data: Data, config: Dict[str, Any], model: Model, parentmodel: Optional[Model]=None) -> Optional[Base]:
        if model.game == 'E02':
            return DrummaniaV(data, config, model)
        if model.game == 'F02':
            return DrummaniaV2(data, config, model)
        if model.game == 'F32':
            return DrummaniaV3(data, config, model)
        if model.game == 'G32':
            return DrummaniaV4(data, config, model)
        if model.game == 'H32':
            return DrummaniaV5(data, config, model)
        if model.game == 'I32':
            return DrummaniaV6(data, config, model)
        if model.game == 'J32':
            return DrummaniaV7(data, config, model)
        if model.game == 'K32':
            return DrummaniaV8(data, config, model)

        # Unknown game
        return None
