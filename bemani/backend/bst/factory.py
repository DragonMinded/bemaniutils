from typing import Dict, Optional, Any

from bemani.backend.base import Base, Factory
from bemani.backend.bst.beatstream2 import Beatstream2
from bemani.backend.bst.beatstream import Beatstream
from bemani.common import Model
from bemani.data import Data

class BSTFactory(Factory):

    MANAGED_CLASSES = [
        Beatstream2,
    ]

    @classmethod
    def register_all(cls) -> None:
        for game in ['NBT']:
            Base.register(game, BSTFactory)

    @classmethod
    def create(cls, data: Data, config: Dict[str, Any], model: Model, parentmodel: Optional[Model]=None) -> Optional[Base]:
        
        if model.gamecode == 'NBT':
            if model.version is None:
                return None   
            if model.version <= 2015121600:  # Beatstream 1
                return Beatstream(data, config, model)
            if model.version <= 2016111400 and model.version > 2015121600:   # Beatstream 2
                return Beatstream2(data, config, model)
        
        # Unknown game version
        return None
