from typing import Dict, Optional, Any

from bemani.backend.base import Base, Factory
from bemani.backend.bishi.bishi import TheStarBishiBashi
from bemani.common import Model
from bemani.data import Data


class BishiBashiFactory(Factory):

    MANAGED_CLASSES = [
        TheStarBishiBashi,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ['IBB']:
            Base.register(gamecode, BishiBashiFactory)

    @classmethod
    def create(cls, data: Data, config: Dict[str, Any], model: Model, parentmodel: Optional[Model]=None) -> Optional[Base]:

        if model.gamecode == 'IBB':
            return TheStarBishiBashi(data, config, model)

        # Unknown game version
        return None
