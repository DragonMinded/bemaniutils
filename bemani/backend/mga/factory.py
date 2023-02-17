from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.mga.mga import MetalGearArcade
from bemani.common import Model
from bemani.data import Config, Data


class MetalGearArcadeFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        MetalGearArcade,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["I36"]:
            Base.register(gamecode, MetalGearArcadeFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        if model.gamecode == "I36":
            return MetalGearArcade(data, config, model)

        # Unknown game version
        return None
