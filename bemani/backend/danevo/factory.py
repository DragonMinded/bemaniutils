from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.danevo.danevo import DanceEvolution
from bemani.common import Model
from bemani.data import Config, Data


class DanceEvolutionFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        DanceEvolution,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["KDM"]:
            Base.register(gamecode, DanceEvolutionFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        # There is only one Dance Evolution.
        return DanceEvolution(data, config, model)
