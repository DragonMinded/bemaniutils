from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.jubeat.stubs import (
    Jubeat,
    JubeatRipples,
    JubeatRipplesAppend,
    JubeatKnit,
    JubeatKnitAppend,
    JubeatCopious,
    JubeatCopiousAppend,
)
from bemani.backend.jubeat.saucer import JubeatSaucer
from bemani.backend.jubeat.saucerfulfill import JubeatSaucerFulfill
from bemani.backend.jubeat.prop import JubeatProp
from bemani.backend.jubeat.qubell import JubeatQubell
from bemani.backend.jubeat.clan import JubeatClan
from bemani.backend.jubeat.festo import JubeatFesto
from bemani.backend.jubeat.avenue import JubeatAvenue
from bemani.common import Model
from bemani.data import Config, Data


class JubeatFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        Jubeat,
        JubeatRipples,
        JubeatRipplesAppend,
        JubeatKnit,
        JubeatKnitAppend,
        JubeatCopious,
        JubeatCopiousAppend,
        JubeatSaucer,
        JubeatSaucerFulfill,
        JubeatProp,
        JubeatQubell,
        JubeatClan,
        JubeatFesto,
        JubeatAvenue,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["H44", "I44", "J44", "K44", "L44"]:
            Base.register(gamecode, JubeatFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        if model.gamecode == "H44":
            return Jubeat(data, config, model)
        if model.gamecode == "I44":
            if model.version >= 2010031800:
                return JubeatRipplesAppend(data, config, model)
            else:
                return JubeatRipples(data, config, model)
        if model.gamecode == "J44":
            if model.version >= 2011032300:
                return JubeatKnitAppend(data, config, model)
            else:
                return JubeatKnit(data, config, model)
        if model.gamecode == "K44":
            if model.version >= 2012031400:
                return JubeatCopiousAppend(data, config, model)
            else:
                return JubeatCopious(data, config, model)
        if model.gamecode == "L44":
            if model.version <= 2014022400:
                return JubeatSaucer(data, config, model)
            if model.version >= 2014030300 and model.version < 2015022000:
                return JubeatSaucerFulfill(data, config, model)
            if model.version >= 2015022000 and model.version < 2016033000:
                return JubeatProp(data, config, model)
            if model.version >= 2016033000 and model.version < 2017062600:
                return JubeatQubell(data, config, model)
            if model.version >= 2017062600 and model.version < 2018090500:
                return JubeatClan(data, config, model)
            if model.version >= 2018090500 and model.version < 2022080300:
                return JubeatFesto(data, config, model)
            if model.version >= 2022080300:
                return JubeatAvenue(data, config, model)

        # Unknown game version
        return None
