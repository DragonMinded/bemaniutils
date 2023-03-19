from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.ddr.stubs import (
    DDRX,
    DDRSuperNova2,
    DDRSuperNova,
    DDRExtreme,
    DDR7thMix,
    DDR6thMix,
    DDR5thMix,
    DDR4thMix,
    DDR3rdMix,
    DDR2ndMix,
    DDR1stMix,
)
from bemani.backend.ddr.ddrx2 import DDRX2
from bemani.backend.ddr.ddrx3 import DDRX3
from bemani.backend.ddr.ddr2013 import DDR2013
from bemani.backend.ddr.ddr2014 import DDR2014
from bemani.backend.ddr.ddrace import DDRAce
from bemani.backend.ddr.ddra20 import DDRA20
from bemani.common import Model, VersionConstants
from bemani.data import Config, Data


class DDRFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        DDR1stMix,
        DDR2ndMix,
        DDR4thMix,
        DDR3rdMix,
        DDR5thMix,
        DDR6thMix,
        DDR7thMix,
        DDRExtreme,
        DDRSuperNova,
        DDRSuperNova2,
        DDRX,
        DDRX2,
        DDRX3,
        DDR2013,
        DDR2014,
        DDRAce,
        DDRA20,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["HDX", "JDX", "KDX", "MDX"]:
            Base.register(gamecode, DDRFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date < 2014051200:
                return VersionConstants.DDR_2013
            elif date >= 2014051200 and date < 2016033000:
                return VersionConstants.DDR_2014
            elif date >= 2016033000 and date < 2019042300:
                return VersionConstants.DDR_ACE
            elif date >= 2019042300:
                return VersionConstants.DDR_A20
            return None

        if model.gamecode == "HDX":
            return DDRX(data, config, model)
        if model.gamecode == "JDX":
            return DDRX2(data, config, model)
        if model.gamecode == "KDX":
            return DDRX3(data, config, model)
        if model.gamecode == "MDX":
            if model.version is None:
                if parentmodel is None:
                    return None

                # We have no way to tell apart newer versions. However, we can make
                # an educated guess if we happen to be summoned for old profile lookup.
                if parentmodel.gamecode not in ["HDX", "JDX", "KDX", "MDX"]:
                    return None

                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.DDR_A20:
                    return DDRAce(data, config, model)
                if parentversion == VersionConstants.DDR_ACE:
                    return DDR2014(data, config, model)
                if parentversion == VersionConstants.DDR_2014:
                    return DDR2013(data, config, model)
                if parentversion == VersionConstants.DDR_2013:
                    return DDRX3(data, config, model)

                # Unknown older version
                return None

            version = version_from_date(model.version)
            if version == VersionConstants.DDR_2013:
                return DDR2013(data, config, model)
            if version == VersionConstants.DDR_2014:
                return DDR2014(data, config, model)
            if version == VersionConstants.DDR_ACE:
                return DDRAce(data, config, model)
            if version == VersionConstants.DDR_A20:
                return DDRA20(data, config, model)

        # Unknown game version
        return None
