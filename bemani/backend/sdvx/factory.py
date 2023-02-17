from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.sdvx.booth import SoundVoltexBooth
from bemani.backend.sdvx.infiniteinfection import SoundVoltexInfiniteInfection
from bemani.backend.sdvx.gravitywars import SoundVoltexGravityWars
from bemani.backend.sdvx.gravitywars_s1 import SoundVoltexGravityWarsSeason1
from bemani.backend.sdvx.gravitywars_s2 import SoundVoltexGravityWarsSeason2
from bemani.backend.sdvx.heavenlyhaven import SoundVoltexHeavenlyHaven
from bemani.common import Model, VersionConstants
from bemani.data import Config, Data


class SoundVoltexFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        SoundVoltexBooth,
        SoundVoltexInfiniteInfection,
        SoundVoltexGravityWars,
        SoundVoltexHeavenlyHaven,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["KFC"]:
            Base.register(gamecode, SoundVoltexFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date < 2013060500:
                return VersionConstants.SDVX_BOOTH
            elif date >= 2013060500 and date < 2014112000:
                return VersionConstants.SDVX_INFINITE_INFECTION
            elif date >= 2014112000 and date < 2016122100:
                return VersionConstants.SDVX_GRAVITY_WARS
            elif date >= 2016122100:
                return VersionConstants.SDVX_HEAVENLY_HAVEN
            return None

        if model.gamecode == "KFC":
            if model.version is None:
                if parentmodel is None:
                    return None

                # We have no way to tell apart newer versions. However, we can make
                # an educated guess if we happen to be summoned for old profile lookup.
                if parentmodel.gamecode != "KFC":
                    return None

                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.SDVX_INFINITE_INFECTION:
                    return SoundVoltexBooth(data, config, model)
                if parentversion == VersionConstants.SDVX_GRAVITY_WARS:
                    return SoundVoltexInfiniteInfection(data, config, model)
                if parentversion == VersionConstants.SDVX_HEAVENLY_HAVEN:
                    # We return the generic here because this is usually for profile
                    # checks, which means we only care about existence.
                    return SoundVoltexGravityWars(data, config, model)

                # Unknown older version
                return None

        version = version_from_date(model.version)
        if version == VersionConstants.SDVX_BOOTH:
            return SoundVoltexBooth(data, config, model)
        if version == VersionConstants.SDVX_INFINITE_INFECTION:
            return SoundVoltexInfiniteInfection(data, config, model)
        if version == VersionConstants.SDVX_GRAVITY_WARS:
            # Determine which season
            if model.version < 2015120400:
                return SoundVoltexGravityWarsSeason1(data, config, model)
            else:
                return SoundVoltexGravityWarsSeason2(data, config, model)
        if version == VersionConstants.SDVX_HEAVENLY_HAVEN:
            return SoundVoltexHeavenlyHaven(data, config, model)

        # Unknown game
        return None
