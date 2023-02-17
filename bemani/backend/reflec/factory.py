from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.reflec.reflecbeat import ReflecBeat
from bemani.backend.reflec.limelight import ReflecBeatLimelight
from bemani.backend.reflec.colette import ReflecBeatColette
from bemani.backend.reflec.groovin import ReflecBeatGroovin
from bemani.backend.reflec.volzza import ReflecBeatVolzza
from bemani.backend.reflec.volzza2 import ReflecBeatVolzza2
from bemani.common import Model, VersionConstants
from bemani.data import Config, Data


class ReflecBeatFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        ReflecBeat,
        ReflecBeatLimelight,
        ReflecBeatColette,
        ReflecBeatGroovin,
        ReflecBeatVolzza,
        ReflecBeatVolzza2,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["KBR", "LBR", "MBR"]:
            Base.register(gamecode, ReflecBeatFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date < 2014060400:
                return VersionConstants.REFLEC_BEAT_COLETTE
            if date >= 2014060400 and date < 2015102800:
                return VersionConstants.REFLEC_BEAT_GROOVIN
            if date >= 2015102800 and date < 2016032400:
                return VersionConstants.REFLEC_BEAT_VOLZZA
            if date >= 2016032400 and date < 2016120100:
                return VersionConstants.REFLEC_BEAT_VOLZZA_2
            if date >= 2016120100:
                return VersionConstants.REFLEC_BEAT_REFLESIA
            return None

        if model.gamecode == "KBR":
            return ReflecBeat(data, config, model)
        if model.gamecode == "LBR":
            return ReflecBeatLimelight(data, config, model)
        if model.gamecode == "MBR":
            if model.version is None:
                if parentmodel is None:
                    return None

                if parentmodel.gamecode not in ["KBR", "LBR", "MBR"]:
                    return None
                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.REFLEC_BEAT_COLETTE:
                    return ReflecBeatLimelight(data, config, model)
                if parentversion == VersionConstants.REFLEC_BEAT_GROOVIN:
                    return ReflecBeatColette(data, config, model)
                if parentversion == VersionConstants.REFLEC_BEAT_VOLZZA:
                    return ReflecBeatGroovin(data, config, model)
                if parentversion == VersionConstants.REFLEC_BEAT_VOLZZA_2:
                    return ReflecBeatVolzza(data, config, model)

                # Unknown older version
                return None

            version = version_from_date(model.version)
            if version == VersionConstants.REFLEC_BEAT_COLETTE:
                return ReflecBeatColette(data, config, model)
            if version == VersionConstants.REFLEC_BEAT_GROOVIN:
                return ReflecBeatGroovin(data, config, model)
            if version == VersionConstants.REFLEC_BEAT_VOLZZA:
                return ReflecBeatVolzza(data, config, model)
            if version == VersionConstants.REFLEC_BEAT_VOLZZA_2:
                return ReflecBeatVolzza2(data, config, model)

        # Unknown game version
        return None
