from typing import Optional
from bemani.backend.base import Base, Factory
from bemani.backend.gitadora.stubs import Gitadora
from bemani.backend.gitadora.stubs import GitadoraOverDrive
from bemani.backend.gitadora.stubs import GitadoraTriBoost
from bemani.backend.gitadora.stubs import GitadoraTriBoostReEVOLVE
from bemani.backend.gitadora.stubs import GitadoraMatixx
from bemani.backend.gitadora.stubs import GitadoraExchain
from bemani.backend.gitadora.nextage import GitadoraNextage
from bemani.backend.gitadora.highvoltage import GitadoraHighVoltage
from bemani.backend.gitadora.fuzzup import GitadoraFuzzUp
from bemani.backend.gitadora.galaxywave import GitadoraGalaxyWave
from bemani.common import Model, VersionConstants
from bemani.data import Data, Config


class GitadoraFactory(Factory):
    MANAGED_CLASSES = [
        Gitadora,
        GitadoraOverDrive,
        GitadoraTriBoost,
        GitadoraTriBoostReEVOLVE,
        GitadoraMatixx,
        GitadoraExchain,
        GitadoraNextage,
        GitadoraHighVoltage,
        GitadoraFuzzUp,
        GitadoraGalaxyWave,
    ]

    @classmethod
    def register_all(cls) -> None:
        for game in ["M32"]:
            Base.register(game, GitadoraFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date >= 2013021400 and date < 2014030500:
                return VersionConstants.GITADORA
            elif date >= 2014030500 and date < 2015042100:
                return VersionConstants.GITADORA_OVERDRIVE
            elif date >= 2015042100 and date < 2016121400:
                return VersionConstants.GITADORA_TRIBOOST
            elif date >= 2016121400 and date < 2017090600:
                return VersionConstants.GITADORA_TRIBOOST_RE_EVOLVE
            elif date >= 2017090600 and date < 2018072700:
                return VersionConstants.GITADORA_MATIXX
            elif date >= 2018072700 and date < 2019092400:
                return VersionConstants.GITADORA_EXCHAIN
            elif date >= 2019100200 and date < 2021042100:
                return VersionConstants.GITADORA_NEXTAGE
            elif date >= 2021042100 and date < 2022121400:
                return VersionConstants.GITADORA_HIGH_VOLTAGE
            elif date >= 2022121400 and date < 2024031300:
                return VersionConstants.GITADORA_FUZZUP
            elif date >= 2024031300:
                return VersionConstants.GITADORA_GALAXYWAVE
            return None

        if model.gamecode == "M32":
            if model.version is None:
                if parentmodel is None:
                    return None

                # We have no way to tell apart newer versions. However, we can make
                # an educated guess if we happen to be summoned for old profile lookup.
                if parentmodel.gamecode != "M32":
                    return None

                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.GITADORA_OVERDRIVE:
                    return Gitadora(data, config, model)
                if parentversion == VersionConstants.GITADORA_TRIBOOST:
                    return GitadoraOverDrive(data, config, model)
                if parentversion == VersionConstants.GITADORA_TRIBOOST_RE_EVOLVE:
                    return GitadoraTriBoost(data, config, model)
                if parentversion == VersionConstants.GITADORA_MATIXX:
                    return GitadoraTriBoostReEVOLVE(data, config, model)
                if parentversion == VersionConstants.GITADORA_EXCHAIN:
                    return GitadoraMatixx(data, config, model)
                if parentversion == VersionConstants.GITADORA_NEXTAGE:
                    return GitadoraExchain(data, config, model)
                if parentversion == VersionConstants.GITADORA_HIGH_VOLTAGE:
                    return GitadoraNextage(data, config, model)
                if parentversion == VersionConstants.GITADORA_FUZZUP:
                    return GitadoraHighVoltage(data, config, model)
                if parentversion == VersionConstants.GITADORA_GALAXYWAVE:
                    return GitadoraFuzzUp(data, config, model)
                # Unknown older version
                return None

            version = version_from_date(model.version)
            if version == VersionConstants.GITADORA:
                return Gitadora(data, config, model)
            if version == VersionConstants.GITADORA_OVERDRIVE:
                return GitadoraOverDrive(data, config, model)
            if version == VersionConstants.GITADORA_TRIBOOST:
                return GitadoraTriBoost(data, config, model)
            if version == VersionConstants.GITADORA_TRIBOOST_RE_EVOLVE:
                return GitadoraTriBoostReEVOLVE(data, config, model)
            if version == VersionConstants.GITADORA_MATIXX:
                return GitadoraMatixx(data, config, model)
            if version == VersionConstants.GITADORA_EXCHAIN:
                return GitadoraExchain(data, config, model)
            if version == VersionConstants.GITADORA_NEXTAGE:
                return GitadoraNextage(data, config, model)
            if version == VersionConstants.GITADORA_HIGH_VOLTAGE:
                return GitadoraHighVoltage(data, config, model)
            if version == VersionConstants.GITADORA_FUZZUP:
                return GitadoraFuzzUp(data, config, model)
            if version == VersionConstants.GITADORA_GALAXYWAVE:
                return GitadoraGalaxyWave(data, config, model)
        # Unknown game version
        return None
