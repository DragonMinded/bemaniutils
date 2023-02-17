from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.iidx.stubs import (
    IIDX1stStyle,
    IIDX2ndStyle,
    IIDX3rdStyle,
    IIDX4thStyle,
    IIDX5thStyle,
    IIDX6thStyle,
    IIDX7thStyle,
    IIDX8thStyle,
    IIDX9thStyle,
    IIDX10thStyle,
    IIDXRed,
    IIDXHappySky,
    IIDXDistorted,
    IIDXGold,
    IIDXDJTroopers,
    IIDXEmpress,
    IIDXSirius,
    IIDXResortAnthem,
    IIDXLincle,
)
from bemani.backend.iidx.tricoro import IIDXTricoro
from bemani.backend.iidx.spada import IIDXSpada
from bemani.backend.iidx.pendual import IIDXPendual
from bemani.backend.iidx.copula import IIDXCopula
from bemani.backend.iidx.sinobuz import IIDXSinobuz
from bemani.backend.iidx.cannonballers import IIDXCannonBallers
from bemani.backend.iidx.rootage import IIDXRootage
from bemani.backend.iidx.heroicverse import IIDXHeroicVerse
from bemani.backend.iidx.bistrover import IIDXBistrover
from bemani.common import Model, VersionConstants
from bemani.data import Config, Data


class IIDXFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        IIDX1stStyle,
        IIDX2ndStyle,
        IIDX3rdStyle,
        IIDX4thStyle,
        IIDX5thStyle,
        IIDX6thStyle,
        IIDX7thStyle,
        IIDX8thStyle,
        IIDX9thStyle,
        IIDX10thStyle,
        IIDXRed,
        IIDXHappySky,
        IIDXDistorted,
        IIDXGold,
        IIDXDJTroopers,
        IIDXEmpress,
        IIDXSirius,
        IIDXResortAnthem,
        IIDXLincle,
        IIDXTricoro,
        IIDXSpada,
        IIDXPendual,
        IIDXCopula,
        IIDXSinobuz,
        IIDXCannonBallers,
        IIDXRootage,
        IIDXHeroicVerse,
        IIDXBistrover,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["JDJ", "JDZ", "KDZ", "LDJ"]:
            Base.register(gamecode, IIDXFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date < 2013100200:
                return VersionConstants.IIDX_TRICORO
            if date >= 2013100200 and date < 2014091700:
                return VersionConstants.IIDX_SPADA
            if date >= 2014091700 and date < 2015111100:
                return VersionConstants.IIDX_PENDUAL
            if date >= 2015111100 and date < 2016102600:
                return VersionConstants.IIDX_COPULA
            if date >= 2016102600 and date < 2017122100:
                return VersionConstants.IIDX_SINOBUZ
            if date >= 2017122100 and date < 2018110700:
                return VersionConstants.IIDX_CANNON_BALLERS
            if date >= 2018110700 and date < 2019101600:
                return VersionConstants.IIDX_ROOTAGE
            if date >= 2019101600 and date < 2020102800:
                return VersionConstants.IIDX_HEROIC_VERSE
            if date >= 2020102800:
                return VersionConstants.IIDX_BISTROVER
            return None

        if model.gamecode == "JDJ":
            return IIDXSirius(data, config, model)
        if model.gamecode == "JDZ":
            return IIDXResortAnthem(data, config, model)
        if model.gamecode == "KDZ":
            return IIDXLincle(data, config, model)
        if model.gamecode == "LDJ":
            if model.version is None:
                if parentmodel is None:
                    return None

                # We have no way to tell apart newer versions. However, we can make
                # an educated guess if we happen to be summoned for old profile lookup.
                if parentmodel.gamecode not in ["JDJ", "JDZ", "KDZ", "LDJ"]:
                    return None
                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.IIDX_SPADA:
                    return IIDXTricoro(data, config, model)
                if parentversion == VersionConstants.IIDX_PENDUAL:
                    return IIDXSpada(data, config, model)
                if parentversion == VersionConstants.IIDX_COPULA:
                    return IIDXPendual(data, config, model)
                if parentversion == VersionConstants.IIDX_SINOBUZ:
                    return IIDXCopula(data, config, model)
                if parentversion == VersionConstants.IIDX_CANNON_BALLERS:
                    return IIDXSinobuz(data, config, model)
                if parentversion == VersionConstants.IIDX_ROOTAGE:
                    return IIDXCannonBallers(data, config, model)
                if parentversion == VersionConstants.IIDX_HEROIC_VERSE:
                    return IIDXRootage(data, config, model)
                if parentversion == VersionConstants.IIDX_BISTROVER:
                    return IIDXHeroicVerse(data, config, model)

                # Unknown older version
                return None

            version = version_from_date(model.version)
            if version == VersionConstants.IIDX_TRICORO:
                return IIDXTricoro(data, config, model)
            if version == VersionConstants.IIDX_SPADA:
                return IIDXSpada(data, config, model)
            if version == VersionConstants.IIDX_PENDUAL:
                return IIDXPendual(data, config, model)
            if version == VersionConstants.IIDX_COPULA:
                return IIDXCopula(data, config, model)
            if version == VersionConstants.IIDX_SINOBUZ:
                return IIDXSinobuz(data, config, model)
            if version == VersionConstants.IIDX_CANNON_BALLERS:
                return IIDXCannonBallers(data, config, model)
            if version == VersionConstants.IIDX_ROOTAGE:
                return IIDXRootage(data, config, model)
            if version == VersionConstants.IIDX_HEROIC_VERSE:
                return IIDXHeroicVerse(data, config, model)
            if version == VersionConstants.IIDX_BISTROVER:
                return IIDXBistrover(data, config, model)

        # Unknown game version
        return None
