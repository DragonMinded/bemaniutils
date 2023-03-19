from typing import List, Optional, Type

from bemani.backend.base import Base, Factory
from bemani.backend.popn.stubs import (
    PopnMusic,
    PopnMusic2,
    PopnMusic3,
    PopnMusic4,
    PopnMusic5,
    PopnMusic6,
    PopnMusic7,
    PopnMusic8,
    PopnMusic9,
    PopnMusic10,
    PopnMusic11,
    PopnMusicIroha,
    PopnMusicCarnival,
    PopnMusicFever,
    PopnMusicAdventure,
    PopnMusicParty,
    PopnMusicTheMovie,
    PopnMusicSengokuRetsuden,
)
from bemani.backend.popn.tunestreet import PopnMusicTuneStreet
from bemani.backend.popn.fantasia import PopnMusicFantasia
from bemani.backend.popn.sunnypark import PopnMusicSunnyPark
from bemani.backend.popn.lapistoria import PopnMusicLapistoria
from bemani.backend.popn.eclale import PopnMusicEclale
from bemani.backend.popn.usaneko import PopnMusicUsaNeko
from bemani.backend.popn.peace import PopnMusicPeace
from bemani.backend.popn.kaimei import PopnMusicKaimei
from bemani.common import Model, VersionConstants
from bemani.data import Config, Data


class PopnMusicFactory(Factory):
    MANAGED_CLASSES: List[Type[Base]] = [
        PopnMusic,
        PopnMusic2,
        PopnMusic3,
        PopnMusic4,
        PopnMusic5,
        PopnMusic6,
        PopnMusic7,
        PopnMusic8,
        PopnMusic9,
        PopnMusic10,
        PopnMusic11,
        PopnMusicIroha,
        PopnMusicCarnival,
        PopnMusicFever,
        PopnMusicAdventure,
        PopnMusicParty,
        PopnMusicTheMovie,
        PopnMusicSengokuRetsuden,
        PopnMusicTuneStreet,
        PopnMusicFantasia,
        PopnMusicSunnyPark,
        PopnMusicLapistoria,
        PopnMusicEclale,
        PopnMusicUsaNeko,
        PopnMusicPeace,
        PopnMusicKaimei,
    ]

    @classmethod
    def register_all(cls) -> None:
        for gamecode in ["G15", "H16", "I17", "J39", "K39", "L39", "M39"]:
            Base.register(gamecode, PopnMusicFactory)

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional[Base]:
        def version_from_date(date: int) -> Optional[int]:
            if date <= 2014061900:
                return VersionConstants.POPN_MUSIC_SUNNY_PARK
            if date >= 2014062500 and date < 2015112600:
                return VersionConstants.POPN_MUSIC_LAPISTORIA
            if date >= 2015112600 and date < 2016121400:
                return VersionConstants.POPN_MUSIC_ECLALE
            if date >= 2016121400 and date < 2018101700:
                return VersionConstants.POPN_MUSIC_USANEKO
            if date >= 2018101700 and date < 2021042600:
                return VersionConstants.POPN_MUSIC_PEACE
            if date >= 2021042600:
                return VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES
            return None

        if model.gamecode == "G15":
            return PopnMusicAdventure(data, config, model)
        if model.gamecode == "H16":
            return PopnMusicParty(data, config, model)
        if model.gamecode == "I17":
            return PopnMusicTheMovie(data, config, model)
        if model.gamecode == "J39":
            return PopnMusicSengokuRetsuden(data, config, model)
        if model.gamecode == "K39":
            return PopnMusicTuneStreet(data, config, model)
        if model.gamecode == "L39":
            return PopnMusicFantasia(data, config, model)
        if model.gamecode == "M39":
            if model.version is None:
                if parentmodel is None:
                    return None

                # We have no way to tell apart newer versions. However, we can make
                # an educated guess if we happen to be summoned for old profile lookup.
                if parentmodel.gamecode not in [
                    "G15",
                    "H16",
                    "I17",
                    "J39",
                    "K39",
                    "L39",
                    "M39",
                ]:
                    return None
                parentversion = version_from_date(parentmodel.version)
                if parentversion == VersionConstants.POPN_MUSIC_LAPISTORIA:
                    return PopnMusicSunnyPark(data, config, model)
                if parentversion == VersionConstants.POPN_MUSIC_ECLALE:
                    return PopnMusicLapistoria(data, config, model)
                if parentversion == VersionConstants.POPN_MUSIC_USANEKO:
                    return PopnMusicEclale(data, config, model)
                if parentversion == VersionConstants.POPN_MUSIC_PEACE:
                    return PopnMusicUsaNeko(data, config, model)
                if parentversion == VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES:
                    return PopnMusicPeace(data, config, model)

                # Unknown older version
                return None

            version = version_from_date(model.version)
            if version == VersionConstants.POPN_MUSIC_SUNNY_PARK:
                return PopnMusicSunnyPark(data, config, model)
            if version == VersionConstants.POPN_MUSIC_LAPISTORIA:
                return PopnMusicLapistoria(data, config, model)
            if version == VersionConstants.POPN_MUSIC_ECLALE:
                return PopnMusicEclale(data, config, model)
            if version == VersionConstants.POPN_MUSIC_USANEKO:
                return PopnMusicUsaNeko(data, config, model)
            if version == VersionConstants.POPN_MUSIC_PEACE:
                return PopnMusicPeace(data, config, model)
            if version == VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES:
                return PopnMusicKaimei(data, config, model)

        # Unknown game version
        return None
