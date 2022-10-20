import yaml
from typing import Set

from bemani.backend.iidx import IIDXFactory
from bemani.backend.popn import PopnMusicFactory
from bemani.backend.jubeat import JubeatFactory
from bemani.backend.bishi import BishiBashiFactory
from bemani.backend.ddr import DDRFactory
from bemani.backend.sdvx import SoundVoltexFactory
from bemani.backend.reflec import ReflecBeatFactory
from bemani.backend.museca import MusecaFactory
from bemani.backend.mga import MetalGearArcadeFactory
from bemani.common import GameConstants
from bemani.data import Config, Data


def load_config(filename: str, config: Config) -> None:
    config.update(yaml.safe_load(open(filename)))
    config["database"]["engine"] = Data.create_engine(config)
    config["filename"] = filename

    supported_series: Set[GameConstants] = set()
    for series in GameConstants:
        if config.get("support", {}).get(series.value, False):
            supported_series.add(series)
    config["support"] = supported_series


def register_games(config: Config) -> None:
    if GameConstants.POPN_MUSIC in config.support:
        PopnMusicFactory.register_all()
    if GameConstants.JUBEAT in config.support:
        JubeatFactory.register_all()
    if GameConstants.IIDX in config.support:
        IIDXFactory.register_all()
    if GameConstants.BISHI_BASHI in config.support:
        BishiBashiFactory.register_all()
    if GameConstants.DDR in config.support:
        DDRFactory.register_all()
    if GameConstants.SDVX in config.support:
        SoundVoltexFactory.register_all()
    if GameConstants.REFLEC_BEAT in config.support:
        ReflecBeatFactory.register_all()
    if GameConstants.MUSECA in config.support:
        MusecaFactory.register_all()
    if GameConstants.MGA in config.support:
        MetalGearArcadeFactory.register_all()
