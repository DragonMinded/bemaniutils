import yaml
from flask import Flask
from typing import Optional, Set

from bemani.backend.iidx import IIDXFactory
from bemani.backend.popn import PopnMusicFactory
from bemani.backend.jubeat import JubeatFactory
from bemani.backend.bishi import BishiBashiFactory
from bemani.backend.danevo import DanceEvolutionFactory
from bemani.backend.ddr import DDRFactory
from bemani.backend.sdvx import SoundVoltexFactory
from bemani.backend.reflec import ReflecBeatFactory
from bemani.backend.museca import MusecaFactory
from bemani.backend.mga import MetalGearArcadeFactory
from bemani.common import GameConstants, cache
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


def instantiate_cache(config: Config, app: Optional[Flask] = None) -> None:
    # Possibly set up a dummy app context because flask-caching needs it.
    if app is None:
        app = Flask(__name__)

    # This could easily be extended to add support for any other backend that flask-caching
    # supports but right now the only demand is for in-memory, filesystem and memcached.
    if config.memcached_server is not None:
        cache.init_app(
            app,
            config={
                "CACHE_TYPE": "MemcachedCache",
                "CACHE_MEMCACHED_SERVERS": [config.memcached_server],
            },
        )
    elif config.cache_dir is not None:
        cache.init_app(
            app,
            config={
                "CACHE_TYPE": "FileSystemCache",
                "CACHE_DIR": config.cache_dir,
            },
        )
    else:
        cache.init_app(
            app,
            config={
                "CACHE_TYPE": "SimpleCache",
            },
        )


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
    if GameConstants.DANCE_EVOLUTION in config.support:
        DanceEvolutionFactory.register_all()
