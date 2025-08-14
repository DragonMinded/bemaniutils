import argparse
from typing import Any, List

from bemani.backend.popn import PopnMusicFactory
from bemani.backend.jubeat import JubeatFactory
from bemani.backend.iidx import IIDXFactory
from bemani.backend.bishi import BishiBashiFactory
from bemani.backend.mga import MetalGearArcadeFactory
from bemani.backend.ddr import DDRFactory
from bemani.backend.sdvx import SoundVoltexFactory
from bemani.backend.reflec import ReflecBeatFactory
from bemani.backend.museca import MusecaFactory
from bemani.backend.danevo import DanceEvolutionFactory
from bemani.frontend.popn import PopnMusicCache
from bemani.frontend.iidx import IIDXCache
from bemani.frontend.jubeat import JubeatCache
from bemani.frontend.bishi import BishiBashiCache
from bemani.frontend.mga import MetalGearArcadeCache
from bemani.frontend.ddr import DDRCache
from bemani.frontend.sdvx import SoundVoltexCache
from bemani.frontend.reflec import ReflecBeatCache
from bemani.frontend.museca import MusecaCache
from bemani.common import GameConstants, Time
from bemani.data import Config, Data
from bemani.utils.config import load_config, instantiate_cache


def run_scheduled_work(config: Config) -> None:
    data = Data(config)

    # Only run scheduled work for enabled components
    enabled_factories: List[Any] = []
    enabled_caches: List[Any] = []
    if GameConstants.IIDX in config.support:
        enabled_factories.append(IIDXFactory)
        enabled_caches.append(IIDXCache)
    if GameConstants.POPN_MUSIC in config.support:
        enabled_factories.append(PopnMusicFactory)
        enabled_caches.append(PopnMusicCache)
    if GameConstants.JUBEAT in config.support:
        enabled_factories.append(JubeatFactory)
        enabled_caches.append(JubeatCache)
    if GameConstants.BISHI_BASHI in config.support:
        enabled_factories.append(BishiBashiFactory)
        enabled_caches.append(BishiBashiCache)
    if GameConstants.MGA in config.support:
        enabled_factories.append(MetalGearArcadeFactory)
        enabled_caches.append(MetalGearArcadeCache)
    if GameConstants.DDR in config.support:
        enabled_factories.append(DDRFactory)
        enabled_caches.append(DDRCache)
    if GameConstants.SDVX in config.support:
        enabled_factories.append(SoundVoltexFactory)
        enabled_caches.append(SoundVoltexCache)
    if GameConstants.REFLEC_BEAT in config.support:
        enabled_factories.append(ReflecBeatFactory)
        enabled_caches.append(ReflecBeatCache)
    if GameConstants.MUSECA in config.support:
        enabled_factories.append(MusecaFactory)
        enabled_caches.append(MusecaCache)
    if GameConstants.DANCE_EVOLUTION in config.support:
        enabled_factories.append(DanceEvolutionFactory)
        # TODO: Frontend cache here.

    # First, run any backend scheduled work
    for factory in enabled_factories:
        factory.run_scheduled_work(data, config)

    # Now, warm the caches for the frontend
    for cache in enabled_caches:
        cache.preload(data, config)

    # Now, possibly delete old log entries
    keep_duration = config.get("event_log_duration", 0)
    if keep_duration > 0:
        # Calculate timestamp of events we should delete
        oldest_event = Time.now() - keep_duration
        data.local.network.delete_events(oldest_event)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A scheduler for work that needs to be done periodically.")
    parser.add_argument(
        "-c",
        "--config",
        help="Core configuration. Defaults to server.yaml",
        type=str,
        default="server.yaml",
    )
    parser.add_argument(
        "-o",
        "--read-only",
        action="store_true",
        help="Force the database into read-only mode.",
    )
    args = parser.parse_args()

    # Set up global configuration
    config = Config()
    load_config(args.config, config)
    if args.read_only:
        config["database"]["read_only"] = True

    # Set up production cache.
    instantiate_cache(config)

    # Run out of band work
    run_scheduled_work(config)
