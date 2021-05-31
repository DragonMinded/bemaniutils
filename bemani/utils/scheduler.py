import argparse
import yaml
from typing import Any, Dict, List

from bemani.backend.popn import PopnMusicFactory
from bemani.backend.jubeat import JubeatFactory
from bemani.backend.iidx import IIDXFactory
from bemani.backend.bishi import BishiBashiFactory
from bemani.backend.ddr import DDRFactory
from bemani.backend.sdvx import SoundVoltexFactory
from bemani.backend.reflec import ReflecBeatFactory
from bemani.backend.museca import MusecaFactory
from bemani.frontend.popn import PopnMusicCache
from bemani.frontend.iidx import IIDXCache
from bemani.frontend.jubeat import JubeatCache
from bemani.frontend.bishi import BishiBashiCache
from bemani.frontend.ddr import DDRCache
from bemani.frontend.sdvx import SoundVoltexCache
from bemani.frontend.reflec import ReflecBeatCache
from bemani.frontend.museca import MusecaCache
from bemani.common import GameConstants, Time
from bemani.data import Data


def run_scheduled_work(config: Dict[str, Any]) -> None:
    data = Data(config)

    # Only run scheduled work for enabled components
    enabled_factories: List[Any] = []
    enabled_caches: List[Any] = []
    if config.get('support', {}).get(GameConstants.IIDX, False):
        enabled_factories.append(IIDXFactory)
        enabled_caches.append(IIDXCache)
    if config.get('support', {}).get(GameConstants.POPN_MUSIC, False):
        enabled_factories.append(PopnMusicFactory)
        enabled_caches.append(PopnMusicCache)
    if config.get('support', {}).get(GameConstants.JUBEAT, False):
        enabled_factories.append(JubeatFactory)
        enabled_caches.append(JubeatCache)
    if config.get('support', {}).get(GameConstants.BISHI_BASHI, False):
        enabled_factories.append(BishiBashiFactory)
        enabled_caches.append(BishiBashiCache)
    if config.get('support', {}).get(GameConstants.DDR, False):
        enabled_factories.append(DDRFactory)
        enabled_caches.append(DDRCache)
    if config.get('support', {}).get(GameConstants.SDVX, False):
        enabled_factories.append(SoundVoltexFactory)
        enabled_caches.append(SoundVoltexCache)
    if config.get('support', {}).get(GameConstants.REFLEC_BEAT, False):
        enabled_factories.append(ReflecBeatFactory)
        enabled_caches.append(ReflecBeatCache)
    if config.get('support', {}).get(GameConstants.MUSECA, False):
        enabled_factories.append(MusecaFactory)
        enabled_caches.append(MusecaCache)

    # First, run any backend scheduled work
    for factory in enabled_factories:
        factory.run_scheduled_work(data, config)

    # Now, warm the caches for the frontend
    for cache in enabled_caches:
        cache.preload(data, config)

    # Now, possibly delete old log entries
    keep_duration = config.get('event_log_duration', 0)
    if keep_duration > 0:
        # Calculate timestamp of events we should delete
        oldest_event = Time.now() - keep_duration
        data.local.network.delete_events(oldest_event)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A scheduler for work that needs to be done periodically.")
    parser.add_argument("-c", "--config", help="Core configuration. Defaults to server.yaml", type=str, default="server.yaml")
    args = parser.parse_args()

    # Set up global configuration
    config = yaml.safe_load(open(args.config))
    config['database']['engine'] = Data.create_engine(config)

    # Run out of band work
    run_scheduled_work(config)
