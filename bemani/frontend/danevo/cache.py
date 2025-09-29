from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.danevo.danevo import DanceEvolutionFrontend


class DanceEvolutionCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = DanceEvolutionFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
