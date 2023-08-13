from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.reflec.reflec import ReflecBeatFrontend


class ReflecBeatCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = ReflecBeatFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
