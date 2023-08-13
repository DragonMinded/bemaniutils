from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.jubeat.jubeat import JubeatFrontend


class JubeatCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = JubeatFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
