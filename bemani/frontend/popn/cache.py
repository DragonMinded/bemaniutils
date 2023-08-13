from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.popn.popn import PopnMusicFrontend


class PopnMusicCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = PopnMusicFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
