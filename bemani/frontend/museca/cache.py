from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.museca.museca import MusecaFrontend


class MusecaCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = MusecaFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
