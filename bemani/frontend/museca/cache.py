from flask_caching import Cache

from bemani.data import Config, Data
from bemani.frontend.app import app
from bemani.frontend.museca.museca import MusecaFrontend


class MusecaCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        cache = Cache(
            app,
            config={
                "CACHE_TYPE": "filesystem",
                "CACHE_DIR": config.cache_dir,
            },
        )
        frontend = MusecaFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
