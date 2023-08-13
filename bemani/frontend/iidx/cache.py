from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.iidx.iidx import IIDXFrontend


class IIDXCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = IIDXFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
