from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.ddr.ddr import DDRFrontend


class DDRCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = DDRFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
