from bemani.common import cache
from bemani.data import Config, Data
from bemani.frontend.sdvx.sdvx import SoundVoltexFrontend


class SoundVoltexCache:
    @classmethod
    def preload(cls, data: Data, config: Config) -> None:
        frontend = SoundVoltexFrontend(data, config, cache)
        frontend.get_all_songs(force_db_load=True)
