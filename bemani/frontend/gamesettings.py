from typing import Any, Dict, List

from bemani.backend.base import Base
from bemani.common import ValidatedDict, GameConstants
from bemani.data import Data, ArcadeID


def get_game_settings(data: Data, arcadeid: ArcadeID) -> List[Dict[str, Any]]:
    game_lut: Dict[GameConstants, Dict[int, str]] = {}
    settings_lut: Dict[GameConstants, Dict[int, Dict[str, Any]]] = {}
    all_settings = []

    for game, version, name in Base.all_games():
        if game not in game_lut:
            game_lut[game] = {}
            settings_lut[game] = {}
        game_lut[game][version] = name
        settings_lut[game][version] = {}

    for game, version, settings in Base.all_settings():
        if not settings:
            continue

        # First, set up the basics
        game_settings: Dict[str, Any] = {
            "game": game.value,
            "version": version,
            "name": game_lut[game][version],
            "bools": [],
            "ints": [],
            "strs": [],
            "longstrs": [],
        }

        # Now, look up the current setting for each returned setting
        for setting_type, setting_unpacker in [
            ("bools", "get_bool"),
            ("ints", "get_int"),
            ("strs", "get_str"),
            ("longstrs", "get_str"),
        ]:
            for setting in settings.get(setting_type, []):
                if setting["category"] not in settings_lut[game][version]:
                    cached_setting = data.local.machine.get_settings(arcadeid, game, version, setting["category"])
                    if cached_setting is None:
                        cached_setting = ValidatedDict()
                    settings_lut[game][version][setting["category"]] = cached_setting

                current_settings = settings_lut[game][version][setting["category"]]
                setting["value"] = getattr(current_settings, setting_unpacker)(setting["setting"])
                game_settings[setting_type].append(setting)

        # Now, include it!
        all_settings.append(game_settings)

    return sorted(
        all_settings,
        key=lambda setting: (setting["game"], setting["version"]),
    )
