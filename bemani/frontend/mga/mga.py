# vim: set fileencoding=utf-8
import copy
from typing import Any, Dict, Iterator, Tuple

from flask_caching import Cache

from bemani.backend.mga import MetalGearArcadeFactory
from bemani.common import Profile, ValidatedDict, ID, GameConstants
from bemani.data import Data, Config
from bemani.frontend.base import FrontendBase


class MetalGearArcadeFrontend(FrontendBase):
    game: GameConstants = GameConstants.MGA

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        super().__init__(data, config, cache)
        self.machines: Dict[int, str] = {}

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from MetalGearArcadeFactory.all_games()

    def __update_value(self, oldvalue: str, newvalue: bytes) -> str:
        try:
            newstr = newvalue.decode("shift-jis")
        except Exception:
            newstr = ""
        if len(newstr) == 0:
            return oldvalue
        else:
            return newstr

    def sanitize_name(self, name: str) -> str:
        if len(name) == 0:
            return "なし"
        return name

    def update_name(self, profile: Profile, name: str) -> Profile:
        newprofile = copy.deepcopy(profile)
        for i in range(len(newprofile["strdatas"])):
            strdata = newprofile["strdatas"][i]

            # Figure out the profile type
            csvs = strdata.split(b",")
            if len(csvs) < 2:
                # Not long enough to care about
                continue
            datatype = csvs[1].decode("ascii")
            if datatype != "PLAYDATA":
                # Not the right profile type requested
                continue
            csvs[27] = name.encode("shift-jis")
            newprofile["strdatas"][i] = b",".join(csvs)

        return newprofile

    def format_profile(
        self, profile: Profile, playstats: ValidatedDict
    ) -> Dict[str, Any]:
        name = "なし"  # Nothing
        shop = "未設定"  # Not set
        shop_area = "未設定"  # Not set

        for i in range(len(profile["strdatas"])):
            strdata = profile["strdatas"][i]

            # Figure out the profile type
            csvs = strdata.split(b",")
            if len(csvs) < 2:
                # Not long enough to care about
                continue
            datatype = csvs[1].decode("ascii")
            if datatype != "PLAYDATA":
                # Not the right profile type requested
                continue

            name = self.__update_value(name, csvs[27])
            shop = self.__update_value(shop, csvs[30])
            shop_area = self.__update_value(shop_area, csvs[31])

        return {
            "name": name,
            "extid": ID.format_extid(profile.extid),
            "shop": shop,
            "shop_area": shop_area,
            "first_play_time": playstats.get_int("first_play_timestamp"),
            "last_play_time": playstats.get_int("last_play_timestamp"),
            "plays": playstats.get_int("total_plays"),
        }
