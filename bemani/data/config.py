import copy
import os
from sqlalchemy.engine import Engine
from typing import Any, Dict, Optional, Set

from bemani.common import GameConstants, RegionConstants
from bemani.data.types import ArcadeID


class Database:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def address(self) -> str:
        return str(self.__config.get("database", {}).get("address", "localhost"))

    @property
    def database(self) -> str:
        return str(self.__config.get("database", {}).get("database", "bemani"))

    @property
    def user(self) -> str:
        return str(self.__config.get("database", {}).get("user", "bemani"))

    @property
    def password(self) -> str:
        return str(self.__config.get("database", {}).get("password", "bemani"))

    @property
    def engine(self) -> Engine:
        engine = self.__config.get("database", {}).get("engine")
        if engine is None:
            raise Exception("Config object is not instantiated properly, no SQLAlchemy engine present!")
        if not isinstance(engine, Engine):
            raise Exception("Config object is not instantiated properly, engine property is not a SQLAlchemy Engine!")
        return engine

    @property
    def read_only(self) -> bool:
        return bool(self.__config.get("database", {}).get("read_only", False))


class Server:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def address(self) -> str:
        return str(self.__config.get("server", {}).get("address", "127.0.0.1"))

    @property
    def keepalive(self) -> str:
        return str(self.__config.get("server", {}).get("keepalive", self.address))

    @property
    def port(self) -> int:
        return int(self.__config.get("server", {}).get("port", 80))

    @property
    def https(self) -> bool:
        return bool(self.__config.get("server", {}).get("https", False))

    @property
    def uri(self) -> Optional[str]:
        uri = self.__config.get("server", {}).get("uri")
        return str(uri) if uri else None

    @property
    def redirect(self) -> Optional[str]:
        redirect = self.__config.get("server", {}).get("redirect")
        return str(redirect) if redirect else None

    @property
    def enforce_pcbid(self) -> bool:
        return bool(self.__config.get("server", {}).get("enforce_pcbid", False))

    @property
    def pcbid_self_grant_limit(self) -> int:
        return int(self.__config.get("server", {}).get("pcbid_self_grant_limit", 0))

    @property
    def region(self) -> int:
        region = int(self.__config.get("server", {}).get("region", RegionConstants.USA))
        if region in {RegionConstants.EUROPE, RegionConstants.NO_MAPPING}:
            # Bogus values we support.
            return region
        if region < RegionConstants.MIN or region > RegionConstants.MAX:
            # Pick the original default for the network (USA).
            return RegionConstants.USA
        # Region was fine.
        return region

    @property
    def area(self) -> Optional[str]:
        area = self.__config.get("server", {}).get("area")
        return str(area) if area else None


class Client:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def address(self) -> str:
        address = self.__config.get("client", {}).get("address")
        if address is None:
            raise Exception("Config object is not instantiated properly, no client address present!")
        return str(address)


class Machine:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def pcbid(self) -> str:
        pcbid = self.__config.get("machine", {}).get("pcbid")
        if pcbid is None:
            raise Exception("Config object is not instantiated properly, no machine pcbid present!")
        return str(pcbid)

    @property
    def arcade(self) -> Optional[ArcadeID]:
        return self.__config.get("machine", {}).get("arcade")


class PASELI:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def enabled(self) -> bool:
        return bool(self.__config.get("paseli", {}).get("enabled", False))

    @property
    def infinite(self) -> bool:
        return bool(self.__config.get("paseli", {}).get("infinite", False))


class WebHooks:
    def __init__(self, parent_config: "Config") -> None:
        self.discord = DiscordWebHooks(parent_config)


class DiscordWebHooks:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    def __getitem__(self, key: GameConstants) -> Optional[str]:
        uri = self.__config.get("webhooks", {}).get("discord", {}).get(key.value)
        return str(uri) if uri else None


class Assets:
    def __init__(self, parent_config: "Config") -> None:
        self.jubeat = JubeatAssets(parent_config)


class JubeatAssets:
    def __init__(self, parent_config: "Config") -> None:
        self.__config = parent_config

    @property
    def emblems(self) -> Optional[str]:
        directory = self.__config.get("assets", {}).get("jubeat", {}).get("emblems")
        return str(directory) if directory else None


class Config(dict):
    def __init__(self, existing_contents: Dict[str, Any] = {}) -> None:
        super().__init__(existing_contents or {})

        self.database = Database(self)
        self.server = Server(self)
        self.client = Client(self)
        self.paseli = PASELI(self)
        self.webhooks = WebHooks(self)
        self.assets = Assets(self)
        self.machine = Machine(self)

    def clone(self) -> "Config":
        # Somehow its not possible to clone this object if an instantiated Engine is present,
        # so we do a little shenanigans here.
        engine = self.get("database", {}).get("engine")
        if engine is not None:
            self["database"]["engine"] = None

        clone = Config(copy.deepcopy(self))

        if engine is not None:
            self["database"]["engine"] = engine
            clone["database"]["engine"] = engine

        return clone

    @property
    def filename(self) -> str:
        filename = self.get("filename")
        if filename is None:
            raise Exception("Config object is not instantiated properly, no filename present!")
        return os.path.abspath(str(filename))

    @property
    def support(self) -> Set[GameConstants]:
        support = self.get("support")
        if support is None:
            raise Exception("Config object is not instantiated properly, no support list present!")
        if not isinstance(support, set):
            raise Exception("Config object is not instantiated properly, support property is not a Set!")
        return support

    @property
    def secret_key(self) -> str:
        return str(self.get("secret_key", "youdidntchangethisatalldidyou?"))

    @property
    def name(self) -> str:
        return str(self.get("name", "e-AMUSEMENT Network"))

    @property
    def email(self) -> str:
        return str(self.get("email", "nobody@nowhere.com"))

    @property
    def cache_dir(self) -> Optional[str]:
        cache_dir = self.get("cache_dir")
        if cache_dir is None:
            return None
        return os.path.abspath(str(cache_dir))

    @property
    def memcached_server(self) -> Optional[str]:
        server = self.get("memcached_server")
        if server is None:
            return None
        return str(server)

    @property
    def theme(self) -> str:
        return str(self.get("theme", "default"))

    @property
    def event_log_duration(self) -> Optional[int]:
        duration = self.get("event_log_duration")
        return int(duration) if duration else None
