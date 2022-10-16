import os

import alembic.config
from alembic.migration import MigrationContext
from alembic.autogenerate import compare_metadata  # type: ignore
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy.orm import scoped_session  # type: ignore
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine  # type: ignore
from sqlalchemy.sql import text  # type: ignore
from sqlalchemy.exc import ProgrammingError  # type: ignore

from bemani.data.api.user import GlobalUserData
from bemani.data.api.game import GlobalGameData
from bemani.data.api.music import GlobalMusicData
from bemani.data.config import Config
from bemani.data.mysql.base import metadata
from bemani.data.mysql.user import UserData
from bemani.data.mysql.music import MusicData
from bemani.data.mysql.machine import MachineData
from bemani.data.mysql.game import GameData
from bemani.data.mysql.network import NetworkData
from bemani.data.mysql.lobby import LobbyData
from bemani.data.mysql.api import APIData
from bemani.data.triggers import Triggers


class DBCreateException(Exception):
    pass


class LocalProvider:
    """
    A wrapper object for implementing local data operations only. Right
    now this goes to the MySQL classes and talks to the backend DB.
    """

    def __init__(
        self,
        user: UserData,
        music: MusicData,
        machine: MachineData,
        game: GameData,
        network: NetworkData,
        lobby: LobbyData,
        api: APIData,
    ) -> None:
        self.user = user
        self.music = music
        self.machine = machine
        self.game = game
        self.network = network
        self.lobby = lobby
        self.api = api


class GlobalProvider:
    """
    A class that handles fetching data locally and from remote data APIs.
    This means combining data fetched from local MySQL with data fetched
    from remote servers that support BEMAPI.
    """

    def __init__(
        self,
        local: LocalProvider,
    ) -> None:
        self.user = GlobalUserData(
            local.api,
            local.user,
        )
        self.music = GlobalMusicData(
            local.api,
            local.user,
            local.music,
        )
        self.game = GlobalGameData(
            local.api,
        )


class Data:
    """
    An object that is meant to be used as a singleton, in order to hold
    DB configuration info and provide a set of functions for querying
    and storing data.
    """

    def __init__(self, config: Config) -> None:
        """
        Initializes the data object.

        Parameters:
            config - A config structure with a 'database' section which is used
                     to initialize an internal DB connection.
        """
        session_factory = sessionmaker(
            bind=config.database.engine,
            autoflush=True,
            autocommit=True,
        )
        self.__config = config
        self.__session = scoped_session(session_factory)
        self.__url = Data.sqlalchemy_url(config)
        self.__user = UserData(config, self.__session)
        self.__music = MusicData(config, self.__session)
        self.__machine = MachineData(config, self.__session)
        self.__game = GameData(config, self.__session)
        self.__network = NetworkData(config, self.__session)
        self.__lobby = LobbyData(config, self.__session)
        self.__api = APIData(config, self.__session)
        self.local = LocalProvider(
            self.__user,
            self.__music,
            self.__machine,
            self.__game,
            self.__network,
            self.__lobby,
            self.__api,
        )
        self.remote = GlobalProvider(self.local)
        self.triggers = Triggers(config)

    @classmethod
    def sqlalchemy_url(cls, config: Config) -> str:
        return f"mysql://{config.database.user}:{config.database.password}@{config.database.address}/{config.database.database}?charset=utf8mb4"

    @classmethod
    def create_engine(cls, config: Config) -> Engine:
        return create_engine(
            Data.sqlalchemy_url(config),
            pool_recycle=3600,
        )

    def __exists(self) -> bool:
        # See if the DB was already created
        try:
            cursor = self.__session.execute(
                text("SELECT COUNT(version_num) AS count FROM alembic_version")
            )
            return cursor.fetchone()["count"] == 1
        except ProgrammingError:
            return False

    def __alembic_cmd(self, command: str, *args: str) -> None:
        base_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "migrations"
        )
        alembicArgs = [
            "-c",
            os.path.join(base_dir, "alembic.ini"),
            "-x",
            f"script_location={base_dir}",
            "-x",
            f"sqlalchemy.url={self.__url}",
            command,
        ]
        alembicArgs.extend(args)
        os.chdir(base_dir)
        alembic.config.main(argv=alembicArgs)  # type: ignore

    def create(self) -> None:
        """
        Create any tables that need to be created.
        """
        if self.__exists():
            # Cowardly refused to do anything, we should be using the upgrade path instead.
            raise DBCreateException(
                "Tables already created, use upgrade to upgrade schema!"
            )

        metadata.create_all(
            self.__config.database.engine.connect(),
            checkfirst=True,
        )

        # Stamp the end revision as if alembic had created it, so it can take off after this.
        self.__alembic_cmd(
            "stamp",
            "head",
        )

    def generate(self, message: str, allow_empty: bool) -> None:
        """
        Generate upgrade scripts using alembic.
        """
        if not self.__exists():
            raise DBCreateException(
                "Tables have not been created yet, use create to create them!"
            )

        # Verify that there are actual changes, and refuse to create empty migration scripts
        context = MigrationContext.configure(
            self.__config.database.engine.connect(), opts={"compare_type": True}
        )
        diff = compare_metadata(context, metadata)
        if (not allow_empty) and (len(diff) == 0):
            raise DBCreateException(
                "There is nothing different between code and the DB, refusing to create migration!"
            )

        self.__alembic_cmd(
            "revision",
            "--autogenerate",
            "-m",
            message,
        )

    def upgrade(self) -> None:
        """
        Upgrade an existing DB to the current model.
        """
        if not self.__exists():
            raise DBCreateException(
                "Tables have not been created yet, use create to create them!"
            )

        self.__alembic_cmd(
            "upgrade",
            "head",
        )

    def close(self) -> None:
        """
        Close any open data connection.
        """
        # Make sure we don't leak connections between web requests
        if self.__session is not None:
            self.__session.close()
            self.__session = None
