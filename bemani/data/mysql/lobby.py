import copy

from sqlalchemy import Table, Column, UniqueConstraint  # type: ignore
from sqlalchemy.types import String, Integer, JSON  # type: ignore
from sqlalchemy.dialects.mysql import BIGINT as BigInteger  # type: ignore
from typing import Optional, Dict, List, Tuple, Any

from bemani.common import GameConstants, ValidatedDict, Time
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.types import UserID

"""
Table for storing logistical information about a player who's session is
live. Mostly, this is used to store IP addresses and such for players that
could potentially match.
"""
playsession = Table(
    "playsession",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("time", Integer, nullable=False, index=True),
    Column("data", JSON, nullable=False),
    UniqueConstraint("game", "version", "userid", name="game_version_userid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing open lobbies for matching between games.
"""
lobby = Table(
    "lobby",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("time", Integer, nullable=False, index=True),
    Column("data", JSON, nullable=False),
    UniqueConstraint("game", "version", "userid", name="game_version_userid"),
    mysql_charset="utf8mb4",
)


class LobbyData(BaseData):
    def get_play_session_info(
        self, game: GameConstants, version: int, userid: UserID
    ) -> Optional[ValidatedDict]:
        """
        Given a game, version and a user ID, look up play session information for that user.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.
            userid - Integer identifying a user, as possibly looked up by UserData.

        Returns:
            A dictionary representing play session info stored by a game class, or None
            if there is no active session for this game/version/user. The dictionary will
            always contain an 'id' field which is the play session ID, and a 'time' field
            which represents the timestamp when the play session began.
        """
        sql = """
            SELECT id, time, data FROM playsession
            WHERE
                game = :game AND
                version = :version AND
                userid = :userid AND
                time > :time
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "time": Time.now() - Time.SECONDS_IN_HOUR,
            },
        )

        if cursor.rowcount != 1:
            # Settings doesn't exist
            return None

        result = cursor.fetchone()
        data = ValidatedDict(self.deserialize(result["data"]))
        data["id"] = result["id"]
        data["time"] = result["time"]
        return data

    def get_all_play_session_infos(
        self, game: GameConstants, version: int
    ) -> List[Tuple[UserID, ValidatedDict]]:
        """
        Given a game and version, look up all play session information.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.

        Returns:
            A list of Tuples, consisting of a UserID and the dictionary that would be
            returned for that user if get_play_session_info() was called for that user.
        """
        sql = """
            SELECT id, time, userid, data FROM playsession
            WHERE game = :game AND version = :version AND time > :time
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "time": Time.now() - Time.SECONDS_IN_HOUR,
            },
        )

        def format_result(result: Dict[str, Any]) -> ValidatedDict:
            data = ValidatedDict(self.deserialize(result["data"]))
            data["id"] = result["id"]
            data["time"] = result["time"]
            return data

        return [(UserID(result["userid"]), format_result(result)) for result in cursor]

    def put_play_session_info(
        self, game: GameConstants, version: int, userid: UserID, data: Dict[str, Any]
    ) -> None:
        """
        Given a game, version and a user ID, save play session information for that user.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.
            userid - Integer identifying a user.
            data - A dictionary of play session information to store.
        """
        data = copy.deepcopy(data)
        if "id" in data:
            del data["id"]
        if "time" in data:
            del data["time"]

        # Add json to player session
        sql = """
            INSERT INTO playsession (game, version, userid, time, data)
            VALUES (:game, :version, :userid, :time, :data)
            ON DUPLICATE KEY UPDATE time=VALUES(time), data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "time": Time.now(),
                "data": self.serialize(data),
            },
        )

    def destroy_play_session_info(
        self, game: GameConstants, version: int, userid: UserID
    ) -> None:
        """
        Given a game, version and a user ID, throw away session info for that play session.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.
            userid - Integer identifying a user, as possibly looked up by UserData.
        """
        # Kill this play session
        sql = "DELETE FROM playsession WHERE game = :game AND version = :version AND userid = :userid"
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
            },
        )
        # Prune any orphaned lobbies too
        sql = "DELETE FROM playsession WHERE time <= :time"
        self.execute(sql, {"time": Time.now() - Time.SECONDS_IN_HOUR})

    def get_lobby(
        self, game: GameConstants, version: int, userid: UserID
    ) -> Optional[ValidatedDict]:
        """
        Given a game, version and a user ID, look up lobby information for that user.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.
            userid - Integer identifying a user, as possibly looked up by UserData.

        Returns:
            A dictionary representing lobby info stored by a game class, or None
            if there is no active session for this game/version/user. The dictionary will
            always contain an 'id' field which is the lobby ID, and a 'time' field representing
            the timestamp the lobby was created.
        """
        sql = """
            SELECT id, time, data FROM lobby
            WHERE
                game = :game AND
                version = :version AND
                userid = :userid AND
                time > :time
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "time": Time.now() - Time.SECONDS_IN_HOUR,
            },
        )

        if cursor.rowcount != 1:
            # Settings doesn't exist
            return None

        result = cursor.fetchone()
        data = ValidatedDict(self.deserialize(result["data"]))
        data["id"] = result["id"]
        data["time"] = result["time"]
        return data

    def get_all_lobbies(
        self, game: GameConstants, version: int
    ) -> List[Tuple[UserID, ValidatedDict]]:
        """
        Given a game and version, look up all active lobbies.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.

        Returns:
            A list of dictionaries representing lobby info stored by a game class.
        """
        sql = """
            SELECT userid, id, data FROM lobby
            WHERE game = :game AND version = :version AND time > :time
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "time": Time.now() - Time.SECONDS_IN_HOUR,
            },
        )

        def format_result(result: Dict[str, Any]) -> ValidatedDict:
            data = ValidatedDict(self.deserialize(result["data"]))
            data["id"] = result["id"]
            data["time"] = result["time"]
            return data

        return [(UserID(result["userid"]), format_result(result)) for result in cursor]

    def put_lobby(
        self, game: GameConstants, version: int, userid: UserID, data: Dict[str, Any]
    ) -> None:
        """
        Given a game, version and a user ID, save lobby information for that user.

        Parameters:
            game - Enum value identifying a game series.
            version - Integer identifying the version of the game in the series.
            userid - Integer identifying a user.
            data - A dictionary of lobby information to store.
        """
        data = copy.deepcopy(data)
        if "id" in data:
            del data["id"]
        if "time" in data:
            del data["time"]

        # Add json to lobby
        sql = """
            INSERT INTO lobby (game, version, userid, time, data)
            VALUES (:game, :version, :userid, :time, :data)
            ON DUPLICATE KEY UPDATE time=VALUES(time), data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "time": Time.now(),
                "data": self.serialize(data),
            },
        )

    def destroy_lobby(self, lobbyid: int) -> None:
        """
        Given a lobby ID, destroy the lobby. The lobby ID can be obtained by reading
        the 'id' field of the get_lobby response.

        Parameters:
            lobbyid: Integer identifying a lobby.
        """
        # Delete this lobby
        sql = "DELETE FROM lobby WHERE id = :id"
        self.execute(sql, {"id": lobbyid})
        # Prune any orphaned lobbies too
        sql = "DELETE FROM lobby WHERE time <= :time"
        self.execute(sql, {"time": Time.now() - Time.SECONDS_IN_HOUR})
