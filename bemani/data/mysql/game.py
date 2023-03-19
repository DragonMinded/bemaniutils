from sqlalchemy import Table, Column, UniqueConstraint  # type: ignore
from sqlalchemy.types import String, Integer, JSON  # type: ignore
from sqlalchemy.dialects.mysql import BIGINT as BigInteger  # type: ignore
from typing import Any, Dict, List, Optional

from bemani.common import GameConstants, ValidatedDict, Time
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.types import Achievement, Item, UserID

"""
Table for storing game settings that span multiple versions of the same
game, such as play statistics. This table intentionally doesn't have a
key on game version, just game string and userid.
"""
game_settings = Table(
    "game_settings",
    metadata,
    Column("game", String(32), nullable=False),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("game", "userid", name="game_userid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing shop items that are server-side verified.
"""
catalog = Table(
    "catalog",
    metadata,
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("id", Integer, nullable=False),
    Column("type", String(64), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("game", "version", "id", "type", name="game_version_id_type"),
    mysql_charset="utf8mb4",
)

"""
Table for storing series achievements that span multiple versions of the same
game, such as course scores. This table intentionally doesn't have a
key on game version, just game string and userid.
"""
series_achievement = Table(
    "series_achievement",
    metadata,
    Column("game", String(32), nullable=False),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("id", Integer, nullable=False),
    Column("type", String(64), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("game", "userid", "id", "type", name="game_userid_id_type"),
    mysql_charset="utf8mb4",
)

"""
Table for storing time-based game settings that aren't tied to a user
account, such as dailies, weeklies, etc.
"""
time_sensitive_settings = Table(
    "time_sensitive_settings",
    metadata,
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("name", String(32), nullable=False),
    Column("start_time", Integer, nullable=False, index=True),
    Column("end_time", Integer, nullable=False, index=True),
    Column("data", JSON, nullable=False),
    UniqueConstraint(
        "game", "version", "name", "start_time", name="game_version_name_start_time"
    ),
    mysql_charset="utf8mb4",
)


class GameData(BaseData):
    def get_settings(
        self, game: GameConstants, userid: UserID
    ) -> Optional[ValidatedDict]:
        """
        Given a game and a user ID, look up game-wide settings as a dictionary.

        It is expected that game classes call this function, and provide a consistent
        game name from version to version, so game settings can be looked up across
        all versions in a game series.

        Parameters:
            game - Enum value identifying a game series.
            userid - Integer identifying a user, as possibly looked up by UserData.

        Returns:
            A dictionary representing game settings stored by a game class, or None
            if there are no settings for this game/user.
        """
        sql = "SELECT data FROM game_settings WHERE game = :game AND userid = :userid"
        cursor = self.execute(sql, {"game": game.value, "userid": userid})

        if cursor.rowcount != 1:
            # Settings doesn't exist
            return None

        result = cursor.fetchone()
        return ValidatedDict(self.deserialize(result["data"]))

    def put_settings(
        self, game: GameConstants, userid: UserID, settings: Dict[str, Any]
    ) -> None:
        """
        Given a game and a user ID, save game-wide settings to the DB.

        Parameters:
            game - Enum value identifying a game series.
            userid - Integer identifying a user.
            settings - A dictionary of settings that a game wishes to retrieve later.
        """
        # Add settings json to game settings
        sql = """
            INSERT INTO game_settings (game, userid, data)
            VALUES (:game, :userid, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {"game": game.value, "userid": userid, "data": self.serialize(settings)},
        )

    def get_achievement(
        self,
        game: GameConstants,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
    ) -> Optional[ValidatedDict]:
        """
        Given a game/userid and achievement id/type, find that achievement.

        Note that there can be more than one achievement with the same ID and game/userid
        as long as each one is a different type. Essentially, achievementtype namespaces achievements.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.

        Returns:
            A dictionary as stored by a game class previously, or None if not found.
        """
        sql = """
            SELECT data FROM series_achievement
            WHERE game = :game AND userid = :userid AND id = :id AND type = :type
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "userid": userid,
                "id": achievementid,
                "type": achievementtype,
            },
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return ValidatedDict(self.deserialize(result["data"]))

    def get_achievements(
        self, game: GameConstants, userid: UserID
    ) -> List[Achievement]:
        """
        Given a game/userid, find all achievements

        Parameters:
            game - Enum value identifier of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A list of Achievement objects.
        """
        sql = "SELECT id, type, data FROM series_achievement WHERE game = :game AND userid = :userid"
        cursor = self.execute(sql, {"game": game.value, "userid": userid})

        return [
            Achievement(
                result["id"],
                result["type"],
                None,
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]

    def put_achievement(
        self,
        game: GameConstants,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Given a game/userid and achievement id/type, save an achievement.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.
            data - A dictionary of data that the game wishes to retrieve later.
        """
        # Add achievement JSON to achievements
        sql = """
            INSERT INTO series_achievement (game, userid, id, type, data)
            VALUES (:game, :userid, :id, :type, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "userid": userid,
                "id": achievementid,
                "type": achievementtype,
                "data": self.serialize(data),
            },
        )

    def get_time_sensitive_settings(
        self, game: GameConstants, version: int, name: str
    ) -> Optional[ValidatedDict]:
        """
        Given a game/version/name, look up the current time-sensitive settings for this game.

        Parameters:
            game - Enum value identifier of the game we want settings for.
            version - Integer identifying the game version we want settings for.
            name - The name of the setting we are concerned with.

        Returns:
            A ValidatedDict of stored settings if the current setting is found, or None otherwise.
            If settings were found, they are guaranteed to include the attributes 'start_time' and
            'end_time' which will both be seconds since the unix epoch (UTC).
        """
        sql = """
            SELECT data, start_time, end_time FROM time_sensitive_settings
            WHERE
                game = :game AND
                version = :version AND
                name = :name AND
                start_time <= :time AND
                end_time > :time
        """
        cursor = self.execute(
            sql,
            {"game": game.value, "version": version, "name": name, "time": Time.now()},
        )
        if cursor.rowcount != 1:
            # setting doesn't exist
            return None

        result = cursor.fetchone()
        retval = ValidatedDict(self.deserialize(result["data"]))
        retval["start_time"] = result["start_time"]
        retval["end_time"] = result["end_time"]
        return retval

    def get_all_time_sensitive_settings(
        self, game: GameConstants, version: int, name: str
    ) -> List[ValidatedDict]:
        """
        Given a game/version/name, look up all of the time-sensitive settings for this game.

        Parameters:
            game - Enum value identifier of the game we want settings for.
            version - Integer identifying the game version we want settings for.
            name - The name of the setting we are concerned with.

        Returns:
            A list of ValidatedDict of stored settings if there were settings found, or [] otherwise.
            If settings were found, they are guaranteed to include the attributes 'start_time' and
            'end_time' which will both be seconds since the unix epoch (UTC).
        """
        sql = """
            SELECT data, start_time, end_time FROM time_sensitive_settings
            WHERE game = :game AND version = :version AND name = :name
        """
        cursor = self.execute(
            sql, {"game": game.value, "version": version, "name": name}
        )
        if cursor.rowcount == 0:
            # setting doesn't exist
            return []

        return [
            ValidatedDict(
                {
                    **self.deserialize(result["data"]),
                    "start_time": result["start_time"],
                    "end_time": result["end_time"],
                }
            )
            for result in cursor
        ]

    def put_time_sensitive_settings(
        self, game: GameConstants, version: int, name: str, settings: Dict[str, Any]
    ) -> None:
        """
        Given a game/version/name and a settings dictionary that contains 'start_time' and 'end_time',
        as seconds since the unix epoch (UTC), update the DB to store or update this time-sensitive
        setting. Verifies that start time comes before end time, that there is at least one second in
        the setting duration, and that this setting doesn't overlap any other setting already present.

        Parameters:
            game - Enum value identifier of the game we want settings for.
            version - Integer identifying the game version we want settings for.
            name - The name of the setting we are concerned with.
            settings - A dictionary containing at least 'start_time' and 'end_time'.
        """
        start_time = settings["start_time"]
        end_time = settings["end_time"]
        del settings["start_time"]
        del settings["end_time"]

        if start_time > end_time:
            raise Exception("Start time is greater than end time!")
        if start_time == end_time:
            raise Exception("This setting spans zero seconds!")

        # Verify that this isn't overlapping some event.
        sql = """
            SELECT start_time, end_time FROM time_sensitive_settings
            WHERE game = :game AND version = :version AND name = :name AND
            (
                (start_time >= :start_time AND start_time < :end_time) OR
                (end_time > :start_time AND end_time <= :end_time) OR
                (start_time < :start_time AND end_time > :end_time)
            )
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "name": name,
                "start_time": start_time,
                "end_time": end_time,
            },
        )
        for result in cursor:
            if result["start_time"] == start_time and result["end_time"] == end_time:
                # This is just this event being updated, that's fine.
                continue
            raise Exception(
                f'This event overlaps an existing one with start time {result["start_time"]} and end time {result["end_time"]}'
            )

        # Insert or update this setting
        sql = """
            INSERT INTO time_sensitive_settings (game, version, name, start_time, end_time, data)
            VALUES (:game, :version, :name, :start_time, :end_time, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "name": name,
                "start_time": start_time,
                "end_time": end_time,
                "data": self.serialize(settings),
            },
        )

    def get_item(
        self, game: GameConstants, version: int, catid: int, cattype: str
    ) -> Optional[ValidatedDict]:
        """
        Given a game/userid and catalog id/type, find that catalog entry.

        Note that there can be more than one catalog entry with the same ID and game/userid
        as long as each one is a different type. Essentially, cattype namespaces catalog entry.

        Parameters:
            game - Enum value identifier of the game looking up this entry.
            version - Integer identifier of the version looking up this entry.
            catid - Integer ID, as provided by a game.
            cattype - The type of catalog entry.

        Returns:
            A dictionary as stored by a game class previously, or None if not found.
        """
        sql = """
            SELECT data FROM catalog
            WHERE game = :game AND version = :version AND id = :id AND type = :type
        """
        cursor = self.execute(
            sql, {"game": game.value, "version": version, "id": catid, "type": cattype}
        )
        if cursor.rowcount != 1:
            # entry doesn't exist
            return None

        result = cursor.fetchone()
        return ValidatedDict(self.deserialize(result["data"]))

    def get_items(self, game: GameConstants, version: int) -> List[Item]:
        """
        Given a game/userid, find all items in the catalog.

        Parameters:
            game - Enum value identifier of the game looking up the catalog.
            version - Integer identifier of the version looking up this catalog.

        Returns:
            A list of Item objects.
        """
        sql = "SELECT id, type, data FROM catalog WHERE game = :game AND version = :version"
        cursor = self.execute(sql, {"game": game.value, "version": version})

        return [
            Item(
                result["type"],
                result["id"],
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]
