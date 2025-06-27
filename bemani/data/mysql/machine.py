from sqlalchemy import Table, Column, UniqueConstraint
from sqlalchemy.types import String, Integer, JSON
from sqlalchemy.dialects.mysql import BIGINT as BigInteger
from typing import Optional, Dict, List, Tuple, Any
from typing_extensions import Final

from bemani.common import GameConstants, ValidatedDict
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.types import Machine, Arcade, UserID, ArcadeID

"""
Table for storing recognized machines on the network. This is used in conjunction
with PCBID enforcement to ensure machines not authorized on the network are denied
a connection. It is also used for settings such as port forwarding and which arcade
a machine belongs to for the purpose of PASELI balance.
"""
machine = Table(
    "machine",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("pcbid", String(20), nullable=False, unique=True),
    Column("name", String(255), nullable=False),
    Column("description", String(255), nullable=False),
    Column("arcadeid", Integer),
    Column("port", Integer, nullable=False, unique=True),
    Column("game", String(20)),
    Column("version", Integer),
    Column("data", JSON),
    mysql_charset="utf8mb4",
)

"""
Table for storing an arcade, to which zero or more machines may belong. This allows
an arcade to override some global settings such as PASELI enabled and infinite.
"""
arcade = Table(
    "arcade",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("description", String(255), nullable=False),
    Column("pin", String(8), nullable=False),
    Column("pref", Integer, nullable=False),
    Column("area", String(63)),
    Column("data", JSON),
    mysql_charset="utf8mb4",
)

"""
Table for storing arcade ownership. This allows for more than one owner to own an arcade.
"""
arcade_owner = Table(
    "arcade_owner",
    metadata,
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("arcadeid", Integer, nullable=False),
    UniqueConstraint("userid", "arcadeid", name="userid_arcadeid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing arcade settings for a particular game/version. This allows the arcade
owner to change settings related to a particular game, such as the events active or the
shop ranking courses.
"""
arcade_settings = Table(
    "arcade_settings",
    metadata,
    Column("arcadeid", Integer, nullable=False),
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("type", String(64), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("arcadeid", "game", "version", "type", name="arcadeid_game_version_type"),
    mysql_charset="utf8mb4",
)


class ArcadeCreationException(Exception):
    pass


class MachineData(BaseData):
    # This relies on the fact that arcadeid in the arcade_settings table is auto-increment
    # and thus will start at 1.
    DEFAULT_SETTINGS_ARCADE: Final[ArcadeID] = ArcadeID(-1)

    def from_port(self, port: int) -> Optional[str]:
        """
        Given a port, look up the PCBID attached to that port.

        Parameters:
            port - Integer specifying the port we are interested in.

        Returns:
            A string representing the PCBID of a machine attached to a port, or None if
            there is no machine matching this port.
        """
        sql = "SELECT pcbid FROM machine WHERE port = :port LIMIT 1"
        cursor = self.execute(sql, {"port": port})
        if cursor.rowcount != 1:
            # Machine doesn't exist
            return None

        result = cursor.mappings().fetchone()  # type: ignore
        return result["pcbid"]

    def from_machine_id(self, machine_id: int) -> Optional[str]:
        """
        Given a machine ID, look up the PCBID attached to that ID.

        Parameters:
            machine_id - Integer specifying the machine ID we are interested in.

        Returns:
            A string representing the PCBID of a machine attached to that ID, or None if
            there is no machine matching this ID.
        """
        sql = "SELECT pcbid FROM machine WHERE id = :id LIMIT 1"
        cursor = self.execute(sql, {"id": machine_id})
        if cursor.rowcount != 1:
            # Machine doesn't exist
            return None

        result = cursor.mappings().fetchone()  # type: ignore
        return result["pcbid"]

    def from_userid(self, userid: UserID) -> List[ArcadeID]:
        """
        Given a user ID, look up the arcades that this user owns.

        Parameters:
            userid - Integer specifying the user we are interested in.

        Returns:
            A list of integer IDs of the arcades this user owns.
        """
        sql = "SELECT arcadeid FROM arcade_owner WHERE userid = :userid"
        cursor = self.execute(sql, {"userid": userid})
        return [ArcadeID(result["arcadeid"]) for result in cursor.mappings()]

    def from_session(self, session: str) -> Optional[ArcadeID]:
        """
        Given a previously-opened session, look up a user ID.

        Parameters:
            session - String identifying a session that was opened by create_session.

        Returns:
            User ID as an integer if found, or None if the session is expired or doesn't exist.
        """
        arcadeid = self._from_session(session, "arcadeid")
        if arcadeid is None:
            return None
        return ArcadeID(arcadeid)

    def get_machine(self, pcbid: str) -> Optional[Machine]:
        """
        Given a PCBID, look up a machine.

        Parameters:
            pcbid - The PCBID as returned from a game.

        Returns:
            A Machine object representing a machine, or None if not found.
        """
        sql = """
            SELECT name, description, arcadeid, id, port, game, version, data
            FROM machine WHERE pcbid = :pcbid
        """
        cursor = self.execute(sql, {"pcbid": pcbid})
        if cursor.rowcount != 1:
            # Machine doesn't exist
            return None

        result = cursor.mappings().fetchone()  # type: ignore
        return Machine(
            result["id"],
            pcbid,
            result["name"],
            result["description"],
            result["arcadeid"],
            result["port"],
            GameConstants(result["game"]) if result["game"] else None,
            result["version"],
            self.deserialize(result["data"]),
        )

    def get_all_machines(self, arcade: Optional[ArcadeID] = None) -> List[Machine]:
        """
        Look up all machines on the network.

        Returns:
            A list of Machine objects representing a machine.
        """
        sql = "SELECT pcbid, name, description, arcadeid, id, port, game, version, data FROM machine"
        data = {}
        if arcade is not None:
            sql = sql + " WHERE arcadeid = :arcade"
            data["arcade"] = arcade

        cursor = self.execute(sql, data)
        return [
            Machine(
                result["id"],
                result["pcbid"],
                result["name"],
                result["description"],
                result["arcadeid"],
                result["port"],
                GameConstants(result["game"]) if result["game"] else None,
                result["version"],
                self.deserialize(result["data"]),
            )
            for result in cursor.mappings()
        ]

    def put_machine(self, machine: Machine) -> None:
        """
        Given a Machine object, update the database with new information.

        Parameters:
            machine - A Machine object representing a machine.
        """
        # Update machine name based on game
        sql = """
            UPDATE `machine`
            SET
                name = :name,
                description = :description,
                arcadeid = :arcadeid,
                port = :port,
                game = :game,
                version = :version,
                data = :data
            WHERE pcbid = :pcbid LIMIT 1
        """
        self.execute(
            sql,
            {
                "name": machine.name,
                "description": machine.description,
                "arcadeid": machine.arcade,
                "port": machine.port,
                "game": machine.game.value if machine.game else None,
                "version": machine.version,
                "pcbid": machine.pcbid,
                "data": self.serialize(machine.data),
            },
        )

    def create_machine(
        self,
        pcbid: str,
        name: str = "なし",
        description: str = "",
        arcade: Optional[ArcadeID] = None,
    ) -> Machine:
        """
        Given a PCBID, create a new machine entry.

        Parameters:
            pcbid - The PCBID as returned from a game.
            name - String specifying the name of the machine. Defaults to
                   なし which means nothing in japanese.
            description - String specifying a description of the machine. Defaults to blank.
            arcade - Optional integer specifying the ID of the arcade owning
                     this machine.

        Returns:
            A Machine object representing the newly-created machine.
        """
        while True:
            # Grab next available port
            sql = "SELECT MAX(port) AS port FROM machine"
            cursor = self.execute(sql)
            if cursor.rowcount != 1:
                # No machines yet
                port = None
            else:
                # Grab highest port
                result = cursor.mappings().fetchone()  # type: ignore
                port = result["port"]
                if port is not None:
                    port = port + 1
            # Default if we didn't get a port
            if port is None:
                port = 10000

            # Add new machine
            try:
                sql = """
                    INSERT INTO `machine` (pcbid, name, description, port, arcadeid)
                    VALUES (:pcbid, :name, :description, :port, :arcadeid)
                """
                self.execute(
                    sql,
                    {
                        "pcbid": pcbid,
                        "name": name,
                        "description": description,
                        "port": port,
                        "arcadeid": arcade,
                    },
                )
            except Exception:
                # Failed to add machine, try with new port
                continue

            machine = self.get_machine(pcbid)
            if machine is not None:
                return machine

    def destroy_machine(self, pcbid: str) -> None:
        """
        Given an PCBID, destroy the machine associated with this PCBID.

        Parameters:
            pcbid - The PCBID as returned from a game.
        """
        sql = "DELETE FROM `machine` WHERE pcbid = :pcbid LIMIT 1"
        self.execute(sql, {"pcbid": pcbid})

    def create_arcade(
        self,
        name: str,
        description: str,
        region: int,
        area: Optional[str],
        data: Dict[str, Any],
        owners: List[UserID],
    ) -> Arcade:
        """
        Given a set of values, create a new arcade and return the ID of that arcade.

        Returns:
            An Arcade object representing this arcade
        """
        sql = """
            INSERT INTO arcade (name, description, pref, area, data, pin)
            VALUES (:name, :desc, :pref, :area, :data, '00000000')
        """
        cursor = self.execute(
            sql,
            {
                "name": name,
                "desc": description,
                "pref": region,
                "area": area,
                "data": self.serialize(data),
            },
        )
        if cursor.rowcount != 1:
            raise ArcadeCreationException("Failed to create arcade!")
        arcadeid = cursor.lastrowid
        for owner in owners:
            sql = """
                INSERT INTO arcade_owner (userid, arcadeid)
                VALUES (:userid, :arcadeid)
            """
            self.execute(sql, {"userid": owner, "arcadeid": arcadeid})
        new_arcade = self.get_arcade(arcadeid)
        if new_arcade is None:
            raise Exception("Failed to create an arcade!")
        return new_arcade

    def get_arcade(self, arcadeid: ArcadeID) -> Optional[Arcade]:
        """
        Given an arcade ID, look up the arcade.

        Parameters:
            arcadeid - The integer arcade ID, most likely returned from a get_machine query.

        Returns:
            An Arcade object if this arcade was found, or None otherwise.
        """
        sql = """
            SELECT name, description, pin, pref, area, data
            FROM arcade WHERE id = :id
        """
        cursor = self.execute(sql, {"id": arcadeid})
        if cursor.rowcount != 1:
            # Arcade doesn't exist
            return None

        result = cursor.mappings().fetchone()  # type: ignore

        sql = "SELECT userid FROM arcade_owner WHERE arcadeid = :id"
        cursor = self.execute(sql, {"id": arcadeid})

        return Arcade(
            arcadeid,
            result["name"],
            result["description"],
            result["pin"],
            result["pref"],
            result["area"] or None,
            self.deserialize(result["data"]),
            [owner["userid"] for owner in cursor.mappings()],
        )

    def put_arcade(self, arcade: Arcade) -> None:
        """
        Given an arcade, update the DB to match the new values

        Parameters:
            arcade - An Arcade object that should be updated.
        """
        # Update machine name based on game
        sql = """
            UPDATE `arcade`
            SET
                name = :name,
                description = :desc,
                pin = :pin,
                pref = :pref,
                area = :area,
                data = :data
            WHERE id = :arcadeid
        """
        self.execute(
            sql,
            {
                "name": arcade.name,
                "desc": arcade.description,
                "pin": arcade.pin,
                "pref": arcade.region,
                "area": arcade.area,
                "data": self.serialize(arcade.data),
                "arcadeid": arcade.id,
            },
        )
        sql = "DELETE FROM `arcade_owner` WHERE arcadeid = :arcadeid"
        self.execute(sql, {"arcadeid": arcade.id})
        for owner in arcade.owners:
            sql = """
                INSERT INTO arcade_owner (userid, arcadeid)
                VALUES (:userid, :arcadeid)
            """
            self.execute(sql, {"userid": owner, "arcadeid": arcade.id})

    def destroy_arcade(self, arcadeid: ArcadeID) -> None:
        """
        Given an arcade ID, remove the arcade from the DB and unlink any PCBIDs
        associated with it.

        Parameters:
            arcadeid - Integer specifying the arcade to delete.
        """
        sql = "DELETE FROM `arcade` WHERE id = :arcadeid LIMIT 1"
        self.execute(sql, {"arcadeid": arcadeid})
        sql = "DELETE FROM `arcade_owner` WHERE arcadeid = :arcadeid"
        self.execute(sql, {"arcadeid": arcadeid})
        sql = "UPDATE `machine` SET arcadeid = NULL WHERE arcadeid = :arcadeid"
        self.execute(sql, {"arcadeid": arcadeid})

    def get_all_arcades(self) -> List[Arcade]:
        """
        List all known arcades in the system.

        Returns:
            A list of Arcade objects.
        """
        sql = "SELECT userid, arcadeid FROM arcade_owner"
        cursor = self.execute(sql)
        arcade_to_owners: Dict[int, List[UserID]] = {}
        for row in cursor.mappings():
            arcade = row["arcadeid"]
            owner = UserID(row["userid"])
            if arcade not in arcade_to_owners:
                arcade_to_owners[arcade] = []
            arcade_to_owners[arcade].append(owner)

        sql = "SELECT id, name, description, pin, pref, area, data FROM arcade"
        cursor = self.execute(sql)
        return [
            Arcade(
                ArcadeID(result["id"]),
                result["name"],
                result["description"],
                result["pin"],
                result["pref"],
                result["area"] or None,
                self.deserialize(result["data"]),
                arcade_to_owners.get(result["id"], []),
            )
            for result in cursor.mappings()
        ]

    def get_settings(
        self, arcadeid: ArcadeID, game: GameConstants, version: int, setting: str
    ) -> Optional[ValidatedDict]:
        """
        Given an arcade and a game/version combo, look up this particular setting.

        Parameters:
            arcadeid - Integer specifying the arcade to delete.
            game - Enum value identifying a game series.
            version - String identifying a game version.
            setting - String identifying the particular setting we're interestsed in.

        Returns:
            A dictionary representing game settings, or None if there are no settings for this game/user.
        """
        sql = "SELECT data FROM arcade_settings WHERE arcadeid = :id AND game = :game AND version = :version AND type = :type"
        cursor = self.execute(
            sql,
            {"id": arcadeid, "game": game.value, "version": version, "type": setting},
        )

        if cursor.rowcount != 1:
            # Settings doesn't exist
            return None

        result = cursor.mappings().fetchone()  # type: ignore
        return ValidatedDict(self.deserialize(result["data"]))

    def put_settings(
        self,
        arcadeid: ArcadeID,
        game: GameConstants,
        version: int,
        setting: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Given an arcade and a game/version combo, update the particular setting.

        Parameters:
            arcadeid - Integer specifying the arcade to delete.
            game - Enum value identifying a game series.
            version - String identifying a game version.
            setting - String identifying the particular setting we're interestsed in.
            data - A dictionary that should be saved for this setting.
        """
        sql = """
            INSERT INTO arcade_settings (arcadeid, game, version, type, data)
            VALUES (:id, :game, :version, :type, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "id": arcadeid,
                "game": game.value,
                "version": version,
                "type": setting,
                "data": self.serialize(data),
            },
        )

    def get_balances(self, arcadeid: ArcadeID) -> List[Tuple[UserID, int]]:
        """
        Given an arcade ID, look up all user's PASELI balances for that arcade.

        Parameters:
            arcadeid - The arcade in question.

        Returns:
            The PASELI balance for each user at this arcade.
        """
        sql = "SELECT userid, balance FROM balance WHERE arcadeid = :arcadeid"
        cursor = self.execute(sql, {"arcadeid": arcadeid})
        return [
            (
                UserID(entry["userid"]),
                entry["balance"],
            )
            for entry in cursor.mappings()
        ]

    def create_session(self, arcadeid: ArcadeID, expiration: int = (30 * 86400)) -> str:
        """
        Given a user ID, create a session string.

        Parameters:
            arcadeid - Arcade ID we wish to start a session for.
            expiration - Number of seconds before this session is invalid.

        Returns:
            A string that can be used as a session ID.
        """
        return self._create_session(arcadeid, "arcadeid", expiration)

    def destroy_session(self, session: str) -> None:
        """
        Destroy a previously-created session.

        Parameters:
            session - A session string as returned from create_session.
        """
        self._destroy_session(session, "arcadeid")
