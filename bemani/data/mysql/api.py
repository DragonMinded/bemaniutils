import uuid
from sqlalchemy import Table, Column  # type: ignore
from sqlalchemy.types import String, Integer  # type: ignore
from typing import Any, Dict, List, Optional

from bemani.common import Time
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.interfaces import APIProviderInterface
from bemani.data.types import Client, Server

"""
Table for storing registered clients to a data exchange API, as added
by an admin.
"""
client = Table(
    "client",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("name", String(255), nullable=False),
    Column("token", String(36), nullable=False),
    mysql_charset="utf8mb4",
)

"""
Table for storing remote servers to a data exchange API, as added
by an admin.
"""
server = Table(
    "server",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("uri", String(1024), nullable=False),
    Column("token", String(64), nullable=False),
    Column("config", Integer, nullable=False),
    mysql_charset="utf8mb4",
)


class APIData(APIProviderInterface, BaseData):
    def get_all_clients(self) -> List[Client]:
        """
        Grab all authorized clients in the system.

        Returns:
            A list of Client objects sorted by add time.
        """
        sql = "SELECT id, timestamp, name, token FROM client ORDER BY timestamp ASC"
        cursor = self.execute(sql)
        return [
            Client(
                result["id"],
                result["timestamp"],
                result["name"],
                result["token"],
            )
            for result in cursor
        ]

    def validate_client(self, token: str) -> bool:
        """
        Given a client ID, return whether this client is authorized or not.

        Parameters:
            token - String that a client passes to us.

        Returns:
            True if the client is authorized, False otherwise.
        """
        sql = "SELECT count(*) AS count FROM client WHERE token = :token"
        cursor = self.execute(sql, {"token": token})
        return cursor.fetchone()["count"] == 1

    def create_client(self, name: str) -> int:
        """
        Given a name, create a new client and generate an authorization token.

        Parameters:
            name - String name of the client.

        Returns:
            The ID of the newly created client.
        """
        sql = "INSERT INTO client (timestamp, name, token) VALUES (:timestamp, :name, :token)"
        cursor = self.execute(
            sql,
            {
                "timestamp": Time.now(),
                "name": name,
                "token": str(uuid.uuid4()),
            },
        )
        return cursor.lastrowid

    def get_client(self, clientid: int) -> Optional[Client]:
        """
        Given a client ID, grab that client from the DB.

        Parameters:
            clientid - Integer specifying client ID.

        Returns:
            A Client object if the client entry was found or None otherwise.
        """
        sql = "SELECT timestamp, name, token FROM client WHERE id = :id"
        cursor = self.execute(sql, {"id": clientid})
        if cursor.rowcount != 1:
            # Couldn't find an entry with this ID
            return None

        result = cursor.fetchone()
        return Client(
            clientid,
            result["timestamp"],
            result["name"],
            result["token"],
        )

    def put_client(self, client: Client) -> None:
        """
        Given a client object, store it back into the DB.

        Parameters:
            client - A Client object to be updated.
        """
        sql = "UPDATE client SET name = :name WHERE id = :id"
        self.execute(sql, {"id": client.id, "name": client.name})

    def destroy_client(self, clientid: int) -> None:
        """
        Given a client ID, remove that client from the DB.

        Parameters:
            clientid - Integer specifying client ID.
        """
        sql = "DELETE FROM client WHERE id = :id LIMIT 1"
        self.execute(sql, {"id": clientid})

    def get_all_servers(self) -> List[Server]:
        """
        Grab all authorized servers in the system.

        Returns:
            A list of Server objects sorted by add time.
        """

        def format_result(result: Dict[str, Any]) -> Server:
            allow_stats = (result["config"] & 0x1) == 0
            allow_scores = (result["config"] & 0x2) == 0
            return Server(
                result["id"],
                result["timestamp"],
                result["uri"],
                result["token"],
                allow_stats,
                allow_scores,
            )

        sql = "SELECT id, timestamp, uri, token, config FROM server ORDER BY timestamp ASC"
        cursor = self.execute(sql)
        return [format_result(result) for result in cursor]

    def create_server(self, uri: str, token: str) -> int:
        """
        Given a uri and a token, create a new server.

        Parameters:
            uri - String name of the server.
            token - Authorization token we will use when talking to the server.

        Returns:
            The ID of the newly created server.
        """
        sql = "INSERT INTO server (timestamp, uri, token, config) VALUES (:timestamp, :uri, :token, 0)"
        cursor = self.execute(
            sql,
            {
                "timestamp": Time.now(),
                "uri": uri,
                "token": token,
            },
        )
        return cursor.lastrowid

    def get_server(self, serverid: int) -> Optional[Server]:
        """
        Given a server ID, grab that server from the DB.

        Parameters:
            serverid - Integer specifying server ID.

        Returns:
            A Server object if the server entry was found or None otherwise.
        """
        sql = "SELECT timestamp, uri, token, config FROM server WHERE id = :id"
        cursor = self.execute(sql, {"id": serverid})
        if cursor.rowcount != 1:
            # Couldn't find an entry with this ID
            return None

        result = cursor.fetchone()
        allow_stats = (result["config"] & 0x1) == 0
        allow_scores = (result["config"] & 0x2) == 0
        return Server(
            serverid,
            result["timestamp"],
            result["uri"],
            result["token"],
            allow_stats,
            allow_scores,
        )

    def put_server(self, server: Server) -> None:
        """
        Given a server object, store it back into the DB.

        Parameters:
            server - A Server object to be updated.
        """
        config = 0
        if not server.allow_stats:
            config = config | 0x1
        if not server.allow_scores:
            config = config | 0x2
        sql = "UPDATE server SET uri = :uri, token = :token, config = :config WHERE id = :id"
        self.execute(
            sql,
            {
                "id": server.id,
                "uri": server.uri,
                "token": server.token,
                "config": config,
            },
        )

    def destroy_server(self, serverid: int) -> None:
        """
        Given a server ID, remove that server from the DB.

        Parameters:
            serverid - Integer specifying server ID.
        """
        sql = "DELETE FROM server WHERE id = :id LIMIT 1"
        self.execute(sql, {"id": serverid})
