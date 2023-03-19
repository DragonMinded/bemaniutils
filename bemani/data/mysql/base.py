import json
import random
from typing import Dict, Any, Optional
from typing_extensions import Final

from bemani.common import Time
from bemani.data.config import Config

from sqlalchemy.engine.base import Connection  # type: ignore
from sqlalchemy.engine import CursorResult  # type: ignore
from sqlalchemy.sql import text  # type: ignore
from sqlalchemy.types import String, Integer  # type: ignore
from sqlalchemy import Table, Column, MetaData  # type: ignore

metadata = MetaData()

"""
Table for storing session IDs, so a session ID can be used to look up an arbitrary ID.
This is currently used for user logins, user and arcade PASELI sessions.
"""
session = Table(
    "session",
    metadata,
    Column("id", Integer, nullable=False),
    Column("type", String(32), nullable=False),
    Column("session", String(32), nullable=False, unique=True),
    Column("expiration", Integer),
    mysql_charset="utf8mb4",
)


class _BytesEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            # We're abusing lists here, we have a mixed type
            return ["__bytes__"] + [b for b in obj]
        return json.JSONEncoder.default(self, obj)


class BaseData:
    SESSION_LENGTH: Final[int] = 32

    def __init__(self, config: Config, conn: Connection) -> None:
        """
        Initialize any DB singleton.

        Should only ever be called by Data.

        Parameters:
            config - config structure which is provided in case any function here
                     needs to look up configuration.
            conn - An established connection to the DB which will be used for all
                   queries.
        """
        self.__config = config
        self.__conn = conn

    def execute(
        self,
        sql: str,
        params: Optional[Dict[str, Any]] = None,
        safe_write_operation: bool = False,
    ) -> CursorResult:
        """
        Given a SQL string and some parameters, execute the query and return the result.

        Parameters:
            sql - The SQL statement to execute.
            params - Dictionary of parameters which will be substituted into the sql string.

        Returns:
            A SQLAlchemy CursorResult object.
        """
        if self.__config.database.read_only:
            # See if this is an insert/update/delete
            lowered = sql.lower()
            for write_statement_group in [
                ["insert into"],
                ["update", "set"],
                ["delete from"],
            ]:
                includes = all(s in lowered for s in write_statement_group)
                if includes and not safe_write_operation:
                    raise Exception("Read-only mode is active!")
        return self.__conn.execute(
            text(sql),
            params if params is not None else {},
        )

    def serialize(self, data: Dict[str, Any]) -> str:
        """
        Given an arbitrary dict, serialize it to JSON.
        """
        return json.dumps(data, cls=_BytesEncoder)

    def deserialize(self, data: Optional[str]) -> Dict[str, Any]:
        """
        Given a string, deserialize it from JSON.
        """
        if data is None:
            return {}

        def fix(jd: Any) -> Any:
            if type(jd) == dict:
                # Fix each element in the dictionary.
                for key in jd:
                    jd[key] = fix(jd[key])
                return jd

            if type(jd) == list:
                # Could be serialized by us, could be a normal list.
                if len(jd) >= 1 and jd[0] == "__bytes__":
                    # This is a serialized bytestring
                    return bytes(jd[1:])

                # Possibly one of these is a dictionary/list/serialized.
                for i in range(len(jd)):
                    jd[i] = fix(jd[i])
                return jd

            # Normal value, its deserialized version is itself.
            return jd

        return fix(json.loads(data))

    def _from_session(self, session: str, sesstype: str) -> Optional[int]:
        """
        Given a previously-opened session, look up an ID.

        Parameters:
            session - String identifying a session that was opened by create_session.
            sesstype - Arbitrary string identifying the session type.

        Returns:
            ID as an integer if found, or None if the session is expired or doesn't exist.
        """
        # Look up the user account, making sure to expire old sessions
        sql = "SELECT id FROM session WHERE session = :session AND type = :type AND expiration > :timestamp"
        cursor = self.execute(
            sql, {"session": session, "type": sesstype, "timestamp": Time.now()}
        )
        if cursor.rowcount != 1:
            # Couldn't find a user with this session
            return None

        result = cursor.fetchone()
        return result["id"]

    def _create_session(
        self, opid: int, optype: str, expiration: int = (30 * 86400)
    ) -> str:
        """
        Given an ID, create a session string.

        Parameters:
            opid - ID we wish to start a session for.
            expiration - Number of seconds before this session is invalid.

        Returns:
            A string that can be used as a session ID.
        """
        # Create a new session that is unique
        while True:
            session = "".join(
                random.choice("0123456789ABCDEF")
                for _ in range(BaseData.SESSION_LENGTH)
            )
            sql = "SELECT session FROM session WHERE session = :session"
            cursor = self.execute(sql, {"session": session})
            if cursor.rowcount == 0:
                # Make sure sessions expire in a reasonable amount of time
                expiration = Time.now() + expiration

                # Use that session
                sql = """
                    INSERT INTO session (id, session, type, expiration)
                    VALUES (:id, :session, :optype, :expiration)
                """
                cursor = self.execute(
                    sql,
                    {
                        "id": opid,
                        "session": session,
                        "optype": optype,
                        "expiration": expiration,
                    },
                    safe_write_operation=True,
                )
                if cursor.rowcount == 1:
                    return session

    def _destroy_session(self, session: str, sesstype: str) -> None:
        """
        Destroy a previously-created session.

        Parameters:
            session - A session string as returned from create_session.
        """
        # Remove the session token
        sql = "DELETE FROM session WHERE session = :session AND type = :sesstype"
        self.execute(
            sql, {"session": session, "sesstype": sesstype}, safe_write_operation=True
        )

        # Also weed out any other defunct sessions
        sql = "DELETE FROM session WHERE expiration < :timestamp"
        self.execute(sql, {"timestamp": Time.now()}, safe_write_operation=True)
