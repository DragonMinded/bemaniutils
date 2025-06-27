from sqlalchemy import Table, Column, UniqueConstraint
from sqlalchemy.types import String, Integer, Text, JSON
from sqlalchemy.dialects.mysql import BIGINT as BigInteger
from typing import Optional, Dict, List, Tuple, Any

from bemani.common import GameConstants, Time
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.types import News, Event, UserID, ArcadeID

"""
Table for storing network news, as edited by an admin. This is displayed
on the front page of the frontend of the network.
"""
news = Table(
    "news",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("title", String(255), nullable=False),
    Column("body", Text, nullable=False),
    mysql_charset="utf8mb4",
)

"""
Table for storing scheduled work history, so that individual game code
can determine if it should run scheduled work or not.
"""
scheduled_work = Table(
    "scheduled_work",
    metadata,
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("name", String(32), nullable=False),
    Column("schedule", String(32), nullable=False),
    Column("year", Integer),
    Column("day", Integer),
    UniqueConstraint("game", "version", "name", "schedule", name="game_version_name_schedule"),
    mysql_charset="utf8mb4",
)

"""
Table for storing audit entries, such as crashes, PCBID denials, daily
song selection, etc. Anything that could be inspected later to verify
correct operation of the network.
"""
audit = Table(
    "audit",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("userid", BigInteger(unsigned=True), index=True),
    Column("arcadeid", Integer, index=True),
    Column("type", String(64), nullable=False, index=True),
    Column("data", JSON, nullable=False),
    mysql_charset="utf8mb4",
)


class NetworkData(BaseData):
    def get_all_news(self) -> List[News]:
        """
        Grab all news in the system.

        Returns:
            A list of News objects sorted by timestamp.
        """
        sql = "SELECT id, timestamp, title, body FROM news ORDER BY timestamp DESC"
        cursor = self.execute(sql)
        return [
            News(
                result["id"],
                result["timestamp"],
                result["title"],
                result["body"],
            )
            for result in cursor.mappings()
        ]

    def create_news(self, title: str, body: str) -> int:
        """
        Given a title and body, create a new news entry.

        Parameters:
            title - String title of the entry.
            body - String body of the entry, may contain HTML.

        Returns:
            The ID of the newly created entry.
        """
        sql = "INSERT INTO news (timestamp, title, body) VALUES (:timestamp, :title, :body)"
        cursor = self.execute(sql, {"timestamp": Time.now(), "title": title, "body": body})
        return cursor.lastrowid

    def get_news(self, newsid: int) -> Optional[News]:
        """
        Given a news ID, grab that news entry from the DB.

        Parameters:
            newsid - Integer specifying news ID.

        Returns:
            A News object if the news entry was found or None otherwise.
        """
        sql = "SELECT timestamp, title, body FROM news WHERE id = :id"
        cursor = self.execute(sql, {"id": newsid})
        if cursor.rowcount != 1:
            # Couldn't find an entry with this ID
            return None

        result = cursor.mappings().fetchone()  # type: ignore
        return News(
            newsid,
            result["timestamp"],
            result["title"],
            result["body"],
        )

    def put_news(self, news: News) -> None:
        """
        Given a news object, store it back into the DB.

        Parameters:
            news - A News object to be updated.
        """
        sql = "UPDATE news SET title = :title, body = :body WHERE id = :id"
        self.execute(sql, {"id": news.id, "title": news.title, "body": news.body})

    def destroy_news(self, newsid: int) -> None:
        """
        Given a news ID, remove that news entry from the DB.

        Parameters:
            newsid - Integer specifying news ID.
        """
        sql = "DELETE FROM news WHERE id = :id LIMIT 1"
        self.execute(sql, {"id": newsid})

    def get_schedule_duration(self, schedule: str) -> Tuple[int, int]:
        """
        Given a schedule type, returns the timestamp for the start and end
        of the current schedule of this type.
        """
        if schedule not in ["daily", "weekly"]:
            raise Exception("Logic error, specify either 'daily' or 'weekly' for schedule type!")

        if schedule == "daily":
            return (Time.beginning_of_today(), Time.end_of_today())

        if schedule == "weekly":
            return (Time.beginning_of_this_week(), Time.end_of_this_week())

        # Should never happen
        return (0, 0)

    def should_schedule(self, game: GameConstants, version: int, name: str, schedule: str) -> bool:
        """
        Given a game/version/name pair and a schedule value, return whether
        this scheduled work is overdue or not.
        """
        if schedule not in ["daily", "weekly"]:
            raise Exception("Logic error, specify either 'daily' or 'weekly' for schedule type!")

        sql = """
            SELECT year, day FROM scheduled_work
            WHERE
                game = :game AND
                version = :version AND
                name = :name AND
                schedule = :schedule
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "name": name,
                "schedule": schedule,
            },
        )
        if cursor.rowcount != 1:
            # No scheduled work was registered, so time to get going!
            return True

        result = cursor.mappings().fetchone()  # type: ignore

        if schedule == "daily":
            # Just look at the day and year, make sure it matches
            year, day = Time.days_into_year()
            if year != result["year"]:
                # Wrong year, so we certainly need to run!
                return True
            if day != result["day"]:
                # Wrong day and we're daily, so need to run!
                return True

        if schedule == "weekly":
            # Find the beginning of the week (Monday), as days since epoch.
            if Time.week_in_days_since_epoch() != result["day"]:
                # Wrong week, so we should run!
                return True

        # We have already run this work for this schedule
        return False

    def mark_scheduled(self, game: GameConstants, version: int, name: str, schedule: str) -> None:
        if schedule not in ["daily", "weekly"]:
            raise Exception("Logic error, specify either 'daily' or 'weekly' for schedule type!")

        if schedule == "daily":
            year, day = Time.days_into_year()
            sql = """
                INSERT INTO scheduled_work (game, version, name, schedule, year, day)
                VALUES (:game, :version, :name, :schedule, :year, :day)
                ON DUPLICATE KEY UPDATE year=VALUES(year), day=VALUES(day)
            """
            self.execute(
                sql,
                {
                    "game": game.value,
                    "version": version,
                    "name": name,
                    "schedule": schedule,
                    "year": year,
                    "day": day,
                },
            )

        if schedule == "weekly":
            days = Time.week_in_days_since_epoch()
            sql = """
                INSERT INTO scheduled_work (game, version, name, schedule, day)
                VALUES (:game, :version, :name, :schedule, :day)
                ON DUPLICATE KEY UPDATE day=VALUES(day)
            """
            self.execute(
                sql,
                {
                    "game": game.value,
                    "version": version,
                    "name": name,
                    "schedule": schedule,
                    "day": days,
                },
            )

    def put_event(
        self,
        event: str,
        data: Dict[str, Any],
        timestamp: Optional[int] = None,
        userid: Optional[UserID] = None,
        arcadeid: Optional[ArcadeID] = None,
    ) -> None:
        if timestamp is None:
            timestamp = Time.now()
        sql = "INSERT INTO audit (timestamp, userid, arcadeid, type, data) VALUES (:ts, :uid, :aid, :type, :data)"
        self.execute(
            sql,
            {
                "ts": timestamp,
                "type": event,
                "data": self.serialize(data),
                "uid": userid,
                "aid": arcadeid,
            },
        )

    def get_events(
        self,
        userid: Optional[UserID] = None,
        arcadeid: Optional[ArcadeID] = None,
        event: Optional[str] = None,
        limit: Optional[int] = None,
        since_id: Optional[int] = None,
        until_id: Optional[int] = None,
    ) -> List[Event]:
        # Base query
        sql = "SELECT id, timestamp, userid, arcadeid, type, data FROM audit "

        # Lets get specific!
        wheres = []
        if userid is not None:
            wheres.append("userid = :userid")
        if arcadeid is not None:
            wheres.append("arcadeid = :arcadeid")
        if event is not None:
            wheres.append("type = :event")
        if since_id is not None:
            wheres.append("id >= :since_id")
        if until_id is not None:
            wheres.append("id < :until_id")
        if len(wheres) > 0:
            sql = sql + f"WHERE {' AND '.join(wheres)} "

        # Order it newest to oldest
        sql = sql + "ORDER BY id DESC"
        if limit is not None:
            sql = sql + " LIMIT :limit"
        cursor = self.execute(
            sql,
            {
                "userid": userid,
                "arcadeid": arcadeid,
                "event": event,
                "limit": limit,
                "since_id": since_id,
                "until_id": until_id,
            },
        )

        return [
            Event(
                result["id"],
                result["timestamp"],
                UserID(result["userid"]) if result["userid"] is not None else None,
                ArcadeID(result["arcadeid"]) if result["arcadeid"] is not None else None,
                result["type"],
                self.deserialize(result["data"]),
            )
            for result in cursor.mappings()
        ]

    def delete_events(self, oldest_event_ts: int) -> None:
        """
        Given a timestamp of the oldset event we should keep around, delete
        all events older than this timestamp.
        """
        sql = "DELETE FROM audit WHERE timestamp < :ts"
        self.execute(sql, {"ts": oldest_event_ts})
