from sqlalchemy import Table, Column, UniqueConstraint  # type: ignore
from sqlalchemy.exc import IntegrityError  # type: ignore
from sqlalchemy.types import String, Integer, JSON  # type: ignore
from sqlalchemy.dialects.mysql import BIGINT as BigInteger  # type: ignore
from typing import Optional, Dict, List, Tuple, Any

from bemani.common import GameConstants, Time
from bemani.data.exceptions import ScoreSaveException
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.types import Score, Attempt, Song, UserID

"""
Table for storing a score for a particular game. This is keyed by userid and
musicid, as a user can only have one score for a particular song/chart combo.
This has a JSON blob for any data the game wishes to store, such as points, medals,
ghost, etc.

Note that this is NOT keyed by game song id and chart, but by an internal musicid
managed by the music table. This is so we can support keeping the same score across
multiple games, even if the game changes the ID it refers to the song by.
"""
score = Table(
    "score",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("musicid", Integer, nullable=False, index=True),
    Column("points", Integer, nullable=False, index=True),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("update", Integer, nullable=False, index=True),
    Column("lid", Integer, nullable=False, index=True),
    Column("data", JSON, nullable=False),
    UniqueConstraint("userid", "musicid", name="userid_musicid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing score history for a particular game. Every entry that is stored
or updated in score will be written into this table as well, for looking up history
over time.
"""
score_history = Table(
    "score_history",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("musicid", Integer, nullable=False, index=True),
    Column("points", Integer, nullable=False),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("lid", Integer, nullable=False, index=True),
    Column("new_record", Integer, nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("userid", "musicid", "timestamp", name="userid_musicid_timestamp"),
    mysql_charset="utf8mb4",
)

"""
Table for storing the mapping between game songid/chart and musicid for the score
and score_history table. To find scores, you will want to join this table with
the score table where id = score.musicid and game/version/songid/chart matches.

NOTE that it is expected to see the same songid/chart present multiple times as long
as the game version changes. In this way, a song which is in multiple versions of
the game can be found when playing each version.
"""
music = Table(
    "music",
    metadata,
    Column("id", Integer, nullable=False, index=True),
    Column("songid", Integer, nullable=False),
    Column("chart", Integer, nullable=False),
    Column("game", String(32), nullable=False, index=True),
    Column("version", Integer, nullable=False, index=True),
    Column("name", String(255)),
    Column("artist", String(255)),
    Column("genre", String(255)),
    Column("data", JSON),
    UniqueConstraint(
        "songid", "chart", "game", "version", name="songid_chart_game_version"
    ),
    mysql_charset="utf8mb4",
)


class MusicData(BaseData):
    def __get_musicid(
        self, game: GameConstants, version: int, songid: int, songchart: int
    ) -> int:
        """
        Given a game/version/songid/chart, look up the unique music ID for this song.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            songid - ID of the song according to the game.
            songchart - Chart number according to the game.

        Returns:
            Integer representing music ID if found or raises an exception otherwise.
        """
        sql = "SELECT id FROM music WHERE songid = :songid AND chart = :chart AND game = :game AND version = :version"
        cursor = self.execute(
            sql,
            {
                "songid": songid,
                "chart": songchart,
                "game": game.value,
                "version": version,
            },
        )
        if cursor.rowcount != 1:
            # music doesn't exist
            raise Exception(
                f"Song {songid} chart {songchart} doesn't exist for game {game} version {version}"
            )
        result = cursor.fetchone()
        return result["id"]

    def put_score(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        songid: int,
        songchart: int,
        location: int,
        points: int,
        data: Dict[str, Any],
        new_record: bool,
        timestamp: Optional[int] = None,
    ) -> None:
        """
        Given a game/version/song/chart and user ID, save a new/updated high score.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.
            songid - ID of the song according to the game.
            songchart - Chart number according to the game.
            location - Machine ID where this score was earned.
            points - Points obtained on this song.
            data - Data that the game wishes to record along with the score.
            new_record - Whether this score was a new record or not.
            timestamp - Optional integer specifying when the high score happened.
        """
        # First look up the song/chart from the music DB
        musicid = self.__get_musicid(game, version, songid, songchart)
        ts = timestamp if timestamp is not None else Time.now()

        # Add to user score
        if new_record:
            # We want to update the timestamp/location to now if its a new record.
            sql = """
                INSERT INTO `score` (`userid`, `musicid`, `points`, `data`, `timestamp`, `update`, `lid`)
                VALUES (:userid, :musicid, :points, :data, :timestamp, :update, :location)
                ON DUPLICATE KEY UPDATE
                    data = VALUES(data),
                    points = VALUES(points),
                    `update` = VALUES(`update`),
                    timestamp = VALUES(timestamp),
                    lid = VALUES(lid)
            """
        else:
            # We don't want to add the timestamp of the record since it wasn't a new high score.
            # We also don't want to update thet location since this wasn't a new record.
            sql = """
                INSERT INTO `score` (`userid`, `musicid`, `points`, `data`, `timestamp`, `update`, `lid`)
                VALUES (:userid, :musicid, :points, :data, :timestamp, :update, :location)
                ON DUPLICATE KEY UPDATE
                    data = VALUES(data),
                    points = VALUES(points),
                    `update` = VALUES(`update`)
            """
        self.execute(
            sql,
            {
                "userid": userid,
                "musicid": musicid,
                "points": points,
                "data": self.serialize(data),
                "timestamp": ts,
                "update": ts,
                "location": location,
            },
        )

    def put_attempt(
        self,
        game: GameConstants,
        version: int,
        userid: Optional[UserID],
        songid: int,
        songchart: int,
        location: int,
        points: int,
        data: Dict[str, Any],
        new_record: bool,
        timestamp: Optional[int] = None,
    ) -> None:
        """
        Given a game/version/song/chart and user ID, save a single score attempt.

        Note that this is different than put_score above, because a user may have only one score
        per song/chart in a given game, but they can have as many history entries as times played.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.
            songid - ID of the song according to the game.
            songchart - Chart number according to the game.
            location - Machine ID where this score was earned.
            points - Points obtained on this song.
            data - Optional data that the game wishes to record along with the score.
            new_record - Whether this score was a new record or not.
            timestamp - Optional integer specifying when the attempt happened.
        """
        # First look up the song/chart from the music DB
        musicid = self.__get_musicid(game, version, songid, songchart)
        ts = timestamp if timestamp is not None else Time.now()

        # Add to score history
        sql = """
            INSERT INTO `score_history` (userid, musicid, timestamp, lid, new_record, points, data)
            VALUES (:userid, :musicid, :timestamp, :location, :new_record, :points, :data)
        """
        try:
            self.execute(
                sql,
                {
                    "userid": userid if userid is not None else 0,
                    "musicid": musicid,
                    "timestamp": ts,
                    "location": location,
                    "new_record": 1 if new_record else 0,
                    "points": points,
                    "data": self.serialize(data),
                },
            )
        except IntegrityError:
            raise ScoreSaveException(
                f"There is already an attempt by {userid if userid is not None else 0} for music id {musicid} at {ts}"
            )

    def get_score(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        songid: int,
        songchart: int,
    ) -> Optional[Score]:
        """
        Look up a user's previous high score.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.
            songid - ID of the song according to the game.
            songchart - Chart number according to the game.

        Returns:
            The optional data stored by the game previously, or None if no score exists.
        """
        sql = """
            SELECT
                music.songid AS songid,
                music.chart AS chart,
                score.id AS scorekey,
                score.timestamp AS timestamp,
                score.update AS `update`,
                score.lid AS lid,
                (
                    SELECT COUNT(score_history.timestamp)
                    FROM score_history
                    WHERE score_history.musicid = music.id AND score_history.userid = :userid
                ) AS plays,
                score.points AS points,
                score.data AS data
            FROM score, music
            WHERE
                score.userid = :userid AND
                score.musicid = music.id AND
                music.game = :game AND
                music.version = :version AND
                music.songid = :songid AND
                music.chart = :songchart
        """
        cursor = self.execute(
            sql,
            {
                "userid": userid,
                "game": game.value,
                "version": version,
                "songid": songid,
                "songchart": songchart,
            },
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return Score(
            result["scorekey"],
            result["songid"],
            result["chart"],
            result["points"],
            result["timestamp"],
            result["update"],
            result["lid"],
            result["plays"],
            self.deserialize(result["data"]),
        )

    def get_score_by_key(
        self, game: GameConstants, version: int, key: int
    ) -> Optional[Tuple[UserID, Score]]:
        """
        Look up previous high score by key.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            key - Integer representing a unique key fetched in a previous Score lookup.

        Returns:
            The optional data stored by the game previously, or None if no score exists.
        """
        sql = """
            SELECT
                music.songid AS songid,
                music.chart AS chart,
                score.id AS scorekey,
                score.timestamp AS timestamp,
                score.update AS `update`,
                score.userid AS userid,
                score.lid AS lid,
                (
                    SELECT COUNT(score_history.timestamp)
                    FROM score_history
                    WHERE score_history.musicid = music.id AND score_history.userid = score.userid
                ) AS plays,
                score.points AS points,
                score.data AS data
            FROM score, music
            WHERE
                score.id = :scorekey AND
                score.musicid = music.id AND
                music.game = :game AND
                music.version = :version
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "scorekey": key,
            },
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return (
            UserID(result["userid"]),
            Score(
                result["scorekey"],
                result["songid"],
                result["chart"],
                result["points"],
                result["timestamp"],
                result["update"],
                result["lid"],
                result["plays"],
                self.deserialize(result["data"]),
            ),
        )

    def get_scores(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Score]:
        """
        Look up all of a user's previous high scores.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.

        Returns:
            A list of Score objects representing all high scores for a game.
        """
        sql = """
            SELECT
                music.songid AS songid,
                music.chart AS chart,
                score.id AS scorekey,
                score.timestamp AS timestamp,
                score.update AS `update`,
                score.lid AS lid,
                (
                    select COUNT(score_history.timestamp) FROM score_history
                    WHERE score_history.musicid = music.id AND score_history.userid = :userid
                ) AS plays,
                score.points AS points,
                score.data AS data
            FROM score, music
            WHERE
                score.userid = :userid AND
                score.musicid = music.id AND
                music.game = :game AND
                music.version = :version
        """
        if since is not None:
            sql = sql + " AND score.update >= :since"
        if until is not None:
            sql = sql + " AND score.update < :until"
        cursor = self.execute(
            sql,
            {
                "userid": userid,
                "game": game.value,
                "version": version,
                "since": since,
                "until": until,
            },
        )

        return [
            Score(
                result["scorekey"],
                result["songid"],
                result["chart"],
                result["points"],
                result["timestamp"],
                result["update"],
                result["lid"],
                result["plays"],
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]

    def get_most_played(
        self, game: GameConstants, version: int, userid: UserID, count: int
    ) -> List[Tuple[int, int]]:
        """
        Look up a user's most played songs.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.
            count - Number of scores to look up.

        Returns:
            A list of tuples, containing the songid and the number of plays across all charts for that song.
        """
        sql = """
            SELECT
                music.songid AS songid,
                COUNT(score_history.timestamp) AS plays
            FROM score_history, music
            WHERE
                score_history.userid = :userid AND
                score_history.musicid = music.id AND
                music.game = :game AND
                music.version = :version
            GROUP BY songid ORDER BY plays DESC LIMIT :count
        """
        cursor = self.execute(
            sql,
            {"userid": userid, "game": game.value, "version": version, "count": count},
        )

        return [(result["songid"], result["plays"]) for result in cursor]

    def get_last_played(
        self, game: GameConstants, version: int, userid: UserID, count: int
    ) -> List[Tuple[int, int]]:
        """
        Look up a user's last played songs.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userid - Integer representing a user. Usually looked up with UserData.
            count - Number of scores to look up.

        Returns:
            A list of tuples, containing the songid and the last played time for this song.
        """
        sql = """
            SELECT
                DISTINCT(music.songid) AS songid,
                score_history.timestamp AS timestamp
            FROM score_history, music
            WHERE
                score_history.userid = :userid AND
                score_history.musicid = music.id AND
                music.game = :game AND
                music.version = :version
            ORDER BY timestamp DESC LIMIT :count
        """
        cursor = self.execute(
            sql,
            {"userid": userid, "game": game.value, "version": version, "count": count},
        )

        return [(result["songid"], result["timestamp"]) for result in cursor]

    def get_hit_chart(
        self,
        game: GameConstants,
        version: int,
        count: int,
        days: Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """
        Look up a game's most played songs.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            count - Number of scores to look up.

        Returns:
            A list of tuples, containing the songid and the number of plays across all charts for that song.
        """
        sql = """
            SELECT
                music.songid AS songid,
                COUNT(score_history.timestamp) AS plays
            FROM score_history, music
            WHERE
                score_history.musicid = music.id AND
                music.game = :game AND
                music.version = :version
        """
        timestamp: Optional[int] = None
        if days is not None:
            # Only select the last X days of hit chart
            sql = sql + "AND score_history.timestamp > :timestamp "
            timestamp = Time.now() - (Time.SECONDS_IN_DAY * days)

        sql = sql + "GROUP BY songid ORDER BY plays DESC LIMIT :count"
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "count": count,
                "timestamp": timestamp,
            },
        )

        return [(result["songid"], result["plays"]) for result in cursor]

    def get_song(
        self,
        game: GameConstants,
        version: int,
        songid: int,
        songchart: int,
    ) -> Optional[Song]:
        """
        Given a game/version/songid/chart, look up the name, artist and genre of that song.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            songid - Integer representing the ID (from the game) for this song.
            songchart - Integer representing the chart for this song.

        Returns:
            A Song object representing the song details
        """
        sql = """
            SELECT
                music.name AS name,
                music.artist AS artist,
                music.genre AS genre,
                music.data AS data
            FROM music
            WHERE
                music.game = :game AND
                music.version = :version AND
                music.songid = :songid AND
                music.chart = :songchart
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "songid": songid,
                "songchart": songchart,
            },
        )
        if cursor.rowcount != 1:
            # music doesn't exist
            return None
        result = cursor.fetchone()
        return Song(
            game,
            version,
            songid,
            songchart,
            result["name"],
            result["artist"],
            result["genre"],
            self.deserialize(result["data"]),
        )

    def get_all_songs(
        self,
        game: GameConstants,
        version: Optional[int] = None,
    ) -> List[Song]:
        """
        Given a game and a version, look up all song/chart combos associated with that game.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.

        Returns:
            A list of Song objects detailing the song information for each song.
        """
        sql = """
            SELECT version, songid, chart, name, artist, genre, data
            FROM music WHERE music.game = :game
        """
        params: Dict[str, Any] = {"game": game.value}
        if version is not None:
            sql += " AND music.version = :version"
            params["version"] = version
        else:
            sql += " ORDER BY music.version DESC"
        cursor = self.execute(sql, params)

        return [
            Song(
                game,
                result["version"],
                result["songid"],
                result["chart"],
                result["name"],
                result["artist"],
                result["genre"],
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]

    def get_all_scores(
        self,
        game: GameConstants,
        version: Optional[int] = None,
        userid: Optional[UserID] = None,
        songid: Optional[int] = None,
        songchart: Optional[int] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Tuple[UserID, Score]]:
        """
        Look up all of a game's high scores for all users.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.

        Returns:
            A list of UserID, Score objects representing all high scores for a game.
        """
        # First, construct the queries for grabbing the songid/chart
        if version is not None:
            songidquery = "SELECT songid FROM music WHERE music.id = score.musicid AND game = :game AND version = :version"
            chartquery = "SELECT chart FROM music WHERE music.id = score.musicid AND game = :game AND version = :version"
        else:
            songidquery = "SELECT songid FROM music WHERE music.id = score.musicid AND game = :game ORDER BY version DESC LIMIT 1"
            chartquery = "SELECT chart FROM music WHERE music.id = score.musicid AND game = :game ORDER BY version DESC LIMIT 1"

        # Select statement for getting play count
        playselect = "SELECT COUNT(timestamp) FROM score_history WHERE score_history.musicid = score.musicid AND score_history.userid = score.userid"

        # Now, construct the inner select statement so we can choose which scores we care about
        innerselect = "SELECT DISTINCT(id) FROM music WHERE game = :game"
        if version is not None:
            innerselect = innerselect + " AND version = :version"
        if songid is not None:
            innerselect = innerselect + " AND songid = :songid"
        if songchart is not None:
            innerselect = innerselect + " AND chart = :songchart"

        # Finally, construct the full query
        sql = f"""
            SELECT
                ({songidquery}) AS songid,
                ({chartquery}) AS chart,
                id AS scorekey,
                points,
                timestamp,
                `update`,
                lid,
                data,
                userid,
                ({playselect}) AS plays
            FROM score WHERE musicid IN ({innerselect})
        """

        # Now, limit the query
        if userid is not None:
            sql = sql + " AND userid = :userid"
        if since is not None:
            sql = sql + " AND score.update >= :since"
        if until is not None:
            sql = sql + " AND score.update < :until"

        # Now, query itself
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "songid": songid,
                "songchart": songchart,
                "since": since,
                "until": until,
            },
        )

        # Objectify result
        return [
            (
                UserID(result["userid"]),
                Score(
                    result["scorekey"],
                    result["songid"],
                    result["chart"],
                    result["points"],
                    result["timestamp"],
                    result["update"],
                    result["lid"],
                    result["plays"],
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]

    def get_all_records(
        self,
        game: GameConstants,
        version: Optional[int] = None,
        userlist: Optional[List[UserID]] = None,
        locationlist: Optional[List[int]] = None,
    ) -> List[Tuple[UserID, Score]]:
        """
        Look up all of a game's records, only returning the top score for each song. For score ties,
        king-of-the-hill rules are in effect, so for two players with an identical top score, the player
        that got the score last wins. If a list of user IDs is given, we will only look up records pertaining
        to those users. So if another user has a higher record, we will ignore this. This can be used to
        display area-local high scores, etc.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            userlist - List of UserIDs to limit the search to.
            locationlist - A list of location IDs to limit searches to.

        Returns:
            A list of UserID, Score objects representing all high scores for a game.
        """
        # First, construct the queries for grabbing the songid/chart
        if version is not None:
            songidquery = "SELECT songid FROM music WHERE music.id = score.musicid AND game = :game AND version = :version"
            chartquery = "SELECT chart FROM music WHERE music.id = score.musicid AND game = :game AND version = :version"
        else:
            songidquery = "SELECT songid FROM music WHERE music.id = score.musicid AND game = :game ORDER BY version DESC LIMIT 1"
            chartquery = "SELECT chart FROM music WHERE music.id = score.musicid AND game = :game ORDER BY version DESC LIMIT 1"

        # Next, get a list of all songs that were played given the input criteria
        musicid_sql = "SELECT DISTINCT(score.musicid) FROM score, music WHERE score.musicid = music.id AND music.game = :game"
        params: Dict[str, Any] = {"game": game.value}
        if version is not None:
            musicid_sql = musicid_sql + " AND music.version = :version"
            params["version"] = version

        # Figure out where the record was earned
        if locationlist is not None:
            if len(locationlist) == 0:
                # We don't have any locations, but SQL will shit the bed, so lets add a default one.
                locationlist.append(-1)
            location_sql = "AND score.lid IN :locationlist"
            params["locationlist"] = tuple(locationlist)
        else:
            location_sql = ""

        # Figure out who got the record
        if userlist is not None:
            if len(userlist) == 0:
                # We don't have any users, but SQL will shit the bed, so lets add a fake one.
                userlist.append(UserID(-1))
            user_sql = f"SELECT userid FROM score WHERE score.musicid = played.musicid AND score.userid IN :userlist {location_sql} ORDER BY points DESC, timestamp DESC LIMIT 1"
            params["userlist"] = tuple(userlist)
        else:
            user_sql = f"SELECT userid FROM score WHERE score.musicid = played.musicid {location_sql} ORDER BY points DESC, timestamp DESC LIMIT 1"
        records_sql = f"""
            SELECT ({user_sql}) AS userid, musicid
            FROM ({musicid_sql}) played
        """

        # Now, join it up against the score and music table to grab the info we need
        sql = f"""
            SELECT
                ({songidquery}) AS songid,
                ({chartquery}) AS chart,
                score.points AS points,
                score.userid AS userid,
                score.id AS scorekey,
                score.data AS data,
                score.timestamp AS timestamp,
                score.update AS `update`,
                score.lid AS lid,
                (
                    SELECT COUNT(score_history.timestamp) FROM score_history
                    WHERE score_history.musicid = score.musicid
                ) AS plays
            FROM score, ({records_sql}) records
            WHERE records.userid = score.userid AND records.musicid = score.musicid
        """
        cursor = self.execute(sql, params)

        return [
            (
                UserID(result["userid"]),
                Score(
                    result["scorekey"],
                    result["songid"],
                    result["chart"],
                    result["points"],
                    result["timestamp"],
                    result["update"],
                    result["lid"],
                    result["plays"],
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]

    def get_attempt_by_key(
        self, game: GameConstants, version: int, key: int
    ) -> Optional[Tuple[UserID, Attempt]]:
        """
        Look up a previous attempt by key.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.
            key - Integer representing a unique key fetched in a previous Attempt lookup.

        Returns:
            The optional data stored by the game previously, or None if no score exists.
        """
        sql = """
            SELECT
                music.songid AS songid,
                music.chart AS chart,
                score_history.id AS scorekey,
                score_history.timestamp AS timestamp,
                score_history.userid AS userid,
                score_history.lid AS lid,
                score_history.new_record AS new_record,
                score_history.points AS points,
                score_history.data AS data
            FROM score_history, music
            WHERE
                score_history.id = :scorekey AND
                score_history.musicid = music.id AND
                music.game = :game AND
                music.version = :version
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "scorekey": key,
            },
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return (
            UserID(result["userid"]),
            Attempt(
                result["scorekey"],
                result["songid"],
                result["chart"],
                result["points"],
                result["timestamp"],
                result["lid"],
                result["new_record"] == 1,
                self.deserialize(result["data"]),
            ),
        )

    def get_all_attempts(
        self,
        game: GameConstants,
        version: Optional[int] = None,
        userid: Optional[UserID] = None,
        songid: Optional[int] = None,
        songchart: Optional[int] = None,
        timelimit: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> List[Tuple[Optional[UserID], Attempt]]:
        """
        Look up all of the attempts to score for a particular game.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.

        Returns:
            A list of UserID, Attempt objects representing all score attempts for a game, sorted newest to oldest attempts.
        """
        # First, construct the queries for grabbing the songid/chart
        if version is not None:
            songidquery = "SELECT songid FROM music WHERE music.id = score_history.musicid AND game = :game AND version = :version"
            chartquery = "SELECT chart FROM music WHERE music.id = score_history.musicid AND game = :game AND version = :version"
        else:
            songidquery = "SELECT songid FROM music WHERE music.id = score_history.musicid AND game = :game ORDER BY version DESC LIMIT 1"
            chartquery = "SELECT chart FROM music WHERE music.id = score_history.musicid AND game = :game ORDER BY version DESC LIMIT 1"

        # Now, construct the inner select statement so we can choose which scores we care about
        innerselect = "SELECT DISTINCT(id) FROM music WHERE game = :game"
        if version is not None:
            innerselect = innerselect + " AND version = :version"
        if songid is not None:
            innerselect = innerselect + " AND songid = :songid"
        if songchart is not None:
            innerselect = innerselect + " AND chart = :songchart"

        # Finally, construct the full query
        sql = f"""
            SELECT
                ({songidquery}) AS songid,
                ({chartquery}) AS chart,
                id AS scorekey,
                timestamp,
                points,
                new_record,
                lid,
                data,
                userid
            FROM score_history WHERE musicid IN ({innerselect})
        """

        # Now, limit the query
        if userid is not None:
            sql = sql + " AND userid = :userid"
        if timelimit is not None:
            sql = sql + " AND timestamp >= :timestamp"
        sql = sql + " ORDER BY timestamp DESC"
        if limit is not None:
            sql = sql + " LIMIT :limit"
        if offset is not None:
            sql = sql + " OFFSET :offset"

        # Now, query itself
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "songid": songid,
                "songchart": songchart,
                "timestamp": timelimit,
                "limit": limit,
                "offset": offset,
            },
        )

        # Now objectify the attempts
        return [
            (
                UserID(result["userid"]) if result["userid"] > 0 else None,
                Attempt(
                    result["scorekey"],
                    result["songid"],
                    result["chart"],
                    result["points"],
                    result["timestamp"],
                    result["lid"],
                    result["new_record"] == 1,
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]
