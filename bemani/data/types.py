from typing import Optional, List, Dict, Any, NewType

from bemani.common import ValidatedDict

UserID = NewType('UserID', int)
ArcadeID = NewType('ArcadeID', int)


class User:
    """
    An object representing a user. This is an account that has zero or more
    cards associated with it (starting with 1 when carding in for the first time),
    and possibly has a username/password/email if the user has signed up for
    the frontend. Once that is done, users can remove their only card, or add
    more cards, or swap out a card for a new one.
    """

    def __init__(self, userid: UserID, username: Optional[str], email: Optional[str], admin: bool) -> None:
        """
        Initialize the user object.

        Parameters:
            userid - The ID of the user.
            username - An optional string, set if the user has claimed their account on
                       the web UI.
            email - An optional string, set if the user has claimed their account on the
                    web UI.
        """
        self.id = userid
        self.username = username
        self.email = email
        self.admin = admin

    def __repr__(self) -> str:
        return "User(userid={}, username={}, email={}, admin={})".format(
            self.id,
            self.username,
            self.email,
            self.admin,
        )


class Achievement:
    """
    An object representing a single achievement for a user.

    Achievements are referred to loosely here. An achievement is really any type/id pair
    that can have some attached data, such as item unlocks, tran medals, course progress, etc.
    """

    def __init__(self, achievementid: int, achievementtype: str, timestamp: Optional[int], data: Dict[str, Any]) -> None:
        """
        Initialize the achievement object.

        Parameters:
            achievementid - The ID of the achievement, as assigned by a game class.
            achievementtype - The type of the achievement, as assigned by a game class.
            timestamp - The timestamp this achievement was earned, if available.
            data - Any optional data the game wishes to save and retrieve later.
        """
        self.id = achievementid
        self.type = achievementtype
        self.timestamp = timestamp
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Achievement(achievementid={}, achievementtype={}, timestamp={}, data={})".format(
            self.id,
            self.type,
            self.timestamp,
            self.data,
        )


class Link:
    """
    An object representing a single link between two users. The type of the link is
    determined by the game that needs this linkage.
    """

    def __init__(self, userid: UserID, linktype: str, other_userid: UserID, data: Dict[str, Any]) -> None:
        """
        Initialize the achievement object.

        Parameters:
            userid - The ID of the user.
            linktype - The type of the link, as assigned by a game class.
            other_userid - The ID of the second user we're linked against.
            data - Any optional data the game wishes to save and retrieve later.
        """
        self.userid = userid
        self.type = linktype
        self.other_userid = other_userid
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Link(userid={}, linktype={}, other_userid={}, data={})".format(
            self.userid,
            self.type,
            self.other_userid,
            self.data,
        )


class Machine:
    """
    An object representing a single machine found in the DB. Machines are
    potentially owned by arcades, and keyed by PCBID. There will always be
    a 1:1 mapping between a PCBID seen on the network and a Machine.
    """

    def __init__(
        self,
        machineid: int,
        pcbid: str,
        name: str,
        description: str,
        arcade: Optional[ArcadeID],
        port: int,
        game: Optional[str],
        version: Optional[int],
        data: Dict[str, Any],
    ) -> None:
        """
        Initialize the machine instance.

        Parameters:
            machineid - The machine's internal ID, from the DB.
            pcbid - The PCBID assigned to the machine.
            name - The name of the machine, as potentially set by the operator.
            arcade - Optionally, the ID of the arcade this machine belongs in.
            port - The port this machine is assigned.
            game - Optionally, the game series that this machine is tied to.
            version - Optionally, the version of the above game required. If it
                      is negative, then any game equal to or lower in version to
                      the abs of this is required.
            data - Extra data that a game backend may want to save with a machine.
        """
        self.id = machineid
        self.pcbid = pcbid
        self.name = name
        self.description = description
        self.arcade = arcade
        self.port = port
        self.game = game
        self.version = version
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Machine(machineid={}, pcbid={}, name={}, description={}, arcade={}, port={}, game={}, version={}, data={})".format(
            self.id,
            self.pcbid,
            self.name,
            self.description,
            self.arcade,
            self.port,
            self.game,
            self.version,
            self.data,
        )


class Arcade:
    """
    An object representing a single arcade found in the DB. Arcades can be given owners
    and should be seen as a zone of machines. Zones can override PASELI settings and set
    up events/globals/other settings. In this way, you can give power to operators of
    arcades on your network, who can then go on to configure events and PASELI including
    crediting accounts. Machines belong to either no arcade or a single arcase.
    """

    def __init__(self, arcadeid: ArcadeID, name: str, description: str, pin: str, data: Dict[str, Any], owners: List[UserID]) -> None:
        """
        Initialize the arcade instance.

        Parameters:
            arcadeid - The arcade's internal ID, from the DB.
            name - The name of the arcade.
            description - The description of the arcade.
            pin - An eight digit string representing the PIN used to pull up PASELI info.
            data - A dictionary of settings for this arcade.
            owners - An list of integers specifying the user IDs of owners for this arcade.
        """
        self.id = arcadeid
        self.name = name
        self.description = description
        self.pin = pin
        self.data = ValidatedDict(data)
        self.owners = owners

    def __repr__(self) -> str:
        return "Arcade(arcadeid={}, name={}, description={}, pin={}, data={}, owners={})".format(
            self.id,
            self.name,
            self.description,
            self.pin,
            self.data,
            self.owners,
        )


class Song:
    """
    An object representing a single song in the DB.
    """

    def __init__(
        self,
        game: str,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> None:
        """
        Initialize the song object.

        Parameters:
            game - The song's game series.
            version - The song's game version.
            songid - The song's ID according to the game.
            songchart - The song's chart number, according to the game.
            name - The name of the song, from the DB.
            artist - The artist of the song, from the DB.
            genre - The genre of the song, from the DB.
            data - Any optional data that a game class uses for a song.
        """
        self.game = game
        self.version = version
        self.id = songid
        self.chart = songchart
        self.name = name
        self.artist = artist
        self.genre = genre
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Song(game={}, version={}, songid={}, songchart={}, name={}, artist={}, genre={}, data={})".format(
            self.game,
            self.version,
            self.id,
            self.chart,
            self.name,
            self.artist,
            self.genre,
            self.data,
        )


class Score:
    """
    An object representing a single score for a user.
    """

    def __init__(
        self,
        key: int,
        songid: int,
        songchart: int,
        points: int,
        timestamp: int,
        update: int,
        location: int,
        plays: int,
        data: Dict[str, Any],
    ) -> None:
        """
        Initialize the score object.

        Parameters:
            key - A unique key identifying this exact score.
            songid - The song's ID according to the game.
            songchart - The song's chart number, according to the game.
            points - The points achieved on this song, from the DB.
            timestamp - The timestamp when the record was earned.
            update - The timestamp when the record was last updated (including play count).
            plays - The number of plays the user has recorded for this song and chart.
            location - The ID of the machine that this score was earned on.
            data - Any optional data that a game class recorded with this score.
        """
        self.key = key
        self.id = songid
        self.chart = songchart
        self.points = points
        self.timestamp = timestamp
        self.update = update
        self.location = location
        self.plays = plays
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Score(key={}, songid={}, songchart={}, points={}, timestamp={}, update={}, location={}, plays={}, data={})".format(
            self.key,
            self.id,
            self.chart,
            self.points,
            self.timestamp,
            self.update,
            self.location,
            self.plays,
            self.data,
        )


class Attempt:
    """
    An object representing a single score attempt for a user.
    """

    def __init__(
        self,
        key: int,
        songid: int,
        songchart: int,
        points: int,
        timestamp: int,
        location: int,
        new_record: bool,
        data: Dict[str, Any],
    ) -> None:
        """
        Initialize the score object.

        Parameters:
            key - A unique key identifying this exact attempt.
            songid - The song's ID according to the game.
            songchart - The song's chart number, according to the game.
            points - The points achieved on this song, from the DB.
            timestamp - The timestamp of the attempt.
            location - The ID of the machine that this score was earned on.
            new_record - Whether this attempt resulted in a new record for this user.
            data - Any optional data that a game class recorded with this score.
        """
        self.key = key
        self.id = songid
        self.chart = songchart
        self.points = points
        self.timestamp = timestamp
        self.location = location
        self.new_record = new_record
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Attempt(key={}, songid={}, songchart={}, points={}, timestamp={}, location={}, new_record={}, data={})".format(
            self.key,
            self.id,
            self.chart,
            self.points,
            self.timestamp,
            self.location,
            self.new_record,
            self.data,
        )


class News:
    """
    An object representing an item of news as displayed on the homepage of
    the frontend.
    """

    def __init__(self, newsid: int, timestamp: int, title: str, body: str) -> None:
        """
        Initialize the news object.

        Parameters:
            newsid - Integer identifier for the news item.
            timestamp - Integer representing unix timestamp of the news item being created.
            title - String representing news title.
            body - String representing news body.
        """
        self.id = newsid
        self.timestamp = timestamp
        self.title = title
        self.body = body

    def __repr__(self) -> str:
        return "News(newsid={}, timestamp={}, title={}, body={})".format(
            self.id,
            self.timestamp,
            self.title,
            self.body,
        )


class Event:
    """
    An object representing an audit event. These are PCB events, errors, exceptions,
    invalid PCBIDs trying to connect, or more mundate events such as daily selection.
    """

    def __init__(self, auditid: int, timestamp: int, userid: Optional[UserID], arcadeid: Optional[ArcadeID], event: str, data: Dict[str, Any]) -> None:
        """
        Initialize the audit event object.

        Parameters:
            auditid - Integer identifier for the audit entry.
            timestamp - Integer representing unix timestamp of the audit entrys creation.
            userid - User ID of the user the event related to, or None if there was no user.
            arcadeid - Arcade ID of the arcade the event related to, or None if there was no arcade.
            event - String event type.
            data - Optional dictionary of values for the event.
        """
        self.id = auditid
        self.timestamp = timestamp
        self.userid = userid
        self.arcadeid = arcadeid
        self.type = event
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Event(auditid={}, timestamp={}, userid={}, arcadeid={}, event={}, data={})".format(
            self.id,
            self.timestamp,
            self.userid,
            self.arcadeid,
            self.type,
            self.data,
        )


class Item:
    """
    An object representing an item from the catalog for a game.
    """

    def __init__(self, cattype: str, catid: int, data: Dict[str, Any]) -> None:
        """
        Initialize the catalog object.

        Parameters:
            cattype - Catalog type.
            catid - Catalog ID.
            data - Optional dictionary of values for the catalog item.
        """
        self.type = cattype
        self.id = catid
        self.data = ValidatedDict(data)

    def __repr__(self) -> str:
        return "Item(cattype={}, catid={}, data={})".format(
            self.type,
            self.id,
            self.data,
        )


class Client:
    """
    An object representing a client that's been authorized to talk to our BEMAPI
    server implementation.
    """

    def __init__(self, clientid: int, timestamp: int, name: str, token: str) -> None:
        """
        Initialize the client object.

        Parameters:
            clientid - Integer identifier for the client.
            timestamp - Add time as an integer unix timestamp.
            name - Name of the client.
            token - Authorization token given to the client.
        """
        self.id = clientid
        self.timestamp = timestamp
        self.name = name
        self.token = token

    def __repr__(self) -> str:
        return "Client(clientid={}, timestamp={}, name={}, token={})".format(
            self.id,
            self.timestamp,
            self.name,
            self.token,
        )


class Server:
    """
    An object representing a BEMAPI server that's we've been authorized to talk
    to for pulling data.
    """

    def __init__(self, serverid: int, timestamp: int, uri: str, token: str, allow_stats: bool, allow_scores: bool) -> None:
        """
        Initialize the server object.

        Parameters:
            serverid - Integer identifier for the server.
            timestamp - Add time as an integer unix timestamp.
            uri - Base URI of the server.
            token - Authorization token given to us.
            allow_stats - True if we should pull statistics from this server.
            allow_scores - True if we should pull scores from this server.
        """
        self.id = serverid
        self.timestamp = timestamp
        self.uri = uri
        self.token = token
        self.allow_stats = allow_stats
        self.allow_scores = allow_scores

    def __repr__(self) -> str:
        return "Server(serverid={}, timestamp={}, uri={}, token={}, allow_stats={}, allow_scores={})".format(
            self.id,
            self.timestamp,
            self.uri,
            self.token,
            self.allow_stats,
            self.allow_scores,
        )
