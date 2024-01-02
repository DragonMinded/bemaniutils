from typing import Optional, List, Dict, Any, NewType

from bemani.common import ValidatedDict, GameConstants

UserID = NewType("UserID", int)
ArcadeID = NewType("ArcadeID", int)


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
        return f"User(userid={self.id}, username={self.username}, email={self.email}, admin={self.admin})"


class Achievement:
    """
    An object representing a single achievement for a user.

    Achievements are referred to loosely here. An achievement is really any type/id pair
    that can have some attached data, such as item unlocks, tran medals, course progress, etc.
    """

    def __init__(
        self,
        achievementid: int,
        achievementtype: str,
        timestamp: Optional[int],
        data: Dict[str, Any],
    ) -> None:
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
        return f"Achievement(achievementid={self.id}, achievementtype={self.type}, timestamp={self.timestamp}, data={self.data})"


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
        return f"Link(userid={self.userid}, linktype={self.type}, other_userid={self.other_userid}, data={self.data})"


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
        game: Optional[GameConstants],
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
        return f"Machine(machineid={self.id}, pcbid={self.pcbid}, name={self.name}, description={self.description}, arcade={self.arcade}, port={self.port}, game={self.game}, version={self.version}, data={self.data})"


class Arcade:
    """
    An object representing a single arcade found in the DB. Arcades can be given owners
    and should be seen as a zone of machines. Zones can override PASELI settings and set
    up events/globals/other settings. In this way, you can give power to operators of
    arcades on your network, who can then go on to configure events and PASELI including
    crediting accounts. Machines belong to either no arcade or a single arcase.
    """

    def __init__(
        self,
        arcadeid: ArcadeID,
        name: str,
        description: str,
        pin: str,
        region: int,
        area: Optional[str],
        data: Dict[str, Any],
        owners: List[UserID],
    ) -> None:
        """
        Initialize the arcade instance.

        Parameters:
            arcadeid - The arcade's internal ID, from the DB.
            name - The name of the arcade.
            description - The description of the arcade.
            pin - An eight digit string representing the PIN used to pull up PASELI info.
            region - An integer representing the region this arcade is in.
            area - A string representing the custom area this arcade is in, or None if default.
            data - A dictionary of settings for this arcade.
            owners - An list of integers specifying the user IDs of owners for this arcade.
        """
        self.id = arcadeid
        self.name = name
        self.description = description
        self.pin = pin
        self.region = region
        self.area = area
        self.data = ValidatedDict(data)
        self.owners = owners

    def __repr__(self) -> str:
        return f"Arcade(arcadeid={self.id}, name={self.name}, description={self.description}, pin={self.pin}, region={self.region}, area={self.area}, data={self.data}, owners={self.owners})"


class Song:
    """
    An object representing a single song in the DB.
    """

    def __init__(
        self,
        game: GameConstants,
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
        return f"Song(game={self.game}, version={self.version}, songid={self.id}, songchart={self.chart}, name={self.name}, artist={self.artist}, genre={self.genre}, data={self.data})"


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
        return f"Score(key={self.key}, songid={self.id}, songchart={self.chart}, points={self.points}, timestamp={self.timestamp}, update={self.update}, location={self.location}, plays={self.plays}, data={self.data})"


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
        return f"Attempt(key={self.key}, songid={self.id}, songchart={self.chart}, points={self.points}, timestamp={self.timestamp}, location={self.location}, new_record={self.new_record}, data={self.data})"


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
        return f"News(newsid={self.id}, timestamp={self.timestamp}, title={self.title}, body={self.body})"


class Event:
    """
    An object representing an audit event. These are PCB events, errors, exceptions,
    invalid PCBIDs trying to connect, or more mundate events such as daily selection.
    """

    def __init__(
        self,
        auditid: int,
        timestamp: int,
        userid: Optional[UserID],
        arcadeid: Optional[ArcadeID],
        event: str,
        data: Dict[str, Any],
    ) -> None:
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
        return f"Event(auditid={self.id}, timestamp={self.timestamp}, userid={self.userid}, arcadeid={self.arcadeid}, event={self.type}, data={self.data})"


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
        return f"Item(cattype={self.type}, catid={self.id}, data={self.data})"


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
        return f"Client(clientid={self.id}, timestamp={self.timestamp}, name={self.name}, token={self.token})"


class Server:
    """
    An object representing a BEMAPI server that's we've been authorized to talk
    to for pulling data.
    """

    def __init__(
        self,
        serverid: int,
        timestamp: int,
        uri: str,
        token: str,
        allow_stats: bool,
        allow_scores: bool,
    ) -> None:
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
        return f"Server(serverid={self.id}, timestamp={self.timestamp}, uri={self.uri}, token={self.token}, allow_stats={self.allow_stats}, allow_scores={self.allow_scores})"
