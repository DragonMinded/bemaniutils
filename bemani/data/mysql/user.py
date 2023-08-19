import random
from sqlalchemy import Table, Column, UniqueConstraint  # type: ignore
from sqlalchemy.types import String, Integer, JSON  # type: ignore
from sqlalchemy.dialects.mysql import BIGINT as BigInteger  # type: ignore
from sqlalchemy.exc import IntegrityError  # type: ignore
from typing import Optional, Dict, List, Tuple, Any
from typing_extensions import Final
from passlib.hash import pbkdf2_sha512  # type: ignore

from bemani.common import ValidatedDict, Profile, GameConstants, Time
from bemani.data.mysql.base import BaseData, metadata
from bemani.data.remoteuser import RemoteUser
from bemani.data.types import User, Achievement, Link, UserID, ArcadeID

"""
Table representing a user. Each user has a unique ID and a pin which
is used with all cards associated with the user's account. Username
and password are optional as a user does not need to create a web login
to use the network. However, an active user account is required
before creating a web login.
"""
user = Table(
    "user",
    metadata,
    Column("id", Integer, nullable=False, primary_key=True),
    Column("pin", String(4), nullable=False),
    Column("username", String(255), unique=True),
    Column("password", String(255)),
    Column("email", String(255)),
    Column("admin", Integer),
    mysql_charset="utf8mb4",
)

"""
Table representing a card associated with a user. Users may have zero
or more cards associated with them. When a new card is used in a game
a new user will be created to associate with a card, but it can later
be unlinked.
"""
card = Table(
    "card",
    metadata,
    Column("id", String(16), nullable=False, unique=True),
    Column("userid", BigInteger(unsigned=True), nullable=False, index=True),
    mysql_charset="utf8mb4",
)

"""
Table representing an extid for a user across a game series. Each game
series on the network gets its own extid (8 digit number) for each user.
"""
extid = Table(
    "extid",
    metadata,
    Column("game", String(32), nullable=False),
    Column("extid", Integer, nullable=False, unique=True),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    UniqueConstraint("game", "userid", name="game_userid"),
    mysql_charset="utf8mb4",
)

"""
Table representing a refid for a user. Each unique game on the network will
need a refid for each user/game/version they have a profile for. If a user
does not have a profile for a particular game, a new and unique refid
will be generated for the user.

Note that a user might have an extid/refid for a game without a profile,
but a user cannot have a profile without an extid/refid.
"""
refid = Table(
    "refid",
    metadata,
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("refid", String(16), nullable=False, unique=True),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    UniqueConstraint("game", "version", "userid", name="game_version_userid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing JSON profile blobs, indexed by refid.
"""
profile = Table(
    "profile",
    metadata,
    Column("refid", String(16), nullable=False, unique=True),
    Column("data", JSON, nullable=False),
    mysql_charset="utf8mb4",
)

"""
Table for storing game achievements. An achievement is just a blob of data
with a unique ID and type. Games are free to store a JSON blob for each
achievement. Examples would be tran medals, event unlocks, items earned,
etc.
"""
achievement = Table(
    "achievement",
    metadata,
    Column("refid", String(16), nullable=False),
    Column("id", Integer, nullable=False),
    Column("type", String(64), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("refid", "id", "type", name="refid_id_type"),
    mysql_charset="utf8mb4",
)

"""
Table for storing time-based achievements. A time-based achievement is
almost identical to a regular achievement, but you can earn multiple of
the same type of achievement at different times, and it matters when
you earn it. Games are free to store a JSON blob for each achievement and
the blob does not need to be equal across different instances of the same
achievement for the same user. Examples would be calorie earnings for DDR.
"""
time_based_achievement = Table(
    "time_based_achievement",
    metadata,
    Column("refid", String(16), nullable=False),
    Column("id", Integer, nullable=False),
    Column("type", String(64), nullable=False),
    Column("timestamp", Integer, nullable=False, index=True),
    Column("data", JSON, nullable=False),
    UniqueConstraint(
        "refid", "id", "type", "timestamp", name="refid_id_type_timestamp"
    ),
    mysql_charset="utf8mb4",
)

"""
Table for storing a user's PASELI balance, given an arcade. There is no global
balance on this network.
"""
balance = Table(
    "balance",
    metadata,
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("arcadeid", Integer, nullable=False),
    Column("balance", Integer, nullable=False),
    UniqueConstraint("userid", "arcadeid", name="userid_arcadeid"),
    mysql_charset="utf8mb4",
)

"""
Table for storing links between two users in a game/version, whatever that
may be. Typically used for rivals.
etc.
"""
link = Table(
    "link",
    metadata,
    Column("game", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("userid", BigInteger(unsigned=True), nullable=False),
    Column("type", String(64), nullable=False),
    Column("other_userid", BigInteger(unsigned=True), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint(
        "game",
        "version",
        "userid",
        "type",
        "other_userid",
        name="game_version_userid_type_other_uuserid",
    ),
    mysql_charset="utf8mb4",
)


class AccountCreationException(Exception):
    pass


class UserData(BaseData):
    REF_ID_LENGTH: Final[int] = 16

    def from_cardid(self, cardid: str) -> Optional[UserID]:
        """
        Given a 16 digit card ID, look up a user ID.

        Note that this is the E004 number as stored on the card. Not the 16 digit
        ASCII value on the back. Use CardCipher to convert.

        Parameters:
            cardid - 16-digit card ID to look for.

        Returns:
            User ID as an integer if found, or None if not.
        """
        # First, look up the user account
        sql = "SELECT userid FROM card WHERE id = :id"
        cursor = self.execute(sql, {"id": cardid})
        if cursor.rowcount != 1:
            # Couldn't find a user with this card
            return None

        result = cursor.fetchone()
        return UserID(result["userid"])

    def from_username(self, username: str) -> Optional[UserID]:
        """
        Given a username, look up a user ID.

        Parameters:
            username - A string representing the user's username.

        Returns:
            User ID as an integer if found, or None if not.
        """
        sql = "SELECT id FROM user WHERE username = :username"
        cursor = self.execute(sql, {"username": username})
        if cursor.rowcount != 1:
            # Couldn't find this username
            return None

        result = cursor.fetchone()
        return UserID(result["id"])

    def from_refid(
        self, game: GameConstants, version: int, refid: str
    ) -> Optional[UserID]:
        """
        Given a generated RefID, look up a user ID.

        Note that there is a unique RefID and ExtID for each profile, and both can be used
        to look up a user. When creating a new profile, we generate a unique RefID and ExtID.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            refid - RefID in question, most likely previously generated by this class.

        Returns:
            User ID as an integer if found, or None if not.
        """
        # First, look up the user account
        sql = "SELECT userid FROM refid WHERE game = :game AND version = :version AND refid = :refid"
        cursor = self.execute(
            sql, {"game": game.value, "version": version, "refid": refid}
        )
        if cursor.rowcount != 1:
            # Couldn't find a user with this refid
            return None

        result = cursor.fetchone()
        return UserID(result["userid"])

    def from_extid(
        self, game: GameConstants, version: int, extid: int
    ) -> Optional[UserID]:
        """
        Given a generated ExtID, look up a user ID.

        Note that there is a unique RefID and ExtID for each profile, and both can be used
        to look up a user. When creating a new profile, we generate a unique RefID and ExtID.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            extid - ExtID in question, most likely previously generated by this class.

        Returns:
            User ID as an integer if found, or None if not.
        """
        # First, look up the user account
        sql = "SELECT userid FROM extid WHERE game = :game AND extid = :extid"
        cursor = self.execute(sql, {"game": game.value, "extid": extid})
        if cursor.rowcount != 1:
            # Couldn't find a user with this refid
            return None

        result = cursor.fetchone()
        return UserID(result["userid"])

    def from_session(self, session: str) -> Optional[UserID]:
        """
        Given a previously-opened session, look up a user ID.

        Parameters:
            session - String identifying a session that was opened by create_session.

        Returns:
            User ID as an integer if found, or None if the session is expired or doesn't exist.
        """
        userid = self._from_session(session, "userid")
        if userid is None:
            return None
        return UserID(userid)

    def get_user(self, userid: UserID) -> Optional[User]:
        """
        Given a userid, look up details about the account.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A User object if found, or None otherwise.
        """
        sql = "SELECT username, email, admin FROM user WHERE id = :userid"
        cursor = self.execute(sql, {"userid": userid})
        if cursor.rowcount != 1:
            # User doesn't exist, but we have a reference?
            return None

        result = cursor.fetchone()
        return User(userid, result["username"], result["email"], result["admin"] == 1)

    def get_all_users(self) -> List[User]:
        """
        Look up all users in the system.

        Returns:
            A list of User objects representing all users.
        """
        sql = "SELECT id, username, email, admin FROM user"
        cursor = self.execute(sql)
        return [
            User(
                UserID(result["id"]),
                result["username"],
                result["email"],
                result["admin"] == 1,
            )
            for result in cursor
        ]

    def get_all_usernames(self) -> List[str]:
        """
        Look up all valid usernames in the system.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A list of strings representing usernames.
        """
        sql = "SELECT username FROM user WHERE username is not null"
        cursor = self.execute(sql)
        return [res["username"] for res in cursor]

    def get_all_cards(self) -> List[Tuple[str, UserID]]:
        """
        Look up all cards associated with any account.

        Returns:
            A list of Tuples representing representing card ID, user ID pairs.
        """
        sql = "SELECT id, userid FROM card"
        cursor = self.execute(sql)
        return [(str(res["id"]).upper(), UserID(res["userid"])) for res in cursor]

    def get_cards(self, userid: UserID) -> List[str]:
        """
        Given a userid, look up all cards associated with the account.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A list of strings representing card IDs.
        """
        sql = "SELECT id FROM card WHERE userid = :userid"
        cursor = self.execute(sql, {"userid": userid})
        return [str(res["id"]).upper() for res in cursor]

    def add_card(self, userid: UserID, cardid: str) -> None:
        """
        Given a user ID and a card ID, link that card with that user.

        Note that this is the E004 number as stored on the card. Not the 16 digit
        ASCII value on the back. Use CardCipher to convert.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            cardid - 16-digit card ID to add.
        """
        if RemoteUser.is_remote(userid):
            raise AccountCreationException(
                "Should not add local cards to remote users!"
            )
        sql = "INSERT INTO card (userid, id) VALUES (:userid, :cardid)"
        self.execute(sql, {"userid": userid, "cardid": cardid})

        oldid = RemoteUser.card_to_userid(cardid)
        if RemoteUser.is_remote(oldid):
            # Kill any refid/extid that related to this card, since its now associated
            # with another existing account.
            sql = "DELETE FROM extid WHERE userid = :oldid"
            self.execute(sql, {"oldid": oldid})
            sql = "DELETE FROM refid WHERE userid = :oldid"
            self.execute(sql, {"oldid": oldid})

            # Point at the new account for any rivals against this card. Note that this
            # might result in a duplicate rival, but its a very small edge case.
            sql = "UPDATE link SET other_userid = :newid WHERE other_userid = :oldid"
            self.execute(sql, {"newid": userid, "oldid": oldid})

    def destroy_card(self, userid: UserID, cardid: str) -> None:
        """
        Given a user ID and a card ID, remove the card ID link from that user.

        Note that this is the E004 number as stored on the card. Not the 16 digit
        ASCII value on the back. Use CardCipher to convert.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            cardid - 16-digit card ID to remove.
        """
        sql = "DELETE FROM card WHERE id = :cardid AND userid = :userid LIMIT 1"
        self.execute(sql, {"cardid": cardid, "userid": userid})

    def put_user(self, user: User) -> None:
        """
        Given a user object, update the DB to save new user info.

        Parameters:
            user - A user, which has optional values set.
        """
        sql = "UPDATE user SET username = :username, email = :email, admin = :admin WHERE id = :userid"
        self.execute(
            sql,
            {
                "username": user.username,
                "email": user.email,
                "admin": 1 if user.admin else 0,
                "userid": user.id,
            },
        )

    def validate_pin(self, userid: UserID, pin: str) -> bool:
        """
        Given a userid and PIN, validate the PIN.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            pin - 4 digit string returned by the game for PIN entry.

        Returns:
            True if PIN is valid, False otherwise.
        """
        sql = "SELECT pin FROM user WHERE id = :userid"
        cursor = self.execute(sql, {"userid": userid})
        if cursor.rowcount != 1:
            # User doesn't exist, but we have a reference?
            return False

        result = cursor.fetchone()
        return pin == result["pin"]

    def update_pin(self, userid: UserID, pin: str) -> None:
        """
        Given a userid and a new PIN, update the PIN for that user.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            pin - 4 digit string returned by the game for PIN entry.
        """
        sql = "UPDATE user SET pin = :pin WHERE id = :userid"
        self.execute(sql, {"pin": pin, "userid": userid})

    def validate_password(self, userid: UserID, password: str) -> bool:
        """
        Given a password, validate that the password matches the stored hash

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            password - String, plaintext password that will be hashed

        Returns:
            True if password is valid, False otherwise.
        """
        sql = "SELECT password FROM user WHERE id = :userid"
        cursor = self.execute(sql, {"userid": userid})
        if cursor.rowcount != 1:
            # User doesn't exist, but we have a reference?
            return False

        result = cursor.fetchone()
        passhash = result["password"]

        try:
            # Verifying the password
            return pbkdf2_sha512.verify(password, passhash)
        except (ValueError, TypeError):
            return False

    def update_password(self, userid: UserID, password: str) -> None:
        """
        Given a userid and a new password, update the password for that user.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            password - String, plaintext password that will be hashed
        """
        passhash = pbkdf2_sha512.hash(password)
        sql = "UPDATE user SET password = :hash WHERE id = :userid"
        self.execute(sql, {"hash": passhash, "userid": userid})

    def get_profile(
        self, game: GameConstants, version: int, userid: UserID
    ) -> Optional[Profile]:
        """
        Given a game/version/userid, look up the associated profile.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A dictionary previously stored by a game class if found, or None otherwise.
        """
        sql = """
            SELECT refid.refid AS refid, extid.extid AS extid, profile.data AS data
            FROM refid, extid, profile
            WHERE
                refid.userid = :userid AND
                refid.game = :game AND
                refid.version = :version AND
                extid.userid = refid.userid AND
                extid.game = refid.game AND
                profile.refid = refid.refid
        """
        cursor = self.execute(
            sql, {"userid": userid, "game": game.value, "version": version}
        )
        if cursor.rowcount != 1:
            # Profile doesn't exist
            return None

        result = cursor.fetchone()
        return Profile(
            game,
            version,
            result["refid"],
            result["extid"],
            self.deserialize(result["data"]),
        )

    def get_any_profile(
        self, game: GameConstants, version: int, userid: UserID
    ) -> Optional[Profile]:
        """
        Given a game/version/userid, look up the associated profile. If the profile for that version
        doesn't exist, try another profile, failing only if there is no profile for any version of
        this game.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A dictionary previously stored by a game class if found, or None otherwise.
        """
        played = self.get_games_played(userid, game=game)
        versions = {p[1] for p in played}

        if version in versions:
            return self.get_profile(game, version, userid)
        elif len(versions) > 0:
            return self.get_profile(game, max(versions), userid)
        else:
            return None

    def get_any_profiles(
        self, game: GameConstants, version: int, userids: List[UserID]
    ) -> List[Tuple[UserID, Optional[Profile]]]:
        """
        Does the exact same thing as get_any_profile but across a list of users instead of one.
        Provided purely as a convenience function.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userids - List of Integer user IDs, as looked up by one of the above functions.

        Returns:
            A List of tuples containing a userid and a dictionary previously stored by a game class if found,
            or None otherwise.
        """
        if not userids:
            return []
        sql = """
            SELECT refid.version AS version, refid.userid AS userid
            FROM refid
            INNER JOIN profile ON refid.refid = profile.refid
            WHERE refid.game = :game AND refid.userid IN :userids
        """
        cursor = self.execute(sql, {"game": game.value, "userids": userids})
        profilever: Dict[UserID, int] = {}

        for result in cursor:
            tuid = UserID(result["userid"])
            tver = result["version"]

            if tuid not in profilever:
                # Just assign it the first profile we find
                profilever[tuid] = tver
            else:
                # If the profile for this version exists, prioritize it
                if tver == version:
                    profilever[tuid] = tver

                # Only update the profile version with the newest game profile if the game
                # profile for this version doesn't exist.
                elif profilever[tuid] != version:
                    profilever[tuid] = max(profilever[tuid], tver)

        return [
            (
                uid,
                self.get_profile(game, profilever[uid], uid)
                if uid in profilever
                else None,
            )
            for uid in userids
        ]

    def get_games_played(
        self, userid: UserID, game: Optional[GameConstants] = None
    ) -> List[Tuple[GameConstants, int]]:
        """
        Given a user ID, look up all game/version combos this user has played.

        Parameters:
            userid - Integer user ID, as looked up by one of the above functions.
            game - An optional game series to constrain search to.

        Returns:
            A List of Tuples of game, version for each game/version the user has played.
        """
        sql = """
            SELECT refid.game AS game, refid.version AS version
            FROM refid
            INNER JOIN profile ON refid.refid = profile.refid
            WHERE refid.userid = :userid
        """
        vals: Dict[str, Any] = {"userid": userid}

        if game is not None:
            sql += " AND game = :game"
            vals["game"] = game.value

        cursor = self.execute(sql, vals)
        return [(GameConstants(result["game"]), result["version"]) for result in cursor]

    def get_all_profiles(
        self, game: GameConstants, version: int
    ) -> List[Tuple[UserID, Profile]]:
        """
        Given a game/version, look up all user profiles for that game.

        Parameters:
            game - Enum value identifier of the game we want all user profiles for.
            version - Integer version of the game we want all user profiles for.

        Returns:
            A list of (UserID, dictionaries) previously stored by a game class for each profile.
        """
        sql = """
            SELECT refid.userid AS userid, refid.refid AS refid, extid.extid AS extid, profile.data AS data
            FROM refid, profile, extid
            WHERE
                refid.game = :game AND
                refid.version = :version AND
                refid.refid = profile.refid AND
                extid.game = refid.game AND
                extid.userid = refid.userid
        """
        cursor = self.execute(sql, {"game": game.value, "version": version})

        return [
            (
                UserID(result["userid"]),
                Profile(
                    game,
                    version,
                    result["refid"],
                    result["extid"],
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]

    def get_all_players(self, game: GameConstants, version: int) -> List[UserID]:
        """
        Given a game/version, look up all user IDs that played this game/version.

        Parameters:
            game - Enum value identifier of the game we want all user profiles for.
            version - Integer version of the game we want all user profiles for.

        Returns:
            A list of UserIDs for users that played this version of this game.
        """
        sql = """
            SELECT refid.userid AS userid FROM refid
            WHERE refid.game = :game AND refid.version = :version
        """
        cursor = self.execute(sql, {"game": game.value, "version": version})

        return [UserID(result["userid"]) for result in cursor]

    def get_all_achievements(
        self,
        game: GameConstants,
        version: int,
        achievementid: Optional[int] = None,
        achievementtype: Optional[str] = None,
    ) -> List[Tuple[UserID, Achievement]]:
        """
        Given a game/version, find all achievements for all players.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.

        Returns:
            A list of (UserID, Achievement) objects.
        """
        sql = """
            SELECT
                achievement.id AS id,
                achievement.type AS type,
                achievement.data AS data,
                refid.userid AS userid
            FROM achievement, refid
            WHERE
                refid.game = :game AND
                refid.version = :version AND
                refid.refid = achievement.refid
        """
        params: Dict[str, Any] = {"game": game.value, "version": version}
        if achievementtype is not None:
            sql += " AND achievement.type = :type"
            params["type"] = achievementtype
        if achievementid is not None:
            sql += " AND achievement.id = :id"
            params["id"] = achievementid
        cursor = self.execute(sql, params)

        return [
            (
                UserID(result["userid"]),
                Achievement(
                    result["id"],
                    result["type"],
                    None,
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]

    def put_profile(
        self, game: GameConstants, version: int, userid: UserID, profile: Profile
    ) -> None:
        """
        Given a game/version/userid, save an associated profile.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            profile - A dictionary that a game class will want to retrieve later.
        """
        refid = self.get_refid(game, version, userid)

        # Add profile json to game profile
        sql = """
            INSERT INTO profile (refid, data)
            VALUES (:refid, :json)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(sql, {"refid": refid, "json": self.serialize(profile)})

        # Update profile details just in case this was a new profile that was just saved.
        profile.game = game
        profile.version = version
        profile.refid = refid
        if profile.extid == 0:
            profile.extid = self.get_extid(game, version, userid)

    def delete_profile(self, game: GameConstants, version: int, userid: UserID) -> None:
        """
        Given a game/version/userid, delete any associated profile.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
        """
        refid = self.get_refid(game, version, userid)

        # Delete profile JSON to unlink the profile for this game/version.
        sql = "DELETE FROM profile WHERE refid = :refid LIMIT 1"
        self.execute(sql, {"refid": refid})

    def get_achievement(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
    ) -> Optional[ValidatedDict]:
        """
        Given a game/version/userid and achievement id/type, find that achievement.

        Note that there can be more than one achievement with the same ID and game/version/userid
        as long as each one is a different type. Essentially, achievementtype namespaces achievements.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.

        Returns:
            A dictionary as stored by a game class previously, or None if not found.
        """
        refid = self.get_refid(game, version, userid)
        sql = "SELECT data FROM achievement WHERE refid = :refid AND id = :id AND type = :type"
        cursor = self.execute(
            sql, {"refid": refid, "id": achievementid, "type": achievementtype}
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return ValidatedDict(self.deserialize(result["data"]))

    def get_achievements(
        self, game: GameConstants, version: int, userid: UserID
    ) -> List[Achievement]:
        """
        Given a game/version/userid, find all achievements

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A list of Achievement objects.
        """
        refid = self.get_refid(game, version, userid)
        sql = "SELECT id, type, data FROM achievement WHERE refid = :refid"
        cursor = self.execute(sql, {"refid": refid})

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
        version: int,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Given a game/version/userid and achievement id/type, save an achievement.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.
            data - A dictionary of data that the game wishes to retrieve later.
        """
        refid = self.get_refid(game, version, userid)

        # Add achievement JSON to achievements
        sql = """
            INSERT INTO achievement (refid, id, type, data)
            VALUES (:refid, :id, :type, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "refid": refid,
                "id": achievementid,
                "type": achievementtype,
                "data": self.serialize(data),
            },
        )

    def destroy_achievement(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
    ) -> None:
        """
        Given a game/version/userid and achievement id/type, delete an achievement.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.
        """
        refid = self.get_refid(game, version, userid)

        # Nuke the achievement from the user
        sql = """
            DELETE FROM achievement
            WHERE refid = :refid AND id = :id AND type = :type
        """
        self.execute(
            sql, {"refid": refid, "id": achievementid, "type": achievementtype}
        )

    def get_time_based_achievements(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        achievementtype: Optional[str] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Achievement]:
        """
        Given a game/version/userid, find all time-based achievements

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementtype - Optional string specifying to constrain to a type of achievement.
            since - Return achievements since this time (inclusive).
            until - Return achievements until this time (exclusive).

        Returns:
            A list of Achievement objects.
        """
        refid = self.get_refid(game, version, userid)
        sql = "SELECT id, type, timestamp, data FROM time_based_achievement WHERE refid = :refid"
        if achievementtype is not None:
            sql += " AND type = :type"
        if since is not None:
            sql += " AND timestamp >= :since"
        if until is not None:
            sql += " AND timestamp < :until"
        cursor = self.execute(
            sql,
            {"refid": refid, "type": achievementtype, "since": since, "until": until},
        )

        return [
            Achievement(
                result["id"],
                result["type"],
                result["timestamp"],
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]

    def put_time_based_achievement(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        achievementid: int,
        achievementtype: str,
        data: Dict[str, Any],
    ) -> None:
        """
        Given a game/version/userid and achievement id/type, save a time-based achievement. Assumes that
        time-based achievements are immutable once saved.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            achievementid - Integer ID, as provided by a game.
            achievementtype - The type of achievement.
            data - A dictionary of data that the game wishes to retrieve later.
        """
        refid = self.get_refid(game, version, userid)

        # Add achievement JSON to achievements
        sql = """
            INSERT INTO time_based_achievement (refid, id, type, timestamp, data)
            VALUES (:refid, :id, :type, :ts, :data)
        """
        self.execute(
            sql,
            {
                "refid": refid,
                "id": achievementid,
                "type": achievementtype,
                "ts": Time.now(),
                "data": self.serialize(data),
            },
        )

    def get_all_time_based_achievements(
        self, game: GameConstants, version: int
    ) -> List[Tuple[UserID, Achievement]]:
        """
        Given a game/version, find all time-based achievements for all players.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.

        Returns:
            A list of (UserID, Achievement) objects.
        """
        sql = """
            SELECT
                time_based_achievement.id AS id,
                time_based_achievement.type AS type,
                time_based_achievement.data AS data,
                time_based_achievement.timestamp AS timestamp,
                refid.userid AS userid
            FROM time_based_achievement, refid
            WHERE
                refid.game = :game AND
                refid.version = :version AND
                refid.refid = time_based_achievement.refid
        """
        cursor = self.execute(sql, {"game": game.value, "version": version})

        return [
            (
                UserID(result["userid"]),
                Achievement(
                    result["id"],
                    result["type"],
                    result["timestamp"],
                    self.deserialize(result["data"]),
                ),
            )
            for result in cursor
        ]

    def get_link(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        linktype: str,
        other_userid: UserID,
    ) -> Optional[ValidatedDict]:
        """
        Given a game/version/userid and link type + other userid, find that link.

        Note that there can be more than one link with the same user IDs and game/version
        as long as each one is a different type.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            linktype - The type of link.
            other_userid - Integer user ID of the account we're linked to.

        Returns:
            A dictionary as stored by a game class previously, or None if not found.
        """
        sql = """
            SELECT data
            FROM link
            WHERE
                game = :game AND
                version = :version AND
                userid = :userid AND
                type = :type AND
                other_userid = :other_userid
        """
        cursor = self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "type": linktype,
                "other_userid": other_userid,
            },
        )
        if cursor.rowcount != 1:
            # score doesn't exist
            return None

        result = cursor.fetchone()
        return ValidatedDict(self.deserialize(result["data"]))

    def get_links(
        self, game: GameConstants, version: int, userid: UserID
    ) -> List[Link]:
        """
        Given a game/version/userid, find all links between this user and other users

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A list of Link objects.
        """
        sql = """
            SELECT type, other_userid, data
            FROM link
            WHERE game = :game AND version = :version AND userid = :userid
        """
        cursor = self.execute(
            sql, {"game": game.value, "version": version, "userid": userid}
        )

        return [
            Link(
                userid,
                result["type"],
                UserID(result["other_userid"]),
                self.deserialize(result["data"]),
            )
            for result in cursor
        ]

    def put_link(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        linktype: str,
        other_userid: UserID,
        data: Dict[str, Any],
    ) -> None:
        """
        Given a game/version/userid and link id + other_userid, save an link.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            linktype - The type of link.
            other_userid - Integer user ID of the account we're linked to.
            data - A dictionary of data that the game wishes to retrieve later.
        """
        # Add link JSON to link
        sql = """
            INSERT INTO link (game, version, userid, type, other_userid, data)
            VALUES (:game, :version, :userid, :type, :other_userid, :data)
            ON DUPLICATE KEY UPDATE data=VALUES(data)
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "type": linktype,
                "other_userid": other_userid,
                "data": self.serialize(data),
            },
        )

    def destroy_link(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        linktype: str,
        other_userid: UserID,
    ) -> None:
        """
        Given a game/version/userid and link id + other_userid, destroy the link.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.
            linktype - The type of link.
            other_userid - Integer user ID of the account we're linked to.
        """
        sql = """
            DELETE FROM link
            WHERE
                game = :game AND
                version = :version AND
                userid = :userid AND
                type = :type AND
                other_userid = :other_userid
        """
        self.execute(
            sql,
            {
                "game": game.value,
                "version": version,
                "userid": userid,
                "type": linktype,
                "other_userid": other_userid,
            },
        )

    def get_balance(self, userid: UserID, arcadeid: ArcadeID) -> int:
        """
        Given a user and an arcade ID, look up the user's PASELI balance for that arcade.

        Parameters:
            userid - The user ID in question, as looked up by this class.
            arcadeid - The arcade in question.

        Returns:
            The PASELI balance for this user at this arcade.
        """
        sql = "SELECT balance FROM balance WHERE userid = :userid AND arcadeid = :arcadeid"
        cursor = self.execute(sql, {"userid": userid, "arcadeid": arcadeid})
        if cursor.rowcount == 1:
            result = cursor.fetchone()
            return result["balance"]
        else:
            return 0

    def update_balance(
        self, userid: UserID, arcadeid: ArcadeID, delta: int
    ) -> Optional[int]:
        """
        Given a user and an arcade ID, update the PASELI balance for that arcade.

        Parameters:
            userid - The user ID in question, as looked up by this class.
            arcadeid - The arcade in question.
            delta - The value to add (or subtract, if delta is negative).

        Returns:
            The new PASELI balance if successful, or None if there wasn't enough to apply the delta.
        """
        sql = """
            INSERT INTO balance (userid, arcadeid, balance) VALUES (:userid, :arcadeid, :delta)
            ON DUPLICATE KEY UPDATE balance = balance + :delta
        """
        self.execute(sql, {"delta": delta, "userid": userid, "arcadeid": arcadeid})
        newbalance = self.get_balance(userid, arcadeid)
        if newbalance < 0:
            # Went under while grabbing, put the balance back and return nothing
            sql = "UPDATE balance SET balance = balance - :delta WHERE userid = :userid AND arcadeid = :arcadeid"
            self.execute(sql, {"delta": delta, "userid": userid, "arcadeid": arcadeid})
            return None
        return newbalance

    def get_refid(self, game: GameConstants, version: int, userid: UserID) -> str:
        """
        Given a game/version and user ID, look up the RefID for the profile.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            The RefID associated with the profile for this user. If there isn't one, creates one
            and returns it, which can be used for creating/looking up a profile in the future.
        """
        sql = "SELECT refid FROM refid WHERE userid = :userid AND game = :game AND version = :version"
        cursor = self.execute(
            sql, {"userid": userid, "game": game.value, "version": version}
        )
        if cursor.rowcount == 1:
            result = cursor.fetchone()
            return result["refid"]
        else:
            return self.create_refid(game, version, userid)

    def get_extid(self, game: GameConstants, version: int, userid: UserID) -> int:
        """
        Given a game/version and a user ID, look up the ExtID for the profile.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            The ExtID associated with the profile for this user. If there isn't one, creates
            one in the same manner as get_refid() above.
        """

        def fetch_extid() -> Optional[int]:
            sql = "SELECT extid FROM extid WHERE userid = :userid AND game = :game"
            cursor = self.execute(sql, {"userid": userid, "game": game.value})
            if cursor.rowcount == 1:
                result = cursor.fetchone()
                return result["extid"]
            else:
                return None

        extid = fetch_extid()
        if extid is not None:
            return extid
        else:
            self.create_refid(game, version, userid)
            extid = fetch_extid()
            if extid is not None:
                return extid
            else:
                raise AccountCreationException(
                    "Failed to cteate a new refid/extid pair!"
                )

    def create_session(self, userid: UserID, expiration: int = (30 * 86400)) -> str:
        """
        Given a user ID, create a session string.

        Parameters:
            userid - User ID we wish to start a session for.
            expiration - Number of seconds before this session is invalid.

        Returns:
            A string that can be used as a session ID.
        """
        return self._create_session(userid, "userid", expiration)

    def destroy_session(self, session: str) -> None:
        """
        Destroy a previously-created session.

        Parameters:
            session - A session string as returned from create_session.
        """
        self._destroy_session(session, "userid")

    def create_refid(self, game: GameConstants, version: int, userid: UserID) -> str:
        """
        Given a game/version/userid, create a RefID and an ExtID if necessary.

        Note that while this function returns the created RefID, an ExtID is also
        created and stored in the DB. Both RefID and ExtID are guaranteed to be
        unique, but the RefID is guaranteed unique for each profile while ExtID
        is guaranteed unique for each game series/user.

        Parameters:
            game - Enum value identifier of the game looking up the user.
            version - Integer version of the game looking up the user.
            userid - Integer user ID, as looked up by one of the above functions.

        Returns:
            A string RefID value.
        """
        # Create a new extid that is unique
        while True:
            extid = random.randint(0, 89999999) + 10000000
            sql = "SELECT extid FROM extid WHERE extid = :extid"
            cursor = self.execute(sql, {"extid": extid})
            if cursor.rowcount == 0:
                break

        # Use that extid
        sql = """
            INSERT INTO extid (game, extid, userid)
            VALUES (:game, :extid, :userid)
        """
        try:
            cursor = self.execute(
                sql, {"game": game.value, "extid": extid, "userid": userid}
            )
        except IntegrityError:
            # User already has an ExtID for this game series
            pass

        # Create a new refid that is unique
        while True:
            refid = "".join(
                random.choice("0123456789ABCDEF") for _ in range(UserData.REF_ID_LENGTH)
            )
            sql = "SELECT refid FROM refid WHERE refid = :refid"
            cursor = self.execute(sql, {"refid": refid})
            if cursor.rowcount == 0:
                break

        # Use that refid
        sql = """
            INSERT INTO refid (game, version, refid, userid)
            VALUES (:game, :version, :refid, :userid)
        """
        try:
            cursor = self.execute(
                sql,
                {
                    "game": game.value,
                    "version": version,
                    "refid": refid,
                    "userid": userid,
                },
            )
            if cursor.rowcount != 1:
                raise AccountCreationException(
                    "Failed to create and fetch a new refid!"
                )
            return refid
        except IntegrityError:
            # We maybe lost the race? Look up the ID from another creation. Don't call get_refid
            # because it calls us, so we don't want an infinite loop.
            sql = "SELECT refid FROM refid WHERE userid = :userid AND game = :game AND version = :version"
            cursor = self.execute(
                sql, {"userid": userid, "game": game.value, "version": version}
            )
            if cursor.rowcount == 1:
                result = cursor.fetchone()
                return result["refid"]
            # Shouldn't be possible, but here we are
            raise AccountCreationException("Failed to recover lost race refid!")

    def create_account(self, cardid: str, pin: str) -> Optional[UserID]:
        """
        Given a Card ID and a PIN, create a new account.

        Parameters:
            cardid - 16-digit card ID of the card we are creating an account for.
            pin - Four digit PIN as entered by the user on a cabinet.

        Returns:
            A User ID if creation was successful, or None otherwise.
        """
        # First, create a user account
        sql = "INSERT INTO user (pin, admin) VALUES (:pin, 0)"
        cursor = self.execute(sql, {"pin": pin})
        if cursor.rowcount != 1:
            return None
        userid = cursor.lastrowid

        # Now, insert the card, tying it to the account
        sql = "INSERT INTO card (id, userid) VALUES (:cardid, :userid)"
        cursor = self.execute(sql, {"cardid": cardid, "userid": userid})
        if cursor.rowcount != 1:
            return None

        # Now, if this user played on a remote network and their profile
        # was ever fetched locally or they were ever rivaled against,
        # convert those locally too so that players don't lose rivals
        # on new account creation.
        oldid = RemoteUser.card_to_userid(cardid)
        if RemoteUser.is_remote(oldid):
            sql = "UPDATE extid SET userid = :newid WHERE userid = :oldid"
            self.execute(sql, {"newid": userid, "oldid": oldid})
            sql = "UPDATE refid SET userid = :newid WHERE userid = :oldid"
            self.execute(sql, {"newid": userid, "oldid": oldid})
            sql = "UPDATE link SET other_userid = :newid WHERE other_userid = :oldid"
            self.execute(sql, {"newid": userid, "oldid": oldid})

        # Finally, return the user ID
        return userid
