from abc import ABC, abstractmethod
import traceback
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Type
from typing_extensions import Final

from bemani.common import (
    Model,
    ValidatedDict,
    Profile,
    PlayStatistics,
    GameConstants,
    RegionConstants,
    Time,
    cache,
)
from bemani.data import Config, Data, Arcade, Machine, UserID, RemoteUser


class ProfileCreationException(Exception):
    pass


class Status:
    """
    List of statuses we return to the game for various reasons.
    """

    SUCCESS: Final[int] = 0
    NO_PROFILE: Final[int] = 109
    NOT_ALLOWED: Final[int] = 110
    NOT_REGISTERED: Final[int] = 112
    INVALID_PIN: Final[int] = 116


class Factory(ABC):
    """
    The base class every game factory inherits from. Defines a create method
    which should return some game class which can handle packets. Game classes
    inherit from Base, and have handle_<call>_requests service methods or
    handle_<call>_<method>_request methods on them that Dispatch will look up
    in order to handle calls.
    """

    MANAGED_CLASSES: List[Type["Base"]]

    @classmethod
    @abstractmethod
    def register_all(cls) -> None:
        """
        Subclasses of this class should use this function to register themselves
        with Base, using Base.register(). Factories specify the game code that
        they support, which Base will use when routing requests.
        """
        raise NotImplementedError("Override this in subclass!")

    @classmethod
    def run_scheduled_work(cls, data: Data, config: Config) -> None:
        """
        Subclasses of this class should use this function to run any scheduled
        work on classes which it is a factory for. This is usually used for
        out-of-band DB operations such as generating new weekly/daily charts,
        calculating league scores, etc.
        """
        for game in cls.MANAGED_CLASSES:
            try:
                events = game.run_scheduled_work(data, config)
            except Exception:
                events = []
                stack = traceback.format_exc()
                print(stack)
                data.local.network.put_event(
                    "exception",
                    {
                        "service": "scheduler",
                        "traceback": stack,
                    },
                )
            for event in events:
                data.local.network.put_event(event[0], event[1])

    @classmethod
    def all_games(cls) -> Iterator[Tuple[GameConstants, int, str]]:
        """
        Given a particular factory, iterate over all game, version combinations.
        Useful for loading things from the DB without wanting to hardcode values.
        """
        for game in cls.MANAGED_CLASSES:
            yield (game.game, game.version, game.name)

    @classmethod
    def all_settings(cls) -> Iterator[Tuple[GameConstants, int, Dict[str, Any]]]:
        """
        Given a particular factory, iterate over all game, version combinations that
        have settings and return those settings.
        """
        for game in cls.MANAGED_CLASSES:
            yield (game.game, game.version, game.get_settings())

    @classmethod
    @abstractmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional["Base"]:
        """
        Given a modelstring and an optional parent model, return an instantiated game class that can handle a packet.

        Parameters:
            data - A Data singleton for DB access
            config - Configuration dictionary
            model - A parsed Model, used by game factories to determine which game class to return
            parentmodel - The parent model doing the requesting. In some cases, games request an older
                          version game class to migrate profiles. This presents a problem when they don't
                          specify version strings, because some game lookups are ambiguous without them.
                          This allows a factory to determine which game to return based on the parent
                          requesting model, assuming that we want one version back.

        Returns:
            A subclass of Base that hopefully has a handle_<call>_request method on it, for the particular
            call that Dispatch wants to resolve, or None if we can't look up a game.
        """
        raise NotImplementedError("Override this in subclass!")


class Base(ABC):
    """
    The base class every game class inherits from. Incudes handlers for card management, PASELI, most
    non-game startup packets, and simple code for loading/storing profiles.
    """

    __registered_games: Dict[str, Type[Factory]] = {}
    __registered_handlers: Set[Type[Factory]] = set()

    """
    Override this in your subclass.
    """
    game: GameConstants

    """
    Override this in your subclass.
    """
    version: int

    """
    Override this in your subclass.
    """
    name: str

    @property
    def extra_services(self) -> List[str]:
        """
        A list of extra services that this game needs to advertise.
        Override in your subclass if you need to advertise extra
        services for a particular game or series.
        """
        return []

    @property
    def supports_paseli(self) -> bool:
        """
        An override so that particular games can disable PASELI support
        regardless of the server settings. Some games and some regions
        are buggy with respect to PASELI.
        """
        return True

    @property
    def supports_expired_profiles(self) -> bool:
        """
        Override this in your subclass if your game or series requires non-expired profiles
        in order to correctly present migrations to the user.
        """
        return True

    @property
    def requires_extended_regions(self) -> bool:
        """
        Override this in your subclass if your game requires an updated region list.
        """
        return False

    def __init__(self, data: Data, config: Config, model: Model) -> None:
        self.data = data
        self.config = config
        self.model = model

        # Provided purely for convenience. You can also import cache directly from bemani.common
        # in order to use the object for decorators such as @cache.memoize.
        self.cache = cache

    @classmethod
    def create(
        cls,
        data: Data,
        config: Config,
        model: Model,
        parentmodel: Optional[Model] = None,
    ) -> Optional["Base"]:
        """
        Given a modelstring and an optional parent model, return an instantiated game class that can handle a packet.

        Note that this is provided here as game factories register with Base to advertise that the will
        handle some model string. This allows game code to ask for other game classes by model only.

        Parameters:
            data - A Data singleton for DB access
            config - Configuration dictionary
            model - A parsed Model, used by game factories to determine which game class to return
            parentmodel - The parent model doing the requesting. In some cases, games request an older
                          version game class to migrate profiles. This presents a problem when they don't
                          specify version strings, because some game lookups are ambiguous without them.
                          This allows a factory to determine which game to return based on the parent
                          requesting model, assuming that we want one version back.

        Returns:
            A subclass of Base that hopefully has a handle_<call>_request method on it, for the particular
            call that Dispatch wants to resolve, or an instance of Base itself if no game is registered for
            this model. Its possible to return None from this function if a registered game has no way of
            handling this particular modelstring.
        """
        if model.gamecode not in cls.__registered_games:
            # Return just this base model, which will provide nothing
            return Base(data, config, model)
        else:
            # Return the registered module providing this game
            return cls.__registered_games[model.gamecode].create(
                data, config, model, parentmodel=parentmodel
            )

    @classmethod
    def register(cls, gamecode: str, handler: Type[Factory]) -> None:
        """
        Register a factory to handle a game. Note that the game should be the game
        code as returned by a game, such as "LDJ" or "MDX".

        Parameters:
            game - 3-character string identifying a game
            handler - A factory which has a create() method that can spawn game classes.
        """
        cls.__registered_games[gamecode] = handler
        cls.__registered_handlers.add(handler)

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Config
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Run any out-of-band scheduled work that is applicable to this game.
        """
        return []

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return any game settings this game wishes a front-end to modify.
        """
        return {}

    @classmethod
    def all_games(cls) -> Iterator[Tuple[GameConstants, int, str]]:
        """
        Given all registered factories, iterate over all game, version combinations.
        Useful for loading things from the DB without wanting to hardcode values.
        """
        for factory in cls.__registered_handlers:
            for game in factory.MANAGED_CLASSES:
                yield (game.game, game.version, game.name)

    @classmethod
    def all_settings(cls) -> Iterator[Tuple[GameConstants, int, Dict[str, Any]]]:
        """
        Given all registered factories, iterate over all game, version combinations that
        have settings and return those settings.
        """
        for factory in cls.__registered_handlers:
            for game in factory.MANAGED_CLASSES:
                yield (game.game, game.version, game.get_settings())

    def bind_profile(self, userid: UserID) -> None:
        """
        Handling binding the user's profile to this version on this server.

        Parameters:
            userid - The user ID we are binding the profile for.
        """

    def has_profile(self, userid: UserID) -> bool:
        """
        Return whether a user has a profile for this game/version on this server.

        Parameters:
            userid - The user ID we are binding the profile for.

        Returns:
            True if the profile exists, False if not.
        """
        return (
            self.data.local.user.get_profile(self.game, self.version, userid)
            is not None
        )

    def get_profile(self, userid: UserID) -> Optional[Profile]:
        """
        Return the profile for a user given this game/version on any connected server.

        Parameters:
            userid - The user ID we are getting the profile for.

        Returns:
            A dictionary representing the user's profile, or None if it doesn't exist.
        """
        return self.data.remote.user.get_profile(self.game, self.version, userid)

    def get_any_profile(self, userid: UserID) -> Profile:
        """
        Return ANY profile for a user in a game series.

        Tries to look up the profile for a userid/game/version on any connected server.
        If that fails, looks for the latest profile that the user has for the current
        game series. This is usually used for fetching profiles to display names for
        scores, as users can earn scores on different mixes of games and on remote
        networks.

        Parameters:
            userid - The user ID we are getting the profile for.

        Returns:
            A dictionary representing the user's profile, or an empty dictionary if
            none was found.
        """
        profile = self.data.remote.user.get_any_profile(self.game, self.version, userid)
        if profile is None:
            profile = Profile(
                self.game,
                self.version,
                "",
                0,
            )
        return profile

    def get_any_profiles(self, userids: List[UserID]) -> List[Tuple[UserID, Profile]]:
        """
        Does the identical thing to the above function, but takes a list of user IDs to
        fetch in bulk.

        Parameters:
            userids - List of user IDs we are getting the profile for.

        Returns:
            A list of tuples with the User ID and dictionary representing the user's profile,
            or an empty dictionary if nothing was found.
        """
        userids = list(set(userids))
        profiles = self.data.remote.user.get_any_profiles(
            self.game, self.version, userids
        )
        return [
            (
                userid,
                profile
                if profile is not None
                else Profile(self.game, self.version, "", 0),
            )
            for (userid, profile) in profiles
        ]

    def put_profile(self, userid: UserID, profile: Profile) -> None:
        """
        Save a new profile for this user given a game/version.

        Parameters:
            userid - The user ID we are saving the profile for.
            profile - A dictionary that should be looked up later using get_profile.
        """
        if RemoteUser.is_remote(userid):
            raise Exception("Trying to save a remote profile locally!")
        self.data.local.user.put_profile(self.game, self.version, userid, profile)

    def update_play_statistics(
        self, userid: UserID, stats: Optional[PlayStatistics] = None
    ) -> None:
        """
        Given a user ID, calculate new play statistics.

        Handles keeping track of statistics such as consecutive days played, last
        play date, times played today, times played total, etc.

        Parameters:
            userid - The user ID we are binding the profile for.
            stats - A play statistics object we should store extra data from.
        """
        if RemoteUser.is_remote(userid):
            raise Exception("Trying to save remote statistics locally!")

        # We store the play statistics in a series-wide settings blob so its available
        # across all game versions, since it isn't game-specific.
        settings = self.data.local.game.get_settings(
            self.game, userid
        ) or ValidatedDict({})

        if stats is not None:
            for key in stats:
                # Make sure we don't override anything we manage here
                if key in {
                    "total_plays",
                    "today_plays",
                    "total_days",
                    "first_play_timestamp",
                    "last_play_timestamp",
                    "last_play_date",
                    "consecutive_days",
                }:
                    continue
                # Safe to copy over
                settings[key] = stats[key]

        settings.replace_int("total_plays", settings.get_int("total_plays") + 1)
        settings.replace_int(
            "first_play_timestamp", settings.get_int("first_play_timestamp", Time.now())
        )
        settings.replace_int("last_play_timestamp", Time.now())

        last_play_date = settings.get_int_array("last_play_date", 3)
        today_play_date = Time.todays_date()
        yesterday_play_date = Time.yesterdays_date()
        if (
            last_play_date[0] == today_play_date[0]
            and last_play_date[1] == today_play_date[1]
            and last_play_date[2] == today_play_date[2]
        ):
            # We already played today, add one.
            settings.replace_int("today_plays", settings.get_int("today_plays") + 1)
        else:
            # We played on a new day, so count total days up.
            settings.replace_int("total_days", settings.get_int("total_days") + 1)

            # We played only once today (the play we are saving).
            settings.replace_int("today_plays", 1)
            if (
                last_play_date[0] == yesterday_play_date[0]
                and last_play_date[1] == yesterday_play_date[1]
                and last_play_date[2] == yesterday_play_date[2]
            ):
                # We played yesterday, add one to consecutive days
                settings.replace_int(
                    "consecutive_days", settings.get_int("consecutive_days") + 1
                )
            else:
                # We haven't played yesterday, so we have only one consecutive day.
                settings.replace_int("consecutive_days", 1)
        settings.replace_int_array("last_play_date", 3, today_play_date)

        # Save back
        self.data.local.game.put_settings(self.game, userid, settings)

    def get_machine_id(self) -> int:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        return machine.id

    def get_machine(self) -> Machine:
        return self.data.local.machine.get_machine(self.config.machine.pcbid)

    def update_machine_name(self, newname: Optional[str]) -> None:
        if newname is None:
            return
        machine = self.get_machine()
        machine.name = newname
        self.data.local.machine.put_machine(machine)

    def update_machine_data(self, newdata: Dict[str, Any]) -> None:
        machine = self.get_machine()
        machine.data.update(newdata)
        self.data.local.machine.put_machine(machine)

    def update_machine(self, newmachine: Machine) -> None:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        machine.name = newmachine.name
        machine.data = newmachine.data
        self.data.local.machine.put_machine(machine)

    def get_arcade(self) -> Optional[Arcade]:
        machine = self.get_machine()
        if machine.arcade is None:
            return None
        return self.data.local.machine.get_arcade(machine.arcade)

    def get_machine_region(self) -> int:
        arcade = self.get_arcade()
        if arcade is None:
            return RegionConstants.db_to_game_region(
                self.requires_extended_regions, self.config.server.region
            )
        else:
            return RegionConstants.db_to_game_region(
                self.requires_extended_regions, arcade.region
            )

    def get_game_config(self) -> ValidatedDict:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)

        # If this machine belongs to an arcade, use its settings. If the settings aren't present,
        # default to the game's defaults.
        if machine.arcade is not None:
            settings = self.data.local.machine.get_settings(
                machine.arcade, self.game, self.version, "game_config"
            )
            if settings is None:
                settings = ValidatedDict()
            return settings

        # If this machine does not belong to an arcade, use the server-wide settings. If the settings
        # aren't present, default ot the game's default.
        else:
            settings = self.data.local.machine.get_settings(
                self.data.local.machine.DEFAULT_SETTINGS_ARCADE,
                self.game,
                self.version,
                "game_config",
            )
            if settings is None:
                settings = ValidatedDict()
            return settings

    def get_play_statistics(self, userid: UserID) -> PlayStatistics:
        """
        Given a user ID, get the play statistics.

        Note that games wishing to use this when generating profiles to send to
        a game should call update_play_statistics when parsing a profile save.

        Parameters:
            userid - The user ID we are binding the profile for.

        Returns a dictionary optionally containing the following attributes:
            total_plays - Integer count of total plays for this game series
            first_play_timestamp - Unix timestamp of first play time
            last_play_timestamp - Unix timestamp of last play time
            last_play_date - List of ints in the form of [YYYY, MM, DD] of last play date
            today_plays - Number of times played today
            total_days - Total individual days played
            consecutive_days - Number of consecutive days played at this time.
        """
        if RemoteUser.is_remote(userid):
            return PlayStatistics(
                self.game,
                0,
                0,
                0,
                0,
                Time.now(),
                Time.now(),
            )

        # Grab the last saved settings and today's date.
        settings = self.data.local.game.get_settings(self.game, userid)
        today_play_date = Time.todays_date()
        yesterday_play_date = Time.yesterdays_date()
        if settings is None:
            return PlayStatistics(
                self.game,
                1,
                1,
                1,
                1,
                Time.now(),
                Time.now(),
            )

        # Calculate whether we are on our first play of the day or not.
        last_play_date = settings.get_int_array("last_play_date", 3)
        if (
            last_play_date[0] == today_play_date[0]
            and last_play_date[1] == today_play_date[1]
            and last_play_date[2] == today_play_date[2]
        ):
            # We last played today, so the total days and today plays are accurate
            # as stored.
            today_count = settings.get_int("today_plays", 0)
            total_days = settings.get_int("total_days", 1)
            consecutive_days = settings.get_int("consecutive_days", 1)
        else:
            if (
                last_play_date[0] != 0
                and last_play_date[1] != 0
                and last_play_date[2] != 0
            ):
                # We've played before but not today, so the total days is
                # the stored count plus today.
                total_days = settings.get_int("total_days") + 1
            else:
                # We've never played before, so the total days is just 1.
                total_days = 1

            if (
                last_play_date[0] == yesterday_play_date[0]
                and last_play_date[1] == yesterday_play_date[1]
                and last_play_date[2] == yesterday_play_date[2]
            ):
                # We've played before, and it was yesterday, so today is the
                # next consecutive day. So add the current value and today.
                consecutive_days = settings.get_int("consecutive_days") + 1
            else:
                # This is the first consecutive day, we've either never played
                # or we played a bunch but in the past before yesterday.
                consecutive_days = 1

            # We haven't played yet today.
            today_count = 0

        # Grab any extra settings that a game may have stored here.
        extra_settings: Dict[str, Any] = {
            key: value
            for (key, value) in settings.items()
            if key
            not in {
                "total_plays",
                "today_plays",
                "total_days",
                "first_play_timestamp",
                "last_play_timestamp",
                "last_play_date",
                "consecutive_days",
            }
        }

        return PlayStatistics(
            self.game,
            settings.get_int("total_plays") + 1,
            today_count + 1,
            total_days,
            consecutive_days,
            settings.get_int("first_play_timestamp", Time.now()),
            settings.get_int("last_play_timestamp", Time.now()),
            extra_settings,
        )
