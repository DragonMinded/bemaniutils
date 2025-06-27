# vim: set fileencoding=utf-8
import copy
from abc import ABC
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, cast

from flask_caching import Cache

from bemani.common import GameConstants, Profile, ValidatedDict, ID
from bemani.data import Data, Config, Score, Attempt, Link, Song, UserID, RemoteUser


class FrontendBase(ABC):
    """
    All subclasses should override this attribute with the string
    the game series uses in the DB.
    """

    game: GameConstants

    """
    If a subclass wishes to constrain music searches to a particular
    version, this should be set. If this is left blank, music operations
    such as records and attempts will pull from all versions of the game.
    """
    version: Optional[int] = None

    """
    List of valid chart integers. Should be overridden by the game.
    """
    valid_charts: List[int] = []

    """
    List of valid rival type strings. Should be overridden by the game.
    """
    valid_rival_types: List[str] = []

    def __init__(self, data: Data, config: Config, cache: Cache) -> None:
        self.data = data
        self.config = config
        self.cache = cache

    def make_index(self, songid: int, chart: int) -> str:
        return f"{songid}-{chart}"

    def get_duplicate_id(self, musicid: int, chart: int) -> Optional[Tuple[int, int]]:
        return None

    def format_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        return {
            "userid": str(userid),
            "songid": score.id,
            "chart": score.chart,
            "plays": score.plays,
            "points": score.points,
        }

    def format_top_score(self, userid: UserID, score: Score) -> Dict[str, Any]:
        return self.format_score(userid, score)

    def format_attempt(self, userid: UserID, attempt: Attempt) -> Dict[str, Any]:
        return {
            "userid": str(userid),
            "songid": attempt.id,
            "chart": attempt.chart,
            "timestamp": attempt.timestamp,
            "raised": attempt.new_record,
            "points": attempt.points,
        }

    def format_rival(self, link: Link, profile: Profile) -> Dict[str, Any]:
        return {
            "type": link.type,
            "userid": str(link.other_userid),
            "remote": RemoteUser.is_remote(link.other_userid),
        }

    def format_profile(self, profile: Profile, playstats: ValidatedDict) -> Dict[str, Any]:
        return {
            "name": profile.get_str("name"),
            "extid": ID.format_extid(profile.extid),
            "first_play_time": playstats.get_int("first_play_timestamp"),
            "last_play_time": playstats.get_int("last_play_timestamp"),
        }

    def format_song(self, song: Song) -> Dict[str, Any]:
        return {
            "name": song.name,
            "artist": song.artist,
            "genre": song.genre,
        }

    def merge_song(self, existing: Dict[str, Any], new: Song) -> Dict[str, Any]:
        return existing

    def round_to_ten(self, elems: List[Any]) -> List[Any]:
        num = len(elems)
        if num % 10 == 0:
            return elems
        else:
            return elems[: -(num % 10)]

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        """
        Override this to return an interator based on a game series factory.
        """

    def get_all_songs(self, force_db_load: bool = False) -> Dict[int, Dict[str, Any]]:
        if not force_db_load:
            cached_songs = self.cache.get(f"{self.game.value}.sorted_songs")
            if cached_songs is not None:
                # Not sure why mypy insists that this is a str instead of Any.
                return cast(Dict[int, Dict[str, Any]], cached_songs)

        # Find all songs in the game, process notecounts and difficulties
        songs: Dict[int, Dict[str, Any]] = {}
        for song in self.data.local.music.get_all_songs(self.game, self.version):
            if song.chart not in self.valid_charts:
                # No beginner chart support
                continue
            if song.id not in songs:
                songs[song.id] = self.format_song(song)
            else:
                songs[song.id] = self.merge_song(songs[song.id], song)

        self.cache.set(f"{self.game.value}.sorted_songs", songs, timeout=600)
        return songs

    def get_all_player_info(
        self,
        userids: List[UserID],
        limit: Optional[int] = None,
        allow_remote: bool = False,
    ) -> Dict[UserID, Dict[int, Dict[str, Any]]]:
        info: Dict[UserID, Dict[int, Dict[str, Any]]] = {}
        playstats: Dict[UserID, ValidatedDict] = {}

        # Find all versions of the users' profiles, sorted newest to oldest.
        versions = sorted([version for (game, version, name) in self.all_games()], reverse=True)
        for userid in userids:
            info[userid] = {}
            userlimit = limit
            for version in versions:
                if allow_remote:
                    profile = self.data.remote.user.get_profile(self.game, version, userid)
                else:
                    profile = self.data.local.user.get_profile(self.game, version, userid)
                if profile is not None:
                    if userid not in playstats:
                        stats = self.data.local.game.get_settings(self.game, userid)
                        if stats is None:
                            stats = ValidatedDict()
                        playstats[userid] = stats
                    info[userid][version] = self.format_profile(profile, playstats[userid])
                    info[userid][version]["remote"] = RemoteUser.is_remote(userid)
                    # Exit out if we've hit the limit
                    if userlimit is not None:
                        userlimit = userlimit - 1
                        if userlimit == 0:
                            break

        return info

    def get_latest_player_info(self, userids: List[UserID]) -> Dict[UserID, Dict[str, Any]]:
        # Grab the latest profile for each user
        all_info = self.get_all_player_info(userids, 1)
        info = {}

        for userid in userids:
            for version in all_info[userid]:
                info[userid] = all_info[userid][version]
                break

        return info

    def get_all_players(self) -> Dict[UserID, Dict[str, Any]]:
        userids: Set[UserID] = set()

        versions = [version for (game, version, name) in self.all_games()]
        for version in versions:
            userids.update(self.data.local.user.get_all_players(self.game, version))

        return self.get_latest_player_info(list(userids))

    def get_network_scores(self, limit: Optional[int] = None) -> Dict[str, Any]:
        userids: List[UserID] = []

        # Find all attempts across all games
        attempts = [
            attempt
            for attempt in self.data.local.music.get_all_attempts(game=self.game, version=self.version, limit=limit)
            if attempt[0] is not None
        ]
        for attempt in attempts:
            if attempt[0] not in userids:
                userids.append(attempt[0])

        return {
            "attempts": sorted(
                [self.format_attempt(attempt[0], attempt[1]) for attempt in attempts],
                reverse=True,
                key=lambda attempt: (
                    attempt["timestamp"],
                    attempt["songid"],
                    attempt["chart"],
                ),
            ),
            "players": self.get_latest_player_info(userids),
        }

    def get_network_records(self) -> Dict[str, Any]:
        records: Dict[str, Tuple[UserID, Score]] = {}
        userids: List[UserID] = []

        # Find all high-scores across all games
        highscores = self.data.local.music.get_all_records(game=self.game, version=self.version)
        for score in highscores:
            index = self.make_index(score[1].id, score[1].chart)
            if index not in records:
                records[index] = score
                if score[0] not in userids:
                    userids.append(score[0])
            # Also take care of duplicate IDs (revivals, omnimix, etc)
            alternate = self.get_duplicate_id(score[1].id, score[1].chart)
            if alternate is not None:
                altid, altchart = alternate
                index = self.make_index(altid, altchart)
                if index not in records:
                    newscore = copy.deepcopy(score)
                    newscore[1].id = altid
                    newscore[1].chart = altchart
                    records[index] = newscore

        return {
            "records": [self.format_score(records[index][0], records[index][1]) for index in records],
            "players": self.get_latest_player_info(userids),
        }

    def get_scores(self, userid: UserID, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        # Find all attempts across all games
        attempts = [
            attempt
            for attempt in self.data.local.music.get_all_attempts(
                game=self.game, version=self.version, userid=userid, limit=limit
            )
            if attempt[0] is not None
        ]

        return sorted(
            [self.format_attempt(None, attempt[1]) for attempt in attempts],
            reverse=True,
            key=lambda attempt: (
                attempt["timestamp"],
                attempt["songid"],
                attempt["chart"],
            ),
        )

    def get_records(self, userid: UserID) -> List[Dict[str, Any]]:
        records: Dict[str, Tuple[UserID, Score]] = {}

        # Find all high-scores across all games
        highscores = self.data.local.music.get_all_scores(game=self.game, version=self.version, userid=userid)
        for score in highscores:
            index = self.make_index(score[1].id, score[1].chart)
            if index not in records:
                records[index] = score
            else:
                current_score = records[index][1].points
                current_plays = records[index][1].plays
                new_score = score[1].points
                new_plays = score[1].plays
                if new_score > current_score:
                    records[index] = score
                    records[index][1].plays += current_plays
                else:
                    records[index][1].plays += new_plays

        # Copy over records to duplicate IDs, such as revivals
        indexes = [index for index in records]
        for index in indexes:
            alternate = self.get_duplicate_id(records[index][1].id, records[index][1].chart)
            if alternate is not None:
                altid, altchart = alternate
                newindex = self.make_index(altid, altchart)
                if newindex not in records:
                    newscore = copy.deepcopy(score)
                    newscore[1].id = altid
                    newscore[1].chart = altchart
                    records[newindex] = newscore

        return [self.format_score(None, records[index][1]) for index in records]

    def get_top_scores(self, musicid: int) -> Dict[str, Any]:
        scores = self.data.local.music.get_all_scores(game=self.game, version=self.version, songid=musicid)
        userids: List[UserID] = []
        for score in scores:
            if score[1].chart not in self.valid_charts:
                # No beginner chart support
                continue
            if score[0] not in userids:
                userids.append(score[0])

        for score in scores:
            # See if this is a legacy ID
            if score[1].id != musicid:
                alternative = self.get_duplicate_id(score[1].id, score[1].chart)
                if alternative is None:
                    continue

                oldid, oldchart = alternative
                if oldid == musicid:
                    score[1].id = oldid
                    score[1].chart = oldchart

        return {
            "topscores": [
                self.format_top_score(score[0], score[1]) for score in scores if score[1].chart in self.valid_charts
            ],
            "players": self.get_latest_player_info(userids),
        }

    def get_rivals(
        self, userid: UserID
    ) -> Tuple[Dict[int, List[Dict[str, Any]]], Dict[UserID, Dict[int, Dict[str, Any]]]]:
        rivals = {}
        userids = set()
        versions = [version for (game, version, name) in self.all_games()]
        profiles = {}
        for version in versions:
            profile = self.data.local.user.get_profile(self.game, version, userid)
            if profile is None:
                # No profile for this version, so no rivals either.
                continue
            profiles[version] = profile
            rivals[version] = [
                link
                for link in self.data.local.user.get_links(self.game, version, userid)
                if link.type in self.valid_rival_types
            ]
            for rival in rivals[version]:
                userids.add(rival.other_userid)

        return (
            {version: [self.format_rival(rival, profiles[version]) for rival in rivals[version]] for version in rivals},
            self.get_all_player_info(list(userids), allow_remote=True),
        )
