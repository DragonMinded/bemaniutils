import json
import requests
from typing import Tuple, Dict, List, Any, Optional
from typing_extensions import Final

from bemani.common import (
    APIConstants,
    GameConstants,
    VersionConstants,
    DBConstants,
    ValidatedDict,
    Time,
    cache,
)


class APIException(Exception):
    pass


class NotAuthorizedAPIException(APIException):
    pass


class UnsupportedRequestAPIException(APIException):
    pass


class UnrecognizedRequestAPIException(APIException):
    pass


class UnsupportedVersionAPIException(APIException):
    pass


class RemoteServerErrorAPIException(APIException):
    pass


class APIClient:
    """
    A client that fully speaks BEMAPI and can pull information from a remote server.
    """

    API_VERSION: Final[str] = "v1"

    def __init__(self, base_uri: str, token: str, allow_stats: bool, allow_scores: bool) -> None:
        self.base_uri = base_uri
        self.token = token
        self.allow_stats = allow_stats
        self.allow_scores = allow_scores

    def __repr__(self) -> str:
        # Specifically defined so that two different instances of the same API client
        # cache under the same key, as we want to share results from a given server
        # to all local requests. We also have to be sensitive to any control character
        # limitations for memcached.
        repr_val = (
            "APIClient("
            + f"base_uri={self.base_uri!r},"
            + f"token={self.token!r},"
            + f"allow_stats={self.allow_stats!r},"
            + f"allow_scores={self.allow_scores!r}"
            + ")"
        )
        repr_val = repr_val.replace(" ", "_")
        repr_val = repr_val.replace("\r", "_")
        repr_val = repr_val.replace("\n", "_")
        return repr_val

    def _content_type_valid(self, content_type: str) -> bool:
        if ";" in content_type:
            left, right = content_type.split(";", 1)
            left = left.strip().lower()
            right = right.strip().lower()

            if left == "application/json" and ("=" in right):
                identifier, charset = right.split("=", 1)
                identifier = identifier.strip()
                charset = charset.strip()

                if identifier == "charset" and charset == "utf-8":
                    # This is valid.
                    return True
        return False

    def __exchange_data(self, request_uri: str, request_args: Dict[str, Any]) -> Dict[str, Any]:
        if self.base_uri[-1:] != "/":
            uri = f"{self.base_uri}/{request_uri}"
        else:
            uri = f"{self.base_uri}{request_uri}"

        headers = {
            "Authorization": f"Token {self.token}",
            "Content-Type": "application/json; charset=utf-8",
        }
        data = json.dumps(request_args).encode("utf8")

        try:
            r = requests.request(
                "GET",
                uri,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=10,
            )
        except Exception:
            raise APIException("Failed to query remote server!")

        # Verify that content type is in the form of "application/json; charset=utf-8".
        if not self._content_type_valid(r.headers["content-type"]):
            raise APIException(f'API returned invalid content type \'{r.headers["content-type"]}\'!')

        jsondata = r.json()

        if r.status_code == 200:
            return jsondata

        if "error" not in jsondata:
            raise APIException(
                f"API returned error code {r.status_code} but did not include 'error' attribute in response JSON!"
            )
        error = jsondata["error"]

        if r.status_code == 401:
            raise NotAuthorizedAPIException("The API token used is not authorized against this server!")
        if r.status_code == 404:
            raise UnsupportedRequestAPIException("The server does not support this game/version or request object!")
        if r.status_code == 405:
            raise UnrecognizedRequestAPIException("The server did not recognize the request!")
        if r.status_code == 500:
            raise RemoteServerErrorAPIException(
                f"The server had an error processing the request and returned '{error}'"
            )
        if r.status_code == 501:
            raise UnsupportedVersionAPIException("The server does not support this version of the API!")
        raise APIException("The server returned an invalid status code {}!", format(r.status_code))

    def __translate(self, game: GameConstants, version: int) -> Tuple[str, str]:
        servergame = {
            GameConstants.DDR: "ddr",
            GameConstants.IIDX: "iidx",
            GameConstants.JUBEAT: "jubeat",
            GameConstants.MUSECA: "museca",
            GameConstants.POPN_MUSIC: "popnmusic",
            GameConstants.REFLEC_BEAT: "reflecbeat",
            GameConstants.SDVX: "soundvoltex",
            GameConstants.DANCE_EVOLUTION: "danceevolution",
        }.get(game)
        if servergame is None:
            raise UnsupportedRequestAPIException("The client does not support this game/version!")

        if version >= DBConstants.OMNIMIX_VERSION_BUMP:
            version = version - DBConstants.OMNIMIX_VERSION_BUMP
            omnimix = True
        else:
            omnimix = False

        serverversion = (
            {
                GameConstants.DDR: {
                    VersionConstants.DDR_X2: "12",
                    VersionConstants.DDR_X3_VS_2NDMIX: "13",
                    VersionConstants.DDR_2013: "14",
                    VersionConstants.DDR_2014: "15",
                    VersionConstants.DDR_ACE: "16",
                    VersionConstants.DDR_A20: "17",
                },
                GameConstants.IIDX: {
                    VersionConstants.IIDX_TRICORO: "20",
                    VersionConstants.IIDX_SPADA: "21",
                    VersionConstants.IIDX_PENDUAL: "22",
                    VersionConstants.IIDX_COPULA: "23",
                    VersionConstants.IIDX_SINOBUZ: "24",
                    VersionConstants.IIDX_CANNON_BALLERS: "25",
                    VersionConstants.IIDX_ROOTAGE: "26",
                    VersionConstants.IIDX_HEROIC_VERSE: "27",
                    VersionConstants.IIDX_BISTROVER: "28",
                },
                GameConstants.JUBEAT: {
                    VersionConstants.JUBEAT_SAUCER: "5",
                    VersionConstants.JUBEAT_SAUCER_FULFILL: "5a",
                    VersionConstants.JUBEAT_PROP: "6",
                    VersionConstants.JUBEAT_QUBELL: "7",
                    VersionConstants.JUBEAT_CLAN: "8",
                    VersionConstants.JUBEAT_FESTO: "9",
                    VersionConstants.JUBEAT_AVENUE: "10",
                },
                GameConstants.MUSECA: {
                    VersionConstants.MUSECA: "1",
                    VersionConstants.MUSECA_1_PLUS: "1p",
                },
                GameConstants.POPN_MUSIC: {
                    VersionConstants.POPN_MUSIC_TUNE_STREET: "19",
                    VersionConstants.POPN_MUSIC_FANTASIA: "20",
                    VersionConstants.POPN_MUSIC_SUNNY_PARK: "21",
                    VersionConstants.POPN_MUSIC_LAPISTORIA: "22",
                    VersionConstants.POPN_MUSIC_ECLALE: "23",
                    VersionConstants.POPN_MUSIC_USANEKO: "24",
                    VersionConstants.POPN_MUSIC_PEACE: "25",
                    VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES: "26",
                    VersionConstants.POPN_MUSIC_UNILAB: "27",
                },
                GameConstants.REFLEC_BEAT: {
                    VersionConstants.REFLEC_BEAT: "1",
                    VersionConstants.REFLEC_BEAT_LIMELIGHT: "2",
                    VersionConstants.REFLEC_BEAT_COLETTE: "3as",
                    VersionConstants.REFLEC_BEAT_GROOVIN: "4u",
                    VersionConstants.REFLEC_BEAT_VOLZZA: "5",
                    VersionConstants.REFLEC_BEAT_VOLZZA_2: "5a",
                    VersionConstants.REFLEC_BEAT_REFLESIA: "6",
                },
                GameConstants.SDVX: {
                    VersionConstants.SDVX_BOOTH: "1",
                    VersionConstants.SDVX_INFINITE_INFECTION: "2",
                    VersionConstants.SDVX_GRAVITY_WARS: "3",
                    VersionConstants.SDVX_HEAVENLY_HAVEN: "4",
                },
                GameConstants.DANCE_EVOLUTION: {
                    VersionConstants.DANCE_EVOLUTION: "1",
                },
            }
            .get(game, {})
            .get(version)
        )
        if serverversion is None:
            raise UnsupportedRequestAPIException("The client does not support this game/version!")

        if omnimix:
            serverversion = "o" + serverversion

        return (servergame, serverversion)

    # Not caching this, as it is only hit when looking at the admin panel, and we want this to
    # always be up-to-date.
    def get_server_info(self) -> ValidatedDict:
        resp = self.__exchange_data("", {})
        return ValidatedDict(
            {
                "name": resp["name"],
                "email": resp["email"],
                "versions": resp["versions"],
            }
        )

    # Not caching this, as we would have to go back and ensure that any code which got outdated
    # profiles from a cache didn't end up with KeyError exceptions when trying to link profiles to
    # records. This is the coward's way out, but whatever.
    def get_profiles(
        self, game: GameConstants, version: int, idtype: APIConstants, ids: List[str]
    ) -> List[Dict[str, Any]]:
        # Allow remote servers to be disabled
        if not self.allow_scores:
            return []

        try:
            servergame, serverversion = self.__translate(game, version)
            resp = self.__exchange_data(
                f"{self.API_VERSION}/{servergame}/{serverversion}",
                {
                    "ids": ids,
                    "type": idtype.value,
                    "objects": ["profile"],
                },
            )
            return resp["profile"]
        except APIException:
            # Couldn't talk to server, assume empty profiles
            return []

    @cache.memoize(Time.SECONDS_IN_MINUTE * 1)
    def get_records(
        self,
        game: GameConstants,
        version: int,
        idtype: APIConstants,
        ids: List[str],
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        # Allow remote servers to be disabled
        if not self.allow_scores:
            return []

        try:
            servergame, serverversion = self.__translate(game, version)
            data: Dict[str, Any] = {
                "ids": ids,
                "type": idtype.value,
                "objects": ["records"],
            }
            if since is not None:
                data["since"] = since
            if until is not None:
                data["until"] = until
            resp = self.__exchange_data(
                f"{self.API_VERSION}/{servergame}/{serverversion}",
                data,
            )
            return resp["records"]
        except APIException:
            # Couldn't talk to server, assume empty records
            return []

    @cache.memoize(Time.SECONDS_IN_MINUTE * 5)
    def get_statistics(
        self, game: GameConstants, version: int, idtype: APIConstants, ids: List[str]
    ) -> List[Dict[str, Any]]:
        # Allow remote servers to be disabled
        if not self.allow_stats:
            return []

        try:
            servergame, serverversion = self.__translate(game, version)
            resp = self.__exchange_data(
                f"{self.API_VERSION}/{servergame}/{serverversion}",
                {
                    "ids": ids,
                    "type": idtype.value,
                    "objects": ["statistics"],
                },
            )
            return resp["statistics"]
        except APIException:
            # Couldn't talk to server, assume empty statistics
            return []

    @cache.memoize(Time.SECONDS_IN_HOUR * 1)
    def get_catalog(self, game: GameConstants, version: int) -> Dict[str, List[Dict[str, Any]]]:
        # No point disallowing this, since its only ever used for bootstrapping.

        try:
            servergame, serverversion = self.__translate(game, version)
            resp = self.__exchange_data(
                f"{self.API_VERSION}/{servergame}/{serverversion}",
                {
                    "ids": [],
                    "type": "server",
                    "objects": ["catalog"],
                },
            )
            return resp["catalog"]
        except APIException:
            # Couldn't talk to server, assume empty catalog
            return {}
