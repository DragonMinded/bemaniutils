from typing import List, Any, Dict

from bemani.api.exceptions import APIException
from bemani.common import APIConstants, GameConstants
from bemani.data import Data


class BaseObject:
    """
    A base class which represents a fetchable API object. Every fetchable object
    will subclass from this and implement one or more version fetches. These
    are dynamically looked up by the version number provided by the client, so
    objects can control which versions they reply to by subclassing or ignoring
    various fetch versions.
    """

    def __init__(
        self, data: Data, game: GameConstants, version: int, omnimix: bool
    ) -> None:
        self.data = data
        self.game = game
        self.version = version
        self.omnimix = omnimix

    def fetch_v1(
        self, idtype: APIConstants, ids: List[str], params: Dict[str, Any]
    ) -> Any:
        raise APIException("Object fetch not supported for this version!")
