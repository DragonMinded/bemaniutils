import copy
from typing import Any, Dict, Iterator, List, Tuple

from bemani.backend.bst import BSTFactory, BSTBase
from bemani.common import Profile, ValidatedDict, GameConstants, VersionConstants
from bemani.data import Attempt, Link, RemoteUser, Score, Song, UserID
from bemani.frontend.base import FrontendBase

class BSTFrontend(FrontendBase):
    game: GameConstants = GameConstants.BST

    def all_games(self) -> Iterator[Tuple[GameConstants, int, str]]:
        yield from BSTFactory.all_games()

    def update_name(self, profile: Profile, name: str) -> Profile:
        newprofile = copy.deepcopy(profile)
        newprofile.replace_str('name', name)
        return newprofile