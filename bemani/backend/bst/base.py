from bemani.common import Profile
from bemani.data.types import UserID
from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import GameConstants
from bemani.protocol import Node

class BSTBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    game = GameConstants.BST

    # Helper method that enables events based on the server config
    def get_events(self) -> Node:
        return Node.void('event_ctrl')

    def update_score(self, extid, songid, chartid, loc, points, gauge, 
    max_combo, grade, medal, fanta_count, great_count, fine_count, miss_count) -> None:
        return None

    def unformat_player_profile(self, profile: Node, refid: str, extid: int, userid: UserID) -> Profile:
        return None

    def format_player_profile(self, profile: Profile, userid: UserID) -> Node:
        return None