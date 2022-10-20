import random

from bemani.backend.base import Base
from bemani.protocol import Node


class EventLogHandler(Base):
    """
    A mixin that can be used to provide ESS eventlog handling.
    """

    def handle_eventlog_write_request(self, request: Node) -> Node:
        # Just turn off further logging
        gamesession = request.child_value("data/gamesession")
        if gamesession < 0:
            gamesession = random.randint(1, 1000000)

        root = Node.void("eventlog")
        root.add_child(Node.s64("gamesession", gamesession))
        root.add_child(Node.s32("logsendflg", 0))
        root.add_child(Node.s32("logerrlevel", 0))
        root.add_child(Node.s32("evtidnosendflg", 0))
        return root
