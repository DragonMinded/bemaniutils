# vim: set fileencoding=utf-8
import unittest
from unittest.mock import Mock

from bemani.common import GameConstants
from bemani.data.mysql.game import GameData
from bemani.tests.helpers import FakeCursor


class TestGameData(unittest.TestCase):
    def test_put_time_sensitive_settings(self) -> None:
        game = GameData(Mock(), None)

        # Verify that we catch incorrect input order
        with self.assertRaises(Exception) as context:
            game.put_time_sensitive_settings(
                GameConstants.BISHI_BASHI,
                1,
                "work",
                {"start_time": 12345, "end_time": 12340},
            )
        self.assertTrue("Start time is greater than end time!" in str(context.exception))

        # Verify that we catch events spanning no time
        with self.assertRaises(Exception) as context:
            game.put_time_sensitive_settings(
                GameConstants.BISHI_BASHI,
                1,
                "work",
                {"start_time": 12345, "end_time": 12345},
            )
        self.assertTrue("This setting spans zero seconds!" in str(context.exception))

        # Verify that we ignore finding ourselves before updating
        game.execute = Mock(return_value=FakeCursor([{"start_time": 12345, "end_time": 12346}]))  # type: ignore
        game.put_time_sensitive_settings(
            GameConstants.BISHI_BASHI,
            1,
            "work",
            {"start_time": 12345, "end_time": 12346},
        )

        # Verify that we catch events overlapping other events in the DB
        game.execute = Mock(return_value=FakeCursor([{"start_time": 12345, "end_time": 12350}]))  # type: ignore
        with self.assertRaises(Exception) as context:
            game.put_time_sensitive_settings(
                GameConstants.BISHI_BASHI,
                1,
                "work",
                {"start_time": 12347, "end_time": 12355},
            )
        self.assertTrue(
            "This event overlaps an existing one with start time 12345 and end time 12350" in str(context.exception)
        )
