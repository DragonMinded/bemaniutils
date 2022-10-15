# vim: set fileencoding=utf-8
import unittest
from unittest.mock import Mock
from freezegun import freeze_time

from bemani.common import GameConstants
from bemani.data.mysql.network import NetworkData
from bemani.tests.helpers import FakeCursor


class TestNetworkData(unittest.TestCase):
    def test_get_schedule_type(self) -> None:
        network = NetworkData(Mock(), None)

        with freeze_time("2016-01-01 12:00"):
            # Check daily schedule
            self.assertEqual(
                # 2016-01-01 -> 2016-01-02
                (1451606400, 1451692800),
                network.get_schedule_duration("daily"),
            )

            # Check weekly schedule (weeks start on monday in python lol)
            self.assertEqual(
                # 2015-12-27 -> 2916-01-03
                (1451260800, 1451865600),
                network.get_schedule_duration("weekly"),
            )

    def test_should_schedule(self) -> None:
        network = NetworkData(Mock(), None)

        with freeze_time("2016-01-01"):
            # Check for should schedule if nothing in DB
            network.execute = Mock(return_value=FakeCursor([]))  # type: ignore
            self.assertTrue(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "daily")
            )
            self.assertTrue(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "weekly")
            )

            # Check for don't schedule if DB time is our current time
            network.execute = Mock(return_value=FakeCursor([{"year": 2016, "day": 1}]))  # type: ignore
            self.assertFalse(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "daily")
            )

            network.execute = Mock(return_value=FakeCursor([{"year": None, "day": 16797}]))  # type: ignore
            self.assertFalse(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "weekly")
            )

            # Check for do schedule if DB time is older than our current time
            network.execute = Mock(return_value=FakeCursor([{"year": 2015, "day": 365}]))  # type: ignore
            self.assertTrue(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "daily")
            )

            network.execute = Mock(return_value=FakeCursor([{"year": None, "day": 16790}]))  # type: ignore
            self.assertTrue(
                network.should_schedule(GameConstants.BISHI_BASHI, 1, "work", "weekly")
            )
