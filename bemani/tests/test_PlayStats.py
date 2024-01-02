# vim: set fileencoding=utf-8
import unittest
from freezegun import freeze_time
from typing import Dict, Any
from unittest.mock import Mock

from bemani.backend.base import Base
from bemani.common import GameConstants, Time, ValidatedDict
from bemani.data import UserID


# Make the normally-abstract base instantiable so we can test it.
class InstantiableBase(Base):
    game = GameConstants.BISHI_BASHI
    version = -1
    name = "Test Class"


# Make an easier mock implementation of load/save stats.
def mock_stats(existing_value: Dict[str, Any]) -> Mock:
    data = Mock()
    data.local = Mock()
    data.local.game = Mock()
    data.local.game.get_settings = Mock(return_value=ValidatedDict(existing_value) if existing_value else None)
    data.local.game.put_settings = Mock()
    return data


def saved_stats(mock: Mock) -> ValidatedDict:
    return ValidatedDict(mock.local.game.put_settings.call_args.args[2])


class TestPlayStats(unittest.TestCase):
    def test_get_brand_new_profile(self) -> None:
        with freeze_time("2021-08-24"):
            stats = None
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))

            self.assertEqual(settings.game, GameConstants.BISHI_BASHI)
            self.assertEqual(settings.total_plays, 1)
            self.assertEqual(settings.today_plays, 1)
            self.assertEqual(settings.total_days, 1)
            self.assertEqual(settings.consecutive_days, 1)
            self.assertEqual(settings.first_play_timestamp, Time.now())
            self.assertEqual(settings.last_play_timestamp, Time.now())

    def test_put_brand_new_profile(self) -> None:
        with freeze_time("2021-08-24"):
            stats = None
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))
            base.update_play_statistics(UserID(1337), settings)
            new_settings = saved_stats(data)

            self.assertEqual(new_settings.get_int("total_plays"), 1)
            self.assertEqual(new_settings.get_int("today_plays"), 1)
            self.assertEqual(new_settings.get_int("total_days"), 1)
            self.assertEqual(new_settings.get_int("consecutive_days"), 1)
            self.assertEqual(new_settings.get_int("first_play_timestamp"), Time.now())
            self.assertEqual(new_settings.get_int("last_play_timestamp"), Time.now())
            self.assertEqual(new_settings.get_int_array("last_play_date", 3), Time.todays_date())

    def test_get_played_today(self) -> None:
        with freeze_time("2021-08-24"):
            play_date = Time.todays_date()
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 9876543210,
                "consecutive_days": 69,
                "last_play_date": [play_date[0], play_date[1], play_date[2]],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))

            self.assertEqual(settings.game, GameConstants.BISHI_BASHI)
            self.assertEqual(settings.total_plays, 1235)
            self.assertEqual(settings.today_plays, 421)
            self.assertEqual(settings.total_days, 10)
            self.assertEqual(settings.consecutive_days, 69)
            self.assertEqual(settings.first_play_timestamp, 1234567890)
            self.assertEqual(settings.last_play_timestamp, 9876543210)

    def test_put_played_today(self) -> None:
        with freeze_time("2021-08-24"):
            play_date = Time.todays_date()
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 1234567890,
                "consecutive_days": 69,
                "last_play_date": [play_date[0], play_date[1], play_date[2]],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))
            base.update_play_statistics(UserID(1337), settings)
            new_settings = saved_stats(data)

            self.assertEqual(new_settings.get_int("total_plays"), 1235)
            self.assertEqual(new_settings.get_int("today_plays"), 421)
            self.assertEqual(new_settings.get_int("total_days"), 10)
            self.assertEqual(new_settings.get_int("consecutive_days"), 69)
            self.assertEqual(new_settings.get_int("first_play_timestamp"), 1234567890)
            self.assertEqual(new_settings.get_int("last_play_timestamp"), Time.now())
            self.assertEqual(new_settings.get_int_array("last_play_date", 3), Time.todays_date())

    def test_get_played_yesterday(self) -> None:
        with freeze_time("2021-08-24"):
            play_date = Time.yesterdays_date()
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 9876543210,
                "consecutive_days": 69,
                "last_play_date": [play_date[0], play_date[1], play_date[2]],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))

            self.assertEqual(settings.game, GameConstants.BISHI_BASHI)
            self.assertEqual(settings.total_plays, 1235)
            self.assertEqual(settings.today_plays, 1)
            self.assertEqual(settings.total_days, 11)
            self.assertEqual(settings.consecutive_days, 70)
            self.assertEqual(settings.first_play_timestamp, 1234567890)
            self.assertEqual(settings.last_play_timestamp, 9876543210)

    def test_put_played_yesterday(self) -> None:
        with freeze_time("2021-08-24"):
            play_date = Time.yesterdays_date()
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 1234567890,
                "consecutive_days": 69,
                "last_play_date": [play_date[0], play_date[1], play_date[2]],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))
            base.update_play_statistics(UserID(1337), settings)
            new_settings = saved_stats(data)

            self.assertEqual(new_settings.get_int("total_plays"), 1235)
            self.assertEqual(new_settings.get_int("today_plays"), 1)
            self.assertEqual(new_settings.get_int("total_days"), 11)
            self.assertEqual(new_settings.get_int("consecutive_days"), 70)
            self.assertEqual(new_settings.get_int("first_play_timestamp"), 1234567890)
            self.assertEqual(new_settings.get_int("last_play_timestamp"), Time.now())
            self.assertEqual(new_settings.get_int_array("last_play_date", 3), Time.todays_date())

    def test_get_played_awhile_ago(self) -> None:
        with freeze_time("2021-08-24"):
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 9876543210,
                "consecutive_days": 69,
                "last_play_date": [2010, 4, 20],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))

            self.assertEqual(settings.game, GameConstants.BISHI_BASHI)
            self.assertEqual(settings.total_plays, 1235)
            self.assertEqual(settings.today_plays, 1)
            self.assertEqual(settings.total_days, 11)
            self.assertEqual(settings.consecutive_days, 1)
            self.assertEqual(settings.first_play_timestamp, 1234567890)
            self.assertEqual(settings.last_play_timestamp, 9876543210)

    def test_put_played_awhile_ago(self) -> None:
        with freeze_time("2021-08-24"):
            stats = {
                "total_plays": 1234,
                "today_plays": 420,
                "total_days": 10,
                "first_play_timestamp": 1234567890,
                "last_play_timestamp": 1234567890,
                "consecutive_days": 69,
                "last_play_date": [2010, 4, 20],
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))
            base.update_play_statistics(UserID(1337), settings)
            new_settings = saved_stats(data)

            self.assertEqual(new_settings.get_int("total_plays"), 1235)
            self.assertEqual(new_settings.get_int("today_plays"), 1)
            self.assertEqual(new_settings.get_int("total_days"), 11)
            self.assertEqual(new_settings.get_int("consecutive_days"), 1)
            self.assertEqual(new_settings.get_int("first_play_timestamp"), 1234567890)
            self.assertEqual(new_settings.get_int("last_play_timestamp"), Time.now())
            self.assertEqual(new_settings.get_int_array("last_play_date", 3), Time.todays_date())

    def test_get_extra_settings(self) -> None:
        with freeze_time("2021-08-24"):
            stats = {
                "total_plays": 1234,
                "key": "value",
                "int": 1337,
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))

            self.assertEqual(settings.get_int("int"), 1337)
            self.assertEqual(settings.get_str("key"), "value")
            self.assertEqual(settings.get_int("total_plays"), 0)

    def test_put_extra_settings(self) -> None:
        with freeze_time("2021-08-24"):
            stats = {
                "total_plays": 1234,
                "key": "value",
                "int": 1337,
            }
            data = mock_stats(stats)
            base = InstantiableBase(data, Mock(), Mock())

            settings = base.get_play_statistics(UserID(1337))
            settings.replace_int("int", 420)
            settings.replace_int("int2", 69)
            settings.replace_int("total_plays", 37)
            base.update_play_statistics(UserID(1337), settings)

            new_settings = saved_stats(data)

            self.assertEqual(new_settings.get_int("int"), 420)
            self.assertEqual(new_settings.get_str("key"), "value")
            self.assertEqual(new_settings.get_int("int2"), 69)
            self.assertEqual(new_settings.get_int("total_plays"), 1235)
