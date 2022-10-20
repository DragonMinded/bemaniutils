# vim: set fileencoding=utf-8
import unittest
from freezegun import freeze_time

from bemani.common.time import Time


class TestTime(unittest.TestCase):
    def test_days_since_epoch(self) -> None:
        # Verify that we just get the right number of days.
        with freeze_time("2016-01-01"):
            self.assertEqual(16797, Time.week_in_days_since_epoch())

        # Verify that adding a day doesn't change the value, because it rounds to nearest week.
        with freeze_time("2016-01-02"):
            self.assertEqual(16797, Time.week_in_days_since_epoch())

        # Verify that adding a week makes the value go up by 7 days.
        with freeze_time("2016-01-08"):
            self.assertEqual(16804, Time.week_in_days_since_epoch())

    def test_end_of_this_week(self) -> None:
        # Verify that we can detect the end of the month properly
        with freeze_time("2017-10-16"):
            self.assertEqual(1508716800, Time.end_of_this_week())

    def test_beginning_of_this_week(self) -> None:
        # Verify that we can detect the end of the month properly
        with freeze_time("2017-10-16"):
            self.assertEqual(1508112000, Time.beginning_of_this_week())

    def test_end_of_this_month(self) -> None:
        # Verify that we can detect the end of the month properly
        with freeze_time("2017-10-16"):
            self.assertEqual(1509494400, Time.end_of_this_month())

    def test_beginning_of_this_month(self) -> None:
        # Verify that we can detect the end of the month properly
        with freeze_time("2017-10-16"):
            self.assertEqual(1506816000, Time.beginning_of_this_month())
