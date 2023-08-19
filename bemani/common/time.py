import calendar
import datetime
from dateutil import tz

from typing import List, Optional
from typing_extensions import Final


class Time:
    """
    Python's time stuff sucks, so this provides a sane interface to getting
    standard unix timestamps at UTC timezone given various parameters.
    """

    SECONDS_IN_SECOND: Final[int] = 1
    SECONDS_IN_MINUTE: Final[int] = 60
    SECONDS_IN_HOUR: Final[int] = 3600
    SECONDS_IN_DAY: Final[int] = 86400
    SECONDS_IN_WEEK: Final[int] = 604800

    @staticmethod
    def now() -> int:
        """
        Returns the current unix timestamp in the UTC timezone.
        """
        return calendar.timegm(datetime.datetime.utcnow().timetuple())

    @staticmethod
    def end_of_today() -> int:
        """
        Returns the unix timestamp for the end of today in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        beginning_of_day = datetime.datetime(
            now.year, now.month, now.day, tzinfo=tz.tzutc()
        )
        end_of_day = beginning_of_day + datetime.timedelta(days=1)
        return calendar.timegm(end_of_day.timetuple())

    @staticmethod
    def beginning_of_today() -> int:
        """
        Returns the unix timestamp for the beginning of today in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        beginning_of_day = datetime.datetime(
            now.year, now.month, now.day, tzinfo=tz.tzutc()
        )
        return calendar.timegm(beginning_of_day.timetuple())

    @staticmethod
    def end_of_this_week() -> int:
        """
        Returns the unix timestamp for the end of this week in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        this_week = now - datetime.timedelta(days=now.timetuple().tm_wday)
        next_week = this_week + datetime.timedelta(days=7)
        return calendar.timegm(next_week.timetuple())

    @staticmethod
    def beginning_of_this_week() -> int:
        """
        Returns the unix timestamp for the beginning of this week in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        this_week = now - datetime.timedelta(days=now.timetuple().tm_wday)
        return calendar.timegm(this_week.timetuple())

    @staticmethod
    def end_of_this_month() -> int:
        """
        Returns the unix timestamp for the end of this month in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        return Time.timestamp_from_date(now.year, now.month + 1, 1)

    @staticmethod
    def beginning_of_this_month() -> int:
        """
        Returns the unix timestamp for the beginning of this month in UTC timezone.
        """
        now = datetime.datetime.utcnow().date()
        this_month = datetime.date(now.year, now.month, 1)
        return calendar.timegm(this_month.timetuple())

    @staticmethod
    def todays_date() -> List[int]:
        """
        Returns a [year, month, day] list representing today's date.
        """
        now = datetime.datetime.utcnow().date()
        return [now.year, now.month, now.day]

    @staticmethod
    def yesterdays_date() -> List[int]:
        """
        Returns a [year, month, day] list representing yesterday's date.
        """
        now = datetime.datetime.utcnow().date()
        yesterday = now - datetime.timedelta(days=1)
        return [yesterday.year, yesterday.month, yesterday.day]

    @staticmethod
    def week_in_days_since_epoch(timestamp: Optional[int] = None) -> int:
        """
        Returns the day number of the beginning of this week, where day zero is
        the unix epoch at UTC timezone. So if we were one week in, this would return
        7. If a timestamp is provided, returns the same value from that reverence
        point instead of now.
        """
        if timestamp is None:
            date = datetime.datetime.utcnow().date()
        else:
            date = datetime.datetime.utcfromtimestamp(timestamp).date()
        week = date - datetime.timedelta(days=date.timetuple().tm_wday)
        return (week - datetime.date(1970, 1, 1)).days

    @staticmethod
    def days_into_year(timestamp: Optional[int] = None) -> List[int]:
        """
        Returns a [year, days] list representing the current year, and number
        of days into the current year. If a timestamp is provided, returns the
        same value from that reverence point instead of now.
        """
        if timestamp is None:
            date = datetime.datetime.utcnow().date().timetuple()
        else:
            date = datetime.datetime.utcfromtimestamp(timestamp).date().timetuple()
        return [date.tm_year, date.tm_yday]

    @staticmethod
    def days_into_week(timestamp: Optional[int] = None) -> int:
        """
        Returns an integer representing the number of days into the current week
        we are, with 0 = monday, 1 = tuesday, etc. If a timestamp is provided,
        returns the same value from that reverence point instead of now.
        """
        if timestamp is None:
            date = datetime.datetime.utcnow().date().timetuple()
        else:
            date = datetime.datetime.utcfromtimestamp(timestamp).date().timetuple()
        return date.tm_wday

    @staticmethod
    def timestamp_from_date(year: int, month: int = 1, day: int = 1) -> int:
        """
        Given a date (either a year, year/month, or year/month/day), returns
        the unix timestamp from UTC of that date. Supports out of bounds
        indexing on month.
        """
        while month < 1:
            year = year - 1
            month = month + 12
        while month > 12:
            year = year + 1
            month = month - 12

        date = datetime.datetime(year, month, day, tzinfo=tz.tzutc())
        return calendar.timegm(date.timetuple())

    @staticmethod
    def date_from_timestamp(timestamp: int) -> List[int]:
        """
        Returns a [year, month, day] given a UTC unix timestamp.
        """
        date = datetime.datetime.utcfromtimestamp(timestamp).date()
        return [date.year, date.month, date.day]

    @staticmethod
    def format(timestamp: int, formatstr: str) -> str:
        """
        Returns a unix timestamp based at UTC timezone formatted as a string.
        """
        return datetime.datetime.utcfromtimestamp(timestamp).strftime(formatstr)
