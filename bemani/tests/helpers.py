# vim: set fileencoding=utf-8
import os
import sys
import unittest
from typing import Iterable, List, Dict, Any


# Supress custom handler tracebacks inside handler frames
__unittest = True


class ExtendedTestCase(unittest.TestCase):
    @property
    def verbose(self) -> bool:
        return ("-v" in sys.argv) or ("--verbose" in sys.argv)

    def assertItemsEqual(self, a: Iterable[Any], b: Iterable[Any]) -> None:
        a_items = {x for x in a}
        b_items = {x for x in b}
        self.assertEqual(a_items, b_items)


class FakeCursor:
    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.__rows = rows
        self.rowcount = len(rows)
        self.pos = -1

    def fetchone(self) -> Dict[str, Any]:
        if len(self.__rows) != 1:
            raise Exception(f"Tried to fetch one row and there are {len(self.__rows)} rows!")
        return self.__rows[0]

    def __iter__(self) -> "FakeCursor":
        self.pos = -1
        return self

    def __next__(self) -> Dict[str, Any]:
        self.pos += 1
        if self.pos < self.rowcount:
            return self.__rows[self.pos]
        else:
            raise StopIteration


def get_fixture(name: str) -> bytes:
    location = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(location, name), "rb") as fp:
        return fp.read()
