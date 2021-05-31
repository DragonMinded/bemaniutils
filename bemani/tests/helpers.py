# vim: set fileencoding=utf-8
import os
import sys
import unittest
from typing import Container, List, Dict, Any


# Supress custom handler tracebacks inside handler frames
__unittest = True


class ExtendedTestCase(unittest.TestCase):
    @property
    def verbose(self) -> bool:
        return ("-v" in sys.argv) or ("--verbose" in sys.argv)

    def assertItemsEqual(self, a: Container[Any], b: Container[Any]) -> None:
        a_items = {x for x in a}
        b_items = {x for x in b}
        self.assertEqual(a_items, b_items)


class FakeCursor():

    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.__rows = rows
        self.rowcount = len(rows)

    def fetchone(self) -> Dict[str, Any]:
        if len(self.__rows) != 1:
            raise Exception(f'Tried to fetch one row and there are {len(self.__rows)} rows!')
        return self.__rows[0]

    def fetchall(self) -> List[Dict[str, Any]]:
        return self.__rows


def get_fixture(name: str) -> bytes:
    location = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(location, name), "rb") as fp:
        return fp.read()
