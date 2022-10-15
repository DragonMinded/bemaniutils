# vim: set fileencoding=utf-8
import unittest
from unittest.mock import Mock

from bemani.data.mysql.base import BaseData


class TestBaseData(unittest.TestCase):
    def test_basic_serialize(self) -> None:
        data = BaseData(Mock(), None)

        testdict = {
            "test1": 1,
            "test2": "2",
            "test3": 3.3,
            "test4": [1, 2, 3, 4],
            "test5": {
                "a": "b",
            },
            "testempty": [],
        }

        self.assertEqual(data.deserialize(data.serialize(testdict)), testdict)

    def test_basic_byte_serialize(self) -> None:
        data = BaseData(Mock(), None)

        testdict = {
            "bytes": b"\x01\x02\x03\x04\x05",
        }

        serialized = data.serialize(testdict)
        self.assertEqual(serialized, '{"bytes": ["__bytes__", 1, 2, 3, 4, 5]}')
        self.assertEqual(data.deserialize(serialized), testdict)

    def test_deep_byte_serialize(self) -> None:
        data = BaseData(Mock(), None)

        testdict = {
            "sentinal": True,
            "test": {
                "sentinal": False,
                "bytes": b"\x01\x02\x03\x04\x05",
                "bytes2": b"",
            },
        }

        self.assertEqual(data.deserialize(data.serialize(testdict)), testdict)
