# vim: set fileencoding=utf-8
import unittest

from bemani.common import ID


class TestID(unittest.TestCase):
    def test_format_extid(self) -> None:
        self.assertEqual(ID.format_extid(12345678), "1234-5678")
        self.assertEqual(ID.parse_extid("1234-5678"), 12345678)
        self.assertEqual(ID.parse_extid("bla"), None)
        self.assertEqual(ID.parse_extid("blah-blah"), None)

    def test_format_machine_id(self) -> None:
        self.assertEqual(ID.format_machine_id(123), "US-123")
        self.assertEqual(ID.parse_machine_id("US-123"), 123)
        self.assertEqual(ID.parse_machine_id("bla"), None)
        self.assertEqual(ID.parse_machine_id("US-blah"), None)
