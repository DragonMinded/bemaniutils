# vim: set fileencoding=utf-8
import unittest

from bemani.data.api.client import APIClient


class TestAPIClient(unittest.TestCase):
    def test_content_type(self) -> None:
        client = APIClient("https://127.0.0.1", "token", False, False)
        self.assertFalse(client._content_type_valid("application/text"))
        self.assertFalse(client._content_type_valid("application/json"))
        self.assertFalse(
            client._content_type_valid("application/json; charset=shift-jis")
        )
        self.assertTrue(client._content_type_valid("application/json; charset=utf-8"))
        self.assertTrue(client._content_type_valid("application/json;charset=utf-8"))
        self.assertTrue(client._content_type_valid("application/json;charset = utf-8"))
        self.assertTrue(client._content_type_valid("application/json; charset = utf-8"))
        self.assertTrue(client._content_type_valid("application/json; charset=UTF-8"))
        self.assertTrue(client._content_type_valid("application/json;charset=UTF-8"))
        self.assertTrue(client._content_type_valid("application/json;charset = UTF-8"))
        self.assertTrue(client._content_type_valid("application/json; charset = UTF-8"))
