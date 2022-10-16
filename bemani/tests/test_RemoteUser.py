# vim: set fileencoding=utf-8
import unittest

from bemani.data.remoteuser import RemoteUser
from bemani.data.types import UserID


class TestRemoteUser(unittest.TestCase):
    def test_id_mangling(self) -> None:
        card = "E0040100DEADBEEF"
        userid = RemoteUser.card_to_userid(card)
        self.assertTrue(userid > (2**32 - 1))
        newcard = RemoteUser.userid_to_card(userid)
        self.assertEqual(card, newcard)

    def test_is_remote(self) -> None:
        self.assertTrue(RemoteUser.is_remote(UserID(2**64 - 1)))
        self.assertTrue(RemoteUser.is_remote(UserID(2**32)))
        self.assertFalse(RemoteUser.is_remote(UserID(2**32 - 1)))
        self.assertFalse(RemoteUser.is_remote(UserID(0)))
        self.assertFalse(RemoteUser.is_remote(UserID(1)))
