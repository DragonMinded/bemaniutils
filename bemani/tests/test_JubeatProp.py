# vim: set fileencoding=utf-8
import unittest
from unittest.mock import Mock

from bemani.backend.jubeat.prop import JubeatProp
from bemani.common import Profile
from bemani.data.types import Achievement, UserID


class TestJubeatProp(unittest.TestCase):
    def test_increment_class(self) -> None:
        # Verify normal increase
        self.assertEqual(JubeatProp._increment_class(1, 5), (1, 4))
        self.assertEqual(JubeatProp._increment_class(1, 4), (1, 3))
        self.assertEqual(JubeatProp._increment_class(3, 3), (3, 2))

        # Verify bumping class when minor class is at max
        self.assertEqual(JubeatProp._increment_class(1, 1), (2, 5))
        self.assertEqual(JubeatProp._increment_class(2, 1), (3, 5))

        # Verify bumping class to legend which only has one subclass
        self.assertEqual(JubeatProp._increment_class(3, 1), (4, 1))

        # Verify bumping when already at max
        self.assertEqual(JubeatProp._increment_class(4, 1), (4, 1))

    def test_decrement_class(self) -> None:
        # Verify normal decrease
        self.assertEqual(JubeatProp._decrement_class(1, 3), (1, 4))
        self.assertEqual(JubeatProp._decrement_class(1, 4), (1, 5))
        self.assertEqual(JubeatProp._decrement_class(3, 2), (3, 3))

        # Verify demoting class when minor class is at min
        self.assertEqual(JubeatProp._decrement_class(2, 5), (1, 1))
        self.assertEqual(JubeatProp._decrement_class(3, 5), (2, 1))

        # Verify demoting class when starting at legend
        self.assertEqual(JubeatProp._decrement_class(4, 1), (3, 1))

        # Verify decrease when already at min
        self.assertEqual(JubeatProp._decrement_class(1, 5), (1, 5))

    def test_get_league_buckets(self) -> None:
        # Verify correct behavior with empty input
        self.assertEqual(
            JubeatProp._get_league_buckets(
                [],
            ),
            (
                [],
                [],
                [],
            ),
        )

        # Verify correct behavior with only one entrant (should be promoted)
        self.assertEqual(
            JubeatProp._get_league_buckets(
                [
                    (UserID(5), 12345),
                ],
            ),
            (
                [
                    UserID(5),
                ],
                [],
                [],
            ),
        )

        # Verify correct behavior with two entrants (should be one promotion, one demotion)
        self.assertEqual(
            JubeatProp._get_league_buckets(
                [
                    (UserID(5), 12345),
                    (UserID(7), 54321),
                ],
            ),
            (
                [
                    UserID(7),
                ],
                [],
                [
                    UserID(5),
                ],
            ),
        )

        # Verify correct behavior with three entrants (should be one promotion, one demotion, one same)
        self.assertEqual(
            JubeatProp._get_league_buckets(
                [
                    (UserID(5), 12345),
                    (UserID(7), 54321),
                    (UserID(9), 33333),
                ],
            ),
            (
                [
                    UserID(7),
                ],
                [
                    UserID(9),
                ],
                [
                    UserID(5),
                ],
            ),
        )

        # Verify correct behavior with ten entrants (should be 3 promotions, 3 demotions, 4 same)
        self.assertEqual(
            JubeatProp._get_league_buckets(
                [
                    (UserID(5), 55555),
                    (UserID(7), 77777),
                    (UserID(9), 99999),
                    (UserID(1), 11111),
                    (UserID(6), 66666),
                    (UserID(8), 88888),
                    (UserID(2), 22222),
                    (UserID(3), 33333),
                    (UserID(10), 100000),
                    (UserID(4), 44444),
                ],
            ),
            (
                [
                    UserID(10),
                    UserID(9),
                    UserID(8),
                ],
                [
                    UserID(7),
                    UserID(6),
                    UserID(5),
                    UserID(4),
                ],
                [
                    UserID(3),
                    UserID(2),
                    UserID(1),
                ],
            ),
        )

    def test_get_league_scores(self) -> None:
        data = Mock()
        data.local = Mock()
        data.local.user = Mock()

        # Test correct behavior on empty input
        self.assertEqual(
            JubeatProp._get_league_scores(None, 999, []),
            (
                [],
                [],
            ),
        )

        # Test that we can load last week's score if it exists for a user
        data.local.user.get_achievement = Mock(return_value={"score": [123, 456, 789]})
        self.assertEqual(
            JubeatProp._get_league_scores(
                data,
                999,
                [(UserID(1337), Profile(JubeatProp.game, JubeatProp.version, "", 0))],
            ),
            (
                [(1337, 1368)],
                [],
            ),
        )
        data.local.user.get_achievement.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            1337,
            998,
            "league",
        )
        data.local.user.get_achievement.reset_mock()

        # Test that if it doesn't exist last week they get marked as absent
        data.local.user.get_achievement = Mock(return_value=None)
        self.assertEqual(
            JubeatProp._get_league_scores(
                data,
                999,
                [(UserID(1337), Profile(JubeatProp.game, JubeatProp.version, "", 0))],
            ),
            (
                [],
                [1337],
            ),
        )
        data.local.user.get_achievement.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            1337,
            998,
            "league",
        )
        data.local.user.get_achievement.reset_mock()

    def test_get_league_absentees(self) -> None:
        data = Mock()
        data.local = Mock()
        data.local.user = Mock()

        # Test that we do the right thing with empty input
        self.assertEqual(
            JubeatProp._get_league_absentees(
                None,
                999,
                [],
            ),
            [],
        )

        # Test that a user who never played doesn't get flagged absentee
        data.local.user.get_achievements = Mock(return_value=[])
        self.assertEqual(
            JubeatProp._get_league_absentees(
                data,
                999,
                [UserID(1337)],
            ),
            [],
        )
        data.local.user.get_achievements.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
        )
        data.local.user.get_achievements.reset_mock()

        # Test that a user who only skipped last week doesn't get flagged absentee
        data.local.user.get_achievements = Mock(
            return_value=[
                Achievement(997, "league", None, {}),
            ]
        )
        self.assertEqual(
            JubeatProp._get_league_absentees(
                data,
                999,
                [UserID(1337)],
            ),
            [],
        )
        data.local.user.get_achievements.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
        )
        data.local.user.get_achievements.reset_mock()

        # Test that a user who skipped last two week gets flagged absentee
        data.local.user.get_achievements = Mock(
            return_value=[
                Achievement(996, "league", None, {}),
            ]
        )
        self.assertEqual(
            JubeatProp._get_league_absentees(
                data,
                999,
                [UserID(1337)],
            ),
            [UserID(1337)],
        )
        data.local.user.get_achievements.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
        )
        data.local.user.get_achievements.reset_mock()

        # Test that a user who skipped last three week doesn't get flagged
        # (they got flagged last week)
        data.local.user.get_achievements = Mock(
            return_value=[
                Achievement(995, "league", None, {}),
            ]
        )
        self.assertEqual(
            JubeatProp._get_league_absentees(
                data,
                999,
                [UserID(1337)],
            ),
            [],
        )
        data.local.user.get_achievements.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
        )
        data.local.user.get_achievements.reset_mock()

        # Test that a user who skipped last four week gets flagged absentee
        data.local.user.get_achievements = Mock(
            return_value=[
                Achievement(994, "league", None, {}),
            ]
        )
        self.assertEqual(
            JubeatProp._get_league_absentees(
                data,
                999,
                [UserID(1337)],
            ),
            [UserID(1337)],
        )
        data.local.user.get_achievements.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
        )
        data.local.user.get_achievements.reset_mock()

    def test_modify_profile(self) -> None:
        data = Mock()
        data.local = Mock()
        data.local.user = Mock()

        # Test demoting a user at the bottom does nothing.
        data.local.user.get_profile = Mock(
            return_value=Profile(
                JubeatProp.game,
                JubeatProp.version,
                "",
                0,
                {
                    "league_class": 1,
                    "league_subclass": 5,
                },
            )
        )
        JubeatProp._modify_profile(
            data,
            UserID(1337),
            "demote",
        )
        self.assertFalse(data.local.user.put_profile.called)

        # Test promoting a user at the top does nothing.
        data.local.user.get_profile = Mock(
            return_value=Profile(
                JubeatProp.game,
                JubeatProp.version,
                "",
                0,
                {
                    "league_class": 4,
                    "league_subclass": 1,
                },
            )
        )
        JubeatProp._modify_profile(
            data,
            UserID(1337),
            "promote",
        )
        self.assertFalse(data.local.user.put_profile.called)

        # Test regular promotion updates profile properly
        data.local.user.get_profile = Mock(
            return_value=Profile(
                JubeatProp.game,
                JubeatProp.version,
                "",
                0,
                {
                    "league_class": 1,
                    "league_subclass": 5,
                    "league_is_checked": True,
                },
            )
        )
        JubeatProp._modify_profile(
            data,
            UserID(1337),
            "promote",
        )
        data.local.user.put_profile.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
            {
                "league_class": 1,
                "league_subclass": 4,
                "league_is_checked": False,
                "last": {
                    "league_class": 1,
                    "league_subclass": 5,
                },
            },
        )
        data.local.user.put_profile.reset_mock()

        # Test regular demote updates profile properly
        data.local.user.get_profile = Mock(
            return_value=Profile(
                JubeatProp.game,
                JubeatProp.version,
                "",
                0,
                {
                    "league_class": 1,
                    "league_subclass": 3,
                    "league_is_checked": True,
                },
            )
        )
        JubeatProp._modify_profile(
            data,
            UserID(1337),
            "demote",
        )
        data.local.user.put_profile.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
            {
                "league_class": 1,
                "league_subclass": 4,
                "league_is_checked": False,
                "last": {
                    "league_class": 1,
                    "league_subclass": 3,
                },
            },
        )
        data.local.user.put_profile.reset_mock()

        # Test demotion after not checking doesn't update old values
        data.local.user.get_profile = Mock(
            return_value=Profile(
                JubeatProp.game,
                JubeatProp.version,
                "",
                0,
                {
                    "league_class": 1,
                    "league_subclass": 4,
                    "league_is_checked": False,
                    "last": {
                        "league_class": 1,
                        "league_subclass": 3,
                    },
                },
            )
        )
        JubeatProp._modify_profile(
            data,
            UserID(1337),
            "demote",
        )
        data.local.user.put_profile.assert_called_once_with(
            JubeatProp.game,
            JubeatProp.version,
            UserID(1337),
            {
                "league_class": 1,
                "league_subclass": 5,
                "league_is_checked": False,
                "last": {
                    "league_class": 1,
                    "league_subclass": 3,
                },
            },
        )
        data.local.user.put_profile.reset_mock()
