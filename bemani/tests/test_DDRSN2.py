import unittest
from typing import Dict, Any
from unittest.mock import Mock, MagicMock

from bemani.backend.ddr.ddrsn2 import PlayerInfo
from bemani.common import Profile, GameConstants, VersionConstants


class TestDDRSN2(unittest.TestCase):
    def create_profile(self, initial_values: Dict[str, Any] = {}) -> Profile:
        return Profile(GameConstants.DDR, VersionConstants.DDR_SUPERNOVA_2, "unittest", 0, initial_values)

    def test_new_profile_creates_default_options(self) -> None:
        player_info = PlayerInfo.create(MagicMock(), self.create_profile(), 0, MagicMock())

        options = player_info.options

        self.assertEqual(options[0], 2, "Default value for first option is 2")
        self.assertEqual(options[1], 0, "Default value for first option is 0")
        self.assertEqual(options[2], 0, "Default value for first option is 0")
        self.assertEqual(options[3], 0, "Default value for first option is 0")
        self.assertEqual(options[4], 0, "Default value for first option is 0")
        self.assertEqual(options[5], 0, "Default value for first option is 0")
        self.assertEqual(options[6], 0, "Default value for first option is 0")
        self.assertEqual(options[7], 0, "Default value for first option is 0")
        self.assertEqual(options[8], 1, "Default value for first option is 1")
        self.assertEqual(options[9], 1, "Default value for first option is 1")
        self.assertEqual(options[10], 0, "Default value for first option is 0")
        self.assertEqual(options[11], 2, "Default value for first option is 2")
        self.assertEqual(options[12], 0, "Default value for first option is 0")
        self.assertEqual(options[13], 0, "Default value for first option is 0")
        self.assertEqual(options[14], 0, "Default value for first option is 0")
        self.assertEqual(options[15], 0, "Default value for first option is 0")

    def test_existing_profile_maintains_default_options(self) -> None:
        player_info = PlayerInfo.create(MagicMock(), self.create_profile({"opt": [1 for i in range(16)]}), 0, MagicMock())

        options = player_info.options
        # Only 16 options loaded from profile. Other options either unused or set on eamuse?
        for opt in range(16):
            self.assertEqual(options[opt], 1, "Expected option to be 1")

