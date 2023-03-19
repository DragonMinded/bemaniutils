# vim: set fileencoding=utf-8
from typing import Any, Dict, Tuple

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.common import PopnMusicModernBase
from bemani.backend.popn.usaneko import PopnMusicUsaNeko
from bemani.common import VersionConstants


class PopnMusicPeace(PopnMusicModernBase):
    name: str = "Pop'n Music peace"
    version: int = VersionConstants.POPN_MUSIC_PEACE

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: int = 1877

    # Biggest deco part ID in the game
    GAME_MAX_DECO_ID: int = 133

    # Item limits are as follows:
    # 0: 1877 - ID is the music ID that the player purchased/unlocked.
    # 1: 2284
    # 2: 3
    # 3: 133 - ID points at a character part that can be purchased on the character screen.
    # 4: 1
    # 5: 1
    # 6: 60

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicUsaNeko(self.data, self.config, self.model)

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "ints": [
                {
                    "name": "Music Open Phase",
                    "tip": "Default music phase for all players.",
                    "category": "game_config",
                    "setting": "music_phase",
                    "values": {
                        # The value goes to 23 now, but it starts where usaneko left off at 11
                        # Unlocks a total of 53 songs
                        12: "No music unlocks",
                        13: "Phase 1",
                        14: "Phase 2",
                        15: "Phase 3",
                        16: "Phase 4",
                        17: "Phase 5",
                        18: "Phase 6",
                        19: "Phase 7",
                        20: "Phase 8",
                        21: "Phase 9",
                        22: "Phase 10",
                        23: "Phase MAX",
                    },
                },
                {
                    "name": "NAVI-Kun Event Phase",
                    "tip": "NAVI-Kun event phase for all players.",
                    "category": "game_config",
                    "setting": "navikun_phase",
                    "values": {
                        # The value goes to 30 now, but it starts where usaneko left off at 15
                        # Unlocks a total of 89 songs
                        15: "Phase 1",
                        16: "Phase 2",
                        17: "Phase 3",
                        18: "Phase 4",
                        19: "Phase 5",
                        20: "Phase 6",
                        21: "Phase 7",
                        22: "Phase 8",
                        23: "Phase 9",
                        24: "Phase 10",
                        25: "Phase 11",
                        26: "Phase 12",
                        27: "Phase 13",
                        28: "Phase 14",
                        29: "Phase 15",
                        30: "Phase MAX",
                    },
                },
                {
                    # For festive times, it's possible to change the welcome greeting.  I'm not sure why you would want to change this, but now you can.
                    "name": "Holiday Greeting",
                    "tip": "Changes the payment selection confirmation sound.",
                    "category": "game_config",
                    "setting": "holiday_greeting",
                    "values": {
                        0: "Okay!",
                        1: "Merry Christmas!",
                        2: "Happy New Year!",
                    },
                },
                {
                    # The following values control the pop'n music event archive. Setting the flag to the following values has the
                    # corresponding effect. Each value will include the events above it, for example setting it to 5 gives you the
                    # pop'n 15 event, as well as SP, 12, and 11 events.  Setting it to 0 disabled the event and skips the entire screen,
                    # setting it to 20 makes all of the events available for selection. Completing the minigame unlocks the associated content.
                    "name": "Event Archive Phase",
                    "tip": "Event Archive mini-game phase for all players.",
                    "category": "game_config",
                    "setting": "event_archive_phase",
                    "values": {
                        0: "Event Archive disabled",
                        1: "pop'n music 11 - The Latest Space Station",
                        2: "pop'n music 11 & 12 Iroha - The Southernmost Point of the Universe / Ninja Otasuke Cheat Sheet in Trouble",
                        3: "pop'n music Sunny Park - I Love Walking in Happiness Park",
                        4: "pop'n music 12 Iroha - Ninja Code: April 1st Volume",
                        5: "pop'n music 15 ADVENTURE - Route to Awaken the Soul",
                        6: "pop'n music 20 fantasia - A Braided Fantasy Song",
                        7: "EXTRA",
                        8: "pop'n music 15 ADVENTURE - A Route with a Faint Bell Sound",
                        9: "pop'n music 13 Carnival - Bunny Magician Attraction",
                        10: "pop'n music 14 FEVER! - That Burning Special Attack, again!",
                        11: "pop'n music Sunny Park - Festival Nightfall Park",
                        12: "pop'n music 20 fantasia - A Fantasy Song by the Bladed Warrior",
                        13: "pop'n music 19 TUNE STREET - A Town Where the Sound of the Brass Band Rings After School",
                        14: "pop'n music éclale - Fun Rag Hour",
                        15: "pop'n music 13 Carnival - Ghost Piano Attraction",
                        16: "pop'n music 14 FEVER! - That Warrior Defending Peace, again!",
                        17: "pop'n music 18 Sengoku Retsuden - A Territory with a Glamorous Cultural Flavor",
                        18: "pop'n music éclale - Runaway Guitarist in the Starry Sky",
                        19: "pop'n music 17 THE MOVIE - A Blockbuster Uncovering a Conspiracy in the Peaceful City",
                        20: "pop'n music lapistoria - God's Forgotten Things",
                    },
                },
            ],
            "bools": [
                # We don't currently support lobbies or anything, so this is commented out until
                # somebody gets around to implementing it.
                # {
                #     'name': 'Net Taisen',
                #     'tip': 'Enable Net Taisen, including win/loss display on song select',
                #     'category': 'game_config',
                #     'setting': 'enable_net_taisen',
                # },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
        }

    def get_common_config(self) -> Tuple[Dict[int, int], bool]:
        game_config = self.get_game_config()
        music_phase = game_config.get_int("music_phase")
        event_archive_phase = game_config.get_int("event_archive_phase")
        holiday_greeting = game_config.get_int("holiday_greeting")
        enable_net_taisen = False  # game_config.get_bool('enable_net_taisen')
        navikun_phase = game_config.get_int("navikun_phase")

        # Event phases
        return (
            {
                # Default song phase availability (0-23)
                # The following songs are unlocked when the phase is at or above the number specified:
                # 1  - 1589, 1590, 1591
                # 2  - 1594, 1595
                # 3  - 1596, 1597
                # 4  - 1593
                # 5  - 1602
                # 6  - 1604
                # 7  - 1629, 1630, 1631, 1633, 1641, 1642, 1643, 1644, 1645, 1646, 1647
                # 8  - 1632
                # 9  - 1651
                # 10 - 1679, 1680, 1681
                # 11 - 1669, 1670, 1669, 1670
                # 12 - Nothing gets unlocked here, the above values are identical to UsaNeko so presumably
                #      this is the new phase 0 for Peace.
                # 13 - 1728, 1730, 1731
                # 14 - 1729, 1732
                # 15 - 1763, 1764, 1765
                # 16 - 1785, 1786, 1787, 1788
                # 17 - 1820, 1822, 1826, 1827
                # 18 - 1817
                # 19 - 1821
                # 20 - 1819
                # 21 - 1818
                # 22 - 1825
                # 23 - 1858, 1857
                0: music_phase,
                # Unknown event (0-4)
                1: 4,
                # Holiday Greeting (0-2)
                2: holiday_greeting,
                # Unknown event (0-4)
                3: 4,
                # Unknown event (0-1)
                4: 1,
                # Enable Net Taisen, including win/loss display on song select (0-1)
                5: 1 if enable_net_taisen else 0,
                # Enable NAVI-kun shunkyoku toujou, allows song 1608 to be unlocked (0-1)
                6: 1,
                # Unknown event (0-1)
                7: 1,
                # Unknown event (0-2)
                8: 2,
                # Daily Mission (0-2)
                9: 2,
                # NAVI-kun Song phase availability (0-30)
                # The following songs are unlocked when the phase is at or above the number specified:
                # 1  - 1553
                # 2  - 1577, 1576, 1569
                # 3  - 1575, 1557
                # 4  - 1567
                # 5  - 1587, 1588, 1585
                # 6  - 1586
                # 7  - 1601, 1600, 1599
                # 8  - 1603
                # 9  - 1606, 1607, 1605
                # 10 - 1610, 1611, 1612
                # 11 - 1616, 1613, 1614, 1615
                # 12 - 1619, 1618, 1620, 1617
                # 13 - 1624, 1621, 1623, 1622
                # 14 - 1627, 1626, 1625
                # 15 - 1628
                # 16 - 1634, 1635, 1636, 1637, 1638
                # 17 - 1639, 1640
                # 18 - 1649, 1648, 1650
                # 19 - 1654, 1653, 1652
                # 20 - 1657, 1655, 1656
                # 21 - 1658, 1659, 1687, 1686
                # 22 - 1665, 1663, 1664
                # 23 - 1660, 1661, 1662, 1690, 1691
                # 24 - 1672, 1671
                # 25 - 1673, 1674, 1675
                # 26 - 1676, 1677, 1678
                # 27 - 1685, 1688, 1689
                # 28 - 1692, 1693, 1694
                # 29 - 1696, 1697, 1698, 1699, 1700, 1701, 1702
                # 30 - 1682, 1683, 1684
                10: navikun_phase,
                # Unknown event (0-1)
                11: 1,
                # Unknown event (0-2)
                12: 2,
                # Enable Pop'n Peace preview song (0-1)
                13: 1,
                # Stamp Card Rally (0-39)
                14: 39,
                # Unknown event (0-2)
                15: 2,
                # Unknown event (0-3)
                16: 3,
                # Unknown event (0-8)
                17: 8,
                # FLOOR INFECTION event (0-1)
                # The following songs are linked to this event:
                # 1 - 1223, 1224, 1225, 1239, 1240, 1241, 1245, 1247, 1340, 1342, 1394, 1523, 1524, 1525, 1598, 1667, 1668, 1666
                18: 1,
                # pop'n music × NOSTALGIA kyouenkai (0-1)
                # Setting this to 1 is linked to the song 1695
                19: 1,
                # Event archive event (0-13)
                # The following songs are unlocked when the phase is at or above the number specified:
                # 1  - 1745, 1744, 1743, 1746, 203, 214, 225, 226, 1749, 215, 591, 320, 1775, 449, 1768
                # 2  - 1759, 1760, 1761, 1762, 1748, 1754, 1755, 1756, 1757, 1758
                # 3  - 1737, 1776, 1777, 1780, 1783
                # 4  - 1725, 1726, 1751, 1750, 1753, 1752
                # 5  - 1703, 1724, 1747, 1738, 1733, 1739
                # 6  - 1722, 1723, 1740, 1735, 1734
                # 7  - 1766, 1769, 1771, 1770, 1736, 1741, 356, 1778, 1779, 284, 1742
                # 8  - 165, 171, 169, 1774, 1773, 118, 135, 1781, 105, 107, 1782
                # 9  - 113, 548, 436, 1792, 1791, 148, 125, 1832
                # 10 - 66, 74, 147, 79, 89, 1767, 49, 1772, 40, 1784, 16, 25, 1790, 1793
                # 11 - 1807, 1814, 1806, 1815, 1813
                # 12 - 1803, 1804, 1805
                # 13 - 1833, 1824
                20: 13,
                # Pop'n event archive song phase availability (0-20)
                21: event_archive_phase,
                # バンめし♪ ふるさとグランプリunlocks (split into two rounds) (0-2)
                # The following songs are linked to this event:
                # 1 - 1851, 1852, 1853, 1854
                # 2 - 1863, 1864, 1865, 1866
                22: 2,
                # いちかのBEMANI投票選抜戦2019 unlocks (0-1)
                # The following songs are linked to this event:
                # 1 - 1794, 1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802
                23: 1,
                # ダンキラ!!! × pop'n music unlocks (0-1)
                # The following songs are linked to this event:
                # 1 - 1845, 1846, 1847
                24: 1,
            },
            False,
        )
