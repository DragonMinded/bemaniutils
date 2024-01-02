# vim: set fileencoding=utf-8
import math
import random
from typing import Any, Dict, List, Tuple

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.common import PopnMusicModernBase
from bemani.backend.popn.peace import PopnMusicPeace
from bemani.common import VersionConstants
from bemani.common.validateddict import Profile
from bemani.data.types import UserID
from bemani.protocol.node import Node


class PopnMusicKaimei(PopnMusicModernBase):
    name: str = "Pop'n Music 解明リドルズ"
    version: int = VersionConstants.POPN_MUSIC_KAIMEI_RIDDLES

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: int = 2019

    # Biggest deco part ID in the game
    GAME_MAX_DECO_ID: int = 133

    # Item limits are as follows:
    # 0: 2019 - ID is the music ID that the player purchased/unlocked.
    # 1: 2344
    # 2: 3
    # 3: 133 - ID points at a character part that can be purchased on the character screen.
    # 4: 1
    # 5: 1
    # 6: 60

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicPeace(self.data, self.config, self.model)

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
                        # The value goes to 30 now, but it starts where usaneko left off at 23
                        # Unlocks a total of 10 songs
                        23: "No music unlocks",
                        24: "Phase 1",
                        25: "Phase 2",
                        26: "Phase 3",
                        27: "Phase 4",
                        28: "Phase 5",
                        29: "Phase 6",
                        30: "Phase MAX",
                    },
                },
                {
                    "name": "Kaimei! MN tanteisha event Phase",
                    "tip": "Kaimei! MN tanteisha event phase for all players.",
                    "category": "game_config",
                    "setting": "mn_tanteisha_phase",
                    "values": {
                        0: "Disabled",
                        1: "Roki",
                        2: "shiroro",
                        3: "PIERRE&JILL",
                        4: "ROSA",
                        5: "taoxiang",
                        6: "TangTang",
                        7: "OTOBEAR",
                        8: "kaorin",
                        9: "CHARLY",
                        10: "ALOE",
                        11: "RIE♥chan",
                        12: "hina",
                        13: "PAPYRUS",
                        14: "雷蔵, miho, RIE♥chan, Ryusei Honey",
                        15: "Murasaki",
                        16: "Lucifelle",
                        17: "六",
                        18: "stella",
                        19: "ちせ",
                        20: "LISA",
                        21: "SUMIRE",
                        22: "SHISHITUGU",
                        23: "WALKER",
                        24: "Candy",
                        25: "Jade",
                        26: "AYA",
                        27: "kaorin",
                        28: "Lord Meh",
                        29: "HAMANOV",
                        30: "Agent",
                        31: "Yima",
                        32: "ikkei",
                        33: "echidna",
                        34: "lithos",
                        35: "SMOKE",
                        36: "the KING",
                        37: "Kicoro",
                        38: "DEBORAH",
                        39: "Teruo",
                        40: "the TOWER",
                        41: "Mamoru-kun",
                        42: "Canopus",
                        43: "Mimi Nyami",
                        44: "iO-LOWER",
                        45: "BOY",
                        46: "Sergei",
                        47: "SAPPHIRE",
                        48: "Chocky",
                        49: "HAPPPY",
                        50: "SHOLLKEE",
                        51: "CHARA-O",
                        52: "Hugh, GRIM, SUMIKO",
                        53: "Peetan",
                        54: "SHARK",
                        55: "Nakajima-san",
                        56: "KIKYO",
                        57: "SUMIRE",
                        58: "NAKAJI",
                        59: "moi moi",
                        60: "TITICACA",
                        61: "MASAMUNE",
                        62: "YUMMY",
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
                    # peace soundtrack hatsubai kinen SP event, 0 = off, 1 = active, 2 = off (0-2)
                    "name": "peace soundtrack hatsubai kinen SP",
                    "tip": "peace soundtrack hatsubai kinen SP for all players.",
                    "category": "game_config",
                    "setting": "peace_soundtrack",
                    "values": {
                        0: "Not stated",
                        1: "Active",
                        2: "Ended",
                    },
                },
                {
                    "name": "MZD no kimagure tanteisha joshu",
                    "tip": "Boost increasing the Clarification Level, if four or more Requests still unresolved.",
                    "category": "game_config",
                    "setting": "tanteisha_joshu",
                    "values": {
                        0: "Not stated",
                        1: "Active",
                        2: "Ended",
                    },
                },
                {
                    # Shutchou! pop'n quest Lively II event
                    "name": "Shutchou! pop'n quest Lively phase",
                    "tip": "Shutchou! pop'n quest Lively phase for all players.",
                    "category": "game_config",
                    "setting": "popn_quest_lively",
                    "values": {
                        0: "Not started",
                        1: "fes 1",
                        2: "fes 2",
                        3: "fes FINAL",
                        4: "fes EXTRA",
                        5: "Ended",
                    },
                },
                {
                    # Shutchou! pop'n quest Lively II event
                    "name": "Shutchou! pop'n quest Lively II phase",
                    "tip": "Shutchou! pop'n quest Lively II phase for all players.",
                    "category": "game_config",
                    "setting": "popn_quest_lively_2",
                    "values": {
                        0: "Not started",
                        1: "fes 1",
                        2: "fes 2",
                        3: "fes FINAL",
                        4: "fes EXTRA",
                        5: "fes THE END",
                        6: "Ended",
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
        holiday_greeting = game_config.get_int("holiday_greeting")
        enable_net_taisen = False  # game_config.get_bool('enable_net_taisen')
        mn_tanteisha_phase = game_config.get_int("mn_tanteisha_phase")
        peace_soundtrack = game_config.get_int("peace_soundtrack")
        tanteisha_joshu = game_config.get_int("tanteisha_joshu")
        popn_quest_lively = game_config.get_int("popn_quest_lively")
        popn_quest_lively_2 = game_config.get_int("popn_quest_lively_2")

        # Event phases
        return (
            {
                # Default song phase availability (0-30)
                # The following songs are unlocked when the phase is at or above the number specified:
                # For 23 and before, see usaneko/peace
                # 24 - 1929, 1930
                # 25 - 1964
                # 26 - 1966, 1967
                # 27 - 1975
                # 28 - 1994
                # 29 - 1995, 1996
                # 30 - 1997
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
                10: 30,
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
                18: 1,
                # pop'n music × NOSTALGIA kyouenkai (0-1)
                19: 1,
                # Event archive event (0-13)
                20: 13,
                # Pop'n event archive song phase availability (0-20)
                21: 20,
                # バンめし♪ ふるさとグランプリunlocks (split into two rounds) (0-2)
                22: 2,
                # いちかのBEMANI投票選抜戦2019 unlocks (0-1)
                23: 1,
                # ダンキラ!!! × pop'n music unlocks (0-1)
                24: 1,
                # Kaimei riddles events starts here
                # Kaimei! MN tanteisha event Phase (0-62)
                # When active, the following songs are available for unlock
                # 1: 1914
                # 2: 195
                # 3: 1915
                # 4: 1916
                # 5: 1896
                # 6: 1908
                # 7: 1931
                # 8: 1924
                # 9: 1925
                # 10: 1894
                # 11: 1926
                # 12: 1927
                # 13: 1928
                # 14: 1932, 1933, 1934, 1935
                # 15: 521
                # 16: 1936
                # 17: 1943
                # 18: 1937
                # 19: 1938
                # 20: 1939
                # 21: 1943
                # 22: 1941
                # 23: 1942
                # 24: 323
                # 25: 1946
                # 26: 575
                # 27: 1947
                # 28: 1955
                # 29: 1957
                # 30: 1958
                # 31: 1959
                # 32: 1960
                # 33: 1961
                # 34: 1963
                # 35: 1962
                # 36: 1968
                # 37: 1969
                # 38: 1965
                # 39: 1970
                # 40: 1976
                # 41: 1977
                # 42: 1978
                # 43: 1945
                # 44: 1944
                # 45: 1999
                # 46: 2000
                # 47: 2001
                # 48: 2002
                # 49: 2003
                # 50: 2004
                # 51: 2005
                # 52: 267, 1998, 2006
                # 53: 2011
                # 54: 2007
                # 55: 2008
                # 56: 2009
                # 57: 2010
                # 58: 2016
                # 59: 2012
                # 60: 2018
                # 61: 2013
                # 62: 2015
                25: mn_tanteisha_phase,
                # Unknown event (0-3)
                26: 3,
                # peace soundtrack hatsubai kinen SP (0-2)
                # When active, the following songs are available for unlock: 1971, 1972, 1973
                27: peace_soundtrack,
                # MZD no kimagure tanteisha joshu (0-2)
                28: tanteisha_joshu,
                # Shutchou! pop'n quest Lively (0-5)
                # When active, the following songs are available for unlock
                # 1: 1917, 1918
                # 2: 1919, 1921
                # 3: 1920, 1922, 1923
                # 4: 1974
                29: popn_quest_lively,
                # Shutchou! pop'n quest Lively II (0-6)
                # When active, the following songs are available for unlock
                # 1: 1989, 1990, 1991
                # 2: 1984, 1985, 1992
                # 3: 1982, 1983, 1988
                # 4: 1986, 1987, 1993
                # 5: 2017
                30: popn_quest_lively_2,
            },
            False,
        )

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = super().format_profile(userid, profile)

        account = root.child("account")
        account.add_child(Node.s16("card_again_count", profile.get_int("card_again_count")))
        account.add_child(Node.s16("sp_riddles_id", profile.get_int("sp_riddles_id")))

        # Kaimei riddles events
        event2021 = Node.void("event2021")
        root.add_child(event2021)
        event2021.add_child(Node.u32("point", profile.get_int("point")))
        event2021.add_child(Node.u8("step", profile.get_int("step")))
        event2021.add_child(Node.u32_array("quest_point", profile.get_int_array("quest_point", 8, [0] * 8)))
        event2021.add_child(Node.u8("step_nos", profile.get_int("step_nos")))
        event2021.add_child(
            Node.u32_array(
                "quest_point_nos",
                profile.get_int_array("quest_point_nos", 13, [0] * 13),
            )
        )

        riddles_data = Node.void("riddles_data")
        root.add_child(riddles_data)

        # Generate Short Riddles for MN tanteisha
        randomRiddles: List[int] = []
        for _ in range(3):
            riddle = 0
            while True:
                riddle = math.floor(random.randrange(1, 21, 1))
                try:
                    randomRiddles.index(riddle)
                except ValueError:
                    break

            randomRiddles.append(riddle)

            sh_riddles = Node.void("sh_riddles")
            riddles_data.add_child(sh_riddles)
            sh_riddles.add_child(Node.u32("sh_riddles_id", riddle))

        # Set up kaimei riddles achievements
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
        for achievement in achievements:
            if achievement.type == "riddle":
                kaimei_gauge = achievement.data.get_int("kaimei_gauge")
                is_cleared = achievement.data.get_bool("is_cleared")
                riddles_cleared = achievement.data.get_bool("riddles_cleared")
                select_count = achievement.data.get_int("select_count")
                other_count = achievement.data.get_int("other_count")

                sp_riddles = Node.void("sp_riddles")
                riddles_data.add_child(sp_riddles)
                sp_riddles.add_child(Node.u16("kaimei_gauge", kaimei_gauge))
                sp_riddles.add_child(Node.bool("is_cleared", is_cleared))
                sp_riddles.add_child(Node.bool("riddles_cleared", riddles_cleared))
                sp_riddles.add_child(Node.u8("select_count", select_count))
                sp_riddles.add_child(Node.u32("other_count", other_count))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = super().unformat_profile(userid, request, oldprofile)

        account = request.child("account")
        if account is not None:
            newprofile.replace_int("card_again_count", account.child_value("card_again_count"))
            newprofile.replace_int("sp_riddles_id", account.child_value("sp_riddles_id"))

        # Kaimei riddles events
        event2021 = request.child("event2021")
        if event2021 is not None:
            newprofile.replace_int("point", event2021.child_value("point"))
            newprofile.replace_int("step", event2021.child_value("step"))
            newprofile.replace_int_array("quest_point", 8, event2021.child_value("quest_point"))
            newprofile.replace_int("step_nos", event2021.child_value("step_nos"))
            newprofile.replace_int_array("quest_point_nos", 13, event2021.child_value("quest_point_nos"))

        # Extract kaimei riddles achievements
        for node in request.children:
            if node.name == "riddles_data":
                riddle_id = 0
                playedRiddle = request.child("account").child_value("sp_riddles_id")
                for riddle in node.children:
                    kaimei_gauge = riddle.child_value("kaimei_gauge")
                    is_cleared = riddle.child_value("is_cleared")
                    riddles_cleared = riddle.child_value("riddles_cleared")
                    select_count = riddle.child_value("select_count")
                    other_count = riddle.child_value("other_count")

                    if riddles_cleared or select_count >= 3:
                        select_count = 3
                    elif playedRiddle == riddle_id:
                        select_count += 1

                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        riddle_id,
                        "riddle",
                        {
                            "kaimei_gauge": kaimei_gauge,
                            "is_cleared": is_cleared,
                            "riddles_cleared": riddles_cleared,
                            "select_count": select_count,
                            "other_count": other_count,
                        },
                    )

                    riddle_id += 1

        return newprofile
