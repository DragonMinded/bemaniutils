# vim: set fileencoding=utf-8
import math
import random
from typing import Any, Dict, List, Tuple

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.common import PopnMusicModernBase
from bemani.backend.popn.kaimei import PopnMusicKaimei
from bemani.common import VersionConstants
from bemani.common.validateddict import Profile
from bemani.data.types import UserID
from bemani.protocol.node import Node


class PopnMusicUnilab(PopnMusicModernBase):
    name: str = "Pop'n Music Unilab"
    version: int = VersionConstants.POPN_MUSIC_UNILAB

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: int = 2188

    # Biggest deco part ID in the game
    GAME_MAX_DECO_ID: int = 81

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicKaimei(self.data, self.config, self.model)

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
                        0: "No music unlocks",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase 3",
                        4: "Phase 4",
                        5: "Phase 5",
                        6: "Phase MAX",
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
                {
                    "name": "Narunaru♪ UniLab jikkenshitsu! event Phase",
                    "tip": "Narunaru♪ UniLab jikkenshitsu! event Phase for all players.",
                    "category": "game_config",
                    "setting": "narunaru_phase",
                    "values": {
                        0: "Disabled",
                        1: "ラブケミ / 悪夢♡ショコラティエ",
                        2: "001 -どうしんのかいろ-",
                        3: "MA・TSU・RI / MOVE! (We Keep It Movin')",
                        4: "斑咲花 / ユメブキ",
                        5: "ホムンクルスレシピ",
                        6: "脳ミソ de 向上",
                        7: "Awakening Wings",
                        8: "カタルシスの月 (UPPER) / ちくわパフェだよ☆CKP (UPPER) / ホーンテッド★メイドランチ (UPPER)",
                        9: "HAGURUMA / ノープラン・デイズ / Sweet Illusion",
                        10: "左脳スパーク (UPPER)",
                        11: "東京メモリー",
                        12: "にゃんのパレードマーチ♪",
                        13: "明滅の果てに",
                        14: "Shout It Out",
                        15: "グランデーロの守り",
                        16: "恋するMonstro",
                        17: "Versa (UPPER)",
                        18: "Xジェネの逆襲",
                        19: "Engraved on my heart ft. 小林マナ",
                        20: "fallen leaves -IIDX edition-",
                        21: "Τέλος",
                        22: "Candy Crime Toe Shoes",
                        23: "High Speed Junkie!",
                        24: "Pure Rude",
                        25: "地方創生☆チクワクティクス (UPPER) / 乙女繚乱 舞い咲き誇れ (UPPER)",
                        26: "pastel@sweets labo(*'v'*) / 恋はどう？モロ◎波動OK☆方程式！！ (UPPER) / Mecha Kawa Breaker!!",
                        27: "あまるがむ",
                        28: "勇猛無比",
                        29: "Unknown Region",
                        30: "unisonote",
                        31: "灰の羽搏",
                        32: "情熱タンデムRUNAWAY",
                        33: "Satan",
                        34: "粋 -IKI-",
                        35: "Treasure Hoard (UPPER)",
                        36: "SOLID STATE SQUAD -RISEN RELIC REMIX-",
                        37: "夏色のセーブデータ",
                        38: "革命パッショネイト (UPPER) / めうめうぺったんたん！！ (UPPER)",
                        39: "Gabbalungang",
                        40: "Caldwell 99",
                        41: "葬送のエウロパ / ただ、それだけの理由で",
                        42: "ISERBROOK",
                        43: "Amulet of Enbarr",
                        44: "Sword of Vengeance",
                        45: "Caldwell 99",
                        46: "満漢全席火花ノ舞",
                        47: "mathematical good-bye → Hexer → F/S",
                        48: "Ended",
                    },
                },
                {
                    # Kakusei no Elem event Phase
                    "name": "Kakusei no Elem event Phase",
                    "tip": "Kakusei no Elem event Phase for all players.",
                    "category": "game_config",
                    "setting": "kakusei_phase",
                    "values": {
                        0: "Disabled",
                        1: "Tan♪Tan♪Tan♪",
                        2: "Keep the Faith",
                        3: "Lovin' You",
                        4: "Redemption Tears",
                        5: "Dancin' in シャングリラ",
                        6: "ココロコースター",
                        7: "ma plume / ma plume (UPPER)",
                        8: "いばら姫",
                        9: "螺旋",
                        10: "めうめうぺったんたん！！ (ZAQUVA Remix) / ちくわパフェだよ☆ＣＫＰ (Yvya Remix)",
                        11: "狼弦暴威",
                        12: "The Escape",
                        13: "謎情の雫 ft. Kanae Asaba",
                        14: "黒猫と珈琲",
                        15: "Head Scratcher",
                        16: "ドーナツホール (UPPER) / マトリョシカ (UPPER)",
                        17: "遊戯大熊猫",
                        18: "Stylus",
                        19: "Crazy Shuffle",
                        20: "speedstar[02]",
                        21: "少年A",
                        22: "what I wish",
                        23: "TAKE YOU AWAY",
                        24: "Dragon Blade -The Arrange-",
                        25: "Pump up dA CORE",
                        26: "TURBO BOOSTER",
                        27: "夜虹",
                        28: "天泣 ",
                        29: "オッタマゲッター",
                        30: "luck (UPPER) / 脳漿炸裂ガール (UPPER)",
                        31: "TYPHØN",
                        32: "REFLEXED MANIPULATION",
                        33: "オーバー ",
                        34: "Knockin' On Red Button",
                        35: "The Metalist",
                        36: "イマココ!この瞬間 ",
                        37: "チョコレートスマイル (UPPER)",
                        38: "キリステゴメン (UPPER)",
                        39: "Liar×Girl / Hades Doll",
                        40: "Jazz is Rad / アモ",
                        41: "encounter / 不可説不可説転",
                        42: "弾幕信仰 / 閉塞的フレーション / 残像ニ繋ガレタ追憶ノHIDEAWAY",
                        43: "ROBOROS OVERDIVE / Megalara Garuda",
                        44: "Megalara Garuda (UPPER)",
                    },
                },
                {
                    # Awakening Boost
                    "name": "Super Unilab BOOST!",
                    "tip": "Super Unilab BOOST! for all players.",
                    "category": "game_config",
                    "setting": "super_unilab_boost",
                    "values": {
                        0: "Disabled",
                        1: "Active",
                        2: "Ended",
                    },
                },
                {
                    # CanCan's Super Awakening Boost
                    "name": "CanCan's Super Awakening Boost",
                    "tip": "CanCan's Super Awakening Boost for all players.",
                    "category": "game_config",
                    "setting": "cancan_boost",
                    "values": {
                        0: "Disabled",
                        1: "Active",
                        2: "Ended",
                    },
                },
                {
                    # KAC 2023
                    "name": "KAC Lab Phase",
                    "tip": "KAC Lab for all players",
                    "category": "game_config",
                    "setting": "kac_2023",
                    "values": {
                        0: "Not Started",
                        1: "Caldwell 99 (KAC Woman/Free Set A)",
                        3: "Hexer / mathematical good-bye (KAC Woman/Free Set B)",
                        4: "Ended",
                    },
                },
                # We don't currently support lobbies or anything, so this is commented out until
                # somebody gets around to implementing it.
                # {
                #    # Net Taisen and local mode
                #    "name": "Net Taisen / Local Mode",
                #    "tip": "Enable Net Taisen and Local Mode",
                #    "category": "game_config",
                #    "setting": "enable_net_taisen_local_mode",
                #    "values": {
                #        0: "Disabled",
                #        1: "Net Taisen",
                #        2: "Net Taisen / Local Mode",
                #    },
                # },
            ],
            "bools": [
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
                {
                    "name": "Force Deco Unlock",
                    "tip": "Force unlock all Deco parts.",
                    "category": "game_config",
                    "setting": "force_unlock_deco",
                },
                {
                    "name": "Unlock KAC Qualifier (パーフェクトイーター)",
                    "tip": "Force unlock Perfect Eater for all players.",
                    "category": "game_config",
                    "setting": "force_unlock_perfect_eater",
                },
                {
                    # Overly complicated event where you'd play songs from other games to unlock them in other games.
                    # Unlocks the following songs after one play when set:
                    # 2045 - 鴉
                    # 2046 - 蒼氷のフラグメント
                    # 2047 - Indigo Nocturne
                    # 2048 - 輪廻の鴉
                    # 2049 - VOLAQUAS
                    "name": "Unlock いちかのごちゃまぜMix UP！ Songs",
                    "tip": "Force unlock Ichika no Gochamaze Mix UP! songs for all players.",
                    "category": "game_config",
                    "setting": "force_unlock_ichika",
                },
            ],
        }

    def get_common_config(self) -> Tuple[Dict[int, int], bool]:
        game_config = self.get_game_config()
        music_phase = game_config.get_int("music_phase")
        narunaru_phase = game_config.get_int("narunaru_phase")
        enable_net_taisen = False  # game_config.get_bool('enable_net_taisen')
        super_unilab_boost = game_config.get_int("super_unilab_boost")
        cancan_boost = game_config.get_int("cancan_boost")
        kakusei_phase = game_config.get_int("kakusei_phase")
        popn_quest_lively_2 = game_config.get_int("popn_quest_lively_2")
        kac_2023 = game_config.get_int("kac_2023")
        # Enable event and mark complete
        if game_config.get_bool("force_unlock_deco"):
            kakusei_phase = 1

        # Event phases
        return (
            {
                # Default song phase availability (0-6)
                # 1 - 2071 - Hopes and Dreams/夢と希望
                #     2072 - MEGALOVANIA
                #     2073 - Battle Against a True Hero/本物のヒーローとの戦い
                # 2 - 2146 - ポラリスノウタ
                # 3 - 2149 - 第ゼロ感
                # 4 - 2150 - 強風オールバック
                #     2151 - 恋愛パクチー
                # 5 - 2172 - レイドバックジャーニー
                # 6 - 2188 - Super Heroine
                0: music_phase,
                # Shutchou! pop'n quest Lively II (0-6)
                # When active, the following songs are available for unlock
                # 1 - 1989 - Ketter
                #     1990 - Petit Queen
                #     1991 - 波と凪の挟間で
                # 2 - 1984 - コルドバの女
                #     1985 - say...but in vain
                #     1992 - Northern Cross
                # 3 - 1982 - Surf on the Light
                #     1983 - バッドエンド・シンドローム
                #     1988 - Danza Pantera
                # 4 - 1986 - virkatoの主題によるperson09風超絶技巧変奏曲
                #     1987 - 水晶塔のオルカ
                #     1993 - Un Happy Heart
                # 5 - 2017 - virkatoの主題によるperson09風超絶技巧変奏曲 upper
                # 6 - Event Ended
                1: popn_quest_lively_2,
                # KAC 2023 (0-4) - Please see the site below for what songs are in set A and set B
                # https://bemaniwiki.com/?%B8%F8%BC%B0%C2%E7%B2%F1/KONAMI+Arcade+Championship%282023%29/%CD%BD%C1%AA%A5%E9%A5%A6%A5%F3%A5%C9#popn
                # 0 - Disabled
                # 1 - Caldwell 99 (KAC Woman/Free Set A)
                # 2 - Disabled
                # 3 - Hexer / mathematical good-bye (KAC Woman/Free Set B)
                # 4 - Disabled
                2: kac_2023,
                # Enable Net Taisen, including win/loss display on song select (0-2)
                # 0 - Disable
                # 1 - Net taisen
                # 2 - Net taisen + Local mode
                3: 1 if enable_net_taisen else 0,
                # Unknown event (0-7)
                4: 7,
                # Narunaru♪ UniLab jikkenshitsu! (0-48)
                # 6500 clear points are needed unless otherwise specified
                #  1 - 2040 - ラブケミ - 1000 points
                #      2043 - 悪夢♡ショコラティエ
                #  2 - 2044 - 001 -どうしんのかいろ-
                #  3 - 2050 - MA・TSU・RI
                #      2051 - MOVE! (We Keep It Movin')
                #  4 - 2052 - 斑咲花
                #      2053 - ユメブキ
                #  5 - 2054 - ホムンクルスレシピ
                #  6 - 2055 - 脳ミソ de 向上
                #  7 - 2059 - Awakening Wings
                #  8 - 2062 - カタルシスの月 upper - 5000 points
                #      2061 - ホーンテッド★メイドランチ upper - 5000 points
                #      2060 - ちくわパフェだよ☆CKP upper - 5000 points
                #  9 - 2074 - HAGURUMA - 5000 points
                #      2075 - ノープラン・デイズ - 5000 points
                #       502 - Sweet Illusion [ex] - 5000 points
                # 10 - 2076 - 左脳スパーク upper - 5000 points
                # 11 - 2077 - 東京メモリー - 5000 points
                # 12 - 2078 - にゃんのパレードマーチ♪ - 5000 points
                # 13 - 2079 - 明滅の果てに - 5000 points
                # 14 - 2080 - Shout It Out
                # 15 - 2081 - グランデーロの守り
                # 16 - 2082 - 恋するMonstro
                # 17 - 2083 - Versa upper
                # 18 - 2084 - Xジェネの逆襲
                # 19 - 2085 - Engraved on my heart ft. 小林マナ
                # 20 - 2086 - fallen leaves -IIDX edition-
                # 21 - 2087 - Τέλος
                # 22 - 2088 - Candy Crime Toe Shoes
                # 23 - 2089 - High Speed Junkie!
                # 24 - 2090 - Pure Rude
                # 25 - 2092 - 地方創生☆チクワクティクス upper - 5000 points
                #      2091 - 乙女繚乱 舞い咲き誇れ upper - 5000 points
                # 26 - 2093 - pastel@sweets labo(*'v'*)
                #      2095 - 恋はどう？モロ◎波動OK☆方程式！！ upper - 5000 points
                #      2094 - Mecha Kawa Breaker!!
                # 27 - 2096 - あまるがむ
                # 28 - 2097 - 勇猛無比
                # 29 - 2098 - Unknown Region
                # 30 - 2110 - unisonote
                # 31 - 2107 - 灰の羽搏
                # 32 - 2113 - 情熱タンデムRUNAWAY
                # 33 - 2108 - Satan
                # 34 - 2111 - 粋 -IKI-
                # 35 - 2112 - Treasure Hoard upper
                # 36 - 2109 - SOLID STATE SQUAD -RISEN RELIC REMIX-
                # 37 - 2114 - 夏色のセーブデータ
                # 38 - 2117 - めうめうぺったんたん！！ upper - 5000 points
                #      2116 - 革命パッショネイト upper - 5000 points
                # 39 - 2118 - Gabbalungang
                # 40 - 2120 - Caldwell 99 - 13000 points
                # 41 - 2065 - 葬送のエウロパ
                #      2064 - ただ、それだけの理由で
                # 42 - 2121 - ISERBROOK
                # 43 - 2122 - Amulet of Enbarr
                # 44 - 2123 - Sword of Vengeance
                # 45 - 2120 - Caldwell 99 (set B) - 13000 points
                # 46 - 2124 - 満漢全席火花ノ舞
                # 47 - 2126 - mathematical good-bye - 13000 points
                #      2125 - Hexer - 13000 points
                #      2127 - F/S - 14000
                # 48 - Ended
                5: narunaru_phase,
                # Super Unilab BOOST! (0-2)
                # Boost should be 120, 150, or 200, bemaniwiki has the explanation and it's based on the unlocks left to do
                6: super_unilab_boost,
                # Unknown event (0-6)
                7: 6,
                # Unknown event (0-2)
                8: 2,
                # Kakusei no Elem - Awakening Elem (0-44)
                # Songs are unlocked as a percentage of 280 points unless otherwise specified
                #  0 - Disabled
                #  1 - 2128 - Tan♪Tan♪Tan♪
                #  2 - 2129 - Keep the Faith
                #  3 - 2130 - Lovin' You
                #  4 - 2131 - Redemption Tears
                #  5 - 2132 - Dancin' in シャングリラ
                #  6 - 2133 - ココロコースター
                #  7 - 2136 - ma plume
                #      2137 - ma plume upper
                #  8 - 2135 - いばら姫
                #  9 - 2134 - 螺旋
                # 10 - 2147 - めうめうぺったんたん！！ (ZAQUVA Remix)
                #      2148 - ちくわパフェだよ☆ＣＫＰ (Yvya Remix)
                # 11 - 2152 - 狼弦暴威
                #           - Player must complete the first 12 before this will show up in the event
                # 12 - 2067 - The Escape
                # 13 - 2153 - 謎情の雫 ft. Kanae Asaba
                # 14 - 2154 - 黒猫と珈琲
                # 15 - 2155 - Head Scratcher
                # 16 - 2156 - ドーナツホール upper - 230 points
                #      2157 - マトリョシカ upper - 230 points
                # 17 - 2063 - 遊戯大熊猫
                # 18 - 2138 - Stylus
                # 19 - 2158 - Crazy Shuffle
                # 20 - 2159 - speedstar[02]
                # 21 - 2160 - 少年A
                # 22 - 2161 - what I wish
                # 23 - 2068 - TAKE YOU AWAY
                # 24 - 2070 - Dragon Blade -The Arrange-
                # 25 - 2162 - Pump up dA CORE
                # 26 - 2175 - TURBO BOOSTER
                # 27 - 2176 - 夜虹
                # 28 - 2066 - 天泣
                # 29 - 2173 - オッタマゲッター
                # 30 - 2177 - luck upper - 230 points
                #      2178 - 脳漿炸裂ガール upper - 230 points
                # 31 - 2179 - TYPHØN
                # 32 - 2069 - REFLEXES MANIPULATION
                # 33 - 2174 - オーバー
                # 34 - 2115 - Knockin' On Red Button
                # 35 - 2180 - The Metalist
                # 36 - 2181 - イマココ!この瞬間
                # 37 - 2182 - チョコレートスマイル upper - 230 points
                # 38 - 2183 - キリステゴメン upper - 230 points
                # 39 - 2099 - Liar×Girl
                #      2101 - Hades Doll
                # 40 - 2102 - Jazz is Rad
                #      2104 - アモ
                # 41 - 2100 - encounter
                #      2103 - 不可説不可説転
                # 42 - 2185 - 閉塞的フレーション
                #      2186 - 残像ニ繋ガレタ追憶ノHIDEAWAY
                #      2187 - 弾幕信仰
                # 43 - 2105 - UROBOROS OVERDIVE
                #      2106 - Megalara Garuda
                # 44 - 2184 - Megalara Garuda upper
                9: kakusei_phase,
                # Enable Awakening Elem (0-1)
                10: 1 if (kakusei_phase > 0) else 0,
                # CanCan's Super Awakening Boost (0-2)
                11: cancan_boost,
                # Unknown event (0-2)
                12: 2,
                # Unknown event (0-2)
                13: 2,
            },
            False,
        )

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = super().format_profile(userid, profile)

        account = root.child("account")
        account.add_child(Node.s16("sp_riddles_id", profile.get_int("sp_riddles_id")))

        # options
        option = root.child("option")
        option_dict = profile.get_dict("option")
        option.add_child(Node.bool("lift", option_dict.get_bool("lift")))
        option.add_child(Node.s16("lift_rate", option_dict.get_int("lift_rate")))

        # Kaimei riddles events
        event2021 = Node.void("event2021")
        root.add_child(event2021)
        event2021.add_child(Node.u32("point", profile.get_int("point")))
        event2021.add_child(Node.u8("step", profile.get_int("step")))
        event2021.add_child(Node.u32_array("quest_point", profile.get_int_array("quest_point", 8, [0] * 8)))
        event2021.add_child(Node.u8("step_nos", profile.get_int("step_nos")))
        event2021.add_child(Node.u32_array("quest_point_nos", profile.get_int_array("quest_point_nos", 13, [0] * 13)))

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

        # Narunaru♪ UniLab jikkenshitsu! event
        event_p27 = Node.void("event_p27")
        root.add_child(event_p27)
        event_p27.add_child(Node.s16("team_id", profile.get_int("team_id")))
        event_p27.add_child(Node.bool("first_play", profile.get_bool("first_play", True)))
        event_p27.add_child(Node.s16("select_battery_id", profile.get_int("select_battery_id", 1)))
        event_p27.add_child(Node.bool("elem_first_play", profile.get_bool("elem_first_play", True)))
        event_p27.add_child(Node.bool("today_first_play", profile.get_bool("today_first_play", True)))

        # Set up Narunaru♪ UniLab jikkenshitsu! achievements
        for achievement in achievements:
            if achievement.type == "lab":
                team_id = achievement.data.get_int("team_id")
                ex_no = achievement.data.get_int("ex_no")
                point = achievement.data.get_int("point")
                is_cleared = achievement.data.get_bool("is_cleared")

                team = Node.void("team")
                event_p27.add_child(team)
                team.add_child(Node.s16("team_id", team_id))
                team.add_child(Node.s16("ex_no", ex_no))
                team.add_child(Node.u32("point", point))
                team.add_child(Node.bool("is_cleared", is_cleared))

        # Set up Kakusei no Elem achievements
        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_deco"):
            battery = Node.void("battery")
            event_p27.add_child(battery)
            battery.add_child(Node.s16("battery_id", 1))
            battery.add_child(Node.u32("energy", 300))
            battery.add_child(Node.bool("is_cleared", True))
        else:
            for achievement in achievements:
                if achievement.type == "battery":
                    battery_id = achievement.data.get_int("battery_id")
                    energy = achievement.data.get_int("energy")
                    is_cleared = achievement.data.get_bool("is_cleared")

                    battery = Node.void("battery")
                    event_p27.add_child(battery)
                    battery.add_child(Node.s16("battery_id", battery_id))
                    battery.add_child(Node.u32("energy", energy))
                    battery.add_child(Node.bool("is_cleared", is_cleared))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = super().unformat_profile(userid, request, oldprofile)

        game_config = self.get_game_config()
        account = request.child("account")
        if account is not None:
            newprofile.replace_int("card_again_count", account.child_value("card_again_count"))
            newprofile.replace_int("sp_riddles_id", account.child_value("sp_riddles_id"))

        option_dict = newprofile.get_dict("option")
        option = request.child("option")
        if option is not None:
            option_dict.replace_bool("lift", option.child_value("lift"))
            option_dict.replace_int("lift_rate", option.child_value("lift_rate"))
        newprofile.replace_dict("option", option_dict)

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

        # Unilab event
        event_p27 = request.child("event_p27")
        if event_p27 is not None:
            newprofile.replace_int("team_id", event_p27.child_value("team_id"))
            newprofile.replace_bool("first_play", False)
            newprofile.replace_bool("select_battery_id", event_p27.child_value("select_battery_id"))
            newprofile.replace_bool("elem_first_play", False)
            newprofile.replace_bool("today_first_play", False)

            # Extract Narunaru♪ UniLab jikkenshitsu! achievements
            lab_data = event_p27.child("team")
            if lab_data is not None:
                team_id = lab_data.child_value("team_id")
                ex_no = lab_data.child_value("ex_no")
                point = lab_data.child_value("point")
                is_cleared = lab_data.child_value("is_cleared")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    ex_no,
                    "lab",
                    {
                        "team_id": team_id,
                        "ex_no": ex_no,
                        "point": point,
                        "is_cleared": is_cleared,
                    },
                )

            # Extract Kakusei no Elem achievements
            battery_data = event_p27.child("battery")
            if battery_data is not None:
                battery_id = battery_data.child_value("battery_id")
                energy = battery_data.child_value("energy")
                is_cleared = battery_data.child_value("is_cleared")

                if not game_config.get_bool("force_unlock_deco"):
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        battery_id,
                        "battery",
                        {
                            "battery_id": battery_id,
                            "energy": energy,
                            "is_cleared": is_cleared,
                        },
                    )

        # Unlock 2119 - Perfect Eater, KAC Qualifier song after one play. Opens KAC Lab.
        if game_config.get_bool("force_unlock_perfect_eater"):
            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                2119,
                "item_0",
                {
                    "param": 0,
                    "is_new": False,
                    "get_time": 0,
                },
            )

        # Unlock Ichika no gochamaze Mix UP! songs after one play.
        if game_config.get_bool("force_unlock_ichika"):
            for songid in range(2045, 2050):  # song IDs 2045 to 2049
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    songid,
                    "item_0",
                    {
                        "param": 0,
                        "is_new": False,
                        "get_time": 0,
                    },
                )

        return newprofile
