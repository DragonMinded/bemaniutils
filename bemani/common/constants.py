from enum import Enum
from typing import Dict
from typing_extensions import Final


class GameConstants(Enum):
    """
    Constants that identify a game series. These are used in the code as enums
    in order to catch type errors and prevent raw strings being introduced for
    game series. They re also used verbatum in MySQL, so any column named 'game'
    in any of the tables should only contain one of the following strings.
    """

    BISHI_BASHI = "bishi"
    DANCE_EVOLUTION = "danevo"
    DDR = "ddr"
    IIDX = "iidx"
    JUBEAT = "jubeat"
    MGA = "mga"
    MUSECA = "museca"
    POPN_MUSIC = "pnm"
    REFLEC_BEAT = "reflec"
    SDVX = "sdvx"


class VersionConstants:
    """
    Constants used to centralize game versions. These are not enumerations
    since there are multiple keys with the same value. However, all database
    column named 'version' should contain only values found here.
    """

    BISHI_BASHI_TSBB: Final[int] = 1

    DANCE_EVOLUTION: Final[int] = 1

    DDR_1STMIX: Final[int] = 1
    DDR_2NDMIX: Final[int] = 2
    DDR_3RDMIX: Final[int] = 3
    DDR_4THMIX: Final[int] = 4
    DDR_5THMIX: Final[int] = 5
    DDR_6THMIX: Final[int] = 6
    DDR_7THMIX: Final[int] = 7
    DDR_EXTREME: Final[int] = 8
    DDR_SUPERNOVA: Final[int] = 9
    DDR_SUPERNOVA_2: Final[int] = 10
    DDR_X: Final[int] = 11
    DDR_X2: Final[int] = 12
    DDR_X3_VS_2NDMIX: Final[int] = 13
    DDR_2013: Final[int] = 14
    DDR_2014: Final[int] = 15
    DDR_ACE: Final[int] = 16
    DDR_A20: Final[int] = 17

    IIDX: Final[int] = 1
    IIDX_2ND_STYLE: Final[int] = 2
    IIDX_3RD_STYLE: Final[int] = 3
    IIDX_4TH_STYLE: Final[int] = 4
    IIDX_5TH_STYLE: Final[int] = 5
    IIDX_6TH_STYLE: Final[int] = 6
    IIDX_7TH_STYLE: Final[int] = 7
    IIDX_8TH_STYLE: Final[int] = 8
    IIDX_9TH_STYLE: Final[int] = 9
    IIDX_10TH_STYLE: Final[int] = 10
    IIDX_RED: Final[int] = 11
    IIDX_HAPPY_SKY: Final[int] = 12
    IIDX_DISTORTED: Final[int] = 13
    IIDX_GOLD: Final[int] = 14
    IIDX_DJ_TROOPERS: Final[int] = 15
    IIDX_EMPRESS: Final[int] = 16
    IIDX_SIRIUS: Final[int] = 17
    IIDX_RESORT_ANTHEM: Final[int] = 18
    IIDX_LINCLE: Final[int] = 19
    IIDX_TRICORO: Final[int] = 20
    IIDX_SPADA: Final[int] = 21
    IIDX_PENDUAL: Final[int] = 22
    IIDX_COPULA: Final[int] = 23
    IIDX_SINOBUZ: Final[int] = 24
    IIDX_CANNON_BALLERS: Final[int] = 25
    IIDX_ROOTAGE: Final[int] = 26
    IIDX_HEROIC_VERSE: Final[int] = 27
    IIDX_BISTROVER: Final[int] = 28

    JUBEAT: Final[int] = 1
    JUBEAT_RIPPLES: Final[int] = 2
    JUBEAT_RIPPLES_APPEND: Final[int] = 3
    JUBEAT_KNIT: Final[int] = 4
    JUBEAT_KNIT_APPEND: Final[int] = 5
    JUBEAT_COPIOUS: Final[int] = 6
    JUBEAT_COPIOUS_APPEND: Final[int] = 7
    JUBEAT_SAUCER: Final[int] = 8
    JUBEAT_SAUCER_FULFILL: Final[int] = 9
    JUBEAT_PROP: Final[int] = 10
    JUBEAT_QUBELL: Final[int] = 11
    JUBEAT_CLAN: Final[int] = 12
    JUBEAT_FESTO: Final[int] = 13
    JUBEAT_AVENUE: Final[int] = 14

    MGA: Final[int] = 1

    MUSECA: Final[int] = 1
    MUSECA_1_PLUS: Final[int] = 2

    POPN_MUSIC: Final[int] = 1
    POPN_MUSIC_2: Final[int] = 2
    POPN_MUSIC_3: Final[int] = 3
    POPN_MUSIC_4: Final[int] = 4
    POPN_MUSIC_5: Final[int] = 5
    POPN_MUSIC_6: Final[int] = 6
    POPN_MUSIC_7: Final[int] = 7
    POPN_MUSIC_8: Final[int] = 8
    POPN_MUSIC_9: Final[int] = 9
    POPN_MUSIC_10: Final[int] = 10
    POPN_MUSIC_11: Final[int] = 11
    POPN_MUSIC_IROHA: Final[int] = 12
    POPN_MUSIC_CARNIVAL: Final[int] = 13
    POPN_MUSIC_FEVER: Final[int] = 14
    POPN_MUSIC_ADVENTURE: Final[int] = 15
    POPN_MUSIC_PARTY: Final[int] = 16
    POPN_MUSIC_THE_MOVIE: Final[int] = 17
    POPN_MUSIC_SENGOKU_RETSUDEN: Final[int] = 18
    POPN_MUSIC_TUNE_STREET: Final[int] = 19
    POPN_MUSIC_FANTASIA: Final[int] = 20
    POPN_MUSIC_SUNNY_PARK: Final[int] = 21
    POPN_MUSIC_LAPISTORIA: Final[int] = 22
    POPN_MUSIC_ECLALE: Final[int] = 23
    POPN_MUSIC_USANEKO: Final[int] = 24
    POPN_MUSIC_PEACE: Final[int] = 25
    POPN_MUSIC_KAIMEI_RIDDLES: Final[int] = 26
    POPN_MUSIC_UNILAB: Final[int] = 27

    REFLEC_BEAT: Final[int] = 1
    REFLEC_BEAT_LIMELIGHT: Final[int] = 2
    REFLEC_BEAT_COLETTE: Final[int] = 3
    REFLEC_BEAT_GROOVIN: Final[int] = 4
    REFLEC_BEAT_VOLZZA: Final[int] = 5
    REFLEC_BEAT_VOLZZA_2: Final[int] = 6
    REFLEC_BEAT_REFLESIA: Final[int] = 7

    SDVX_BOOTH: Final[int] = 1
    SDVX_INFINITE_INFECTION: Final[int] = 2
    SDVX_GRAVITY_WARS: Final[int] = 3
    SDVX_HEAVENLY_HAVEN: Final[int] = 4


class APIConstants(Enum):
    """
    The four types of IDs found in a BEMAPI request or response.
    """

    ID_TYPE_SERVER = "server"
    ID_TYPE_CARD = "card"
    ID_TYPE_SONG = "song"
    ID_TYPE_INSTANCE = "instance"


class DBConstants:
    """
    Constants found in the DB relating to clear lamps, halos, grades, and the like.
    """

    # When adding new game series, I try to make sure that constants
    # go in order, and have a difference of 100 between them. This is
    # so I can promote lamps/scores/etc by using a simple "max", while
    # still allowing for new game versions to insert new constants anywhere
    # in the lineup. You'll notice a few areas where constants go up by
    # non-100. This is because a new game came out in this series after
    # existing scores were in production, so constants for new grades/lamps
    # had to be snuck in. The actual constant doesn't matter as long as they
    # go in order, so this works out nicely.

    # Its up to various games to map the in-game constant to these DB
    # constants. Most games will implement a pair of functions that takes
    # one of these values and spits out the game-specific constant, and
    # vice versa. This keeps us individual game agnostic and allows us to
    # react easily to renumberings and constant insertions. These constants
    # will only be found in the DB itself, as well as used on the frontend
    # to display various general information about scores.

    OMNIMIX_VERSION_BUMP: Final[int] = 10000

    DDR_HALO_NONE: Final[int] = 100
    DDR_HALO_GOOD_FULL_COMBO: Final[int] = 200
    DDR_HALO_GREAT_FULL_COMBO: Final[int] = 300
    DDR_HALO_PERFECT_FULL_COMBO: Final[int] = 400
    DDR_HALO_MARVELOUS_FULL_COMBO: Final[int] = 500
    DDR_RANK_E: Final[int] = 100
    DDR_RANK_D: Final[int] = 200
    DDR_RANK_D_PLUS: Final[int] = 233
    DDR_RANK_C_MINUS: Final[int] = 266
    DDR_RANK_C: Final[int] = 300
    DDR_RANK_C_PLUS: Final[int] = 333
    DDR_RANK_B_MINUS: Final[int] = 366
    DDR_RANK_B: Final[int] = 400
    DDR_RANK_B_PLUS: Final[int] = 433
    DDR_RANK_A_MINUS: Final[int] = 466
    DDR_RANK_A: Final[int] = 500
    DDR_RANK_A_PLUS: Final[int] = 533
    DDR_RANK_AA_MINUS: Final[int] = 566
    DDR_RANK_AA: Final[int] = 600
    DDR_RANK_AA_PLUS: Final[int] = 650
    DDR_RANK_AAA: Final[int] = 700

    IIDX_CLEAR_STATUS_NO_PLAY: Final[int] = 50
    IIDX_CLEAR_STATUS_FAILED: Final[int] = 100
    IIDX_CLEAR_STATUS_ASSIST_CLEAR: Final[int] = 200
    IIDX_CLEAR_STATUS_EASY_CLEAR: Final[int] = 300
    IIDX_CLEAR_STATUS_CLEAR: Final[int] = 400
    IIDX_CLEAR_STATUS_HARD_CLEAR: Final[int] = 500
    IIDX_CLEAR_STATUS_EX_HARD_CLEAR: Final[int] = 600
    IIDX_CLEAR_STATUS_FULL_COMBO: Final[int] = 700
    IIDX_DAN_RANK_7_KYU: Final[int] = 100
    IIDX_DAN_RANK_6_KYU: Final[int] = 200
    IIDX_DAN_RANK_5_KYU: Final[int] = 300
    IIDX_DAN_RANK_4_KYU: Final[int] = 400
    IIDX_DAN_RANK_3_KYU: Final[int] = 500
    IIDX_DAN_RANK_2_KYU: Final[int] = 600
    IIDX_DAN_RANK_1_KYU: Final[int] = 700
    IIDX_DAN_RANK_1_DAN: Final[int] = 800
    IIDX_DAN_RANK_2_DAN: Final[int] = 900
    IIDX_DAN_RANK_3_DAN: Final[int] = 1000
    IIDX_DAN_RANK_4_DAN: Final[int] = 1100
    IIDX_DAN_RANK_5_DAN: Final[int] = 1200
    IIDX_DAN_RANK_6_DAN: Final[int] = 1300
    IIDX_DAN_RANK_7_DAN: Final[int] = 1400
    IIDX_DAN_RANK_8_DAN: Final[int] = 1500
    IIDX_DAN_RANK_9_DAN: Final[int] = 1600
    IIDX_DAN_RANK_10_DAN: Final[int] = 1700
    IIDX_DAN_RANK_CHUDEN: Final[int] = 1800
    IIDX_DAN_RANK_KAIDEN: Final[int] = 1900

    JUBEAT_PLAY_MEDAL_FAILED: Final[int] = 100
    JUBEAT_PLAY_MEDAL_CLEARED: Final[int] = 200
    JUBEAT_PLAY_MEDAL_NEARLY_FULL_COMBO: Final[int] = 300
    JUBEAT_PLAY_MEDAL_FULL_COMBO: Final[int] = 400
    JUBEAT_PLAY_MEDAL_NEARLY_EXCELLENT: Final[int] = 500
    JUBEAT_PLAY_MEDAL_EXCELLENT: Final[int] = 600

    MUSECA_GRADE_DEATH: Final[int] = 100  # 没
    MUSECA_GRADE_POOR: Final[int] = 200  # 拙
    MUSECA_GRADE_MEDIOCRE: Final[int] = 300  # 凡
    MUSECA_GRADE_GOOD: Final[int] = 400  # 佳
    MUSECA_GRADE_GREAT: Final[int] = 500  # 良
    MUSECA_GRADE_EXCELLENT: Final[int] = 600  # 優
    MUSECA_GRADE_SUPERB: Final[int] = 700  # 秀
    MUSECA_GRADE_MASTERPIECE: Final[int] = 800  # 傑
    MUSECA_GRADE_PERFECT: Final[int] = 900  # 傑
    MUSECA_CLEAR_TYPE_FAILED: Final[int] = 100
    MUSECA_CLEAR_TYPE_CLEARED: Final[int] = 200
    MUSECA_CLEAR_TYPE_FULL_COMBO: Final[int] = 300

    POPN_MUSIC_PLAY_MEDAL_NO_PLAY: Final[int] = 50
    POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED: Final[int] = 100
    POPN_MUSIC_PLAY_MEDAL_DIAMOND_FAILED: Final[int] = 200
    POPN_MUSIC_PLAY_MEDAL_STAR_FAILED: Final[int] = 300
    POPN_MUSIC_PLAY_MEDAL_EASY_CLEAR: Final[int] = 400
    POPN_MUSIC_PLAY_MEDAL_CIRCLE_CLEARED: Final[int] = 500
    POPN_MUSIC_PLAY_MEDAL_DIAMOND_CLEARED: Final[int] = 600
    POPN_MUSIC_PLAY_MEDAL_STAR_CLEARED: Final[int] = 700
    POPN_MUSIC_PLAY_MEDAL_CIRCLE_FULL_COMBO: Final[int] = 800
    POPN_MUSIC_PLAY_MEDAL_DIAMOND_FULL_COMBO: Final[int] = 900
    POPN_MUSIC_PLAY_MEDAL_STAR_FULL_COMBO: Final[int] = 1000
    POPN_MUSIC_PLAY_MEDAL_PERFECT: Final[int] = 1100

    REFLEC_BEAT_CLEAR_TYPE_NO_PLAY: Final[int] = 100
    REFLEC_BEAT_CLEAR_TYPE_FAILED: Final[int] = 200
    REFLEC_BEAT_CLEAR_TYPE_CLEARED: Final[int] = 300
    REFLEC_BEAT_CLEAR_TYPE_HARD_CLEARED: Final[int] = 400
    REFLEC_BEAT_CLEAR_TYPE_S_HARD_CLEARED: Final[int] = 500
    REFLEC_BEAT_COMBO_TYPE_NONE: Final[int] = 100
    REFLEC_BEAT_COMBO_TYPE_ALMOST_COMBO: Final[int] = 200
    REFLEC_BEAT_COMBO_TYPE_FULL_COMBO: Final[int] = 300
    REFLEC_BEAT_COMBO_TYPE_FULL_COMBO_ALL_JUST: Final[int] = 400

    SDVX_CLEAR_TYPE_NO_PLAY: Final[int] = 50
    SDVX_CLEAR_TYPE_FAILED: Final[int] = 100
    SDVX_CLEAR_TYPE_CLEAR: Final[int] = 200
    SDVX_CLEAR_TYPE_HARD_CLEAR: Final[int] = 300
    SDVX_CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = 400
    SDVX_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[int] = 500
    SDVX_GRADE_NO_PLAY: Final[int] = 100
    SDVX_GRADE_D: Final[int] = 200
    SDVX_GRADE_C: Final[int] = 300
    SDVX_GRADE_B: Final[int] = 400
    SDVX_GRADE_A: Final[int] = 500
    SDVX_GRADE_A_PLUS: Final[int] = 550
    SDVX_GRADE_AA: Final[int] = 600
    SDVX_GRADE_AA_PLUS: Final[int] = 650
    SDVX_GRADE_AAA: Final[int] = 700
    SDVX_GRADE_AAA_PLUS: Final[int] = 800
    SDVX_GRADE_S: Final[int] = 900


class BroadcastConstants(Enum):
    """
    Enum representing the various sections of a broadcast trigger. These come
    into play when a new score is earned and there is a trigger such as a
    discord webhook that needs to be notified.
    """

    # Sections related to the player/song/etc.
    DJ_NAME = "DJ Name"
    SONG_NAME = "Song"
    ARTIST_NAME = "Artist"
    DIFFICULTY = "Difficulty"

    # Section headers.
    PLAY_STATS_HEADER = "Play Stats"

    # Stats that relate to the song, but not the current play of the song.
    TARGET_EXSCORE = "Target EXScore"
    BEST_CLEAR_STATUS = "Best Clear"

    # Stats that have to do with the current play of the song.
    EXSCORE = "Your EXScore"
    CLEAR_STATUS = "Clear Status"
    PERFECT_GREATS = "Perfect Greats"
    GREATS = "Greats"
    GOODS = "Goods"
    BADS = "Bads"
    POORS = "Poors"
    COMBO_BREAKS = "Combo Breaks"
    SLOWS = "Slow"
    FASTS = "Fast"
    GRADE = "Grade"
    RATE = "Score Rate"

    # Added for Pnm
    PLAYER_NAME = "Player Name"
    SCORE = "Your Score"
    COOLS = "Cools"
    COMBO = "Combo"
    MEDAL = "Medal"


class _RegionConstants:
    """
    Class representing the various region IDs found in all games.
    """

    # The following are the original enumerations, that still are correct
    # for new games today.
    HOKKAIDO: Final[int] = 1
    AOMORI: Final[int] = 2
    IWATE: Final[int] = 3
    MIYAGI: Final[int] = 4
    AKITA: Final[int] = 5
    YAMAGATA: Final[int] = 6
    FUKUSHIMA: Final[int] = 7
    IBARAKI: Final[int] = 8
    TOCHIGI: Final[int] = 9
    GUNMA: Final[int] = 10
    SAITAMA: Final[int] = 11
    CHIBA: Final[int] = 12
    TOKYO: Final[int] = 13
    KANAGAWA: Final[int] = 14
    NIIGATA: Final[int] = 15
    TOYAMA: Final[int] = 16
    ISHIKAWA: Final[int] = 17
    FUKUI: Final[int] = 18
    YAMANASHI: Final[int] = 19
    NAGANO: Final[int] = 20
    GIFU: Final[int] = 21
    SHIZUOKA: Final[int] = 22
    AICHI: Final[int] = 23
    MIE: Final[int] = 24
    SHIGA: Final[int] = 25
    KYOTO: Final[int] = 26
    OSAKA: Final[int] = 27
    HYOGO: Final[int] = 28
    NARA: Final[int] = 29
    WAKAYAMA: Final[int] = 30
    TOTTORI: Final[int] = 31
    SHIMANE: Final[int] = 32
    OKAYAMA: Final[int] = 33
    HIROSHIMA: Final[int] = 34
    YAMAGUCHI: Final[int] = 35
    TOKUSHIMA: Final[int] = 36
    KAGAWA: Final[int] = 37
    EHIME: Final[int] = 38
    KOUCHI: Final[int] = 39
    FUKUOKA: Final[int] = 40
    SAGA: Final[int] = 41
    NAGASAKI: Final[int] = 42
    KUMAMOTO: Final[int] = 43
    OITA: Final[int] = 44
    MIYAZAKI: Final[int] = 45
    KAGOSHIMA: Final[int] = 46
    OKINAWA: Final[int] = 47
    HONG_KONG: Final[int] = 48
    KOREA: Final[int] = 49
    TAIWAN: Final[int] = 50

    # The following are new additions, replacing the "OLD" values below.
    THAILAND: Final[int] = 51
    INDONESIA: Final[int] = 52
    SINGAPORE: Final[int] = 53
    PHILLIPINES: Final[int] = 54
    MACAO: Final[int] = 55
    USA: Final[int] = 56
    OTHER: Final[int] = 57

    # Bogus value for europe.
    EUROPE: Final[int] = 1000
    NO_MAPPING: Final[int] = 2000

    # Old constant values.
    OLD_USA: Final[int] = 51
    OLD_EUROPE: Final[int] = 52
    OLD_OTHER: Final[int] = 53

    # Min/max valid values for server.
    MIN: Final[int] = 1
    MAX: Final[int] = 56

    # Min/max valid values for JP prefectures
    MIN_PREF: Final[int] = 1
    MAX_PREF: Final[int] = 47

    # This is a really nasty LUT to attempt to make the frontend display
    # the same regardless of the game in question. This is mostly because
    # the prefecture/region stored in the profile is editable by IIDX and
    # I didn't anticipate this ever changing.
    def db_to_game_region(self, use_new_table: bool, region: int) -> int:
        if use_new_table:
            # The new lookup table does not have Europe as an option.
            if region in {RegionConstants.EUROPE, RegionConstants.NO_MAPPING}:
                return RegionConstants.OTHER

            # The rest matches what we have already.
            return region
        else:
            # The old lookup table supports most of the values.
            if region <= RegionConstants.TAIWAN:
                return region

            # Map the two values that still exist back to their old values.
            if region == RegionConstants.USA:
                return RegionConstants.OLD_USA
            if region == RegionConstants.EUROPE:
                return RegionConstants.OLD_EUROPE

            # The rest get mapped to other.
            return RegionConstants.OLD_OTHER

    # This performs the equivalent inverse of the above function. Note that
    # depending on the game and selection, this is lossy (as in, Europe could
    # get converted to Other, etc).
    def game_to_db_region(self, use_new_table: bool, region: int) -> int:
        if use_new_table:
            if region == RegionConstants.OTHER:
                return RegionConstants.NO_MAPPING

            # The new lookup table is correct aside from the above correction.
            return region
        else:
            # The old lookup table supports most of the values.
            if region <= RegionConstants.TAIWAN:
                return region

            # Map the three values that might be seen to new DB values.
            if region == RegionConstants.OLD_USA:
                return RegionConstants.USA
            if region == RegionConstants.OLD_EUROPE:
                return RegionConstants.EUROPE
            if region == RegionConstants.OLD_OTHER:
                return RegionConstants.NO_MAPPING

            raise Exception(f"Unexpected value {region} for game region!")

    @property
    def LUT(cls) -> Dict[int, str]:
        return {
            cls.HOKKAIDO: "北海道 (Hokkaido)",
            cls.AOMORI: "青森県 (Aomori)",
            cls.IWATE: "岩手県 (Iwate)",
            cls.MIYAGI: "宮城県 (Miyagi)",
            cls.AKITA: "秋田県 (Akita)",
            cls.YAMAGATA: "山形県 (Yamagata)",
            cls.FUKUSHIMA: "福島県 (Fukushima)",
            cls.IBARAKI: "茨城県 (Ibaraki)",
            cls.TOCHIGI: "栃木県 (Tochigi)",
            cls.GUNMA: "群馬県 (Gunma)",
            cls.SAITAMA: "埼玉県 (Saitama)",
            cls.CHIBA: "千葉県 (Chiba)",
            cls.TOKYO: "東京都 (Tokyo)",
            cls.KANAGAWA: "神奈川県 (Kanagawa)",
            cls.NIIGATA: "新潟県 (Niigata)",
            cls.TOYAMA: "富山県 (Toyama)",
            cls.ISHIKAWA: "石川県 (Ishikawa)",
            cls.FUKUI: "福井県 (Fukui)",
            cls.YAMANASHI: "山梨県 (Yamanashi)",
            cls.NAGANO: "長野県 (Nagano)",
            cls.GIFU: "岐阜県 (Gifu)",
            cls.SHIZUOKA: "静岡県 (Shizuoka)",
            cls.AICHI: "愛知県 (Aichi)",
            cls.MIE: "三重県 (Mie)",
            cls.SHIGA: "滋賀県 (Shiga)",
            cls.KYOTO: "京都府 (Kyoto)",
            cls.OSAKA: "大阪府 (Osaka)",
            cls.HYOGO: "兵庫県 (Hyogo)",
            cls.NARA: "奈良県 (Nara)",
            cls.WAKAYAMA: "和歌山県 (Wakayama)",
            cls.TOTTORI: "鳥取県 (Tottori)",
            cls.SHIMANE: "島根県 (Shimane)",
            cls.OKAYAMA: "岡山県 (Okayama)",
            cls.HIROSHIMA: "広島県 (Hiroshima)",
            cls.YAMAGUCHI: "山口県 (Yamaguchi)",
            cls.TOKUSHIMA: "徳島県 (Tokushima)",
            cls.KAGAWA: "香川県 (Kagawa)",
            cls.EHIME: "愛媛県 (Ehime)",
            cls.KOUCHI: "高知県 (Kochi)",
            cls.FUKUOKA: "福岡県 (Fukuoka)",
            cls.SAGA: "佐賀県 (Saga)",
            cls.NAGASAKI: "長崎県 (Nagasaki)",
            cls.KUMAMOTO: "熊本県 (Kumamoto)",
            cls.OITA: "大分県 (Oita)",
            cls.MIYAZAKI: "宮崎県 (Miyazaki)",
            cls.KAGOSHIMA: "鹿児島県 (Kagoshima)",
            cls.OKINAWA: "沖縄県 (Okinawa)",
            cls.HONG_KONG: "香港 (Hong Kong)",
            cls.KOREA: "韓国 (Korea)",
            cls.TAIWAN: "台湾 (Taiwan)",
            # The following are different depending on the version of the game,
            # so we choose the new value.
            cls.THAILAND: "タイ (Thailand)",
            cls.INDONESIA: "インドネシア (Indonesia)",
            cls.SINGAPORE: "シンガポール (Singapore)",
            cls.PHILLIPINES: "フィリピン (Phillipines)",
            cls.MACAO: "マカオ (Macao)",
            cls.USA: "アメリカ (USA)",
            cls.EUROPE: "欧州 (Europe)",
            cls.NO_MAPPING: "海外 (Other)",
        }


# This is just so I can use the defined constants inside a LUT
# without having the LUT itself outside the class.
RegionConstants = _RegionConstants()
