from typing_extensions import Final


class GameConstants:
    BISHI_BASHI: Final[str] = 'bishi'
    DANCE_EVOLUTION: Final[str] = 'danevo'
    DDR: Final[str] = 'ddr'
    IIDX: Final[str] = 'iidx'
    JUBEAT: Final[str] = 'jubeat'
    MUSECA: Final[str] = 'museca'
    POPN_MUSIC: Final[str] = 'pnm'
    REFLEC_BEAT: Final[str] = 'reflec'
    SDVX: Final[str] = 'sdvx'


class VersionConstants:
    BISHI_BASHI_TSBB: Final[int] = 1

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
    POPN_MUSIC_KRIDDLES: Final[int] = 26

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


class APIConstants:
    ID_TYPE_SERVER: Final[str] = 'server'
    ID_TYPE_CARD: Final[str] = 'card'
    ID_TYPE_SONG: Final[str] = 'song'
    ID_TYPE_INSTANCE: Final[str] = 'instance'


class DBConstants:
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

    MUSECA_GRADE_DEATH: Final[int] = 100        # 没
    MUSECA_GRADE_POOR: Final[int] = 200         # 拙
    MUSECA_GRADE_MEDIOCRE: Final[int] = 300     # 凡
    MUSECA_GRADE_GOOD: Final[int] = 400         # 佳
    MUSECA_GRADE_GREAT: Final[int] = 500        # 良
    MUSECA_GRADE_EXCELLENT: Final[int] = 600    # 優
    MUSECA_GRADE_SUPERB: Final[int] = 700       # 秀
    MUSECA_GRADE_MASTERPIECE: Final[int] = 800  # 傑
    MUSECA_GRADE_PERFECT: Final[int] = 900      # 傑
    MUSECA_CLEAR_TYPE_FAILED: Final[int] = 100
    MUSECA_CLEAR_TYPE_CLEARED: Final[int] = 200
    MUSECA_CLEAR_TYPE_FULL_COMBO: Final[int] = 300

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
