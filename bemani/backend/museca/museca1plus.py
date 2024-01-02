from typing import Optional, Dict, Any
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.museca.base import MusecaBase
from bemani.backend.museca.common import (
    MusecaGameFrozenHandler,
    MusecaGameHiscoreHandler,
    MusecaGameNewHandler,
    MusecaGamePlayEndHandler,
    MusecaGameSaveHandler,
    MusecaGameSaveMusicHandler,
    MusecaGameShopHandler,
)
from bemani.backend.museca.museca1 import Museca1
from bemani.common import VersionConstants, Profile, ID
from bemani.data import UserID
from bemani.protocol import Node


class Museca1Plus(
    EventLogHandler,
    MusecaGameFrozenHandler,
    MusecaGameHiscoreHandler,
    MusecaGameNewHandler,
    MusecaGamePlayEndHandler,
    MusecaGameSaveHandler,
    MusecaGameSaveMusicHandler,
    MusecaGameShopHandler,
    MusecaBase,
):
    name: str = "MÚSECA 1+1/2"
    version: int = VersionConstants.MUSECA_1_PLUS

    GAME_LIMITED_LOCKED: Final[int] = 1
    GAME_LIMITED_UNLOCKABLE: Final[int] = 2
    GAME_LIMITED_UNLOCKED: Final[int] = 3

    GAME_CATALOG_TYPE_SONG: Final[int] = 0
    GAME_CATALOG_TYPE_GRAFICA: Final[int] = 15
    GAME_CATALOG_TYPE_MISSION: Final[int] = 16

    GAME_GRADE_DEATH: Final[int] = 0
    GAME_GRADE_POOR: Final[int] = 1
    GAME_GRADE_MEDIOCRE: Final[int] = 2
    GAME_GRADE_GOOD: Final[int] = 3
    GAME_GRADE_GREAT: Final[int] = 4
    GAME_GRADE_EXCELLENT: Final[int] = 5
    GAME_GRADE_SUPERB: Final[int] = 6
    GAME_GRADE_MASTERPIECE: Final[int] = 7
    GAME_GRADE_PERFECT: Final[int] = 8

    GAME_CLEAR_TYPE_FAILED: Final[int] = 1
    GAME_CLEAR_TYPE_CLEARED: Final[int] = 2
    GAME_CLEAR_TYPE_FULL_COMBO: Final[int] = 4

    def previous_version(self) -> Optional[MusecaBase]:
        return Museca1(self.data, self.config, self.model)

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Disable Online Matching",
                    "tip": "Disable online matching between games.",
                    "category": "game_config",
                    "setting": "disable_matching",
                },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
        }

    def game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEARED: self.CLEAR_TYPE_CLEARED,
            self.GAME_CLEAR_TYPE_FULL_COMBO: self.CLEAR_TYPE_FULL_COMBO,
        }[clear_type]

    def db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED: self.GAME_CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_FULL_COMBO: self.GAME_CLEAR_TYPE_FULL_COMBO,
        }[clear_type]

    def game_to_db_grade(self, grade: int) -> int:
        return {
            self.GAME_GRADE_DEATH: self.GRADE_DEATH,
            self.GAME_GRADE_POOR: self.GRADE_POOR,
            self.GAME_GRADE_MEDIOCRE: self.GRADE_MEDIOCRE,
            self.GAME_GRADE_GOOD: self.GRADE_GOOD,
            self.GAME_GRADE_GREAT: self.GRADE_GREAT,
            self.GAME_GRADE_EXCELLENT: self.GRADE_EXCELLENT,
            self.GAME_GRADE_SUPERB: self.GRADE_SUPERB,
            self.GAME_GRADE_MASTERPIECE: self.GRADE_MASTERPIECE,
            self.GAME_GRADE_PERFECT: self.GRADE_PERFECT,
        }[grade]

    def db_to_game_grade(self, grade: int) -> int:
        return {
            self.GRADE_DEATH: self.GAME_GRADE_DEATH,
            self.GRADE_POOR: self.GAME_GRADE_POOR,
            self.GRADE_MEDIOCRE: self.GAME_GRADE_MEDIOCRE,
            self.GRADE_GOOD: self.GAME_GRADE_GOOD,
            self.GRADE_GREAT: self.GAME_GRADE_GREAT,
            self.GRADE_EXCELLENT: self.GAME_GRADE_EXCELLENT,
            self.GRADE_SUPERB: self.GAME_GRADE_SUPERB,
            self.GRADE_MASTERPIECE: self.GAME_GRADE_MASTERPIECE,
            self.GRADE_PERFECT: self.GAME_GRADE_PERFECT,
        }[grade]

    def handle_game_3_common_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        limited = Node.void("music_limited")
        game.add_child(limited)

        # Song unlock config
        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            ids = set()
            songs = self.data.local.music.get_all_songs(self.game, self.music_version)
            for song in songs:
                if song.data.get_int("limited") in (
                    self.GAME_LIMITED_LOCKED,
                    self.GAME_LIMITED_UNLOCKABLE,
                ):
                    ids.add((song.id, song.chart))

            for songid, chart in ids:
                info = Node.void("info")
                limited.add_child(info)
                info.add_child(Node.s32("music_id", songid))
                info.add_child(Node.u8("music_type", chart))
                info.add_child(Node.u8("limited", self.GAME_LIMITED_UNLOCKED))

        # Event config
        event = Node.void("event")
        game.add_child(event)

        def enable_event(eid: int) -> None:
            evt = Node.void("info")
            event.add_child(evt)
            evt.add_child(Node.u32("event_id", eid))

        if not game_config.get_bool("disable_matching"):
            enable_event(143)  # Matching enabled

        # These events are meant specifically for Museca Plus
        museca_plus_events = [
            140,  # Agetta Moratta (vmlink_phase 3 in musicdb)
            211,  # News 1
            212,  # News 2
        ]
        event_ids = [
            1,  # Extended pedal options (no effect on Museca 1+1/2)
            56,  # Generator grafica icon <print 1 in musicdb>
            83,  # Paseli Light Start
            86,  # Generator grafica icon <print 2 in musicdb>
            98,  # Caption 2 notice (grs_grafica_caption_2.png)
            105,  # Makes the "Number of Layers" option visible in game settings
            130,  # Curator Rank
            141,  # Coconatsu & Mukipara grafica effects
            145,  # MUKIPARA UNLOCKS
            146,  # MUKIPARA UNLOCKS
            147,  # MUKIPARA UNLOCKS
            148,  # MUKIPARA UNLOCKS
            149,  # MUKIPARA UNLOCKS
            195,  # Fictional Curator (foot pedal options)
        ]

        for evtid in event_ids:
            enable_event(evtid)
        if self.omnimix:
            for evtid in museca_plus_events:
                enable_event(evtid)

        # List of known event IDs:
        # 56,   # Generator grafica icon <print 1 in musicdb>
        # 83,   # Paseli Light Start
        # 86,   # Generator grafica icon <print 2 in musicdb>
        # 98,   # Caption 2 notice (grs_grafica_caption_2.png)
        # 100,  # DJ YOSHITAKA EXHIBITION 2016
        # 103,  # HATSUNE MIKU EXHIBITION 2016 - PART 1
        # 104,  # HATSUNE MIKU EXHIBITION 2016 - PART 2
        # 105,  # Makes the "Number of Layers" option visible in game settings
        # 106,  # HATSUNE MIKU EXHIBITION 2016 - PART 3
        # 117,  # NEW GENERATION METEOR DIFFUSE FESTA 2016 / RYUSEI FESTA TRIGGER
        # 129,  # COCONATSU EXHIBITION 2016
        # 130,  # Curator Rank
        # 97,   # Agetta Moratta (vmlink_phase 1 in musicdb)
        # 114,  # Agetta Moratta (vmlink_phase 2 in musicdb)
        # 140,  # Agetta Moratta (vmlink_phase 3 in musicdb)
        # 141,  # Coconatsu & Mukipara grafica effects
        # 143,  # Matching
        # 144,  # BEMANI ARCHAEOLOGICAL EXHIBITION
        # 163,  # TUTORIAL SNOW
        # 169,  # SHIORI FUJISAKI EXHIBITION 2017 - PART 1
        # 174,  # SHIORI FUJISAKI EXHIBITION 2017 - PART 2
        # 182,  # Mute illil's voice?
        # 192,  # GREAT REPRINT FESTIVAL: MIKU + DJ YOSHITAKA
        # 194,  # Continue
        # 195,  # Fictional Curator (foot pedal options)
        # 211,  #News 1
        # 212,  #News 2
        # 213,  #News 3
        # 214,  #News 4
        # 217,  #News 5
        # 218,  #News 6
        # 219,  #News 7
        # 220,  #News 8
        # 221,  # GRAFICA PRESENTATION CAMPAIGN “THE PRIMITIVE LIFE EXHIBITION”
        # 222,  # GRAFICA PRESENTATION CAMPAIGN "NOISE"
        # 223,  # GRAFICA PRESENTATION CAMPAIGN "PATISSERIE ROUGE"
        # 224,  # GRAFICA PRESENTATION CAMPAIGN "GUNSLINGER"
        # 145,  # MUKIPARA UNLOCKS
        # 146,  # MUKIPARA UNLOCKS
        # 147,  # MUKIPARA UNLOCKS
        # 148,  # MUKIPARA UNLOCKS
        # 149,  # MUKIPARA UNLOCKS

        # Makes special missions available on grafica that have them.
        extend = Node.void("extend")
        game.add_child(extend)
        info = Node.void("info")
        extend.add_child(info)
        info.add_child(Node.u32("extend_id", 1))
        info.add_child(Node.u32("extend_type", 9))
        info.add_child(Node.s32("param_num_1", 2))
        info.add_child(Node.s32("param_num_2", 50))
        info.add_child(Node.s32("param_num_3", 59))
        info.add_child(Node.s32("param_num_4", 64))
        info.add_child(Node.s32("param_num_5", 86))
        info.add_child(Node.string("param_str_1", "available_ex: 1"))
        info.add_child(Node.string("param_str_2", "available_ex: 1"))
        info.add_child(Node.string("param_str_3", "available_ex: 1"))
        info.add_child(Node.string("param_str_4", "available_ex: 1"))
        info.add_child(Node.string("param_str_5", "available_ex: 1"))

        if self.omnimix:
            info = Node.void("info")
            extend.add_child(info)
            info.add_child(Node.u32("extend_id", 2))
            info.add_child(Node.u32("extend_type", 9))
            info.add_child(Node.s32("param_num_1", 210))
            info.add_child(Node.s32("param_num_2", 0))
            info.add_child(Node.s32("param_num_3", 0))
            info.add_child(Node.s32("param_num_4", 0))
            info.add_child(Node.s32("param_num_5", 0))
            info.add_child(Node.string("param_str_1", ""))
            info.add_child(Node.string("param_str_2", ""))
            info.add_child(Node.string("param_str_3", ""))
            info.add_child(Node.string("param_str_4", ""))
            info.add_child(Node.string("param_str_5", ""))

        return game

    def handle_game_3_lounge_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        # Refresh interval in seconds.
        game.add_child(Node.u32("interval", 10))
        return game

    def handle_game_3_exception_request(self, request: Node) -> Node:
        return Node.void("game_3")

    def handle_game_3_load_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        root = self.get_profile_by_refid(refid)
        if root is not None:
            return root

        # Figure out if this user has an older profile or not
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        if userid is not None:
            previous_game = self.previous_version()
        else:
            previous_game = None

        if previous_game is not None:
            profile = previous_game.get_profile(userid)
        else:
            profile = None

        if profile is not None:
            # Return the previous formatted profile to the game.
            return previous_game.format_profile(userid, profile)
        else:
            root = Node.void("game_3")
            root.add_child(Node.u8("result", 1))
            return root

    def handle_game_3_load_m_request(self, request: Node) -> Node:
        refid = request.child_value("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
        else:
            scores = []

        # Output to the game
        game = Node.void("game_3")
        new = Node.void("new")
        game.add_child(new)

        for score in scores:
            music = Node.void("music")
            new.add_child(music)
            music.add_child(Node.u32("music_id", score.id))
            music.add_child(Node.u32("music_type", score.chart))
            music.add_child(Node.u32("score", score.points))
            music.add_child(Node.u32("cnt", score.plays))
            music.add_child(Node.u32("combo", score.data.get_int("combo")))
            music.add_child(
                Node.u32(
                    "clear_type",
                    self.db_to_game_clear_type(score.data.get_int("clear_type")),
                )
            )
            music.add_child(Node.u32("score_grade", self.db_to_game_grade(score.data.get_int("grade"))))
            stats = score.data.get_dict("stats")
            music.add_child(Node.u32("btn_rate", stats.get_int("btn_rate")))
            music.add_child(Node.u32("long_rate", stats.get_int("long_rate")))
            music.add_child(Node.u32("vol_rate", stats.get_int("vol_rate")))

        return game

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        game = Node.void("game_3")

        # Generic profile stuff
        game.add_child(Node.string("name", profile.get_str("name")))
        game.add_child(Node.string("code", ID.format_extid(profile.extid)))
        game.add_child(Node.u32("gamecoin_packet", profile.get_int("packet")))
        game.add_child(Node.u32("gamecoin_block", profile.get_int("block")))
        game.add_child(Node.s16("skill_name_id", profile.get_int("skill_name_id", -1)))
        game.add_child(Node.s32_array("hidden_param", profile.get_int_array("hidden_param", 20)))
        game.add_child(Node.u32("blaster_energy", profile.get_int("blaster_energy")))
        game.add_child(Node.u32("blaster_count", profile.get_int("blaster_count")))

        # Enable Ryusei Festa
        ryusei_festa = Node.void("ryusei_festa")
        game.add_child(ryusei_festa)
        ryusei_festa.add_child(Node.bool("ryusei_festa_trigger", True))

        # Play statistics
        statistics = self.get_play_statistics(userid)
        game.add_child(Node.u32("play_count", statistics.total_plays))
        game.add_child(Node.u32("daily_count", statistics.today_plays))
        game.add_child(Node.u32("play_chain", statistics.consecutive_days))

        # Last played stuff
        if "last" in profile:
            lastdict = profile.get_dict("last")
            last = Node.void("last")
            game.add_child(last)
            last.add_child(Node.s32("music_id", lastdict.get_int("music_id", -1)))
            last.add_child(Node.u8("music_type", lastdict.get_int("music_type")))
            last.add_child(Node.u8("sort_type", lastdict.get_int("sort_type")))
            last.add_child(Node.u8("narrow_down", lastdict.get_int("narrow_down")))
            last.add_child(Node.u8("headphone", lastdict.get_int("headphone")))
            last.add_child(Node.u16("appeal_id", lastdict.get_int("appeal_id", 1001)))
            last.add_child(Node.u16("comment_id", lastdict.get_int("comment_id")))
            last.add_child(Node.u8("gauge_option", lastdict.get_int("gauge_option")))

        # Item unlocks
        itemnode = Node.void("item")
        game.add_child(itemnode)

        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)

        for item in achievements:
            if item.type[:5] != "item_":
                continue
            itemtype = int(item.type[5:])

            if game_config.get_bool("force_unlock_songs") and itemtype == self.GAME_CATALOG_TYPE_SONG:
                # Don't echo unlocked songs, we will add all of them later
                continue

            info = Node.void("info")
            itemnode.add_child(info)
            info.add_child(Node.u8("type", itemtype))
            info.add_child(Node.u32("id", item.id))
            info.add_child(Node.u32("param", item.data.get_int("param")))
            if "diff_param" in item.data:
                info.add_child(Node.s32("diff_param", item.data.get_int("diff_param")))

        if game_config.get_bool("force_unlock_songs"):
            ids: Dict[int, int] = {}
            songs = self.data.local.music.get_all_songs(self.game, self.music_version)
            for song in songs:
                if song.id not in ids:
                    ids[song.id] = 0

                if song.data.get_int("difficulty") > 0:
                    ids[song.id] = ids[song.id] | (1 << song.chart)

            for itemid in ids:
                if ids[itemid] == 0:
                    continue

                info = Node.void("info")
                itemnode.add_child(info)
                info.add_child(Node.u8("type", self.GAME_CATALOG_TYPE_SONG))
                info.add_child(Node.u32("id", itemid))
                info.add_child(Node.u32("param", ids[itemid]))

        return game

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()

        # Update blaster energy and in-game currencies
        earned_gamecoin_packet = request.child_value("earned_gamecoin_packet")
        if earned_gamecoin_packet is not None:
            newprofile.replace_int("packet", newprofile.get_int("packet") + earned_gamecoin_packet)
        earned_gamecoin_block = request.child_value("earned_gamecoin_block")
        if earned_gamecoin_block is not None:
            newprofile.replace_int("block", newprofile.get_int("block") + earned_gamecoin_block)
        earned_blaster_energy = request.child_value("earned_blaster_energy")
        if earned_blaster_energy is not None:
            newprofile.replace_int(
                "blaster_energy",
                newprofile.get_int("blaster_energy") + earned_blaster_energy,
            )

        # Miscelaneous stuff
        newprofile.replace_int("blaster_count", request.child_value("blaster_count"))
        newprofile.replace_int("skill_name_id", request.child_value("skill_name_id"))
        newprofile.replace_int_array("hidden_param", 20, request.child_value("hidden_param"))

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()

        if request.child("item") is not None:
            for child in request.child("item").children:
                if child.name != "info":
                    continue

                item_id = child.child_value("id")
                item_type = child.child_value("type")
                param = child.child_value("param")
                diff_param = child.child_value("diff_param")

                if game_config.get_bool("force_unlock_songs") and item_type == self.GAME_CATALOG_TYPE_SONG:
                    # Don't save back songs, because they were force unlocked
                    continue

                if diff_param is not None:
                    paramvals = {
                        "diff_param": diff_param,
                        "param": param,
                    }
                else:
                    paramvals = {
                        "param": param,
                    }

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    item_id,
                    f"item_{item_type}",
                    paramvals,
                )

        # Grab last information.
        lastdict = newprofile.get_dict("last")
        lastdict.replace_int("headphone", request.child_value("headphone"))
        lastdict.replace_int("appeal_id", request.child_value("appeal_id"))
        lastdict.replace_int("comment_id", request.child_value("comment_id"))
        lastdict.replace_int("music_id", request.child_value("music_id"))
        lastdict.replace_int("music_type", request.child_value("music_type"))
        lastdict.replace_int("sort_type", request.child_value("sort_type"))
        lastdict.replace_int("narrow_down", request.child_value("narrow_down"))
        lastdict.replace_int("gauge_option", request.child_value("gauge_option"))

        # Save back last information gleaned from results
        newprofile.replace_dict("last", lastdict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
