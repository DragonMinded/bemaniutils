# vim: set fileencoding=utf-8
from typing import Dict, Any
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.stubs import PopnMusicSengokuRetsuden

from bemani.backend.base import Status
from bemani.common import Profile, VersionConstants
from bemani.data import Score, UserID
from bemani.protocol import Node


class PopnMusicTuneStreet(PopnMusicBase):
    name: str = "Pop'n Music TUNE STREET"
    version: int = VersionConstants.POPN_MUSIC_TUNE_STREET

    # Play modes, as reported by profile save from the game
    GAME_PLAY_MODE_CHALLENGE: Final[int] = 3
    GAME_PLAY_MODE_CHO_CHALLENGE: Final[int] = 4
    GAME_PLAY_MODE_TOWN_CHO_CHALLENGE: Final[int] = 15

    # Play flags, as saved into/loaded from the DB
    GAME_PLAY_FLAG_FAILED: Final[int] = 0
    GAME_PLAY_FLAG_CLEARED: Final[int] = 1
    GAME_PLAY_FLAG_FULL_COMBO: Final[int] = 2
    GAME_PLAY_FLAG_PERFECT_COMBO: Final[int] = 3

    # Chart type, as reported by profile save from the game
    GAME_CHART_TYPE_NORMAL: Final[int] = 0
    GAME_CHART_TYPE_HYPER: Final[int] = 1
    GAME_CHART_TYPE_5_BUTTON: Final[int] = 2
    GAME_CHART_TYPE_EX: Final[int] = 3
    GAME_CHART_TYPE_BATTLE_NORMAL: Final[int] = 4
    GAME_CHART_TYPE_BATTLE_HYPER: Final[int] = 5
    GAME_CHART_TYPE_ENJOY_5_BUTTON: Final[int] = 6
    GAME_CHART_TYPE_ENJOY_9_BUTTON: Final[int] = 7

    # Extra chart types supported by Pop'n 19
    CHART_TYPE_OLD_NORMAL: Final[int] = 4
    CHART_TYPE_OLD_HYPER: Final[int] = 5
    CHART_TYPE_OLD_EX: Final[int] = 6
    CHART_TYPE_ENJOY_5_BUTTON: Final[int] = 7
    CHART_TYPE_ENJOY_9_BUTTON: Final[int] = 8
    CHART_TYPE_5_BUTTON: Final[int] = 9

    # Chart type, as packed into a hiscore binary
    GAME_CHART_TYPE_5_BUTTON_POSITION: Final[int] = 0
    GAME_CHART_TYPE_NORMAL_POSITION: Final[int] = 1
    GAME_CHART_TYPE_HYPER_POSITION: Final[int] = 2
    GAME_CHART_TYPE_EX_POSITION: Final[int] = 3
    GAME_CHART_TYPE_CHO_NORMAL_POSITION: Final[int] = 4
    GAME_CHART_TYPE_CHO_HYPER_POSITION: Final[int] = 5
    GAME_CHART_TYPE_CHO_EX_POSITION: Final[int] = 6

    # Highest song ID we can represent
    GAME_MAX_MUSIC_ID: Final[int] = 1045

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicSengokuRetsuden(self.data, self.config, self.model)

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "ints": [
                {
                    "name": "Game Phase",
                    "tip": "Game unlock phase for all players.",
                    "category": "game_config",
                    "setting": "game_phase",
                    "values": {
                        0: "NO PHASE",
                        1: "SECRET DATA RELEASE",
                        2: "MAX: ALL DATA RELEASE",
                    },
                },
                {
                    "name": "Town Mode Phase",
                    "tip": "Town mode phase for all players.",
                    "category": "game_config",
                    "setting": "town_phase",
                    "values": {
                        0: "town mode disabled",
                        1: "town phase 1",
                        2: "town phase 2",
                        3: "Pop'n Naan Festival",
                        # 4 seems to be a continuation of town phase 2. Intentionally leaving it out.
                        5: "town phase 3",
                        6: "town phase 4",
                        7: "Miracle 4 + 1",
                        # 8 seems to be a continuation of town phase 4. Intentionally leaving it out.
                        9: "town phase MAX",
                        10: "Find your daughter!",
                        # 11 is a continuation of phase MAX after find your daughter, with Tanabata
                        # bamboo grass added as well.
                        11: "town phase MAX+1",
                        12: "Peruri-san visits",
                        # 13 is a continuation of phase MAX+1 after peruri-san visits, with Watermelon
                        # pattern tank added as well.
                        13: "town phase MAX+2",
                        14: "Find Deuil!",
                        # 15 is a continuation of phase MAX+2 after find deuil, with Tsukimi dumplings
                        # added as well.
                        15: "town phase MAX+3",
                        16: "Landmark stamp rally",
                        # 17 is a continuation of MAX+3 after landmark stamp rally ends, but offering
                        # no additional stuff.
                    },
                },
            ],
            "bools": [
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
                {
                    "name": "Force Customization Unlock",
                    "tip": "Force unlock all theme and menu customizations.",
                    "category": "game_config",
                    "setting": "force_unlock_customizations",
                },
            ],
        }

    def __format_flags_for_score(self, score: Score) -> int:
        # Format song flags (cleared/not, combo flags)
        playedflag = {
            self.CHART_TYPE_5_BUTTON: 0x2000,
            self.CHART_TYPE_OLD_NORMAL: 0x0800,
            self.CHART_TYPE_OLD_HYPER: 0x1000,
            self.CHART_TYPE_OLD_EX: 0x4000,
            self.CHART_TYPE_NORMAL: 0x0800,
            self.CHART_TYPE_HYPER: 0x1000,
            self.CHART_TYPE_EX: 0x4000,
            # We don't have a played flag for these, only cleared/no play
            self.CHART_TYPE_ENJOY_5_BUTTON: 0,
            self.CHART_TYPE_ENJOY_9_BUTTON: 0,
        }[score.chart]
        # Shift value for cleared/failed/combo indicators
        shift = {
            self.CHART_TYPE_5_BUTTON: 4,
            self.CHART_TYPE_OLD_NORMAL: 0,
            self.CHART_TYPE_OLD_HYPER: 2,
            self.CHART_TYPE_OLD_EX: 6,
            self.CHART_TYPE_NORMAL: 0,
            self.CHART_TYPE_HYPER: 2,
            self.CHART_TYPE_EX: 6,
            self.CHART_TYPE_ENJOY_5_BUTTON: 9,
            self.CHART_TYPE_ENJOY_9_BUTTON: 8,
        }[score.chart]
        flags = {
            self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_FLAG_PERFECT_COMBO,
        }[score.data.get_int("medal")]
        return (flags << shift) | playedflag

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("playerdata")

        # Format profile
        binary_profile = [0] * 2198

        # Copy name. We intentionally leave location 12 alone as it is
        # the null termination for the name if it happens to be 12
        # characters (6 shift-jis kana).
        name_binary = profile.get_str("name", "なし").encode("shift-jis")[0:12]
        for name_pos, byte in enumerate(name_binary):
            binary_profile[name_pos] = byte

        # Copy game mode. Modes sent to the game are as follows.
        # 0 - Enjoy mode.
        # 1 - Challenge mode.
        # 2 - Battle mode.
        # 3 - Net ranking mode (enabled by setting netvs_phase in game.get).
        # 4 - Cho challenge mode.
        # 5 - Town mode (enabled by event_phase in game.get).
        binary_profile[13] = {
            0: 0,
            1: 0,
            2: 1,
            3: 1,
            4: 4,
            5: 2,
            13: 5,
            14: 5,
            15: 5,
        }[profile.get_int("play_mode")]

        # Copy miscelaneous values
        binary_profile[15] = profile.get_int("last_play_flag") & 0xFF
        binary_profile[16] = profile.get_int("medal_and_friend") & 0xFF
        binary_profile[37] = profile.get_int("read_news") & 0xFF
        binary_profile[38] = profile.get_int("skin_tex_note") & 0xFF
        binary_profile[39] = profile.get_int("skin_tex_cmn") & 0xFF
        binary_profile[40] = profile.get_int("skin_sd_bgm") & 0xFF
        binary_profile[41] = profile.get_int("skin_sd_se") & 0xFF
        binary_profile[44] = profile.get_int("option") & 0xFF
        binary_profile[45] = (profile.get_int("option") >> 8) & 0xFF
        binary_profile[46] = (profile.get_int("option") >> 16) & 0xFF
        binary_profile[47] = (profile.get_int("option") >> 24) & 0xFF
        binary_profile[48] = profile.get_int("jubeat_collabo") & 0xFF
        binary_profile[49] = (profile.get_int("jubeat_collabo") >> 8) & 0xFF

        # 52-56 and 56-60 make up two 32 bit colors found in color_3p_flag.
        binary_profile[60] = profile.get_int("chara", -1) & 0xFF
        binary_profile[61] = (profile.get_int("chara", -1) >> 8) & 0xFF
        binary_profile[62] = profile.get_int("music") & 0xFF
        binary_profile[63] = (profile.get_int("music") >> 8) & 0xFF
        binary_profile[64] = profile.get_int("sheet") & 0xFF
        binary_profile[65] = profile.get_int("category") & 0xFF
        binary_profile[66] = profile.get_int("norma_point") & 0xFF
        binary_profile[67] = (profile.get_int("norma_point") >> 8) & 0xFF

        # Format Scores
        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 7) * 17) + 7) / 8)
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart in [
                self.CHART_TYPE_EASY,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            flags = self.__format_flags_for_score(score)

            flags_index = score.id * 2
            binary_profile[108 + flags_index] = binary_profile[108 + flags_index] | (
                flags & 0xFF
            )
            binary_profile[109 + flags_index] = binary_profile[109 + flags_index] | (
                (flags >> 8) & 0xFF
            )

            if score.chart in [
                self.CHART_TYPE_ENJOY_5_BUTTON,
                self.CHART_TYPE_ENJOY_9_BUTTON,
            ]:
                # We don't return enjoy scores, just the flags that we played them
                continue

            # Format actual score, according to DB chart position
            hiscore_index = (score.id * 7) + {
                self.CHART_TYPE_5_BUTTON: self.GAME_CHART_TYPE_5_BUTTON_POSITION,
                self.CHART_TYPE_OLD_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_OLD_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_OLD_EX: self.GAME_CHART_TYPE_EX_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_CHO_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_CHO_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_CHO_EX_POSITION,
            }[score.chart]
            hiscore_byte_pos = int((hiscore_index * 17) / 8)
            hiscore_bit_pos = int((hiscore_index * 17) % 8)
            hiscore_value = score.points << hiscore_bit_pos
            hiscore_array[hiscore_byte_pos] = hiscore_array[hiscore_byte_pos] | (
                hiscore_value & 0xFF
            )
            hiscore_array[hiscore_byte_pos + 1] = hiscore_array[
                hiscore_byte_pos + 1
            ] | ((hiscore_value >> 8) & 0xFF)
            hiscore_array[hiscore_byte_pos + 2] = hiscore_array[
                hiscore_byte_pos + 2
            ] | ((hiscore_value >> 16) & 0xFF)

        # Format most played
        most_played = [
            x[0]
            for x in self.data.local.music.get_most_played(
                self.game, self.version, userid, 20
            )
        ]
        while len(most_played) < 20:
            most_played.append(-1)
        profile_pos = 68
        for musicid in most_played:
            binary_profile[profile_pos] = musicid & 0xFF
            binary_profile[profile_pos + 1] = (musicid >> 8) & 0xFF
            profile_pos = profile_pos + 2

        # Town purchases, including BGM/announcer changes and such.
        # The town customization area will show up if the player owns
        # one or more customization in any of the following four
        # purchase locations. These are all purchased in town mode.
        # - 4-7 are song unlock flags.
        # - 8 appears to be purchased pop-kuns.
        # - 9 appears to be purchased themes.
        # - 10 appears to be purchased BGMs.
        # - 11 appears to be purchased sound effects.
        binary_town = [0] * 141
        town = profile.get_dict("town")

        # Last play flag, so the selection for 5/9/9+cool sticks.
        binary_town[140] = town.get_int("play_type")

        # Fill in basic town points, tracked here and returned in basic profile for some reason.
        binary_town[0] = town.get_int("points") & 0xFF
        binary_town[1] = (town.get_int("points") >> 8) & 0xFF
        binary_town[2] = (town.get_int("points") >> 16) & 0xFF
        binary_town[3] = (town.get_int("points") >> 24) & 0xFF

        # Fill in purchase flags (this is for stuff like BGMs, SEs, Pop-kun customizations, etc).
        bought_flg = town.get_int_array("bought_flg", 3)
        game_config = self.get_game_config()
        force_unlock_songs = game_config.get_bool("force_unlock_songs")
        force_unlock_customizations = game_config.get_bool(
            "force_unlock_customizations"
        )

        if force_unlock_songs:
            bought_flg[0] = 0xFFFFFFFF
        if force_unlock_customizations:
            bought_flg[1] = 0xFFFFFFFF

        for flg, off in enumerate([4, 8, 12]):
            binary_town[off + 0] = bought_flg[flg] & 0xFF
            binary_town[off + 1] = (bought_flg[flg] >> 8) & 0xFF
            binary_town[off + 2] = (bought_flg[flg] >> 16) & 0xFF
            binary_town[off + 3] = (bought_flg[flg] >> 24) & 0xFF

        # Fill in build flags (presumably for what parcels of land have been bought and built on).
        build_flg = town.get_int_array("build_flg", 8)
        for flg, off in enumerate([16, 20, 24, 28, 32, 36, 40, 44]):
            binary_town[off + 0] = build_flg[flg] & 0xFF
            binary_town[off + 1] = (build_flg[flg] >> 8) & 0xFF
            binary_town[off + 2] = (build_flg[flg] >> 16) & 0xFF
            binary_town[off + 3] = (build_flg[flg] >> 24) & 0xFF

        # Fill in character flags (presumably for character location, orientation, stats, etc).
        chara_flg = town.get_int_array("chara_flg", 19)
        for flg, off in enumerate(
            [
                48,
                52,
                56,
                60,
                64,
                68,
                72,
                76,
                80,
                84,
                88,
                92,
                96,
                100,
                104,
                108,
                112,
                116,
                120,
            ]
        ):
            binary_town[off + 0] = chara_flg[flg] & 0xFF
            binary_town[off + 1] = (chara_flg[flg] >> 8) & 0xFF
            binary_town[off + 2] = (chara_flg[flg] >> 16) & 0xFF
            binary_town[off + 3] = (chara_flg[flg] >> 24) & 0xFF

        # Fill in miscellaneous event flags.
        event_flg = town.get_int_array("event_flg", 4)
        for flg, off in enumerate([124, 128, 132, 136]):
            binary_town[off + 0] = event_flg[flg] & 0xFF
            binary_town[off + 1] = (event_flg[flg] >> 8) & 0xFF
            binary_town[off + 2] = (event_flg[flg] >> 16) & 0xFF
            binary_town[off + 3] = (event_flg[flg] >> 24) & 0xFF

        # Construct final profile
        root.add_child(Node.binary("b", bytes(binary_profile)))
        root.add_child(Node.binary("hiscore", bytes(hiscore_array)))
        root.add_child(Node.binary("town", bytes(binary_town)))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()

        # Extract the playmode, important for scores later
        playmode = int(request.attribute("play_mode"))
        newprofile.replace_int("play_mode", playmode)

        # Extract profile options
        newprofile.replace_int("chara", int(request.attribute("chara_num")))
        if "option" in request.attributes:
            newprofile.replace_int("option", int(request.attribute("option")))
        if "last_play_flag" in request.attributes:
            newprofile.replace_int(
                "last_play_flag", int(request.attribute("last_play_flag"))
            )
        if "medal_and_friend" in request.attributes:
            newprofile.replace_int(
                "medal_and_friend", int(request.attribute("medal_and_friend"))
            )
        if "music_num" in request.attributes:
            newprofile.replace_int("music", int(request.attribute("music_num")))
        if "sheet_num" in request.attributes:
            newprofile.replace_int("sheet", int(request.attribute("sheet_num")))
        if "category_num" in request.attributes:
            newprofile.replace_int("category", int(request.attribute("category_num")))
        if "read_news_no_max" in request.attributes:
            newprofile.replace_int(
                "read_news", int(request.attribute("read_news_no_max"))
            )
        if "jubeat_collabo" in request.attributes:
            newprofile.replace_int(
                "jubeat_collabo", int(request.attribute("jubeat_collabo"))
            )
        if "norma_point" in request.attributes:
            newprofile.replace_int("norma_point", int(request.attribute("norma_point")))
        if "skin_tex_note" in request.attributes:
            newprofile.replace_int(
                "skin_tex_note", int(request.attribute("skin_tex_note"))
            )
        if "skin_tex_cmn" in request.attributes:
            newprofile.replace_int(
                "skin_tex_cmn", int(request.attribute("skin_tex_cmn"))
            )
        if "skin_sd_bgm" in request.attributes:
            newprofile.replace_int("skin_sd_bgm", int(request.attribute("skin_sd_bgm")))
        if "skin_sd_se" in request.attributes:
            newprofile.replace_int("skin_sd_se", int(request.attribute("skin_sd_se")))

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract scores
        for node in request.children:
            if node.name == "music":
                songid = int(node.attribute("music_num"))
                chart = int(node.attribute("sheet_num"))
                points = int(node.attribute("score"))
                data = int(node.attribute("data"))

                # We never save battle scores
                if chart in [
                    self.GAME_CHART_TYPE_BATTLE_NORMAL,
                    self.GAME_CHART_TYPE_BATTLE_HYPER,
                ]:
                    continue

                # Arrange order to be compatible with future mixes
                if playmode in {
                    self.GAME_PLAY_MODE_CHO_CHALLENGE,
                    self.GAME_PLAY_MODE_TOWN_CHO_CHALLENGE,
                }:
                    if chart in [
                        self.GAME_CHART_TYPE_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_9_BUTTON,
                    ]:
                        # We don't save 5 button for cho scores, or enjoy modes
                        continue
                    chart = {
                        self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                        self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                        self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
                    }[chart]
                else:
                    chart = {
                        self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_OLD_NORMAL,
                        self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_OLD_HYPER,
                        self.GAME_CHART_TYPE_5_BUTTON: self.CHART_TYPE_5_BUTTON,
                        self.GAME_CHART_TYPE_EX: self.CHART_TYPE_OLD_EX,
                        self.GAME_CHART_TYPE_ENJOY_5_BUTTON: self.CHART_TYPE_ENJOY_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_9_BUTTON: self.CHART_TYPE_ENJOY_9_BUTTON,
                    }[chart]

                # Extract play flags
                shift = {
                    self.CHART_TYPE_5_BUTTON: 4,
                    self.CHART_TYPE_OLD_NORMAL: 0,
                    self.CHART_TYPE_OLD_HYPER: 2,
                    self.CHART_TYPE_OLD_EX: 6,
                    self.CHART_TYPE_NORMAL: 0,
                    self.CHART_TYPE_HYPER: 2,
                    self.CHART_TYPE_EX: 6,
                    self.CHART_TYPE_ENJOY_5_BUTTON: 9,
                    self.CHART_TYPE_ENJOY_9_BUTTON: 8,
                }[chart]

                if chart in [
                    self.CHART_TYPE_ENJOY_5_BUTTON,
                    self.CHART_TYPE_ENJOY_9_BUTTON,
                ]:
                    # We only store cleared or not played for enjoy mode
                    mask = 0x1
                else:
                    # We store all data for regular charts
                    mask = 0x3

                # Grab flags, map to medals in DB. Choose lowest one for each so
                # a newer pop'n can still improve scores and medals.
                flags = (data >> shift) & mask
                medal = {
                    self.GAME_PLAY_FLAG_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
                    self.GAME_PLAY_FLAG_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
                    self.GAME_PLAY_FLAG_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
                    self.GAME_PLAY_FLAG_PERFECT_COMBO: self.PLAY_MEDAL_PERFECT,
                }[flags]
                self.update_score(userid, songid, chart, points, medal)

        # Update town mode data.
        town = newprofile.get_dict("town")

        # Basic stuff that's in the base node for no reason?
        if "tp" in request.attributes:
            town.replace_int("points", int(request.attribute("tp")))

        # Stuff that is in the town node
        townnode = request.child("town")
        if townnode is not None:
            if "play_type" in townnode.attributes:
                town.replace_int("play_type", int(townnode.attribute("play_type")))
            if "base" in townnode.attributes:
                town.replace_int_array(
                    "base", 4, [int(x) for x in townnode.attribute("base").split(",")]
                )
            if "bought_flg" in townnode.attributes:
                bought_array = [
                    int(x) for x in townnode.attribute("bought_flg").split(",")
                ]
                if len(bought_array) == 3:
                    game_config = self.get_game_config()
                    force_unlock_songs = game_config.get_bool("force_unlock_songs")
                    force_unlock_customizations = game_config.get_bool(
                        "force_unlock_customizations"
                    )
                    old_bought_array = town.get_int_array("bought_flg", 3)

                    if force_unlock_songs:
                        # Don't save force unlocked flags, it'll clobber the profile.
                        bought_array[0] = old_bought_array[0]
                    if force_unlock_customizations:
                        # Don't save force unlocked flags, it'll clobber the profile.
                        bought_array[1] = old_bought_array[1]

                    town.replace_int_array("bought_flg", 3, bought_array)
            if "build_flg" in townnode.attributes:
                town.replace_int_array(
                    "build_flg",
                    8,
                    [int(x) for x in townnode.attribute("build_flg").split(",")],
                )
            if "chara_flg" in townnode.attributes:
                town.replace_int_array(
                    "chara_flg",
                    19,
                    [int(x) for x in townnode.attribute("chara_flg").split(",")],
                )
            if "event_flg" in townnode.attributes:
                town.replace_int_array(
                    "event_flg",
                    4,
                    [int(x) for x in townnode.attribute("event_flg").split(",")],
                )
            for bid in range(8):
                if f"building_{bid}" in townnode.attributes:
                    town.replace_int_array(
                        f"building_{bid}",
                        8,
                        [
                            int(x)
                            for x in townnode.attribute(f"building_{bid}").split(",")
                        ],
                    )

        newprofile.replace_dict("town", town)

        return newprofile

    def handle_game_get_request(self, request: Node) -> Node:
        game_config = self.get_game_config()
        game_phase = game_config.get_int("game_phase")
        town_phase = game_config.get_int("town_phase")

        root = Node.void("game")
        root.set_attribute(
            "game_phase", str(game_phase)
        )  # Phase unlocks, for song availability.
        root.set_attribute("boss_battle_point", "1")
        root.set_attribute("boss_diff", "100,100,100,100,100,100,100,100,100,100")
        root.set_attribute("card_phase", "3")
        root.set_attribute(
            "event_phase", str(town_phase)
        )  # Town mode, for the main event.
        root.set_attribute("gfdm_phase", "2")
        root.set_attribute("ir_phase", "14")
        root.set_attribute("jubeat_phase", "2")
        root.set_attribute("local_matching_enable", "1")
        root.set_attribute("matching_sec", "120")
        root.set_attribute(
            "netvs_phase", "0"
        )  # Net taisen mode phase, maximum 18 (no lobby support).
        return root

    def handle_game_active_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.attribute("shop_name"))
        return Node.void("game")

    def handle_playerdata_expire_request(self, request: Node) -> Node:
        return Node.void("playerdata")

    def handle_playerdata_logout_request(self, request: Node) -> Node:
        return Node.void("playerdata")

    def handle_playerdata_get_request(self, request: Node) -> Node:
        modelstring = request.attribute("model")
        refid = request.attribute("ref_id")
        root = self.get_profile_by_refid(
            refid,
            self.NEW_PROFILE_ONLY if modelstring is None else self.OLD_PROFILE_ONLY,
        )
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_playerdata_town_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        root = Node.void("playerdata")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return root

        profile = self.get_profile(userid)
        if profile is None:
            return root

        town = profile.get_dict("town")

        residence = Node.void("residence")
        root.add_child(residence)
        residence.set_attribute("id", str(town.get_int("residence")))

        # It appears there can be up to 9 map nodes, not sure why. I'm only returning the
        # first one. Perhaps if there's multiple towns, the residence ID lets you choose
        # between them? Maybe it has to do with friends towns?
        mapdata = [0] * 180

        # Map over progress for base and buildings. Positions 173-176 are for base flags.
        base = town.get_int_array("base", 4)
        for i in range(4):
            mapdata[173 + i] = base[i]

        # Positions 42-105 are for building flags.
        for bid, start in enumerate([42, 50, 58, 66, 74, 82, 90, 98]):
            building = town.get_int_array(f"building_{bid}", 8)
            for i in range(8):
                mapdata[start + i] = building[i]

        mapnode = Node.binary("map", bytes(mapdata))
        root.add_child(mapnode)
        mapnode.set_attribute("residence", "0")

        return root

    def handle_playerdata_new_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        name = request.attribute("name")
        root = self.new_profile_by_refid(refid, name)
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_playerdata_set_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")

        root = Node.void("playerdata")
        if refid is None:
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return root

        oldprofile = self.get_profile(userid) or Profile(
            self.game, self.version, refid, 0
        )
        newprofile = self.unformat_profile(userid, request, oldprofile)

        if newprofile is not None:
            self.put_profile(userid, newprofile)

        return root

    def handle_lobby_requests(self, request: Node) -> Node:
        # Stub out the entire lobby service
        return Node.void("lobby")
