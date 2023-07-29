# vim: set fileencoding=utf-8
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.tunestreet import PopnMusicTuneStreet

from bemani.backend.base import Status
from bemani.common import Profile, VersionConstants, ID
from bemani.data import Score, Link, UserID
from bemani.protocol import Node


class PopnMusicFantasia(PopnMusicBase):
    name: str = "Pop'n Music fantasia"
    version: int = VersionConstants.POPN_MUSIC_FANTASIA

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY: Final[int] = 2
    GAME_CHART_TYPE_NORMAL: Final[int] = 0
    GAME_CHART_TYPE_HYPER: Final[int] = 1
    GAME_CHART_TYPE_EX: Final[int] = 3

    # Chart type, as packed into a hiscore binary
    GAME_CHART_TYPE_EASY_POSITION: Final[int] = 0
    GAME_CHART_TYPE_NORMAL_POSITION: Final[int] = 1
    GAME_CHART_TYPE_HYPER_POSITION: Final[int] = 2
    GAME_CHART_TYPE_EX_POSITION: Final[int] = 3

    # Medal type, as returned from the game
    GAME_PLAY_MEDAL_CIRCLE_FAILED: Final[int] = 1
    GAME_PLAY_MEDAL_DIAMOND_FAILED: Final[int] = 2
    GAME_PLAY_MEDAL_STAR_FAILED: Final[int] = 3
    GAME_PLAY_MEDAL_CIRCLE_CLEARED: Final[int] = 5
    GAME_PLAY_MEDAL_DIAMOND_CLEARED: Final[int] = 6
    GAME_PLAY_MEDAL_STAR_CLEARED: Final[int] = 7
    GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: Final[int] = 9
    GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: Final[int] = 10
    GAME_PLAY_MEDAL_STAR_FULL_COMBO: Final[int] = 11
    GAME_PLAY_MEDAL_PERFECT: Final[int] = 15

    # Maximum music ID for this game
    GAME_MAX_MUSIC_ID: Final[int] = 1150

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicTuneStreet(self.data, self.config, self.model)

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
                    "name": "Pop'n Quest Event Phase",
                    "tip": "Event phase for all players.",
                    "category": "game_config",
                    "setting": "event_phase",
                    "values": {
                        0: "No event",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase 3",
                        4: "Phase 4",
                        5: "Phase MAX",
                    },
                },
            ]
        }

    def __format_medal_for_score(self, score: Score) -> int:
        medal = {
            self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
            self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
            self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
            self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,  # Map approximately
            self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
            self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
            self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
            self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
            self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
            self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
            self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
        }[score.data.get_int("medal")]
        position = {
            self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
            self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
            self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
            self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
        }[score.chart]
        return medal << (position * 4)

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("playerdata")

        # Set up the base profile
        base = Node.void("base")
        root.add_child(base)
        base.add_child(Node.string("name", profile.get_str("name", "なし")))
        base.add_child(Node.string("g_pm_id", ID.format_extid(profile.extid)))
        base.add_child(Node.u8("mode", profile.get_int("mode", 0)))
        base.add_child(Node.s8("button", profile.get_int("button", 0)))
        base.add_child(Node.s8("last_play_flag", profile.get_int("last_play_flag", -1)))
        base.add_child(
            Node.u8("medal_and_friend", profile.get_int("medal_and_friend", 0))
        )
        base.add_child(Node.s8("category", profile.get_int("category", -1)))
        base.add_child(Node.s8("sub_category", profile.get_int("sub_category", -1)))
        base.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        base.add_child(Node.s8("chara_category", profile.get_int("chara_category", -1)))
        base.add_child(Node.u8("collabo", profile.get_int("collabo", 255)))
        base.add_child(Node.u8("sheet", profile.get_int("sheet", 0)))
        base.add_child(Node.s8("tutorial", profile.get_int("tutorial", 0)))
        base.add_child(Node.s32("music_open_pt", profile.get_int("music_open_pt", 0)))
        base.add_child(Node.s8("is_conv", -1))
        base.add_child(Node.s32("option", profile.get_int("option", 0)))
        base.add_child(Node.s16("music", profile.get_int("music", -1)))
        base.add_child(Node.u16("ep", profile.get_int("ep", 0)))
        base.add_child(
            Node.s32_array("sp_color_flg", profile.get_int_array("sp_color_flg", 2))
        )
        base.add_child(Node.s32("read_news", profile.get_int("read_news", 0)))
        base.add_child(
            Node.s16(
                "consecutive_days_coupon", profile.get_int("consecutive_days_coupon", 0)
            )
        )
        base.add_child(Node.s8("staff", 0))

        # Player card section
        player_card_dict = profile.get_dict("player_card")
        player_card = Node.void("player_card")
        root.add_child(player_card)
        player_card.add_child(
            Node.u8_array("title", player_card_dict.get_int_array("title", 2, [0, 1]))
        )
        player_card.add_child(Node.u8("frame", player_card_dict.get_int("frame")))
        player_card.add_child(Node.u8("base", player_card_dict.get_int("base")))
        player_card.add_child(
            Node.u8_array("seal", player_card_dict.get_int_array("seal", 2))
        )
        player_card.add_child(
            Node.s32_array("get_title", player_card_dict.get_int_array("get_title", 4))
        )
        player_card.add_child(
            Node.s32("get_frame", player_card_dict.get_int("get_frame"))
        )
        player_card.add_child(
            Node.s32("get_base", player_card_dict.get_int("get_base"))
        )
        player_card.add_child(
            Node.s32_array("get_seal", player_card_dict.get_int_array("get_seal", 2))
        )
        player_card.add_child(Node.s8("is_open", 1))

        # Player card EX section
        player_card_ex = Node.void("player_card_ex")
        root.add_child(player_card_ex)
        player_card_ex.add_child(
            Node.s32("get_title_ex", player_card_dict.get_int("get_title_ex"))
        )
        player_card_ex.add_child(
            Node.s32("get_frame_ex", player_card_dict.get_int("get_frame_ex"))
        )
        player_card_ex.add_child(
            Node.s32("get_base_ex", player_card_dict.get_int("get_base_ex"))
        )
        player_card_ex.add_child(
            Node.s32("get_seal_ex", player_card_dict.get_int("get_seal_ex"))
        )

        # Statistics section and scores section
        statistics = self.get_play_statistics(userid)
        base.add_child(Node.s32("total_play_cnt", statistics.total_plays))
        base.add_child(Node.s16("today_play_cnt", statistics.today_plays))
        base.add_child(Node.s16("consecutive_days", statistics.consecutive_days))

        # Number of rivals that are active for this version.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivalcount = 0
        for link in links:
            if link.type != "rival":
                continue

            if not self.has_profile(link.other_userid):
                continue

            # This profile is valid.
            rivalcount += 1
        base.add_child(Node.u8("active_fr_num", rivalcount))

        last_played = [
            x[0]
            for x in self.data.local.music.get_last_played(
                self.game, self.music_version, userid, 3
            )
        ]
        most_played = [
            x[0]
            for x in self.data.local.music.get_most_played(
                self.game, self.music_version, userid, 20
            )
        ]
        while len(last_played) < 3:
            last_played.append(-1)
        while len(most_played) < 20:
            most_played.append(-1)

        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)
        clear_medal = [0] * self.GAME_MAX_MUSIC_ID
        clear_medal_sub = [0] * self.GAME_MAX_MUSIC_ID

        scores = self.data.remote.music.get_scores(
            self.game, self.music_version, userid
        )
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            clear_medal[score.id] = clear_medal[
                score.id
            ] | self.__format_medal_for_score(score)
            hiscore_index = (score.id * 4) + {
                self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
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

        hiscore = bytes(hiscore_array)

        player_card.add_child(Node.s16_array("best_music", most_played[0:3]))
        base.add_child(Node.s16_array("my_best", most_played))
        base.add_child(Node.s16_array("latest_music", last_played))
        base.add_child(Node.u16_array("clear_medal", clear_medal))
        base.add_child(Node.u8_array("clear_medal_sub", clear_medal_sub))

        # Goes outside of base for some reason
        root.add_child(Node.binary("hiscore", hiscore))

        # Net VS section
        netvs = Node.void("netvs")
        root.add_child(netvs)
        netvs.add_child(Node.s32_array("get_ojama", [0, 0]))
        netvs.add_child(Node.s32("rank_point", 0))
        netvs.add_child(Node.s32("play_point", 0))
        netvs.add_child(Node.s16_array("record", [0, 0, 0, 0, 0, 0]))
        netvs.add_child(Node.u8("rank", 0))
        netvs.add_child(Node.s8_array("ojama_condition", [0] * 74))
        netvs.add_child(Node.s8_array("set_ojama", [0, 0, 0]))
        netvs.add_child(Node.s8_array("set_recommend", [0, 0, 0]))
        netvs.add_child(Node.s8_array("jewelry", [0] * 15))
        for dialog in [0, 1, 2, 3, 4, 5]:
            netvs.add_child(Node.string("dialog", f"dialog#{dialog}"))

        sp_data = Node.void("sp_data")
        root.add_child(sp_data)
        sp_data.add_child(Node.s32("sp", profile.get_int("sp", 0)))

        reflec_data = Node.void("reflec_data")
        root.add_child(reflec_data)
        reflec_data.add_child(
            Node.s8_array("reflec", profile.get_int_array("reflec", 2))
        )

        # Navigate section
        for i in range(3):
            navigate_dict = profile.get_dict(f"navigate_{i}")
            navigate = Node.void("navigate")
            root.add_child(navigate)
            navigate.add_child(Node.s8("genre", navigate_dict.get_int("genre", -1)))
            navigate.add_child(Node.s8("image", navigate_dict.get_int("image", -1)))
            navigate.add_child(Node.s8("level", navigate_dict.get_int("level", -1)))
            navigate.add_child(Node.s8("ojama", navigate_dict.get_int("ojama", -1)))
            navigate.add_child(
                Node.s16("limit_num", navigate_dict.get_int("limit_num", -1))
            )
            navigate.add_child(Node.s8("button", navigate_dict.get_int("button", -1)))
            navigate.add_child(Node.s8("life", navigate_dict.get_int("life", -1)))
            navigate.add_child(
                Node.s16("progress", navigate_dict.get_int("progress", -1))
            )

        return root

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("playerdata")

        root.add_child(Node.string("name", profile.get_str("name", "なし")))
        root.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        root.add_child(Node.s32("option", profile.get_int("option", 0)))
        root.add_child(Node.u8("version", 0))
        root.add_child(Node.u8("kind", 0))
        root.add_child(Node.u8("season", 0))

        clear_medal = [0] * self.GAME_MAX_MUSIC_ID
        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)

        scores = self.data.remote.music.get_scores(
            self.game, self.music_version, userid
        )
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            clear_medal[score.id] = clear_medal[
                score.id
            ] | self.__format_medal_for_score(score)
            hiscore_index = (score.id * 4) + {
                self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
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

        root.add_child(Node.u16_array("clear_medal", clear_medal))
        root.add_child(Node.binary("hiscore", bytes(hiscore_array)))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        # For some reason, Pop'n 20 sends us two profile saves, one with 'not done yet'
        # so we only want to process the done yet node. The 'not gameover' save has
        # jubeat collabo stuff set in it, but we don't use that so it doesn't matter.
        if request.child_value("is_not_gameover") == 1:
            return oldprofile

        newprofile = oldprofile.clone()
        newprofile.replace_int("option", request.child_value("option"))
        newprofile.replace_int("chara", request.child_value("chara"))
        newprofile.replace_int("mode", request.child_value("mode"))
        newprofile.replace_int("button", request.child_value("button"))
        newprofile.replace_int("music", request.child_value("music"))
        newprofile.replace_int("sheet", request.child_value("sheet"))
        newprofile.replace_int("last_play_flag", request.child_value("last_play_flag"))
        newprofile.replace_int("category", request.child_value("category"))
        newprofile.replace_int("sub_category", request.child_value("sub_category"))
        newprofile.replace_int("chara_category", request.child_value("chara_category"))
        newprofile.replace_int(
            "medal_and_friend", request.child_value("medal_and_friend")
        )
        newprofile.replace_int("ep", request.child_value("ep"))
        newprofile.replace_int_array(
            "sp_color_flg", 2, request.child_value("sp_color_flg")
        )
        newprofile.replace_int("read_news", request.child_value("read_news"))
        newprofile.replace_int(
            "consecutive_days_coupon", request.child_value("consecutive_days_coupon")
        )
        newprofile.replace_int("tutorial", request.child_value("tutorial"))
        newprofile.replace_int("music_open_pt", request.child_value("music_open_pt"))
        newprofile.replace_int("collabo", request.child_value("collabo"))

        sp_node = request.child("sp_data")
        if sp_node is not None:
            newprofile.replace_int("sp", sp_node.child_value("sp"))

        reflec_node = request.child("reflec_data")
        if reflec_node is not None:
            newprofile.replace_int_array("reflec", 2, reflec_node.child_value("reflec"))

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract player card stuff
        player_card_dict = newprofile.get_dict("player_card")
        player_card_dict.replace_int_array("title", 2, request.child_value("title"))
        player_card_dict.replace_int("frame", request.child_value("frame"))
        player_card_dict.replace_int("base", request.child_value("base"))
        player_card_dict.replace_int_array("seal", 2, request.child_value("seal"))
        player_card_dict.replace_int_array(
            "get_title", 4, request.child_value("get_title")
        )
        player_card_dict.replace_int("get_frame", request.child_value("get_frame"))
        player_card_dict.replace_int("get_base", request.child_value("get_base"))
        player_card_dict.replace_int_array(
            "get_seal", 2, request.child_value("get_seal")
        )

        player_card_ex = request.child("player_card_ex")
        if player_card_ex is not None:
            player_card_dict.replace_int(
                "get_title_ex", player_card_ex.child_value("get_title_ex")
            )
            player_card_dict.replace_int(
                "get_frame_ex", player_card_ex.child_value("get_frame_ex")
            )
            player_card_dict.replace_int(
                "get_base_ex", player_card_ex.child_value("get_base_ex")
            )
            player_card_dict.replace_int(
                "get_seal_ex", player_card_ex.child_value("get_seal_ex")
            )
        newprofile.replace_dict("player_card", player_card_dict)

        # Extract navigate stuff
        nav_id = 0
        for navigate in request.children:
            if navigate.name == "navigate":
                navigate_dict = newprofile.get_dict(f"navigate_{nav_id}")
                navigate_dict.replace_int("genre", navigate.child_value("genre"))
                navigate_dict.replace_int("image", navigate.child_value("image"))
                navigate_dict.replace_int("level", navigate.child_value("level"))
                navigate_dict.replace_int("ojama", navigate.child_value("ojama"))
                navigate_dict.replace_int(
                    "limit_num", navigate.child_value("limit_num")
                )
                navigate_dict.replace_int("button", navigate.child_value("button"))
                navigate_dict.replace_int("life", navigate.child_value("life"))
                navigate_dict.replace_int("progress", navigate.child_value("progress"))
                newprofile.replace_dict(f"navigate_{nav_id}", navigate_dict)
                nav_id += 1

            if nav_id >= 3:
                break

        # Extract scores
        for node in request.children:
            if node.name == "stage":
                songid = node.child_value("no")
                chart = {
                    self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
                    self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                    self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                    self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
                }.get(node.child_value("sheet"))
                if chart is None:
                    # Some old versions of Fantasia still send empty chart data for Tune Street
                    # charts that don't exist in the game. Ignore these or we end up crashing on
                    # profile save.
                    continue
                medal = (node.child_value("n_data") >> (chart * 4)) & 0x000F
                medal = {
                    self.GAME_PLAY_MEDAL_CIRCLE_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
                    self.GAME_PLAY_MEDAL_DIAMOND_FAILED: self.PLAY_MEDAL_DIAMOND_FAILED,
                    self.GAME_PLAY_MEDAL_STAR_FAILED: self.PLAY_MEDAL_STAR_FAILED,
                    self.GAME_PLAY_MEDAL_CIRCLE_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
                    self.GAME_PLAY_MEDAL_DIAMOND_CLEARED: self.PLAY_MEDAL_DIAMOND_CLEARED,
                    self.GAME_PLAY_MEDAL_STAR_CLEARED: self.PLAY_MEDAL_STAR_CLEARED,
                    self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_STAR_FULL_COMBO: self.PLAY_MEDAL_STAR_FULL_COMBO,
                    self.GAME_PLAY_MEDAL_PERFECT: self.PLAY_MEDAL_PERFECT,
                }[medal]
                points = node.child_value("score")
                self.update_score(userid, songid, chart, points, medal)

        return newprofile

    def handle_playerdata_expire_request(self, request: Node) -> Node:
        return Node.void("playerdata")

    def handle_playerdata_logout_request(self, request: Node) -> Node:
        return Node.void("playerdata")

    def handle_playerdata_get_request(self, request: Node) -> Node:
        modelstring = request.attribute("model")
        refid = request.child_value("ref_id")
        root = self.get_profile_by_refid(
            refid,
            self.NEW_PROFILE_ONLY if modelstring is None else self.OLD_PROFILE_ONLY,
        )
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_playerdata_conversion_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        chara = request.child_value("chara")
        root = self.new_profile_by_refid(refid, name, chara)
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_playerdata_new_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_playerdata_set_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        machine = self.get_machine()

        root = Node.void("playerdata")
        root.add_child(
            Node.s8("pref", machine.data.get_int("pref", self.get_machine_region()))
        )

        if refid is None:
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s16("chara", -1))
            root.add_child(Node.u8("frame", 0))
            root.add_child(Node.u8("base", 0))
            root.add_child(Node.u8("seal_1", 0))
            root.add_child(Node.u8("seal_2", 0))
            root.add_child(Node.u8("title_1", 0))
            root.add_child(Node.u8("title_2", 0))
            root.add_child(Node.s16("recommend_1", -1))
            root.add_child(Node.s16("recommend_2", -1))
            root.add_child(Node.s16("recommend_3", -1))
            root.add_child(Node.string("message", ""))
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s16("chara", -1))
            root.add_child(Node.u8("frame", 0))
            root.add_child(Node.u8("base", 0))
            root.add_child(Node.u8("seal_1", 0))
            root.add_child(Node.u8("seal_2", 0))
            root.add_child(Node.u8("title_1", 0))
            root.add_child(Node.u8("title_2", 0))
            root.add_child(Node.s16("recommend_1", -1))
            root.add_child(Node.s16("recommend_2", -1))
            root.add_child(Node.s16("recommend_3", -1))
            root.add_child(Node.string("message", ""))
            return root

        oldprofile = self.get_profile(userid) or Profile(
            self.game, self.version, refid, 0
        )
        newprofile = self.unformat_profile(userid, request, oldprofile)

        if newprofile is not None:
            player_card_dict = newprofile.get_dict("player_card")

            self.put_profile(userid, newprofile)
            root.add_child(Node.string("name", newprofile.get_str("name", "なし")))
            root.add_child(Node.s16("chara", newprofile.get_int("chara", -1)))
            root.add_child(Node.u8("frame", player_card_dict.get_int("frame")))
            root.add_child(Node.u8("base", player_card_dict.get_int("base")))
            root.add_child(
                Node.u8("seal_1", player_card_dict.get_int_array("seal", 2)[0])
            )
            root.add_child(
                Node.u8("seal_2", player_card_dict.get_int_array("seal", 2)[1])
            )
            root.add_child(
                Node.u8(
                    "title_1", player_card_dict.get_int_array("title", 2, [0, 1])[0]
                )
            )
            root.add_child(
                Node.u8(
                    "title_2", player_card_dict.get_int_array("title", 2, [0, 1])[1]
                )
            )
            root.add_child(Node.s16("recommend_1", -1))
            root.add_child(Node.s16("recommend_2", -1))
            root.add_child(Node.s16("recommend_3", -1))
            root.add_child(Node.string("message", ""))

        return root

    def handle_playerdata_friend_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        root = Node.void("playerdata")

        # Look up our own user ID based on the RefID provided.
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root.set_attribute("status", str(Status.NO_PROFILE))
            return root

        # Grab the links that we care about.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        profiles: Dict[UserID, Profile] = {}
        rivals: List[Link] = []
        for link in links:
            if link.type != "rival":
                continue

            other_profile = self.get_profile(link.other_userid)
            if other_profile is None:
                continue
            profiles[link.other_userid] = other_profile
            rivals.append(link)

        for rival in links[:2]:
            rivalid = rival.other_userid
            rivalprofile = profiles[rivalid]
            scores = self.data.remote.music.get_scores(
                self.game, self.music_version, rivalid
            )

            # First, output general profile info.
            friend = Node.void("friend")
            root.add_child(friend)

            # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
            # ranking numbers disappear and the player icon show a questionmark.
            friend.add_child(Node.s8("open", 1))

            # Set up some sane defaults.
            friend.add_child(Node.string("name", rivalprofile.get_str("name", "なし")))
            friend.add_child(
                Node.string("g_pm_id", ID.format_extid(rivalprofile.extid))
            )
            friend.add_child(Node.s16("chara", rivalprofile.get_int("chara", -1)))

            # Perform hiscore/medal conversion.
            hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)
            clear_medal = [0] * self.GAME_MAX_MUSIC_ID
            for score in scores:
                if score.id > self.GAME_MAX_MUSIC_ID:
                    continue

                # Skip any scores for chart types we don't support
                if score.chart not in [
                    self.CHART_TYPE_EASY,
                    self.CHART_TYPE_NORMAL,
                    self.CHART_TYPE_HYPER,
                    self.CHART_TYPE_EX,
                ]:
                    continue
                if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                    continue

                clear_medal[score.id] = clear_medal[
                    score.id
                ] | self.__format_medal_for_score(score)
                hiscore_index = (score.id * 4) + {
                    self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                    self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                    self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                    self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
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

            hiscore = bytes(hiscore_array)
            friend.add_child(Node.u16_array("clear_medal", clear_medal))
            friend.add_child(Node.binary("hiscore", hiscore))

            # Note that if we ever support internet ranking mode, there's an 'ir_hiscore' node here as well.

            # Also note that if we support lobbies, there's a few extra nodes in each friend for current lobby
            # that they're in as well as previous lobby logs.

        return root

    def handle_game_get_request(self, request: Node) -> Node:
        game_config = self.get_game_config()
        game_phase = game_config.get_int("game_phase")
        event_phase = game_config.get_int("event_phase")

        root = Node.void("game")
        root.add_child(Node.s32("game_phase", game_phase))
        root.add_child(Node.s32("ir_phase", 0))
        root.add_child(Node.s32("event_phase", event_phase))
        root.add_child(
            Node.s32("netvs_phase", 0)
        )  # Net taisen mode, we don't support lobbies.
        root.add_child(Node.s32("card_phase", 6))
        root.add_child(Node.s32("illust_phase", 2))
        root.add_child(
            Node.s32("psp_phase", 5)
        )  # Unlock songs from Pop'n Music Portable.
        root.add_child(Node.s32("other_phase", 1))
        root.add_child(Node.s32("jubeat_phase", 1))
        root.add_child(Node.s32("public_phase", 3))
        root.add_child(Node.s32("kac_phase", 2))
        root.add_child(Node.s32("local_matching_enable", 1))
        root.add_child(Node.s32("n_matching_sec", 60))
        root.add_child(Node.s32("l_matching_sec", 60))
        root.add_child(Node.s32("is_check_cpu", 0))
        root.add_child(Node.s32("week_no", 0))
        root.add_child(Node.s32("team_day", 0))
        root.add_child(Node.s32_array("ng_illust", [-1] * 64))
        root.add_child(Node.s16_array("sel_ranking", [-1] * 10))
        root.add_child(Node.s16_array("up_ranking", [-1] * 10))

        return root

    def handle_game_active_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes. Also store the prefecture.
        machine = self.get_machine()
        machine.name = request.child_value("shop_name") or machine.name
        machine.data.replace_int("pref", request.child_value("pref"))
        self.update_machine(machine)
        return Node.void("game")

    def handle_lobby_requests(self, request: Node) -> Node:
        # Stub out the entire lobby service
        return Node.void("lobby")
