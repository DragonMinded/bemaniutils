# vim: set fileencoding=utf-8
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.fantasia import PopnMusicFantasia

from bemani.backend.base import Status
from bemani.common import Profile, VersionConstants, ID
from bemani.data import UserID, Link, Score
from bemani.protocol import Node


class PopnMusicSunnyPark(PopnMusicBase):
    name: str = "Pop'n Music Sunny Park"
    version: int = VersionConstants.POPN_MUSIC_SUNNY_PARK

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY: Final[int] = 0
    GAME_CHART_TYPE_NORMAL: Final[int] = 1
    GAME_CHART_TYPE_HYPER: Final[int] = 2
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
    GAME_MAX_MUSIC_ID: Final[int] = 1350

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicFantasia(self.data, self.config, self.model)

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
                        0: "No music unlocks",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase 3",
                        4: "Phase 4",
                        5: "Phase 5",
                        6: "Phase 6",
                        7: "Phase 7",
                        8: "Phase 8",
                        9: "Phase MAX",
                    },
                },
                {
                    "name": "Event Phase",
                    "tip": "Event phase for all players.",
                    "category": "game_config",
                    "setting": "event_phase",
                    "values": {
                        0: "No event",
                        1: "Pop'n Walker Phase 1",
                        2: "Pop'n Walker Phase 2",
                        3: "Pop'n Walker Phase 3",
                        # Phase 4 turns off Pop'n Walker but does not enable
                        # Wai Wai Pop'n Zoo so I've left it out.
                        # Phase 5 appears to be identical to phase 6 below.
                        6: "Wai Wai Pop'n Zoo Phase 1: Elephants",
                        # Phase 7 appears to be identical to phase 8 below.
                        8: "Wai Wai Pop'n Zoo Phase 2: Dog",
                        9: "Wai Wai Pop'n Zoo Phase 3: Alpaca",
                        10: "Wai Wai Pop'n Zoo Phase 4: Cow",
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
        medal_pos = {
            self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
            self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
            self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
            self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
        }[score.chart]
        return medal << (medal_pos * 4)

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
        base.add_child(Node.u8("medal_and_friend", profile.get_int("medal_and_friend", 0)))
        base.add_child(Node.s8("category", profile.get_int("category", -1)))
        base.add_child(Node.s8("sub_category", profile.get_int("sub_category", -1)))
        base.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        base.add_child(Node.s8("chara_category", profile.get_int("chara_category", -1)))
        base.add_child(Node.u8("collabo", 255))
        base.add_child(Node.u8("sheet", profile.get_int("sheet", 0)))
        base.add_child(Node.s8("tutorial", profile.get_int("tutorial", 0)))
        base.add_child(Node.s8("music_open_pt", profile.get_int("music_open_pt", 0)))
        base.add_child(Node.s8("is_conv", -1))
        base.add_child(Node.s32("option", profile.get_int("option", 0)))
        base.add_child(Node.s16("music", profile.get_int("music", -1)))
        base.add_child(Node.u16("ep", profile.get_int("ep", 0)))
        base.add_child(Node.s32_array("sp_color_flg", profile.get_int_array("sp_color_flg", 2)))
        base.add_child(Node.s32("read_news", profile.get_int("read_news", 0)))
        base.add_child(Node.s16("consecutive_days_coupon", profile.get_int("consecutive_days_coupon", 0)))
        base.add_child(Node.s8("staff", 0))
        # These are probably from an old event, but if they aren't present and defaulted,
        # then different songs show up in the Zoo event.
        base.add_child(
            Node.u16_array(
                "gitadora_point",
                profile.get_int_array("gitadora_point", 3, [2000, 2000, 2000]),
            )
        )
        base.add_child(Node.u8("gitadora_select", profile.get_int("gitadora_select", 2)))

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

        last_played = [x[0] for x in self.data.local.music.get_last_played(self.game, self.music_version, userid, 3)]
        most_played = [x[0] for x in self.data.local.music.get_most_played(self.game, self.music_version, userid, 20)]
        while len(last_played) < 3:
            last_played.append(-1)
        while len(most_played) < 20:
            most_played.append(-1)

        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 4) * 17) + 7) / 8)
        clear_medal = [0] * self.GAME_MAX_MUSIC_ID
        clear_medal_sub = [0] * self.GAME_MAX_MUSIC_ID

        scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
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

            clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)
            hiscore_index = (score.id * 4) + {
                self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
            }[score.chart]
            hiscore_byte_pos = int((hiscore_index * 17) / 8)
            hiscore_bit_pos = int((hiscore_index * 17) % 8)
            hiscore_value = score.points << hiscore_bit_pos
            hiscore_array[hiscore_byte_pos] = hiscore_array[hiscore_byte_pos] | (hiscore_value & 0xFF)
            hiscore_array[hiscore_byte_pos + 1] = hiscore_array[hiscore_byte_pos + 1] | ((hiscore_value >> 8) & 0xFF)
            hiscore_array[hiscore_byte_pos + 2] = hiscore_array[hiscore_byte_pos + 2] | ((hiscore_value >> 16) & 0xFF)

        hiscore = bytes(hiscore_array)

        base.add_child(Node.s16_array("my_best", most_played))
        base.add_child(Node.s16_array("latest_music", last_played))
        base.add_child(Node.u16_array("clear_medal", clear_medal))
        base.add_child(Node.u8_array("clear_medal_sub", clear_medal_sub))

        # Goes outside of base for some reason
        root.add_child(Node.binary("hiscore", hiscore))

        # Avatar section
        avatar_dict = profile.get_dict("avatar")
        avatar = Node.void("avatar")
        root.add_child(avatar)
        avatar.add_child(Node.u8("hair", avatar_dict.get_int("hair", 0)))
        avatar.add_child(Node.u8("face", avatar_dict.get_int("face", 0)))
        avatar.add_child(Node.u8("body", avatar_dict.get_int("body", 0)))
        avatar.add_child(Node.u8("effect", avatar_dict.get_int("effect", 0)))
        avatar.add_child(Node.u8("object", avatar_dict.get_int("object", 0)))
        avatar.add_child(Node.u8_array("comment", avatar_dict.get_int_array("comment", 2)))
        avatar.add_child(Node.s32_array("get_hair", avatar_dict.get_int_array("get_hair", 2)))
        avatar.add_child(Node.s32_array("get_face", avatar_dict.get_int_array("get_face", 2)))
        avatar.add_child(Node.s32_array("get_body", avatar_dict.get_int_array("get_body", 2)))
        avatar.add_child(Node.s32_array("get_effect", avatar_dict.get_int_array("get_effect", 2)))
        avatar.add_child(Node.s32_array("get_object", avatar_dict.get_int_array("get_object", 2)))
        avatar.add_child(Node.s32_array("get_comment_over", avatar_dict.get_int_array("get_comment_over", 3)))
        avatar.add_child(Node.s32_array("get_comment_under", avatar_dict.get_int_array("get_comment_under", 3)))

        # Avatar add section
        avatar_add_dict = profile.get_dict("avatar_add")
        avatar_add = Node.void("avatar_add")
        root.add_child(avatar_add)
        avatar_add.add_child(Node.s32_array("get_hair", avatar_add_dict.get_int_array("get_hair", 2)))
        avatar_add.add_child(Node.s32_array("get_face", avatar_add_dict.get_int_array("get_face", 2)))
        avatar_add.add_child(Node.s32_array("get_body", avatar_add_dict.get_int_array("get_body", 2)))
        avatar_add.add_child(Node.s32_array("get_effect", avatar_add_dict.get_int_array("get_effect", 2)))
        avatar_add.add_child(Node.s32_array("get_object", avatar_add_dict.get_int_array("get_object", 2)))
        avatar_add.add_child(Node.s32_array("get_comment_over", avatar_add_dict.get_int_array("get_comment_over", 2)))
        avatar_add.add_child(
            Node.s32_array(
                "get_comment_under",
                avatar_add_dict.get_int_array("get_comment_under", 2),
            )
        )
        avatar_add.add_child(Node.s32_array("new_hair", avatar_add_dict.get_int_array("new_hair", 2)))
        avatar_add.add_child(Node.s32_array("new_face", avatar_add_dict.get_int_array("new_face", 2)))
        avatar_add.add_child(Node.s32_array("new_body", avatar_add_dict.get_int_array("new_body", 2)))
        avatar_add.add_child(Node.s32_array("new_effect", avatar_add_dict.get_int_array("new_effect", 2)))
        avatar_add.add_child(Node.s32_array("new_object", avatar_add_dict.get_int_array("new_object", 2)))
        avatar_add.add_child(Node.s32_array("new_comment_over", avatar_add_dict.get_int_array("new_comment_over", 2)))
        avatar_add.add_child(
            Node.s32_array(
                "new_comment_under",
                avatar_add_dict.get_int_array("new_comment_under", 2),
            )
        )

        # Net VS section
        netvs = Node.void("netvs")
        root.add_child(netvs)
        netvs.add_child(Node.s32("rank_point", 0))
        netvs.add_child(Node.s16_array("record", [0, 0, 0, 0, 0, 0]))
        netvs.add_child(Node.u8("rank", 0))
        netvs.add_child(Node.s8("vs_rank_old", 0))
        netvs.add_child(Node.s8_array("ojama_condition", [0] * 74))
        netvs.add_child(Node.s8_array("set_ojama", [0, 0, 0]))
        netvs.add_child(Node.s8_array("set_recommend", [0, 0, 0]))
        netvs.add_child(Node.u8("netvs_play_cnt", 0))
        for dialog in [0, 1, 2, 3, 4, 5]:
            netvs.add_child(Node.string("dialog", f"dialog#{dialog}"))

        sp_data = Node.void("sp_data")
        root.add_child(sp_data)
        sp_data.add_child(Node.s32("sp", profile.get_int("sp", 0)))

        gakuen = Node.void("gakuen_data")
        root.add_child(gakuen)
        gakuen.add_child(Node.s32("music_list", -1))

        saucer = Node.void("flying_saucer")
        root.add_child(saucer)
        saucer.add_child(Node.s32("music_list", -1))
        saucer.add_child(Node.s32("tune_count", -1))
        saucer.add_child(Node.u32("clear_norma", 0))
        saucer.add_child(Node.u32("clear_norma_add", 0))

        # Wai Wai Pop'n Zoo event
        zoo_dict = profile.get_dict("zoo")
        zoo = Node.void("zoo")
        root.add_child(zoo)
        zoo.add_child(Node.u16_array("point", zoo_dict.get_int_array("point", 5)))
        zoo.add_child(Node.s32_array("music_list", zoo_dict.get_int_array("music_list", 2)))
        zoo.add_child(Node.s8_array("today_play_flag", zoo_dict.get_int_array("today_play_flag", 4)))

        # Pop'n Walker event
        personal_event_dict = profile.get_dict("personal_event")
        personal_event = Node.void("personal_event")
        root.add_child(personal_event)
        personal_event.add_child(Node.s16_array("pos", personal_event_dict.get_int_array("pos", 2)))
        personal_event.add_child(Node.s16("point", personal_event_dict.get_int("point")))
        personal_event.add_child(Node.u32_array("walk_data", personal_event_dict.get_int_array("walk_data", 128)))
        personal_event.add_child(Node.u32_array("event_data", personal_event_dict.get_int_array("event_data", 4)))

        # We don't support triple journey, so this is stubbed out.
        triple = Node.void("triple_journey")
        root.add_child(triple)
        triple.add_child(Node.s32("music_list", -1))
        triple.add_child(Node.s32_array("boss_damage", [65534, 65534, 65534, 65534]))
        triple.add_child(Node.s32_array("boss_stun", [0, 0, 0, 0]))
        triple.add_child(Node.s32("magic_gauge", 0))
        triple.add_child(Node.s32("today_party", 0))
        triple.add_child(Node.bool("union_magic", False))
        triple.add_child(Node.float("base_attack_rate", 1.0))
        triple.add_child(Node.s32("iidx_play_num", 0))
        triple.add_child(Node.s32("reflec_play_num", 0))
        triple.add_child(Node.s32("voltex_play_num", 0))
        triple.add_child(Node.bool("iidx_play_flg", True))
        triple.add_child(Node.bool("reflec_play_flg", True))
        triple.add_child(Node.bool("voltex_play_flg", True))

        ios = Node.void("ios")
        root.add_child(ios)
        ios.add_child(Node.s32("continueRightAnswer", 30))
        ios.add_child(Node.s32("totalRightAnswer", 30))

        kac2013 = Node.void("kac2013")
        root.add_child(kac2013)
        kac2013.add_child(Node.s8("music_num", 0))
        kac2013.add_child(Node.s16("music", 0))
        kac2013.add_child(Node.u8("sheet", 0))

        baseball = Node.void("baseball_data")
        root.add_child(baseball)
        baseball.add_child(Node.s64("music_list", -1))

        for id in [3, 5, 7]:
            node = Node.void("floor_infection")
            root.add_child(node)
            node.add_child(Node.s32("infection_id", id))
            node.add_child(Node.s32("music_list", -1))

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

        scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
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

            clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)

        root.add_child(Node.u16_array("clear_medal", clear_medal))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
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
        newprofile.replace_int("medal_and_friend", request.child_value("medal_and_friend"))
        newprofile.replace_int("ep", request.child_value("ep"))
        newprofile.replace_int_array("sp_color_flg", 2, request.child_value("sp_color_flg"))
        newprofile.replace_int("read_news", request.child_value("read_news"))
        newprofile.replace_int("consecutive_days_coupon", request.child_value("consecutive_days_coupon"))
        newprofile.replace_int("tutorial", request.child_value("tutorial"))
        newprofile.replace_int("music_open_pt", request.child_value("music_open_pt"))
        newprofile.replace_int_array("gitadora_point", 3, request.child_value("gitadora_point"))
        newprofile.replace_int("gitadora_select", request.child_value("gitadora_select"))

        sp_node = request.child("sp_data")
        if sp_node is not None:
            newprofile.replace_int("sp", sp_node.child_value("sp"))

        zoo_dict = newprofile.get_dict("zoo")
        zoo_node = request.child("zoo")
        if zoo_node is not None:
            zoo_dict.replace_int_array("point", 5, zoo_node.child_value("point"))
            zoo_dict.replace_int_array("music_list", 2, zoo_node.child_value("music_list"))
            zoo_dict.replace_int_array("today_play_flag", 4, zoo_node.child_value("today_play_flag"))
        newprofile.replace_dict("zoo", zoo_dict)

        personal_event_dict = newprofile.get_dict("personal_event")
        personal_event_node = request.child("personal_event")
        if personal_event_node is not None:
            personal_event_dict.replace_int_array("pos", 2, personal_event_node.child_value("pos"))
            personal_event_dict.replace_int("point", personal_event_node.child_value("point"))
            personal_event_dict.replace_int_array("walk_data", 128, personal_event_node.child_value("walk_data"))
            personal_event_dict.replace_int_array("event_data", 4, personal_event_node.child_value("event_data"))
        newprofile.replace_dict("personal_event", personal_event_dict)

        avatar_dict = newprofile.get_dict("avatar")
        avatar_dict.replace_int("hair", request.child_value("hair"))
        avatar_dict.replace_int("face", request.child_value("face"))
        avatar_dict.replace_int("body", request.child_value("body"))
        avatar_dict.replace_int("effect", request.child_value("effect"))
        avatar_dict.replace_int("object", request.child_value("object"))
        avatar_dict.replace_int_array("comment", 2, request.child_value("comment"))
        avatar_dict.replace_int_array("get_hair", 2, request.child_value("get_hair"))
        avatar_dict.replace_int_array("get_face", 2, request.child_value("get_face"))
        avatar_dict.replace_int_array("get_body", 2, request.child_value("get_body"))
        avatar_dict.replace_int_array("get_effect", 2, request.child_value("get_effect"))
        avatar_dict.replace_int_array("get_object", 2, request.child_value("get_object"))
        avatar_dict.replace_int_array("get_comment_over", 3, request.child_value("get_comment_over"))
        avatar_dict.replace_int_array("get_comment_under", 3, request.child_value("get_comment_under"))
        newprofile.replace_dict("avatar", avatar_dict)

        avatar_add_dict = newprofile.get_dict("avatar_add")
        avatar_add_node = request.child("avatar_add")
        if avatar_add_node is not None:
            avatar_add_dict.replace_int_array("get_hair", 2, avatar_add_node.child_value("get_hair"))
            avatar_add_dict.replace_int_array("get_face", 2, avatar_add_node.child_value("get_face"))
            avatar_add_dict.replace_int_array("get_body", 2, avatar_add_node.child_value("get_body"))
            avatar_add_dict.replace_int_array("get_effect", 2, avatar_add_node.child_value("get_effect"))
            avatar_add_dict.replace_int_array("get_object", 2, avatar_add_node.child_value("get_object"))
            avatar_add_dict.replace_int_array("get_comment_over", 2, avatar_add_node.child_value("get_comment_over"))
            avatar_add_dict.replace_int_array("get_comment_under", 2, avatar_add_node.child_value("get_comment_under"))
            avatar_add_dict.replace_int_array("new_hair", 2, avatar_add_node.child_value("new_hair"))
            avatar_add_dict.replace_int_array("new_face", 2, avatar_add_node.child_value("new_face"))
            avatar_add_dict.replace_int_array("new_body", 2, avatar_add_node.child_value("new_body"))
            avatar_add_dict.replace_int_array("new_effect", 2, avatar_add_node.child_value("new_effect"))
            avatar_add_dict.replace_int_array("new_object", 2, avatar_add_node.child_value("new_object"))
            avatar_add_dict.replace_int_array("new_comment_over", 2, avatar_add_node.child_value("new_comment_over"))
            avatar_add_dict.replace_int_array("new_comment_under", 2, avatar_add_node.child_value("new_comment_under"))
        newprofile.replace_dict("avatar_add", avatar_add_dict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract scores
        for node in request.children:
            if node.name == "stage":
                songid = node.child_value("no")
                chart = {
                    self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
                    self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                    self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                    self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
                }[node.child_value("sheet")]
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

    def handle_game_get_request(self, request: Node) -> Node:
        game_config = self.get_game_config()
        event_phase = game_config.get_int("event_phase")
        music_phase = game_config.get_int("music_phase")

        root = Node.void("game")
        root.add_child(Node.s32("ir_phase", 0))
        root.add_child(Node.s32("music_open_phase", music_phase))
        root.add_child(Node.s32("collabo_phase", 8))
        root.add_child(Node.s32("personal_event_phase", event_phase))
        root.add_child(Node.s32("shop_event_phase", 6))
        root.add_child(Node.s32("netvs_phase", 0))
        root.add_child(Node.s32("card_phase", 9))
        root.add_child(Node.s32("other_phase", 9))
        root.add_child(Node.s32("local_matching_enable", 1))
        root.add_child(Node.s32("n_matching_sec", 60))
        root.add_child(Node.s32("l_matching_sec", 60))
        root.add_child(Node.s32("is_check_cpu", 0))
        root.add_child(Node.s32("week_no", 0))
        root.add_child(Node.s16_array("sel_ranking", [-1, -1, -1, -1, -1]))
        root.add_child(Node.s16_array("up_ranking", [-1, -1, -1, -1, -1]))
        return root

    def handle_game_active_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        machine = self.get_machine()
        machine.name = request.child_value("shop_name") or machine.name
        machine.data.replace_int("pref", request.child_value("pref"))
        self.update_machine(machine)
        return Node.void("game")

    def handle_game_taxphase_request(self, request: Node) -> Node:
        return Node.void("game")

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
        root.add_child(Node.s8("pref", machine.data.get_int("pref", self.get_machine_region())))
        if refid is None:
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s8("get_coupon_cnt", -1))
            root.add_child(Node.s16("chara", -1))
            root.add_child(Node.u8("hair", 0))
            root.add_child(Node.u8("face", 0))
            root.add_child(Node.u8("body", 0))
            root.add_child(Node.u8("effect", 0))
            root.add_child(Node.u8("object", 0))
            root.add_child(Node.u8("comment_1", 0))
            root.add_child(Node.u8("comment_2", 0))
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root.add_child(Node.string("name", ""))
            root.add_child(Node.s8("get_coupon_cnt", -1))
            root.add_child(Node.s16("chara", -1))
            root.add_child(Node.u8("hair", 0))
            root.add_child(Node.u8("face", 0))
            root.add_child(Node.u8("body", 0))
            root.add_child(Node.u8("effect", 0))
            root.add_child(Node.u8("object", 0))
            root.add_child(Node.u8("comment_1", 0))
            root.add_child(Node.u8("comment_2", 0))
            return root

        oldprofile = self.get_profile(userid) or Profile(self.game, self.version, refid, 0)
        newprofile = self.unformat_profile(userid, request, oldprofile)

        if newprofile is not None:
            self.put_profile(userid, newprofile)
            avatar_dict = newprofile.get_dict("avatar")

            root.add_child(Node.string("name", newprofile["name"]))
            root.add_child(Node.s8("get_coupon_cnt", -1))
            root.add_child(Node.s16("chara", newprofile.get_int("chara", -1)))
            root.add_child(Node.u8("hair", avatar_dict.get_int("hair", 0)))
            root.add_child(Node.u8("face", avatar_dict.get_int("face", 0)))
            root.add_child(Node.u8("body", avatar_dict.get_int("body", 0)))
            root.add_child(Node.u8("effect", avatar_dict.get_int("effect", 0)))
            root.add_child(Node.u8("object", avatar_dict.get_int("object", 0)))
            root.add_child(Node.u8("comment_1", avatar_dict.get_int_array("comment", 2)[0]))
            root.add_child(Node.u8("comment_2", avatar_dict.get_int_array("comment", 2)[1]))

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
            scores = self.data.remote.music.get_scores(self.game, self.music_version, rivalid)

            # First, output general profile info.
            friend = Node.void("friend")
            root.add_child(friend)

            # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
            # ranking numbers disappear and the player icon show a questionmark.
            friend.add_child(Node.s8("open", 1))

            # Set up some sane defaults.
            friend.add_child(Node.string("name", rivalprofile.get_str("name", "なし")))
            friend.add_child(Node.string("g_pm_id", ID.format_extid(rivalprofile.extid)))
            friend.add_child(Node.s16("chara", rivalprofile.get_int("chara", -1)))

            # Set up player avatar.
            avatar_dict = rivalprofile.get_dict("avatar")
            friend.add_child(Node.u8("hair", avatar_dict.get_int("hair", 0)))
            friend.add_child(Node.u8("face", avatar_dict.get_int("face", 0)))
            friend.add_child(Node.u8("body", avatar_dict.get_int("body", 0)))
            friend.add_child(Node.u8("effect", avatar_dict.get_int("effect", 0)))
            friend.add_child(Node.u8("object", avatar_dict.get_int("object", 0)))
            friend.add_child(Node.u8_array("comment", avatar_dict.get_int_array("comment", 2)))

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

                clear_medal[score.id] = clear_medal[score.id] | self.__format_medal_for_score(score)
                hiscore_index = (score.id * 4) + {
                    self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY_POSITION,
                    self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                    self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                    self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX_POSITION,
                }[score.chart]
                hiscore_byte_pos = int((hiscore_index * 17) / 8)
                hiscore_bit_pos = int((hiscore_index * 17) % 8)
                hiscore_value = score.points << hiscore_bit_pos
                hiscore_array[hiscore_byte_pos] = hiscore_array[hiscore_byte_pos] | (hiscore_value & 0xFF)
                hiscore_array[hiscore_byte_pos + 1] = hiscore_array[hiscore_byte_pos + 1] | (
                    (hiscore_value >> 8) & 0xFF
                )
                hiscore_array[hiscore_byte_pos + 2] = hiscore_array[hiscore_byte_pos + 2] | (
                    (hiscore_value >> 16) & 0xFF
                )

            hiscore = bytes(hiscore_array)
            friend.add_child(Node.u16_array("clear_medal", clear_medal))
            friend.add_child(Node.binary("hiscore", hiscore))

        return root

    def handle_lobby_requests(self, request: Node) -> Node:
        # Stub out the entire lobby service
        return Node.void("lobby")
