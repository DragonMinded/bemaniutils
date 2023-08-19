# vim: set fileencoding=utf-8
import random
from typing import Any, Dict, List, Optional, Set, Tuple
from typing_extensions import Final

from bemani.backend.base import Status
from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.common import (
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
)
from bemani.backend.jubeat.prop import JubeatProp

from bemani.common import Profile, ValidatedDict, VersionConstants
from bemani.data import Data, Score, Song, UserID
from bemani.protocol import Node


class JubeatQubell(
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
    JubeatBase,
):
    name: str = "Jubeat Qubell"
    version: int = VersionConstants.JUBEAT_QUBELL

    JBOX_EMBLEM_NORMAL: Final[int] = 1
    JBOX_EMBLEM_PREMIUM: Final[int] = 2

    ENABLE_GARNET: Final[bool] = False

    EVENTS: Dict[int, Dict[str, bool]] = {
        5: {
            "enabled": False,
        },
        6: {
            "enabled": False,
        },
        15: {
            "enabled": False,
        },
        19: {
            "enabled": False,
        },
    }

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatProp(self.data, self.config, self.model)

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Dict[str, Any]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Insert daily FC challenges into the DB.
        """
        events = []
        if data.local.network.should_schedule(
            cls.game, cls.version, "fc_challenge", "daily"
        ):
            # Generate a new list of two FC challenge songs.
            start_time, end_time = data.local.network.get_schedule_duration("daily")
            all_songs = set(
                song.id
                for song in data.local.music.get_all_songs(cls.game, cls.version)
            )
            if len(all_songs) >= 2:
                daily_songs = random.sample(all_songs, 2)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "fc_challenge",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "today": daily_songs[0],
                        "whim": daily_songs[1],
                    },
                )
                events.append(
                    (
                        "jubeat_fc_challenge_charts",
                        {
                            "version": cls.version,
                            "today": daily_songs[0],
                            "whim": daily_songs[1],
                        },
                    )
                )

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "fc_challenge", "daily"
                )
        return events

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Force Unlock All Songs",
                    "tip": "Forces all songs to be available by default",
                    "category": "game_config",
                    "setting": "force_song_unlock",
                },
            ],
        }

    def __get_global_info(self) -> Node:
        info = Node.void("info")

        # Event info. Valid event IDs are 5, 6, 15, 19
        event_info = Node.void("event_info")
        info.add_child(event_info)
        for event in self.EVENTS:
            evt = Node.void("event")
            event_info.add_child(evt)
            evt.set_attribute("type", str(event))
            evt.add_child(Node.u8("state", 1 if self.EVENTS[event]["enabled"] else 0))

        # Each of the following two sections should have zero or more child nodes (no
        # particular name) which look like the following:
        #     <node>
        #         <id __type="s32">songid</id>
        #         <stime __type="str">start time?</stime>
        #         <etime __type="str">end time?</etime>
        #     </node>
        # Share music?
        share_music = Node.void("share_music")
        info.add_child(share_music)

        # Bonus music?
        bonus_music = Node.void("bonus_music")
        info.add_child(bonus_music)

        # Some sort of music DB whitelist
        info.add_child(
            Node.s32_array(
                "white_music_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "white_marker_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "white_theme_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "open_music_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        info.add_child(
            Node.s32_array(
                "shareable_music_list",
                [
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                    -1,
                ],
            )
        )

        jbox = Node.void("jbox")
        info.add_child(jbox)
        jbox.add_child(Node.s32("point", 0))
        emblem = Node.void("emblem")
        jbox.add_child(emblem)
        normal = Node.void("normal")
        emblem.add_child(normal)
        premium = Node.void("premium")
        emblem.add_child(premium)
        normal.add_child(Node.s16("index", 2))
        premium.add_child(Node.s16("index", 1))

        born = Node.void("born")
        info.add_child(born)
        born.add_child(Node.s8("status", 0))
        born.add_child(Node.s16("year", 0))

        digdig = Node.void("digdig")
        info.add_child(digdig)
        stage_list = Node.void("stage_list")
        digdig.add_child(stage_list)
        # Stage numbers are between 1 and 13 inclusive.
        for i in range(1, 14):
            stage = Node.void("stage")
            stage_list.add_child(stage)
            stage.set_attribute("number", str(i))
            stage.add_child(Node.u8("state", 0x1))

        # Collection list values should look like:
        #     <rating>
        #         <id __type="s32">songid</id>
        #         <stime __type="str">start time?</stime>
        #         <etime __type="str">end time?</etime>
        #     </node>
        collection = Node.void("collection")
        info.add_child(collection)
        collection.add_child(Node.void("rating_s"))

        # Additional digdig nodes that aren't the main event
        generic_dig = Node.void("generic_dig")
        info.add_child(generic_dig)
        map_list = Node.void("map_list")
        generic_dig.add_child(map_list)
        # DigDig nodes here have the following format:
        # <map release_code='somecode' dataversion='someversion' id='someid' client_map_kind='somekind'>
        #     <stime __type="str">start time?</stime>
        #     <etime __type="str">end time?</etime>
        #     <stage_list>
        #         <!-- stage number is between 1 and 14 inclusive here -->
        #         <stage number='number'>
        #             <need_point __type="s32">point</need_point>
        #             <need_norma_num __type="s32">norma num</need_point>
        #             <norma_list>
        #                 <norma>
        #                     <point __type="s32">point</point>
        #                     <!-- between 1 and 15 inclusive -->
        #                     <type __type="s32">type</type>
        #                     <music_id __type="s32">music_id</music_id>
        #                     <seq_difficulty __type="s32">seq_difficulty</seq_difficulty>
        #                     <rating __type="s32">rating</rating>
        #                     <stage_level __type="s32">stage_level</stage_level>
        #                     <goal __type="s32">goal</goalpoint>
        #                     <title_line_list>
        #                         <!-- there can be up to 4 of these -->
        #                         <title type="str">32 bytes long title</title>
        #                     </title_line_list>
        #                 </norma>
        #             </norma_list>
        #             <item_list>
        #                 <item>
        #                     <point __type="s32">point</point>
        #                     <!-- between 1 and 7 inclusive -->
        #                     <type __type="s32">type</type>
        #                     <music_id __type="s32">music_id</music_id>
        #                     <bonus_tune_point __type="s32">bonus_tune_point</bonus_tune_point>
        #                     <title_id __type="s32">title_id</title_id>
        #                     <marker_id __type="s32">marker_id</marker_id>
        #                     <background_id __type="s32">background_id</background_id>
        #                 </item>
        #             </item_list>
        #             <!-- unlock challenge -->
        #             <unlock>
        #                 <tune_list>
        #                     <!-- between 1 and 3 inclusive -->
        #                     <tune no='number'>
        #                         <seq_list>
        #                             <seq>
        #                                 <music_id __type="s32">music_id</music_id>
        #                                 <seq_difficulty __type="s32">seq_difficulty</seq_difficulty>
        #                                 <!-- flags are optional -->
        #                                 <flags __type="str">SECRET|empty</flags>
        #                             </seq>
        #                         </seq_list>
        #                     </tune>
        #                 </tune_list>
        #                 <flags __type="str">RISKY|empty</flags>
        #                 <!-- requirements for normal clear -->
        #                 <clear>
        #                     <type __type="s32">type</type>
        #                     <!-- between 0 and 8 inclusive -->
        #                     <rating __type="s32">rating</rating>
        #                     <score __type="s32">score</score>
        #                     <ex_option>
        #                         <is_hard __type="bool">true/false</is_hard>
        #                         <!-- between 0 and 6 inclusive -->
        #                         <hazard_type __type="s32">type</hazard_type>
        #                     </ex_option>
        #                 </clear>
        #                 <!-- requirements for gold clear -->
        #                 <gold>
        #                     <type __type="s32">type</type>
        #                     <!-- between 0 and 8 inclusive -->
        #                     <rating __type="s32">rating</rating>
        #                     <score __type="s32">score</score>
        #                     <ex_option>
        #                         <is_hard __type="bool">true/false</is_hard>
        #                         <!-- between 0 and 6 inclusive -->
        #                         <hazard_type __type="s32">type</hazard_type>
        #                     </ex_option>
        #                 </gold>
        #             </unlock>
        #             <serif_list>
        #                 <!-- kind should be between 1 and 6 inclusive -->
        #                 <serif kind='kind'>
        #                     <line_list>
        #                         <!-- there can be up to four of these -->
        #                         <line __type="str">64 byte string</str>
        #                     </line_list>
        #                 </serif>
        #             </serif_list>
        #             <bgm_list>
        #                 <!-- kind can be between 1 and 2 inclusive -->
        #                 <bgm kind='kind' id='id' />
        #             </bgm_list>
        #             <se_list>
        #                 <!-- kind can be between 1 and 20 inclusive -->
        #                 <se kind='kind' id='id' />
        #             </se_list>
        #             <!-- optional node -->
        #             <tex_number __type="s32">unknown</tex_number>
        #         </stage>
        #     </stage_list>
        # </map>

        expert_option = Node.void("expert_option")
        info.add_child(expert_option)
        expert_option.add_child(Node.bool("is_available", True))

        tsumtsum = Node.void("tsumtsum")
        info.add_child(tsumtsum)
        tsumtsum.add_child(Node.bool("is_available", True))

        nagatanien = Node.void("nagatanien")
        info.add_child(nagatanien)
        nagatanien.add_child(Node.bool("is_available", True))

        all_music_matching = Node.void("all_music_matching")
        info.add_child(all_music_matching)
        all_music_matching.add_child(Node.bool("is_available", True))

        question_list = Node.void("question_list")
        info.add_child(question_list)

        return info

    def handle_shopinfo_regist_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("shop/name"))

        shopinfo = Node.void("shopinfo")

        data = Node.void("data")
        shopinfo.add_child(data)
        data.add_child(Node.u32("cabid", 1))
        data.add_child(Node.string("locationid", "nowhere"))
        data.add_child(Node.u8("tax_phase", 1))

        facility = Node.void("facility")
        data.add_child(facility)
        facility.add_child(Node.u32("exist", 1))

        data.add_child(self.__get_global_info())

        return shopinfo

    def handle_recommend_get_recommend_request(self, request: Node) -> Node:
        recommend = Node.void("recommend")
        data = Node.void("data")
        recommend.add_child(data)

        player = Node.void("player")
        data.add_child(player)
        music_list = Node.void("music_list")
        player.add_child(music_list)

        # TODO: Might be a way to figure out who plays what song and then offer
        # recommendations based on that. There should be 12 songs returned here.
        recommended_songs: List[Song] = []
        for i, song in enumerate(recommended_songs):
            music = Node.void("music")
            music_list.add_child(music)
            music.set_attribute("order", str(i))
            music.add_child(Node.s32("music_id", song.id))
            music.add_child(Node.s8("seq", song.chart))

        return recommend

    def handle_gametop_regist_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        refid = player.child_value("refid")
        name = player.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        return root

    def handle_gametop_get_pdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        refid = player.child_value("refid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("gametop")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_gametop_get_mdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        extid = player.child_value("jid")
        mdata_ver = player.child_value("mdata_ver")
        root = self.get_scores_by_extid(extid, mdata_ver, 3)
        if root is None:
            root = Node.void("gametop")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_gametop_get_info_request(self, request: Node) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)
        data.add_child(self.__get_global_info())

        return root

    def handle_gameend_final_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")

        if player is not None:
            refid = player.child_value("refid")
        else:
            refid = None

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            profile = self.get_profile(userid)

            # Grab unlock progress
            item = player.child("item")
            if item is not None:
                owned_emblems = self.calculate_owned_items(
                    item.child_value("emblem_list")
                )
                for index in owned_emblems:
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        index,
                        "emblem",
                        {},
                    )

            # jbox stuff
            jbox = player.child("jbox")
            jboxdict = profile.get_dict("jbox")
            if jbox is not None:
                jboxdict.replace_int("point", jbox.child_value("point"))
                emblemtype = jbox.child_value("emblem/type")
                index = jbox.child_value("emblem/index")
                if emblemtype == self.JBOX_EMBLEM_NORMAL:
                    jboxdict.replace_int("normal_index", index)
                elif emblemtype == self.JBOX_EMBLEM_PREMIUM:
                    jboxdict.replace_int("premium_index", index)
            profile.replace_dict("jbox", jboxdict)

            # Born stuff
            born = player.child("born")
            if born is not None:
                profile.replace_int("born_status", born.child_value("status"))
                profile.replace_int("born_year", born.child_value("year"))
        else:
            profile = None

        if userid is not None and profile is not None:
            self.put_profile(userid, profile)

        return Node.void("gameend")

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)

        # Figure out if we're force-unlocking songs.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        owned_songs: Set[int] = set()
        owned_secrets: Set[int] = set()
        owned_emblems: Set[int] = set()
        for achievement in achievements:
            if achievement.type == "emblem":
                owned_emblems.add(achievement.id)
            elif achievement.type == "song":
                owned_songs.add(achievement.id)
            elif achievement.type == "secret":
                owned_secrets.add(achievement.id)

        # Make sure we grant ownership of default main parts.
        default_emblems = self.default_select_jbox()
        owned_emblems.update(default_emblems)
        default_main = next(iter(default_emblems)) if default_emblems else 0

        # Jubeat Prop appears to allow full event overrides per-player
        data.add_child(self.__get_global_info())

        player = Node.void("player")
        data.add_child(player)

        # Some server node
        server = Node.void("server")
        player.add_child(server)

        # Basic profile info
        player.add_child(Node.string("name", profile.get_str("name", "なし")))
        player.add_child(Node.s32("jid", profile.extid))

        # Miscelaneous crap
        player.add_child(Node.s32("session_id", 1))
        player.add_child(Node.u64("event_flag", 0))

        # Player info and statistics
        info = Node.void("info")
        player.add_child(info)
        info.add_child(Node.s16("jubility", profile.get_int("jubility")))
        info.add_child(Node.s16("jubility_yday", profile.get_int("jubility_yday")))
        info.add_child(Node.s32("tune_cnt", profile.get_int("tune_cnt")))
        info.add_child(Node.s32("save_cnt", profile.get_int("save_cnt")))
        info.add_child(Node.s32("saved_cnt", profile.get_int("saved_cnt")))
        info.add_child(Node.s32("fc_cnt", profile.get_int("fc_cnt")))
        info.add_child(Node.s32("ex_cnt", profile.get_int("ex_cnt")))
        info.add_child(Node.s32("clear_cnt", profile.get_int("clear_cnt")))
        info.add_child(Node.s32("match_cnt", profile.get_int("match_cnt")))
        info.add_child(Node.s32("beat_cnt", profile.get_int("beat_cnt")))
        info.add_child(Node.s32("mynews_cnt", profile.get_int("mynews_cnt")))
        info.add_child(
            Node.s32("bonus_tune_points", profile.get_int("bonus_tune_points"))
        )
        info.add_child(
            Node.bool("is_bonus_tune_played", profile.get_bool("is_bonus_tune_played"))
        )

        # Looks to be set to true when there's an old profile, stops tutorial from
        # happening on first load.
        info.add_child(
            Node.bool(
                "inherit",
                profile.get_bool("has_old_version") and not profile.get_bool("saved"),
            )
        )

        # Not saved, but loaded
        info.add_child(Node.s32("mtg_entry_cnt", 123))
        info.add_child(Node.s32("mtg_hold_cnt", 456))
        info.add_child(Node.u8("mtg_result", 10))

        # Last played data, for showing cursor and such
        lastdict = profile.get_dict("last")
        last = Node.void("last")
        player.add_child(last)
        last.add_child(Node.s64("play_time", lastdict.get_int("play_time")))
        last.add_child(Node.string("shopname", lastdict.get_str("shopname")))
        last.add_child(Node.string("areaname", lastdict.get_str("areaname")))
        last.add_child(Node.s32("music_id", lastdict.get_int("music_id")))
        last.add_child(Node.s8("seq_id", lastdict.get_int("seq_id")))
        last.add_child(Node.s8("sort", lastdict.get_int("sort")))
        last.add_child(Node.s8("category", lastdict.get_int("category")))
        last.add_child(Node.s8("expert_option", lastdict.get_int("expert_option")))
        last.add_child(Node.s32("dig_select", lastdict.get_int("dig_select")))

        settings = Node.void("settings")
        last.add_child(settings)
        settings.add_child(Node.s8("marker", lastdict.get_int("marker")))
        settings.add_child(Node.s8("theme", lastdict.get_int("theme")))
        settings.add_child(Node.s16("title", lastdict.get_int("title")))
        settings.add_child(Node.s16("parts", lastdict.get_int("parts")))
        settings.add_child(Node.s8("rank_sort", lastdict.get_int("rank_sort")))
        settings.add_child(Node.s8("combo_disp", lastdict.get_int("combo_disp")))
        settings.add_child(Node.s8("matching", lastdict.get_int("matching")))
        settings.add_child(Node.s8("hazard", lastdict.get_int("hazard")))
        settings.add_child(Node.s8("hard", lastdict.get_int("hard")))

        # Hack to make the default emblem appear properly.
        partslist = lastdict.get_int_array("emblem", 5, [0, default_main, 0, 0, 0])
        if partslist[1] == 0:
            partslist[1] = default_main
        settings.add_child(Node.s16_array("emblem", partslist))

        # Secret unlocks
        item = Node.void("item")
        player.add_child(item)
        item.add_child(
            Node.s32_array(
                "music_list", profile.get_int_array("music_list", 64, [-1] * 64)
            )
        )
        item.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 64)
                if force_unlock
                else self.create_owned_items(owned_songs, 64),
            )
        )
        item.add_child(
            Node.s32_array(
                "theme_list", profile.get_int_array("theme_list", 16, [-1] * 16)
            )
        )
        item.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list", 16, [-1] * 16)
            )
        )
        item.add_child(
            Node.s32_array(
                "title_list", profile.get_int_array("title_list", 160, [-1] * 160)
            )
        )
        item.add_child(
            Node.s32_array(
                "parts_list", profile.get_int_array("parts_list", 160, [-1] * 160)
            )
        )
        item.add_child(
            Node.s32_array("emblem_list", self.create_owned_items(owned_emblems, 96))
        )

        new = Node.void("new")
        item.add_child(new)
        new.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 64)
                if force_unlock
                else self.create_owned_items(owned_secrets, 64),
            )
        )
        new.add_child(
            Node.s32_array(
                "theme_list", profile.get_int_array("theme_list_new", 16, [-1] * 16)
            )
        )
        new.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list_new", 16, [-1] * 16)
            )
        )

        # Add rivals to profile.
        rivallist = Node.void("rivallist")
        player.add_child(rivallist)

        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivalcount = 0
        for link in links:
            if link.type != "rival":
                continue

            rprofile = self.get_profile(link.other_userid)
            if rprofile is None:
                continue

            rival = Node.void("rival")
            rivallist.add_child(rival)
            rival.add_child(Node.s32("jid", rprofile.extid))
            rival.add_child(Node.string("name", rprofile.get_str("name")))

            # This looks like a carry-over from prop's career and isn't displayed.
            career = Node.void("career")
            rival.add_child(career)
            career.add_child(Node.s16("level", 1))

            # Lazy way of keeping track of rivals, since we can only have 3
            # or the game with throw up.
            rivalcount += 1
            if rivalcount >= 3:
                break

        rivallist.set_attribute("count", str(rivalcount))

        lab_edit_seq = Node.void("lab_edit_seq")
        player.add_child(lab_edit_seq)
        lab_edit_seq.set_attribute("count", "0")

        # Full combo challenge
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "fc_challenge"
        )
        if entry is None:
            entry = ValidatedDict()

        # Figure out if we've played these songs
        start_time, end_time = self.data.local.network.get_schedule_duration("daily")
        today_attempts = self.data.local.music.get_all_attempts(
            self.game,
            self.music_version,
            userid,
            entry.get_int("today", -1),
            timelimit=start_time,
        )
        whim_attempts = self.data.local.music.get_all_attempts(
            self.game,
            self.music_version,
            userid,
            entry.get_int("whim", -1),
            timelimit=start_time,
        )

        fc_challenge = Node.void("fc_challenge")
        player.add_child(fc_challenge)
        today = Node.void("today")
        fc_challenge.add_child(today)
        today.add_child(Node.s32("music_id", entry.get_int("today", -1)))
        today.add_child(Node.u8("state", 0x40 if len(today_attempts) > 0 else 0x0))
        whim = Node.void("whim")
        fc_challenge.add_child(whim)
        whim.add_child(Node.s32("music_id", entry.get_int("whim", -1)))
        whim.add_child(Node.u8("state", 0x40 if len(whim_attempts) > 0 else 0x0))

        # No news, ever.
        news = Node.void("news")
        player.add_child(news)
        news.add_child(Node.s16("checked", 0))
        news.add_child(Node.u32("checked_flag", 0))

        # Sane defaults for unknown/who cares nodes
        history = Node.void("history")
        player.add_child(history)
        history.set_attribute("count", "0")
        free_first_play = Node.void("free_first_play")
        player.add_child(free_first_play)
        free_first_play.add_child(Node.bool("is_available", False))
        navi = Node.void("navi")
        player.add_child(navi)
        navi.add_child(Node.u64("flag", profile.get_int("navi_flag")))

        # Player status for events
        event_info = Node.void("event_info")
        player.add_child(event_info)
        for achievement in achievements:
            if achievement.type == "event":
                # There are two significant bits here, 0x1 and 0x2, I think the first
                # one is whether the event is started, second is if its finished?
                event = Node.void("event")
                event_info.add_child(event)
                event.set_attribute("type", str(achievement.id))

                state = 0x0
                state = (
                    state + 0x2 if achievement.data.get_bool("is_completed") else 0x0
                )
                event.add_child(Node.u8("state", state))

        # JBox stuff
        jbox = Node.void("jbox")
        jboxdict = profile.get_dict("jbox")
        player.add_child(jbox)
        jbox.add_child(Node.s32("point", jboxdict.get_int("point")))
        emblem = Node.void("emblem")
        jbox.add_child(emblem)
        normal = Node.void("normal")
        emblem.add_child(normal)
        premium = Node.void("premium")
        emblem.add_child(premium)

        # Calculate a random index for normal and premium to give to player
        # as a gatcha.
        normalindex, premiumindex = self.random_select_jbox(owned_emblems)
        normal.add_child(Node.s16("index", normalindex))
        premium.add_child(Node.s16("index", premiumindex))

        # Digdig stuff
        digdig = Node.void("digdig")
        digdigdict = profile.get_dict("digdig")
        eternaldict = digdigdict.get_dict("eternal")
        olddict = digdigdict.get_dict("old")
        player.add_child(digdig)
        digdig.add_child(Node.u64("flag", digdigdict.get_int("flag")))

        # Emerald main stages
        main = Node.void("main")
        digdig.add_child(main)
        stage = Node.void("stage")
        main.add_child(stage)
        stage.set_attribute("number", str(digdigdict.get_int("stage_number", 1)))
        stage.add_child(Node.s32("point", digdigdict.get_int("point")))
        stage.add_child(
            Node.s32_array("param", digdigdict.get_int_array("param", 12, [0] * 12))
        )

        # Emerald eternal stages
        eternal = Node.void("eternal")
        digdig.add_child(eternal)
        eternal.add_child(Node.s32("ratio", 1))
        eternal.add_child(Node.s64("used_point", eternaldict.get_int("used_point")))
        eternal.add_child(Node.s64("point", eternaldict.get_int("point")))
        eternal.add_child(
            Node.s64("excavated_point", eternaldict.get_int("excavated_point"))
        )
        cube = Node.void("cube")
        eternal.add_child(cube)
        cube.add_child(
            Node.s8_array("state", eternaldict.get_int_array("state", 12, [0] * 12))
        )
        item = Node.void("item")
        cube.add_child(item)
        item.add_child(
            Node.s32_array("kind", eternaldict.get_int_array("item_kind", 12, [0] * 12))
        )
        item.add_child(
            Node.s32_array(
                "value", eternaldict.get_int_array("item_value", 12, [0] * 12)
            )
        )
        norma = Node.void("norma")
        cube.add_child(norma)
        norma.add_child(Node.s64_array("till_time", [0] * 12))
        norma.add_child(
            Node.s32_array(
                "kind", eternaldict.get_int_array("norma_kind", 12, [0] * 12)
            )
        )
        norma.add_child(
            Node.s32_array(
                "value", eternaldict.get_int_array("norma_value", 12, [0] * 12)
            )
        )
        norma.add_child(
            Node.s32_array(
                "param", eternaldict.get_int_array("norma_param", 12, [0] * 12)
            )
        )

        if self.ENABLE_GARNET:
            # Garnet
            old = Node.void("old")
            digdig.add_child(old)
            old.add_child(Node.s32("need_point", olddict.get_int("need_point")))
            old.add_child(Node.s32("point", olddict.get_int("point")))
            old.add_child(
                Node.s32_array(
                    "excavated_point",
                    olddict.get_int_array("excavated_point", 5, [0] * 5),
                )
            )
            old.add_child(
                Node.s32_array(
                    "excavated", olddict.get_int_array("excavated", 5, [0] * 5)
                )
            )
            old.add_child(
                Node.s32_array("param", olddict.get_int_array("param", 5, [0] * 5))
            )
            # This should have a bunch of sub-nodes with the following format. Note that only
            # the first ten nodes are saved even if more are read. Presumably this is the list
            # of old songs we are allowing the player to unlock? Doesn't matter, we're disabling
            # Garnet anyway.:
            # <music>
            #     <music_id __type="s32">id</music_id>
            # </music>
            old.add_child(Node.void("music_list"))

        # Unlock event, turns on unlock challenge for a particular stage.
        unlock = Node.void("unlock")
        player.add_child(unlock)
        main = Node.void("main")
        unlock.add_child(main)
        stage_list = Node.void("stage_list")
        main.add_child(stage_list)
        # Stage numbers are between 1 and 13 inclusive.
        for i in range(1, 14):
            stage_flags = self.data.local.user.get_achievement(
                self.game, self.version, userid, i, "stage"
            )
            if stage_flags is None:
                stage_flags = ValidatedDict()

            stage = Node.void("stage")
            stage_list.add_child(stage)
            stage.set_attribute("number", str(i))
            stage.add_child(Node.u8("state", stage_flags.get_int("state")))

        # DigDig event for server-controlled cubes (basically anything not Garnet or Emerald)
        generic_dig = Node.void("generic_dig")
        player.add_child(generic_dig)
        map_list = Node.void("map_list")
        generic_dig.add_child(map_list)
        # Map list consists of up to 9 of the following structures:
        # <map id="id of map as defined in info node above">
        #     <point __type="s32">points</point>
        #     <used_point __type="s32">points</used_point>
        #     <stage_num __type="s32">stage</stage_num>
        #     <stage_list>
        #         <stage number="number matching a stage number from info node above:"">
        #             <norma>
        #                 <param __type="s32">0 0 0 0 0 0 0 0 0 0 0 0</param>
        #             </norma>
        #             <unlock>
        #                 <state __type="u8">0</state>
        #             </unlock>
        #         </stage>
        #     </stage_list>
        # </map>

        # New Music stuff
        new_music = Node.void("new_music")
        player.add_child(new_music)

        # Gift list, maybe from other players?
        gift_list = Node.void("gift_list")
        player.add_child(gift_list)
        # If we had gifts, they look like this:
        #     <gift reason="??" kind="??">
        #         <id __type="s32">??</id>
        #     </gift>

        # Birthday event?
        born = Node.void("born")
        player.add_child(born)
        born.add_child(Node.s8("status", profile.get_int("born_status")))
        born.add_child(Node.s16("year", profile.get_int("born_year")))

        # More crap
        question_list = Node.void("question_list")
        player.add_child(question_list)

        return root

    def format_scores(
        self, userid: UserID, profile: Profile, scores: List[Score]
    ) -> Node:
        root = Node.void("gametop")
        datanode = Node.void("data")
        root.add_child(datanode)
        player = Node.void("player")
        datanode.add_child(player)
        player.add_child(Node.s32("jid", profile.extid))
        playdata = Node.void("mdata_list")
        player.add_child(playdata)

        music = ValidatedDict()
        for score in scores:
            # Ignore festo-and-above chart types.
            if score.chart not in {
                self.CHART_TYPE_BASIC,
                self.CHART_TYPE_ADVANCED,
                self.CHART_TYPE_EXTREME,
            }:
                continue

            data = music.get_dict(str(score.id))
            play_cnt = data.get_int_array("play_cnt", 3)
            clear_cnt = data.get_int_array("clear_cnt", 3)
            clear_flags = data.get_int_array("clear_flags", 3)
            fc_cnt = data.get_int_array("fc_cnt", 3)
            ex_cnt = data.get_int_array("ex_cnt", 3)
            points = data.get_int_array("points", 3)

            # Replace data for this chart type
            play_cnt[score.chart] = score.plays
            clear_cnt[score.chart] = score.data.get_int("clear_count")
            fc_cnt[score.chart] = score.data.get_int("full_combo_count")
            ex_cnt[score.chart] = score.data.get_int("excellent_count")
            points[score.chart] = score.points

            # Format the clear flags
            clear_flags[score.chart] = self.GAME_FLAG_BIT_PLAYED
            if score.data.get_int("clear_count") > 0:
                clear_flags[score.chart] |= self.GAME_FLAG_BIT_CLEARED
            if score.data.get_int("full_combo_count") > 0:
                clear_flags[score.chart] |= self.GAME_FLAG_BIT_FULL_COMBO
            if score.data.get_int("excellent_count") > 0:
                clear_flags[score.chart] |= self.GAME_FLAG_BIT_EXCELLENT

            # Save chart data back
            data.replace_int_array("play_cnt", 3, play_cnt)
            data.replace_int_array("clear_cnt", 3, clear_cnt)
            data.replace_int_array("clear_flags", 3, clear_flags)
            data.replace_int_array("fc_cnt", 3, fc_cnt)
            data.replace_int_array("ex_cnt", 3, ex_cnt)
            data.replace_int_array("points", 3, points)

            # Update the ghost (untyped)
            ghost = data.get("ghost", [None, None, None])
            ghost[score.chart] = score.data.get("ghost")
            data["ghost"] = ghost

            # Save it back
            music.replace_dict(str(score.id), data)

        for scoreid in music:
            scoredata = music[scoreid]
            musicdata = Node.void("musicdata")
            playdata.add_child(musicdata)

            musicdata.set_attribute("music_id", scoreid)
            musicdata.add_child(
                Node.s32_array("play_cnt", scoredata.get_int_array("play_cnt", 3))
            )
            musicdata.add_child(
                Node.s32_array("clear_cnt", scoredata.get_int_array("clear_cnt", 3))
            )
            musicdata.add_child(
                Node.s32_array("fc_cnt", scoredata.get_int_array("fc_cnt", 3))
            )
            musicdata.add_child(
                Node.s32_array("ex_cnt", scoredata.get_int_array("ex_cnt", 3))
            )
            musicdata.add_child(
                Node.s32_array("score", scoredata.get_int_array("points", 3))
            )
            musicdata.add_child(
                Node.s8_array("clear", scoredata.get_int_array("clear_flags", 3))
            )

            ghosts = scoredata.get("ghost", [None, None, None])
            for i in range(len(ghosts)):
                ghost = ghosts[i]
                if ghost is None:
                    continue

                bar = Node.u8_array("bar", ghost)
                musicdata.add_child(bar)
                bar.set_attribute("seq", str(i))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()
        newprofile.replace_bool("saved", True)
        data = request.child("data")

        # Figure out if we're force-unlocking songs. If we are, we don't want to persist
        # secret stuff otherwise the game will accidentally unlock everything in the profile.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        # Grab system information
        sysinfo = data.child("info")

        # Grab player information
        player = data.child("player")

        # Grab result information
        result = data.child("result")

        # Grab last information. Lots of this will be filled in while grabbing scores
        last = newprofile.get_dict("last")
        if sysinfo is not None:
            last.replace_int("play_time", sysinfo.child_value("time_gameend"))
            last.replace_str("shopname", sysinfo.child_value("shopname"))
            last.replace_str("areaname", sysinfo.child_value("areaname"))

        # Grab player info for echoing back
        info = player.child("info")
        if info is not None:
            newprofile.replace_int("jubility", info.child_value("jubility"))
            newprofile.replace_int("jubility_yday", info.child_value("jubility_yday"))
            newprofile.replace_int("tune_cnt", info.child_value("tune_cnt"))
            newprofile.replace_int("save_cnt", info.child_value("save_cnt"))
            newprofile.replace_int("saved_cnt", info.child_value("saved_cnt"))
            newprofile.replace_int("fc_cnt", info.child_value("fc_cnt"))
            newprofile.replace_int("ex_cnt", info.child_value("ex_cnt"))
            newprofile.replace_int("clear_cnt", info.child_value("clear_cnt"))
            newprofile.replace_int("match_cnt", info.child_value("match_cnt"))
            newprofile.replace_int("beat_cnt", info.child_value("beat_cnt"))
            newprofile.replace_int("mynews_cnt", info.child_value("mynews_cnt"))

            newprofile.replace_int(
                "bonus_tune_points", info.child_value("bonus_tune_points")
            )
            newprofile.replace_bool(
                "is_bonus_tune_played", info.child_value("is_bonus_tune_played")
            )

        # Grab last settings
        lastnode = player.child("last")
        if lastnode is not None:
            last.replace_int("expert_option", lastnode.child_value("expert_option"))
            last.replace_int("dig_select", lastnode.child_value("dig_select"))
            last.replace_int("sort", lastnode.child_value("sort"))
            last.replace_int("category", lastnode.child_value("category"))

            settings = lastnode.child("settings")
            if settings is not None:
                last.replace_int("matching", settings.child_value("matching"))
                last.replace_int("hazard", settings.child_value("hazard"))
                last.replace_int("hard", settings.child_value("hard"))
                last.replace_int("marker", settings.child_value("marker"))
                last.replace_int("theme", settings.child_value("theme"))
                last.replace_int("title", settings.child_value("title"))
                last.replace_int("parts", settings.child_value("parts"))
                last.replace_int("rank_sort", settings.child_value("rank_sort"))
                last.replace_int("combo_disp", settings.child_value("combo_disp"))
                last.replace_int_array("emblem", 5, settings.child_value("emblem"))

        # Grab unlock progress
        item = player.child("item")
        if item is not None:
            newprofile.replace_int_array(
                "music_list", 64, item.child_value("music_list")
            )
            newprofile.replace_int_array(
                "theme_list", 16, item.child_value("theme_list")
            )
            newprofile.replace_int_array(
                "marker_list", 16, item.child_value("marker_list")
            )
            newprofile.replace_int_array(
                "title_list", 160, item.child_value("title_list")
            )
            newprofile.replace_int_array(
                "parts_list", 160, item.child_value("parts_list")
            )

            if not force_unlock:
                # Don't persist if we're force-unlocked, this data will be bogus.
                owned_songs = self.calculate_owned_items(
                    item.child_value("secret_list")
                )
                for index in owned_songs:
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        index,
                        "song",
                        {},
                    )

            owned_emblems = self.calculate_owned_items(item.child_value("emblem_list"))
            for index in owned_emblems:
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    index,
                    "emblem",
                    {},
                )

            newitem = item.child("new")
            if newitem is not None:
                newprofile.replace_int_array(
                    "theme_list_new", 16, newitem.child_value("theme_list")
                )
                newprofile.replace_int_array(
                    "marker_list_new", 16, newitem.child_value("marker_list")
                )

                if not force_unlock:
                    # Don't persist if we're force-unlocked, this data will be bogus.
                    owned_secrets = self.calculate_owned_items(
                        newitem.child_value("secret_list")
                    )
                    for index in owned_secrets:
                        self.data.local.user.put_achievement(
                            self.game,
                            self.version,
                            userid,
                            index,
                            "secret",
                            {},
                        )

        # jbox stuff
        jbox = player.child("jbox")
        jboxdict = newprofile.get_dict("jbox")
        if jbox is not None:
            jboxdict.replace_int("point", jbox.child_value("point"))
            emblemtype = jbox.child_value("emblem/type")
            index = jbox.child_value("emblem/index")
            if emblemtype == self.JBOX_EMBLEM_NORMAL:
                jboxdict.replace_int("normal_index", index)
            elif emblemtype == self.JBOX_EMBLEM_PREMIUM:
                jboxdict.replace_int("premium_index", index)
        newprofile.replace_dict("jbox", jboxdict)

        # event stuff
        event_info = player.child("event_info")
        if event_info is not None:
            for child in event_info.children:
                try:
                    eventid = int(child.attribute("type"))
                except TypeError:
                    # Event is empty
                    continue
                is_completed = child.child_value("is_completed")

                # Figure out if we should update the rating/scores or not
                oldevent = self.data.local.user.get_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventid,
                    "event",
                )

                if oldevent is None:
                    # Create a new event structure for this
                    oldevent = ValidatedDict()

                oldevent.replace_bool("is_completed", is_completed)

                # Save it as an achievement
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventid,
                    "event",
                    oldevent,
                )

        # DigDig stuff
        digdig = player.child("digdig")
        digdigdict = newprofile.get_dict("digdig")
        if digdig is not None:
            digdigdict.replace_int("flag", digdig.child_value("flag"))

            main = digdig.child("main")
            if main is not None:
                stage = main.child("stage")
                stage_num = int(stage.attribute("number"))
                digdigdict.replace_int("stage_number", stage_num)
                digdigdict.replace_int("point", stage.child_value("point"))
                digdigdict.replace_int_array("param", 12, stage.child_value("param"))

                if stage.child_value("uc_available") is True:
                    # We should enable unlock challenge for this node because the game
                    # doesn't do it for us automatically.
                    stage_flags = self.data.local.user.get_achievement(
                        self.game, self.version, userid, stage_num, "stage"
                    )
                    if stage_flags is None:
                        stage_flags = ValidatedDict()
                    stage_flags.replace_int("state", stage_flags.get_int("state") | 0x2)
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        stage_num,
                        "stage",
                        stage_flags,
                    )

            eternal = digdig.child("eternal")
            eternaldict = digdigdict.get_dict("eternal")
            if eternal is not None:
                eternaldict.replace_int("used_point", eternal.child_value("used_point"))
                eternaldict.replace_int("point", eternal.child_value("point"))
                eternaldict.replace_int(
                    "excavated_point", eternal.child_value("excavated_point")
                )
                eternaldict.replace_int_array(
                    "state", 12, eternal.child_value("cube/state")
                )
                eternaldict.replace_int_array(
                    "item_kind", 12, eternal.child_value("cube/item/kind")
                )
                eternaldict.replace_int_array(
                    "item_value", 12, eternal.child_value("cube/item/value")
                )
                eternaldict.replace_int_array(
                    "norma_kind", 12, eternal.child_value("cube/norma/kind")
                )
                eternaldict.replace_int_array(
                    "norma_value", 12, eternal.child_value("cube/norma/value")
                )
                eternaldict.replace_int_array(
                    "norma_param", 12, eternal.child_value("cube/norma/param")
                )
            digdigdict.replace_dict("eternal", eternaldict)

            if self.ENABLE_GARNET:
                old = digdig.child("old")
                olddict = digdigdict.get_dict("old")
                if old is not None:
                    olddict.replace_int("need_point", old.child_value("need_point"))
                    olddict.replace_int("point", old.child_value("point"))
                    olddict.replace_int_array(
                        "excavated_point", 5, old.child_value("excavated_point")
                    )
                    olddict.replace_int_array(
                        "excavated", 5, old.child_value("excavated")
                    )
                    olddict.replace_int_array("param", 5, old.child_value("param"))
                digdigdict.replace_dict("old", olddict)

        # DigDig unlock event
        unlock = player.child("unlock")
        if unlock is not None:
            stage = unlock.child("main/stage")
            if stage is not None:
                stage_num = int(stage.attribute("number"))
                state = stage.child_value("state")

                # Just overwrite the state with this value
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    stage_num,
                    "stage",
                    {"state": state},
                )

                # If they cleared stage 13, we need to unlock eternal mode
                if stage_num == 13 and (state & 0x18) > 0:
                    digdigdict.replace_int("flag", digdigdict.get_int("flag") | 0x2)

        # Save this back now that we've parsed everything
        newprofile.replace_dict("digdig", digdigdict)

        # Still don't know what this is for lol
        newprofile.replace_int("navi_flag", player.child_value("navi/flag"))

        # Grab scores and save those
        if result is not None:
            for tune in result.children:
                if tune.name != "tune":
                    continue
                result = tune.child("player")

                songid = tune.child_value("music")
                timestamp = tune.child_value("timestamp") / 1000
                chart = int(result.child("score").attribute("seq"))
                points = result.child_value("score")
                flags = int(result.child("score").attribute("clear"))
                combo = int(result.child("score").attribute("combo"))
                ghost = result.child_value("mbar")

                stats = {
                    "perfect": result.child_value("nr_perfect"),
                    "great": result.child_value("nr_great"),
                    "good": result.child_value("nr_good"),
                    "poor": result.child_value("nr_poor"),
                    "miss": result.child_value("nr_miss"),
                }

                # Miscelaneous last data for echoing to profile get
                last.replace_int("music_id", songid)
                last.replace_int("seq_id", chart)

                mapping = {
                    self.GAME_FLAG_BIT_CLEARED: self.PLAY_MEDAL_CLEARED,
                    self.GAME_FLAG_BIT_FULL_COMBO: self.PLAY_MEDAL_FULL_COMBO,
                    self.GAME_FLAG_BIT_EXCELLENT: self.PLAY_MEDAL_EXCELLENT,
                    self.GAME_FLAG_BIT_NEARLY_FULL_COMBO: self.PLAY_MEDAL_NEARLY_FULL_COMBO,
                    self.GAME_FLAG_BIT_NEARLY_EXCELLENT: self.PLAY_MEDAL_NEARLY_EXCELLENT,
                }

                # Figure out the highest medal based on bits passed in
                medal = self.PLAY_MEDAL_FAILED
                for bit in mapping:
                    if flags & bit > 0:
                        medal = max(medal, mapping[bit])

                self.update_score(
                    userid, timestamp, songid, chart, points, medal, combo, ghost, stats
                )

        # Born stuff
        born = player.child("born")
        if born is not None:
            newprofile.replace_int("born_status", born.child_value("status"))
            newprofile.replace_int("born_year", born.child_value("year"))

        # Save back last information gleaned from results
        newprofile.replace_dict("last", last)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
