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
from bemani.backend.jubeat.course import JubeatCourse
from bemani.backend.jubeat.saucer import JubeatSaucer
from bemani.common import Profile, ValidatedDict, VersionConstants, Time
from bemani.data import Data, Score, UserID
from bemani.protocol import Node


class JubeatSaucerFulfill(
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
    JubeatCourse,
    JubeatBase,
):
    name: str = "Jubeat Saucer Fulfill"
    version: int = VersionConstants.JUBEAT_SAUCER_FULFILL

    GAME_COURSE_REQUIREMENT_SCORE: Final[int] = 1
    GAME_COURSE_REQUIREMENT_FULL_COMBO: Final[int] = 2
    GAME_COURSE_REQUIREMENT_PERFECT_PERCENT: Final[int] = 3

    GAME_COURSE_RATING_FAILED: Final[int] = 1
    GAME_COURSE_RATING_BRONZE: Final[int] = 2
    GAME_COURSE_RATING_SILVER: Final[int] = 3
    GAME_COURSE_RATING_GOLD: Final[int] = 4

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatSaucer(self.data, self.config, self.model)

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

    def handle_shopinfo_regist_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("shop/name"))

        shopinfo = Node.void("shopinfo")

        data = Node.void("data")
        shopinfo.add_child(data)
        data.add_child(Node.u32("cabid", 1))
        data.add_child(Node.string("locationid", "nowhere"))
        data.add_child(Node.u8("is_send", 1))
        data.add_child(
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
                ],
            )
        )
        data.add_child(Node.u8("tax_phase", 1))

        lab = Node.void("lab")
        data.add_child(lab)
        lab.add_child(Node.bool("is_open", False))

        vocaloid_event = Node.void("vocaloid_event")
        data.add_child(vocaloid_event)
        vocaloid_event.add_child(Node.u8("state", 0))
        vocaloid_event.add_child(Node.s32("music_id", 0))

        vocaloid_event2 = Node.void("vocaloid_event2")
        data.add_child(vocaloid_event2)
        vocaloid_event2.add_child(Node.u8("state", 0))
        vocaloid_event2.add_child(Node.s32("music_id", 0))

        # No obnoxious 30 second wait to play.
        matching_off = Node.void("matching_off")
        data.add_child(matching_off)
        matching_off.add_child(Node.bool("is_open", True))

        tenka = Node.void("tenka")
        data.add_child(tenka)
        tenka.add_child(Node.bool("is_participant", False))

        return shopinfo

    def handle_gametop_get_course_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        extid = player.child_value("jid")

        gametop = Node.void("gametop")
        data = Node.void("data")
        gametop.add_child(data)

        # Course list available
        course_list = Node.void("course_list")
        data.add_child(course_list)

        validcourses: List[int] = []
        for course in self.get_all_courses():
            coursenode = Node.void("course")
            course_list.add_child(coursenode)

            # Basic course info
            if course["id"] in validcourses:
                raise Exception("Cannot have same course ID specified twice!")
            validcourses.append(course["id"])
            coursenode.add_child(Node.s32("id", course["id"]))
            coursenode.add_child(Node.string("name", course["name"]))
            coursenode.add_child(Node.u8("level", course["level"]))

            # Translate internal to game
            def translate_req(internal_req: int) -> int:
                return {
                    self.COURSE_REQUIREMENT_SCORE: self.GAME_COURSE_REQUIREMENT_SCORE,
                    self.COURSE_REQUIREMENT_FULL_COMBO: self.GAME_COURSE_REQUIREMENT_FULL_COMBO,
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: self.GAME_COURSE_REQUIREMENT_PERFECT_PERCENT,
                }.get(internal_req, 0)

            # Course bronze/silver/gold rules
            ids = [0] * 3
            bronze_values = [0] * 3
            silver_values = [0] * 3
            gold_values = [0] * 3
            slot = 0
            for req in course["requirements"]:
                req_values = course["requirements"][req]

                ids[slot] = translate_req(req)
                bronze_values[slot] = req_values[0]
                silver_values[slot] = req_values[1]
                gold_values[slot] = req_values[2]
                slot = slot + 1

            norma = Node.void("norma")
            coursenode.add_child(norma)
            norma.add_child(Node.s32_array("norma_id", ids))
            norma.add_child(Node.s32_array("bronze_value", bronze_values))
            norma.add_child(Node.s32_array("silver_value", silver_values))
            norma.add_child(Node.s32_array("gold_value", gold_values))

            # Music list for course
            music_index = 0
            music_list = Node.void("music_list")
            coursenode.add_child(music_list)

            for entry in course["music"]:
                music = Node.void("music")
                music.set_attribute("index", str(music_index))
                music_list.add_child(music)
                music.add_child(Node.s32("music_id", entry[0]))
                music.add_child(Node.u8("seq", entry[1]))
                music_index = music_index + 1

        # Look up profile so we can load the last course played
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        profile = self.get_profile(userid)
        if profile is None:
            profile = Profile(self.game, self.version, "", extid)

        # Player scores for courses
        player_list = Node.void("player_list")
        data.add_child(player_list)
        player = Node.void("player")
        player_list.add_child(player)
        player.add_child(Node.s32("jid", extid))

        result_list = Node.void("result_list")
        player.add_child(result_list)
        playercourses = self.get_courses(userid)
        for courseid in playercourses:
            if courseid not in validcourses:
                continue

            rating = {
                self.COURSE_RATING_FAILED: self.GAME_COURSE_RATING_FAILED,
                self.COURSE_RATING_BRONZE: self.GAME_COURSE_RATING_BRONZE,
                self.COURSE_RATING_SILVER: self.GAME_COURSE_RATING_SILVER,
                self.COURSE_RATING_GOLD: self.GAME_COURSE_RATING_GOLD,
            }[playercourses[courseid]["rating"]]
            scores = playercourses[courseid]["scores"]

            result = Node.void("result")
            result_list.add_child(result)
            result.add_child(Node.s32("id", courseid))
            result.add_child(Node.u8("rating", rating))
            result.add_child(Node.s32_array("score", scores))

        # Last course ID
        last_course_id = Node.s32(
            "last_course_id", profile.get_dict("last").get_int("last_course_id", -1)
        )
        data.add_child(last_course_id)

        return gametop

    def handle_gametop_regist_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        passnode = player.child("pass")
        refid = passnode.child_value("refid")
        name = player.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        return root

    def handle_gametop_get_pdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        passnode = player.child("pass")
        refid = passnode.child_value("refid")
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

    def handle_gametop_get_rival_mdata_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        extid = player.child_value("rival")
        mdata_ver = player.child_value("mdata_ver")
        root = self.get_scores_by_extid(extid, mdata_ver, 3)
        if root is None:
            root = Node.void("gametop")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)
        player = Node.void("player")
        data.add_child(player)

        # Figure out if we're force-unlocking songs.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        # Allow figuring out owned songs.
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        owned_songs: Set[int] = set()
        owned_secrets: Set[int] = set()
        for achievement in achievements:
            if achievement.type == "song":
                owned_songs.add(achievement.id)
            elif achievement.type == "secret":
                owned_secrets.add(achievement.id)

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
        info.add_child(Node.s32("pf_cnt", profile.get_int("pf_cnt")))
        info.add_child(Node.s32("clear_cnt", profile.get_int("clear_cnt")))
        info.add_child(Node.s32("match_cnt", profile.get_int("match_cnt")))
        info.add_child(Node.s32("beat_cnt", profile.get_int("beat_cnt")))
        info.add_child(Node.s32("mynews_cnt", profile.get_int("mynews_cnt")))
        info.add_child(Node.s32("extra_point", profile.get_int("extra_point")))
        info.add_child(
            Node.bool("is_extra_played", profile.get_bool("is_extra_played"))
        )
        if "total_best_score" in profile:
            info.add_child(
                Node.s32("total_best_score", profile.get_int("total_best_score"))
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

        # First play stuff we don't support
        free_first_play = Node.void("free_first_play")
        player.add_child(free_first_play)
        free_first_play.add_child(Node.bool("is_available", False))
        free_first_play.add_child(Node.s32("point", 0))
        free_first_play.add_child(Node.s32("point_used", 0))

        # Secret unlocks
        item = Node.void("item")
        player.add_child(item)
        item.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 32)
                if force_unlock
                else self.create_owned_items(owned_songs, 32),
            )
        )
        item.add_child(
            Node.s32_array(
                "title_list",
                profile.get_int_array(
                    "title_list",
                    96,
                    [-1] * 96,
                ),
            )
        )
        item.add_child(Node.s16("theme_list", profile.get_int("theme_list", -1)))
        item.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list", 2, [-1] * 2)
            )
        )
        item.add_child(
            Node.s32_array(
                "parts_list", profile.get_int_array("parts_list", 96, [-1] * 96)
            )
        )

        new = Node.void("new")
        item.add_child(new)
        new.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 32)
                if force_unlock
                else self.create_owned_items(owned_secrets, 32),
            )
        )
        new.add_child(
            Node.s32_array(
                "title_list",
                profile.get_int_array(
                    "title_list_new",
                    96,
                    [-1] * 96,
                ),
            )
        )
        new.add_child(Node.s16("theme_list", profile.get_int("theme_list_new", -1)))
        new.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list_new", 2, [-1] * 2)
            )
        )

        # Last played data, for showing cursor and such
        lastdict = profile.get_dict("last")
        last = Node.void("last")
        player.add_child(last)
        last.add_child(Node.s32("music_id", lastdict.get_int("music_id")))
        last.add_child(Node.s8("marker", lastdict.get_int("marker")))
        last.add_child(Node.s16("title", lastdict.get_int("title")))
        last.add_child(Node.s8("theme", lastdict.get_int("theme")))
        last.add_child(Node.s8("sort", lastdict.get_int("sort")))
        last.add_child(Node.s8("rank_sort", lastdict.get_int("rank_sort")))
        last.add_child(Node.s8("combo_disp", lastdict.get_int("combo_disp")))
        last.add_child(Node.s8("seq_id", lastdict.get_int("seq_id")))
        last.add_child(Node.s16("parts", lastdict.get_int("parts")))
        last.add_child(Node.s8("category", lastdict.get_int("category")))
        last.add_child(Node.s64("play_time", lastdict.get_int("play_time")))
        last.add_child(Node.string("shopname", lastdict.get_str("shopname")))
        last.add_child(Node.string("areaname", lastdict.get_str("areaname")))
        last.add_child(Node.s8("expert_option", lastdict.get_int("expert_option")))
        last.add_child(Node.s8("matching", lastdict.get_int("matching")))
        last.add_child(Node.s8("hazard", lastdict.get_int("hazard")))
        last.add_child(Node.s8("hard", lastdict.get_int("hard")))

        # Miscelaneous crap
        player.add_child(Node.s32("session_id", 1))
        player.add_child(Node.u64("event_flag", 0))

        # Macchiato event
        macchiatodict = profile.get_dict("macchiato")
        macchiato = Node.void("macchiato")
        player.add_child(macchiato)
        macchiato.add_child(Node.s32("pack_id", macchiatodict.get_int("pack_id")))
        macchiato.add_child(Node.u16("bean_num", macchiatodict.get_int("bean_num")))
        macchiato.add_child(
            Node.s32("daily_milk_num", macchiatodict.get_int("daily_milk_num"))
        )
        macchiato.add_child(
            Node.bool(
                "is_received_daily_milk",
                macchiatodict.get_bool("is_received_daily_milk"),
            )
        )
        macchiato.add_child(
            Node.s32("today_tune_cnt", macchiatodict.get_int("today_tune_cnt"))
        )
        macchiato.add_child(
            Node.s32_array(
                "daily_milk_bonus",
                macchiatodict.get_int_array(
                    "daily_milk_bonus", 9, [-1, -1, -1, -1, -1, -1, -1, -1, -1]
                ),
            )
        )
        macchiato.add_child(
            Node.s32("daily_play_burst", macchiatodict.get_int("daily_play_burst"))
        )
        macchiato.add_child(
            Node.bool(
                "sub_menu_is_completed", macchiatodict.get_bool("sub_menu_is_completed")
            )
        )
        macchiato.add_child(
            Node.s32("compensation_milk", macchiatodict.get_int("compensation_milk"))
        )
        macchiato.add_child(Node.s32("match_cnt", macchiatodict.get_int("match_cnt")))

        # Probably never will support this
        macchiato_music_list = Node.void("macchiato_music_list")
        macchiato.add_child(macchiato_music_list)
        macchiato_music_list.set_attribute("count", "0")

        # Same with this comment
        macchiato.add_child(Node.s32("sub_pack_id", 0))
        sub_macchiato_music_list = Node.void("sub_macchiato_music_list")
        macchiato.add_child(sub_macchiato_music_list)
        sub_macchiato_music_list.set_attribute("count", "0")

        # And this
        season_music_list = Node.void("season_music_list")
        macchiato.add_child(season_music_list)
        season_music_list.set_attribute("count", "0")

        # Weird, this is sent as a void with a bunch of subnodes, but returned as an int array.
        achievement_list = Node.void("achievement_list")
        macchiato.add_child(achievement_list)
        achievement_list.set_attribute("count", "0")

        # Also probably never supporting this either
        cow_list = Node.void("cow_list")
        macchiato.add_child(cow_list)
        cow_list.set_attribute("count", "0")

        # No news, ever.
        news = Node.void("news")
        player.add_child(news)
        news.add_child(Node.s16("checked", 0))

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

            # Lazy way of keeping track of rivals, since we can only have 4
            # or the game with throw up. At least, I think Fulfill can have
            # 4 instead of the 3 found in newer versions, given the size of
            # the array that it loads the values in. However, to keep things
            # simple, I only supported three here.
            rivalcount += 1
            if rivalcount >= 3:
                break

        rivallist.set_attribute("count", str(rivalcount))

        # Full combo daily challenge.
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

        challenge = Node.void("challenge")
        player.add_child(challenge)
        today = Node.void("today")
        challenge.add_child(today)
        today.add_child(Node.s32("music_id", entry.get_int("today", -1)))
        today.add_child(Node.u8("state", 0x40 if len(today_attempts) > 0 else 0x0))
        whim = Node.void("whim")
        challenge.add_child(whim)
        whim.add_child(Node.s32("music_id", entry.get_int("whim", -1)))
        whim.add_child(Node.u8("state", 0x40 if len(whim_attempts) > 0 else 0x0))

        # Sane defaults for unknown nodes
        only_now_music = Node.void("only_now_music")
        player.add_child(only_now_music)
        only_now_music.set_attribute("count", "0")
        lab_edit_seq = Node.void("lab_edit_seq")
        player.add_child(lab_edit_seq)
        lab_edit_seq.set_attribute("count", "0")
        kac_music = Node.void("kac_music")
        player.add_child(kac_music)
        kac_music.set_attribute("count", "0")
        history = Node.void("history")
        player.add_child(history)
        history.set_attribute("count", "0")
        share_music = Node.void("share_music")
        player.add_child(share_music)
        share_music.set_attribute("count", "0")
        bonus_music = Node.void("bonus_music")
        player.add_child(bonus_music)
        bonus_music.set_attribute("count", "0")

        bingo = Node.void("bingo")
        player.add_child(bingo)
        reward = Node.void("reward")
        bingo.add_child(reward)
        reward.add_child(Node.s32("total", 0))
        reward.add_child(Node.s32("point", 0))
        group = Node.void("group")
        player.add_child(group)
        group.add_child(Node.s32("group_id", 0))

        # Basic profile info
        player.add_child(Node.string("name", profile.get_str("name", "なし")))
        player.add_child(Node.s32("jid", profile.extid))
        player.add_child(Node.string("refid", profile.refid))

        # Miscelaneous history stuff
        data.add_child(Node.u8("termver", 16))
        data.add_child(Node.u32("season_etime", 0))
        data.add_child(
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
                ],
            )
        )
        data.add_child(
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
                ],
            )
        )

        # Unsupported collaboration events with other games
        collabo_info = Node.void("collabo_info")
        data.add_child(collabo_info)

        # Unsupported policy break stuff
        policy_break = Node.void("policy_break")
        collabo_info.add_child(policy_break)
        policy_break.set_attribute("type", "1")
        policy_break.add_child(Node.u8("state", 1))
        policy_break.add_child(Node.bool("is_report_end", False))

        # Unsupported vocaloid stuff
        vocaloid_event = Node.void("vocaloid_event")
        collabo_info.add_child(vocaloid_event)
        vocaloid_event.set_attribute("type", "1")
        vocaloid_event.add_child(Node.u8("state", 0))
        vocaloid_event.add_child(Node.s32("music_id", 0))

        # Unsupported vocaloid stuff
        vocaloid_event2 = Node.void("vocaloid_event2")
        collabo_info.add_child(vocaloid_event2)
        vocaloid_event2.set_attribute("type", "1")
        vocaloid_event2.add_child(Node.u8("state", 0))
        vocaloid_event2.add_child(Node.s32("music_id", 0))

        # Maybe it is possible to turn off internet matching here?
        lab = Node.void("lab")
        data.add_child(lab)
        lab.add_child(Node.bool("is_open", False))
        matching_off = Node.void("matching_off")
        data.add_child(matching_off)
        matching_off.add_child(Node.bool("is_open", True))

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

        # Grab player information
        player = data.child("player")

        # Grab last information. Lots of this will be filled in while grabbing scores
        last = newprofile.get_dict("last")
        last.replace_int("play_time", player.child_value("time_gameend"))
        last.replace_str("shopname", player.child_value("shopname"))
        last.replace_str("areaname", player.child_value("areaname"))

        # Grab player info for echoing back
        info = player.child("info")
        if info is not None:
            newprofile.replace_int("jubility", info.child_value("jubility"))
            newprofile.replace_int("jubility_yday", info.child_value("jubility_yday"))
            newprofile.replace_int("tune_cnt", info.child_value("tune_cnt"))
            newprofile.replace_int("save_cnt", info.child_value("save_cnt"))
            newprofile.replace_int("saved_cnt", info.child_value("saved_cnt"))
            newprofile.replace_int("fc_cnt", info.child_value("fc_cnt"))
            newprofile.replace_int(
                "ex_cnt", info.child_value("exc_cnt")
            )  # Not a mistake, Jubeat is weird
            newprofile.replace_int("pf_cnt", info.child_value("pf_cnt"))
            newprofile.replace_int("clear_cnt", info.child_value("clear_cnt"))
            newprofile.replace_int("match_cnt", info.child_value("match_cnt"))
            newprofile.replace_int("beat_cnt", info.child_value("beat_cnt"))
            newprofile.replace_int(
                "total_best_score", info.child_value("total_best_score")
            )
            newprofile.replace_int("mynews_cnt", info.child_value("mynews_cnt"))
            newprofile.replace_int("extra_point", info.child_value("extra_point"))
            newprofile.replace_bool(
                "is_extra_played", info.child_value("is_extra_played")
            )

            last.replace_int("expert_option", info.child_value("expert_option"))
            last.replace_int("matching", info.child_value("matching"))
            last.replace_int("hazard", info.child_value("hazard"))
            last.replace_int("hard", info.child_value("hard"))

        # Grab unlock progress
        item = player.child("item")
        if item is not None:
            newprofile.replace_int_array(
                "title_list", 96, item.child_value("title_list")
            )
            newprofile.replace_int("theme_list", item.child_value("theme_list"))
            newprofile.replace_int_array(
                "marker_list", 2, item.child_value("marker_list")
            )
            newprofile.replace_int_array(
                "parts_list", 96, item.child_value("parts_list")
            )
            newprofile.replace_int_array(
                "title_list_new", 96, item.child_value("title_new")
            )
            newprofile.replace_int("theme_list_new", item.child_value("theme_new"))
            newprofile.replace_int_array(
                "marker_list_new", 2, item.child_value("marker_new")
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

                owned_secrets = self.calculate_owned_items(
                    item.child_value("secret_new")
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

        # Grab macchiato event
        macchiatodict = newprofile.get_dict("macchiato")
        macchiato = player.child("macchiato")
        if macchiato is not None:
            macchiatodict.replace_int("pack_id", macchiato.child_value("pack_id"))
            macchiatodict.replace_int("bean_num", macchiato.child_value("bean_num"))
            macchiatodict.replace_int(
                "daily_milk_num", macchiato.child_value("daily_milk_num")
            )
            macchiatodict.replace_bool(
                "is_received_daily_milk",
                macchiato.child_value("is_received_daily_milk"),
            )
            macchiatodict.replace_bool(
                "sub_menu_is_completed", macchiato.child_value("sub_menu_is_completed")
            )
            macchiatodict.replace_int(
                "today_tune_cnt", macchiato.child_value("today_tune_cnt")
            )
            macchiatodict.replace_int_array(
                "daily_milk_bonus", 9, macchiato.child_value("daily_milk_bonus")
            )
            macchiatodict.replace_int(
                "compensation_milk", macchiato.child_value("compensation_milk")
            )
            macchiatodict.replace_int("match_cnt", macchiato.child_value("match_cnt"))
            macchiatodict.replace_int("used_bean", macchiato.child_value("used_bean"))
            macchiatodict.replace_int("used_milk", macchiato.child_value("used_milk"))
            macchiatodict.replace_int(
                "daily_play_burst", macchiato.child_value("daily_play_burst")
            )
        newprofile.replace_dict("macchiato", macchiatodict)

        # Get timestamps for played songs
        timestamps: Dict[int, int] = {}
        history = player.child("history")
        if history is not None:
            for tune in history.children:
                if tune.name != "tune":
                    continue
                entry = int(tune.attribute("log_id"))
                ts = int(tune.child_value("timestamp") / 1000)
                timestamps[entry] = ts

        # Grab scores and save those
        result = data.child("result")
        if result is not None:
            for tune in result.children:
                if tune.name != "tune":
                    continue
                result = tune.child("player")

                last.replace_int("marker", tune.child_value("marker"))
                last.replace_int("title", tune.child_value("title"))
                last.replace_int("parts", tune.child_value("parts"))
                last.replace_int("theme", tune.child_value("theme"))
                last.replace_int("sort", tune.child_value("sort"))
                last.replace_int("category", tune.child_value("category"))
                last.replace_int("rank_sort", tune.child_value("rank_sort"))
                last.replace_int("combo_disp", tune.child_value("combo_disp"))

                songid = tune.child_value("music")
                entry = int(tune.attribute("id"))
                timestamp = timestamps.get(entry, Time.now())
                chart = int(result.child("score").attribute("seq"))
                points = result.child_value("score")
                flags = int(result.child("score").attribute("clear"))
                combo = int(result.child("score").attribute("combo"))
                ghost = result.child_value("mbar")

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
                    userid, timestamp, songid, chart, points, medal, combo, ghost
                )

        # Grab the course results as well
        course = data.child("course")
        if course is not None:
            courseid = course.child_value("course_id")
            rating = {
                self.GAME_COURSE_RATING_FAILED: self.COURSE_RATING_FAILED,
                self.GAME_COURSE_RATING_BRONZE: self.COURSE_RATING_BRONZE,
                self.GAME_COURSE_RATING_SILVER: self.COURSE_RATING_SILVER,
                self.GAME_COURSE_RATING_GOLD: self.COURSE_RATING_GOLD,
            }[course.child_value("rating")]
            scores = [0] * 5
            for music in course.children:
                if music.name != "music":
                    continue
                index = int(music.attribute("index"))
                scores[index] = music.child_value("score")

            # Save course itself
            self.save_course(userid, courseid, rating, scores)

            # Save the last course ID
            last.replace_int("last_course_id", courseid)

        # Save back last information gleaned from results
        newprofile.replace_dict("last", last)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile

    def format_scores(
        self, userid: UserID, profile: Profile, scores: List[Score]
    ) -> Node:
        root = Node.void("gametop")
        datanode = Node.void("data")
        root.add_child(datanode)
        player = Node.void("player")
        datanode.add_child(player)
        player.add_child(Node.s32("jid", profile.extid))
        playdata = Node.void("playdata")
        player.add_child(playdata)
        playdata.set_attribute("count", str(len(scores)))

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
