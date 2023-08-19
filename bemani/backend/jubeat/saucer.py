# vim: set fileencoding=utf-8
import random
from typing import Any, Dict, List, Optional, Set, Tuple

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
from bemani.backend.jubeat.stubs import JubeatCopiousAppend
from bemani.common import Profile, ValidatedDict, VersionConstants, Time
from bemani.data import Data, Score, UserID
from bemani.protocol import Node


class JubeatSaucer(
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
    JubeatBase,
):
    name: str = "Jubeat Saucer"
    version: int = VersionConstants.JUBEAT_SAUCER

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatCopiousAppend(self.data, self.config, self.model)

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
            if all_songs:
                today_song = random.sample(all_songs, 1)[0]
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "fc_challenge",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "today": today_song,
                    },
                )
                events.append(
                    (
                        "jubeat_fc_challenge_charts",
                        {
                            "version": cls.version,
                            "today": today_song,
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
                    -16385,
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

        matching_off = Node.void("matching_off")
        data.add_child(matching_off)
        matching_off.add_child(Node.bool("is_open", True))

        return shopinfo

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

        # Miscelaneous crap
        player.add_child(Node.s32("session_id", 1))

        # Maybe hook this up? Unsure what it does, is it like IIDX dailies?
        today_music = Node.void("today_music")
        player.add_child(today_music)
        today_music.add_child(Node.s32("music_id", 0))

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

        # Unclear what this is. Looks related to Jubeat lab.
        mylist = Node.void("mylist")
        player.add_child(mylist)
        mylist.set_attribute("count", "0")

        # No collaboration support yet.
        collabo = Node.void("collabo")
        player.add_child(collabo)
        collabo.add_child(Node.bool("success", False))
        collabo.add_child(Node.bool("completed", False))

        # Daily FC challenge.
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

        challenge = Node.void("challenge")
        player.add_child(challenge)
        today = Node.void("today")
        challenge.add_child(today)
        today.add_child(Node.s32("music_id", entry.get_int("today", -1)))
        today.add_child(Node.u8("state", 0x40 if len(today_attempts) > 0 else 0x0))
        onlynow = Node.void("onlynow")
        challenge.add_child(onlynow)
        onlynow.add_child(Node.s32("magic_no", 0))
        onlynow.add_child(Node.s16("cycle", 0))

        # Bistro event
        bistro = Node.void("bistro")
        player.add_child(bistro)

        # Presumably these can affect the speed of the event
        info_1 = Node.void("info")
        bistro.add_child(info_1)
        info_1.add_child(Node.float("delicious_rate", 1.0))
        info_1.add_child(Node.float("favorite_rate", 1.0))
        bistro.add_child(Node.s32("carry_over", profile.get_int("bistro_carry_over")))

        # Your chef dude, I guess?
        chefdict = profile.get_dict("chef")
        chef = Node.void("chef")
        bistro.add_child(chef)
        chef.add_child(Node.s32("id", chefdict.get_int("id", 1)))
        chef.add_child(Node.u8("ability", chefdict.get_int("ability", 2)))
        chef.add_child(Node.u8("remain", chefdict.get_int("remain", 30)))
        chef.add_child(Node.u8("rate", chefdict.get_int("rate", 1)))

        # Routes, similar to story mode in Pop'n I guess?
        routes = [
            {
                "id": 50000284,
                "price": 20,
                "satisfaction": 10,
                "favorite": True,
            },
            {
                "id": 50000283,
                "price": 20,
                "satisfaction": 20,
                "favorite": False,
            },
            {
                "id": 50000282,
                "price": 30,
                "satisfaction": 10,
                "favorite": False,
            },
            {
                "id": 50000275,
                "price": 10,
                "satisfaction": 55,
                "favorite": False,
            },
            {
                "id": 50000274,
                "price": 40,
                "satisfaction": 40,
                "favorite": False,
            },
            {
                "id": 50000273,
                "price": 80,
                "satisfaction": 60,
                "favorite": False,
            },
            {
                "id": 50000272,
                "price": 70,
                "satisfaction": 60,
                "favorite": False,
            },
            {
                "id": 50000271,
                "price": 90,
                "satisfaction": 80,
                "favorite": False,
            },
            {
                "id": 50000270,
                "price": 90,
                "satisfaction": 20,
                "favorite": False,
            },
        ]
        for route_no in range(len(routes)):
            routedata = routes[route_no]
            route = Node.void("route")
            bistro.add_child(route)
            route.set_attribute("no", str(route_no))

            music = Node.void("music")
            route.add_child(music)
            music.add_child(Node.s32("id", routedata["id"]))
            music.add_child(Node.u16("price", routedata["price"]))
            music.add_child(Node.s32("price_s32", routedata["price"]))

            # Look up any updated satisfaction stored by the game
            routesaved = self.data.local.user.get_achievement(
                self.game, self.version, userid, route_no + 1, "route"
            )
            if routesaved is None:
                routesaved = ValidatedDict()
            satisfaction = routesaved.get_int("satisfaction", routedata["satisfaction"])

            gourmates = Node.void("gourmates")
            route.add_child(gourmates)
            gourmates.add_child(Node.s32("id", route_no + 1))
            gourmates.add_child(Node.u8("favorite", 1 if routedata["favorite"] else 0))
            gourmates.add_child(Node.u16("satisfaction", satisfaction))
            gourmates.add_child(Node.s32("satisfaction_s32", satisfaction))

        # Sane defaults for unknown nodes
        only_now_music = Node.void("only_now_music")
        player.add_child(only_now_music)
        only_now_music.set_attribute("count", "0")
        requested_music = Node.void("requested_music")
        player.add_child(requested_music)
        requested_music.set_attribute("count", "0")
        kac_music = Node.void("kac_music")
        player.add_child(kac_music)
        kac_music.set_attribute("count", "0")
        history = Node.void("history")
        player.add_child(history)
        history.set_attribute("count", "0")

        # Basic profile info
        player.add_child(Node.string("name", profile.get_str("name", "なし")))
        player.add_child(Node.s32("jid", profile.extid))
        player.add_child(Node.string("refid", profile.refid))

        # Miscelaneous history stuff
        data.add_child(Node.u8("termver", 16))
        data.add_child(Node.u32("season_etime", 0))
        data.add_child(Node.s32("bistro_last_music_id", 0))
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
                "old_music_list",
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

        # Unsupported marathon stuff
        run_run_marathon = Node.void("run_run_marathon")
        collabo_info.add_child(run_run_marathon)
        run_run_marathon.set_attribute("type", "1")
        run_run_marathon.add_child(Node.u8("state", 1))
        run_run_marathon.add_child(Node.bool("is_report_end", True))

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

        # No obnoxious 30 second wait to play.
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

        # Grab bistro progress
        bistro = player.child("bistro")
        if bistro is not None:
            newprofile.replace_int(
                "bistro_carry_over", bistro.child_value("carry_over")
            )

            chefdata = newprofile.get_dict("chef")
            chef = bistro.child("chef")
            if chef is not None:
                chefdata.replace_int("id", chef.child_value("id"))
                chefdata.replace_int("ability", chef.child_value("ability"))
                chefdata.replace_int("remain", chef.child_value("remain"))
                chefdata.replace_int("rate", chef.child_value("rate"))
            newprofile.replace_dict("chef", chefdata)

            for route in bistro.children:
                if route.name != "route":
                    continue

                gourmates = route.child("gourmates")
                routeid = gourmates.child_value("id")
                satisfaction = gourmates.child_value("satisfaction_s32")
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    routeid,
                    "route",
                    {
                        "satisfaction": satisfaction,
                    },
                )

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
