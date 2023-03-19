# vim: set fileencoding=utf-8
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.sunnypark import PopnMusicSunnyPark

from bemani.backend.base import Status
from bemani.common import ValidatedDict, Profile, VersionConstants, ID
from bemani.data import UserID, Link
from bemani.protocol import Node


class PopnMusicLapistoria(PopnMusicBase):
    name: str = "Pop'n Music ラピストリア"
    version: int = VersionConstants.POPN_MUSIC_LAPISTORIA

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY: Final[int] = 0
    GAME_CHART_TYPE_NORMAL: Final[int] = 1
    GAME_CHART_TYPE_HYPER: Final[int] = 2
    GAME_CHART_TYPE_EX: Final[int] = 3

    # Medal type, as returned from the game
    GAME_PLAY_MEDAL_NO_PLAY: Final[int] = 0
    GAME_PLAY_MEDAL_CIRCLE_FAILED: Final[int] = 1
    GAME_PLAY_MEDAL_DIAMOND_FAILED: Final[int] = 2
    GAME_PLAY_MEDAL_STAR_FAILED: Final[int] = 3
    GAME_PLAY_MEDAL_EASY_CLEAR: Final[int] = 4
    GAME_PLAY_MEDAL_CIRCLE_CLEARED: Final[int] = 5
    GAME_PLAY_MEDAL_DIAMOND_CLEARED: Final[int] = 6
    GAME_PLAY_MEDAL_STAR_CLEARED: Final[int] = 7
    GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: Final[int] = 8
    GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: Final[int] = 9
    GAME_PLAY_MEDAL_STAR_FULL_COMBO: Final[int] = 10
    GAME_PLAY_MEDAL_PERFECT: Final[int] = 11

    # Max valud music ID for conversions and stuff
    GAME_MAX_MUSIC_ID: Final[int] = 1422

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicSunnyPark(self.data, self.config, self.model)

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
                        9: "Phase 9",
                        10: "Phase 10",
                        11: "Phase 11",
                        12: "Phase 12",
                        13: "Phase 13",
                        14: "Phase 14",
                        15: "Phase 15",
                        16: "Phase MAX",
                    },
                },
                {
                    "name": "Story Mode",
                    "tip": "Story mode phase for all players.",
                    "category": "game_config",
                    "setting": "story_phase",
                    "values": {
                        0: "Disabled",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase 3",
                        4: "Phase 4",
                        5: "Phase 5",
                        6: "Phase 6",
                        7: "Phase 7",
                        8: "Phase 8",
                        9: "Phase 9",
                        10: "Phase 10",
                        11: "Phase 11",
                        12: "Phase 12",
                        13: "Phase 13",
                        14: "Phase 14",
                        15: "Phase 15",
                        16: "Phase 16",
                        17: "Phase 17",
                        18: "Phase 18",
                        19: "Phase 19",
                        20: "Phase 20",
                        21: "Phase 21",
                        22: "Phase 22",
                        23: "Phase 23",
                        24: "Phase 24",
                    },
                },
            ],
            "bools": [
                # We don't currently support lobbies or anything, so this is commented out until
                # somebody gets around to implementing it.
                # {
                #     'name': 'Net Taisen',
                #     'tip': 'Enable Net Taisen, including win/loss display on song select',
                #     'category': 'game_config',
                #     'setting': 'enable_net_taisen',
                # },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
        }

    def handle_info22_common_request(self, request: Node) -> Node:
        game_config = self.get_game_config()
        story_phase = game_config.get_int("story_phase")
        music_phase = game_config.get_int("music_phase")
        enable_net_taisen = False  # game_config.get_bool('enable_net_taisen')

        phases = {
            # Default song phase availability (0-16)
            # The following songs are unlocked when the phase is at or above the number specified:
            # 1  - 1340, 1341, 1342, 1343, 1351, 1352
            # 2  - 1317, 1344, 1345
            # 3  - 1362, 1363
            # 4  - 1368
            # 5  - 1370
            # 6  - 1379, 1380
            # 7  - 1385
            # 8  - 1388
            # 9  - 1395, 1396, 1397
            # 10 - 1393
            # 11 - 1398, 1399
            # 12 - 1400, 1401
            # 13 - 1408
            # 14 - 1414
            # 15 - 1421
            # 16 - 1422
            0: music_phase,
            # Card phase (0-11)
            1: 11,
            # Pop'n Aura, max (0-11) (remove all aura requirements)
            2: 11,
            # Story (0-24)
            # Note also that depending on the story phase, some songs are also unlocked.
            # Given the story phase at or above the below phases, the following songs are unlocked:
            # 1  - 1314, 1328, 1338, 1339
            # 2  - 1346, 1347, 1361
            # 3  - 1349, 1364, 1365, 1367
            # 4  - 1366, 1369
            # 5  - 1337, 1348
            # 6  - 1371, 1372, 1373
            # 7  - 1374
            # 8  - 1383
            # 9  - 1336
            # 10 - 1382
            # 11 - 1387
            # 12 - 1386
            # 15 - 1390
            # 16 - 1389
            # 18 - 1391
            # 19 - 1392
            # 21 - 1405, 1406, 1407
            # 22 - 1410, 1411
            3: story_phase,
            # BEMANI ruins Discovery! 0 = off, 1 = active, 2 = off
            # When in phase 1 or 2, the following songs are available for unlock: 1353, 1354, 1355, 1356, 1357, 1358, 1359, 1360
            4: 2,
            # Unknown event, something to do with net taisen (0-2)
            5: 2 if enable_net_taisen else 0,
            # Unknown event (0-1)
            6: 1,
            # Unknown event (0-1)
            7: 1,
            # Unknown event (0-1)
            8: 1,
            # Course mode phase (0-11)
            9: 11,
            # Pon's Fate Purification Plan, 0 = off, 1 = active, 2 = off
            # When in phase 1 or 2, the following songs are available for unlock: 1375, 1376, 1377, 1378, 1381
            10: 2,
            # Unknown event (0-3)
            11: 3,
            # Unlock song 1384 (0-1)
            12: 1,
            # Appears to be unlocks for course mode including KAC stuff.
            13: 2,
            # Unknown event (0-4)
            14: 4,
            # Unknown event (0-2)
            15: 2,
            # Unknown event (0-2)
            16: 2,
            # Unknown event (0-12)
            17: 12,
            # Kaitou BisCo no yokokujou!! event, 0 = off, 1 = active, 2 = off (0-2)
            # When in phase 1 or 2, the following songs are available for unlock: 1402, 1403, 1404, 1409
            18: 2,
            # Bemani Summer Diary, 0 = off, 1-6 are phases, 7 = off
            # When the phase is at or above the below phases, the following songs are unlocked:
            # 1 - 1415
            # 2 - 1417
            # 3 - 1416
            # 4 - 1418
            # 5 - 1419
            # 6 - 1420
            19: 7,
        }

        root = Node.void("info22")
        for phaseid in phases:
            phase = Node.void("phase")
            root.add_child(phase)
            phase.add_child(Node.s16("event_id", phaseid))
            phase.add_child(Node.s16("phase", phases[phaseid]))

        for storyid in range(173):
            story = Node.void("story")
            root.add_child(story)
            story.add_child(Node.u32("story_id", storyid))
            story.add_child(Node.bool("is_limited", False))
            story.add_child(Node.u64("limit_date", 0))

        return root

    def handle_pcb22_boot_request(self, request: Node) -> Node:
        return Node.void("pcb22")

    def handle_pcb22_error_request(self, request: Node) -> Node:
        return Node.void("pcb22")

    def handle_pcb22_write_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("pcb_setting/name"))
        return Node.void("pcb22")

    def handle_lobby22_requests(self, request: Node) -> Node:
        # Stub out the entire lobby22 service
        return Node.void("lobby22")

    def handle_player22_read_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        # Pop'n Music 22 doesn't send a modelstring to load old profiles,
        # it just expects us to know. So always look for old profiles in
        # Pop'n 22 land.
        root = self.get_profile_by_refid(refid, self.OLD_PROFILE_FALLTHROUGH)
        if root is None:
            root = Node.void("player22")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_player22_new_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        if root is None:
            root = Node.void("player22")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_player22_start_request(self, request: Node) -> Node:
        return Node.void("player22")

    def handle_player22_logout_request(self, request: Node) -> Node:
        return Node.void("player22")

    def handle_player22_write_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player22")
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

    def handle_player22_friend_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        no = int(request.attribute("no", "-1"))

        root = Node.void("player22")
        if no < 0:
            root.add_child(Node.s8("result", 2))
            return root

        # Look up our own user ID based on the RefID provided.
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root.add_child(Node.s8("result", 2))
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

        # Somehow requested an invalid profile.
        if no >= len(rivals):
            root.add_child(Node.s8("result", 2))
            return root
        rivalid = links[no].other_userid
        rivalprofile = profiles[rivalid]
        scores = self.data.remote.music.get_scores(self.game, self.version, rivalid)
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, rivalid
        )

        # First, output general profile info.
        friend = Node.void("friend")
        root.add_child(friend)
        friend.add_child(Node.s16("no", no))
        friend.add_child(Node.string("g_pm_id", ID.format_extid(rivalprofile.extid)))
        friend.add_child(Node.string("name", rivalprofile.get_str("name", "なし")))
        friend.add_child(Node.s16("chara_num", rivalprofile.get_int("chara", -1)))
        # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
        # ranking numbers disappear and the player icon show a questionmark.
        friend.add_child(Node.s8("is_open", 1))

        for score in scores:
            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue

            points = score.points
            medal = score.data.get_int("medal")

            music = Node.void("music")
            friend.add_child(music)
            music.set_attribute("music_num", str(score.id))
            music.set_attribute(
                "sheet_num",
                str(
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart]
                ),
            )
            music.set_attribute("score", str(points))
            music.set_attribute(
                "clearmedal",
                str(
                    {
                        self.PLAY_MEDAL_NO_PLAY: self.GAME_PLAY_MEDAL_NO_PLAY,
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[medal]
                ),
            )

        for course in achievements:
            if course.type == "course":
                total_score = course.data.get_int("total_score")
                clear_medal = course.data.get_int("clear_medal")
                clear_norma = course.data.get_int("clear_norma")
                stage1_score = course.data.get_int("stage1_score")
                stage2_score = course.data.get_int("stage2_score")
                stage3_score = course.data.get_int("stage3_score")
                stage4_score = course.data.get_int("stage4_score")

                coursenode = Node.void("course")
                friend.add_child(coursenode)
                coursenode.set_attribute("course_id", str(course.id))
                coursenode.set_attribute("clear_medal", str(clear_medal))
                coursenode.set_attribute("clear_norma", str(clear_norma))
                coursenode.set_attribute("stage1_score", str(stage1_score))
                coursenode.set_attribute("stage2_score", str(stage2_score))
                coursenode.set_attribute("stage3_score", str(stage3_score))
                coursenode.set_attribute("stage4_score", str(stage4_score))
                coursenode.set_attribute("total_score", str(total_score))

        return root

    def handle_player22_conversion_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        chara = request.child_value("chara")
        root = self.new_profile_by_refid(refid, name, chara)
        if root is None:
            root = Node.void("playerdata")
            root.set_attribute("status", str(Status.NO_PROFILE))
        return root

    def handle_player22_write_music_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player22")
        if refid is None:
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return root

        songid = request.child_value("music_num")
        chart = {
            self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
            self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
            self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
            self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
        }[request.child_value("sheet_num")]
        medal = request.child_value("clearmedal")
        points = request.child_value("score")
        combo = request.child_value("combo")
        stats = {
            "cool": request.child_value("cool"),
            "great": request.child_value("great"),
            "good": request.child_value("good"),
            "bad": request.child_value("bad"),
        }
        medal = {
            self.GAME_PLAY_MEDAL_NO_PLAY: self.PLAY_MEDAL_NO_PLAY,
            self.GAME_PLAY_MEDAL_CIRCLE_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
            self.GAME_PLAY_MEDAL_DIAMOND_FAILED: self.PLAY_MEDAL_DIAMOND_FAILED,
            self.GAME_PLAY_MEDAL_STAR_FAILED: self.PLAY_MEDAL_STAR_FAILED,
            self.GAME_PLAY_MEDAL_EASY_CLEAR: self.PLAY_MEDAL_EASY_CLEAR,
            self.GAME_PLAY_MEDAL_CIRCLE_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
            self.GAME_PLAY_MEDAL_DIAMOND_CLEARED: self.PLAY_MEDAL_DIAMOND_CLEARED,
            self.GAME_PLAY_MEDAL_STAR_CLEARED: self.PLAY_MEDAL_STAR_CLEARED,
            self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
            self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
            self.GAME_PLAY_MEDAL_STAR_FULL_COMBO: self.PLAY_MEDAL_STAR_FULL_COMBO,
            self.GAME_PLAY_MEDAL_PERFECT: self.PLAY_MEDAL_PERFECT,
        }[medal]
        self.update_score(
            userid, songid, chart, points, medal, combo=combo, stats=stats
        )
        return root

    def handle_player22_write_course_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player22")
        if refid is None:
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return root

        # Grab info that we want to update
        total_score = request.child_value("total_score") or 0
        course_id = request.child_value("course_id")
        if course_id is not None:
            machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
            pref = request.child_value("pref") or self.get_machine_region()
            profile = self.get_profile(userid) or Profile(
                self.game, self.version, refid, 0
            )

            course = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                course_id,
                "course",
            ) or ValidatedDict({})

            stage_scores: Dict[int, int] = {}
            for child in request.children:
                if child.name != "stage":
                    continue

                stage = child.child_value("stage")
                score = child.child_value("score")

                if isinstance(stage, int) and isinstance(score, int):
                    stage_scores[stage] = score

            # Update the scores if this was a new high score.
            if total_score > course.get_int("total_score"):
                course.replace_int("total_score", total_score)
                course.replace_int("stage1_score", stage_scores.get(0, 0))
                course.replace_int("stage2_score", stage_scores.get(1, 0))
                course.replace_int("stage3_score", stage_scores.get(2, 0))
                course.replace_int("stage4_score", stage_scores.get(3, 0))

                # Only update ojamas used if this was an updated score.
                course.replace_int("clear_norma", request.child_value("clear_norma"))

                # Only udpate what location and prefecture this was scored in
                # if we updated our score.
                course.replace_int("pref", pref)
                course.replace_int("lid", machine.arcade)

            # Update medal and combo values.
            course.replace_int(
                "max_combo",
                max(course.get_int("max_combo"), request.child_value("max_combo")),
            )
            course.replace_int(
                "clear_medal",
                max(course.get_int("clear_medal"), request.child_value("clear_medal")),
            )

            # Add one to the play count for this course.
            course.increment_int("play_cnt")

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                course_id,
                "course",
                course,
            )

            # Now, attempt to calculate ranking for this user for this run.
            all_courses = self.data.local.user.get_all_achievements(
                self.game,
                self.version,
                achievementid=course_id,
                achievementtype="course",
            )
            global_ranking = sorted(
                all_courses,
                key=lambda entry: entry[1].data.get_int("total_score"),
                reverse=True,
            )
            pref_ranking = [
                c for c in global_ranking if c[1].data.get_int("pref") == pref
            ]
            local_ranking = [
                c for c in global_ranking if c[1].data.get_int("lid") == machine.arcade
            ]

            global_rank = len(global_ranking)
            pref_rank = len(pref_ranking)
            local_rank = len(local_ranking)

            for i, rank in enumerate(global_ranking):
                if userid == rank[0]:
                    global_rank = i + 1
                    break
            for i, rank in enumerate(pref_ranking):
                if userid == rank[0]:
                    pref_rank = i + 1
                    break
            for i, rank in enumerate(local_ranking):
                if userid == rank[0]:
                    local_rank = i + 1
                    break

            # Now, return it all.
            for rank_type, personal_rank, count in [
                ("all_ranking", global_rank, len(global_ranking)),
                ("pref_ranking", pref_rank, len(pref_ranking)),
                ("location_ranking", local_rank, len(local_ranking)),
            ]:
                ranknode = Node.void(rank_type)
                root.add_child(ranknode)
                ranknode.add_child(Node.string("name", profile.get_str("name", "なし")))
                ranknode.add_child(Node.s16("chara_num", profile.get_int("chara", -1)))
                ranknode.add_child(Node.s32("stage1_score", stage_scores.get(0, 0)))
                ranknode.add_child(Node.s32("stage2_score", stage_scores.get(1, 0)))
                ranknode.add_child(Node.s32("stage3_score", stage_scores.get(2, 0)))
                ranknode.add_child(Node.s32("stage4_score", stage_scores.get(3, 0)))
                ranknode.add_child(Node.s32("total_score", total_score))
                ranknode.add_child(Node.s16("player_count", count))
                ranknode.add_child(Node.s16("player_rank", personal_rank))

        return root

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("player22")

        # Result
        root.add_child(Node.s8("result", 0))

        # Set up account
        account = Node.void("account")
        root.add_child(account)
        account.add_child(Node.string("name", profile.get_str("name", "なし")))
        account.add_child(Node.string("g_pm_id", ID.format_extid(profile.extid)))
        account.add_child(Node.s8("tutorial", profile.get_int("tutorial", -1)))
        account.add_child(Node.s16("read_news", profile.get_int("read_news", 0)))
        account.add_child(Node.s8("staff", 0))
        account.add_child(Node.s8("is_conv", 0))
        account.add_child(Node.s16("item_type", 0))
        account.add_child(Node.s16("item_id", 0))
        account.add_child(
            Node.s16_array("license_data", [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1])
        )

        # Statistics section and scores section
        statistics = self.get_play_statistics(userid)
        account.add_child(Node.s16("total_play_cnt", statistics.total_plays))
        account.add_child(Node.s16("today_play_cnt", statistics.today_plays))
        account.add_child(Node.s16("consecutive_days", statistics.consecutive_days))
        account.add_child(Node.s16("total_days", statistics.total_days))
        account.add_child(Node.s16("interval_day", 0))

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
        account.add_child(Node.u8("active_fr_num", rivalcount))

        # Add scores section
        last_played = [
            x[0]
            for x in self.data.local.music.get_last_played(
                self.game, self.version, userid, 5
            )
        ]
        most_played = [
            x[0]
            for x in self.data.local.music.get_most_played(
                self.game, self.version, userid, 10
            )
        ]
        while len(last_played) < 5:
            last_played.append(-1)
        while len(most_played) < 10:
            most_played.append(-1)

        account.add_child(Node.s16_array("my_best", most_played))
        account.add_child(Node.s16_array("latest_music", last_played))

        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue

            points = score.points
            medal = score.data.get_int("medal")

            music = Node.void("music")
            root.add_child(music)
            music.add_child(Node.s16("music_num", score.id))
            music.add_child(
                Node.u8(
                    "sheet_num",
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart],
                )
            )
            music.add_child(Node.s16("cnt", score.plays))
            music.add_child(Node.s32("score", points))
            music.add_child(
                Node.u8(
                    "clear_type",
                    {
                        self.PLAY_MEDAL_NO_PLAY: self.GAME_PLAY_MEDAL_NO_PLAY,
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[medal],
                )
            )
            music.add_child(Node.s32("old_score", 0))
            music.add_child(Node.u8("old_clear_type", 0))

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
        netvs.add_child(Node.u32("netvs_play_cnt", 0))
        for dialog in [0, 1, 2, 3, 4, 5]:
            netvs.add_child(Node.string("dialog", f"dialog#{dialog}"))

        # Set up config
        config = Node.void("config")
        root.add_child(config)
        config.add_child(Node.u8("mode", profile.get_int("mode", 0)))
        config.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        config.add_child(Node.s16("music", profile.get_int("music", -1)))
        config.add_child(Node.u8("sheet", profile.get_int("sheet", 0)))
        config.add_child(Node.s8("category", profile.get_int("category", 1)))
        config.add_child(Node.s8("sub_category", profile.get_int("sub_category", -1)))
        config.add_child(
            Node.s8("chara_category", profile.get_int("chara_category", -1))
        )
        config.add_child(Node.s16("story_id", profile.get_int("story_id", -1)))
        config.add_child(Node.s16("course_id", profile.get_int("course_id", -1)))
        config.add_child(Node.s8("course_folder", profile.get_int("course_folder", -1)))
        config.add_child(Node.s8("story_folder", profile.get_int("story_folder", -1)))
        config.add_child(Node.s8("ms_banner_disp", profile.get_int("ms_banner_disp")))
        config.add_child(Node.s8("ms_down_info", profile.get_int("ms_down_info")))
        config.add_child(Node.s8("ms_side_info", profile.get_int("ms_side_info")))
        config.add_child(Node.s8("ms_raise_type", profile.get_int("ms_raise_type")))
        config.add_child(Node.s8("ms_rnd_type", profile.get_int("ms_rnd_type")))

        # Set up option
        option_dict = profile.get_dict("option")
        option = Node.void("option")
        root.add_child(option)
        option.add_child(Node.s16("hispeed", option_dict.get_int("hispeed", 10)))
        option.add_child(Node.u8("popkun", option_dict.get_int("popkun", 0)))
        option.add_child(Node.bool("hidden", option_dict.get_bool("hidden", False)))
        option.add_child(
            Node.s16("hidden_rate", option_dict.get_int("hidden_rate", -1))
        )
        option.add_child(Node.bool("sudden", option_dict.get_bool("sudden", False)))
        option.add_child(
            Node.s16("sudden_rate", option_dict.get_int("sudden_rate", -1))
        )
        option.add_child(Node.s8("randmir", option_dict.get_int("randmir", 0)))
        option.add_child(Node.s8("gauge_type", option_dict.get_int("gauge_type", 0)))
        option.add_child(Node.u8("ojama_0", option_dict.get_int("ojama_0", 0)))
        option.add_child(Node.u8("ojama_1", option_dict.get_int("ojama_1", 0)))
        option.add_child(
            Node.bool("forever_0", option_dict.get_bool("forever_0", False))
        )
        option.add_child(
            Node.bool("forever_1", option_dict.get_bool("forever_1", False))
        )
        option.add_child(
            Node.bool("full_setting", option_dict.get_bool("full_setting", False))
        )

        # Set up info
        info = Node.void("info")
        root.add_child(info)
        info.add_child(Node.u16("ep", profile.get_int("ep", 0)))
        info.add_child(Node.u16("ap", profile.get_int("ap", 0)))

        # Set up custom_cate
        custom_cate = Node.void("custom_cate")
        root.add_child(custom_cate)
        custom_cate.add_child(Node.s8("valid", 0))
        custom_cate.add_child(Node.s8("lv_min", -1))
        custom_cate.add_child(Node.s8("lv_max", -1))
        custom_cate.add_child(Node.s8("medal_min", -1))
        custom_cate.add_child(Node.s8("medal_max", -1))
        custom_cate.add_child(Node.s8("friend_no", -1))
        custom_cate.add_child(Node.s8("score_flg", -1))

        # Set up customize
        customize_dict = profile.get_dict("customize")
        customize = Node.void("customize")
        root.add_child(customize)
        customize.add_child(Node.u16("effect", customize_dict.get_int("effect")))
        customize.add_child(Node.u16("hukidashi", customize_dict.get_int("hukidashi")))
        customize.add_child(Node.u16("font", customize_dict.get_int("font")))
        customize.add_child(Node.u16("comment_1", customize_dict.get_int("comment_1")))
        customize.add_child(Node.u16("comment_2", customize_dict.get_int("comment_2")))

        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            songs = {
                song.id
                for song in self.data.local.music.get_all_songs(self.game, self.version)
            }
            for song in songs:
                item = Node.void("item")
                root.add_child(item)
                item.add_child(Node.u8("type", 0))
                item.add_child(Node.u16("id", song))
                item.add_child(Node.u16("param", 15))
                item.add_child(Node.bool("is_new", False))

        # Set up achievements
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        for achievement in achievements:
            if achievement.type == "item":
                itemtype = achievement.data.get_int("type")
                param = achievement.data.get_int("param")

                # Maximum for each type is as follows:
                # 0, 1423 - These are song unlocks as far as I can tell, matches Eclale/UsaNeko.
                # 1, 2040
                # 2, 510
                # 3, 173
                # 4, 40
                # 5, 24
                # 6, 24
                # 7, 4158

                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # We already sent song unlocks in the force unlock section above.
                    continue

                item = Node.void("item")
                root.add_child(item)
                item.add_child(Node.u8("type", itemtype))
                item.add_child(Node.u16("id", achievement.id))
                item.add_child(Node.u16("param", param))
                item.add_child(Node.bool("is_new", False))

            elif achievement.type == "achievement":
                count = achievement.data.get_int("count")

                ach_node = Node.void("achievement")
                root.add_child(ach_node)
                ach_node.add_child(Node.u8("type", achievement.id))
                ach_node.add_child(Node.u32("count", count))

            elif achievement.type == "chara":
                friendship = achievement.data.get_int("friendship")

                chara = Node.void("chara_param")
                root.add_child(chara)
                chara.add_child(Node.u16("chara_id", achievement.id))
                chara.add_child(Node.u16("friendship", friendship))

            elif achievement.type == "story":
                chapter = achievement.data.get_int("chapter")
                gauge = achievement.data.get_int("gauge")
                cleared = achievement.data.get_bool("cleared")
                clear_chapter = achievement.data.get_int("clear_chapter")

                story = Node.void("story")
                root.add_child(story)
                story.add_child(Node.u32("story_id", achievement.id))
                story.add_child(Node.u32("chapter_id", chapter))
                story.add_child(Node.u16("gauge_point", gauge))
                story.add_child(Node.bool("is_cleared", cleared))
                story.add_child(Node.u32("clear_chapter", clear_chapter))

            elif achievement.type == "course":
                total_score = achievement.data.get_int("total_score")
                max_combo = achievement.data.get_int("max_combo")
                play_cnt = achievement.data.get_int("play_cnt")
                clear_medal = achievement.data.get_int("clear_medal")
                clear_norma = achievement.data.get_int("clear_norma")
                stage1_score = achievement.data.get_int("stage1_score")
                stage2_score = achievement.data.get_int("stage2_score")
                stage3_score = achievement.data.get_int("stage3_score")
                stage4_score = achievement.data.get_int("stage4_score")

                course = Node.void("course")
                root.add_child(course)
                course.add_child(Node.s16("course_id", achievement.id))
                course.add_child(Node.u8("clear_medal", clear_medal))
                course.add_child(Node.u8("clear_norma", clear_norma))
                course.add_child(Node.s32("stage1_score", stage1_score))
                course.add_child(Node.s32("stage2_score", stage2_score))
                course.add_child(Node.s32("stage3_score", stage3_score))
                course.add_child(Node.s32("stage4_score", stage4_score))
                course.add_child(Node.s32("total_score", total_score))
                course.add_child(
                    Node.s16("max_cmbo", max_combo)
                )  # Yes, it is misspelled.
                course.add_child(Node.s16("play_cnt", play_cnt))
                course.add_child(Node.s16("all_rank", 1))  # Unclear what this does.

        # There are also course_rank nodes, but it doesn't appear they get displayed
        # to the user anywhere.

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()

        account = request.child("account")
        if account is not None:
            newprofile.replace_int("tutorial", account.child_value("tutorial"))
            newprofile.replace_int("read_news", account.child_value("read_news"))

        info = request.child("info")
        if info is not None:
            newprofile.replace_int("ep", info.child_value("ep"))
            newprofile.replace_int("ap", info.child_value("ap"))

        config = request.child("config")
        if config is not None:
            newprofile.replace_int("mode", config.child_value("mode"))
            newprofile.replace_int("chara", config.child_value("chara"))
            newprofile.replace_int("music", config.child_value("music"))
            newprofile.replace_int("sheet", config.child_value("sheet"))
            newprofile.replace_int("category", config.child_value("category"))
            newprofile.replace_int("sub_category", config.child_value("sub_category"))
            newprofile.replace_int(
                "chara_category", config.child_value("chara_category")
            )
            newprofile.replace_int("story_id", config.child_value("story_id"))
            newprofile.replace_int("course_id", config.child_value("course_id"))
            newprofile.replace_int("course_folder", config.child_value("course_folder"))
            newprofile.replace_int("story_folder", config.child_value("story_folder"))
            newprofile.replace_int(
                "ms_banner_disp", config.child_value("ms_banner_disp")
            )
            newprofile.replace_int("ms_down_info", config.child_value("ms_down_info"))
            newprofile.replace_int("ms_side_info", config.child_value("ms_side_info"))
            newprofile.replace_int("ms_raise_type", config.child_value("ms_raise_type"))
            newprofile.replace_int("ms_rnd_type", config.child_value("ms_rnd_type"))

        option_dict = newprofile.get_dict("option")
        option = request.child("option")
        if option is not None:
            option_dict.replace_int("hispeed", option.child_value("hispeed"))
            option_dict.replace_int("popkun", option.child_value("popkun"))
            option_dict.replace_bool("hidden", option.child_value("hidden"))
            option_dict.replace_bool("sudden", option.child_value("sudden"))
            option_dict.replace_int("hidden_rate", option.child_value("hidden_rate"))
            option_dict.replace_int("sudden_rate", option.child_value("sudden_rate"))
            option_dict.replace_int("randmir", option.child_value("randmir"))
            option_dict.replace_int("gauge_type", option.child_value("gauge_type"))
            option_dict.replace_int("ojama_0", option.child_value("ojama_0"))
            option_dict.replace_int("ojama_1", option.child_value("ojama_1"))
            option_dict.replace_bool("forever_0", option.child_value("forever_0"))
            option_dict.replace_bool("forever_1", option.child_value("forever_1"))
            option_dict.replace_bool("full_setting", option.child_value("full_setting"))
        newprofile.replace_dict("option", option_dict)

        customize_dict = newprofile.get_dict("customize")
        customize = request.child("customize")
        if customize is not None:
            customize_dict.replace_int("effect", customize.child_value("effect"))
            customize_dict.replace_int("hukidashi", customize.child_value("hukidashi"))
            customize_dict.replace_int("font", customize.child_value("font"))
            customize_dict.replace_int("comment_1", customize.child_value("comment_1"))
            customize_dict.replace_int("comment_2", customize.child_value("comment_2"))
        newprofile.replace_dict("customize", customize_dict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract achievements
        game_config = self.get_game_config()
        for node in request.children:
            if node.name == "item":
                if not node.child_value("is_new"):
                    # No need to save this one
                    continue

                itemid = node.child_value("id")
                itemtype = node.child_value("type")
                param = node.child_value("param")

                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # If we enabled force song unlocks, don't save songs to the profile.
                    continue

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    "item",
                    {
                        "type": itemtype,
                        "param": param,
                    },
                )

            elif node.name == "achievement":
                achievementid = node.child_value("type")
                count = node.child_value("count")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    achievementid,
                    "achievement",
                    {
                        "count": count,
                    },
                )

            elif node.name == "chara_param":
                charaid = node.child_value("chara_id")
                friendship = node.child_value("friendship")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    charaid,
                    "chara",
                    {
                        "friendship": friendship,
                    },
                )

            elif node.name == "story":
                storyid = node.child_value("story_id")
                chapter = node.child_value("chapter_id")
                gauge = node.child_value("gauge_point")
                cleared = node.child_value("is_cleared")
                clear_chapter = node.child_value("clear_chapter")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    storyid,
                    "story",
                    {
                        "chapter": chapter,
                        "gauge": gauge,
                        "cleared": cleared,
                        "clear_chapter": clear_chapter,
                    },
                )

        return newprofile

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("playerdata")

        root.add_child(Node.string("name", profile.get_str("name", "なし")))
        root.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        root.add_child(Node.s32("option", profile.get_int("option", 0)))
        root.add_child(Node.s8("result", 1))

        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
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

            points = score.points
            medal = score.data.get_int("medal")

            music = Node.void("music")
            root.add_child(music)
            music.add_child(Node.s16("music_num", score.id))
            music.add_child(
                Node.u8(
                    "sheet_num",
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart],
                )
            )
            music.add_child(Node.s16("cnt", score.plays))
            music.add_child(Node.s32("score", 0))
            music.add_child(Node.u8("clear_type", 0))
            music.add_child(Node.s32("old_score", points))
            music.add_child(
                Node.u8(
                    "old_clear_type",
                    {
                        self.PLAY_MEDAL_NO_PLAY: self.GAME_PLAY_MEDAL_NO_PLAY,
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[medal],
                )
            )

        return root
