# vim: set fileencoding=utf-8
from abc import ABC, abstractmethod
import binascii
import random
from typing import Any, Dict, List, Optional, Tuple
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.common import Time, ID, Profile, ValidatedDict, Parallel
from bemani.data import Data, UserID, Achievement, Link
from bemani.protocol import Node


class PopnMusicModernBase(PopnMusicBase, ABC):
    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY: Final[int] = 0
    GAME_CHART_TYPE_NORMAL: Final[int] = 1
    GAME_CHART_TYPE_HYPER: Final[int] = 2
    GAME_CHART_TYPE_EX: Final[int] = 3

    # Medal type, as returned from the game
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

    # Rank type, as returned from the game
    GAME_PLAY_RANK_E: Final[int] = 1
    GAME_PLAY_RANK_D: Final[int] = 2
    GAME_PLAY_RANK_C: Final[int] = 3
    GAME_PLAY_RANK_B: Final[int] = 4
    GAME_PLAY_RANK_A: Final[int] = 5
    GAME_PLAY_RANK_AA: Final[int] = 6
    GAME_PLAY_RANK_AAA: Final[int] = 7
    GAME_PLAY_RANK_S: Final[int] = 8

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: int

    # Biggest deco part ID in the game
    GAME_MAX_DECO_ID: int

    # Return the local2 and lobby2 service so that Pop'n Music 24+ will
    # send game packets.
    extra_services: List[str] = [
        "local2",
        "lobby2",
    ]

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Dict[str, Any]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Once a week, insert a new course.
        """
        events = []
        if data.local.network.should_schedule(
            cls.game, cls.version, "course", "weekly"
        ):
            # Generate a new course list, save it to the DB.
            start_time, end_time = data.local.network.get_schedule_duration("weekly")
            all_songs = [
                song.id
                for song in data.local.music.get_all_songs(cls.game, cls.version)
            ]
            if all_songs:
                course_song = random.choice(all_songs)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "course",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "music": course_song,
                    },
                )
                events.append(
                    (
                        "pnm_course",
                        {
                            "version": cls.version,
                            "song": course_song,
                        },
                    )
                )

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "course", "weekly"
                )
        return events

    def __score_to_rank(self, score: int) -> int:
        if score < 50000:
            return self.GAME_PLAY_RANK_E
        if score < 62000:
            return self.GAME_PLAY_RANK_D
        if score < 72000:
            return self.GAME_PLAY_RANK_C
        if score < 82000:
            return self.GAME_PLAY_RANK_B
        if score < 90000:
            return self.GAME_PLAY_RANK_A
        if score < 95000:
            return self.GAME_PLAY_RANK_AA
        if score < 98000:
            return self.GAME_PLAY_RANK_AAA
        return self.GAME_PLAY_RANK_S

    def handle_lobby24_requests(self, request: Node) -> Node:
        # Stub out the entire lobby24 service
        return Node.void("lobby24")

    def handle_pcb24_error_request(self, request: Node) -> Node:
        return Node.void("pcb24")

    def handle_pcb24_boot_request(self, request: Node) -> Node:
        return Node.void("pcb24")

    def handle_pcb24_write_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("pcb_setting/name"))
        return Node.void("pcb24")

    @abstractmethod
    def get_common_config(self) -> Tuple[Dict[int, int], bool]:
        """
        Return a tuple of configuration options for sending the common node back
        to the client. The first parameter is a dictionary whose keys are event
        IDs and values are the event phase number. The second parameter is a bool
        representing whether or not to send areas.
        """

    def __construct_common_info(self, root: Node) -> None:
        phases, send_areas = self.get_common_config()

        for phaseid, phase_value in phases.items():
            phase = Node.void("phase")
            root.add_child(phase)
            phase.add_child(Node.s16("event_id", phaseid))
            phase.add_child(Node.s16("phase", phase_value))

        # Gather course information and course ranking for users.
        course_infos, achievements, profiles = Parallel.execute(
            [
                lambda: self.data.local.game.get_all_time_sensitive_settings(
                    self.game, self.version, "course"
                ),
                lambda: self.data.local.user.get_all_achievements(
                    self.game, self.version
                ),
                lambda: self.data.local.user.get_all_profiles(self.game, self.version),
            ]
        )
        # Sort courses by newest to oldest so we can grab the newest 256.
        course_infos = sorted(
            course_infos,
            key=lambda c: c["start_time"],
            reverse=True,
        )
        # Sort achievements within course ID from best to worst ranking.
        achievements_by_course_id: Dict[
            int, Dict[str, List[Tuple[UserID, Achievement]]]
        ] = {}
        type_to_chart_lut: Dict[str, str] = {
            f"course_{self.GAME_CHART_TYPE_EASY}": "loc_ranking_e",
            f"course_{self.GAME_CHART_TYPE_NORMAL}": "loc_ranking_n",
            f"course_{self.GAME_CHART_TYPE_HYPER}": "loc_ranking_h",
            f"course_{self.GAME_CHART_TYPE_EX}": "loc_ranking_ex",
        }
        for uid, ach in achievements:
            if ach.type[:7] != "course_":
                continue
            if ach.id not in achievements_by_course_id:
                achievements_by_course_id[ach.id] = {
                    "loc_ranking_e": [],
                    "loc_ranking_n": [],
                    "loc_ranking_h": [],
                    "loc_ranking_ex": [],
                }
            achievements_by_course_id[ach.id][type_to_chart_lut[ach.type]].append(
                (uid, ach)
            )
        for courseid in achievements_by_course_id:
            for chart in [
                "loc_ranking_e",
                "loc_ranking_n",
                "loc_ranking_h",
                "loc_ranking_ex",
            ]:
                achievements_by_course_id[courseid][chart] = sorted(
                    achievements_by_course_id[courseid][chart],
                    key=lambda uid_and_ach: uid_and_ach[1].data.get_int("score"),
                    reverse=True,
                )

        # Cache of userID to profile
        userid_to_profile: Dict[UserID, Profile] = {
            uid: profile for (uid, profile) in profiles
        }

        # Course ranking info for the last 256 courses
        for course_info in course_infos[:256]:
            course_id = int(course_info["start_time"] / 604800)
            course_rankings = achievements_by_course_id.get(course_id, {})

            ranking_info = Node.void("ranking_info")
            root.add_child(ranking_info)
            ranking_info.add_child(Node.s16("course_id", course_id))
            ranking_info.add_child(
                Node.u64("start_date", course_info["start_time"] * 1000)
            )
            ranking_info.add_child(Node.u64("end_date", course_info["end_time"] * 1000))
            ranking_info.add_child(Node.s32("music_id", course_info["music"]))

            # Top 20 rankings for each particular chart.
            for name in [
                "loc_ranking_e",
                "loc_ranking_n",
                "loc_ranking_h",
                "loc_ranking_ex",
            ]:
                chart_rankings = course_rankings.get(name, [])

                for pos, (uid, ach) in enumerate(chart_rankings[:20]):
                    profile = userid_to_profile.get(
                        uid, Profile(self.game, self.version, "", 0)
                    )

                    subnode = Node.void(name)
                    ranking_info.add_child(subnode)
                    subnode.add_child(Node.s16("rank", pos + 1))
                    subnode.add_child(Node.string("name", profile.get_str("name")))
                    subnode.add_child(
                        Node.s16("chara_num", profile.get_int("chara", -1))
                    )
                    subnode.add_child(
                        Node.s32("total_score", ach.data.get_int("score"))
                    )
                    subnode.add_child(
                        Node.u8("clear_type", ach.data.get_int("clear_type"))
                    )
                    subnode.add_child(
                        Node.u8("clear_rank", ach.data.get_int("clear_rank"))
                    )

        if send_areas:
            for area_id in range(1, 16):
                area = Node.void("area")
                root.add_child(area)
                area.add_child(Node.s16("area_id", area_id))
                area.add_child(Node.u64("end_date", 0))
                area.add_child(Node.s16("medal_id", area_id))
                area.add_child(Node.bool("is_limit", False))

        for choco_id in range(0, 5):
            choco = Node.void("choco")
            root.add_child(choco)
            choco.add_child(Node.s16("choco_id", choco_id))
            choco.add_child(Node.s32("param", -1))

        # Set up goods, educated guess here.
        for goods_id in range(self.GAME_MAX_DECO_ID):
            if goods_id < 15:
                price = 30
            elif goods_id < 30:
                price = 40
            elif goods_id < 45:
                price = 60
            elif goods_id < 60:
                price = 80
            elif goods_id < 98:
                price = 200
            else:
                price = 250
            goods = Node.void("goods")
            root.add_child(goods)
            goods.add_child(Node.s32("item_id", goods_id + 1))
            goods.add_child(Node.s16("item_type", 3))
            goods.add_child(Node.s32("price", price))
            goods.add_child(Node.s16("goods_type", 0))

        # Ignoring NAVIfes node, we don't set these.
        # fes = Node.void('fes')
        # fes.add_child(Node.s16('fes_id', -1))
        # fes.add_child(Node.s32('gauge_count', -1))
        # fes.add_child(Node.s32_array('gauge', [-1, -1, -1, -1, -1, -1]))
        # fes.add_child(Node.s32_array('music', [-1, -1, -1, -1, -1, -1]))
        # fes.add_child(Node.s16('r', -1))
        # fes.add_child(Node.s16('g', -1))
        # fes.add_child(Node.s16('b', -1))
        # fes.add_child(Node.s16('poster', -1))

        # Calculate most popular characters
        profiles = self.data.remote.user.get_all_profiles(self.game, self.version)
        charas: Dict[int, int] = {}
        for _userid, profile in profiles:
            chara = profile.get_int("chara", -1)
            if chara <= 0:
                continue
            if chara not in charas:
                charas[chara] = 1
            else:
                charas[chara] = charas[chara] + 1

        # Order a typle by most popular character to least popular character
        charamap = sorted(
            [(c, charas[c]) for c in charas],
            key=lambda c: c[1],
            reverse=True,
        )

        # Top 20 Popular characters
        for rank, (charaid, _usecount) in enumerate(charamap[:20]):
            popular = Node.void("popular")
            root.add_child(popular)
            popular.add_child(Node.s16("rank", rank + 1))
            popular.add_child(Node.s16("chara_num", charaid))

        # Top 500 Popular music
        for songid, _plays in self.data.local.music.get_hit_chart(
            self.game, self.version, 500
        ):
            popular_music = Node.void("popular_music")
            root.add_child(popular_music)
            popular_music.add_child(Node.s16("music_num", songid))

        # Ignoring recommended music, we don't set this
        # recommend = Node.void('recommend')
        # root.add_child(recommend)
        # recommend.add_child(Node.s32_array('music_no', [-1] * 30))

        # Ignoring mission points, we don't set these.
        # mission_point = Node.void('mission_point')
        # mission_point.add_child(Node.s32('point', -1))
        # mission_point.add_child(Node.s32('bonus_point', -1))

        # Ignoring medals, we don't set these.
        # medal = Node.void('medal')
        # medal.add_child(Node.s16('medal_id', -1))
        # medal.add_child(Node.s16('percent', -1))

        # Ignoring chara ranking, we don't set these.
        # chara_ranking = Node.void('chara_ranking')
        # chara_ranking.add_child(Node.s32('rank', -1))
        # chara_ranking.add_child(Node.s32('kind_id', -1))
        # chara_ranking.add_child(Node.s32('point', -1))
        # chara_ranking.add_child(Node.s32('month', -1))

    def handle_info24_common_request(self, root: Node) -> Node:
        root = Node.void("info24")
        self.__construct_common_info(root)
        return root

    def handle_player24_new_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        if root is None:
            root = Node.void("player24")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player24_conversion_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        chara = request.child_value("chara")
        achievements: List[Achievement] = []
        for node in request.children:
            if node.name == "item":
                itemid = node.child_value("id")
                itemtype = node.child_value("type")
                param = node.child_value("param")
                is_new = node.child_value("is_new")
                get_time = node.child_value("get_time")

                achievements.append(
                    Achievement(
                        itemid,
                        f"item_{itemtype}",
                        0,
                        {
                            "param": param,
                            "is_new": is_new,
                            "get_time": get_time,
                        },
                    )
                )
        root = self.new_profile_by_refid(refid, name, chara, achievements=achievements)
        if root is None:
            root = Node.void("player24")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player24_read_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        root = self.get_profile_by_refid(refid, self.OLD_PROFILE_FALLTHROUGH)
        if root is None:
            root = Node.void("player24")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player24_write_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            oldprofile = self.get_profile(userid) or Profile(
                self.game, self.version, refid, 0
            )
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)

        return Node.void("player24")

    def handle_player24_update_ranking_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        root = Node.void("player24")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            course_id = request.child_value("course_id")
            chart = request.child_value("sheet_num")
            score = request.child_value("total_score")
            clear_type = request.child_value("clear_type")
            clear_rank = request.child_value("clear_rank")
            prefecture = request.child_value("pref")
            loc_id = ID.parse_machine_id(request.child_value("location_id"))
            course_type = f"course_{chart}"

            old_course = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                course_id,
                course_type,
            )
            if old_course is None:
                old_course = ValidatedDict()

            new_course = ValidatedDict(
                {
                    "score": max(score, old_course.get_int("score")),
                    "clear_type": max(clear_type, old_course.get_int("clear_type")),
                    "clear_rank": max(clear_rank, old_course.get_int("clear_rank")),
                    "pref": prefecture,
                    "lid": loc_id,
                    "count": old_course.get_int("count") + 1,
                }
            )

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                course_id,
                course_type,
                new_course,
            )

            # Handle fetching all scores
            uids_and_courses, profile = Parallel.execute(
                [
                    lambda: self.data.local.user.get_all_achievements(
                        self.game, self.version
                    ),
                    lambda: self.get_profile(userid)
                    or Profile(self.game, self.version, "", 0),
                ]
            )

            # Grab a sorted list of all scores for this course and chart
            global_uids_and_courses = sorted(
                [
                    (uid, ach)
                    for (uid, ach) in uids_and_courses
                    if ach.type == course_type and ach.id == course_id
                ],
                key=lambda uid_and_course: uid_and_course[1].data.get_int("score"),
                reverse=True,
            )
            # Grab smaller lists that contain only sorted for our prefecture/location
            pref_uids_and_courses = [
                (uid, ach)
                for (uid, ach) in global_uids_and_courses
                if ach.data.get_int("pref") == prefecture
            ]
            loc_uids_and_courses = [
                (uid, ach)
                for (uid, ach) in global_uids_and_courses
                if ach.data.get_int("lid") == loc_id
            ]

            def _get_rank(uac: List[Tuple[UserID, Achievement]]) -> Optional[int]:
                for rank, (uid, _) in enumerate(uac):
                    if uid == userid:
                        return rank + 1
                return None

            for nodename, ranklist in [
                ("all_ranking", global_uids_and_courses),
                ("pref_ranking", pref_uids_and_courses),
                ("location_ranking", loc_uids_and_courses),
            ]:
                # Grab the rank, bail if we don't have any answer since the game doesn't
                # require a response.
                rank = _get_rank(ranklist)
                if rank is None:
                    continue

                # Send back the data for this ranking.
                node = Node.void(nodename)
                root.add_child(node)
                node.add_child(Node.string("name", profile.get_str("name", "なし")))
                node.add_child(Node.s16("chara_num", profile.get_int("chara", -1)))
                node.add_child(Node.s32("total_score", new_course.get_int("score")))
                node.add_child(Node.u8("clear_type", new_course.get_int("clear_type")))
                node.add_child(Node.u8("clear_rank", new_course.get_int("clear_rank")))
                node.add_child(Node.s16("player_count", len(ranklist)))
                node.add_child(Node.s16("player_rank", rank))

        return root

    def handle_player24_friend_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        no = int(request.attribute("no", "-1"))

        root = Node.void("player24")
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

        # First, output general profile info.
        friend = Node.void("friend")
        root.add_child(friend)
        friend.add_child(Node.s16("no", no))
        friend.add_child(
            Node.string("g_pm_id", self.format_extid(rivalprofile.extid))
        )  # UsaNeko formats on its own
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
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
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
            music.set_attribute("clearrank", str(self.__score_to_rank(score.points)))
            music.set_attribute(
                "cleartype",
                str(
                    {
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

        achievements = self.data.local.user.get_achievements(
            self.game, self.version, rivalid
        )
        for achievement in achievements:
            if achievement.type[:7] == "course_":
                sheet = int(achievement.type[7:])

                course_data = Node.void("course_data")
                root.add_child(course_data)
                course_data.add_child(Node.s16("course_id", achievement.id))
                course_data.add_child(
                    Node.u8("clear_type", achievement.data.get_int("clear_type"))
                )
                course_data.add_child(
                    Node.u8("clear_rank", achievement.data.get_int("clear_rank"))
                )
                course_data.add_child(
                    Node.s32("total_score", achievement.data.get_int("score"))
                )
                course_data.add_child(
                    Node.s32("update_count", achievement.data.get_int("count"))
                )
                course_data.add_child(Node.u8("sheet_num", sheet))

        return root

    def handle_player24_read_score_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return Node.void("player24")

        root = Node.void("player24")
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
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

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
            music.add_child(Node.s32("score", score.points))
            music.add_child(
                Node.u8(
                    "clear_type",
                    {
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
                    }[score.data.get_int("medal")],
                )
            )
            music.add_child(Node.u8("clear_rank", self.__score_to_rank(score.points)))
            music.add_child(Node.s16("cnt", score.plays))

        return root

    def handle_player24_write_music_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player24")
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
        medal = request.child_value("clear_type")
        points = request.child_value("score")
        combo = request.child_value("combo")
        stats = {
            "cool": request.child_value("cool"),
            "great": request.child_value("great"),
            "good": request.child_value("good"),
            "bad": request.child_value("bad"),
        }
        medal = {
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

        if request.child_value("is_image_store") == 1:
            self.broadcast_score(userid, songid, chart, medal, points, combo, stats)

        return root

    def handle_player24_start_request(self, request: Node) -> Node:
        root = Node.void("player24")
        root.add_child(Node.s32("play_id", 0))
        self.__construct_common_info(root)
        return root

    def handle_player24_logout_request(self, request: Node) -> Node:
        return Node.void("player24")

    def handle_player24_buy_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            itemid = request.child_value("id")
            itemtype = request.child_value("type")
            itemparam = request.child_value("param")

            price = request.child_value("price")
            lumina = request.child_value("lumina")

            if lumina >= price:
                # Update player lumina balance
                profile = self.get_profile(userid) or Profile(
                    self.game, self.version, refid, 0
                )
                profile.replace_int("player_point", lumina - price)
                self.put_profile(userid, profile)

                # Grant the object
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    f"item_{itemtype}",
                    {
                        "param": itemparam,
                        "is_new": True,
                    },
                )

        return Node.void("player24")

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("player24")
        root.add_child(Node.string("name", profile.get_str("name", "なし")))
        root.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        root.add_child(Node.s8("con_type", 0))
        root.add_child(Node.s8("result", 1))

        # Scores
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
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

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
            music.add_child(Node.s32("score", score.points))
            music.add_child(
                Node.u8(
                    "clear_type",
                    {
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
                    }[score.data.get_int("medal")],
                )
            )
            music.add_child(Node.u8("clear_rank", self.__score_to_rank(score.points)))
            music.add_child(Node.s16("cnt", score.plays))

        return root

    def format_extid(self, extid: int) -> str:
        data = str(extid)
        crc = abs(binascii.crc32(data.encode("ascii"))) % 10000
        return f"{data}{crc:04d}"

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("player24")

        # Mark this as a current profile
        root.add_child(Node.s8("result", 0))

        # Basic account info
        account = Node.void("account")
        root.add_child(account)
        account.add_child(Node.string("g_pm_id", self.format_extid(profile.extid)))
        account.add_child(Node.string("name", profile.get_str("name", "なし")))
        account.add_child(Node.s16("area_id", profile.get_int("area_id")))
        account.add_child(Node.s16("use_navi", profile.get_int("use_navi")))
        account.add_child(Node.s16("read_news", profile.get_int("read_news")))
        account.add_child(
            Node.s16_array("nice", profile.get_int_array("nice", 30, [-1] * 30))
        )
        account.add_child(
            Node.s16_array(
                "favorite_chara", profile.get_int_array("favorite_chara", 20, [-1] * 20)
            )
        )
        account.add_child(
            Node.s16_array(
                "special_area", profile.get_int_array("special_area", 8, [-1] * 8)
            )
        )
        account.add_child(
            Node.s16_array(
                "chocolate_charalist",
                profile.get_int_array("chocolate_charalist", 5, [-1] * 5),
            )
        )
        account.add_child(
            Node.s32("chocolate_sp_chara", profile.get_int("chocolate_sp_chara", -1))
        )
        account.add_child(
            Node.s32("chocolate_pass_cnt", profile.get_int("chocolate_pass_cnt"))
        )
        account.add_child(
            Node.s32("chocolate_hon_cnt", profile.get_int("chocolate_hon_cnt"))
        )
        account.add_child(
            Node.s16_array(
                "teacher_setting",
                profile.get_int_array("teacher_setting", 10, [-1] * 10),
            )
        )
        account.add_child(
            Node.bool("welcom_pack", False)
        )  # Set to true to grant extra stage no matter what.
        account.add_child(Node.s32("ranking_node", profile.get_int("ranking_node")))
        account.add_child(
            Node.s32("chara_ranking_kind_id", profile.get_int("chara_ranking_kind_id"))
        )
        account.add_child(
            Node.s8("navi_evolution_flg", profile.get_int("navi_evolution_flg"))
        )
        account.add_child(
            Node.s32("ranking_news_last_no", profile.get_int("ranking_news_last_no"))
        )
        account.add_child(Node.s32("power_point", profile.get_int("power_point")))
        account.add_child(
            Node.s32("player_point", profile.get_int("player_point", 300))
        )
        account.add_child(
            Node.s32_array(
                "power_point_list",
                profile.get_int_array("power_point_list", 20, [-1] * 20),
            )
        )

        # Tutorial handling is all sorts of crazy in UsaNeko. the tutorial flag
        # is split into two values. The game uses the flag modulo 100 for navigation
        # tutorial progress, and the flag divided by 100 for the hold note tutorial.
        # The hold note tutorial will activate the first time you choose a song with
        # hold notes in it, regardless of whether you say yes/no. The total times you
        # have ever played Pop'n Music also factors in, as the game will only attempt
        # to offer you the basic "how to play" tutorial screen and song on the playthrough
        # attempt where the "total_play_cnt" value is 1. The game expects this to be 1-based,
        # and if you set it to 0 for the first playthorough then it will play a mandatory
        # cursed tutorial stage on the second profile load using the chart of your last
        # played song and keysounds of system menu entries. Valid values for each of the
        # two tutorial values is as follows:
        #
        # Lower values:
        #   0 - Brand new profile and user has not been prompted to choose any tutorials.
        #       Prompts the user for the nagivation tutorial. If the user selects "no" then
        #       moves the tutorial state to "1" at the end of the round. If the user selects
        #       "yes" then moves the tutorial state to "3" immediately and starts the navigation
        #       tutorial. If the total play count for this user is "1" when this value is hit,
        #       the game will offer a basic "how to play" tutorial that can be played or skipped.
        #   1 - Prompt the user on the mode select screen asking them if they want to see
        #       the navigation tutorial. If the user selects "no" then moves the tutorial state
        #       to "2" after the round. If the user selects "yes" then moves the tutorial state
        #       to "3" immediately. If the total play count for this user is "1" when this value
        #       is hit, then the game will bug out and play the hold note tutorial and then crash.
        #   2 - Prompt the user on the mode select screen asking them if they want to see
        #       the navigation tutorial. If the user selects "no" then moves the tutorial state
        #       to "8" immediately. If the user selects "yes" then moves the tutorial state
        #       to "3" immediately. If the total play count for this user is "1" when this value
        #       is hit, then the game will bug out and play the hold note tutorial and then crash.
        #   3 - Display some tutorial elements on most screens, and then advance the tutorial
        #       state to "4" on profile save.
        #   4 - Display some tutorial elements on most screens, and then advance the tutorial
        #       state to "5" on profile save.
        #   5 - Display some tutorial elements on most screens, and then prompt user with a
        #       repeat tutorial question. If the user selects "no" then moves the tutorial
        #       state to "8". If the user selects "yes" then moves the tutorial state to "3".
        #   6 - Do nothing, display nothing, but advance the tutorial state to "7" at the
        #       end of the game. It seems that nothing requests this state.
        #   7 - Display guide information prompt on the option select screen. Game moves
        #       this to "8" after this tutorial has been displayed. It appears that there is
        #       code to go to this state instead of "8" when selecting "no" on the navigation
        #       tutorial prompt but only when the total play count is "1". That crashes the game
        #       as documented above, so it is not clear how this state was ever reachable.
        #   8 - Do not display any more tutorial stuff, this is a terminal state.
        #
        # Upper values:
        #   0 - Brand new profile and user has not been asked for the above navigation tutorial
        #       or shown an optional "how to play" tutorial. The game will advance this to "1"
        #       after going through the mode and character select screens, but only if the total
        #       play count is "1".
        #   1 - Hold note tutorial has not been activated yet and will be displayed when
        #       the player chooses a song with hold notes. Game moves this to "2" after this
        #       tutorial has been activated.
        #   2 - Hold note tutorial was displayed to the user, but the mini-tutorial showing
        #       the hold note indicator that pops up after the hold note tutorial has not
        #       been displayed yet. Presumably this is just in case you play a hold note
        #       song on your last stage. Game moves this to "3" after this tutorial has been
        #       displayed.
        #   3 - All hold note tutorials are finished, this is a terminal state.
        statistics = self.get_play_statistics(userid)
        account.add_child(
            Node.s16(
                "tutorial",
                profile.get_int("tutorial", 100 if statistics.total_plays > 1 else 0),
            )
        )

        # Stuff we never change
        account.add_child(Node.s8("staff", 0))
        account.add_child(Node.s16("item_type", 0))
        account.add_child(Node.s16("item_id", 0))
        account.add_child(Node.s8("is_conv", 0))
        account.add_child(Node.s16_array("license_data", [-1] * 20))

        # Song statistics
        last_played = [
            x[0]
            for x in self.data.local.music.get_last_played(
                self.game, self.version, userid, 10
            )
        ]
        most_played = [
            x[0]
            for x in self.data.local.music.get_most_played(
                self.game, self.version, userid, 20
            )
        ]
        while len(last_played) < 10:
            last_played.append(-1)
        while len(most_played) < 20:
            most_played.append(-1)

        account.add_child(Node.s16_array("my_best", most_played))
        account.add_child(Node.s16_array("latest_music", last_played))

        # Player statistics
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

        # eAmuse account link
        eaappli = Node.void("eaappli")
        root.add_child(eaappli)
        eaappli.add_child(
            Node.s8(
                "relation",
                1 if self.data.triggers.has_broadcast_destination(self.game) else -1,
            )
        )

        # Player info
        info = Node.void("info")
        root.add_child(info)
        info.add_child(Node.u16("ep", profile.get_int("ep")))

        # Player config
        config = Node.void("config")
        root.add_child(config)
        config.add_child(Node.u8("mode", profile.get_int("mode")))
        config.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        config.add_child(Node.s16("music", profile.get_int("music", -1)))
        config.add_child(Node.u8("sheet", profile.get_int("sheet")))
        config.add_child(Node.s8("category", profile.get_int("category", -1)))
        config.add_child(Node.s8("sub_category", profile.get_int("sub_category", -1)))
        config.add_child(
            Node.s8("chara_category", profile.get_int("chara_category", -1))
        )
        config.add_child(Node.s16("course_id", profile.get_int("course_id", -1)))
        config.add_child(Node.s8("course_folder", profile.get_int("course_folder", -1)))
        config.add_child(
            Node.s8("ms_banner_disp", profile.get_int("ms_banner_disp", -1))
        )
        config.add_child(Node.s8("ms_down_info", profile.get_int("ms_down_info", -1)))
        config.add_child(Node.s8("ms_side_info", profile.get_int("ms_side_info", -1)))
        config.add_child(Node.s8("ms_raise_type", profile.get_int("ms_raise_type", -1)))
        config.add_child(Node.s8("ms_rnd_type", profile.get_int("ms_rnd_type", -1)))
        config.add_child(Node.s8("banner_sort", profile.get_int("banner_sort", -1)))

        # Player options
        option = Node.void("option")
        option_dict = profile.get_dict("option")
        root.add_child(option)
        option.add_child(Node.s16("hispeed", option_dict.get_int("hispeed")))
        option.add_child(Node.u8("popkun", option_dict.get_int("popkun")))
        option.add_child(Node.bool("hidden", option_dict.get_bool("hidden")))
        option.add_child(Node.s16("hidden_rate", option_dict.get_int("hidden_rate")))
        option.add_child(Node.bool("sudden", option_dict.get_bool("sudden")))
        option.add_child(Node.s16("sudden_rate", option_dict.get_int("sudden_rate")))
        option.add_child(Node.s8("randmir", option_dict.get_int("randmir")))
        option.add_child(Node.s8("gauge_type", option_dict.get_int("gauge_type")))
        option.add_child(Node.u8("ojama_0", option_dict.get_int("ojama_0")))
        option.add_child(Node.u8("ojama_1", option_dict.get_int("ojama_1")))
        option.add_child(Node.bool("forever_0", option_dict.get_bool("forever_0")))
        option.add_child(Node.bool("forever_1", option_dict.get_bool("forever_1")))
        option.add_child(
            Node.bool("full_setting", option_dict.get_bool("full_setting"))
        )
        option.add_child(Node.u8("judge", option_dict.get_int("judge")))
        option.add_child(Node.s8("guide_se", option_dict.get_int("guide_se")))

        # Player custom category
        custom_cate = Node.void("custom_cate")
        root.add_child(custom_cate)
        custom_cate.add_child(Node.s8("valid", 0))
        custom_cate.add_child(Node.s8("lv_min", -1))
        custom_cate.add_child(Node.s8("lv_max", -1))
        custom_cate.add_child(Node.s8("medal_min", -1))
        custom_cate.add_child(Node.s8("medal_max", -1))
        custom_cate.add_child(Node.s8("friend_no", -1))
        custom_cate.add_child(Node.s8("score_flg", -1))

        # Navi data
        navi_data = Node.void("navi_data")
        root.add_child(navi_data)
        if "navi_points" in profile:
            navi_data.add_child(
                Node.s32_array("raisePoint", profile.get_int_array("navi_points", 5))
            )

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
                item.add_child(Node.u64("get_time", 0))

        # Set up achievements
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        for achievement in achievements:
            if achievement.type[:5] == "item_":
                itemtype = int(achievement.type[5:])
                param = achievement.data.get_int("param")
                is_new = achievement.data.get_bool("is_new")
                get_time = achievement.data.get_int("get_time")

                # Item type can be 0-6 inclusive and is the type of the unlock/item.
                # Item 0 is music unlocks. In this case, the id is the song ID according
                # to the game. Unclear what the param is supposed to be, but i've seen
                # seen 8 and 0. Might be what chart is available?
                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # We already sent song unlocks in the force unlock section above.
                    continue

                item = Node.void("item")
                root.add_child(item)
                item.add_child(Node.u8("type", itemtype))
                item.add_child(Node.u16("id", achievement.id))
                item.add_child(Node.u16("param", param))
                item.add_child(Node.bool("is_new", is_new))
                item.add_child(Node.u64("get_time", get_time))

            elif achievement.type == "chara":
                friendship = achievement.data.get_int("friendship")

                chara = Node.void("chara_param")
                root.add_child(chara)
                chara.add_child(Node.u16("chara_id", achievement.id))
                chara.add_child(Node.u16("friendship", friendship))

            elif achievement.type == "navi":
                # There should only be 12 of these.
                friendship = achievement.data.get_int("friendship")

                # This relies on the above Navi data section to ensure the navi_param
                # node is created.
                navi_param = Node.void("navi_param")
                navi_data.add_child(navi_param)
                navi_param.add_child(Node.u16("navi_id", achievement.id))
                navi_param.add_child(Node.s32("friendship", friendship))

            elif achievement.type == "area":
                # There should only be 16 of these.
                index = achievement.data.get_int("index")
                points = achievement.data.get_int("points")
                cleared = achievement.data.get_bool("cleared")
                diary = achievement.data.get_int("diary")

                area = Node.void("area")
                root.add_child(area)
                area.add_child(Node.u32("area_id", achievement.id))
                area.add_child(Node.u8("chapter_index", index))
                area.add_child(Node.u16("gauge_point", points))
                area.add_child(Node.bool("is_cleared", cleared))
                area.add_child(Node.u32("diary", diary))

            elif achievement.type[:7] == "course_":
                sheet = int(achievement.type[7:])

                course_data = Node.void("course_data")
                root.add_child(course_data)
                course_data.add_child(Node.s16("course_id", achievement.id))
                course_data.add_child(
                    Node.u8("clear_type", achievement.data.get_int("clear_type"))
                )
                course_data.add_child(
                    Node.u8("clear_rank", achievement.data.get_int("clear_rank"))
                )
                course_data.add_child(
                    Node.s32("total_score", achievement.data.get_int("score"))
                )
                course_data.add_child(
                    Node.s32("update_count", achievement.data.get_int("count"))
                )
                course_data.add_child(Node.u8("sheet_num", sheet))

            elif achievement.type == "fes":
                index = achievement.data.get_int("index")
                points = achievement.data.get_int("points")
                cleared = achievement.data.get_bool("cleared")

                fes = Node.void("fes")
                root.add_child(fes)
                fes.add_child(Node.u32("fes_id", achievement.id))
                fes.add_child(Node.u8("chapter_index", index))
                fes.add_child(Node.u16("gauge_point", points))
                fes.add_child(Node.bool("is_cleared", cleared))

        # Handle daily mission. Note that we should be presenting 3 random IDs
        # in the range of 1-228 inclusive, and presenting three new ones per day.
        achievements = self.data.local.user.get_time_based_achievements(
            self.game,
            self.version,
            userid,
            since=Time.beginning_of_today(),
            until=Time.end_of_today(),
        )
        achievements = sorted(achievements, key=lambda a: a.timestamp)
        daily_missions: Dict[int, ValidatedDict] = {}

        # Find the newest version of each daily mission completion,
        # since we've sorted by time above. If we haven't started for
        # today, the defaults will be set after this loop so we at least
        # give the game the right ID.
        for achievement in achievements:
            if achievement.type == "mission":
                daily_missions[achievement.id] = achievement.data

        while len(daily_missions) < 3:
            new_id = random.randint(1, 228)
            if new_id not in daily_missions:
                daily_missions[new_id] = ValidatedDict()

        for i, (daily_id, data) in enumerate(daily_missions.items()):
            if i >= 3:
                break

            points = data.get_int("points")
            complete = data.get_int("complete")

            mission = Node.void("mission")
            root.add_child(mission)
            mission.add_child(Node.u32("mission_id", daily_id))
            mission.add_child(Node.u32("gauge_point", points))
            mission.add_child(Node.u32("mission_comp", complete))

        # Player netvs section
        netvs = Node.void("netvs")
        root.add_child(netvs)
        netvs.add_child(Node.s16_array("record", [0] * 6))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.s8_array("ojama_condition", [0] * 74))
        netvs.add_child(Node.s8_array("set_ojama", [0] * 3))
        netvs.add_child(Node.s8_array("set_recommend", [0] * 3))
        netvs.add_child(Node.u32("netvs_play_cnt", 0))

        # Character customizations
        customize = Node.void("customize")
        root.add_child(customize)
        customize.add_child(Node.u16("effect_left", profile.get_int("effect_left")))
        customize.add_child(Node.u16("effect_center", profile.get_int("effect_center")))
        customize.add_child(Node.u16("effect_right", profile.get_int("effect_right")))
        customize.add_child(Node.u16("hukidashi", profile.get_int("hukidashi")))
        customize.add_child(Node.u16("comment_1", profile.get_int("comment_1")))
        customize.add_child(Node.u16("comment_2", profile.get_int("comment_2")))

        # Stamp stuff
        stamp = Node.void("stamp")
        root.add_child(stamp)
        stamp.add_child(Node.s16("stamp_id", profile.get_int("stamp_id")))
        stamp.add_child(Node.s16("cnt", profile.get_int("stamp_cnt")))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()

        account = request.child("account")
        if account is not None:
            newprofile.replace_int("tutorial", account.child_value("tutorial"))
            newprofile.replace_int("read_news", account.child_value("read_news"))
            newprofile.replace_int("area_id", account.child_value("area_id"))
            newprofile.replace_int("use_navi", account.child_value("use_navi"))
            newprofile.replace_int("ranking_node", account.child_value("ranking_node"))
            newprofile.replace_int(
                "chara_ranking_kind_id", account.child_value("chara_ranking_kind_id")
            )
            newprofile.replace_int(
                "navi_evolution_flg", account.child_value("navi_evolution_flg")
            )
            newprofile.replace_int(
                "ranking_news_last_no", account.child_value("ranking_news_last_no")
            )
            newprofile.replace_int("power_point", account.child_value("power_point"))
            newprofile.replace_int("player_point", account.child_value("player_point"))

            newprofile.replace_int_array("nice", 30, account.child_value("nice"))
            newprofile.replace_int_array(
                "favorite_chara", 20, account.child_value("favorite_chara")
            )
            newprofile.replace_int_array(
                "special_area", 8, account.child_value("special_area")
            )
            newprofile.replace_int_array(
                "chocolate_charalist", 5, account.child_value("chocolate_charalist")
            )
            newprofile.replace_int(
                "chocolate_sp_chara", account.child_value("chocolate_sp_chara")
            )
            newprofile.replace_int(
                "chocolate_pass_cnt", account.child_value("chocolate_pass_cnt")
            )
            newprofile.replace_int(
                "chocolate_hon_cnt", account.child_value("chocolate_hon_cnt")
            )
            newprofile.replace_int(
                "chocolate_giri_cnt", account.child_value("chocolate_giri_cnt")
            )
            newprofile.replace_int(
                "chocolate_kokyu_cnt", account.child_value("chocolate_kokyu_cnt")
            )
            newprofile.replace_int_array(
                "teacher_setting", 10, account.child_value("teacher_setting")
            )
            newprofile.replace_int_array(
                "power_point_list", 20, account.child_value("power_point_list")
            )

        info = request.child("info")
        if info is not None:
            newprofile.replace_int("ep", info.child_value("ep"))

        stamp = request.child("stamp")
        if stamp is not None:
            newprofile.replace_int("stamp_id", stamp.child_value("stamp_id"))
            newprofile.replace_int("stamp_cnt", stamp.child_value("cnt"))

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
            newprofile.replace_int("course_id", config.child_value("course_id"))
            newprofile.replace_int("course_folder", config.child_value("course_folder"))
            newprofile.replace_int(
                "ms_banner_disp", config.child_value("ms_banner_disp")
            )
            newprofile.replace_int("ms_down_info", config.child_value("ms_down_info"))
            newprofile.replace_int("ms_side_info", config.child_value("ms_side_info"))
            newprofile.replace_int("ms_raise_type", config.child_value("ms_raise_type"))
            newprofile.replace_int("ms_rnd_type", config.child_value("ms_rnd_type"))
            newprofile.replace_int("banner_sort", config.child_value("banner_sort"))

        option_dict = newprofile.get_dict("option")
        option = request.child("option")
        if option is not None:
            option_dict.replace_int("hispeed", option.child_value("hispeed"))
            option_dict.replace_int("popkun", option.child_value("popkun"))
            option_dict.replace_bool("hidden", option.child_value("hidden"))
            option_dict.replace_int("hidden_rate", option.child_value("hidden_rate"))
            option_dict.replace_bool("sudden", option.child_value("sudden"))
            option_dict.replace_int("sudden_rate", option.child_value("sudden_rate"))
            option_dict.replace_int("randmir", option.child_value("randmir"))
            option_dict.replace_int("gauge_type", option.child_value("gauge_type"))
            option_dict.replace_int("ojama_0", option.child_value("ojama_0"))
            option_dict.replace_int("ojama_1", option.child_value("ojama_1"))
            option_dict.replace_bool("forever_0", option.child_value("forever_0"))
            option_dict.replace_bool("forever_1", option.child_value("forever_1"))
            option_dict.replace_bool("full_setting", option.child_value("full_setting"))
            option_dict.replace_int("judge", option.child_value("judge"))
            option_dict.replace_int("guide_se", option.child_value("guide_se"))
        newprofile.replace_dict("option", option_dict)

        customize = request.child("customize")
        if customize is not None:
            newprofile.replace_int("effect_left", customize.child_value("effect_left"))
            newprofile.replace_int(
                "effect_center", customize.child_value("effect_center")
            )
            newprofile.replace_int(
                "effect_right", customize.child_value("effect_right")
            )
            newprofile.replace_int("hukidashi", customize.child_value("hukidashi"))
            newprofile.replace_int("comment_1", customize.child_value("comment_1"))
            newprofile.replace_int("comment_2", customize.child_value("comment_2"))

        navi_data = request.child("navi_data")
        if navi_data is not None:
            newprofile.replace_int_array(
                "navi_points", 5, navi_data.child_value("raisePoint")
            )

            # Extract navi achievements
            for node in navi_data.children:
                if node.name == "navi_param":
                    navi_id = node.child_value("navi_id")
                    friendship = node.child_value("friendship")

                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        navi_id,
                        "navi",
                        {
                            "friendship": friendship,
                        },
                    )

        # Extract achievements
        game_config = self.get_game_config()
        for node in request.children:
            if node.name == "item":
                itemid = node.child_value("id")
                itemtype = node.child_value("type")
                param = node.child_value("param")
                is_new = node.child_value("is_new")
                get_time = node.child_value("get_time")

                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # If we enabled force song unlocks, don't save songs to the profile.
                    continue

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    f"item_{itemtype}",
                    {
                        "param": param,
                        "is_new": is_new,
                        "get_time": get_time,
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

            elif node.name == "area":
                area_id = node.child_value("area_id")
                index = node.child_value("chapter_index")
                points = node.child_value("gauge_point")
                cleared = node.child_value("is_cleared")
                diary = node.child_value("diary")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    area_id,
                    "area",
                    {
                        "index": index,
                        "points": points,
                        "cleared": cleared,
                        "diary": diary,
                    },
                )

            elif node.name == "mission":
                # If you don't send the right values on login, then
                # the game sends 0 for mission_id three times. Skip
                # those values since they're bogus.
                mission_id = node.child_value("mission_id")
                if mission_id > 0:
                    points = node.child_value("gauge_point")
                    complete = node.child_value("mission_comp")

                    self.data.local.user.put_time_based_achievement(
                        self.game,
                        self.version,
                        userid,
                        mission_id,
                        "mission",
                        {
                            "points": points,
                            "complete": complete,
                        },
                    )

        # Unlock NAVI-kun and Kenshi Yonezu after one play
        for songid in [1592, 1608]:
            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                songid,
                "item_0",
                {
                    "param": 0xF,
                    "is_new": False,
                    "get_time": Time.now(),
                },
            )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
