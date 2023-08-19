# vim: set fileencoding=utf-8
import math
import random
from typing import Optional, Dict, List, Any, Set, Tuple
from typing_extensions import Final

from bemani.backend.base import Status
from bemani.backend.jubeat.common import (
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
)
from bemani.backend.jubeat.course import JubeatCourse
from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.saucerfulfill import JubeatSaucerFulfill
from bemani.common import Profile, ValidatedDict, VersionConstants, Time
from bemani.data import Data, Score, UserID
from bemani.protocol import Node


class JubeatProp(
    JubeatDemodataGetHitchartHandler,
    JubeatDemodataGetNewsHandler,
    JubeatGamendRegisterHandler,
    JubeatGametopGetMeetingHandler,
    JubeatLobbyCheckHandler,
    JubeatLoggerReportHandler,
    JubeatCourse,
    JubeatBase,
):
    name: str = "Jubeat Prop"
    version: int = VersionConstants.JUBEAT_PROP

    GAME_COURSE_REQUIREMENT_SCORE: Final[int] = 1
    GAME_COURSE_REQUIREMENT_FULL_COMBO: Final[int] = 2
    GAME_COURSE_REQUIREMENT_PERFECT_PERCENT: Final[int] = 3

    GAME_COURSE_RATING_FAILED: Final[int] = 1
    GAME_COURSE_RATING_BRONZE: Final[int] = 2
    GAME_COURSE_RATING_SILVER: Final[int] = 3
    GAME_COURSE_RATING_GOLD: Final[int] = 4

    JBOX_EMBLEM_NORMAL: Final[int] = 1
    JBOX_EMBLEM_PREMIUM: Final[int] = 2

    EVENTS: Dict[int, Dict[str, bool]] = {
        5: {
            "enabled": False,
        },
        6: {
            "enabled": False,
        },
        9: {
            "enabled": False,
        },
        14: {
            "enabled": False,
        },
        15: {
            "enabled": False,
        },
        16: {
            "enabled": False,
        },
        17: {
            "enabled": False,
        },
        18: {
            "enabled": False,
        },
        19: {
            "enabled": False,
        },
    }

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatSaucerFulfill(self.data, self.config, self.model)

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

    @classmethod
    def __class_to_rank(cls, cur_class: int, cur_subclass: int) -> int:
        """
        Given a class and subclass, return an integer rank for that class.

        Class mapping is as follows:
            1 - Amateur
            2 - Regular
            3 - Master
            4 - Legend

        Subclass ranges from 1 to 5, except on Legend where it is 1 only.
        """
        if cur_subclass > 5:
            cur_subclass = 5
        if cur_subclass < 1:
            cur_subclass = 1
        if cur_class > 4:
            cur_class = 4
        if cur_class < 1:
            cur_class = 1

        lut = {
            1: {
                5: 0,
                4: 1,
                3: 2,
                2: 3,
                1: 4,
            },
            2: {
                5: 5,
                4: 6,
                3: 7,
                2: 8,
                1: 9,
            },
            3: {
                5: 10,
                4: 11,
                3: 12,
                2: 13,
                1: 14,
            },
            # Legend only has one sub-class value (1), so to make range checks
            # easier, just map all 5 possible values to the same integer.
            4: {
                5: 15,
                4: 15,
                3: 15,
                2: 15,
                1: 15,
            },
        }
        return lut[cur_class][cur_subclass]

    @classmethod
    def __rank_to_class(cls, rank: int) -> Tuple[int, int]:
        """
        Given a rank, return a tuple representing class, subclass. This function
        is the inverse of __class_to_rank.
        """
        if rank < 0:
            rank = 0
        if rank > 15:
            rank = 15

        lut = {
            0: (1, 5),
            1: (1, 4),
            2: (1, 3),
            3: (1, 2),
            4: (1, 1),
            5: (2, 5),
            6: (2, 4),
            7: (2, 3),
            8: (2, 2),
            9: (2, 1),
            10: (3, 5),
            11: (3, 4),
            12: (3, 3),
            13: (3, 2),
            14: (3, 1),
            15: (4, 1),
        }
        return lut[rank]

    @classmethod
    def _increment_class(cls, cur_class: int, cur_subclass: int) -> Tuple[int, int]:
        """
        Given a class and subclass, return a tuple representing the next
        class/subclass if we were to be promoted.
        """
        return cls.__rank_to_class(cls.__class_to_rank(cur_class, cur_subclass) + 1)

    @classmethod
    def _decrement_class(cls, cur_class: int, cur_subclass: int) -> Tuple[int, int]:
        """
        Given a class and subclass, return a tuple representing the previous
        class/subclass if we were to be demoted.
        """
        return cls.__rank_to_class(cls.__class_to_rank(cur_class, cur_subclass) - 1)

    @classmethod
    def _get_league_buckets(
        cls, scores: List[Tuple[UserID, int]]
    ) -> Tuple[List[UserID], List[UserID], List[UserID]]:
        """
        Given a list of userid, score tuples, return a tuple containing three lists.
        The first list is the top 30% scorer IDs, the next list is the middle 40%
        scorer IDs, and the final list is the bottom 30% scorer IDs.
        """
        sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)

        # Top 30% get promoted
        promoted_amount = math.ceil(len(sorted_scores) * 0.3)
        promotions = [x[0] for x in sorted_scores[:promoted_amount]]
        rest = sorted_scores[promoted_amount:]

        # Bottom 30% get demoted (this is bottom 3/7 of the rest)
        demoted_amount = math.ceil(len(rest) * 0.42)
        demotions = [x[0] for x in rest[-demoted_amount:]]
        neutrals = [x[0] for x in rest[:-demoted_amount]]

        return (promotions, neutrals, demotions)

    @classmethod
    def _get_league_scores(
        cls, data: Data, current_id: int, profiles: List[Tuple[UserID, Profile]]
    ) -> Tuple[List[Tuple[UserID, int]], List[UserID]]:
        """
        Given the current League ID (calculated based on the date range) and a list of
        all user profiles for this game/version, return a uple containing two lists.
        The first list should contain tuples where the first integer is a user ID and
        the second integer is the user's total score for last week's course. The second
        list is a list of user IDs that did not participate last week but have played
        this game at some point.
        """
        last_id = current_id - 1

        scores = []
        absentees = []
        for [userid, _player] in profiles:
            # Look up scores for last week if they played
            league_score = data.local.user.get_achievement(
                cls.game,
                cls.version,
                userid,
                last_id,
                "league",
            )

            # If they played, grab their total score so we can figure out if we should
            # promote, demote or leave alone
            if league_score is not None:
                scores.append(
                    (
                        userid,
                        league_score["score"][0]
                        + league_score["score"][1]
                        + league_score["score"][2],
                    )
                )
            else:
                absentees.append(userid)

        return scores, absentees

    @classmethod
    def _get_league_absentees(
        cls, data: Data, current_id: int, absentees: List[UserID]
    ) -> List[UserID]:
        """
        Given a list of user IDs that didn't play for some number of weeks, return
        a subset of those IDs that have been absent enough weeks to get a demotion.
        Demotions happen for every two weeks without play.
        """
        delinquents = []
        for userid in absentees:
            # Figure out the last time they played, if its an even boundary
            # and at least 2 weeks back, demote them (one demotion for every
            # two weeks not played).
            last_league_id = 0
            for achievement in data.local.user.get_achievements(
                cls.game,
                cls.version,
                userid,
            ):
                if achievement.type == "league":
                    last_league_id = max(achievement.id, last_league_id)

            if last_league_id != 0:
                # If they played mid-week two IDs ago, that's not quite
                # two weeks back, so adjust by one.
                weeks_different = (current_id - last_league_id) - 1

                if weeks_different >= 2 and weeks_different % 2 == 0:
                    # It's been at least two weeks (or four, or six), which means
                    # there have been two weeks since the last time we did this,
                    # demote this person.
                    delinquents.append(userid)

        return delinquents

    @classmethod
    def _modify_profile(cls, data: Data, userid: UserID, direction: str) -> None:
        """
        Given a user ID and a direction (promote or demote), load the user's profile,
        make the necessary promotion/demotion, and set the profile to notify the user
        on next play that they have lost/gained rank. If the user still hasn't checked
        their rank since last time we changed it, make sure they know about multiple
        promotions/demotions.
        """
        profile = data.local.user.get_profile(cls.game, cls.version, userid)
        cur_class = profile.get_int("league_class", 1)
        cur_subclass = profile.get_int("league_subclass", 5)

        if direction == "promote":
            new_class, new_subclass = cls._increment_class(cur_class, cur_subclass)
        elif direction == "demote":
            new_class, new_subclass = cls._decrement_class(cur_class, cur_subclass)
        else:
            raise Exception(f"Logic error, unknown direction {direction}!")

        if new_class != cur_class or new_subclass != cur_subclass:
            # If they've checked last time, set up the new old class.
            if profile.get_bool("league_is_checked"):
                last = profile.get_dict("last")
                last.replace_int("league_class", cur_class)
                last.replace_int("league_subclass", cur_subclass)
                profile.replace_dict("last", last)
            # We actually changed a level, let the user know!
            profile.replace_int("league_class", new_class)
            profile.replace_int("league_subclass", new_subclass)
            profile.replace_bool("league_is_checked", False)
            data.local.user.put_profile(cls.game, cls.version, userid, profile)

    @classmethod
    def run_scheduled_work(
        cls, data: Data, config: Dict[str, Any]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Once a week, insert a new league course. Every day, insert new FC challenge courses.
        """
        events = []
        if data.local.network.should_schedule(
            cls.game, cls.version, "league_course", "weekly"
        ):
            # Generate a new league course list, save it to the DB.
            start_time, end_time = data.local.network.get_schedule_duration("weekly")
            all_songs = set(
                song.id
                for song in data.local.music.get_all_songs(cls.game, cls.version)
            )
            if len(all_songs) >= 3:
                league_songs = random.sample(all_songs, 3)
                data.local.game.put_time_sensitive_settings(
                    cls.game,
                    cls.version,
                    "league",
                    {
                        "start_time": start_time,
                        "end_time": end_time,
                        "music": league_songs,
                    },
                )
                events.append(
                    (
                        "jubeat_league_course",
                        {
                            "version": cls.version,
                            "songs": league_songs,
                        },
                    )
                )

                # League ID for the current league we just added.
                leagueid = int(start_time / 604800)

                # Evaluate player scores on previous courses and find players
                # that didn't play last week.
                all_profiles = data.local.user.get_all_profiles(cls.game, cls.version)
                scores, absentees = cls._get_league_scores(data, leagueid, all_profiles)

                # Get user IDs to promote, demote and ignore based on scores.
                promote, ignore, demote = cls._get_league_buckets(scores)
                demote.extend(cls._get_league_absentees(data, leagueid, absentees))

                # Actually modify the profiles so the game knows to tell the user.
                for userid in promote:
                    cls._modify_profile(data, userid, "promote")
                for userid in demote:
                    cls._modify_profile(data, userid, "demote")

                # Mark that we did some actual work here.
                data.local.network.mark_scheduled(
                    cls.game, cls.version, "league_course", "weekly"
                )

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

    def __get_global_info(self) -> Node:
        info = Node.void("info")

        # Event info. Valid event IDs are 5, 6, 9, 14, 15, 16, 17, 18, 19
        event_info = Node.void("event_info")
        info.add_child(event_info)
        for event in self.EVENTS:
            evt = Node.void("event")
            event_info.add_child(evt)
            evt.set_attribute("type", str(event))
            evt.add_child(Node.u8("state", 1 if self.EVENTS[event]["enabled"] else 0))

        # Each of the following three sections should have zero or more child nodes (no
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

        # Only now music?
        only_now_music = Node.void("only_now_music")
        info.add_child(only_now_music)

        # Full combo challenge?
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "fc_challenge"
        )
        if entry is None:
            entry = ValidatedDict()

        fc_challenge = Node.void("fc_challenge")
        info.add_child(fc_challenge)
        today = Node.void("today")
        fc_challenge.add_child(today)
        today.add_child(Node.s32("music_id", entry.get_int("today", -1)))

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
                ],
            )
        )

        cabinet_survey = Node.void("cabinet_survey")
        info.add_child(cabinet_survey)
        cabinet_survey.add_child(Node.s32("id", -1))
        cabinet_survey.add_child(Node.s32("status", 0))

        kaitou_bisco = Node.void("kaitou_bisco")
        info.add_child(kaitou_bisco)
        kaitou_bisco.add_child(Node.s32("remaining_days", 0))

        league = Node.void("league")
        info.add_child(league)
        league.add_child(Node.u8("status", 1))

        bistro = Node.void("bistro")
        info.add_child(bistro)
        bistro.add_child(Node.u16("bistro_id", 0))

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
        courses = self.get_all_courses()
        courses.extend(
            [
                {
                    "id": 31,
                    "name": "Enjoy! The 5th KAC ~ tracks of prop ~",
                    "level": 5,
                    "music": [
                        (60000065, 1),
                        (60000008, 1),
                        (60000001, 1),
                        (60001009, 1),
                        (60000010, 1),
                    ],
                    "requirements": {
                        self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                        self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 4],
                    },
                },
                {
                    "id": 32,
                    "name": "Challenge! The 5th KAC ~ tracks of prop ~",
                    "level": 7,
                    "music": [
                        (60000065, 2),
                        (60000008, 2),
                        (60000001, 2),
                        (60001009, 2),
                        (60000010, 2),
                    ],
                    "requirements": {
                        self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                    },
                },
                {
                    "id": 33,
                    "name": "The 5th KAC ~ tracks of prop ~",
                    "level": 10,
                    "music": [
                        (60000065, 2),
                        (60000008, 2),
                        (60000001, 2),
                        (60001009, 2),
                        (60000010, 2),
                    ],
                    "requirements": {
                        self.COURSE_REQUIREMENT_SCORE: [920000, 950000, 980000],
                    },
                },
            ]
        )

        for course in courses:
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
        data.add_child(
            Node.s32(
                "last_course_id", profile.get_dict("last").get_int("last_course_id", -1)
            )
        )

        return gametop

    def handle_gametop_get_league_request(self, request: Node) -> Node:
        data = request.child("data")
        player = data.child("player")
        extid = player.child_value("jid")

        # Look up profile so we can load the last course played
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        profile = self.get_profile(userid)
        if profile is None:
            profile = Profile(self.game, self.version, "", extid)

        gametop = Node.void("gametop")
        data = Node.void("data")
        gametop.add_child(data)

        league_list = Node.void("league_list")
        data.add_child(league_list)

        # Look up the current league charts in the DB
        entry = self.data.local.game.get_time_sensitive_settings(
            self.game, self.version, "league"
        )
        if entry is not None:
            # Just get the week number, use that as the ID
            leagueid = int(entry["start_time"] / 604800)

            league = Node.void("league")
            league_list.add_child(league)
            league.set_attribute("index", "0")

            league.add_child(Node.s32("id", leagueid))
            league.add_child(Node.u64("stime", entry["start_time"] * 1000))
            league.add_child(Node.u64("etime", entry["end_time"] * 1000))

            music_list = Node.void("music_list")
            league.add_child(music_list)

            # We need to know the player class so we can determine what chart to present.
            current_class = profile.get_int("league_class", 1)

            song_index = 0
            for song in entry["music"]:
                music = Node.void("music")
                music_list.add_child(music)
                music.set_attribute("index", str(song_index))
                song_index = song_index + 1

                music.add_child(Node.s32("music_id", song))
                music.add_child(Node.u8("seq", 1 if current_class == 1 else 2))

            player_list = Node.void("player_list")
            league.add_child(player_list)

            player = Node.void("player")
            player_list.add_child(player)
            player.add_child(Node.s32("jid", extid))
            result = Node.void("result")
            player.add_child(result)

            league_score = self.data.local.user.get_achievement(
                self.game, self.version, userid, leagueid, "league"
            )
            if league_score is None:
                league_score = ValidatedDict()

            result.add_child(
                Node.s32_array("score", league_score.get_int_array("score", 3, [0] * 3))
            )
            result.add_child(
                Node.s8_array("clear", league_score.get_int_array("clear", 3, [0] * 3))
            )

        data.add_child(
            Node.s32("last_class", profile.get_dict("last").get_int("league_class", 1))
        )
        data.add_child(
            Node.s32(
                "last_subclass", profile.get_dict("last").get_int("league_subclass", 5)
            )
        )
        data.add_child(Node.bool("is_checked", profile.get_bool("league_is_checked")))

        return gametop

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("gametop")
        data = Node.void("data")
        root.add_child(data)

        # Figure out if we're force-unlocking songs.
        game_config = self.get_game_config()
        force_unlock = game_config.get_bool("force_song_unlock")

        # Allow figuring out owned emblems.
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
        info.add_child(Node.s32("pf_cnt", profile.get_int("pf_cnt")))
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
        last.add_child(Node.s8("expert_option", lastdict.get_int("expert_option")))
        last.add_child(Node.s8("category", lastdict.get_int("category")))
        last.add_child(Node.s8("sort", lastdict.get_int("sort")))
        last.add_child(Node.s32("music_id", lastdict.get_int("music_id")))
        last.add_child(Node.s8("seq_id", lastdict.get_int("seq_id")))

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
                "music_list", profile.get_int_array("music_list", 32, [-1] * 32)
            )
        )
        item.add_child(
            Node.s32_array(
                "secret_list",
                ([-1] * 32)
                if force_unlock
                else self.create_owned_items(owned_songs, 32),
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
                ([-1] * 32)
                if force_unlock
                else self.create_owned_items(owned_secrets, 32),
            )
        )
        new.add_child(Node.s16("theme_list", profile.get_int("theme_list_new", -1)))
        new.add_child(
            Node.s32_array(
                "marker_list", profile.get_int_array("marker_list_new", 2, [-1] * 2)
            )
        )

        # Sane defaults for unknown/who cares nodes
        history = Node.void("history")
        player.add_child(history)
        history.set_attribute("count", "0")
        lab_edit_seq = Node.void("lab_edit_seq")
        player.add_child(lab_edit_seq)
        lab_edit_seq.set_attribute("count", "0")
        cabinet_survey = Node.void("cabinet_survey")
        player.add_child(cabinet_survey)
        cabinet_survey.add_child(Node.u32("read_flag", 0))
        kaitou_bisco = Node.void("kaitou_bisco")
        player.add_child(kaitou_bisco)
        kaitou_bisco.add_child(
            Node.u32("read_flag", profile.get_int("kaitou_bisco_read_flag"))
        )
        navi = Node.void("navi")
        player.add_child(navi)
        navi.add_child(Node.u32("flag", profile.get_int("navi_flag")))

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

            rcareerdict = rprofile.get_dict("career")
            career = Node.void("career")
            rival.add_child(career)
            career.add_child(Node.s16("level", rcareerdict.get_int("level", 1)))

            league = Node.void("league")
            rival.add_child(league)
            league.add_child(
                Node.bool(
                    "is_first_play", rprofile.get_bool("league_is_first_play", True)
                )
            )
            league.add_child(Node.s32("class", rprofile.get_int("league_class", 1)))
            league.add_child(
                Node.s32("subclass", rprofile.get_int("league_subclass", 5))
            )

            # Lazy way of keeping track of rivals, since we can only have 3
            # or the game with throw up.
            rivalcount += 1
            if rivalcount >= 3:
                break

        rivallist.set_attribute("count", str(rivalcount))

        # Nothing in life is free, WTF?
        free_first_play = Node.void("free_first_play")
        player.add_child(free_first_play)
        free_first_play.add_child(Node.bool("is_available", False))
        free_first_play.add_child(Node.s32("point", 0))
        free_first_play.add_child(Node.s32("point_used", 0))
        come_come_jbox = Node.void("come_come_jbox")
        free_first_play.add_child(come_come_jbox)
        come_come_jbox.add_child(Node.bool("is_valid", False))
        come_come_jbox.add_child(Node.s64("end_time_if_paired", 0))

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

        # Career stuff
        career = Node.void("career")
        careerdict = profile.get_dict("career")
        player.add_child(career)
        career.add_child(Node.s16("level", careerdict.get_int("level", 1)))
        career.add_child(Node.s32("point", careerdict.get_int("point")))
        career.add_child(
            Node.s32_array("param", careerdict.get_int_array("param", 10, [-1] * 10))
        )
        career.add_child(Node.bool("is_unlocked", careerdict.get_bool("is_unlocked")))

        # League stuff
        league = Node.void("league")
        player.add_child(league)
        league.add_child(
            Node.bool("is_first_play", profile.get_bool("league_is_first_play", True))
        )
        league.add_child(Node.s32("class", profile.get_int("league_class", 1)))
        league.add_child(Node.s32("subclass", profile.get_int("league_subclass", 5)))

        # New Music stuff
        new_music = Node.void("new_music")
        player.add_child(new_music)

        # Emblem list stuff?
        eapass_privilege = Node.void("eapass_privilege")
        player.add_child(eapass_privilege)
        emblem_node = Node.void("emblem_list")
        eapass_privilege.add_child(emblem_node)

        # Bonus music stuff?
        bonus_music = Node.void("bonus_music")
        player.add_child(bonus_music)
        bonus_music.add_child(Node.void("music"))
        bonus_music.add_child(Node.s32("event_id", -1))
        bonus_music.add_child(Node.string("till_time", ""))

        # Bistro stuff is back?
        bistro = Node.void("bistro")
        player.add_child(bistro)
        chef = Node.void("chef")
        bistro.add_child(chef)
        chef.add_child(Node.s32("id", 1))
        bistro.add_child(Node.s32("carry_over", 0))
        route_list = Node.void("route_list")
        bistro.add_child(route_list)
        route_list.add_child(Node.u8("route_count", 0))
        # If we have routes, they look like this:
        #     <route>
        #         <no __type="u8">#</no>
        #         <content kind="?">
        #             <value __type="s32">??</value>
        #         </content>
        #         <gourmates>
        #             <id __type="s32">??</id>
        #         </gourmates>
        bistro.add_child(Node.bool("extension", False))

        # Gift list, maybe from other players?
        gift_list = Node.void("gift_list")
        player.add_child(gift_list)
        # If we had gifts, they look like this:
        #     <gift reason="??" kind="??">
        #         <id __type="s32">??</id>
        #     </gift>

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
            newprofile.replace_int("pf_cnt", info.child_value("pf_cnt"))
            newprofile.replace_int("clear_cnt", info.child_value("clear_cnt"))
            newprofile.replace_int("match_cnt", info.child_value("match_cnt"))
            newprofile.replace_int("beat_cnt", info.child_value("beat_cnt"))
            newprofile.replace_int(
                "total_best_score", info.child_value("total_best_score")
            )
            newprofile.replace_int("mynews_cnt", info.child_value("mynews_cnt"))

            newprofile.replace_int(
                "bonus_tune_points", info.child_value("bonus_tune_points")
            )
            newprofile.replace_bool(
                "is_bonus_tune_played", info.child_value("is_bonus_tune_played")
            )

        # Grab last settings (finally mostly in its own node!)
        lastnode = player.child("last")
        if lastnode is not None:
            last.replace_int("expert_option", lastnode.child_value("expert_option"))
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
                "title_list", 160, item.child_value("title_list")
            )
            newprofile.replace_int("theme_list", item.child_value("theme_list"))
            newprofile.replace_int_array(
                "marker_list", 2, item.child_value("marker_list")
            )
            newprofile.replace_int_array(
                "parts_list", 160, item.child_value("parts_list")
            )
            newprofile.replace_int_array(
                "music_list", 32, item.child_value("music_list")
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
                newprofile.replace_int(
                    "theme_list_new", newitem.child_value("theme_list")
                )
                newprofile.replace_int_array(
                    "marker_list_new", 2, newitem.child_value("marker_list")
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

        # Career progression
        career = player.child("career")
        careerdict = newprofile.get_dict("career")
        if career is not None:
            careerdict.replace_int("level", career.child_value("level"))
            careerdict.replace_int("point", career.child_value("point"))
            careerdict.replace_int_array("param", 10, career.child_value("param"))
            careerdict.replace_bool("is_unlocked", career.child_value("is_unlocked"))
        newprofile.replace_dict("career", careerdict)

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

        # A whole bunch of miscelaneous shit
        newprofile.replace_int("navi_flag", player.child_value("navi/flag"))
        newprofile.replace_int(
            "kaitou_bisco_read_flag", player.child_value("kaitou_bisco/read_flag")
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
        if result is not None:
            for tune in result.children:
                if tune.name != "tune":
                    continue
                result = tune.child("player")

                entry = int(tune.attribute("id"))
                songid = tune.child_value("music")
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

        # If this was a course save, grab and save that info too
        course = player.child("course")
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

        # If this was a league save, grab and save that info too
        league = player.child("league")
        if league is not None:
            leagueid = league.child_value("league_id")
            newprofile.replace_bool(
                "league_is_checked", league.child_value("is_checked")
            )
            newprofile.replace_bool(
                "league_is_first_play", league.child_value("is_first_play")
            )

            # Extract scores
            score = [0] * 3
            clear = [0] * 3
            for music in league.children:
                if music.name != "music":
                    continue
                index = int(music.attribute("index"))
                scorenode = music.child("score")
                clear[index] = int(scorenode.attribute("clear"))
                score[index] = scorenode.value

            # Update score if it is higher
            oldleague = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                leagueid,
                "league",
            )
            if oldleague is None:
                oldleague = ValidatedDict()
            oldscore = oldleague.get_int_array("score", 3)
            if sum(oldscore) < sum(score):
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    leagueid,
                    "league",
                    {"score": score, "clear": clear},
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
