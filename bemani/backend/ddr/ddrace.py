# vim: set fileencoding=utf-8
import base64
from typing import Any, Dict, List, Optional, Tuple
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.ddr.base import DDRBase
from bemani.backend.ddr.ddr2014 import DDR2014
from bemani.common import (
    Profile,
    ValidatedDict,
    VersionConstants,
    CardCipher,
    Time,
    ID,
    intish,
)
from bemani.data import Data, Achievement, Machine, Score, UserID
from bemani.protocol import Node


class DDRAce(
    DDRBase,
    EventLogHandler,
):
    name: str = "DanceDanceRevolution A"
    version: int = VersionConstants.DDR_ACE

    GAME_STYLE_SINGLE: Final[int] = 0
    GAME_STYLE_DOUBLE: Final[int] = 1
    GAME_STYLE_VERSUS: Final[int] = 2

    GAME_RIVAL_TYPE_RIVAL3: Final[int] = 32
    GAME_RIVAL_TYPE_RIVAL2: Final[int] = 16
    GAME_RIVAL_TYPE_RIVAL1: Final[int] = 8
    GAME_RIVAL_TYPE_WORLD: Final[int] = 4
    GAME_RIVAL_TYPE_AREA: Final[int] = 2
    GAME_RIVAL_TYPE_MACHINE: Final[int] = 1

    GAME_CHART_SINGLE_BEGINNER: Final[int] = 0
    GAME_CHART_SINGLE_BASIC: Final[int] = 1
    GAME_CHART_SINGLE_DIFFICULT: Final[int] = 2
    GAME_CHART_SINGLE_EXPERT: Final[int] = 3
    GAME_CHART_SINGLE_CHALLENGE: Final[int] = 4
    GAME_CHART_DOUBLE_BASIC: Final[int] = 5
    GAME_CHART_DOUBLE_DIFFICULT: Final[int] = 6
    GAME_CHART_DOUBLE_EXPERT: Final[int] = 7
    GAME_CHART_DOUBLE_CHALLENGE: Final[int] = 8

    GAME_HALO_NONE: Final[int] = 6
    GAME_HALO_GOOD_COMBO: Final[int] = 7
    GAME_HALO_GREAT_COMBO: Final[int] = 8
    GAME_HALO_PERFECT_COMBO: Final[int] = 9
    GAME_HALO_MARVELOUS_COMBO: Final[int] = 10

    GAME_RANK_E: Final[int] = 15
    GAME_RANK_D: Final[int] = 14
    GAME_RANK_D_PLUS: Final[int] = 13
    GAME_RANK_C_MINUS: Final[int] = 12
    GAME_RANK_C: Final[int] = 11
    GAME_RANK_C_PLUS: Final[int] = 10
    GAME_RANK_B_MINUS: Final[int] = 9
    GAME_RANK_B: Final[int] = 8
    GAME_RANK_B_PLUS: Final[int] = 7
    GAME_RANK_A_MINUS: Final[int] = 6
    GAME_RANK_A: Final[int] = 5
    GAME_RANK_A_PLUS: Final[int] = 4
    GAME_RANK_AA_MINUS: Final[int] = 3
    GAME_RANK_AA: Final[int] = 2
    GAME_RANK_AA_PLUS: Final[int] = 1
    GAME_RANK_AAA: Final[int] = 0

    GAME_MAX_SONGS: Final[int] = 1024

    GAME_COMMON_AREA_OFFSET: Final[int] = 1
    GAME_COMMON_WEIGHT_DISPLAY_OFFSET: Final[int] = 3
    GAME_COMMON_CHARACTER_OFFSET: Final[int] = 4
    GAME_COMMON_EXTRA_CHARGE_OFFSET: Final[int] = 5
    GAME_COMMON_TOTAL_PLAYS_OFFSET: Final[int] = 9
    GAME_COMMON_SINGLE_PLAYS_OFFSET: Final[int] = 11
    GAME_COMMON_DOUBLE_PLAYS_OFFSET: Final[int] = 12
    GAME_COMMON_WEIGHT_OFFSET: Final[int] = 17
    GAME_COMMON_NAME_OFFSET: Final[int] = 25
    GAME_COMMON_SEQ_OFFSET: Final[int] = 26

    GAME_OPTION_SPEED_OFFSET: Final[int] = 1
    GAME_OPTION_BOOST_OFFSET: Final[int] = 2
    GAME_OPTION_APPEARANCE_OFFSET: Final[int] = 3
    GAME_OPTION_TURN_OFFSET: Final[int] = 4
    GAME_OPTION_STEP_ZONE_OFFSET: Final[int] = 5
    GAME_OPTION_SCROLL_OFFSET: Final[int] = 6
    GAME_OPTION_ARROW_COLOR_OFFSET: Final[int] = 7
    GAME_OPTION_CUT_OFFSET: Final[int] = 8
    GAME_OPTION_FREEZE_OFFSET: Final[int] = 9
    GAME_OPTION_JUMPS_OFFSET: Final[int] = 10
    GAME_OPTION_ARROW_SKIN_OFFSET: Final[int] = 11
    GAME_OPTION_FILTER_OFFSET: Final[int] = 12
    GAME_OPTION_GUIDELINE_OFFSET: Final[int] = 13
    GAME_OPTION_GAUGE_OFFSET: Final[int] = 14
    GAME_OPTION_COMBO_POSITION_OFFSET: Final[int] = 15
    GAME_OPTION_FAST_SLOW_OFFSET: Final[int] = 16

    GAME_LAST_CALORIES_OFFSET: Final[int] = 10

    GAME_RIVAL_SLOT_1_ACTIVE_OFFSET: Final[int] = 1
    GAME_RIVAL_SLOT_2_ACTIVE_OFFSET: Final[int] = 2
    GAME_RIVAL_SLOT_3_ACTIVE_OFFSET: Final[int] = 3
    GAME_RIVAL_SLOT_1_DDRCODE_OFFSET: Final[int] = 9
    GAME_RIVAL_SLOT_2_DDRCODE_OFFSET: Final[int] = 10
    GAME_RIVAL_SLOT_3_DDRCODE_OFFSET: Final[int] = 11

    def previous_version(self) -> Optional[DDRBase]:
        return DDR2014(self.data, self.config, self.model)

    @classmethod
    def run_scheduled_work(cls, data: Data, config: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        # DDR Ace has a weird bug where it sends a profile save for a blank
        # profile before reading it back when creating a new profile. If there
        # is no profile on read-back, it errors out, and it also uses the name
        # and area ID as the takeover/succession data if the user had previous
        # data on an old game. However, if for some reason the user cancels out
        # of the name entry, loses power or disconnects from the network at the
        # right time, then the profile exists in a broken state forever until they
        # edit it on the front-end. As a work-around to this, we remember the last
        # time each profile was written to, and we look up profiles that are older
        # than a few minutes (the maximum possible time for DDR Ace to write back
        # a new profile after creating a blank one) and have blank names and delete
        # them in order to keep the profiles on the network in sane order. This
        # should normally never delete any profiles.
        profiles = data.local.user.get_all_profiles(cls.game, cls.version)
        several_minutes_ago = Time.now() - (Time.SECONDS_IN_MINUTE * 5)
        events = []

        for userid, profile in profiles:
            if profile.get_str("name") == "" and profile.get_int("write_time") < several_minutes_ago:
                data.local.user.delete_profile(cls.game, cls.version, userid)
                events.append(
                    (
                        "ddr_profile_purge",
                        {
                            "userid": userid,
                        },
                    )
                )

        return events

    @property
    def supports_paseli(self) -> bool:
        if self.model.dest != "J":
            # DDR Ace in USA mode doesn't support PASELI properly.
            # When in Asia mode it shows PASELI but won't let you select it.
            return False
        else:
            # All other modes should work with PASELI.
            return True

    def game_to_db_rank(self, game_rank: int) -> int:
        return {
            self.GAME_RANK_AAA: self.RANK_AAA,
            self.GAME_RANK_AA_PLUS: self.RANK_AA_PLUS,
            self.GAME_RANK_AA: self.RANK_AA,
            self.GAME_RANK_AA_MINUS: self.RANK_AA_MINUS,
            self.GAME_RANK_A_PLUS: self.RANK_A_PLUS,
            self.GAME_RANK_A: self.RANK_A,
            self.GAME_RANK_A_MINUS: self.RANK_A_MINUS,
            self.GAME_RANK_B_PLUS: self.RANK_B_PLUS,
            self.GAME_RANK_B: self.RANK_B,
            self.GAME_RANK_B_MINUS: self.RANK_B_MINUS,
            self.GAME_RANK_C_PLUS: self.RANK_C_PLUS,
            self.GAME_RANK_C: self.RANK_C,
            self.GAME_RANK_C_MINUS: self.RANK_C_MINUS,
            self.GAME_RANK_D_PLUS: self.RANK_D_PLUS,
            self.GAME_RANK_D: self.RANK_D,
            self.GAME_RANK_E: self.RANK_E,
        }[game_rank]

    def db_to_game_rank(self, db_rank: int) -> int:
        return {
            self.RANK_AAA: self.GAME_RANK_AAA,
            self.RANK_AA_PLUS: self.GAME_RANK_AA_PLUS,
            self.RANK_AA: self.GAME_RANK_AA,
            self.RANK_AA_MINUS: self.GAME_RANK_AA_MINUS,
            self.RANK_A_PLUS: self.GAME_RANK_A_PLUS,
            self.RANK_A: self.GAME_RANK_A,
            self.RANK_A_MINUS: self.GAME_RANK_A_MINUS,
            self.RANK_B_PLUS: self.GAME_RANK_B_PLUS,
            self.RANK_B: self.GAME_RANK_B,
            self.RANK_B_MINUS: self.GAME_RANK_B_MINUS,
            self.RANK_C_PLUS: self.GAME_RANK_C_PLUS,
            self.RANK_C: self.GAME_RANK_C,
            self.RANK_C_MINUS: self.GAME_RANK_C_MINUS,
            self.RANK_D_PLUS: self.GAME_RANK_D_PLUS,
            self.RANK_D: self.GAME_RANK_D,
            self.RANK_E: self.GAME_RANK_E,
        }[db_rank]

    def game_to_db_chart(self, game_chart: int) -> int:
        return {
            self.GAME_CHART_SINGLE_BEGINNER: self.CHART_SINGLE_BEGINNER,
            self.GAME_CHART_SINGLE_BASIC: self.CHART_SINGLE_BASIC,
            self.GAME_CHART_SINGLE_DIFFICULT: self.CHART_SINGLE_DIFFICULT,
            self.GAME_CHART_SINGLE_EXPERT: self.CHART_SINGLE_EXPERT,
            self.GAME_CHART_SINGLE_CHALLENGE: self.CHART_SINGLE_CHALLENGE,
            self.GAME_CHART_DOUBLE_BASIC: self.CHART_DOUBLE_BASIC,
            self.GAME_CHART_DOUBLE_DIFFICULT: self.CHART_DOUBLE_DIFFICULT,
            self.GAME_CHART_DOUBLE_EXPERT: self.CHART_DOUBLE_EXPERT,
            self.GAME_CHART_DOUBLE_CHALLENGE: self.CHART_DOUBLE_CHALLENGE,
        }[game_chart]

    def db_to_game_chart(self, db_chart: int) -> int:
        return {
            self.CHART_SINGLE_BEGINNER: self.GAME_CHART_SINGLE_BEGINNER,
            self.CHART_SINGLE_BASIC: self.GAME_CHART_SINGLE_BASIC,
            self.CHART_SINGLE_DIFFICULT: self.GAME_CHART_SINGLE_DIFFICULT,
            self.CHART_SINGLE_EXPERT: self.GAME_CHART_SINGLE_EXPERT,
            self.CHART_SINGLE_CHALLENGE: self.GAME_CHART_SINGLE_CHALLENGE,
            self.CHART_DOUBLE_BASIC: self.GAME_CHART_DOUBLE_BASIC,
            self.CHART_DOUBLE_DIFFICULT: self.GAME_CHART_DOUBLE_DIFFICULT,
            self.CHART_DOUBLE_EXPERT: self.GAME_CHART_DOUBLE_EXPERT,
            self.CHART_DOUBLE_CHALLENGE: self.GAME_CHART_DOUBLE_CHALLENGE,
        }[db_chart]

    def game_to_db_halo(self, game_halo: int) -> int:
        if game_halo == self.GAME_HALO_MARVELOUS_COMBO:
            return self.HALO_MARVELOUS_FULL_COMBO
        elif game_halo == self.GAME_HALO_PERFECT_COMBO:
            return self.HALO_PERFECT_FULL_COMBO
        elif game_halo == self.GAME_HALO_GREAT_COMBO:
            return self.HALO_GREAT_FULL_COMBO
        elif game_halo == self.GAME_HALO_GOOD_COMBO:
            return self.HALO_GOOD_FULL_COMBO
        else:
            return self.HALO_NONE

    def db_to_game_halo(self, db_halo: int) -> int:
        if db_halo == self.HALO_MARVELOUS_FULL_COMBO:
            return self.GAME_HALO_MARVELOUS_COMBO
        elif db_halo == self.HALO_PERFECT_FULL_COMBO:
            return self.GAME_HALO_PERFECT_COMBO
        elif db_halo == self.HALO_GREAT_FULL_COMBO:
            return self.GAME_HALO_GREAT_COMBO
        elif db_halo == self.HALO_GOOD_FULL_COMBO:
            return self.GAME_HALO_GOOD_COMBO
        else:
            return self.GAME_HALO_NONE

    def handle_tax_get_phase_request(self, request: Node) -> Node:
        tax = Node.void("tax")
        tax.add_child(Node.s32("phase", 0))
        return tax

    def __handle_userload(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        has_profile: bool = False
        achievements: List[Achievement] = []
        scores: List[Score] = []

        if userid is not None:
            has_profile = self.has_profile(userid)
            achievements = self.data.local.user.get_achievements(self.game, self.version, userid)
            scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)

        # Place scores into an arrangement for easier distribution to Ace.
        scores_by_mcode: Dict[int, List[Optional[Score]]] = {}
        for score in scores:
            if score.id not in scores_by_mcode:
                scores_by_mcode[score.id] = [None] * 9

            scores_by_mcode[score.id][self.db_to_game_chart(score.chart)] = score

        # First, set new flag
        response.add_child(Node.bool("is_new", not has_profile))

        # Now, return the scores to Ace
        for mcode in scores_by_mcode:
            music = Node.void("music")
            response.add_child(music)
            music.add_child(Node.u32("mcode", mcode))

            scores_that_matter = scores_by_mcode[mcode]
            while scores_that_matter[-1] is None:
                scores_that_matter = scores_that_matter[:-1]

            for score in scores_that_matter:
                note = Node.void("note")
                music.add_child(note)

                if score is None:
                    note.add_child(Node.u16("count", 0))
                    note.add_child(Node.u8("rank", 0))
                    note.add_child(Node.u8("clearkind", 0))
                    note.add_child(Node.s32("score", 0))
                    note.add_child(Node.s32("ghostid", 0))
                else:
                    note.add_child(Node.u16("count", score.plays))
                    note.add_child(Node.u8("rank", self.db_to_game_rank(score.data.get_int("rank"))))
                    note.add_child(
                        Node.u8(
                            "clearkind",
                            self.db_to_game_halo(score.data.get_int("halo")),
                        )
                    )
                    note.add_child(Node.s32("score", score.points))
                    note.add_child(Node.s32("ghostid", score.key))

        # Active event settings
        activeevents = [
            1,
            3,
            5,
            9,
            10,
            11,
            12,
            13,
            15,
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            36,
            37,
            38,
            39,
            40,
            41,
            42,
        ]

        # Event reward settings
        rewards = {
            "30": {
                999: 5,
            }
        }

        # Now handle event progress and activation.
        events = {ach.id: ach.data for ach in achievements if ach.type == "9999"}
        progress = [ach for ach in achievements if ach.type != "9999"]

        # Make sure we always send a babylon's adventure save event or the game won't send progress
        babylon_included = False
        for evtprogress in progress:
            if evtprogress.id == 999 and evtprogress.type == "30":
                babylon_included = True
                break

        if not babylon_included:
            progress.append(
                Achievement(
                    999,
                    "30",
                    None,
                    {
                        "completed": False,
                        "progress": 0,
                    },
                )
            )

        for event in activeevents:
            # Get completion data
            playerstats = events.get(event, ValidatedDict({"completed": False}))

            # Return the data
            eventdata = Node.void("eventdata")
            response.add_child(eventdata)
            eventdata.add_child(Node.u32("eventid", event))
            eventdata.add_child(Node.s32("eventtype", 9999))
            eventdata.add_child(Node.u32("eventno", 0))
            eventdata.add_child(Node.s64("condition", 0))
            eventdata.add_child(Node.u32("reward", 0))
            eventdata.add_child(Node.s32("comptime", 1 if playerstats.get_bool("completed") else 0))
            eventdata.add_child(Node.s64("savedata", 0))

        for evtprogress in progress:
            # Babylon's adventure progres and anything else the game sends
            eventdata = Node.void("eventdata")
            response.add_child(eventdata)
            eventdata.add_child(Node.u32("eventid", evtprogress.id))
            eventdata.add_child(Node.s32("eventtype", int(evtprogress.type)))
            eventdata.add_child(Node.u32("eventno", 0))
            eventdata.add_child(Node.s64("condition", 0))
            eventdata.add_child(Node.u32("reward", rewards.get(evtprogress.type, {}).get(evtprogress.id)))
            eventdata.add_child(Node.s32("comptime", 1 if evtprogress.data.get_bool("completed") else 0))
            eventdata.add_child(Node.s64("savedata", evtprogress.data.get_int("progress")))

    def __handle_usersave(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        if userid is None:
            # the game sends us empty user ID strings when a guest is playing.
            # Return early so it doesn't wait a minute and a half to show the
            # results screen.
            return

        if requestdata.child_value("isgameover"):
            style = int(requestdata.child_value("playstyle"))
            is_dp = style == self.GAME_STYLE_DOUBLE

            # We don't save anything for gameover requests, since we
            # already saved scores on individual ones. So, just use this
            # as a spot to bump play counts and such
            play_stats = self.get_play_statistics(userid)
            if is_dp:
                play_stats.increment_int("double_plays")
            else:
                play_stats.increment_int("single_plays")
            self.update_play_statistics(userid, play_stats)

            # Now is a good time to check if we have workout mode enabled,
            # and if so, store the calories earned for this set.
            profile = self.get_profile(userid)
            enabled = profile.get_bool("workout_mode")
            weight = profile.get_int("weight")

            if enabled and weight > 0:
                # We enabled weight display, find the calories and save them
                total = 0
                for child in requestdata.children:
                    if child.name != "note":
                        continue

                    total = total + (child.child_value("calorie") or 0)

                self.data.local.user.put_time_based_achievement(
                    self.game,
                    self.version,
                    userid,
                    0,
                    "workout",
                    {
                        "calories": total,
                        "weight": weight,
                    },
                )

            # Find any event updates
            for child in requestdata.children:
                if child.name != "event":
                    continue

                # Skip empty events or events we don't support
                eventid = child.child_value("eventid")
                eventtype = child.child_value("eventtype")
                if eventid == 0 or eventtype == 0:
                    continue

                # Save data to replay to the client later
                completed = child.child_value("comptime") != 0
                progress = child.child_value("savedata")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    eventid,
                    str(eventtype),
                    {
                        "completed": completed,
                        "progress": progress,
                    },
                )

            return

        # Find the highest stagenum played
        score = None
        stagenum = 0
        for child in requestdata.children:
            if child.name != "note":
                continue

            if child.child_value("stagenum") > stagenum:
                score = child
                stagenum = child.child_value("stagenum")

        if score is None:
            raise Exception("Couldn't find newest score to save!")

        songid = score.child_value("mcode")
        chart = self.game_to_db_chart(score.child_value("notetype"))
        rank = self.game_to_db_rank(score.child_value("rank"))
        halo = self.game_to_db_halo(score.child_value("clearkind"))
        points = score.child_value("score")
        combo = score.child_value("maxcombo")
        ghost = score.child_value("ghost")
        self.update_score(
            userid,
            songid,
            chart,
            points,
            rank,
            halo,
            combo,
            ghost=ghost,
        )

    def __handle_rivalload(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        data = Node.void("data")
        response.add_child(data)
        data.add_child(Node.s32("recordtype", requestdata.child_value("loadflag")))

        thismachine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        machines_by_id: Dict[int, Optional[Machine]] = {thismachine.id: thismachine}

        loadkind = requestdata.child_value("loadflag")
        profiles_by_userid: Dict[UserID, Profile] = {}

        def get_machine(lid: int) -> Optional[Machine]:
            if lid not in machines_by_id:
                pcbid = self.data.local.machine.from_machine_id(lid)
                if pcbid is None:
                    machines_by_id[lid] = None
                    return None

                machine = self.data.local.machine.get_machine(pcbid)
                if machine is None:
                    machines_by_id[lid] = None
                    return None

                machines_by_id[lid] = machine
            return machines_by_id[lid]

        if loadkind == self.GAME_RIVAL_TYPE_WORLD:
            # Just load all scores for this network
            scores = self.data.remote.music.get_all_records(self.game, self.music_version)
        elif loadkind == self.GAME_RIVAL_TYPE_AREA:
            if thismachine.arcade is not None:
                match_arcade = thismachine.arcade
                match_machine = None
            else:
                match_arcade = None
                match_machine = thismachine.id

            # Load up all scores by any user registered on a machine in the same arcade
            profiles = self.data.local.user.get_all_profiles(self.game, self.version)
            userids: List[UserID] = []
            for userid, profiledata in profiles:
                profiles_by_userid[userid] = profiledata

                # If we have an arcade to match, see if this user's location matches the arcade.
                # If we don't, just match lid directly
                if match_arcade is not None:
                    theirmachine = get_machine(profiledata.get_int("lid"))
                    if theirmachine is not None and theirmachine.arcade == match_arcade:
                        userids.append(userid)
                elif match_machine is not None:
                    if profiledata.get_int("lid") == match_machine:
                        userids.append(userid)

            # Load all scores for users in the area
            scores = self.data.local.music.get_all_records(self.game, self.music_version, userlist=userids)
        elif loadkind == self.GAME_RIVAL_TYPE_MACHINE:
            # Load up all scores and filter them by those earned at this location
            scores = self.data.local.music.get_all_records(self.game, self.music_version, locationlist=[thismachine.id])
        elif loadkind in [
            self.GAME_RIVAL_TYPE_RIVAL1,
            self.GAME_RIVAL_TYPE_RIVAL2,
            self.GAME_RIVAL_TYPE_RIVAL3,
        ]:
            # Load up this user's highscores, format the way the below code expects it
            extid = requestdata.child_value("ddrcode")
            otherid = self.data.remote.user.from_extid(self.game, self.version, extid)
            userscores = self.data.remote.music.get_scores(self.game, self.music_version, otherid)
            scores = [(otherid, score) for score in userscores]
        else:
            # Nothing here
            scores = []

        missing_users = [userid for (userid, _) in scores if userid not in profiles_by_userid]
        for userid, profile in self.get_any_profiles(missing_users):
            profiles_by_userid[userid] = profile

        for userid, score in scores:
            if profiles_by_userid.get(userid) is None:
                raise Exception(f"Logic error, couldn't find any profile for {userid}")
            profiledata = profiles_by_userid[userid]

            record = Node.void("record")
            data.add_child(record)
            record.add_child(Node.u32("mcode", score.id))
            record.add_child(Node.u8("notetype", self.db_to_game_chart(score.chart)))
            record.add_child(Node.u8("rank", self.db_to_game_rank(score.data.get_int("rank"))))
            record.add_child(Node.u8("clearkind", self.db_to_game_halo(score.data.get_int("halo"))))
            record.add_child(Node.u8("flagdata", 0))
            record.add_child(Node.string("name", profiledata.get_str("name")))
            record.add_child(Node.s32("area", profiledata.get_int("area", 58)))
            record.add_child(Node.s32("code", profiledata.extid))
            record.add_child(Node.s32("score", score.points))
            record.add_child(Node.s32("ghostid", score.key))

    def __handle_usernew(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        if userid is None:
            raise Exception("Expecting valid UserID to create new profile!")

        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        profile = Profile(
            self.game,
            self.version,
            "",
            0,
            {
                "lid": machine.id,
            },
        )
        self.put_profile(userid, profile)

        response.add_child(Node.string("seq", ID.format_extid(profile.extid)))
        response.add_child(Node.s32("code", profile.extid))
        response.add_child(Node.string("shoparea", ""))

    def __handle_inheritance(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        if userid is not None:
            previous_version = self.previous_version()
            profile = previous_version.get_profile(userid)
        else:
            profile = None

        response.add_child(Node.s32("InheritanceStatus", 1 if profile is not None else 0))

    def __handle_ghostload(self, userid: Optional[UserID], requestdata: Node, response: Node) -> None:
        ghostid = requestdata.child_value("ghostid")
        ghost = self.data.local.music.get_score_by_key(self.game, self.music_version, ghostid)
        if ghost is None:
            return

        userid, score = ghost
        profile = self.get_profile(userid)
        if profile is None:
            return

        if "ghost" not in score.data:
            return

        ghostdata = Node.void("ghostdata")
        response.add_child(ghostdata)
        ghostdata.add_child(Node.s32("code", profile.extid))
        ghostdata.add_child(Node.u32("mcode", score.id))
        ghostdata.add_child(Node.u8("notetype", self.db_to_game_chart(score.chart)))
        ghostdata.add_child(Node.s32("ghostsize", len(score.data["ghost"])))
        ghostdata.add_child(Node.string("ghost", score.data["ghost"]))

    def handle_playerdata_usergamedata_advanced_request(self, request: Node) -> Optional[Node]:
        playerdata = Node.void("playerdata")

        # DDR Ace decides to be difficult and have a third level of packet switching
        mode = request.child_value("data/mode")
        refid = request.child_value("data/refid")
        extid = request.child_value("data/ddrcode")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            # Possibly look up by extid instead
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

        if mode == "userload":
            self.__handle_userload(userid, request.child("data"), playerdata)
        elif mode == "usersave":
            self.__handle_usersave(userid, request.child("data"), playerdata)
        elif mode == "rivalload":
            self.__handle_rivalload(userid, request.child("data"), playerdata)
        elif mode == "usernew":
            self.__handle_usernew(userid, request.child("data"), playerdata)
        elif mode == "inheritance":
            self.__handle_inheritance(userid, request.child("data"), playerdata)
        elif mode == "ghostload":
            self.__handle_ghostload(userid, request.child("data"), playerdata)
        else:
            # We don't support this
            return None

        playerdata.add_child(Node.s32("result", 0))
        return playerdata

    def handle_playerdata_usergamedata_send_request(self, request: Node) -> Node:
        playerdata = Node.void("playerdata")
        refid = request.child_value("data/refid")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid) or Profile(self.game, self.version, refid, 0)
            usergamedata = profile.get_dict("usergamedata")

            for record in request.child("data/record").children:
                if record.name != "d":
                    continue

                strdata = base64.b64decode(record.value)
                bindata = base64.b64decode(record.child_value("bin1"))

                # Grab and format the profile objects
                strdatalist = strdata.split(b",")
                profiletype = strdatalist[1].decode("utf-8")
                strdatalist = strdatalist[2:]

                # Extract relevant bits for frontend/API
                if profiletype == "COMMON":
                    profile.replace_str(
                        "name",
                        strdatalist[self.GAME_COMMON_NAME_OFFSET].decode("ascii"),
                    )
                    profile.replace_int(
                        "area",
                        intish(
                            strdatalist[self.GAME_COMMON_AREA_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                    profile.replace_bool(
                        "workout_mode",
                        int(
                            strdatalist[self.GAME_COMMON_WEIGHT_DISPLAY_OFFSET].decode("ascii"),
                            16,
                        )
                        != 0,
                    )
                    profile.replace_int(
                        "weight",
                        int(float(strdatalist[self.GAME_COMMON_WEIGHT_OFFSET].decode("ascii")) * 10),
                    )
                    profile.replace_int(
                        "character",
                        int(
                            strdatalist[self.GAME_COMMON_CHARACTER_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                if profiletype == "OPTION":
                    profile.replace_int(
                        "combo",
                        int(
                            strdatalist[self.GAME_OPTION_COMBO_POSITION_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                    profile.replace_int(
                        "early_late",
                        int(
                            strdatalist[self.GAME_OPTION_FAST_SLOW_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                    profile.replace_int(
                        "arrowskin",
                        int(
                            strdatalist[self.GAME_OPTION_ARROW_SKIN_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                    profile.replace_int(
                        "guidelines",
                        int(
                            strdatalist[self.GAME_OPTION_GUIDELINE_OFFSET].decode("ascii"),
                            16,
                        ),
                    )
                    profile.replace_int(
                        "filter",
                        int(
                            strdatalist[self.GAME_OPTION_FILTER_OFFSET].decode("ascii"),
                            16,
                        ),
                    )

                usergamedata[profiletype] = {
                    "strdata": b",".join(strdatalist),
                    "bindata": bindata,
                }

            profile.replace_dict("usergamedata", usergamedata)
            profile.replace_int("write_time", Time.now())
            self.put_profile(userid, profile)

        playerdata.add_child(Node.s32("result", 0))
        return playerdata

    def handle_playerdata_usergamedata_recv_request(self, request: Node) -> Node:
        playerdata = Node.void("playerdata")

        player = Node.void("player")
        playerdata.add_child(player)

        refid = request.child_value("data/refid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
            links = self.data.local.user.get_links(self.game, self.version, userid)
            records = 0

            record = Node.void("record")
            player.add_child(record)

            def acehex(val: int) -> str:
                return hex(val)[2:]

            if profile is None:
                # Figure out what profiles are being requested
                profiletypes = request.child_value("data/recv_csv").split(",")[::2]
                for ptype in profiletypes:
                    # Just return a default empty node
                    record.add_child(Node.string("d", "<NODATA>"))
                    records += 1
            else:
                # Figure out what profiles are being requested
                profiletypes = request.child_value("data/recv_csv").split(",")[::2]
                usergamedata = profile.get_dict("usergamedata")
                for ptype in profiletypes:
                    if ptype in usergamedata:
                        if ptype == "COMMON":
                            # Return basic profile options
                            name = profile.get_str("name")
                            area = profile.get_int("area", self.get_machine_region())
                            if name == "":
                                # This is a bogus profile created by the first login, substitute the
                                # previous version values so that profile succession works.
                                previous_version = self.previous_version()
                                old_profile = previous_version.get_profile(userid)
                                if old_profile is not None:
                                    name = old_profile.get_str("name")
                                    area = old_profile.get_int("area", self.get_machine_region())
                                else:
                                    area = self.get_machine_region()

                            common = usergamedata[ptype]["strdata"].split(b",")
                            common[self.GAME_COMMON_NAME_OFFSET] = name.encode("ascii")
                            common[self.GAME_COMMON_AREA_OFFSET] = acehex(area).encode("ascii")
                            common[self.GAME_COMMON_WEIGHT_DISPLAY_OFFSET] = (
                                b"1" if profile.get_bool("workout_mode") else b"0"
                            )
                            common[self.GAME_COMMON_WEIGHT_OFFSET] = str(
                                float(profile.get_int("weight")) / 10.0
                            ).encode("ascii")
                            common[self.GAME_COMMON_CHARACTER_OFFSET] = acehex(profile.get_int("character")).encode(
                                "ascii"
                            )
                            usergamedata[ptype]["strdata"] = b",".join(common)
                        if ptype == "OPTION":
                            # Return user settings for frontend
                            option = usergamedata[ptype]["strdata"].split(b",")
                            option[self.GAME_OPTION_FAST_SLOW_OFFSET] = acehex(profile.get_int("early_late")).encode(
                                "ascii"
                            )
                            option[self.GAME_OPTION_COMBO_POSITION_OFFSET] = acehex(profile.get_int("combo")).encode(
                                "ascii"
                            )
                            option[self.GAME_OPTION_ARROW_SKIN_OFFSET] = acehex(profile.get_int("arrowskin")).encode(
                                "ascii"
                            )
                            option[self.GAME_OPTION_GUIDELINE_OFFSET] = acehex(profile.get_int("guidelines")).encode(
                                "ascii"
                            )
                            option[self.GAME_OPTION_FILTER_OFFSET] = acehex(profile.get_int("filter")).encode("ascii")
                            usergamedata[ptype]["strdata"] = b",".join(option)
                        if ptype == "LAST":
                            # Return the number of calories expended in the last day
                            workouts = self.data.local.user.get_time_based_achievements(
                                self.game,
                                self.version,
                                userid,
                                achievementtype="workout",
                                since=Time.now() - Time.SECONDS_IN_DAY,
                            )
                            total = sum([w.data.get_int("calories") for w in workouts])

                            last = usergamedata[ptype]["strdata"].split(b",")
                            last[self.GAME_LAST_CALORIES_OFFSET] = acehex(total).encode("ascii")
                            usergamedata[ptype]["strdata"] = b",".join(last)
                        if ptype == "RIVAL":
                            # Fill in the DDR code and active status of the three active
                            # rivals.
                            rival = usergamedata[ptype]["strdata"].split(b",")
                            lastdict = profile.get_dict("last")

                            friends: Dict[int, Optional[Profile]] = {}
                            for link in links:
                                if link.type[:7] != "friend_":
                                    continue

                                pos = int(link.type[7:])
                                friends[pos] = self.get_profile(link.other_userid)

                            for rivalno in [1, 2, 3]:
                                activeslot = {
                                    1: self.GAME_RIVAL_SLOT_1_ACTIVE_OFFSET,
                                    2: self.GAME_RIVAL_SLOT_2_ACTIVE_OFFSET,
                                    3: self.GAME_RIVAL_SLOT_3_ACTIVE_OFFSET,
                                }[rivalno]

                                whichfriend = lastdict.get_int(f"rival{rivalno}") - 1
                                if whichfriend < 0:
                                    # This rival isn't active
                                    rival[activeslot] = b"0"
                                    continue

                                friendprofile = friends.get(whichfriend)
                                if friendprofile is None:
                                    # This rival doesn't exist
                                    rival[activeslot] = b"0"
                                    continue

                                ddrcodeslot = {
                                    1: self.GAME_RIVAL_SLOT_1_DDRCODE_OFFSET,
                                    2: self.GAME_RIVAL_SLOT_2_DDRCODE_OFFSET,
                                    3: self.GAME_RIVAL_SLOT_3_DDRCODE_OFFSET,
                                }[rivalno]

                                rival[activeslot] = acehex(rivalno).encode("ascii")
                                rival[ddrcodeslot] = acehex(friendprofile.extid).encode("ascii")

                            usergamedata[ptype]["strdata"] = b",".join(rival)

                        dnode = Node.string(
                            "d",
                            base64.b64encode(usergamedata[ptype]["strdata"]).decode("ascii"),
                        )
                        dnode.add_child(
                            Node.string(
                                "bin1",
                                base64.b64encode(usergamedata[ptype]["bindata"]).decode("ascii"),
                            )
                        )
                        record.add_child(dnode)

                    else:
                        # Just return a default empty node
                        record.add_child(Node.string("d", "<NODATA>"))

                    records += 1

            player.add_child(Node.u32("record_num", records))

        playerdata.add_child(Node.s32("result", 0))
        return playerdata

    def handle_system_convcardnumber_request(self, request: Node) -> Node:
        cardid = request.child_value("data/card_id")
        cardnumber = CardCipher.encode(cardid)

        system = Node.void("system")
        data = Node.void("data")
        system.add_child(data)

        system.add_child(Node.s32("result", 0))
        data.add_child(Node.string("card_number", cardnumber))
        return system
