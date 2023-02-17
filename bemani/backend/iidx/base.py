# vim: set fileencoding=utf-8
import struct
from typing import Optional, Dict, Any, List, Tuple
from typing_extensions import Final

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler, PASELIHandler
from bemani.common import (
    Profile,
    ValidatedDict,
    Model,
    GameConstants,
    DBConstants,
    Parallel,
)
from bemani.data import Config, Data, Score, Machine, UserID
from bemani.protocol import Node


class IIDXBase(CoreHandler, CardManagerHandler, PASELIHandler, Base):
    """
    Base game class for all Beatmania IIDX versions. Handles common functionality for
    getting profiles based on refid, creating new profiles, looking up and saving
    scores.
    """

    game: GameConstants = GameConstants.IIDX

    paseli_padding: int = 15

    CLEAR_TYPE_SINGLE: Final[int] = 1
    CLEAR_TYPE_DOUBLE: Final[int] = 2

    CLEAR_STATUS_NO_PLAY: Final[int] = DBConstants.IIDX_CLEAR_STATUS_NO_PLAY
    CLEAR_STATUS_FAILED: Final[int] = DBConstants.IIDX_CLEAR_STATUS_FAILED
    CLEAR_STATUS_ASSIST_CLEAR: Final[int] = DBConstants.IIDX_CLEAR_STATUS_ASSIST_CLEAR
    CLEAR_STATUS_EASY_CLEAR: Final[int] = DBConstants.IIDX_CLEAR_STATUS_EASY_CLEAR
    CLEAR_STATUS_CLEAR: Final[int] = DBConstants.IIDX_CLEAR_STATUS_CLEAR
    CLEAR_STATUS_HARD_CLEAR: Final[int] = DBConstants.IIDX_CLEAR_STATUS_HARD_CLEAR
    CLEAR_STATUS_EX_HARD_CLEAR: Final[int] = DBConstants.IIDX_CLEAR_STATUS_EX_HARD_CLEAR
    CLEAR_STATUS_FULL_COMBO: Final[int] = DBConstants.IIDX_CLEAR_STATUS_FULL_COMBO

    CHART_TYPE_N7: Final[int] = 0
    CHART_TYPE_H7: Final[int] = 1
    CHART_TYPE_A7: Final[int] = 2
    CHART_TYPE_N14: Final[int] = 3
    CHART_TYPE_H14: Final[int] = 4
    CHART_TYPE_A14: Final[int] = 5
    # Beginner charts only save status
    CHART_TYPE_B7: Final[int] = 6

    DAN_RANK_7_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_7_KYU
    DAN_RANK_6_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_6_KYU
    DAN_RANK_5_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_5_KYU
    DAN_RANK_4_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_4_KYU
    DAN_RANK_3_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_3_KYU
    DAN_RANK_2_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_2_KYU
    DAN_RANK_1_KYU: Final[int] = DBConstants.IIDX_DAN_RANK_1_KYU
    DAN_RANK_1_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_1_DAN
    DAN_RANK_2_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_2_DAN
    DAN_RANK_3_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_3_DAN
    DAN_RANK_4_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_4_DAN
    DAN_RANK_5_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_5_DAN
    DAN_RANK_6_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_6_DAN
    DAN_RANK_7_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_7_DAN
    DAN_RANK_8_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_8_DAN
    DAN_RANK_9_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_9_DAN
    DAN_RANK_10_DAN: Final[int] = DBConstants.IIDX_DAN_RANK_10_DAN
    DAN_RANK_CHUDEN: Final[int] = DBConstants.IIDX_DAN_RANK_CHUDEN
    DAN_RANK_KAIDEN: Final[int] = DBConstants.IIDX_DAN_RANK_KAIDEN

    DAN_RANKING_SINGLE: Final[str] = "sgrade"
    DAN_RANKING_DOUBLE: Final[str] = "dgrade"

    GHOST_TYPE_NONE: Final[int] = 0
    GHOST_TYPE_RIVAL: Final[int] = 100
    GHOST_TYPE_GLOBAL_TOP: Final[int] = 200
    GHOST_TYPE_GLOBAL_AVERAGE: Final[int] = 300
    GHOST_TYPE_LOCAL_TOP: Final[int] = 400
    GHOST_TYPE_LOCAL_AVERAGE: Final[int] = 500
    GHOST_TYPE_DAN_TOP: Final[int] = 600
    GHOST_TYPE_DAN_AVERAGE: Final[int] = 700
    GHOST_TYPE_RIVAL_TOP: Final[int] = 800
    GHOST_TYPE_RIVAL_AVERAGE: Final[int] = 900

    # Return the local2 service so that Copula and above will send certain packets.
    extra_services: List[str] = [
        "local2",
    ]

    def __init__(self, data: Data, config: Config, model: Model) -> None:
        super().__init__(data, config, model)
        if model.rev == "X":
            self.omnimix = True
        else:
            self.omnimix = False

    @property
    def music_version(self) -> int:
        if self.omnimix:
            return DBConstants.OMNIMIX_VERSION_BUMP + self.version
        return self.version

    def previous_version(self) -> Optional["IIDXBase"]:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        """
        Base handler for a profile. Given a userid and a profile dictionary,
        return a Node representing a profile. Should be overridden.
        """
        return Node.void("pc")

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        """
        Base handler for profile parsing. Given a request and an old profile,
        return a new profile that's been updated with the contents of the request.
        Should be overridden.
        """
        return oldprofile

    def get_profile_by_refid(self, refid: Optional[str]) -> Optional[Node]:
        """
        Given a RefID, return a formatted profile node. Basically every game
        needs a profile lookup, even if it handles where that happens in
        a different request. This is provided for code deduplication.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            # User doesn't exist but should at this point
            return None

        # Trying to import from current version
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_profile(userid, profile)

    def new_profile_by_refid(
        self, refid: Optional[str], name: Optional[str], pid: Optional[int]
    ) -> Profile:
        """
        Given a RefID and an optional name, create a profile and then return
        that newly created profile.
        """
        if refid is None:
            return None

        if name is None:
            name = "なし"
        if pid is None:
            pid = self.get_machine_region()

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = Profile(
            self.game,
            self.version,
            refid,
            0,
            {
                "name": name,
                "pid": pid,
                "settings": {
                    "flags": 223  # Default to turning on all optional folders
                },
            },
        )
        self.put_profile(userid, profile)
        return profile

    def put_profile_by_extid(self, extid: Optional[int], request: Node) -> None:
        """
        Given an ExtID and a request node, unformat the profile and save it.
        """
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            return

        oldprofile = self.get_profile(userid)
        newprofile = self.unformat_profile(userid, request, oldprofile)
        if newprofile is not None:
            self.put_profile(userid, newprofile)

    def get_machine_by_id(self, shop_id: int) -> Optional[Machine]:
        pcbid = self.data.local.machine.from_machine_id(shop_id)
        if pcbid is not None:
            return self.data.local.machine.get_machine(pcbid)
        else:
            return None

    def machine_joined_arcade(self) -> bool:
        machine = self.data.local.machine.get_machine(self.config.machine.pcbid)
        return machine.arcade is not None

    def get_clear_rates(
        self,
        songid: Optional[int] = None,
        songchart: Optional[int] = None,
    ) -> Dict[int, Dict[int, Dict[str, int]]]:
        """
        Returns a dictionary similar to the following:

        {
            musicid: {
                chart: {
                    total: total plays,
                    clears: total clears,
                    fcs: total full combos,
                },
            },
        }
        """
        all_attempts, remote_attempts = Parallel.execute(
            [
                lambda: self.data.local.music.get_all_attempts(
                    game=self.game,
                    version=self.music_version,
                    songid=songid,
                    songchart=songchart,
                ),
                lambda: self.data.remote.music.get_clear_rates(
                    game=self.game,
                    version=self.music_version,
                    songid=songid,
                    songchart=songchart,
                ),
            ]
        )

        attempts: Dict[int, Dict[int, Dict[str, int]]] = {}
        for _, attempt in all_attempts:
            if attempt.data.get_int("clear_status") == self.CLEAR_STATUS_NO_PLAY:
                # This attempt was outside of the clear infra, so don't bother with it.
                continue

            # Terrible temporary structure is terrible.
            if attempt.id not in attempts:
                attempts[attempt.id] = {}
            if attempt.chart not in attempts[attempt.id]:
                attempts[attempt.id][attempt.chart] = {
                    "total": 0,
                    "clears": 0,
                    "fcs": 0,
                }

            # We saw an attempt, keep the total attempts in sync.
            attempts[attempt.id][attempt.chart]["total"] = (
                attempts[attempt.id][attempt.chart]["total"] + 1
            )

            if (
                attempt.data.get_int("clear_status", self.CLEAR_STATUS_FAILED)
                == self.CLEAR_STATUS_FAILED
            ):
                # This attempt was a failure, so don't count it against clears of full combos
                continue

            # It was at least a clear
            attempts[attempt.id][attempt.chart]["clears"] = (
                attempts[attempt.id][attempt.chart]["clears"] + 1
            )

            if attempt.data.get_int("clear_status") == self.CLEAR_STATUS_FULL_COMBO:
                # This was a full combo clear, so it also counts here
                attempts[attempt.id][attempt.chart]["fcs"] = (
                    attempts[attempt.id][attempt.chart]["fcs"] + 1
                )

        # Merge in remote attempts
        for songid in remote_attempts:
            if songid not in attempts:
                attempts[songid] = {}

            for songchart in remote_attempts[songid]:
                if songchart not in attempts[songid]:
                    attempts[songid][songchart] = {
                        "total": 0,
                        "clears": 0,
                        "fcs": 0,
                    }

                attempts[songid][songchart]["total"] += remote_attempts[songid][
                    songchart
                ]["plays"]
                attempts[songid][songchart]["clears"] += remote_attempts[songid][
                    songchart
                ]["clears"]
                attempts[songid][songchart]["fcs"] += remote_attempts[songid][
                    songchart
                ]["combos"]

        # If requesting a specific song/chart, make sure its in the dict
        if songid is not None:
            if songid not in attempts:
                attempts[songid] = {}

            if songchart is not None:
                if songchart not in attempts[songid]:
                    attempts[songid][songchart] = {
                        "total": 0,
                        "clears": 0,
                        "fcs": 0,
                    }

        return attempts

    def update_score(
        self,
        userid: Optional[UserID],
        songid: int,
        chart: int,
        clear_status: int,
        pgreats: int,
        greats: int,
        miss_count: int,
        ghost: Optional[bytes],
        shop: Optional[int],
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in IIDX series can expect
        the same attributes in a score. Note that the medals passed here are
        expected to be converted from game identifier to our internal identifier,
        so that any game in the series may convert them back. In this way, a song
        played on Pendual that exists in Tricoro will still have scores/medals
        going back all versions.
        """
        # Range check medals
        if clear_status not in [
            self.CLEAR_STATUS_NO_PLAY,
            self.CLEAR_STATUS_FAILED,
            self.CLEAR_STATUS_ASSIST_CLEAR,
            self.CLEAR_STATUS_EASY_CLEAR,
            self.CLEAR_STATUS_CLEAR,
            self.CLEAR_STATUS_HARD_CLEAR,
            self.CLEAR_STATUS_EX_HARD_CLEAR,
            self.CLEAR_STATUS_FULL_COMBO,
        ]:
            raise Exception(f"Invalid clear status value {clear_status}")

        # Calculate ex score
        ex_score = (2 * pgreats) + greats

        if userid is not None:
            if ghost is None:
                raise Exception("Expected a ghost for user score save!")
            oldscore = self.data.local.music.get_score(
                self.game,
                self.music_version,
                userid,
                songid,
                chart,
            )
        else:
            # Storing an anonymous attempt
            if ghost is not None:
                raise Exception("Expected no ghost for anonymous score save!")
            oldscore = None

        # Score history is verbatum, instead of highest score
        history = ValidatedDict(
            {
                "clear_status": clear_status,
                "miss_count": miss_count,
            }
        )
        old_ex_score = ex_score

        if ghost is not None:
            history["ghost"] = ghost

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict(
                {
                    "clear_status": clear_status,
                    "pgreats": pgreats,
                    "greats": greats,
                }
            )
            if miss_count != -1:
                scoredata.replace_int("miss_count", miss_count)
            if ghost is not None:
                scoredata["ghost"] = ghost
            raised = True
            highscore = True
        else:
            # Set the score to any new record achieved
            raised = ex_score > oldscore.points
            highscore = ex_score >= oldscore.points
            ex_score = max(ex_score, oldscore.points)
            scoredata = oldscore.data
            scoredata.replace_int(
                "clear_status", max(scoredata.get_int("clear_status"), clear_status)
            )
            if miss_count != -1:
                if scoredata.get_int("miss_count", -1) == -1:
                    scoredata.replace_int("miss_count", miss_count)
                else:
                    scoredata.replace_int(
                        "miss_count", min(scoredata.get_int("miss_count"), miss_count)
                    )
            if raised:
                scoredata.replace_int("pgreats", pgreats)
                scoredata.replace_int("greats", greats)
                if ghost is not None:
                    scoredata.replace_bytes("ghost", ghost)

        if shop is not None:
            history.replace_int("shop", shop)
            scoredata.replace_int("shop", shop)

        # Look up where this score was earned
        lid = self.get_machine_id()

        if userid is not None:
            # Write the new score back
            self.data.local.music.put_score(
                self.game,
                self.music_version,
                userid,
                songid,
                chart,
                lid,
                ex_score,
                scoredata,
                highscore,
            )

        # Save the history of this score too
        self.data.local.music.put_attempt(
            self.game,
            self.music_version,
            userid,
            songid,
            chart,
            lid,
            old_ex_score,
            history,
            raised,
        )

    def update_rank(
        self,
        userid: UserID,
        dantype: str,
        rank: int,
        percent: int,
        cleared: bool,
        stages_cleared: int,
    ) -> None:
        # Range check type
        if dantype not in [
            self.DAN_RANKING_SINGLE,
            self.DAN_RANKING_DOUBLE,
        ]:
            raise Exception(f"Invalid dan rank type value {dantype}")

        # Range check rank
        if rank not in [
            self.DAN_RANK_7_KYU,
            self.DAN_RANK_6_KYU,
            self.DAN_RANK_5_KYU,
            self.DAN_RANK_4_KYU,
            self.DAN_RANK_3_KYU,
            self.DAN_RANK_2_KYU,
            self.DAN_RANK_1_KYU,
            self.DAN_RANK_1_DAN,
            self.DAN_RANK_2_DAN,
            self.DAN_RANK_3_DAN,
            self.DAN_RANK_4_DAN,
            self.DAN_RANK_5_DAN,
            self.DAN_RANK_6_DAN,
            self.DAN_RANK_7_DAN,
            self.DAN_RANK_8_DAN,
            self.DAN_RANK_9_DAN,
            self.DAN_RANK_10_DAN,
            self.DAN_RANK_CHUDEN,
            self.DAN_RANK_KAIDEN,
        ]:
            raise Exception(f"Invalid dan rank {rank}")

        if cleared:
            # Update profile if needed
            profile = self.get_profile(userid)
            if profile is None:
                profile = Profile(
                    self.game,
                    self.version,
                    "",
                    0,
                )

            profile.replace_int(dantype, max(rank, profile.get_int(dantype, -1)))
            self.put_profile(userid, profile)

        # Update achievement to track pass rate
        dan_score = self.data.local.user.get_achievement(
            self.game,
            self.version,
            userid,
            rank,
            dantype,
        )
        if dan_score is None:
            dan_score = ValidatedDict()
        dan_score.replace_int("percent", max(percent, dan_score.get_int("percent")))
        dan_score.replace_int(
            "stages_cleared", max(stages_cleared, dan_score.get_int("stages_cleared"))
        )
        self.data.local.user.put_achievement(
            self.game, self.version, userid, rank, dantype, dan_score
        )

    def db_to_game_status(self, db_status: int) -> int:
        """
        Given a DB status, translate to a game clear status.
        """
        raise Exception("Implement in specific game class!")

    def game_to_db_status(self, game_status: int) -> int:
        """
        Given a game clear status, translate to DB status.
        """
        raise Exception("Implement in specific game class!")

    def game_to_db_chart(self, game_chart: int) -> int:
        """
        Given a game's chart for a song, return the chart as defined above.
        """
        raise Exception("Implement in sub-class!")

    def db_to_game_chart(self, db_chart: int) -> int:
        """
        Given a chart as defined above, return the game's chart constant.
        """
        raise Exception("Implement in sub-class!")

    def make_score_struct(
        self, scores: List[Score], cltype: int, index: int
    ) -> List[List[int]]:
        scorestruct: Dict[int, List[int]] = {}

        for score in scores:
            musicid = score.id
            chart = score.chart

            # Filter to only singles/doubles charts
            if cltype == self.CLEAR_TYPE_SINGLE:
                if chart not in [
                    self.CHART_TYPE_N7,
                    self.CHART_TYPE_H7,
                    self.CHART_TYPE_A7,
                ]:
                    continue
                chartindex = {
                    self.CHART_TYPE_N7: 0,
                    self.CHART_TYPE_H7: 1,
                    self.CHART_TYPE_A7: 2,
                }[chart]
            if cltype == self.CLEAR_TYPE_DOUBLE:
                if chart not in [
                    self.CHART_TYPE_N14,
                    self.CHART_TYPE_H14,
                    self.CHART_TYPE_A14,
                ]:
                    continue
                chartindex = {
                    self.CHART_TYPE_N14: 0,
                    self.CHART_TYPE_H14: 1,
                    self.CHART_TYPE_A14: 2,
                }[chart]

            if musicid not in scorestruct:
                scorestruct[musicid] = [
                    index,  # -1 is our scores, positive is rival index
                    musicid,  # Music ID!
                    0,  # Normal status,
                    0,  # Hyper status,
                    0,  # Another status,
                    0,  # EX score normal,
                    0,  # EX score hyper,
                    0,  # EX score another,
                    -1,  # Miss count normal,
                    -1,  # Miss count hyper,
                    -1,  # Miss count another,
                ]

            scorestruct[musicid][chartindex + 2] = self.db_to_game_status(
                score.data.get_int("clear_status")
            )
            scorestruct[musicid][chartindex + 5] = score.points
            scorestruct[musicid][chartindex + 8] = score.data.get_int("miss_count", -1)

        return [scorestruct[s] for s in scorestruct]

    def make_beginner_struct(self, scores: List[Score]) -> List[List[int]]:
        scorelist: List[List[int]] = []

        for score in scores:
            musicid = score.id
            chart = score.chart

            # Filter to only beginner charts
            if chart != self.CHART_TYPE_B7:
                continue

            scorelist.append(
                [
                    musicid,
                    self.db_to_game_status(score.data.get_int("clear_status")),
                ]
            )

        return scorelist

    def delta_score(
        self,
        scores: List[Score],
        ghost_length: int,
    ) -> Tuple[Optional[int], Optional[bytes]]:
        if len(scores) == 0:
            return None, None

        total_ghost = [0] * ghost_length
        count = 0

        # Sum up for each bucket
        for score in scores:
            ghost = score.data.get_bytes("ghost")
            for i in range(len(ghost)):
                total_ghost[i] = total_ghost[i] + ghost[i]
            count = count + 1

        # Calculate average for each bucket
        total_ghost = [int(b / count) for b in total_ghost]

        # Grab the ex score for this new ghost, being sure to reverse the scaling rate
        new_ex_score = sum(total_ghost)

        # Spread out into even buckets so we can compute deltas
        reference_ghost = [int(new_ex_score / ghost_length)] * ghost_length

        added_bucket = 0
        try:
            jump = max(1, int(ghost_length / (new_ex_score - sum(reference_ghost))))
        except ZeroDivisionError:
            jump = 1
        while sum(reference_ghost) != new_ex_score:
            reference_ghost[added_bucket] = reference_ghost[added_bucket] + 1
            added_bucket = added_bucket + jump

        # Calculate delta ghost
        delta_ghost = [total_ghost[i] - reference_ghost[i] for i in range(ghost_length)]

        # Return averages
        return new_ex_score, struct.pack("b" * ghost_length, *delta_ghost)

    def user_joined_arcade(self, machine: Machine, profile: Optional[Profile]) -> bool:
        if profile is None:
            return False

        if "shop_location" not in profile:
            return False

        machineid = profile.get_int("shop_location")
        if machineid == machine.id:
            # We can short-circuit arcade lookup because their machine
            # is the current machine.
            return True

        their_machine = self.get_machine_by_id(machineid)
        if their_machine is None:
            return False

        # The machine they joined matches the arcade of the current machine
        return their_machine.arcade == machine.arcade

    def get_ghost(
        self,
        ghost_type: int,
        parameter: str,
        ghost_length: int,
        musicid: int,
        chart: int,
        userid: UserID,
    ) -> Optional[Dict[str, Any]]:
        ghost_score: Dict[str, Any] = None

        if ghost_type == self.GHOST_TYPE_RIVAL:
            rival_extid = int(parameter)
            rival_userid = self.data.remote.user.from_extid(
                self.game, self.version, rival_extid
            )
            if rival_userid is not None:
                rival_profile = self.get_profile(rival_userid)
                rival_score = self.data.remote.music.get_score(
                    self.game, self.music_version, rival_userid, musicid, chart
                )
                if rival_score is not None and rival_profile is not None:
                    ghost_score = {
                        "score": rival_score.points,
                        "ghost": rival_score.data.get_bytes("ghost"),
                        "name": rival_profile.get_str("name"),
                        "pid": rival_profile.get_int("pid"),
                    }

        if (
            ghost_type == self.GHOST_TYPE_GLOBAL_TOP
            or ghost_type == self.GHOST_TYPE_LOCAL_TOP
            or ghost_type == self.GHOST_TYPE_GLOBAL_AVERAGE
            or ghost_type == self.GHOST_TYPE_LOCAL_AVERAGE
        ):
            if (
                ghost_type == self.GHOST_TYPE_LOCAL_TOP
                or ghost_type == self.GHOST_TYPE_LOCAL_AVERAGE
            ):
                all_scores = sorted(
                    self.data.local.music.get_all_scores(
                        game=self.game,
                        version=self.music_version,
                        songid=musicid,
                        songchart=chart,
                    ),
                    key=lambda s: s[1].points,
                    reverse=True,
                )

                # Figure out what arcade this user joined and filter scores by
                # other users who have also joined that arcade.
                my_profile = self.get_profile(userid)
                if my_profile is None:
                    my_profile = Profile(
                        self.game,
                        self.version,
                        "",
                        0,
                    )

                if "shop_location" in my_profile:
                    shop_id = my_profile.get_int("shop_location")
                    machine = self.get_machine_by_id(shop_id)
                else:
                    machine = None

                if machine is not None:
                    all_scores = [
                        score
                        for score in all_scores
                        if self.user_joined_arcade(
                            machine, self.get_any_profile(score[0])
                        )
                    ]
                else:
                    # Not joined an arcade, so nobody matches our scores
                    all_scores = []
            else:
                all_scores = sorted(
                    self.data.remote.music.get_all_scores(
                        game=self.game,
                        version=self.music_version,
                        songid=musicid,
                        songchart=chart,
                    ),
                    key=lambda s: s[1].points,
                    reverse=True,
                )

            if (
                ghost_type == self.GHOST_TYPE_GLOBAL_TOP
                or ghost_type == self.GHOST_TYPE_LOCAL_TOP
            ):
                for potential_top in all_scores:
                    top_userid = potential_top[0]
                    top_score = potential_top[1]
                    top_profile = self.get_any_profile(top_userid)
                    if top_profile is not None:
                        ghost_score = {
                            "score": top_score.points,
                            "ghost": top_score.data.get_bytes("ghost"),
                            "name": top_profile.get_str("name"),
                            "pid": top_profile.get_int("pid"),
                            "extid": top_profile.extid,
                        }
                        break

            if (
                ghost_type == self.GHOST_TYPE_GLOBAL_AVERAGE
                or ghost_type == self.GHOST_TYPE_LOCAL_AVERAGE
            ):
                average_score, delta_ghost = self.delta_score(
                    [score[1] for score in all_scores], ghost_length
                )
                if average_score is not None and delta_ghost is not None:
                    ghost_score = {
                        "score": average_score,
                        "ghost": bytes([0] * ghost_length),
                    }

        if (
            ghost_type == self.GHOST_TYPE_DAN_TOP
            or ghost_type == self.GHOST_TYPE_DAN_AVERAGE
        ):
            is_dp = chart not in [
                self.CHART_TYPE_N7,
                self.CHART_TYPE_H7,
                self.CHART_TYPE_A7,
            ]
            my_profile = self.get_profile(userid)
            if my_profile is None:
                my_profile = Profile(
                    self.game,
                    self.version,
                    "",
                    0,
                )
            if is_dp:
                dan_rank = my_profile.get_int(self.DAN_RANKING_DOUBLE, -1)
            else:
                dan_rank = my_profile.get_int(self.DAN_RANKING_SINGLE, -1)

            if dan_rank != -1:
                all_scores = sorted(
                    self.data.local.music.get_all_scores(
                        game=self.game,
                        version=self.music_version,
                        songid=musicid,
                        songchart=chart,
                    ),
                    key=lambda s: s[1].points,
                    reverse=True,
                )
                all_profiles = self.data.local.user.get_all_profiles(
                    self.game, self.version
                )
                relevant_userids = {
                    profile[0]
                    for profile in all_profiles
                    if profile[1].get_int(
                        self.DAN_RANKING_DOUBLE if is_dp else self.DAN_RANKING_SINGLE
                    )
                    == dan_rank
                }
                relevant_scores = [
                    score for score in all_scores if score[0] in relevant_userids
                ]
                if ghost_type == self.GHOST_TYPE_DAN_TOP:
                    for potential_top in relevant_scores:
                        top_userid = potential_top[0]
                        top_score = potential_top[1]
                        top_profile = self.get_any_profile(top_userid)
                        if top_profile is not None:
                            ghost_score = {
                                "score": top_score.points,
                                "ghost": top_score.data.get_bytes("ghost"),
                                "name": top_profile.get_str("name"),
                                "pid": top_profile.get_int("pid"),
                                "extid": top_profile.extid,
                            }
                            break

                if ghost_type == self.GHOST_TYPE_DAN_AVERAGE:
                    average_score, delta_ghost = self.delta_score(
                        [score[1] for score in relevant_scores], ghost_length
                    )
                    if average_score is not None and delta_ghost is not None:
                        ghost_score = {
                            "score": average_score,
                            "ghost": bytes([0] * ghost_length),
                        }

        if (
            ghost_type == self.GHOST_TYPE_RIVAL_TOP
            or ghost_type == self.GHOST_TYPE_RIVAL_AVERAGE
        ):
            rival_extids = [int(e[1:-1]) for e in parameter.split(",")]
            rival_userids = [
                self.data.remote.user.from_extid(self.game, self.version, rival_extid)
                for rival_extid in rival_extids
            ]

            all_scores = sorted(
                [
                    score
                    for score in self.data.remote.music.get_all_scores(
                        game=self.game,
                        version=self.music_version,
                        songid=musicid,
                        songchart=chart,
                    )
                    if score[0] in rival_userids
                ],
                key=lambda s: s[1].points,
                reverse=True,
            )
            if ghost_type == self.GHOST_TYPE_RIVAL_TOP:
                for potential_top in all_scores:
                    top_userid = potential_top[0]
                    top_score = potential_top[1]
                    top_profile = self.get_any_profile(top_userid)
                    if top_profile is not None:
                        ghost_score = {
                            "score": top_score.points,
                            "ghost": top_score.data.get_bytes("ghost"),
                            "name": top_profile.get_str("name"),
                            "pid": top_profile.get_int("pid"),
                            "extid": top_profile.extid,
                        }
                        break

            if ghost_type == self.GHOST_TYPE_RIVAL_AVERAGE:
                average_score, delta_ghost = self.delta_score(
                    [score[1] for score in all_scores], ghost_length
                )
                if average_score is not None and delta_ghost is not None:
                    ghost_score = {
                        "score": average_score,
                        "ghost": bytes([0] * ghost_length),
                    }

        return ghost_score
