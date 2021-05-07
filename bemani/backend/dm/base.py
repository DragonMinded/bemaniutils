from typing import Dict, List, Optional, Any

from bemani.backend.base import Base
from bemani.backend.core import CoreHandler, CardManagerHandler
from bemani.common import ValidatedDict, GameConstants, Time, DBConstants, Parallel, Model
from bemani.data import UserID, Score, Data
from bemani.protocol import Node

class DrummaniaBase(CoreHandler, CardManagerHandler, Base):
    """
    Trying to work on GFDM right now. starting off strong with DM :)
    """

    game = GameConstants.DRUMMANIA

    CLEAR_TYPE_NO_PLAY = DBConstants.DRUMMANIA_CLEAR_TYPE_NO_PLAY
    CLEAR_TYPE_FAILED = DBConstants.DRUMMANIA_CLEAR_TYPE_FAILED
    CLEAR_TYPE_CLEAR = DBConstants.DRUMMANIA_CLEAR_TYPE_CLEAR
    CLEAR_TYPE_FULL_COMBO = DBConstants.DRUMMANIA_CLEAR_TYPE_FULL_COMBO

    GRADE_NO_PLAY = DBConstants.DRUMMANIA_GRADE_NO_PLAY
    GRADE_D = DBConstants.DRUMMANIA_GRADE_D
    GRADE_C = DBConstants.DRUMMANIA_GRADE_C
    GRADE_B = DBConstants.DRUMMANIA_GRADE_B
    GRADE_A = DBConstants.DRUMMANIA_GRADE_A
    GRADE_AA = DBConstants.DRUMMANIA_GRADE_AA
    GRADE_AAA = DBConstants.DRUMMANIA_GRADE_AAA
    GRADE_S = DBConstants.DRUMMANIA_GRADE_S

    CHART_TYPE_BEGINNER = 0
    CHART_TYPE_BASIC = 1
    CHART_TYPE_ADVANCED = 2
    CHART_TYPE_EXTREME = 3

    def __init__(self, data: Data, config: Dict[str, Any], model: Model) -> None:
        super().__init__(data, config, model)
        if model.rev == 'X':
            self.omnimix = True
        else:
            self.omnimix = False

    @property
    def music_version(self) -> int:
        if self.omnimix:
            return DBConstants.OMNIMIX_VERSION_BUMP + self.version
        return self.version

    def previous_version(self) -> Optional['DrummaniaBase']:
        """
        Returns the previous version of the game, based on this game. Should
        be overridden.
        """
        return None
    
    def get_profile_by_refid(self, refid: Optional[str]) -> Optional[Node]:
        """
        Given a RefID, return a formatted profile node. Basically every game
        needs a profile lookup, even if it handles where that happens in
        a different request. This is provided for code deduplication.
        """
        if refid is None:
            return None

        # First try to load the actual profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        profile = self.get_profile(userid)
        if profile is None:
            return None

        # Now, return it
        return self.format_profile(userid, profile)

    def new_profile_by_refid(self, refid: Optional[str], name: Optional[str], locid: Optional[int]) -> Node:
        """
        Given a RefID and an optional name, create a profile and then return
        a formatted profile node. Similar rationale to get_profile_by_refid.
        """
        if refid is None:
            return None

        if name is None:
            name = 'NONAME'

        # First, create and save the default profile
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        defaultprofile = ValidatedDict({
            'name': name,
            'loc': locid,
        })
        self.put_profile(userid, defaultprofile)

        # Now, reload and format the profile, looking up the has old version flag
        profile = self.get_profile(userid)
        return self.format_profile(userid, profile)

    def put_profile_by_refid(self, refid: Optional[str], request: Node) -> None:
        """
        Given a RefID and a request node, unformat the profile and save it.
        """
        if refid is None:
            return
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return

        oldprofile = self.get_profile(userid)
        newprofile = self.unformat_profile(userid, request, oldprofile)
        if newprofile is not None:
            self.put_profile(userid, newprofile)

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        """
        Base handler for a profile. Given a userid and a profile dictionary,
        return a Node representing a profile. Should be overridden.
        """
        return Node.void('game')

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        """
        Base handler for profile parsing. Given a request and an old profile,
        return a new profile that's been updated with the contents of the request.
        Should be overridden.
        """
        return oldprofile
    
    def get_clear_rates(self) -> Dict[int, Dict[int, Dict[str, int]]]:
        """
        Returns a dictionary similar to the following:

        {
            musicid: {
                chart: {
                    total: total plays,
                    clears: total clears,
                    average: average score,
                },
            },
        }
        """
        all_attempts, remote_attempts = Parallel.execute([
            lambda: self.data.local.music.get_all_attempts(
                game=self.game,
                version=self.version,
            ),
            lambda: self.data.remote.music.get_clear_rates(
                game=self.game,
                version=self.version,
            )
        ])
        attempts: Dict[int, Dict[int, Dict[str, int]]] = {}
        for (_, attempt) in all_attempts:
            # Terrible temporary structure is terrible.
            if attempt.id not in attempts:
                attempts[attempt.id] = {}
            if attempt.chart not in attempts[attempt.id]:
                attempts[attempt.id][attempt.chart] = {
                    'total': 0,
                    'clears': 0,
                    'average': 0,
                }

            # We saw an attempt, keep the total attempts in sync.
            attempts[attempt.id][attempt.chart]['average'] = int(
                (
                    (attempts[attempt.id][attempt.chart]['average'] * attempts[attempt.id][attempt.chart]['total']) +
                    attempt.points
                ) / (attempts[attempt.id][attempt.chart]['total'] + 1)
            )
            attempts[attempt.id][attempt.chart]['total'] += 1

            if attempt.data.get_int('clear_type', self.CLEAR_TYPE_NO_PLAY) in [self.CLEAR_TYPE_NO_PLAY, self.CLEAR_TYPE_FAILED]:
                # This attempt was a failure, so don't count it against clears of full combos
                continue

            # It was at least a clear
            attempts[attempt.id][attempt.chart]['clears'] += 1
        # Merge in remote attempts
        for songid in remote_attempts:
            if songid not in attempts:
                attempts[songid] = {}

            for songchart in remote_attempts[songid]:
                if songchart not in attempts[songid]:
                    attempts[songid][songchart] = {
                        'total': 0,
                        'clears': 0,
                        'average': 0,
                    }

                attempts[songid][songchart]['total'] += remote_attempts[songid][songchart]['plays']
                attempts[songid][songchart]['clears'] += remote_attempts[songid][songchart]['clears']

        return attempts

    def get_scores_by_refid(self, refid: Optional[int]) -> Optional[Node]:
        """
        Given a RefID, return a formatted score node. Similar rationale to
        get_profile_by_extid.
        """
        if refid is None:
            return None

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
        if scores is None:
            return None
        profile = self.get_profile(userid)
        if profile is None:
            return None
        return self.format_scores(userid, profile, scores)

    def update_score(
        self,
        userid: Optional[UserID],
        songid: int,
        seqmode: int,
        clear: int,
        autoclear: int,
        score: int,
        fullcombo: int,
        excellent: int,
        combo: int,
        skill_point: int,
        skill_perc: int,
        result_rank: int,
        combo_rate: int,
        perfect_rate: int,
        difficulty: int,
    ) -> None:
        """
        Given various pieces of a score, update the user's high score and score
        history in a controlled manner, so all games in DM series can expect
        the same attributes in a score.
        """
        

        #pull old score
        oldscore = self.data.local.music.get_score(
            self.game,
            self.music_version,
            userid,
            songid,
            seqmode,
        )

        history = ValidatedDict({})
        oldpoints = score

        if oldscore is None:
            # If it is a new score, create a new dictionary to add to
            scoredata = ValidatedDict({})
            raised = True
            highscore = True
        else:
            # Set the score to any new record achieved
            raised = score > oldscore.points
            highscore = score >= oldscore.points
            score = max(oldscore.points, score)
            scoredata = oldscore.data

        # If we have a combo, replace it
        scoredata.replace_int('combo', max(scoredata.get_int('combo'), combo))
        history.replace_int('combo', combo)

        #write our skill points
        print(skill_perc)
        print(skill_point)
        scoredata.replace_int('skill_points', max(scoredata.get_int('skill_points'), skill_point))
        history.replace_int('skill_points', skill_point)

        #write our skill percent
        scoredata.replace_int('skill_perc', max(scoredata.get_int('skill_perc'), skill_perc))
        history.replace_int('skill_perc', skill_perc)

        #did we clear the song?
        scoredata.replace_int('clear', max(scoredata.get_int('clear'), clear))
        history.replace_int('clear', clear)

        #did we cheat?
        #scoredata.replace_int('autoclear', max(scoredata.get_int('autoclear'), autoclear))
        #history.replace_int('autoclear', autoclear)

        #did we full combo?
        scoredata.replace_int('fullcombo', max(scoredata.get_int('fullcombo'), fullcombo))
        history.replace_int('fullcombo', fullcombo)

        #did we excellent full combo?
        scoredata.replace_int('excellent', max(scoredata.get_int('excellent'), excellent))
        history.replace_int('excellent', excellent)

        #how did we rank?
        scoredata.replace_int('result_rank', max(scoredata.get_int('result_rank'), result_rank))
        history.replace_int('result_rank', result_rank)

        #what was the rate of the combo?
        scoredata.replace_int('combo_rate', max(scoredata.get_int('combo_rate'), combo_rate))
        history.replace_int('combo_rate', combo_rate)

        #what was the perfect rate?
        scoredata.replace_int('perfect_rate', max(scoredata.get_int('perfect_rate'), perfect_rate))
        history.replace_int('perfect_rate', perfect_rate)


        # Look up where this score was earned
        lid = self.get_machine_id()

        # GFDM for all versions sends all of the songs
        # a player played at the end of the round. It doesn't send timestamps
        # for those songs (Jubeat does). So, if a user plays the same song/chart
        # more than once in a round, we will end up failing to store the attempt
        # since we don't allow two of the same attempt at the same time for the
        # same user and song/chart. So, bump the timestamp by one second and retry
        # well past the maximum number of songs.
        now = Time.now()
        for bump in range(10):
            timestamp = now + bump

        print(songid)
        

        # Write the new score back
        self.data.local.music.put_score(
            self.game,
            self.music_version,
            userid,
            songid,
            seqmode,
            lid,
            score,
            scoredata,
            highscore,
            timestamp=timestamp,
        )

        # Save the history of this score too
        self.data.local.music.put_attempt(
            self.game,
            self.music_version,
            userid,
            songid,
            seqmode,
            lid,
            score,
            history,
            highscore,
            timestamp=timestamp,
        )

    def format_scores(self, userid: UserID, profile: ValidatedDict, scores: List[Score]) -> Node:
        """
        Base handler for a score list. Given a userid, profile and a score list,
        return a Node representing a score list. Should be overridden.
        """
        return Node.void('gametop')