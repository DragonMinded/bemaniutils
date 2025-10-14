from typing import List, Optional, Dict, Any, Tuple, Set

from bemani.common import (
    APIConstants,
    GameConstants,
    VersionConstants,
    DBConstants,
    Parallel,
)
from bemani.data.interfaces import APIProviderInterface
from bemani.data.api.base import BaseGlobalData
from bemani.data.mysql.user import UserData
from bemani.data.mysql.music import MusicData
from bemani.data.remoteuser import RemoteUser
from bemani.data.types import UserID, Score, Song


class GlobalMusicData(BaseGlobalData):
    def __init__(self, api: APIProviderInterface, user: UserData, music: MusicData) -> None:
        super().__init__(api)
        self.user = user
        self.music = music

    def __get_cardids(self, userid: UserID) -> List[str]:
        if RemoteUser.is_remote(userid):
            return [RemoteUser.userid_to_card(userid)]
        else:
            return self.user.get_cards(userid)

    def __min(self, int1: int, int2: int) -> int:
        # -1 is used as a 'no value' so it should not overwrite a 0
        if int1 == -1:
            return int2
        if int2 == -1:
            return int1
        return min(int1, int2)

    def __max(self, int1: int, int2: int) -> int:
        return max(int1, int2)

    def __format_danevo_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        grade = {
            "AAA": DBConstants.DANEVO_GRADE_AAA,
            "AA": DBConstants.DANEVO_GRADE_AA,
            "A": DBConstants.DANEVO_GRADE_A,
            "B": DBConstants.DANEVO_GRADE_B,
            "C": DBConstants.DANEVO_GRADE_C,
            "D": DBConstants.DANEVO_GRADE_D,
            "E": DBConstants.DANEVO_GRADE_E,
            "F": DBConstants.DANEVO_GRADE_FAILED,
        }.get(data.get("grade"), DBConstants.DANEVO_GRADE_FAILED)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "combo": int(data.get("combo", -1)),
                "grade": grade,
                "full_combo": bool(data.get("full_combo", False)),
            },
        )

    def __format_ddr_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        halo = {
            "none": DBConstants.DDR_HALO_NONE,
            "gfc": DBConstants.DDR_HALO_GOOD_FULL_COMBO,
            "fc": DBConstants.DDR_HALO_GREAT_FULL_COMBO,
            "pfc": DBConstants.DDR_HALO_PERFECT_FULL_COMBO,
            "mfc": DBConstants.DDR_HALO_MARVELOUS_FULL_COMBO,
        }.get(data.get("halo"), DBConstants.DDR_HALO_NONE)
        rank = {
            "AAA": DBConstants.DDR_RANK_AAA,
            "AA+": DBConstants.DDR_RANK_AA_PLUS,
            "AA": DBConstants.DDR_RANK_AA,
            "AA-": DBConstants.DDR_RANK_AA_MINUS,
            "A+": DBConstants.DDR_RANK_A_PLUS,
            "A": DBConstants.DDR_RANK_A,
            "A-": DBConstants.DDR_RANK_A_MINUS,
            "B+": DBConstants.DDR_RANK_B_PLUS,
            "B": DBConstants.DDR_RANK_B,
            "B-": DBConstants.DDR_RANK_B_MINUS,
            "C+": DBConstants.DDR_RANK_C_PLUS,
            "C": DBConstants.DDR_RANK_C,
            "C-": DBConstants.DDR_RANK_C_MINUS,
            "D+": DBConstants.DDR_RANK_D_PLUS,
            "D": DBConstants.DDR_RANK_D,
            "E": DBConstants.DDR_RANK_E,
        }.get(data.get("rank"), DBConstants.DDR_RANK_E)

        ghost = ""
        trace: List[int] = []

        if version == VersionConstants.DDR_ACE:
            # DDR Ace is specia
            ghost = "".join([str(x) for x in data.get("ghost", [])])
        else:
            trace = [int(x) for x in data.get("ghost", [])]

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "combo": int(data.get("combo", -1)),
                "rank": rank,
                "halo": halo,
                "ghost": ghost,
                "trace": trace,
            },
        )

    def __format_iidx_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        status = {
            "np": DBConstants.IIDX_CLEAR_STATUS_NO_PLAY,
            "failed": DBConstants.IIDX_CLEAR_STATUS_FAILED,
            "ac": DBConstants.IIDX_CLEAR_STATUS_ASSIST_CLEAR,
            "ec": DBConstants.IIDX_CLEAR_STATUS_EASY_CLEAR,
            "nc": DBConstants.IIDX_CLEAR_STATUS_CLEAR,
            "hc": DBConstants.IIDX_CLEAR_STATUS_HARD_CLEAR,
            "exhc": DBConstants.IIDX_CLEAR_STATUS_EX_HARD_CLEAR,
            "fc": DBConstants.IIDX_CLEAR_STATUS_FULL_COMBO,
        }.get(data.get("status"), DBConstants.IIDX_CLEAR_STATUS_NO_PLAY)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "clear_status": status,
                "ghost": bytes([int(b) for b in data.get("ghost", [])]),
                "miss_count": int(data.get("miss", -1)),
                "pgreats": int(data.get("pgreat", -1)),
                "greats": int(data.get("great", -1)),
            },
        )

    def __format_jubeat_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        status = {
            "failed": DBConstants.JUBEAT_PLAY_MEDAL_FAILED,
            "cleared": DBConstants.JUBEAT_PLAY_MEDAL_CLEARED,
            "nfc": DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_FULL_COMBO,
            "fc": DBConstants.JUBEAT_PLAY_MEDAL_FULL_COMBO,
            "nec": DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_EXCELLENT,
            "exc": DBConstants.JUBEAT_PLAY_MEDAL_EXCELLENT,
        }.get(data.get("status"), DBConstants.JUBEAT_PLAY_MEDAL_FAILED)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "medal": status,
                "combo": int(data.get("combo", -1)),
                "ghost": [int(x) for x in data.get("ghost", [])],
                "music_rate": int(data.get("music_rate")),
            },
        )

    def __format_museca_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        rank = {
            "death": DBConstants.MUSECA_GRADE_DEATH,
            "poor": DBConstants.MUSECA_GRADE_POOR,
            "mediocre": DBConstants.MUSECA_GRADE_MEDIOCRE,
            "good": DBConstants.MUSECA_GRADE_GOOD,
            "great": DBConstants.MUSECA_GRADE_GREAT,
            "excellent": DBConstants.MUSECA_GRADE_EXCELLENT,
            "superb": DBConstants.MUSECA_GRADE_SUPERB,
            "masterpiece": DBConstants.MUSECA_GRADE_MASTERPIECE,
            "perfect": DBConstants.MUSECA_GRADE_PERFECT,
        }.get(data.get("rank"), DBConstants.MUSECA_GRADE_DEATH)
        status = {
            "failed": DBConstants.MUSECA_CLEAR_TYPE_FAILED,
            "cleared": DBConstants.MUSECA_CLEAR_TYPE_CLEARED,
            "fc": DBConstants.MUSECA_CLEAR_TYPE_FULL_COMBO,
        }.get(data.get("status"), DBConstants.MUSECA_CLEAR_TYPE_FAILED)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "grade": rank,
                "clear_type": status,
                "combo": int(data.get("combo", -1)),
                "stats": {
                    "btn_rate": int(data.get("buttonrate", -1)),
                    "long_rate": int(data.get("longrate", -1)),
                    "vol_rate": int(data.get("volrate", -1)),
                },
            },
        )

    def __format_popn_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        status = {
            "cf": DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED,
            "df": DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FAILED,
            "sf": DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FAILED,
            "ec": DBConstants.POPN_MUSIC_PLAY_MEDAL_EASY_CLEAR,
            "cc": DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_CLEARED,
            "dc": DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_CLEARED,
            "sc": DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_CLEARED,
            "cfc": DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FULL_COMBO,
            "dfc": DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FULL_COMBO,
            "sfc": DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FULL_COMBO,
            "p": DBConstants.POPN_MUSIC_PLAY_MEDAL_PERFECT,
        }.get(data.get("status"), DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "medal": status,
                "combo": int(data.get("combo", -1)),
            },
        )

    def __format_reflec_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        status = {
            "np": DBConstants.REFLEC_BEAT_CLEAR_TYPE_NO_PLAY,
            "failed": DBConstants.REFLEC_BEAT_CLEAR_TYPE_FAILED,
            "cleared": DBConstants.REFLEC_BEAT_CLEAR_TYPE_CLEARED,
            "hc": DBConstants.REFLEC_BEAT_CLEAR_TYPE_HARD_CLEARED,
            "shc": DBConstants.REFLEC_BEAT_CLEAR_TYPE_S_HARD_CLEARED,
        }.get(data.get("status"), DBConstants.REFLEC_BEAT_CLEAR_TYPE_NO_PLAY)
        halo = {
            "none": DBConstants.REFLEC_BEAT_COMBO_TYPE_NONE,
            "ac": DBConstants.REFLEC_BEAT_COMBO_TYPE_ALMOST_COMBO,
            "fc": DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO,
            "fcaj": DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO_ALL_JUST,
        }.get(data.get("halo"), DBConstants.REFLEC_BEAT_COMBO_TYPE_NONE)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "achievement_rate": int(data.get("rate", -1)),
                "clear_type": status,
                "combo_type": halo,
                "miss_count": int(data.get("miss", -1)),
                "combo": int(data.get("combo", -1)),
            },
        )

    def __format_sdvx_score(self, version: int, songid: int, songchart: int, data: Dict[str, Any]) -> Score:
        status = {
            "np": DBConstants.SDVX_CLEAR_TYPE_NO_PLAY,
            "failed": DBConstants.SDVX_CLEAR_TYPE_FAILED,
            "cleared": DBConstants.SDVX_CLEAR_TYPE_CLEAR,
            "hc": DBConstants.SDVX_CLEAR_TYPE_HARD_CLEAR,
            "uc": DBConstants.SDVX_CLEAR_TYPE_ULTIMATE_CHAIN,
            "puc": DBConstants.SDVX_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }.get(data.get("status"), DBConstants.SDVX_CLEAR_TYPE_NO_PLAY)
        rank = {
            "E": DBConstants.SDVX_GRADE_NO_PLAY,
            "D": DBConstants.SDVX_GRADE_D,
            "C": DBConstants.SDVX_GRADE_C,
            "B": DBConstants.SDVX_GRADE_B,
            "A": DBConstants.SDVX_GRADE_A,
            "A+": DBConstants.SDVX_GRADE_A_PLUS,
            "AA": DBConstants.SDVX_GRADE_AA,
            "AA+": DBConstants.SDVX_GRADE_AA_PLUS,
            "AAA": DBConstants.SDVX_GRADE_AAA,
            "AAA+": DBConstants.SDVX_GRADE_AAA_PLUS,
            "S": DBConstants.SDVX_GRADE_S,
        }.get(data.get("rank"), DBConstants.SDVX_GRADE_NO_PLAY)

        return Score(
            -1,
            songid,
            songchart,
            int(data.get("points", 0)),
            int(data.get("timestamp", -1)),
            self.__max(int(data.get("timestamp", -1)), int(data.get("updated", -1))),
            -1,  # No location for remote play
            1,  # No play info for remote play
            {
                "grade": rank,
                "clear_type": status,
                "combo": int(data.get("combo", -1)),
                "stats": {
                    "btn_rate": int(data.get("buttonrate", -1)),
                    "long_rate": int(data.get("longrate", -1)),
                    "vol_rate": int(data.get("volrate", -1)),
                },
            },
        )

    def __format_score(
        self,
        game: GameConstants,
        version: int,
        songid: int,
        songchart: int,
        data: Dict[str, Any],
    ) -> Optional[Score]:
        if game == GameConstants.DDR:
            return self.__format_ddr_score(version, songid, songchart, data)
        if game == GameConstants.IIDX:
            return self.__format_iidx_score(version, songid, songchart, data)
        if game == GameConstants.JUBEAT:
            return self.__format_jubeat_score(version, songid, songchart, data)
        if game == GameConstants.MUSECA:
            return self.__format_museca_score(version, songid, songchart, data)
        if game == GameConstants.POPN_MUSIC:
            return self.__format_popn_score(version, songid, songchart, data)
        if game == GameConstants.REFLEC_BEAT:
            return self.__format_reflec_score(version, songid, songchart, data)
        if game == GameConstants.SDVX:
            return self.__format_sdvx_score(version, songid, songchart, data)
        if game == GameConstants.DANCE_EVOLUTION:
            return self.__format_danevo_score(version, songid, songchart, data)
        return None

    def __merge_danevo_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "grade": self.__max(oldscore.data["grade"], newscore.data["grade"]),
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
                "full_combo": oldscore.data["full_combo"] or newscore.data["full_combo"],
            },
        )

    def __merge_ddr_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "rank": self.__max(oldscore.data["rank"], newscore.data["rank"]),
                "halo": self.__max(oldscore.data["halo"], newscore.data["halo"]),
                "ghost": (
                    oldscore.data.get("ghost") if oldscore.points > newscore.points else newscore.data.get("ghost")
                ),
                "trace": (
                    oldscore.data.get("trace") if oldscore.points > newscore.points else newscore.data.get("trace")
                ),
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
            },
        )

    def __merge_iidx_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "clear_status": self.__max(oldscore.data["clear_status"], newscore.data["clear_status"]),
                "ghost": (
                    oldscore.data.get("ghost") if oldscore.points > newscore.points else newscore.data.get("ghost")
                ),
                "miss_count": self.__min(
                    oldscore.data.get_int("miss_count", -1),
                    newscore.data.get_int("miss_count", -1),
                ),
                "pgreats": (
                    oldscore.data.get_int("pgreats", -1)
                    if oldscore.points > newscore.points
                    else newscore.data.get_int("pgreats", -1)
                ),
                "greats": (
                    oldscore.data.get_int("greats", -1)
                    if oldscore.points > newscore.points
                    else newscore.data.get_int("greats", -1)
                ),
            },
        )

    def __merge_jubeat_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        rate = self.__max(oldscore.data.get("music_rate", -1), newscore.data.get("music_rate", -1))

        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "ghost": (
                    oldscore.data.get("ghost") if oldscore.points > newscore.points else newscore.data.get("ghost")
                ),
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
                "medal": self.__max(oldscore.data["medal"], newscore.data["medal"]),
                # Conditionally include this if we have any info for it.
                **({"music_rate": rate} if rate >= 0 else {}),
            },
        )

    def __merge_museca_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "grade": self.__max(oldscore.data["grade"], newscore.data["grade"]),
                "clear_type": self.__max(oldscore.data["clear_type"], newscore.data["clear_type"]),
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
                "stats": oldscore.data["stats"] if oldscore.points > newscore.points else newscore.data["stats"],
            },
        )

    def __merge_popn_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
                "medal": self.__max(oldscore.data["medal"], newscore.data["medal"]),
            },
        )

    def __merge_reflec_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "clear_type": self.__max(oldscore.data["clear_type"], newscore.data["clear_type"]),
                "combo_type": self.__max(oldscore.data["combo_type"], newscore.data["combo_type"]),
                "miss_count": self.__min(
                    oldscore.data.get_int("miss_count", -1),
                    newscore.data.get_int("miss_count", -1),
                ),
                "combo": self.__max(oldscore.data["combo"], newscore.data["combo"]),
                "achievement_rate": self.__max(oldscore.data["achievement_rate"], newscore.data["achievement_rate"]),
            },
        )

    def __merge_sdvx_score(self, version: int, oldscore: Score, newscore: Score) -> Score:
        return Score(
            -1,
            oldscore.id,
            oldscore.chart,
            self.__max(oldscore.points, newscore.points),
            self.__max(oldscore.timestamp, newscore.timestamp),
            self.__max(
                self.__max(oldscore.update, newscore.update),
                self.__max(oldscore.timestamp, newscore.timestamp),
            ),
            oldscore.location,  # Always propagate location from local setup if possible
            oldscore.plays + newscore.plays,
            {
                "grade": self.__max(oldscore.data["grade"], newscore.data["grade"]),
                "clear_type": self.__max(oldscore.data["clear_type"], newscore.data["clear_type"]),
                "combo": self.__max(
                    oldscore.data.get_int("combo", 1),
                    newscore.data.get_int("combo", -1),
                ),
                "stats": oldscore.data["stats"] if oldscore.points > newscore.points else newscore.data["stats"],
            },
        )

    def __merge_score(self, game: GameConstants, version: int, oldscore: Score, newscore: Score) -> Score:
        if oldscore.id != newscore.id or oldscore.chart != newscore.chart:
            raise Exception("Logic error! Tried to merge scores from different song/charts!")

        if game == GameConstants.DDR:
            return self.__merge_ddr_score(version, oldscore, newscore)
        if game == GameConstants.IIDX:
            return self.__merge_iidx_score(version, oldscore, newscore)
        if game == GameConstants.JUBEAT:
            return self.__merge_jubeat_score(version, oldscore, newscore)
        if game == GameConstants.MUSECA:
            return self.__merge_museca_score(version, oldscore, newscore)
        if game == GameConstants.POPN_MUSIC:
            return self.__merge_popn_score(version, oldscore, newscore)
        if game == GameConstants.REFLEC_BEAT:
            return self.__merge_reflec_score(version, oldscore, newscore)
        if game == GameConstants.SDVX:
            return self.__merge_sdvx_score(version, oldscore, newscore)
        if game == GameConstants.DANCE_EVOLUTION:
            return self.__merge_danevo_score(version, oldscore, newscore)

        return oldscore

    def get_score(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        songid: int,
        songchart: int,
    ) -> Optional[Score]:
        # Helper function so we can iterate over all servers for a single card
        def get_scores_for_card(cardid: str) -> List[Score]:
            return Parallel.flatten(
                Parallel.call(
                    [client.get_records for client in self.clients],
                    game,
                    version,
                    APIConstants.ID_TYPE_INSTANCE,
                    [songid, songchart, cardid],
                )
            )

        relevant_cards = self.__get_cardids(userid)
        if RemoteUser.is_remote(userid):
            # No need to look up local score for this user
            scores = Parallel.flatten(
                Parallel.map(
                    get_scores_for_card,
                    relevant_cards,
                )
            )
            localscore = None
        else:
            localscore, scores = Parallel.execute(
                [
                    lambda: self.music.get_score(game, version, userid, songid, songchart),
                    lambda: Parallel.flatten(
                        Parallel.map(
                            get_scores_for_card,
                            relevant_cards,
                        )
                    ),
                ]
            )

        topscore = localscore

        for score in scores:
            if int(score["song"]) != songid:
                continue
            if int(score["chart"]) != songchart:
                continue

            newscore = self.__format_score(game, version, songid, songchart, score)

            if topscore is None:
                # No merging needed
                topscore = newscore
                continue

            topscore = self.__merge_score(game, version, topscore, newscore)

        return topscore

    def get_scores(
        self,
        game: GameConstants,
        version: int,
        userid: UserID,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Score]:
        relevant_cards = self.__get_cardids(userid)
        if RemoteUser.is_remote(userid):
            # No need to look up local score for this user
            scores = Parallel.flatten(
                Parallel.call(
                    [client.get_records for client in self.clients],
                    game,
                    version,
                    APIConstants.ID_TYPE_CARD,
                    relevant_cards,
                    since,
                    until,
                )
            )
            localscores: List[Score] = []
        else:
            localscores, scores = Parallel.execute(
                [
                    lambda: self.music.get_scores(game, version, userid, since, until),
                    lambda: Parallel.flatten(
                        Parallel.call(
                            [client.get_records for client in self.clients],
                            game,
                            version,
                            APIConstants.ID_TYPE_CARD,
                            relevant_cards,
                            since,
                            until,
                        )
                    ),
                ]
            )

        allscores: Dict[int, Dict[int, Score]] = {}

        def add_score(score: Score) -> None:
            if score.id not in allscores:
                allscores[score.id] = {}
            allscores[score.id][score.chart] = score

        def get_score(songid: int, songchart: int) -> Optional[Score]:
            return allscores.get(songid, {}).get(songchart)

        # First, seed with local scores
        for score in localscores:
            add_score(score)

        # Second, merge in remote scorse
        for remotescore in scores:
            songid = int(remotescore["song"])
            chart = int(remotescore["chart"])
            newscore = self.__format_score(game, version, songid, chart, remotescore)
            oldscore = get_score(songid, chart)

            if oldscore is None:
                add_score(newscore)
            else:
                add_score(self.__merge_score(game, version, oldscore, newscore))

        # Finally, flatten and return
        finalscores: List[Score] = []
        for songid in allscores:
            for chart in allscores[songid]:
                finalscores.append(allscores[songid][chart])

        return finalscores

    def __merge_global_scores(
        self,
        game: GameConstants,
        version: int,
        localcards: List[Tuple[str, UserID]],
        localscores: List[Tuple[UserID, Score]],
        remotescores: List[Dict[str, Any]],
    ) -> List[Tuple[UserID, Score]]:
        card_to_id = {cardid: userid for (cardid, userid) in localcards}
        allscores: Dict[UserID, Dict[int, Dict[int, Score]]] = {}

        def add_score(userid: UserID, score: Score) -> None:
            if userid not in allscores:
                allscores[userid] = {}
            if score.id not in allscores[userid]:
                allscores[userid][score.id] = {}
            allscores[userid][score.id][score.chart] = score

        def get_score(userid: UserID, songid: int, songchart: int) -> Optional[Score]:
            return allscores.get(userid, {}).get(songid, {}).get(songchart)

        # First, seed with local scores
        for userid, score in localscores:
            add_score(userid, score)

        # Second, merge in remote scorse
        for remotescore in remotescores:
            # Figure out the userid of this score
            cardids = sorted([card.upper() for card in remotescore.get("cards", [])])
            if len(cardids) == 0:
                continue

            for cardid in cardids:
                if cardid in card_to_id:
                    userid = card_to_id[cardid]
                    break
            else:
                userid = RemoteUser.card_to_userid(cardids[0])

            songid = int(remotescore["song"])
            chart = int(remotescore["chart"])
            newscore = self.__format_score(game, version, songid, chart, remotescore)
            oldscore = get_score(userid, songid, chart)

            if oldscore is None:
                add_score(userid, newscore)
            else:
                add_score(userid, self.__merge_score(game, version, oldscore, newscore))

        # Finally, flatten and return
        finalscores: List[Tuple[UserID, Score]] = []
        for userid in allscores:
            for songid in allscores[userid]:
                for chart in allscores[userid][songid]:
                    finalscores.append((userid, allscores[userid][songid][chart]))

        return finalscores

    def get_all_scores(
        self,
        game: GameConstants,
        version: Optional[int] = None,
        userid: Optional[UserID] = None,
        songid: Optional[int] = None,
        songchart: Optional[int] = None,
        since: Optional[int] = None,
        until: Optional[int] = None,
    ) -> List[Tuple[UserID, Score]]:
        # First, pass off to local-only if this was called with parameters we don't support
        if version is None or userid is not None or songid is None:
            return self.music.get_all_scores(game, version, userid, songid, songchart, since, until)

        # Now, figure out the request key based on passed in parameters
        if songchart is None:
            songkey = [songid]
        else:
            songkey = [songid, songchart]

        # Now, fetch all the scores remotely and locally
        localcards, localscores, remotescores = Parallel.execute(
            [
                self.user.get_all_cards,
                lambda: self.music.get_all_scores(game, version, userid, songid, songchart, since, until),
                lambda: Parallel.flatten(
                    Parallel.call(
                        [client.get_records for client in self.clients],
                        game,
                        version,
                        APIConstants.ID_TYPE_SONG,
                        songkey,
                        since,
                        until,
                    )
                ),
            ]
        )

        return self.__merge_global_scores(game, version, localcards, localscores, remotescores)

    def __merge_global_records(
        self,
        game: GameConstants,
        version: int,
        localcards: List[Tuple[str, UserID]],
        localscores: List[Tuple[UserID, Score]],
        remotescores: List[Dict[str, Any]],
    ) -> List[Tuple[UserID, Score]]:
        card_to_id = {cardid: userid for (cardid, userid) in localcards}
        allscores: Dict[int, Dict[int, Tuple[UserID, Score]]] = {}

        def add_score(userid: UserID, score: Score) -> None:
            if score.id not in allscores:
                allscores[score.id] = {}
            allscores[score.id][score.chart] = (userid, score)

        def get_score(songid: int, songchart: int) -> Tuple[Optional[UserID], Optional[Score]]:
            return allscores.get(songid, {}).get(songchart, (None, None))

        # First, seed with local records
        for userid, score in localscores:
            add_score(userid, score)

        # Second, merge in remote records
        for remotescore in remotescores:
            # Figure out the userid of this score
            cardids = sorted([card.upper() for card in remotescore.get("cards", [])])
            if len(cardids) == 0:
                continue

            for cardid in cardids:
                if cardid in card_to_id:
                    userid = card_to_id[cardid]
                    break
            else:
                userid = RemoteUser.card_to_userid(cardids[0])

            songid = int(remotescore["song"])
            chart = int(remotescore["chart"])
            newscore = self.__format_score(game, version, songid, chart, remotescore)
            oldid, oldscore = get_score(songid, chart)

            if oldscore is None:
                add_score(userid, newscore)
            else:
                # if IDs are the same then we should merge them
                if oldid == userid:
                    add_score(userid, self.__merge_score(game, version, oldscore, newscore))
                else:
                    # if the IDs are different we need to check which score actually belongs
                    if newscore.points > oldscore.points:
                        add_score(userid, newscore)

        # Finally, flatten and return
        finalscores: List[Tuple[UserID, Score]] = []
        for songid in allscores:
            for chart in allscores[songid]:
                finalscores.append((allscores[songid][chart][0], allscores[songid][chart][1]))

        return finalscores

    def get_all_records(
        self,
        game: GameConstants,
        version: Optional[int] = None,
        userlist: Optional[List[UserID]] = None,
        locationlist: Optional[List[int]] = None,
    ) -> List[Tuple[UserID, Score]]:
        # First, pass off to local-only if this was called with parameters we don't support
        if version is None or userlist is not None or locationlist is not None:
            return self.music.get_all_records(game, version, userlist, locationlist)

        # Now, fetch all records remotely and locally
        localcards, localscores, remotescores = Parallel.execute(
            [
                self.user.get_all_cards,
                lambda: self.music.get_all_records(game, version, userlist, locationlist),
                lambda: Parallel.flatten(
                    Parallel.call(
                        [client.get_records for client in self.clients],
                        game,
                        version,
                        APIConstants.ID_TYPE_SERVER,
                        [],
                    )
                ),
            ]
        )

        return self.__merge_global_records(game, version, localcards, localscores, remotescores)

    def get_clear_rates(
        self,
        game: GameConstants,
        version: int,
        songid: Optional[int] = None,
        songchart: Optional[int] = None,
    ) -> Dict[int, Dict[int, Dict[str, int]]]:
        """
        Given an optional songid, or optional songid and songchart, looks up clear rates
        in remote servers that are connected to us. If neither id or chart is given, looks
        up global clear rates. If songid is given, looks up clear rates for each chart for
        the song. If songid and chart is given, looks up clear rates for that song/chart.

        Returns a dictionary keyed by songid, whos values are a dictionary keyed by chart,
        whos values are a dictionary containing integer counts keyed by 'plays', 'clears',
        and 'combos'. An example is as follows:

        {
            musicid: {
                chart: {
                    plays: total plays,
                    clears: total clears,
                    combos: total full combos,
                },
            },
        }
        """

        if songid is None and songchart is None:
            statistics = Parallel.flatten(
                Parallel.call(
                    [client.get_statistics for client in self.clients],
                    game,
                    version,
                    APIConstants.ID_TYPE_SERVER,
                    [],
                )
            )
        elif songid is not None:
            if songchart is None:
                ids = [songid]
            else:
                ids = [songid, songchart]
            statistics = Parallel.flatten(
                Parallel.call(
                    [client.get_statistics for client in self.clients],
                    game,
                    version,
                    APIConstants.ID_TYPE_SONG,
                    ids,
                )
            )
        else:
            statistics = []

        retval: Dict[int, Dict[int, Dict[str, int]]] = {}
        for stat in statistics:
            songid = stat.get("song")
            songchart = stat.get("chart")

            if songid is None or songchart is None:
                continue
            songid = int(songid)
            songchart = int(songchart)

            if songid not in retval:
                retval[songid] = {}
            if songchart not in retval[songid]:
                retval[songid][songchart] = {
                    "plays": 0,
                    "clears": 0,
                    "combos": 0,
                }

            def get_val(v: str) -> int:
                out = stat.get(v, -1)
                if out < 0:
                    out = 0
                return out

            retval[songid][songchart]["plays"] += get_val("plays")
            retval[songid][songchart]["clears"] += get_val("clears")
            retval[songid][songchart]["combos"] += get_val("combos")

        return retval

    def __format_danevo_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.DANCE_EVOLUTION,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "level": int(data["level"]),
                "kcal": float(data["kcal"]),
            },
        )

    def __format_ddr_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.DDR,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "groove": {
                    "air": int(data["groove"]["air"]),
                    "chaos": int(data["groove"]["chaos"]),
                    "freeze": int(data["groove"]["freeze"]),
                    "stream": int(data["groove"]["stream"]),
                    "voltage": int(data["groove"]["voltage"]),
                },
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "category": int(data["category"]),
                "difficulty": int(data["difficulty"]),
                "edit_id": int(data["editid"]),
            },
        )

    def __format_iidx_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.IIDX,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "notecount": int(data["notecount"]),
                "difficulty": int(data["difficulty"]),
            },
        )

    def __format_jubeat_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        defaultcategory = {
            1: VersionConstants.JUBEAT,
            2: VersionConstants.JUBEAT_RIPPLES,
            3: VersionConstants.JUBEAT_KNIT,
            4: VersionConstants.JUBEAT_COPIOUS,
            5: VersionConstants.JUBEAT_SAUCER,
            6: VersionConstants.JUBEAT_PROP,
            7: VersionConstants.JUBEAT_QUBELL,
            8: VersionConstants.JUBEAT_CLAN,
            9: VersionConstants.JUBEAT_FESTO,
        }.get(int(songid / 10000000), VersionConstants.JUBEAT)
        # Map the category to the version numbers defined on BEMAPI.
        categorymapping = {
            "1": VersionConstants.JUBEAT,
            "2": VersionConstants.JUBEAT_RIPPLES,
            "2a": VersionConstants.JUBEAT_RIPPLES_APPEND,
            "3": VersionConstants.JUBEAT_KNIT,
            "3a": VersionConstants.JUBEAT_KNIT_APPEND,
            "4": VersionConstants.JUBEAT_COPIOUS,
            "4a": VersionConstants.JUBEAT_COPIOUS_APPEND,
            "5": VersionConstants.JUBEAT_SAUCER,
            "5a": VersionConstants.JUBEAT_SAUCER_FULFILL,
            "6": VersionConstants.JUBEAT_PROP,
            "7": VersionConstants.JUBEAT_QUBELL,
            "8": VersionConstants.JUBEAT_CLAN,
            "9": VersionConstants.JUBEAT_FESTO,
        }
        return Song(
            game=GameConstants.JUBEAT,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "difficulty": int(data["difficulty"]),
                "version": categorymapping.get(data.get("category", "0"), defaultcategory),
            },
        )

    def __format_museca_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.MUSECA,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "limited": int(data["limited"]),
                "difficulty": int(data["difficulty"]),
            },
        )

    def __format_popn_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.POPN_MUSIC,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "difficulty": int(data["difficulty"]),
                "category": str(data["category"]),
            },
        )

    def __format_reflec_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.REFLEC_BEAT,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "difficulty": int(data["difficulty"]),
                "folder": int(data["category"]),
                "chart_id": str(data["musicid"]),
            },
        )

    def __format_sdvx_song(
        self,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Song:
        return Song(
            game=GameConstants.SDVX,
            version=version,
            songid=songid,
            songchart=songchart,
            name=name,
            artist=artist,
            genre=genre,
            data={
                "bpm_min": int(data["bpm_min"]),
                "bpm_max": int(data["bpm_max"]),
                "limited": int(data["limited"]),
                "difficulty": int(data["difficulty"]),
            },
        )

    def __format_song(
        self,
        game: GameConstants,
        version: int,
        songid: int,
        songchart: int,
        name: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        data: Dict[str, Any],
    ) -> Optional[Song]:
        if game == GameConstants.DDR:
            return self.__format_ddr_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.IIDX:
            return self.__format_iidx_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.JUBEAT:
            return self.__format_jubeat_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.MUSECA:
            return self.__format_museca_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.POPN_MUSIC:
            return self.__format_popn_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.REFLEC_BEAT:
            return self.__format_reflec_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.SDVX:
            return self.__format_sdvx_song(version, songid, songchart, name, artist, genre, data)
        if game == GameConstants.DANCE_EVOLUTION:
            return self.__format_danevo_song(version, songid, songchart, name, artist, genre, data)
        return None

    def get_all_songs(
        self,
        game: GameConstants,
        version: Optional[int] = None,
    ) -> List[Song]:
        """
        Given a game and a version, look up all song/chart combos associated with that game.

        Parameters:
            game - Enum value representing a game series.
            version - Integer representing which version of the game.

        Returns:
            A list of Song objects detailing the song information for each song.
        """
        if version is None:
            # We could do a ton of work to support this by iterating over all versions
            # and combining, but this isn't going to be used in that manner, so lets
            # skip that for now.
            return []

        catalogs: List[Dict[str, List[Dict[str, Any]]]] = Parallel.call(
            [client.get_catalog for client in self.clients], game, version
        )
        retval: List[Song] = []
        seen: Set[str] = set()
        for catalog in catalogs:
            for entry in catalog.get("songs", []):
                song = self.__format_song(
                    game,
                    version,
                    int(entry["song"]),
                    int(entry["chart"]),
                    str(entry["title"] if entry["title"] is not None else "") or None,
                    str(entry["artist"] if entry["artist"] is not None else "") or None,
                    str(entry["genre"] if entry["genre"] is not None else "") or None,
                    entry,
                )
                if song is None:
                    continue

                key = f"{song.id}_{song.chart}"
                if key in seen:
                    continue

                retval.append(song)
                seen.add(key)
        return retval
