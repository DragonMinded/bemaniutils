from typing import List, Dict, Tuple, Any

from bemani.api.exceptions import APIException
from bemani.api.objects.base import BaseObject
from bemani.common import APIConstants, DBConstants, GameConstants
from bemani.data import Attempt, UserID


class StatisticsObject(BaseObject):
    def __format_statistics(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "cards": [],
            "song": str(stats["id"]),
            "chart": str(stats["chart"]),
            "plays": stats.get("plays", -1),
            "clears": stats.get("clears", -1),
            "combos": stats.get("combos", -1),
        }

    def __format_user_statistics(self, cardids: List[str], stats: Dict[str, Any]) -> Dict[str, Any]:
        base = self.__format_statistics(stats)
        base["cards"] = cardids
        return base

    @property
    def music_version(self) -> int:
        if self.game in {
            GameConstants.IIDX,
            GameConstants.MUSECA,
            GameConstants.JUBEAT,
            GameConstants.POPN_MUSIC,
        }:
            if self.omnimix:
                return self.version + DBConstants.OMNIMIX_VERSION_BUMP
            else:
                return self.version
        else:
            return self.version

    def __is_play(self, attempt: Attempt) -> bool:
        if self.game in {
            GameConstants.DDR,
            GameConstants.JUBEAT,
            GameConstants.MUSECA,
            GameConstants.POPN_MUSIC,
        }:
            return True
        if self.game == GameConstants.IIDX:
            return attempt.data.get_int("clear_status") != DBConstants.IIDX_CLEAR_STATUS_NO_PLAY
        if self.game == GameConstants.REFLEC_BEAT:
            return attempt.data.get_int("clear_type") != DBConstants.REFLEC_BEAT_CLEAR_TYPE_NO_PLAY
        if self.game == GameConstants.SDVX:
            return attempt.data.get_int("clear_type") != DBConstants.SDVX_CLEAR_TYPE_NO_PLAY

        return False

    def __is_clear(self, attempt: Attempt) -> bool:
        if not self.__is_play(attempt):
            return False

        if self.game == GameConstants.DDR:
            return attempt.data.get_int("rank") != DBConstants.DDR_RANK_E
        if self.game == GameConstants.IIDX:
            return attempt.data.get_int("clear_status") != DBConstants.IIDX_CLEAR_STATUS_FAILED
        if self.game == GameConstants.JUBEAT:
            return attempt.data.get_int("medal") != DBConstants.JUBEAT_PLAY_MEDAL_FAILED
        if self.game == GameConstants.MUSECA:
            return attempt.data.get_int("clear_type") != DBConstants.MUSECA_CLEAR_TYPE_FAILED
        if self.game == GameConstants.POPN_MUSIC:
            return attempt.data.get_int("medal") not in [
                DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED,
                DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FAILED,
                DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FAILED,
            ]
        if self.game == GameConstants.REFLEC_BEAT:
            return attempt.data.get_int("clear_type") != DBConstants.REFLEC_BEAT_CLEAR_TYPE_FAILED
        if self.game == GameConstants.SDVX:
            return attempt.data.get_int("grade") != DBConstants.SDVX_GRADE_NO_PLAY and attempt.data.get_int(
                "clear_type"
            ) not in [
                DBConstants.SDVX_CLEAR_TYPE_NO_PLAY,
                DBConstants.SDVX_CLEAR_TYPE_FAILED,
            ]

        return False

    def __is_combo(self, attempt: Attempt) -> bool:
        if not self.__is_play(attempt):
            return False

        if self.game == GameConstants.DDR:
            return attempt.data.get_int("halo") != DBConstants.DDR_HALO_NONE
        if self.game == GameConstants.IIDX:
            return attempt.data.get_int("clear_status") == DBConstants.IIDX_CLEAR_STATUS_FULL_COMBO
        if self.game == GameConstants.JUBEAT:
            return attempt.data.get_int("medal") in [
                DBConstants.JUBEAT_PLAY_MEDAL_FULL_COMBO,
                DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_EXCELLENT,
                DBConstants.JUBEAT_PLAY_MEDAL_EXCELLENT,
            ]
        if self.game == GameConstants.MUSECA:
            return attempt.data.get_int("clear_type") == DBConstants.MUSECA_CLEAR_TYPE_FULL_COMBO
        if self.game == GameConstants.POPN_MUSIC:
            return attempt.data.get_int("medal") in [
                DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FULL_COMBO,
                DBConstants.POPN_MUSIC_PLAY_MEDAL_PERFECT,
            ]
        if self.game == GameConstants.REFLEC_BEAT:
            return attempt.data.get_int("combo_type") in [
                DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO,
                DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO_ALL_JUST,
            ]
        if self.game == GameConstants.SDVX:
            return attempt.data.get_int("clear_type") in [
                DBConstants.SDVX_CLEAR_TYPE_ULTIMATE_CHAIN,
                DBConstants.SDVX_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
            ]

        return False

    def __aggregate_global(self, attempts: List[Attempt]) -> List[Dict[str, Any]]:
        stats: Dict[int, Dict[int, Dict[str, int]]] = {}

        for attempt in attempts:
            if attempt.id not in stats:
                stats[attempt.id] = {}
            if attempt.chart not in stats[attempt.id]:
                stats[attempt.id][attempt.chart] = {
                    "plays": 0,
                    "clears": 0,
                    "combos": 0,
                }

            if self.__is_play(attempt):
                stats[attempt.id][attempt.chart]["plays"] += 1
            if self.__is_clear(attempt):
                stats[attempt.id][attempt.chart]["clears"] += 1
            if self.__is_combo(attempt):
                stats[attempt.id][attempt.chart]["combos"] += 1

        retval = []
        for songid in stats:
            for songchart in stats[songid]:
                stat = stats[songid][songchart]
                stat["id"] = songid
                stat["chart"] = songchart
                retval.append(self.__format_statistics(stat))

        return retval

    def __aggregate_local(
        self, cards: Dict[int, List[str]], attempts: List[Tuple[UserID, Attempt]]
    ) -> List[Dict[str, Any]]:
        stats: Dict[UserID, Dict[int, Dict[int, Dict[str, int]]]] = {}

        for userid, attempt in attempts:
            if userid not in stats:
                stats[userid] = {}
            if attempt.id not in stats[userid]:
                stats[userid][attempt.id] = {}
            if attempt.chart not in stats[userid][attempt.id]:
                stats[userid][attempt.id][attempt.chart] = {
                    "plays": 0,
                    "clears": 0,
                    "combos": 0,
                }

            if self.__is_play(attempt):
                stats[userid][attempt.id][attempt.chart]["plays"] += 1
            if self.__is_clear(attempt):
                stats[userid][attempt.id][attempt.chart]["clears"] += 1
            if self.__is_combo(attempt):
                stats[userid][attempt.id][attempt.chart]["combos"] += 1

        retval = []
        for userid in stats:
            for songid in stats[userid]:
                for songchart in stats[userid][songid]:
                    stat = stats[userid][songid][songchart]
                    stat["id"] = songid
                    stat["chart"] = songchart
                    retval.append(self.__format_user_statistics(cards[userid], stat))

        return retval

    def fetch_v1(self, idtype: APIConstants, ids: List[str], params: Dict[str, Any]) -> List[Dict[str, Any]]:
        retval: List[Dict[str, Any]] = []

        # Special case, Dance Evolution can't track attempts in any meaningful capacity
        # because the game does not actually send down information about the chart for
        # given attempts. So, we only know that players plays a song, not what chart or
        # whether they cleared it or full-combo'd it.
        if self.game == GameConstants.DANCE_EVOLUTION:
            return []

        # Fetch the attempts
        if idtype == APIConstants.ID_TYPE_SERVER:
            retval = self.__aggregate_global(
                [attempt[1] for attempt in self.data.local.music.get_all_attempts(self.game, self.music_version)]
            )
        elif idtype == APIConstants.ID_TYPE_SONG:
            if len(ids) == 1:
                songid = int(ids[0])
                chart = None
            else:
                songid = int(ids[0])
                chart = int(ids[1])
            retval = self.__aggregate_global(
                [
                    attempt[1]
                    for attempt in self.data.local.music.get_all_attempts(
                        self.game, self.music_version, songid=songid, songchart=chart
                    )
                ]
            )
        elif idtype == APIConstants.ID_TYPE_INSTANCE:
            songid = int(ids[0])
            chart = int(ids[1])
            cardid = ids[2]
            userid = self.data.local.user.from_cardid(cardid)
            if userid is not None:
                retval = self.__aggregate_local(
                    {userid: self.data.local.user.get_cards(userid)},
                    self.data.local.music.get_all_attempts(
                        self.game,
                        self.music_version,
                        songid=songid,
                        songchart=chart,
                        userid=userid,
                    ),
                )
        elif idtype == APIConstants.ID_TYPE_CARD:
            id_to_cards: Dict[int, List[str]] = {}
            attempts: List[Tuple[UserID, Attempt]] = []
            for cardid in ids:
                userid = self.data.local.user.from_cardid(cardid)
                if userid is not None:
                    # Don't duplicate loads for users with multiple card IDs if multiples
                    # of those IDs are requested.
                    if userid in id_to_cards:
                        continue

                    id_to_cards[userid] = self.data.local.user.get_cards(userid)
                    attempts.extend(
                        self.data.local.music.get_all_attempts(self.game, self.music_version, userid=userid)
                    )
            retval = self.__aggregate_local(id_to_cards, attempts)
        else:
            raise APIException("Invalid ID type!")

        return retval
