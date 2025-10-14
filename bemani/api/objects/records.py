from typing import Any, Dict, List, Set, Tuple

from bemani.api.exceptions import APIException
from bemani.api.objects.base import BaseObject
from bemani.common import GameConstants, VersionConstants, APIConstants, DBConstants
from bemani.data import Score, UserID


class RecordsObject(BaseObject):
    def __format_danevo_record(self, record: Score) -> Dict[str, Any]:
        grade = {
            DBConstants.DANEVO_GRADE_AAA: "AAA",
            DBConstants.DANEVO_GRADE_AA: "AA",
            DBConstants.DANEVO_GRADE_A: "A",
            DBConstants.DANEVO_GRADE_B: "B",
            DBConstants.DANEVO_GRADE_C: "C",
            DBConstants.DANEVO_GRADE_D: "D",
            DBConstants.DANEVO_GRADE_E: "E",
            DBConstants.DANEVO_GRADE_FAILED: "F",
        }.get(record.data.get_int("grade"), "F")

        return {
            "grade": grade,
            "combo": record.data.get_int("combo"),
            "full_combo": record.data.get_bool("full_combo"),
        }

    def __format_ddr_record(self, record: Score) -> Dict[str, Any]:
        halo = {
            DBConstants.DDR_HALO_NONE: "none",
            DBConstants.DDR_HALO_GOOD_FULL_COMBO: "gfc",
            DBConstants.DDR_HALO_GREAT_FULL_COMBO: "fc",
            DBConstants.DDR_HALO_PERFECT_FULL_COMBO: "pfc",
            DBConstants.DDR_HALO_MARVELOUS_FULL_COMBO: "mfc",
        }.get(record.data.get_int("halo"), "none")
        rank = {
            DBConstants.DDR_RANK_AAA: "AAA",
            DBConstants.DDR_RANK_AA_PLUS: "AA+",
            DBConstants.DDR_RANK_AA: "AA",
            DBConstants.DDR_RANK_AA_MINUS: "AA-",
            DBConstants.DDR_RANK_A_PLUS: "A+",
            DBConstants.DDR_RANK_A: "A",
            DBConstants.DDR_RANK_A_MINUS: "A-",
            DBConstants.DDR_RANK_B_PLUS: "B+",
            DBConstants.DDR_RANK_B: "B",
            DBConstants.DDR_RANK_B_MINUS: "B-",
            DBConstants.DDR_RANK_C_PLUS: "C+",
            DBConstants.DDR_RANK_C: "C",
            DBConstants.DDR_RANK_C_MINUS: "C-",
            DBConstants.DDR_RANK_D_PLUS: "D+",
            DBConstants.DDR_RANK_D: "D",
            DBConstants.DDR_RANK_E: "E",
        }.get(record.data.get_int("rank"), "E")

        if self.version == VersionConstants.DDR_ACE:
            # DDR Ace is specia
            ghost = [int(x) for x in record.data.get_str("ghost")]
        else:
            if "trace" not in record.data:
                ghost = []
            else:
                ghost = record.data.get_int_array("trace", len(record.data["trace"]))

        return {
            "rank": rank,
            "halo": halo,
            "combo": record.data.get_int("combo"),
            "ghost": ghost,
        }

    def __format_iidx_record(self, record: Score) -> Dict[str, Any]:
        status = {
            DBConstants.IIDX_CLEAR_STATUS_NO_PLAY: "np",
            DBConstants.IIDX_CLEAR_STATUS_FAILED: "failed",
            DBConstants.IIDX_CLEAR_STATUS_ASSIST_CLEAR: "ac",
            DBConstants.IIDX_CLEAR_STATUS_EASY_CLEAR: "ec",
            DBConstants.IIDX_CLEAR_STATUS_CLEAR: "nc",
            DBConstants.IIDX_CLEAR_STATUS_HARD_CLEAR: "hc",
            DBConstants.IIDX_CLEAR_STATUS_EX_HARD_CLEAR: "exhc",
            DBConstants.IIDX_CLEAR_STATUS_FULL_COMBO: "fc",
        }.get(record.data.get_int("clear_status"), "np")

        return {
            "status": status,
            "miss": record.data.get_int("miss_count", -1),
            "ghost": [b for b in record.data.get_bytes("ghost")],
            "pgreat": record.data.get_int("pgreats", -1),
            "great": record.data.get_int("greats", -1),
        }

    def __format_jubeat_record(self, record: Score) -> Dict[str, Any]:
        status = {
            DBConstants.JUBEAT_PLAY_MEDAL_FAILED: "failed",
            DBConstants.JUBEAT_PLAY_MEDAL_CLEARED: "cleared",
            DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_FULL_COMBO: "nfc",
            DBConstants.JUBEAT_PLAY_MEDAL_FULL_COMBO: "fc",
            DBConstants.JUBEAT_PLAY_MEDAL_NEARLY_EXCELLENT: "nec",
            DBConstants.JUBEAT_PLAY_MEDAL_EXCELLENT: "exc",
        }.get(record.data.get_int("medal"), "failed")
        if "ghost" not in record.data:
            ghost: List[int] = []
        else:
            ghost = record.data.get_int_array("ghost", len(record.data["ghost"]))

        return {
            "status": status,
            "combo": record.data.get_int("combo", -1),
            "ghost": ghost,
            "music_rate": record.data.get_int("music_rate"),
        }

    def __format_museca_record(self, record: Score) -> Dict[str, Any]:
        rank = {
            DBConstants.MUSECA_GRADE_DEATH: "death",
            DBConstants.MUSECA_GRADE_POOR: "poor",
            DBConstants.MUSECA_GRADE_MEDIOCRE: "mediocre",
            DBConstants.MUSECA_GRADE_GOOD: "good",
            DBConstants.MUSECA_GRADE_GREAT: "great",
            DBConstants.MUSECA_GRADE_EXCELLENT: "excellent",
            DBConstants.MUSECA_GRADE_SUPERB: "superb",
            DBConstants.MUSECA_GRADE_MASTERPIECE: "masterpiece",
            DBConstants.MUSECA_GRADE_PERFECT: "perfect",
        }.get(record.data.get_int("grade"), "death")
        status = {
            DBConstants.MUSECA_CLEAR_TYPE_FAILED: "failed",
            DBConstants.MUSECA_CLEAR_TYPE_CLEARED: "cleared",
            DBConstants.MUSECA_CLEAR_TYPE_FULL_COMBO: "fc",
        }.get(record.data.get_int("clear_type"), "failed")

        return {
            "rank": rank,
            "status": status,
            "combo": record.data.get_int("combo", -1),
            "buttonrate": record.data.get_dict("stats").get_int("btn_rate"),
            "longrate": record.data.get_dict("stats").get_int("long_rate"),
            "volrate": record.data.get_dict("stats").get_int("vol_rate"),
        }

    def __format_popn_record(self, record: Score) -> Dict[str, Any]:
        status = {
            DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FAILED: "cf",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FAILED: "df",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FAILED: "sf",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_EASY_CLEAR: "ec",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_CLEARED: "cc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_CLEARED: "dc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_CLEARED: "sc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_CIRCLE_FULL_COMBO: "cfc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_DIAMOND_FULL_COMBO: "dfc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_STAR_FULL_COMBO: "sfc",
            DBConstants.POPN_MUSIC_PLAY_MEDAL_PERFECT: "p",
        }.get(record.data.get_int("medal"), "cf")

        return {
            "status": status,
            "combo": record.data.get_int("combo", -1),
        }

    def __format_reflec_record(self, record: Score) -> Dict[str, Any]:
        status = {
            DBConstants.REFLEC_BEAT_CLEAR_TYPE_NO_PLAY: "np",
            DBConstants.REFLEC_BEAT_CLEAR_TYPE_FAILED: "failed",
            DBConstants.REFLEC_BEAT_CLEAR_TYPE_CLEARED: "cleared",
            DBConstants.REFLEC_BEAT_CLEAR_TYPE_HARD_CLEARED: "hc",
            DBConstants.REFLEC_BEAT_CLEAR_TYPE_S_HARD_CLEARED: "shc",
        }.get(record.data.get_int("clear_type"), "np")
        halo = {
            DBConstants.REFLEC_BEAT_COMBO_TYPE_NONE: "none",
            DBConstants.REFLEC_BEAT_COMBO_TYPE_ALMOST_COMBO: "ac",
            DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO: "fc",
            DBConstants.REFLEC_BEAT_COMBO_TYPE_FULL_COMBO_ALL_JUST: "fcaj",
        }.get(record.data.get_int("combo_type"), "none")

        return {
            "rate": record.data.get_int("achievement_rate"),
            "status": status,
            "halo": halo,
            "combo": record.data.get_int("combo", -1),
            "miss": record.data.get_int("miss_count", -1),
        }

    def __format_sdvx_record(self, record: Score) -> Dict[str, Any]:
        status = {
            DBConstants.SDVX_CLEAR_TYPE_NO_PLAY: "np",
            DBConstants.SDVX_CLEAR_TYPE_FAILED: "failed",
            DBConstants.SDVX_CLEAR_TYPE_CLEAR: "cleared",
            DBConstants.SDVX_CLEAR_TYPE_HARD_CLEAR: "hc",
            DBConstants.SDVX_CLEAR_TYPE_ULTIMATE_CHAIN: "uc",
            DBConstants.SDVX_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: "puc",
        }.get(record.data.get_int("clear_type"), "np")
        rank = {
            DBConstants.SDVX_GRADE_NO_PLAY: "E",
            DBConstants.SDVX_GRADE_D: "D",
            DBConstants.SDVX_GRADE_C: "C",
            DBConstants.SDVX_GRADE_B: "B",
            DBConstants.SDVX_GRADE_A: "A",
            DBConstants.SDVX_GRADE_A_PLUS: "A+",
            DBConstants.SDVX_GRADE_AA: "AA",
            DBConstants.SDVX_GRADE_AA_PLUS: "AA+",
            DBConstants.SDVX_GRADE_AAA: "AAA",
            DBConstants.SDVX_GRADE_AAA_PLUS: "AAA+",
            DBConstants.SDVX_GRADE_S: "S",
        }.get(record.data.get_int("grade"), "E")

        return {
            "status": status,
            "rank": rank,
            "combo": record.data.get_int("combo", -1),
            "buttonrate": record.data.get_dict("stats").get_int("btn_rate"),
            "longrate": record.data.get_dict("stats").get_int("long_rate"),
            "volrate": record.data.get_dict("stats").get_int("vol_rate"),
        }

    def __format_record(self, cardids: List[str], record: Score) -> Dict[str, Any]:
        base = {
            "cards": cardids,
            "song": str(record.id),
            "chart": str(record.chart),
            "points": record.points,
            "timestamp": record.timestamp,
            "updated": record.update,
        }

        if self.game == GameConstants.DDR:
            base.update(self.__format_ddr_record(record))
        if self.game == GameConstants.IIDX:
            base.update(self.__format_iidx_record(record))
        if self.game == GameConstants.JUBEAT:
            base.update(self.__format_jubeat_record(record))
        if self.game == GameConstants.MUSECA:
            base.update(self.__format_museca_record(record))
        if self.game == GameConstants.POPN_MUSIC:
            base.update(self.__format_popn_record(record))
        if self.game == GameConstants.REFLEC_BEAT:
            base.update(self.__format_reflec_record(record))
        if self.game == GameConstants.SDVX:
            base.update(self.__format_sdvx_record(record))
        if self.game == GameConstants.DANCE_EVOLUTION:
            base.update(self.__format_danevo_record(record))

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

    def fetch_v1(self, idtype: APIConstants, ids: List[str], params: Dict[str, Any]) -> List[Dict[str, Any]]:
        since = params.get("since")
        until = params.get("until")

        # Fetch the scores
        records: List[Tuple[UserID, Score]] = []
        if idtype == APIConstants.ID_TYPE_SERVER:
            # Because of the way this query works, we can't apply since/until to it directly.
            # If we did, it would miss higher scores earned before since or after until, and
            # incorrectly report records.
            records.extend(self.data.local.music.get_all_records(self.game, self.music_version))
        elif idtype == APIConstants.ID_TYPE_SONG:
            if len(ids) == 1:
                songid = int(ids[0])
                chart = None
            else:
                songid = int(ids[0])
                chart = int(ids[1])
            records.extend(
                self.data.local.music.get_all_scores(
                    self.game,
                    self.music_version,
                    songid=songid,
                    songchart=chart,
                    since=since,
                    until=until,
                )
            )
        elif idtype == APIConstants.ID_TYPE_INSTANCE:
            songid = int(ids[0])
            chart = int(ids[1])
            cardid = ids[2]
            userid = self.data.local.user.from_cardid(cardid)
            if userid is not None:
                score = self.data.local.music.get_score(self.game, self.music_version, userid, songid, chart)
                if score is not None:
                    records.append((userid, score))
        elif idtype == APIConstants.ID_TYPE_CARD:
            users: Set[UserID] = set()
            for cardid in ids:
                userid = self.data.local.user.from_cardid(cardid)
                if userid is not None:
                    # Don't duplicate loads for users with multiple card IDs if multiples
                    # of those IDs are requested.
                    if userid in users:
                        continue
                    users.add(userid)

                    records.extend(
                        [
                            (userid, score)
                            for score in self.data.local.music.get_scores(
                                self.game,
                                self.music_version,
                                userid,
                                since=since,
                                until=until,
                            )
                        ]
                    )
        else:
            raise APIException("Invalid ID type!")

        # Now, fetch the users, and filter out scores belonging to orphaned users
        id_to_cards: Dict[UserID, List[str]] = {}
        retval: List[Dict[str, Any]] = []
        for userid, record in records:
            # Postfilter for queries that can't filter. This will save on data transferred.
            if since is not None:
                if record.update < since:
                    continue
            if until is not None:
                if record.update >= until:
                    continue

            # Dance Evolution is a special case where it stores data in a virtual chart
            # to keep track of play counts, due to the game not sending chart back with
            # attempts.
            if self.game == GameConstants.DANCE_EVOLUTION:
                if record.chart not in [0, 1, 2, 3, 4]:
                    continue

            if userid not in id_to_cards:
                cards = self.data.local.user.get_cards(userid)
                if len(cards) == 0:
                    # Can't add this user, skip the score
                    continue

                id_to_cards[userid] = cards

            # Format the score and add it
            retval.append(self.__format_record(id_to_cards[userid], record))

        return retval
