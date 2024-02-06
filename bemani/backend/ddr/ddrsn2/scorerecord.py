import math

from ctypes import *
from typing import Optional

from bemani.common import DBConstants
from bemani.data import Score


class ScoreRankRecordStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("lo_score", c_int8),
        ("score", c_int16),
        ("rank", c_int8, 5),
        ("unk1", c_int8, 1),
        ("yfc", c_int8, 1),
        ("ofc", c_int8, 1),
    ]


class ScoreRecordStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("beginner", ScoreRankRecordStruct),
        ("basic", ScoreRankRecordStruct),
        ("difficult", ScoreRankRecordStruct),
        ("expert", ScoreRankRecordStruct),
        ("challenge", ScoreRankRecordStruct),
        ("double_basic", ScoreRankRecordStruct),
        ("double_difficult", ScoreRankRecordStruct),
        ("double_expert", ScoreRankRecordStruct),
        ("double_challenge", ScoreRankRecordStruct),
    ]


GAME_RANK_AAA = 0
GAME_RANK_AA = 4
GAME_RANK_A = 8
GAME_RANK_B = 13
GAME_RANK_C = 16
GAME_RANK_D = 20
GAME_RANK_E = 24
GAME_RANK_NONE = 0xFF


class ScoreRecord:
    @staticmethod
    def blank() -> ScoreRecordStruct:
        record = ScoreRecordStruct()

        record.beginner.rank = GAME_RANK_NONE
        record.basic.rank = GAME_RANK_NONE
        record.difficult.rank = GAME_RANK_NONE
        record.expert.rank = GAME_RANK_NONE
        record.challenge.rank = GAME_RANK_NONE

        record.double_basic.rank = GAME_RANK_NONE
        record.double_difficult.rank = GAME_RANK_NONE
        record.double_expert.rank = GAME_RANK_NONE
        record.double_challenge.rank = GAME_RANK_NONE

        return record

    @staticmethod
    def create(scores: Optional[dict[int, Score]]) -> ScoreRecordStruct:
        record = ScoreRecord.blank()

        if scores is not None:
            for chart in scores:
                if chart == 0:
                    chart_rec = record.beginner
                elif chart == 1:
                    chart_rec = record.basic
                elif chart == 2:
                    chart_rec = record.difficult
                elif chart == 3:
                    chart_rec = record.expert
                else:
                    chart_rec = record.challenge

                score = scores[chart]

                formatted_score = math.floor(score.points / 10)
                hi_score = formatted_score >> 8

                lo_score = formatted_score ^ (hi_score << 8)

                chart_rec.lo_score = lo_score
                chart_rec.score = hi_score

                rank = score.data.get_int("rank")
                if rank == DBConstants.DDR_RANK_AAA:
                    chart_rec.rank = GAME_RANK_AAA
                elif rank == DBConstants.DDR_RANK_AA:
                    chart_rec.rank = GAME_RANK_AA
                elif rank == DBConstants.DDR_RANK_A:
                    chart_rec.rank = GAME_RANK_A
                elif rank == DBConstants.DDR_RANK_B:
                    chart_rec.rank = GAME_RANK_B
                elif rank == DBConstants.DDR_RANK_C:
                    chart_rec.rank = GAME_RANK_C
                elif rank == DBConstants.DDR_RANK_D:
                    chart_rec.rank = GAME_RANK_D
                else:
                    chart_rec.rank = GAME_RANK_E

                halo = score.data.get_int("halo")
                if halo == DBConstants.DDR_HALO_PERFECT_FULL_COMBO:
                    chart_rec.yfc = 1
                    chart_rec.ofc = 1
                elif halo == DBConstants.DDR_HALO_GREAT_FULL_COMBO:
                    chart_rec.yfc = 1

        return record
