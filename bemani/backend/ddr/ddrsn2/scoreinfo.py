from ctypes import *

from bemani.backend.ddr.ddrsn2.scorerecord import ScoreRecordStruct, ScoreRecord
from bemani.data import Score


class ScoreInfoStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("records", ScoreRecordStruct * 200),
    ]


class ScoreInfo:
    @staticmethod
    def create(scores: list[Score], part: int) -> ScoreInfoStruct:
        info = ScoreInfoStruct()

        scores_by_song_id: dict[int, dict[int, Score]] = {}

        for score in scores:
            if score.id not in scores_by_song_id:
                scores_by_song_id[score.id] = {}

            scores_by_song_id[score.id][score.chart] = score

        for i in range(len(info.records)):
            if part == 2:
                song_id = i + 200
            else:
                song_id = i

            if song_id in scores_by_song_id:
                score_record = ScoreRecord.create(scores_by_song_id[song_id])
            else:
                score_record = ScoreRecord.create(None)

            info.records[i] = score_record

        return info
