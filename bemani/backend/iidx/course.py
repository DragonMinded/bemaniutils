# vim: set fileencoding=utf-8
from typing import Tuple
from typing_extensions import Final

from bemani.backend.iidx.base import IIDXBase
from bemani.common import ValidatedDict
from bemani.data import UserID


class IIDXCourse(IIDXBase):
    COURSE_TYPE_SECRET: Final[str] = "secret_course"
    COURSE_TYPE_INTERNET_RANKING: Final[str] = "ir_course"
    COURSE_TYPE_CLASSIC: Final[str] = "classic_course"

    def id_and_chart_from_courseid(self, courseid: int) -> Tuple[int, int]:
        return (int(courseid / 6), courseid % 6)

    def update_course(
        self,
        userid: UserID,
        coursetype: str,
        courseid: int,
        chart: int,
        clear_status: int,
        pgreats: int,
        greats: int,
    ) -> None:
        # Range check course type
        if coursetype not in [
            self.COURSE_TYPE_SECRET,
            self.COURSE_TYPE_INTERNET_RANKING,
            self.COURSE_TYPE_CLASSIC,
        ]:
            raise Exception(f"Invalid course type value {coursetype}")

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

        # Update achievement to track course statistics
        course_score = self.data.local.user.get_achievement(
            self.game,
            self.version,
            userid,
            courseid * 6 + chart,
            coursetype,
        )
        if course_score is None:
            course_score = ValidatedDict()
        course_score.replace_int("clear_status", max(clear_status, course_score.get_int("clear_status")))
        old_ex_score = (course_score.get_int("pgnum") * 2) + course_score.get_int("gnum")
        if old_ex_score < ((pgreats * 2) + greats):
            course_score.replace_int("pgnum", pgreats)
            course_score.replace_int("gnum", greats)

        self.data.local.user.put_achievement(
            self.game,
            self.version,
            userid,
            courseid * 6 + chart,
            coursetype,
            course_score,
        )
