# vim: set fileencoding=utf-8
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.data import UserID
from bemani.backend.jubeat.base import JubeatBase


class JubeatCourse(JubeatBase):
    COURSE_RATING_FAILED: Final[int] = 100
    COURSE_RATING_BRONZE: Final[int] = 200
    COURSE_RATING_SILVER: Final[int] = 300
    COURSE_RATING_GOLD: Final[int] = 400

    COURSE_REQUIREMENT_SCORE: Final[int] = 100
    COURSE_REQUIREMENT_FULL_COMBO: Final[int] = 200
    COURSE_REQUIREMENT_PERFECT_PERCENT: Final[int] = 300

    def get_all_courses(self) -> List[Dict[str, Any]]:
        # List of base courses for Saucer Fulfill+ from BemaniWiki
        return [
            {
                "id": 1,
                "name": "溢れ出した記憶、特別なあなたにありがとう。",
                "level": 1,
                "music": [
                    (50000241, 2),
                    (10000052, 2),
                    (30000042, 2),
                    (50000085, 2),
                    (50000144, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [850000, 900000, 950000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [0, 1, 2],
                },
            },
            {
                "id": 2,
                "name": "コースモードが怖い？ばっかお前TAGがついてるだろ",
                "level": 1,
                "music": [
                    (50000121, 1),
                    (30000122, 1),
                    (40000159, 1),
                    (50000089, 1),
                    (40000051, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [800000, 850000, 900000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [0, 1, 2],
                },
            },
            {
                "id": 3,
                "name": "満月の鐘踊り響くは虚空から成る恋の歌",
                "level": 2,
                "music": [
                    (40000121, 2),
                    (50000188, 2),
                    (30000047, 2),
                    (50000237, 2),
                    (50000176, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [850000, 900000, 950000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 3],
                },
            },
            {
                "id": 4,
                "name": "スミスゼミナール 夏の陣開講記念 基本編",
                "level": 2,
                "music": [
                    (50000267, 1),
                    (50000233, 1),
                    (50000228, 1),
                    (50000268, 1),
                    (50000291, 1),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 3],
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [85, 90, 95],
                },
            },
            {
                "id": 5,
                "name": "HARDモードじゃないから、絶対、大丈夫だよっ！",
                "level": 2,
                "music": [
                    (50000144, 2),
                    (50000188, 2),
                    (50000070, 2),
                    (50000151, 2),
                    (50000152, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [850000, 900000, 950000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [0, 1, 2],
                },
            },
            {
                "id": 6,
                "name": "星明かりの下、愛という名の日替わりランチを君と",
                "level": 3,
                "music": [
                    (50000196, 1),
                    (50000151, 2),
                    (50000060, 1),
                    (40000048, 2),
                    (10000051, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [70, 80, 90],
                },
            },
            {
                "id": 7,
                "name": "輝く北極星と幸せなヒーロー",
                "level": 4,
                "music": [
                    (50000079, 2),
                    (20000044, 2),
                    (50000109, 2),
                    (10000043, 2),
                    (10000042, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 3],
                },
            },
            {
                "id": 8,
                "name": "花-鳥-藻-夏",
                "level": 4,
                "music": [
                    (10000068, 2),
                    (40000154, 2),
                    (50000123, 1),
                    (40000051, 2),
                    (30000045, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [70, 80, 90],
                },
            },
            {
                "id": 9,
                "name": "TAG生誕祭2014 俺の記録を抜いてみろ！",
                "level": 4,
                "music": [
                    (30000122, 2),
                    (50000086, 2),
                    (50000121, 2),
                    (50000196, 2),
                    (40000051, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 967252],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [0, 0, 1],
                },
            },
            {
                "id": 10,
                "name": "さよなら、亡くした恋と蝶の舞うヒストリア",
                "level": 5,
                "music": [
                    (20000041, 2),
                    (30000044, 2),
                    (50000037, 2),
                    (20000124, 2),
                    (50000033, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [80, 85, 90],
                },
            },
            {
                "id": 11,
                "name": "きらきらほしふるまぼろしなぎさちゃん",
                "level": 5,
                "music": [
                    (30000050, 2),
                    (30000049, 2),
                    (50000235, 2),
                    (50000157, 2),
                    (50000038, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [700000, 800000, 900000],
                },
            },
            {
                "id": 12,
                "name": "The Memorial Third: 僕みたいに演奏してね",
                "level": 5,
                "music": [
                    (10000037, 2),
                    (20000048, 1),
                    (50000253, 1),
                    (20000121, 2),
                    (50000133, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [75, 80, 85],
                },
            },
            {
                "id": 13,
                "name": "Enjoy! 4thKAC ~ Memories of saucer ~",
                "level": 5,
                "music": [
                    (50000206, 1),
                    (50000023, 1),
                    (50000078, 1),
                    (50000203, 1),
                    (50000323, 1),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 4],
                },
            },
            {
                "id": 14,
                "name": "風に吹かれるキケンなシロクマダンス",
                "level": 6,
                "music": [
                    (50000059, 2),
                    (50000197, 2),
                    (30000037, 2),
                    (50000182, 2),
                    (20000038, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [1, 2, 3],
                },
            },
            {
                "id": 15,
                "name": "君主は視線で友との愛を語るめう",
                "level": 6,
                "music": [
                    (40000052, 2),
                    (50000152, 2),
                    (50000090, 2),
                    (20000040, 2),
                    (50000184, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [85, 90, 95],
                },
            },
            {
                "id": 16,
                "name": "スミスゼミナール 夏の陣開講記念 応用編",
                "level": 6,
                "music": [
                    (50000233, 2),
                    (50000267, 2),
                    (50000268, 2),
                    (50000228, 2),
                    (50000291, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [750000, 850000, 900000],
                },
            },
            {
                "id": 17,
                "name": "天から降り注ぐ星はまるで甘いキャンディ",
                "level": 7,
                "music": [
                    (20000044, 2),
                    (30000050, 2),
                    (50000080, 2),
                    (40000126, 2),
                    (10000067, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [85, 90, 95],
                },
            },
            {
                "id": 18,
                "name": "てんとう虫が囁いている「Wow Wow…」",
                "level": 7,
                "music": [
                    (50000132, 2),
                    (40000128, 2),
                    (10000036, 2),
                    (50000119, 2),
                    (50000030, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [85, 90, 95],
                },
            },
            {
                "id": 19,
                "name": "HARDモードでも大丈夫だよ！絶対、大丈夫だよっ！",
                "level": 7,
                "music": [
                    (50000144, 2),
                    (50000070, 2),
                    (50000188, 2),
                    (50000151, 2),
                    (50000152, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [850000, 900000, 950000],
                },
            },
            {
                "id": 20,
                "name": "こんなHARDモード、滅べばいい…",
                "level": 7,
                "music": [
                    (50000294, 2),
                    (50000295, 2),
                    (50000234, 2),
                    (50000245, 2),
                    (50000282, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [850000, 900000, 950000],
                },
            },
            {
                "id": 21,
                "name": "Challenge! 4thKAC ~ Memories of saucer ~",
                "level": 7,
                "music": [
                    (50000206, 2),
                    (50000023, 2),
                    (50000078, 2),
                    (50000203, 2),
                    (50000323, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                },
            },
            {
                "id": 22,
                "name": "サヨナラ・キングコング ~ 恋のつぼみは愛の虹へ ~",
                "level": 8,
                "music": [
                    (50000148, 2),
                    (50000101, 2),
                    (10000064, 2),
                    (50000171, 2),
                    (50000070, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [900000, 950000, 980000],
                },
            },
            {
                "id": 23,
                "name": "風に舞う白鳥の翼と花弁、さながら万華鏡のよう",
                "level": 8,
                "music": [
                    (30000036, 2),
                    (50000122, 2),
                    (10000062, 2),
                    (50000199, 2),
                    (40000153, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [90, 95, 98],
                },
            },
            {
                "id": 24,
                "name": "The 小さなおぼろガチョウ♪",
                "level": 8,
                "music": [
                    (50000049, 2),
                    (50000071, 2),
                    (10000041, 2),
                    (50000031, 2),
                    (40000129, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [970000, 980000, 990000],
                    self.COURSE_REQUIREMENT_FULL_COMBO: [2, 3, 4],
                },
            },
            {
                "id": 25,
                "name": "TAG生誕祭2014 俺の記録を抜いてみろ！~ HARD編 ~",
                "level": 8,
                "music": [
                    (50000089, 2),
                    (50000083, 2),
                    (50000210, 2),
                    (50000030, 2),
                    (40000159, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [800000, 900000, 931463],
                },
            },
            {
                "id": 26,
                "name": "凍る世界で見る鳳凰の火の花",
                "level": 9,
                "music": [
                    (30000043, 2),
                    (10000039, 2),
                    (20000048, 2),
                    (50000096, 2),
                    (20000038, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [920000, 950000, 980000],
                },
            },
            {
                "id": 27,
                "name": "真実の桜が乱れしとき、キルト纏いし君は修羅となる",
                "level": 9,
                "music": [
                    (50000113, 2),
                    (50000184, 2),
                    (50000177, 2),
                    (30000124, 2),
                    (50000078, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_PERFECT_PERCENT: [80, 85, 90],
                },
            },
            {
                "id": 28,
                "name": "THE FINAL01 ~ 雷光に月、乙女に花散る祝福を ~",
                "level": 10,
                "music": [
                    (10000038, 2),
                    (20000051, 2),
                    (30000048, 2),
                    (40000060, 2),
                    (50000023, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [920000, 950000, 980000],
                },
            },
            {
                "id": 29,
                "name": "The Memorial Third: assimilated all into Nature",
                "level": 10,
                "music": [
                    (50000135, 2),
                    (50000029, 2),
                    (40000047, 2),
                    (40000046, 2),
                    (50000253, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [920000, 950000, 980000],
                },
            },
            {
                "id": 30,
                "name": "4thKAC ~ Memories of saucer ~",
                "level": 10,
                "music": [
                    (50000206, 2),
                    (50000023, 2),
                    (50000078, 2),
                    (50000203, 2),
                    (50000323, 2),
                ],
                "requirements": {
                    self.COURSE_REQUIREMENT_SCORE: [920000, 950000, 980000],
                },
            },
        ]

    def save_course(
        self,
        userid: UserID,
        courseid: int,
        rating: int,
        scores: List[int],
    ) -> None:
        if len(scores) != 5:
            raise Exception("Invalid course scores list!")
        if rating not in [
            self.COURSE_RATING_FAILED,
            self.COURSE_RATING_BRONZE,
            self.COURSE_RATING_SILVER,
            self.COURSE_RATING_GOLD,
        ]:
            raise Exception("Invalid course rating!")

        # Figure out if we should update the rating/scores or not
        oldcourse = self.data.local.game.get_achievement(
            self.game,
            userid,
            courseid,
            "course",
        )

        if oldcourse is not None:
            # Update the rating if the user did better
            rating = max(rating, oldcourse.get_int("rating"))

            # Update the scores if the total score was better
            if sum(scores) < sum(oldcourse.get_int_array("scores", 5)):
                scores = oldcourse.get_int_array("scores", 5)

        # Save it as an achievement
        self.data.local.game.put_achievement(
            self.game,
            userid,
            courseid,
            "course",
            {
                "rating": rating,
                "scores": scores,
            },
        )

    def get_courses(
        self,
        userid: UserID,
    ) -> Dict[int, Dict[str, Any]]:
        courses = {}
        achievements = self.data.local.game.get_achievements(self.game, userid)
        for achievement in achievements:
            if achievement.type == "course":
                courses[achievement.id] = {
                    "rating": achievement.data.get_int("rating"),
                    "scores": achievement.data.get_int_array("scores", 5),
                }
        return courses
