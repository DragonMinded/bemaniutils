from typing import Dict, Optional, Tuple

from bemani.backend.ddr.base import DDRBase
from bemani.common import Profile, intish
from bemani.data import Score, UserID
from bemani.protocol import Node


class DDRGameShopHandler(DDRBase):
    def handle_game_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.attribute("name"))

        game = Node.void("game")
        game.set_attribute("stop", "0")
        return game


class DDRGameLogHandler(DDRBase):
    def handle_game_log_request(self, request: Node) -> Node:
        return Node.void("game")


class DDRGameMessageHandler(DDRBase):
    def handle_game_message_request(self, request: Node) -> Node:
        return Node.void("game")


class DDRGameRankingHandler(DDRBase):
    def handle_game_ranking_request(self, request: Node) -> Node:
        # Ranking request, unknown what its for
        return Node.void("game")


class DDRGameLockHandler(DDRBase):
    def handle_game_lock_request(self, request: Node) -> Node:
        game = Node.void("game")
        game.set_attribute("now_login", "0")
        return game


class DDRGameTaxInfoHandler(DDRBase):
    def handle_game_tax_info_request(self, request: Node) -> Node:
        game = Node.void("game")
        tax_info = Node.void("tax_info")
        game.add_child(tax_info)
        tax_info.set_attribute("tax_phase", "0")
        return game


class DDRGameRecorderHandler(DDRBase):
    def handle_game_recorder_request(self, request: Node) -> Node:
        return Node.void("game")


class DDRGameHiscoreHandler(DDRBase):
    def handle_game_hiscore_request(self, request: Node) -> Node:
        records = self.data.remote.music.get_all_records(self.game, self.music_version)

        sortedrecords: Dict[int, Dict[int, Tuple[UserID, Score]]] = {}
        missing_profiles = []
        for userid, score in records:
            if score.id not in sortedrecords:
                sortedrecords[score.id] = {}
            sortedrecords[score.id][score.chart] = (userid, score)
            missing_profiles.append(userid)
        users = {
            userid: profile
            for (userid, profile) in self.get_any_profiles(missing_profiles)
        }

        game = Node.void("game")
        for song in sortedrecords:
            music = Node.void("music")
            game.add_child(music)
            music.set_attribute("reclink_num", str(song))

            for chart in sortedrecords[song]:
                userid, score = sortedrecords[song][chart]
                try:
                    gamechart = self.db_to_game_chart(chart)
                except KeyError:
                    # Don't support this chart in this game
                    continue
                gamerank = self.db_to_game_rank(score.data.get_int("rank"))
                combo_type = self.db_to_game_halo(score.data.get_int("halo"))

                typenode = Node.void("type")
                music.add_child(typenode)
                typenode.set_attribute("diff", str(gamechart))

                typenode.add_child(Node.string("name", users[userid].get_str("name")))
                typenode.add_child(Node.u32("score", score.points))
                typenode.add_child(
                    Node.u16(
                        "area", users[userid].get_int("area", self.get_machine_region())
                    )
                )
                typenode.add_child(Node.u8("rank", gamerank))
                typenode.add_child(Node.u8("combo_type", combo_type))
                typenode.add_child(Node.u32("code", users[userid].extid))

        return game


class DDRGameAreaHiscoreHandler(DDRBase):
    def handle_game_area_hiscore_request(self, request: Node) -> Node:
        shop_area = int(request.attribute("shop_area"))

        # First, get all users that are in the current shop's area
        area_users = {
            uid: prof
            for (uid, prof) in self.data.local.user.get_all_profiles(
                self.game, self.version
            )
            if prof.get_int("area", self.get_machine_region()) == shop_area
        }

        # Second, look up records belonging only to those users
        records = self.data.local.music.get_all_records(
            self.game, self.music_version, userlist=list(area_users.keys())
        )

        # Now, do the same lazy thing as 'hiscore' because I don't want
        # to think about how to change this knowing that we only pulled
        # up area records.
        area_records: Dict[int, Dict[int, Tuple[UserID, Score]]] = {}
        for userid, score in records:
            if score.id not in area_records:
                area_records[score.id] = {}
            area_records[score.id][score.chart] = (userid, score)

        game = Node.void("game")
        for song in area_records:
            music = Node.void("music")
            game.add_child(music)
            music.set_attribute("reclink_num", str(song))

            for chart in area_records[song]:
                userid, score = area_records[song][chart]
                if (
                    area_users[userid].get_int("area", self.get_machine_region())
                    != shop_area
                ):
                    # Don't return this, this user isn't in this area
                    continue
                try:
                    gamechart = self.db_to_game_chart(chart)
                except KeyError:
                    # Don't support this chart in this game
                    continue
                gamerank = self.db_to_game_rank(score.data.get_int("rank"))
                combo_type = self.db_to_game_halo(score.data.get_int("halo"))

                typenode = Node.void("type")
                music.add_child(typenode)
                typenode.set_attribute("diff", str(gamechart))

                typenode.add_child(
                    Node.string("name", area_users[userid].get_str("name"))
                )
                typenode.add_child(Node.u32("score", score.points))
                typenode.add_child(
                    Node.u16(
                        "area",
                        area_users[userid].get_int("area", self.get_machine_region()),
                    )
                )
                typenode.add_child(Node.u8("rank", gamerank))
                typenode.add_child(Node.u8("combo_type", combo_type))
                typenode.add_child(Node.u32("code", area_users[userid].extid))

        return game


class DDRGameScoreHandler(DDRBase):
    def handle_game_score_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        songid = int(request.attribute("mid"))
        chart = self.game_to_db_chart(int(request.attribute("type")))

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            attempts = self.data.local.music.get_all_attempts(
                self.game,
                self.music_version,
                userid,
                songid=songid,
                songchart=chart,
                limit=5,
            )
            recentscores = [attempt.points for (_, attempt) in attempts]
        else:
            recentscores = []

        # Always pad to five, so we ensure that we return all the scores
        while len(recentscores) < 5:
            recentscores.append(0)

        # Return the most recent five scores
        game = Node.void("game")
        for i in range(len(recentscores)):
            game.set_attribute(f"sc{i + 1}", str(recentscores[i]))
        return game


class DDRGameTraceHandler(DDRBase):
    def handle_game_trace_request(self, request: Node) -> Node:
        extid = int(request.attribute("code"))
        chart = int(request.attribute("type"))
        cid = intish(request.attribute("cid"))
        mid = intish(request.attribute("mid"))

        # Base packet is just game, if we find something we add to it
        game = Node.void("game")

        # Rival trace loading
        userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is None:
            # Nothing to load
            return game

        if mid is not None:
            # Load trace from song score
            songscore = self.data.remote.music.get_score(
                self.game,
                self.music_version,
                userid,
                mid,
                self.game_to_db_chart(chart),
            )
            if songscore is not None and "trace" in songscore.data:
                game.add_child(Node.u32("size", len(songscore.data["trace"])))
                game.add_child(Node.u8_array("trace", songscore.data["trace"]))

        elif cid is not None:
            # Load trace from achievement
            coursescore = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                (cid * 4) + chart,
                "course",
            )
            if coursescore is not None and "trace" in coursescore:
                game.add_child(Node.u32("size", len(coursescore["trace"])))
                game.add_child(Node.u8_array("trace", coursescore["trace"]))

        # Nothing found, return empty
        return game


class DDRGameLoadHandler(DDRBase):
    def handle_game_load_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        profile = self.get_profile_by_refid(refid)
        if profile is not None:
            return profile

        game = Node.void("game")
        game.set_attribute("none", "0")
        return game


class DDRGameLoadDailyHandler(DDRBase):
    def handle_game_load_daily_request(self, request: Node) -> Node:
        extid = intish(request.attribute("code"))
        refid = request.attribute("refid")
        game = Node.void("game")
        profiledict = None

        if extid is not None:
            # Rival daily loading
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        else:
            # Self daily loading
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profiledict = self.get_profile(userid)

        if profiledict is not None:
            play_stats = self.get_play_statistics(userid)

            # Day play counts
            daycount = Node.void("daycount")
            game.add_child(daycount)
            daycount.set_attribute("playcount", str(play_stats.today_plays))

            # Daily combo stuff, unclear how this works
            dailycombo = Node.void("dailycombo")
            game.add_child(dailycombo)
            dailycombo.set_attribute("daily_combo", str(0))
            dailycombo.set_attribute("daily_combo_lv", str(0))

        return game


class DDRGameOldHandler(DDRBase):
    def handle_game_old_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        game = Node.void("game")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        previous_version: Optional[DDRBase] = None
        oldprofile: Optional[Profile] = None

        if userid is not None:
            previous_version = self.previous_version()
        if previous_version is not None:
            oldprofile = previous_version.get_profile(userid)
        if oldprofile is not None:
            game.set_attribute("name", oldprofile.get_str("name"))
            game.set_attribute(
                "area", str(oldprofile.get_int("area", self.get_machine_region()))
            )
        return game


class DDRGameNewHandler(DDRBase):
    def handle_game_new_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        area = int(request.attribute("area"))
        name = request.attribute("name").strip()

        # Create a new profile for this user!
        self.new_profile_by_refid(refid, name, area)

        # No response needed
        game = Node.void("game")
        return game


class DDRGameSaveHandler(DDRBase):
    def handle_game_save_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        self.put_profile_by_refid(refid, request)

        # No response needed
        game = Node.void("game")
        return game


class DDRGameFriendHandler(DDRBase):
    def handle_game_friend_request(self, request: Node) -> Node:
        extid = intish(request.attribute("code"))
        userid = None
        friend = None

        if extid is not None:
            # Rival score loading
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        if userid is not None:
            friend = self.get_profile(userid)
            play_stats = self.get_play_statistics(userid)

        if friend is None:
            # Return an empty node to tell the game we don't have a player here
            game = Node.void("game")
            return game

        game = Node.void("game")
        game.set_attribute("data", "1")
        game.add_child(Node.u32("code", friend.extid))
        game.add_child(Node.string("name", friend.get_str("name")))
        game.add_child(
            Node.u8("area", friend.get_int("area", self.get_machine_region()))
        )
        game.add_child(Node.u32("exp", play_stats.get_int("exp")))
        game.add_child(Node.u32("star", friend.get_int("star")))

        # Drill rankings
        if "title" in friend:
            title = Node.void("title")
            game.add_child(title)
            titledict = friend.get_dict("title")
            if "t" in titledict:
                title.set_attribute("t", str(titledict.get_int("t")))
            if "s" in titledict:
                title.set_attribute("s", str(titledict.get_int("s")))
            if "d" in titledict:
                title.set_attribute("d", str(titledict.get_int("d")))

        if "title_gr" in friend:
            title_gr = Node.void("title_gr")
            game.add_child(title_gr)
            title_grdict = friend.get_dict("title_gr")
            if "t" in title_grdict:
                title_gr.set_attribute("t", str(title_grdict.get_int("t")))
            if "s" in title_grdict:
                title_gr.set_attribute("s", str(title_grdict.get_int("s")))
            if "d" in title_grdict:
                title_gr.set_attribute("d", str(title_grdict.get_int("d")))

        # Groove gauge level-ups
        gr_s = Node.void("gr_s")
        game.add_child(gr_s)
        index = 1
        for entry in friend.get_int_array("gr_s", 5):
            gr_s.set_attribute(f"gr{index}", str(entry))
            index = index + 1

        gr_d = Node.void("gr_d")
        game.add_child(gr_d)
        index = 1
        for entry in friend.get_int_array("gr_d", 5):
            gr_d.set_attribute(f"gr{index}", str(entry))
            index = index + 1
        return game


class DDRGameLoadCourseHandler(DDRBase):
    def handle_game_load_c_request(self, request: Node) -> Node:
        extid = intish(request.attribute("code"))
        refid = request.attribute("refid")

        if extid is not None:
            # Rival score loading
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
        else:
            # Self score loading
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        coursedata = [0] * 3200
        if userid is not None:
            for course in self.data.local.user.get_achievements(
                self.game, self.version, userid
            ):
                if course.type != "course":
                    continue

                # Grab course ID and chart (kinda pointless because we add it right back up
                # below, but it is more documented/readable this way.
                courseid = int(course.id / 4)
                coursechart = course.id % 4

                # Populate course data
                index = ((courseid * 4) + coursechart) * 8
                if index >= 0 and index <= (len(coursedata) - 8):
                    coursedata[index + 0] = int(course.data.get_int("score") / 10000)
                    coursedata[index + 1] = course.data.get_int("score") % 10000
                    coursedata[index + 2] = course.data.get_int("combo")
                    coursedata[index + 3] = self.db_to_game_rank(
                        course.data.get_int("rank")
                    )
                    coursedata[index + 5] = course.data.get_int("stage")
                    coursedata[index + 6] = course.data.get_int("combo_type")

        game = Node.void("game")
        game.add_child(Node.u16_array("course", coursedata))
        return game


class DDRGameSaveCourseHandler(DDRBase):
    def handle_game_save_c_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        courseid = int(request.attribute("cid"))
        chart = int(request.attribute("ctype"))

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            # Calculate statistics
            data = request.child("data")
            points = int(data.attribute("score"))
            combo = int(data.attribute("combo"))
            combo_type = int(data.attribute("combo_type"))
            stage = int(data.attribute("stage"))
            rank = self.game_to_db_rank(int(data.attribute("rank")))
            trace = request.child_value("trace")

            # Grab the old course score
            oldcourse = self.data.local.user.get_achievement(
                self.game,
                self.version,
                userid,
                (courseid * 4) + chart,
                "course",
            )

            if oldcourse is not None:
                highscore = points > oldcourse.get_int("score")

                points = max(points, oldcourse.get_int("score"))
                combo = max(combo, oldcourse.get_int("combo"))
                stage = max(stage, oldcourse.get_int("stage"))
                rank = max(rank, oldcourse.get_int("rank"))
                combo_type = max(combo_type, oldcourse.get_int("combo_type"))

                if not highscore:
                    # Don't overwrite the ghost for a non-highscore
                    trace = oldcourse.get_int_array("trace", len(trace))

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                (courseid * 4) + chart,
                "course",
                {
                    "score": points,
                    "combo": combo,
                    "stage": stage,
                    "rank": rank,
                    "combo_type": combo_type,
                    "trace": trace,
                },
            )

        # No response needed
        game = Node.void("game")
        return game
