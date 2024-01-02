from bemani.backend.museca.base import MusecaBase
from bemani.common import ID
from bemani.protocol import Node


class MusecaGameShopHandler(MusecaBase):
    def handle_game_3_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("shopname"))

        # Respond with number of milliseconds until next request
        game = Node.void("game_3")
        game.add_child(Node.u32("nxt_time", 1000 * 5 * 60))
        return game


class MusecaGameHiscoreHandler(MusecaBase):
    def handle_game_3_hiscore_request(self, request: Node) -> Node:
        # Grab location for local scores
        locid = ID.parse_machine_id(request.child_value("locid"))

        # Start the response packet
        game = Node.void("game_3")

        # First, grab hit chart
        playcounts = self.data.local.music.get_hit_chart(self.game, self.version, 1024)

        hitchart = Node.void("hitchart")
        game.add_child(hitchart)
        for songid, count in playcounts:
            info = Node.void("info")
            hitchart.add_child(info)
            info.add_child(Node.u32("id", songid))
            info.add_child(Node.u32("cnt", count))

        # Now, grab user records
        records = self.data.remote.music.get_all_records(self.game, self.version)
        users = {uid: prof for (uid, prof) in self.get_any_profiles([r[0] for r in records])}

        hiscore_allover = Node.void("hiscore_allover")
        game.add_child(hiscore_allover)

        # Output records
        for userid, score in records:
            info = Node.void("info")

            if userid not in users:
                raise Exception("Logic error, could not find profile for user!")
            profile = users[userid]

            info.add_child(Node.u32("id", score.id))
            info.add_child(Node.u32("type", score.chart))
            info.add_child(Node.string("name", profile.get_str("name")))
            info.add_child(Node.string("seq", ID.format_extid(profile.extid)))
            info.add_child(Node.u32("score", score.points))

            # Add to global scores
            hiscore_allover.add_child(info)

        # Now, grab local records
        area_users = [
            uid
            for (uid, prof) in self.data.local.user.get_all_profiles(self.game, self.version)
            if prof.get_int("loc", -1) == locid
        ]
        records = self.data.local.music.get_all_records(self.game, self.version, userlist=area_users)
        missing_players = [uid for (uid, _) in records if uid not in users]
        for uid, prof in self.get_any_profiles(missing_players):
            users[uid] = prof

        hiscore_location = Node.void("hiscore_location")
        game.add_child(hiscore_location)

        # Output records
        for userid, score in records:
            info = Node.void("info")

            if userid not in users:
                raise Exception("Logic error, could not find profile for user!")
            profile = users[userid]

            info.add_child(Node.u32("id", score.id))
            info.add_child(Node.u32("type", score.chart))
            info.add_child(Node.string("name", profile.get_str("name")))
            info.add_child(Node.string("seq", ID.format_extid(profile.extid)))
            info.add_child(Node.u32("score", score.points))

            # Add to global scores
            hiscore_location.add_child(info)

        # Now, grab clear rates
        clear_rate = Node.void("clear_rate")
        game.add_child(clear_rate)

        clears = self.get_clear_rates()
        for songid in clears:
            for chart in clears[songid]:
                if clears[songid][chart]["total"] > 0:
                    rate = float(clears[songid][chart]["clears"]) / float(clears[songid][chart]["total"])
                    dnode = Node.void("d")
                    clear_rate.add_child(dnode)
                    dnode.add_child(Node.u32("id", songid))
                    dnode.add_child(Node.u32("type", chart))
                    dnode.add_child(Node.s16("cr", int(rate * 10000)))

        return game


class MusecaGameFrozenHandler(MusecaBase):
    def handle_game_3_frozen_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        game.add_child(Node.u8("result", 0))
        return game


class MusecaGameNewHandler(MusecaBase):
    def handle_game_3_new_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        name = request.child_value("name")
        loc = ID.parse_machine_id(request.child_value("locid"))
        self.new_profile_by_refid(refid, name, loc)

        root = Node.void("game_3")
        return root


class MusecaGameSaveMusicHandler(MusecaBase):
    def handle_game_3_save_m_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        # Doesn't matter if userid is None here, that's an anonymous score
        musicid = request.child_value("music_id")
        chart = request.child_value("music_type")
        points = request.child_value("score")
        combo = request.child_value("max_chain")
        clear_type = self.game_to_db_clear_type(request.child_value("clear_type"))
        grade = self.game_to_db_grade(request.child_value("score_grade"))
        stats = {
            "btn_rate": request.child_value("btn_rate"),
            "long_rate": request.child_value("long_rate"),
            "vol_rate": request.child_value("vol_rate"),
            "critical": request.child_value("critical"),
            "near": request.child_value("near"),
            "error": request.child_value("error"),
        }

        # Save the score
        self.update_score(
            userid,
            musicid,
            chart,
            points,
            clear_type,
            grade,
            combo,
            stats,
        )

        # Return a blank response
        return Node.void("game_3")


class MusecaGamePlayEndHandler(MusecaBase):
    def handle_game_3_play_e_request(self, request: Node) -> Node:
        return Node.void("game_3")


class MusecaGameSaveHandler(MusecaBase):
    def handle_game_3_save_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            oldprofile = self.get_profile(userid)
            newprofile = self.unformat_profile(userid, request, oldprofile)
        else:
            newprofile = None

        if userid is not None and newprofile is not None:
            self.put_profile(userid, newprofile)

        return Node.void("game_3")
