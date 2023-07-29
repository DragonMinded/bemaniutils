# vim: set fileencoding=utf-8
import binascii
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.lapistoria import PopnMusicLapistoria

from bemani.common import Profile, VersionConstants
from bemani.data import UserID, Link
from bemani.protocol import Node


class PopnMusicEclale(PopnMusicBase):
    name: str = "Pop'n Music éclale"
    version: int = VersionConstants.POPN_MUSIC_ECLALE

    # Chart type, as returned from the game
    GAME_CHART_TYPE_EASY: Final[int] = 0
    GAME_CHART_TYPE_NORMAL: Final[int] = 1
    GAME_CHART_TYPE_HYPER: Final[int] = 2
    GAME_CHART_TYPE_EX: Final[int] = 3

    # Medal type, as returned from the game
    GAME_PLAY_MEDAL_CIRCLE_FAILED: Final[int] = 1
    GAME_PLAY_MEDAL_DIAMOND_FAILED: Final[int] = 2
    GAME_PLAY_MEDAL_STAR_FAILED: Final[int] = 3
    GAME_PLAY_MEDAL_EASY_CLEAR: Final[int] = 4
    GAME_PLAY_MEDAL_CIRCLE_CLEARED: Final[int] = 5
    GAME_PLAY_MEDAL_DIAMOND_CLEARED: Final[int] = 6
    GAME_PLAY_MEDAL_STAR_CLEARED: Final[int] = 7
    GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: Final[int] = 8
    GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: Final[int] = 9
    GAME_PLAY_MEDAL_STAR_FULL_COMBO: Final[int] = 10
    GAME_PLAY_MEDAL_PERFECT: Final[int] = 11

    # Biggest ID in the music DB
    GAME_MAX_MUSIC_ID: Final[int] = 1550

    def previous_version(self) -> PopnMusicBase:
        return PopnMusicLapistoria(self.data, self.config, self.model)

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "ints": [
                {
                    "name": "Music Open Phase",
                    "tip": "Default music phase for all players.",
                    "category": "game_config",
                    "setting": "music_phase",
                    "values": {
                        0: "No music unlocks",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase 3",
                        4: "Phase 4",
                        5: "Phase 5",
                        6: "Phase 6",
                        7: "Phase 7",
                        8: "Phase 8",
                        9: "Phase 9",
                        10: "Phase 10",
                        11: "Phase 11",
                        12: "Phase 12",
                        13: "Phase 13",
                        14: "Phase 14",
                        15: "Phase 15",
                        16: "Phase MAX",
                    },
                },
                {
                    "name": "Additional Music Unlock Phase",
                    "tip": "Additional music unlock phase for all players.",
                    "category": "game_config",
                    "setting": "music_sub_phase",
                    "values": {
                        0: "No additional unlocks",
                        1: "Phase 1",
                        2: "Phase 2",
                        3: "Phase MAX",
                    },
                },
            ],
            "bools": [
                {
                    "name": "Enable Starmaker Event",
                    "tip": "Enable Starmaker event as well as song shop.",
                    "category": "game_config",
                    "setting": "starmaker_enable",
                },
                # We don't currently support lobbies or anything, so this is commented out until
                # somebody gets around to implementing it.
                # {
                #     'name': 'Net Taisen',
                #     'tip': 'Enable Net Taisen, including win/loss display on song select',
                #     'category': 'game_config',
                #     'setting': 'enable_net_taisen',
                # },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
            ],
        }

    def __construct_common_info(self, root: Node) -> None:
        game_config = self.get_game_config()
        music_phase = game_config.get_int("music_phase")
        music_sub_phase = game_config.get_int("music_sub_phase")
        enable_net_taisen = False  # game_config.get_bool('enable_net_taisen')

        # Event phases. Eclale seems to be so basic that there is no way to disable/enable
        # the starmaker event. It is just baked into the game.
        phases = {
            # Music open phase (0-16).
            # The following songs are unlocked when the phase is at or above the number specified:
            # 1  - 1470, 1471, 1472
            # 2  - 1447, 1450, 1454, 1457
            # 3  - 1477, 1475, 1483
            # 4  - 1473
            # 5  - 1480, 1479, 1481
            # 6  - 1494, 1495
            # 7  - 1490, 1491
            # 8  - 1489
            # 9  - 1502, 1503, 1504, 1505, 1506, 1507
            # 10 - 1492
            # 11 - 1508, 1509, 1510, 1511
            # 12 - 1518
            # 13 - 1530
            # 14 - 1543
            # 15 - 1544
            # 16 - 1548
            0: music_phase,
            # Unknown event (0-3)
            1: 3,
            # Unknown event (0-1)
            2: 1,
            # Unknown event (0-2)
            3: 2,
            # Something to do with favorites folder and the favorites button on the 10key (0-1)
            4: 1,
            # Looks like something to do with stamp cards, enabled with 1 (0-2)
            5: 1,
            # Unknown event (0-1)
            6: 1,
            # Unknown event (0-4)
            7: 4,
            # Unlock a few more songs (1: 1496, 2: 1474, 3: 1531) (0-3)
            8: music_sub_phase,
            # Unknown event (0-4)
            9: 4,
            # Unknown event (0-4)
            10: 4,
            # Unknown event, maybe something to do with song categories? (0-1)
            11: 1,
            # Enable Net Taisen, including win/loss sort option on music select (0-1)
            12: 1 if enable_net_taisen else 0,
            # Enable local and server-side matching when selecting a song (0-4)
            13: 4,
        }

        for phaseid in phases:
            phase = Node.void("phase")
            root.add_child(phase)
            phase.add_child(Node.s16("event_id", phaseid))
            phase.add_child(Node.s16("phase", phases[phaseid]))

        if game_config.get_bool("starmaker_enable"):
            for areaid in range(1, 51):
                area = Node.void("area")
                root.add_child(area)
                area.add_child(Node.s16("area_id", areaid))
                area.add_child(Node.u64("end_date", 0))
                area.add_child(Node.s16("medal_id", areaid))
                area.add_child(Node.bool("is_limit", False))

        # Calculate most popular characters
        profiles = self.data.remote.user.get_all_profiles(self.game, self.version)
        charas: Dict[int, int] = {}
        for _userid, profile in profiles:
            chara = profile.get_int("chara", -1)
            if chara <= 0:
                continue
            if chara not in charas:
                charas[chara] = 1
            else:
                charas[chara] = charas[chara] + 1

        # Order a typle by most popular character to least popular character
        charamap = sorted(
            [(c, charas[c]) for c in charas],
            key=lambda c: c[1],
            reverse=True,
        )

        # Output the top 20 of them
        rank = 1
        for charaid, _usecount in charamap[:20]:
            popular = Node.void("popular")
            root.add_child(popular)
            popular.add_child(Node.s16("rank", rank))
            popular.add_child(Node.s16("chara_num", charaid))
            rank = rank + 1

        # Output the hit chart
        for songid, _plays in self.data.local.music.get_hit_chart(
            self.game, self.music_version, 500
        ):
            popular_music = Node.void("popular_music")
            root.add_child(popular_music)
            popular_music.add_child(Node.s16("music_num", songid))

        # Output goods prices
        for goodsid in range(1, 421):
            if goodsid >= 1 and goodsid <= 80:
                price = 60
            elif goodsid >= 81 and goodsid <= 120:
                price = 250
            elif goodsid >= 121 and goodsid <= 142:
                price = 500
            elif goodsid >= 143 and goodsid <= 300:
                price = 100
            elif goodsid >= 301 and goodsid <= 420:
                price = 150
            else:
                raise Exception("Invalid goods ID!")
            goods = Node.void("goods")
            root.add_child(goods)
            goods.add_child(Node.s16("goods_id", goodsid))
            goods.add_child(Node.s32("price", price))
            goods.add_child(Node.s16("goods_type", 0))

    def handle_pcb23_boot_request(self, request: Node) -> Node:
        return Node.void("pcb23")

    def handle_pcb23_error_request(self, request: Node) -> Node:
        return Node.void("pcb23")

    def handle_pcb23_dlstatus_request(self, request: Node) -> Node:
        return Node.void("pcb23")

    def handle_pcb23_write_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value("pcb_setting/name"))
        return Node.void("pcb23")

    def handle_info23_common_request(self, request: Node) -> Node:
        info = Node.void("info23")
        self.__construct_common_info(info)
        return info

    def handle_lobby22_requests(self, request: Node) -> Node:
        # Stub out the entire lobby22 service (yes, its lobby22 in Pop'n 23)
        return Node.void("lobby22")

    def handle_player23_start_request(self, request: Node) -> Node:
        root = Node.void("player23")
        root.add_child(Node.s32("play_id", 0))
        self.__construct_common_info(root)
        return root

    def handle_player23_logout_request(self, request: Node) -> Node:
        return Node.void("player23")

    def handle_player23_read_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        root = self.get_profile_by_refid(refid, self.OLD_PROFILE_FALLTHROUGH)
        if root is None:
            root = Node.void("player23")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player23_write_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            oldprofile = self.get_profile(userid) or Profile(
                self.game, self.version, refid, 0
            )
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)

        return Node.void("player23")

    def handle_player23_new_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        root = self.new_profile_by_refid(refid, name)
        if root is None:
            root = Node.void("player23")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player23_conversion_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")
        name = request.child_value("name")
        chara = request.child_value("chara")
        root = self.new_profile_by_refid(refid, name, chara)
        if root is None:
            root = Node.void("player23")
            root.add_child(Node.s8("result", 2))
        return root

    def handle_player23_buy_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            itemid = request.child_value("id")
            itemtype = request.child_value("type")
            itemparam = request.child_value("param")

            price = request.child_value("price")
            lumina = request.child_value("lumina")

            if lumina >= price:
                # Update player lumina balance
                profile = self.get_profile(userid) or Profile(
                    self.game, self.version, refid, 0
                )
                profile.replace_int("lumina", lumina - price)
                self.put_profile(userid, profile)

                # Grant the object
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    f"item_{itemtype}",
                    {
                        "param": itemparam,
                        "is_new": True,
                    },
                )

        return Node.void("player23")

    def handle_player23_read_score_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player23")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            scores = self.data.remote.music.get_scores(
                self.game, self.music_version, userid
            )
        else:
            scores = []

        for score in scores:
            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            points = score.points
            medal = score.data.get_int("medal")

            music = Node.void("music")
            root.add_child(music)
            music.add_child(Node.s16("music_num", score.id))
            music.add_child(
                Node.u8(
                    "sheet_num",
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart],
                )
            )
            music.add_child(Node.s32("score", points))
            music.add_child(
                Node.u8(
                    "clear_type",
                    {
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[medal],
                )
            )
            music.add_child(Node.s16("cnt", score.plays))

        return root

    def handle_player23_friend_request(self, request: Node) -> Node:
        refid = request.attribute("ref_id")
        no = int(request.attribute("no", "-1"))

        root = Node.void("player23")
        if no < 0:
            root.add_child(Node.s8("result", 2))
            return root

        # Look up our own user ID based on the RefID provided.
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root.add_child(Node.s8("result", 2))
            return root

        # Grab the links that we care about.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        profiles: Dict[UserID, Profile] = {}
        rivals: List[Link] = []
        for link in links:
            if link.type != "rival":
                continue

            other_profile = self.get_profile(link.other_userid)
            if other_profile is None:
                continue
            profiles[link.other_userid] = other_profile
            rivals.append(link)

        # Somehow requested an invalid profile.
        if no >= len(rivals):
            root.add_child(Node.s8("result", 2))
            return root
        rivalid = links[no].other_userid
        rivalprofile = profiles[rivalid]
        scores = self.data.remote.music.get_scores(
            self.game, self.music_version, rivalid
        )

        # First, output general profile info.
        friend = Node.void("friend")
        root.add_child(friend)
        friend.add_child(Node.s16("no", no))
        friend.add_child(
            Node.string("g_pm_id", self.format_extid(rivalprofile.extid))
        )  # Eclale formats on its own
        friend.add_child(Node.string("name", rivalprofile.get_str("name", "なし")))
        friend.add_child(Node.s16("chara_num", rivalprofile.get_int("chara", -1)))
        # This might be for having non-active or non-confirmed friends, but setting to 0 makes the
        # ranking numbers disappear and the player icon show a questionmark.
        friend.add_child(Node.s8("is_open", 1))

        for score in scores:
            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            points = score.points
            medal = score.data.get_int("medal")

            music = Node.void("music")
            friend.add_child(music)
            music.set_attribute("music_num", str(score.id))
            music.set_attribute(
                "sheet_num",
                str(
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart]
                ),
            )
            music.set_attribute("score", str(points))
            music.set_attribute(
                "clearmedal",
                str(
                    {
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[medal]
                ),
            )

        return root

    def handle_player23_write_music_request(self, request: Node) -> Node:
        refid = request.child_value("ref_id")

        root = Node.void("player23")
        if refid is None:
            return root

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            return root

        songid = request.child_value("music_num")
        chart = {
            self.GAME_CHART_TYPE_EASY: self.CHART_TYPE_EASY,
            self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
            self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
            self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
        }[request.child_value("sheet_num")]
        medal = request.child_value("clearmedal")
        points = request.child_value("score")
        combo = request.child_value("combo")
        stats = {
            "cool": request.child_value("cool"),
            "great": request.child_value("great"),
            "good": request.child_value("good"),
            "bad": request.child_value("bad"),
        }
        medal = {
            self.GAME_PLAY_MEDAL_CIRCLE_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
            self.GAME_PLAY_MEDAL_DIAMOND_FAILED: self.PLAY_MEDAL_DIAMOND_FAILED,
            self.GAME_PLAY_MEDAL_STAR_FAILED: self.PLAY_MEDAL_STAR_FAILED,
            self.GAME_PLAY_MEDAL_EASY_CLEAR: self.PLAY_MEDAL_EASY_CLEAR,
            self.GAME_PLAY_MEDAL_CIRCLE_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
            self.GAME_PLAY_MEDAL_DIAMOND_CLEARED: self.PLAY_MEDAL_DIAMOND_CLEARED,
            self.GAME_PLAY_MEDAL_STAR_CLEARED: self.PLAY_MEDAL_STAR_CLEARED,
            self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
            self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO: self.PLAY_MEDAL_DIAMOND_FULL_COMBO,
            self.GAME_PLAY_MEDAL_STAR_FULL_COMBO: self.PLAY_MEDAL_STAR_FULL_COMBO,
            self.GAME_PLAY_MEDAL_PERFECT: self.PLAY_MEDAL_PERFECT,
        }[medal]
        self.update_score(
            userid, songid, chart, points, medal, combo=combo, stats=stats
        )

        if request.child_value("is_image_store") == 1:
            self.broadcast_score(userid, songid, chart, medal, points, combo, stats)

        return root

    def format_conversion(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("player23")
        root.add_child(Node.string("name", profile.get_str("name", "なし")))
        root.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        root.add_child(Node.s8("result", 1))

        # Scores
        scores = self.data.remote.music.get_scores(
            self.game, self.music_version, userid
        )
        for score in scores:
            # Skip any scores for chart types we don't support
            if score.chart not in [
                self.CHART_TYPE_EASY,
                self.CHART_TYPE_NORMAL,
                self.CHART_TYPE_HYPER,
                self.CHART_TYPE_EX,
            ]:
                continue
            if score.data.get_int("medal") == self.PLAY_MEDAL_NO_PLAY:
                continue

            music = Node.void("music")
            root.add_child(music)
            music.add_child(Node.s16("music_num", score.id))
            music.add_child(
                Node.u8(
                    "sheet_num",
                    {
                        self.CHART_TYPE_EASY: self.GAME_CHART_TYPE_EASY,
                        self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_NORMAL,
                        self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_HYPER,
                        self.CHART_TYPE_EX: self.GAME_CHART_TYPE_EX,
                    }[score.chart],
                )
            )
            music.add_child(Node.s32("score", score.points))
            music.add_child(
                Node.u8(
                    "clear_type",
                    {
                        self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_MEDAL_CIRCLE_FAILED,
                        self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_MEDAL_DIAMOND_FAILED,
                        self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_MEDAL_STAR_FAILED,
                        self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_MEDAL_EASY_CLEAR,
                        self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_MEDAL_CIRCLE_CLEARED,
                        self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_MEDAL_DIAMOND_CLEARED,
                        self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_MEDAL_STAR_CLEARED,
                        self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_MEDAL_CIRCLE_FULL_COMBO,
                        self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_MEDAL_DIAMOND_FULL_COMBO,
                        self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_MEDAL_STAR_FULL_COMBO,
                        self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_MEDAL_PERFECT,
                    }[score.data.get_int("medal")],
                )
            )
            music.add_child(Node.s16("cnt", score.plays))

        return root

    def format_extid(self, extid: int) -> str:
        data = str(extid)
        crc = abs(binascii.crc32(data.encode("ascii"))) % 10000
        return f"{data}{crc:04d}"

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        root = Node.void("player23")

        # Mark this as a current profile
        root.add_child(Node.s8("result", 0))

        # Account stuff
        account = Node.void("account")
        root.add_child(account)
        account.add_child(Node.string("g_pm_id", self.format_extid(profile.extid)))
        account.add_child(Node.string("name", profile.get_str("name", "なし")))
        account.add_child(Node.s8("tutorial", profile.get_int("tutorial")))
        account.add_child(Node.s16("area_id", profile.get_int("area_id")))
        account.add_child(Node.s16("lumina", profile.get_int("lumina", 300)))
        account.add_child(Node.s16("read_news", profile.get_int("read_news")))
        account.add_child(
            Node.bool("welcom_pack", False)
        )  # Set this to true to grant extra stage no matter what.
        account.add_child(
            Node.s16_array("medal_set", profile.get_int_array("medal_set", 4))
        )
        account.add_child(
            Node.s16_array("nice", profile.get_int_array("nice", 30, [-1] * 30))
        )
        account.add_child(
            Node.s16_array(
                "favorite_chara", profile.get_int_array("favorite_chara", 20, [-1] * 20)
            )
        )
        account.add_child(
            Node.s16_array("special_area", profile.get_int_array("special_area", 8))
        )
        account.add_child(
            Node.s16_array(
                "chocolate_charalist",
                profile.get_int_array("chocolate_charalist", 5, [-1] * 5),
            )
        )
        account.add_child(
            Node.s16_array(
                "teacher_setting", profile.get_int_array("teacher_setting", 10)
            )
        )

        # Stuff we never change
        account.add_child(Node.s8("staff", 0))
        account.add_child(Node.s16("item_type", 0))
        account.add_child(Node.s16("item_id", 0))
        account.add_child(Node.s8("is_conv", 0))
        account.add_child(Node.bool("meteor_flg", True))
        account.add_child(Node.s16_array("license_data", [-1] * 20))

        # Add statistics section
        last_played = [
            x[0]
            for x in self.data.local.music.get_last_played(
                self.game, self.music_version, userid, 5
            )
        ]
        most_played = [
            x[0]
            for x in self.data.local.music.get_most_played(
                self.game, self.music_version, userid, 10
            )
        ]
        while len(last_played) < 5:
            last_played.append(-1)
        while len(most_played) < 10:
            most_played.append(-1)

        account.add_child(Node.s16_array("my_best", most_played))
        account.add_child(Node.s16_array("latest_music", last_played))

        # Number of rivals that are active for this version.
        links = self.data.local.user.get_links(self.game, self.version, userid)
        rivalcount = 0
        for link in links:
            if link.type != "rival":
                continue

            if not self.has_profile(link.other_userid):
                continue

            # This profile is valid.
            rivalcount += 1
        account.add_child(Node.u8("active_fr_num", rivalcount))

        # player statistics
        statistics = self.get_play_statistics(userid)
        account.add_child(Node.s16("total_play_cnt", statistics.total_plays))
        account.add_child(Node.s16("today_play_cnt", statistics.today_plays))
        account.add_child(Node.s16("consecutive_days", statistics.consecutive_days))
        account.add_child(Node.s16("total_days", statistics.total_days))
        account.add_child(Node.s16("interval_day", 0))

        # eAmuse account link
        eaappli = Node.void("eaappli")
        root.add_child(eaappli)
        eaappli.add_child(
            Node.s8(
                "relation",
                1 if self.data.triggers.has_broadcast_destination(self.game) else -1,
            )
        )

        # Set up info node
        info = Node.void("info")
        root.add_child(info)
        info.add_child(Node.u16("ep", profile.get_int("ep")))

        # Set up last information
        config = Node.void("config")
        root.add_child(config)
        config.add_child(Node.u8("mode", profile.get_int("mode")))
        config.add_child(Node.s16("chara", profile.get_int("chara", -1)))
        config.add_child(Node.s16("music", profile.get_int("music", -1)))
        config.add_child(Node.u8("sheet", profile.get_int("sheet")))
        config.add_child(Node.s8("category", profile.get_int("category", -1)))
        config.add_child(Node.s8("sub_category", profile.get_int("sub_category", -1)))
        config.add_child(
            Node.s8("chara_category", profile.get_int("chara_category", -1))
        )
        config.add_child(Node.s16("course_id", profile.get_int("course_id", -1)))
        config.add_child(Node.s8("course_folder", profile.get_int("course_folder", -1)))
        config.add_child(Node.s8("ms_banner_disp", profile.get_int("ms_banner_disp")))
        config.add_child(Node.s8("ms_down_info", profile.get_int("ms_down_info")))
        config.add_child(Node.s8("ms_side_info", profile.get_int("ms_side_info")))
        config.add_child(Node.s8("ms_raise_type", profile.get_int("ms_raise_type")))
        config.add_child(Node.s8("ms_rnd_type", profile.get_int("ms_rnd_type")))

        # Player options
        option = Node.void("option")
        option_dict = profile.get_dict("option")
        root.add_child(option)
        option.add_child(Node.s16("hispeed", option_dict.get_int("hispeed")))
        option.add_child(Node.u8("popkun", option_dict.get_int("popkun")))
        option.add_child(Node.bool("hidden", option_dict.get_bool("hidden")))
        option.add_child(Node.s16("hidden_rate", option_dict.get_int("hidden_rate")))
        option.add_child(Node.bool("sudden", option_dict.get_bool("sudden")))
        option.add_child(Node.s16("sudden_rate", option_dict.get_int("sudden_rate")))
        option.add_child(Node.s8("randmir", option_dict.get_int("randmir")))
        option.add_child(Node.s8("gauge_type", option_dict.get_int("gauge_type")))
        option.add_child(Node.u8("ojama_0", option_dict.get_int("ojama_0")))
        option.add_child(Node.u8("ojama_1", option_dict.get_int("ojama_1")))
        option.add_child(Node.bool("forever_0", option_dict.get_bool("forever_0")))
        option.add_child(Node.bool("forever_1", option_dict.get_bool("forever_1")))
        option.add_child(
            Node.bool("full_setting", option_dict.get_bool("full_setting"))
        )
        option.add_child(Node.u8("judge", option_dict.get_int("judge")))

        # Unknown custom category stuff?
        custom_cate = Node.void("custom_cate")
        root.add_child(custom_cate)
        custom_cate.add_child(Node.s8("valid", 0))
        custom_cate.add_child(Node.s8("lv_min", -1))
        custom_cate.add_child(Node.s8("lv_max", -1))
        custom_cate.add_child(Node.s8("medal_min", -1))
        custom_cate.add_child(Node.s8("medal_max", -1))
        custom_cate.add_child(Node.s8("friend_no", -1))
        custom_cate.add_child(Node.s8("score_flg", -1))

        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            songs = {
                song.id
                for song in self.data.local.music.get_all_songs(
                    self.game, self.music_version
                )
            }
            for song in songs:
                item = Node.void("item")
                root.add_child(item)
                item.add_child(Node.u8("type", 0))
                item.add_child(Node.u16("id", song))
                item.add_child(Node.u16("param", 15))
                item.add_child(Node.bool("is_new", False))

        # Set up achievements
        achievements = self.data.local.user.get_achievements(
            self.game, self.version, userid
        )
        for achievement in achievements:
            if achievement.type[:5] == "item_":
                itemtype = int(achievement.type[5:])
                param = achievement.data.get_int("param")
                is_new = achievement.data.get_bool("is_new")

                # Type is the type of unlock/item. Type 0 is song unlock in Eclale.
                # In this case, the id is the song ID according to the game. Unclear
                # what the param is supposed to be, but i've seen 8 and 0. Might be
                # what chart is available?
                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # We already sent song unlocks in the force unlock section above.
                    continue

                item = Node.void("item")
                root.add_child(item)
                item.add_child(Node.u8("type", itemtype))
                item.add_child(Node.u16("id", achievement.id))
                item.add_child(Node.u16("param", param))
                item.add_child(Node.bool("is_new", is_new))

            elif achievement.type == "chara":
                friendship = achievement.data.get_int("friendship")

                chara = Node.void("chara_param")
                root.add_child(chara)
                chara.add_child(Node.u16("chara_id", achievement.id))
                chara.add_child(Node.u16("friendship", friendship))

            elif achievement.type == "medal":
                level = achievement.data.get_int("level")
                exp = achievement.data.get_int("exp")
                set_count = achievement.data.get_int("set_count")
                get_count = achievement.data.get_int("get_count")

                medal = Node.void("medal")
                root.add_child(medal)
                medal.add_child(Node.s16("medal_id", achievement.id))
                medal.add_child(Node.s16("level", level))
                medal.add_child(Node.s32("exp", exp))
                medal.add_child(Node.s32("set_count", set_count))
                medal.add_child(Node.s32("get_count", get_count))

        # Character customizations
        customize = Node.void("customize")
        root.add_child(customize)
        customize.add_child(Node.u16("effect_left", profile.get_int("effect_left")))
        customize.add_child(Node.u16("effect_center", profile.get_int("effect_center")))
        customize.add_child(Node.u16("effect_right", profile.get_int("effect_right")))
        customize.add_child(Node.u16("hukidashi", profile.get_int("hukidashi")))
        customize.add_child(Node.u16("comment_1", profile.get_int("comment_1")))
        customize.add_child(Node.u16("comment_2", profile.get_int("comment_2")))

        # NetVS section
        netvs = Node.void("netvs")
        root.add_child(netvs)
        netvs.add_child(Node.s16_array("record", [0] * 6))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.string("dialog", ""))
        netvs.add_child(Node.s8_array("ojama_condition", [0] * 74))
        netvs.add_child(Node.s8_array("set_ojama", [0] * 3))
        netvs.add_child(Node.s8_array("set_recommend", [0] * 3))
        netvs.add_child(Node.u32("netvs_play_cnt", 0))

        # Event stuff
        event = Node.void("event")
        root.add_child(event)
        event.add_child(Node.s16("enemy_medal", profile.get_int("event_enemy_medal")))
        event.add_child(Node.s16("hp", profile.get_int("event_hp")))

        # Stamp stuff
        stamp = Node.void("stamp")
        root.add_child(stamp)
        stamp.add_child(Node.s16("stamp_id", profile.get_int("stamp_id")))
        stamp.add_child(Node.s16("cnt", profile.get_int("stamp_cnt")))

        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile
    ) -> Profile:
        newprofile = oldprofile.clone()

        account = request.child("account")
        if account is not None:
            newprofile.replace_int("tutorial", account.child_value("tutorial"))
            newprofile.replace_int("read_news", account.child_value("read_news"))
            newprofile.replace_int("area_id", account.child_value("area_id"))
            newprofile.replace_int("lumina", account.child_value("lumina"))
            newprofile.replace_int_array(
                "medal_set", 4, account.child_value("medal_set")
            )
            newprofile.replace_int_array("nice", 30, account.child_value("nice"))
            newprofile.replace_int_array(
                "favorite_chara", 20, account.child_value("favorite_chara")
            )
            newprofile.replace_int_array(
                "special_area", 8, account.child_value("special_area")
            )
            newprofile.replace_int_array(
                "chocolate_charalist", 5, account.child_value("chocolate_charalist")
            )
            newprofile.replace_int_array(
                "teacher_setting", 10, account.child_value("teacher_setting")
            )

        info = request.child("info")
        if info is not None:
            newprofile.replace_int("ep", info.child_value("ep"))

        config = request.child("config")
        if config is not None:
            newprofile.replace_int("mode", config.child_value("mode"))
            newprofile.replace_int("chara", config.child_value("chara"))
            newprofile.replace_int("music", config.child_value("music"))
            newprofile.replace_int("sheet", config.child_value("sheet"))
            newprofile.replace_int("category", config.child_value("category"))
            newprofile.replace_int("sub_category", config.child_value("sub_category"))
            newprofile.replace_int(
                "chara_category", config.child_value("chara_category")
            )
            newprofile.replace_int("course_id", config.child_value("course_id"))
            newprofile.replace_int("course_folder", config.child_value("course_folder"))
            newprofile.replace_int(
                "ms_banner_disp", config.child_value("ms_banner_disp")
            )
            newprofile.replace_int("ms_down_info", config.child_value("ms_down_info"))
            newprofile.replace_int("ms_side_info", config.child_value("ms_side_info"))
            newprofile.replace_int("ms_raise_type", config.child_value("ms_raise_type"))
            newprofile.replace_int("ms_rnd_type", config.child_value("ms_rnd_type"))

        option_dict = newprofile.get_dict("option")
        option = request.child("option")
        if option is not None:
            option_dict.replace_int("hispeed", option.child_value("hispeed"))
            option_dict.replace_int("popkun", option.child_value("popkun"))
            option_dict.replace_bool("hidden", option.child_value("hidden"))
            option_dict.replace_int("hidden_rate", option.child_value("hidden_rate"))
            option_dict.replace_bool("sudden", option.child_value("sudden"))
            option_dict.replace_int("sudden_rate", option.child_value("sudden_rate"))
            option_dict.replace_int("randmir", option.child_value("randmir"))
            option_dict.replace_int("gauge_type", option.child_value("gauge_type"))
            option_dict.replace_int("ojama_0", option.child_value("ojama_0"))
            option_dict.replace_int("ojama_1", option.child_value("ojama_1"))
            option_dict.replace_bool("forever_0", option.child_value("forever_0"))
            option_dict.replace_bool("forever_1", option.child_value("forever_1"))
            option_dict.replace_bool("full_setting", option.child_value("full_setting"))
            option_dict.replace_int("judge", option.child_value("judge"))
        newprofile.replace_dict("option", option_dict)

        customize = request.child("customize")
        if customize is not None:
            newprofile.replace_int("effect_left", customize.child_value("effect_left"))
            newprofile.replace_int(
                "effect_center", customize.child_value("effect_center")
            )
            newprofile.replace_int(
                "effect_right", customize.child_value("effect_right")
            )
            newprofile.replace_int("hukidashi", customize.child_value("hukidashi"))
            newprofile.replace_int("comment_1", customize.child_value("comment_1"))
            newprofile.replace_int("comment_2", customize.child_value("comment_2"))

        event = request.child("event")
        if event is not None:
            newprofile.replace_int(
                "event_enemy_medal", event.child_value("enemy_medal")
            )
            newprofile.replace_int("event_hp", event.child_value("hp"))

        stamp = request.child("stamp")
        if stamp is not None:
            newprofile.replace_int("stamp_id", stamp.child_value("stamp_id"))
            newprofile.replace_int("stamp_cnt", stamp.child_value("cnt"))

        # Extract achievements
        game_config = self.get_game_config()
        for node in request.children:
            if node.name == "item":
                itemid = node.child_value("id")
                itemtype = node.child_value("type")
                param = node.child_value("param")
                is_new = node.child_value("is_new")

                if game_config.get_bool("force_unlock_songs") and itemtype == 0:
                    # If we enabled force song unlocks, don't save songs to the profile.
                    continue

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    itemid,
                    f"item_{itemtype}",
                    {
                        "param": param,
                        "is_new": is_new,
                    },
                )

            elif node.name == "chara_param":
                charaid = node.child_value("chara_id")
                friendship = node.child_value("friendship")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    charaid,
                    "chara",
                    {
                        "friendship": friendship,
                    },
                )

            elif node.name == "medal":
                medalid = node.child_value("medal_id")
                level = node.child_value("level")
                exp = node.child_value("exp")
                set_count = node.child_value("set_count")
                get_count = node.child_value("get_count")

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    medalid,
                    "medal",
                    {
                        "level": level,
                        "exp": exp,
                        "set_count": set_count,
                        "get_count": get_count,
                    },
                )

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
