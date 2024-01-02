# vim: set fileencoding=utf-8
from typing import Any, Dict, List, Optional
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.sdvx.base import SoundVoltexBase
from bemani.backend.sdvx.infiniteinfection import SoundVoltexInfiniteInfection
from bemani.common import ID, VersionConstants
from bemani.protocol import Node


class SoundVoltexGravityWars(
    EventLogHandler,
    SoundVoltexBase,
):
    name: str = "SOUND VOLTEX III GRAVITY WARS"
    version: int = VersionConstants.SDVX_GRAVITY_WARS

    GAME_LIMITED_LOCKED: Final[int] = 1
    GAME_LIMITED_UNLOCKABLE: Final[int] = 2
    GAME_LIMITED_UNLOCKED: Final[int] = 3

    GAME_CURRENCY_PACKETS: Final[int] = 0
    GAME_CURRENCY_BLOCKS: Final[int] = 1

    GAME_CLEAR_TYPE_NO_CLEAR: Final[int] = 1
    GAME_CLEAR_TYPE_CLEAR: Final[int] = 2
    GAME_CLEAR_TYPE_HARD_CLEAR: Final[int] = 3
    GAME_CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = 4
    GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[int] = 5

    GAME_GRADE_NO_PLAY: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_AA: Final[int] = 5
    GAME_GRADE_AAA: Final[int] = 6

    GAME_CATALOG_TYPE_SONG: Final[int] = 0
    GAME_CATALOG_TYPE_APPEAL_CARD: Final[int] = 1
    GAME_CATALOG_TYPE_CREW: Final[int] = 4

    GAME_GAUGE_TYPE_SKILL: Final[int] = 1

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Disable Online Matching",
                    "tip": "Disable online matching between games.",
                    "category": "game_config",
                    "setting": "disable_matching",
                },
                {
                    "name": "Force Song Unlock",
                    "tip": "Force unlock all songs.",
                    "category": "game_config",
                    "setting": "force_unlock_songs",
                },
                {
                    "name": "Force Appeal Card Unlock",
                    "tip": "Force unlock all appeal cards.",
                    "category": "game_config",
                    "setting": "force_unlock_cards",
                },
                {
                    "name": "Force Crew Card Unlock",
                    "tip": "Force unlock all crew and subcrew cards.",
                    "category": "game_config",
                    "setting": "force_unlock_crew",
                },
            ],
        }

    def previous_version(self) -> Optional[SoundVoltexBase]:
        return SoundVoltexInfiniteInfection(self.data, self.config, self.model)

    def _get_skill_analyzer_courses(self) -> List[Dict[str, Any]]:
        # This is overridden in S1/S2 code.
        return []

    def _get_skill_analyzer_seasons(self) -> Dict[int, str]:
        # This is overridden in S1/S2 code.
        return {}

    def _get_extra_events(self) -> List[int]:
        # This is overridden in S1/S2 code.
        return []

    def __game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_CLEAR: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEAR: self.CLEAR_TYPE_CLEAR,
            self.GAME_CLEAR_TYPE_HARD_CLEAR: self.CLEAR_TYPE_HARD_CLEAR,
            self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN: self.CLEAR_TYPE_ULTIMATE_CHAIN,
            self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_CLEAR: self.GAME_CLEAR_TYPE_CLEAR,
            self.CLEAR_TYPE_HARD_CLEAR: self.GAME_CLEAR_TYPE_HARD_CLEAR,
            self.CLEAR_TYPE_ULTIMATE_CHAIN: self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN,
            self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __game_to_db_grade(self, grade: int) -> int:
        return {
            self.GAME_GRADE_NO_PLAY: self.GRADE_NO_PLAY,
            self.GAME_GRADE_D: self.GRADE_D,
            self.GAME_GRADE_C: self.GRADE_C,
            self.GAME_GRADE_B: self.GRADE_B,
            self.GAME_GRADE_A: self.GRADE_A,
            self.GAME_GRADE_AA: self.GRADE_AA,
            self.GAME_GRADE_AAA: self.GRADE_AAA,
        }[grade]

    def __db_to_game_grade(self, grade: int) -> int:
        return {
            self.GRADE_NO_PLAY: self.GAME_GRADE_NO_PLAY,
            self.GRADE_D: self.GAME_GRADE_D,
            self.GRADE_C: self.GAME_GRADE_C,
            self.GRADE_B: self.GAME_GRADE_B,
            self.GRADE_A: self.GAME_GRADE_A,
            self.GRADE_A_PLUS: self.GAME_GRADE_A,
            self.GRADE_AA: self.GAME_GRADE_AA,
            self.GRADE_AA_PLUS: self.GAME_GRADE_AA,
            self.GRADE_AAA: self.GAME_GRADE_AAA,
            self.GRADE_AAA_PLUS: self.GAME_GRADE_AAA,
            self.GRADE_S: self.GAME_GRADE_AAA,
        }[grade]

    def __get_skill_analyzer_skill_levels(self) -> Dict[int, str]:
        return {
            0: "Skill LEVEL 01 岳翔",
            1: "Skill LEVEL 02 流星",
            2: "Skill LEVEL 03 月衝",
            3: "Skill LEVEL 04 瞬光",
            4: "Skill LEVEL 05 天極",
            5: "Skill LEVEL 06 烈風",
            6: "Skill LEVEL 07 雷電",
            7: "Skill LEVEL 08 麗華",
            8: "Skill LEVEL 09 魔騎士",
            9: "Skill LEVEL 10 剛力羅",
            10: "Skill LEVEL 11 或帝滅斗",
            11: "Skill LEVEL ∞(12) 暴龍天",
        }

    def handle_game_3_common_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        limited = Node.void("music_limited")
        game.add_child(limited)

        # Song unlock config
        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            ids = set()
            songs = self.data.local.music.get_all_songs(self.game, self.version)
            for song in songs:
                if song.data.get_int("limited") in (
                    self.GAME_LIMITED_LOCKED,
                    self.GAME_LIMITED_UNLOCKABLE,
                ):
                    ids.add((song.id, song.chart))

            for songid, chart in ids:
                info = Node.void("info")
                limited.add_child(info)
                info.add_child(Node.s32("music_id", songid))
                info.add_child(Node.u8("music_type", chart))
                info.add_child(Node.u8("limited", self.GAME_LIMITED_UNLOCKED))

        # Event config
        event = Node.void("event")
        game.add_child(event)

        def enable_event(eid: int) -> None:
            evt = Node.void("info")
            event.add_child(evt)
            evt.add_child(Node.u32("event_id", eid))

        if not game_config.get_bool("disable_matching"):
            enable_event(1)  # Matching enabled
        enable_event(2)  # Floor Infection
        enable_event(3)  # Policy Break
        enable_event(60)  # BEMANI Summer Diary

        for eventid in self._get_extra_events():
            enable_event(eventid)

        # Skill Analyzer config
        skill_course = Node.void("skill_course")
        game.add_child(skill_course)

        seasons = self._get_skill_analyzer_seasons()
        skillnames = self.__get_skill_analyzer_skill_levels()
        courses = self._get_skill_analyzer_courses()
        max_level: Dict[int, int] = {}
        for course in courses:
            max_level[course["level"]] = max(course["season_id"], max_level.get(course["level"], -1))
        for course in courses:
            info = Node.void("info")
            skill_course.add_child(info)
            info.add_child(Node.s16("course_id", course.get("id", course["level"])))
            info.add_child(Node.s16("level", course["level"]))
            info.add_child(Node.s32("season_id", course["season_id"]))
            info.add_child(Node.string("season_name", seasons[course["season_id"]]))
            info.add_child(Node.bool("season_new_flg", max_level[course["level"]] == course["season_id"]))
            info.add_child(
                Node.string(
                    "course_name",
                    course.get("skill_name", skillnames.get(course["level"], "")),
                )
            )
            info.add_child(Node.s16("course_type", 0))
            info.add_child(Node.s16("skill_name_id", course.get("skill_name_id", course["level"])))
            info.add_child(Node.bool("matching_assist", course["level"] >= 0 and course["level"] <= 6))
            info.add_child(Node.s16("gauge_type", self.GAME_GAUGE_TYPE_SKILL))
            info.add_child(Node.s16("paseli_type", 0))

            for trackno, trackdata in enumerate(course["tracks"]):
                track = Node.void("track")
                info.add_child(track)
                track.add_child(Node.s16("track_no", trackno))
                track.add_child(Node.s32("music_id", trackdata["id"]))
                track.add_child(Node.s8("music_type", trackdata["type"]))

        return game

    def handle_game_3_exception_request(self, request: Node) -> Node:
        return Node.void("game_3")

    def handle_game_3_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("shopname"))

        # Respond with number of milliseconds until next request
        game = Node.void("game_3")
        game.add_child(Node.u32("nxt_time", 1000 * 5 * 60))
        return game

    def handle_game_3_lounge_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        # Refresh interval in seconds.
        game.add_child(Node.u32("interval", 10))
        return game

    def handle_game_3_entry_s_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        # This should be created on the fly for a lobby that we're in.
        game.add_child(Node.u32("entry_id", 1))
        return game

    def handle_game_3_entry_e_request(self, request: Node) -> Node:
        # Lobby destroy method, eid node (u32) should be used
        # to destroy any open lobbies.
        return Node.void("game_3")

    def handle_game_3_frozen_request(self, request: Node) -> Node:
        game = Node.void("game_3")
        game.add_child(Node.u8("result", 0))
        return game

    def handle_game_3_save_e_request(self, request: Node) -> Node:
        # This has to do with Policy Break against ReflecBeat and
        # floor infection, but we don't implement multi-game support so meh.
        return Node.void("game_3")

    def handle_game_3_play_e_request(self, request: Node) -> Node:
        return Node.void("game_3")

    def handle_game_3_buy_request(self, request: Node) -> Node:
        refid = request.child_value("refid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            profile = self.get_profile(userid)
        else:
            profile = None

        if userid is not None and profile is not None:
            # Look up packets and blocks
            packet = profile.get_int("packet")
            block = profile.get_int("block")

            # Add on any additional we earned this round
            packet = packet + (request.child_value("earned_gamecoin_packet") or 0)
            block = block + (request.child_value("earned_gamecoin_block") or 0)

            currency_type = request.child_value("currency_type")
            price = request.child_value("item/price")
            if isinstance(price, list):
                # Sometimes we end up buying more than one item at once
                price = sum(price)

            if currency_type == self.GAME_CURRENCY_PACKETS:
                # This is a valid purchase
                newpacket = packet - price
                if newpacket < 0:
                    result = 1
                else:
                    packet = newpacket
                    result = 0
            elif currency_type == self.GAME_CURRENCY_BLOCKS:
                # This is a valid purchase
                newblock = block - price
                if newblock < 0:
                    result = 1
                else:
                    block = newblock
                    result = 0
            else:
                # Bad currency type
                result = 1

            if result == 0:
                # Transaction is valid, update the profile with new packets and blocks
                profile.replace_int("packet", packet)
                profile.replace_int("block", block)
                self.put_profile(userid, profile)

                # If this was a song unlock, we should mark it as unlocked
                item_type = request.child_value("item/item_type")
                item_id = request.child_value("item/item_id")
                param = request.child_value("item/param")

                if not isinstance(item_type, list):
                    # Sometimes we buy multiple things at once. Make it easier by always assuming this.
                    item_type = [item_type]
                    item_id = [item_id]
                    param = [param]

                for i in range(len(item_type)):
                    self.data.local.user.put_achievement(
                        self.game,
                        self.version,
                        userid,
                        item_id[i],
                        f"item_{item_type[i]}",
                        {
                            "param": param[i],
                        },
                    )

        else:
            # Unclear what to do here, return a bad response
            packet = 0
            block = 0
            result = 1

        game = Node.void("game_3")
        game.add_child(Node.u32("gamecoin_packet", packet))
        game.add_child(Node.u32("gamecoin_block", block))
        game.add_child(Node.s8("result", result))
        return game

    def handle_game_3_new_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        name = request.child_value("name")
        loc = ID.parse_machine_id(request.child_value("locid"))
        self.new_profile_by_refid(refid, name, loc)

        root = Node.void("game_3")
        return root

    def handle_game_3_load_request(self, request: Node) -> Node:
        refid = request.child_value("refid")
        root = self.get_profile_by_refid(refid)
        if root is not None:
            return root

        # Figure out if this user has an older profile or not
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)

        if userid is not None:
            previous_game = self.previous_version()
        else:
            previous_game = None

        if previous_game is not None:
            profile = previous_game.get_profile(userid)
        else:
            profile = None

        if profile is not None:
            root = Node.void("game_3")
            root.add_child(Node.u8("result", 2))
            root.add_child(Node.string("name", profile.get_str("name")))
            return root
        else:
            root = Node.void("game_3")
            root.add_child(Node.u8("result", 1))
            return root

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

    def handle_game_3_load_m_request(self, request: Node) -> Node:
        refid = request.child_value("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        else:
            scores = []

        # Output to the game
        game = Node.void("game_3")
        new = Node.void("new")
        game.add_child(new)

        for score in scores:
            music = Node.void("music")
            new.add_child(music)
            music.add_child(Node.u32("music_id", score.id))
            music.add_child(Node.u32("music_type", score.chart))
            music.add_child(Node.u32("score", score.points))
            music.add_child(Node.u32("cnt", score.plays))
            music.add_child(
                Node.u32(
                    "clear_type",
                    self.__db_to_game_clear_type(score.data.get_int("clear_type")),
                )
            )
            music.add_child(Node.u32("score_grade", self.__db_to_game_grade(score.data.get_int("grade"))))
            stats = score.data.get_dict("stats")
            music.add_child(Node.u32("btn_rate", stats.get_int("btn_rate")))
            music.add_child(Node.u32("long_rate", stats.get_int("long_rate")))
            music.add_child(Node.u32("vol_rate", stats.get_int("vol_rate")))

        return game

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
        clear_type = self.__game_to_db_clear_type(request.child_value("clear_type"))
        grade = self.__game_to_db_grade(request.child_value("score_grade"))
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

    def handle_game_3_save_c_request(self, request: Node) -> Node:
        refid = request.child_value("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            course_id = request.child_value("crsid")
            clear_type = request.child_value("ct")
            achievement_rate = request.child_value("ar")
            season_id = request.child_value("ssnid")

            # Do not update the course achievement when old achievement rate is greater.
            old = self.data.local.user.get_achievement(
                self.game, self.version, userid, (season_id * 100) + course_id, "course"
            )
            if old is not None and old.get_int("achievement_rate") > achievement_rate:
                return Node.void("game_3")

            self.data.local.user.put_achievement(
                self.game,
                self.version,
                userid,
                (season_id * 100) + course_id,
                "course",
                {
                    "clear_type": clear_type,
                    "achievement_rate": achievement_rate,
                },
            )

        # Return a blank response
        return Node.void("game_3")
