# vim: set fileencoding=utf-8
from typing import Any, Dict, Optional, Tuple
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.sdvx.base import SoundVoltexBase
from bemani.common import Profile, VersionConstants, ID, intish
from bemani.data import Score, UserID
from bemani.protocol import Node


class SoundVoltexBooth(
    EventLogHandler,
    SoundVoltexBase,
):
    name: str = "SOUND VOLTEX BOOTH"
    version: int = VersionConstants.SDVX_BOOTH

    GAME_LIMITED_LOCKED: Final[int] = 1
    GAME_LIMITED_UNLOCKED: Final[int] = 2

    GAME_CURRENCY_PACKETS: Final[int] = 0
    GAME_CURRENCY_BLOCKS: Final[int] = 1

    GAME_CLEAR_TYPE_NO_CLEAR: Final[int] = 1
    GAME_CLEAR_TYPE_CLEAR: Final[int] = 2
    GAME_CLEAR_TYPE_ULTIMATE_CHAIN: Final[int] = 3
    GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: Final[int] = 4

    GAME_GRADE_NO_PLAY: Final[int] = 0
    GAME_GRADE_D: Final[int] = 1
    GAME_GRADE_C: Final[int] = 2
    GAME_GRADE_B: Final[int] = 3
    GAME_GRADE_A: Final[int] = 4
    GAME_GRADE_AA: Final[int] = 5
    GAME_GRADE_AAA: Final[int] = 6

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
            ],
        }

    def previous_version(self) -> Optional[SoundVoltexBase]:
        return None

    def __game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_NO_CLEAR: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEAR: self.CLEAR_TYPE_CLEAR,
            self.GAME_CLEAR_TYPE_ULTIMATE_CHAIN: self.CLEAR_TYPE_ULTIMATE_CHAIN,
            self.GAME_CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN: self.CLEAR_TYPE_PERFECT_ULTIMATE_CHAIN,
        }[clear_type]

    def __db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_NO_PLAY: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_NO_CLEAR,
            self.CLEAR_TYPE_CLEAR: self.GAME_CLEAR_TYPE_CLEAR,
            self.CLEAR_TYPE_HARD_CLEAR: self.GAME_CLEAR_TYPE_CLEAR,
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

    def handle_game_exception_request(self, request: Node) -> Node:
        return Node.void("game")

    def handle_game_entry_s_request(self, request: Node) -> Node:
        game = Node.void("game")
        # This should be created on the fly for a lobby that we're in.
        game.add_child(Node.u32("entry_id", 1))
        return game

    def handle_game_lounge_request(self, request: Node) -> Node:
        game = Node.void("game")
        # Refresh interval in seconds.
        game.add_child(Node.u32("interval", 10))
        return game

    def handle_game_entry_e_request(self, request: Node) -> Node:
        # Lobby destroy method, eid attribute (u32) should be used
        # to destroy any open lobbies.
        return Node.void("game")

    def handle_game_frozen_request(self, request: Node) -> Node:
        game = Node.void("game")
        game.set_attribute("result", "0")
        return game

    def handle_game_shop_request(self, request: Node) -> Node:
        self.update_machine_name(request.child_value("shopname"))

        # Respond with number of milliseconds until next request
        game = Node.void("game")
        game.add_child(Node.u32("nxt_time", 1000 * 5 * 60))
        return game

    def handle_game_common_request(self, request: Node) -> Node:
        game = Node.void("game")
        limited = Node.void("limited")
        game.add_child(limited)

        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_songs"):
            ids = set()
            songs = self.data.local.music.get_all_songs(self.game, self.version)
            for song in songs:
                if song.data.get_int("limited") == self.GAME_LIMITED_LOCKED:
                    ids.add(song.id)

            for songid in ids:
                music = Node.void("music")
                limited.add_child(music)
                music.set_attribute("id", str(songid))
                music.set_attribute("flag", str(self.GAME_LIMITED_UNLOCKED))

        event = Node.void("event")
        game.add_child(event)

        def enable_event(eid: int) -> None:
            evt = Node.void("info")
            event.add_child(evt)
            evt.set_attribute("id", str(eid))

        if not game_config.get_bool("disable_matching"):
            enable_event(3)  # Matching enabled
        enable_event(9)  # Rank Soukuu
        enable_event(13)  # Year-end bonus

        catalog = Node.void("catalog")
        game.add_child(catalog)
        songunlocks = self.data.local.game.get_items(self.game, self.version)
        for unlock in songunlocks:
            if unlock.type != "song_unlock":
                continue

            info = Node.void("info")
            catalog.add_child(info)
            info.set_attribute("id", str(unlock.id))
            info.set_attribute("currency", str(self.GAME_CURRENCY_BLOCKS))
            info.set_attribute("price", str(unlock.data.get_int("blocks")))

        kacinfo = Node.void("kacinfo")
        game.add_child(kacinfo)
        kacinfo.add_child(Node.u32("note00", 0))
        kacinfo.add_child(Node.u32("note01", 0))
        kacinfo.add_child(Node.u32("note02", 0))
        kacinfo.add_child(Node.u32("note10", 0))
        kacinfo.add_child(Node.u32("note11", 0))
        kacinfo.add_child(Node.u32("note12", 0))
        kacinfo.add_child(Node.u32("rabbeat0", 0))
        kacinfo.add_child(Node.u32("rabbeat1", 0))

        return game

    def handle_game_hiscore_request(self, request: Node) -> Node:
        game = Node.void("game")

        # Ranking system I think?
        for i in range(1, 21):
            ranking = Node.void("ranking")
            game.add_child(ranking)
            ranking.set_attribute("id", str(i))

        hiscore = Node.void("hiscore")
        game.add_child(hiscore)
        hiscore.set_attribute("type", "1")

        records = self.data.remote.music.get_all_records(self.game, self.version)

        # Organize by song->chart
        records_by_id: Dict[int, Dict[int, Tuple[UserID, Score]]] = {}
        missing_users = []
        for record in records:
            userid, score = record
            if score.id not in records_by_id:
                records_by_id[score.id] = {}

            records_by_id[score.id][score.chart] = record
            missing_users.append(userid)

        users = {userid: profile for (userid, profile) in self.get_any_profiles(missing_users)}

        # Output records
        for songid in records_by_id:
            music = Node.void("music")
            hiscore.add_child(music)
            music.set_attribute("id", str(songid))

            for chart in records_by_id[songid]:
                note = Node.void("note")
                music.add_child(note)
                note.set_attribute("type", str(chart))

                userid, score = records_by_id[songid][chart]
                note.set_attribute("score", str(score.points))
                note.set_attribute("name", users[userid].get_str("name"))

        return game

    def handle_game_new_request(self, request: Node) -> Node:
        refid = request.attribute("refid")
        name = request.attribute("name")
        loc = ID.parse_machine_id(request.attribute("locid"))
        self.new_profile_by_refid(refid, name, loc)

        root = Node.void("game")
        return root

    def handle_game_load_request(self, request: Node) -> Node:
        refid = request.attribute("dataid")
        root = self.get_profile_by_refid(refid)
        if root is None:
            root = Node.void("game")
            root.set_attribute("none", "1")
        return root

    def handle_game_save_request(self, request: Node) -> Node:
        refid = request.attribute("refid")

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

        return Node.void("game")

    def handle_game_load_m_request(self, request: Node) -> Node:
        refid = request.attribute("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        else:
            scores = []

        # Organize by song->chart
        scores_by_id: Dict[int, Dict[int, Score]] = {}
        for score in scores:
            if score.id not in scores_by_id:
                scores_by_id[score.id] = {}

            scores_by_id[score.id][score.chart] = score

        # Output to the game
        game = Node.void("game")
        for songid in scores_by_id:
            music = Node.void("music")
            game.add_child(music)
            music.set_attribute("music_id", str(songid))

            for chart in scores_by_id[songid]:
                typenode = Node.void("type")
                music.add_child(typenode)
                typenode.set_attribute("type_id", str(chart))

                score = scores_by_id[songid][chart]
                typenode.set_attribute("score", str(score.points))
                typenode.set_attribute("cnt", str(score.plays))
                typenode.set_attribute(
                    "clear_type",
                    str(self.__db_to_game_clear_type(score.data.get_int("clear_type"))),
                )
                typenode.set_attribute(
                    "score_grade",
                    str(self.__db_to_game_grade(score.data.get_int("grade"))),
                )

        return game

    def handle_game_save_m_request(self, request: Node) -> Node:
        refid = request.attribute("dataid")

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is None:
            return Node.void("game")

        musicid = int(request.attribute("music_id"))
        chart = int(request.attribute("music_type"))
        score = int(request.attribute("score"))
        combo = int(request.attribute("max_chain"))
        grade = self.__game_to_db_grade(int(request.attribute("score_grade")))
        clear_type = self.__game_to_db_clear_type(int(request.attribute("clear_type")))

        # Save the score
        self.update_score(
            userid,
            musicid,
            chart,
            score,
            clear_type,
            grade,
            combo,
        )

        # No response necessary
        return Node.void("game")

    def handle_game_buy_request(self, request: Node) -> Node:
        refid = request.attribute("refid")

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

            # Look up the item to get the actual price and currency used
            item = self.data.local.game.get_item(
                self.game,
                self.version,
                request.child_value("catalog_id"),
                "song_unlock",
            )
            if item is not None:
                currency_type = request.child_value("currency_type")
                if currency_type == self.GAME_CURRENCY_PACKETS:
                    if "packets" in item:
                        # This is a valid purchase
                        newpacket = packet - item.get_int("packets")
                        if newpacket < 0:
                            result = 1
                        else:
                            packet = newpacket
                            result = 0
                    else:
                        # Bad transaction
                        result = 1
                elif currency_type == self.GAME_CURRENCY_BLOCKS:
                    if "blocks" in item:
                        # This is a valid purchase
                        newblock = block - item.get_int("blocks")
                        if newblock < 0:
                            result = 1
                        else:
                            block = newblock
                            result = 0
                    else:
                        # Bad transaction
                        result = 1
                else:
                    # Bad currency type
                    result = 1

                if result == 0:
                    # Transaction is valid, update the profile with new packets and blocks
                    profile.replace_int("packet", packet)
                    profile.replace_int("block", block)
                    self.put_profile(userid, profile)
            else:
                # Bad catalog ID
                result = 1
        else:
            # Unclear what to do here, return a bad response
            packet = 0
            block = 0
            result = 1

        game = Node.void("game")
        game.add_child(Node.u32("gamecoin_packet", packet))
        game.add_child(Node.u32("gamecoin_block", block))
        game.add_child(Node.s8("result", result))
        return game

    def format_profile(self, userid: UserID, profile: Profile) -> Node:
        game = Node.void("game")

        # Generic profile stuff
        game.add_child(Node.string("name", profile.get_str("name")))
        game.add_child(Node.string("code", ID.format_extid(profile.extid)))
        game.add_child(Node.u32("gamecoin_packet", profile.get_int("packet")))
        game.add_child(Node.u32("gamecoin_block", profile.get_int("block")))
        game.add_child(Node.u32("exp_point", profile.get_int("exp")))
        game.add_child(Node.u32("m_user_cnt", profile.get_int("m_user_cnt")))

        game_config = self.get_game_config()
        if game_config.get_bool("force_unlock_cards"):
            game.add_child(Node.bool_array("have_item", [True] * 512))
        else:
            game.add_child(
                Node.bool_array(
                    "have_item",
                    [x > 0 for x in profile.get_int_array("have_item", 512)],
                )
            )
        if game_config.get_bool("force_unlock_songs"):
            game.add_child(Node.bool_array("have_note", [True] * 512))
        else:
            game.add_child(
                Node.bool_array(
                    "have_note",
                    [x > 0 for x in profile.get_int_array("have_note", 512)],
                )
            )

        # Last played stuff
        lastdict = profile.get_dict("last")
        last = Node.void("last")
        game.add_child(last)
        last.set_attribute("music_id", str(lastdict.get_int("music_id")))
        last.set_attribute("music_type", str(lastdict.get_int("music_type")))
        last.set_attribute("sort_type", str(lastdict.get_int("sort_type")))
        last.set_attribute("headphone", str(lastdict.get_int("headphone")))
        last.set_attribute("hispeed", str(lastdict.get_int("hispeed")))
        last.set_attribute("appeal_id", str(lastdict.get_int("appeal_id")))
        last.set_attribute("frame0", str(lastdict.get_int("frame0")))
        last.set_attribute("frame1", str(lastdict.get_int("frame1")))
        last.set_attribute("frame2", str(lastdict.get_int("frame2")))
        last.set_attribute("frame3", str(lastdict.get_int("frame3")))
        last.set_attribute("frame4", str(lastdict.get_int("frame4")))

        return game

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile) -> Profile:
        newprofile = oldprofile.clone()

        # Update experience and in-game currencies
        earned_gamecoin_packet = request.child_value("earned_gamecoin_packet")
        if earned_gamecoin_packet is not None:
            newprofile.replace_int("packet", newprofile.get_int("packet") + earned_gamecoin_packet)
        earned_gamecoin_block = request.child_value("earned_gamecoin_block")
        if earned_gamecoin_block is not None:
            newprofile.replace_int("block", newprofile.get_int("block") + earned_gamecoin_block)
        gain_exp = request.child_value("gain_exp")
        if gain_exp is not None:
            newprofile.replace_int("exp", newprofile.get_int("exp") + gain_exp)

        # Miscelaneous stuff
        newprofile.replace_int("m_user_cnt", request.child_value("m_user_cnt"))

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()
        if not game_config.get_bool("force_unlock_cards"):
            have_item = request.child_value("have_item")
            if have_item is not None:
                newprofile.replace_int_array("have_item", 512, [1 if x else 0 for x in have_item])
        if not game_config.get_bool("force_unlock_songs"):
            have_note = request.child_value("have_note")
            if have_note is not None:
                newprofile.replace_int_array("have_note", 512, [1 if x else 0 for x in have_note])

        # Grab last information.
        lastdict = newprofile.get_dict("last")
        lastdict.replace_int("headphone", request.child_value("headphone"))
        lastdict.replace_int("hispeed", request.child_value("hispeed"))
        lastdict.replace_int("appeal_id", request.child_value("appeal_id"))
        lastdict.replace_int("frame0", request.child_value("frame0"))
        lastdict.replace_int("frame1", request.child_value("frame1"))
        lastdict.replace_int("frame2", request.child_value("frame2"))
        lastdict.replace_int("frame3", request.child_value("frame3"))
        lastdict.replace_int("frame4", request.child_value("frame4"))
        last = request.child("last")
        if last is not None:
            lastdict.replace_int("music_id", intish(last.attribute("music_id")))
            lastdict.replace_int("music_type", intish(last.attribute("music_type")))
            lastdict.replace_int("sort_type", intish(last.attribute("sort_type")))

        # Save back last information gleaned from results
        newprofile.replace_dict("last", lastdict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
