import base64
import struct
from typing import Any, Dict, List
from typing_extensions import Final

from bemani.backend.ess import EventLogHandler
from bemani.backend.danevo.base import DanceEvolutionBase
from bemani.common import VersionConstants, Profile, CardCipher, Time
from bemani.protocol import Node


class DanceEvolution(
    EventLogHandler,
    DanceEvolutionBase,
):
    name: str = "Dance Evolution"
    version: int = VersionConstants.DANCE_EVOLUTION

    # Dance Evolution is a mess that only uses profile blobs for everything from the server.
    # This includes scores/records, and your profile and class advancement. DATA01 includes
    # standard profile info in the CSV portion much like every ESS game. DATA03 includes, for
    # some reason, the ID of the songs you just played as well as the score, but not the chart.
    # DATA04 includes your cumulative score earned across all plays. DATA01-DATA05 as well as
    # DATA11-DATA15 hold the records for songs in the binary portion, where 01-05 indicate the
    # chart difficulty for the song and the offset into the binary data can be calculated by
    # the song's offset in the music DB. RDATA01 appears to be for attempts, and seems to
    # include information in the binary of previous attempts at songs, ordered by attempt.
    # This, however, does not include the chart played, so it can't be used to inform the backend
    # of attempts.

    # RDATA running score list includes history chunks that are 32 bytes in length. The game
    # never sends trailing zeros for a data structure, even if it internally recognizes them,
    # so this may have length not divisible by 32 if there are no non-zero bytes after a certain
    # location. The correct thing to do is to fill with assumed zero bytes to a 32-byte boundary.
    # The first 4 bytes of any history chunk are the score in little endian. The next 4 bytes
    # is a packed structure containing the song ID, difficulty, score, grade, combo and full
    # combo indicator. Then, a 64 bit timestamp in milliseconds follows.

    # DATA01-05 store the records for songs, including the high score, the letter grade earned,
    # and whether the song has been played (a record exists), cleared and whether a full combo
    # has been earned. The first 63 songs are stored in DATA01-05 (songs with ID 0-62). Song
    # ID 63 and above are stored in DATA11-15 instead, but in an identical format. Each record
    # is 8 bytes long and can be found by multiplying the music ID by 8. To get to songs in the
    # second chunk, first subtract 63 from the song ID and then multiply that value by 8. The
    # first 4 bytes are the high score, stored in little-endian. The next byte is the combo
    # achieved. The next byte is always observed to be 0x04, and the one after that 0x00. Finally,
    # the last byte is the letter grade and full combo marker. Bit 4 set indicates the player
    # earned a full combo. Bits 3-1 are a 3 bit integer indicating the letter grade. Bit 0 is
    # unused. The game considers any letter grade other than 0 to be a pass.

    # The game stores records for each chart in a different DATAXX location. See the below chart
    # for exact storage locations. Note that yes, stealth and master are reversed from how they
    # are presented in game.
    #
    # DATA01/11 - Light
    # DATA02/12 - Standard
    # DATA03/13 - Extreme
    # DATA04/14 - Stealth
    # DATA05/15 - Master

    # The letter grades are believed to be as follows.
    #
    # 0 - Failed. Game displays a white gem to indicate the song was played.
    # 1 - E. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 2 - D. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 3 - C. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 4 - B. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 5 - A. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 6 - AA. Game displays a colored gem matching the chart to indicate the song was cleared.
    # 7 - AAA. Game displays a colored gem matching the chart to indicate the song was cleared.

    DATA01_CLASS_OFFSET: Final[int] = 2
    DATA01_GOLD_OFFSET: Final[int] = 3
    DATA01_NAME_OFFSET: Final[int] = 25
    DATA01_AREA_OFFSET: Final[int] = 26
    DATA01_SHOP_OFFSET: Final[int] = 27

    DATA02_DANCE_MATE_NAME_OFFSET: Final[int] = 25

    DATA03_DANCE_MATE_OFFSET: Final[int] = 8
    DATA03_FIRST_SONG_OFFSET: Final[int] = 13
    DATA03_FIRST_HIGH_SCORE_OFFSET: Final[int] = 14
    DATA03_SECOND_SONG_OFFSET: Final[int] = 15
    DATA03_SECOND_HIGH_SCORE_OFFSET: Final[int] = 16
    DATA03_THIRD_SONG_OFFSET: Final[int] = 17
    DATA03_THIRD_HIGH_SCORE_OFFSET: Final[int] = 18

    DATA04_TOTAL_SCORE_EARNED_OFFSET: Final[int] = 9

    GAME_GRADE_FAILED: Final[int] = 0
    GAME_GRADE_E: Final[int] = 1
    GAME_GRADE_D: Final[int] = 2
    GAME_GRADE_C: Final[int] = 3
    GAME_GRADE_B: Final[int] = 4
    GAME_GRADE_A: Final[int] = 5
    GAME_GRADE_AA: Final[int] = 6
    GAME_GRADE_AAA: Final[int] = 7

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {}

    def __update_shop_name(self, profiledata: bytes) -> None:
        # Figure out the profile type
        csvs = profiledata.split(b",")
        if len(csvs) < 2:
            # Not long enough to care about
            return
        datatype = csvs[1].decode("ascii")
        if datatype != "DATA01":
            # Not the right profile type requested
            return

        # Grab the shop name, which is offset based on storage, not based on the
        # game's sending this to us now.
        try:
            shopname = csvs[self.DATA01_SHOP_OFFSET + 2].decode("shift-jis")
        except Exception:
            return
        self.update_machine_name(shopname)

    def handle_tax_get_phase_request(self, request: Node) -> Node:
        tax = Node.void("tax")
        tax.add_child(Node.s32("phase", 0))
        return tax

    def handle_system_convcardnumber_request(self, request: Node) -> Node:
        cardid = request.child_value("data/card_id")
        cardnumber = CardCipher.encode(cardid)

        system = Node.void("system")
        data = Node.void("data")
        system.add_child(data)

        system.add_child(Node.s32("result", 0))
        data.add_child(Node.string("card_number", cardnumber))
        return system

    def handle_system_getmaster_request(self, request: Node) -> Node:
        # See if we can grab the request
        data = request.child("data")
        if not data:
            root = Node.void("system")
            root.add_child(Node.s32("result", 0))
            return root

        # Figure out what type of messsage this is
        reqtype = data.child_value("datatype")
        reqkey = data.child_value("datakey")  # noqa

        # System message
        root = Node.void("system")

        if reqtype == "S_SRVMSG":
            # Known keys include: INFO, ARK_ARR0, ARK_HAS0, SONGOPEN, IRDATA, EVTMSG3, WEEKLYSO
            strdata = ""

            root.add_child(Node.string("strdata1", base64.b64encode(strdata.encode("ascii")).decode("ascii")))
            root.add_child(Node.string("strdata2", ""))
            root.add_child(Node.u64("updatedate", Time.now() * 1000))
            root.add_child(Node.s32("result", 1))
        else:
            # Unknown message.
            root.add_child(Node.s32("result", 0))

        return root

    def handle_playerdata_usergamedata_recvscores_request(self, request: Node) -> Node:
        # NOTE: This is an entirely made up endpoint. The game does not call it. This exists
        # entirely to allow for client integration tests (trafficgen) to verify score saving
        # because otherwise there's no way to know that the backend actually parsed a score.
        playerdata = Node.void("playerdata")

        player = Node.void("player")
        playerdata.add_child(player)

        refid = request.child_value("data/refid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            scorecount = 0
            scores = Node.void("scores")
            player.add_child(scores)
            player.add_child(Node.string("refid", refid))

            for score in self.data.local.music.get_scores(self.game, self.version, userid):
                if score.chart not in {
                    self.CHART_TYPE_LIGHT,
                    self.CHART_TYPE_STANDARD,
                    self.CHART_TYPE_EXTREME,
                    self.CHART_TYPE_STEALTH,
                    self.CHART_TYPE_MASTER,
                }:
                    # Skip virtual scores for tracking play counts and popularity.
                    continue

                grade = {
                    self.GRADE_FAILED: self.GAME_GRADE_FAILED,
                    self.GRADE_E: self.GAME_GRADE_E,
                    self.GRADE_D: self.GAME_GRADE_D,
                    self.GRADE_C: self.GAME_GRADE_C,
                    self.GRADE_B: self.GAME_GRADE_B,
                    self.GRADE_A: self.GAME_GRADE_A,
                    self.GRADE_AA: self.GAME_GRADE_AA,
                    self.GRADE_AAA: self.GAME_GRADE_AAA,
                }[score.data.get_int("grade")]

                scorenode = Node.void("score")
                scorenode.add_child(Node.u16("id", score.id))
                scorenode.add_child(Node.u8("chart", score.chart))
                scorenode.add_child(Node.u32("points", score.points))
                scorenode.add_child(Node.u8("grade", grade))
                scorenode.add_child(Node.u8("combo", score.data.get_int("combo")))
                scorenode.add_child(Node.bool("full_combo", score.data.get_bool("full_combo")))
                scores.add_child(scorenode)
                scorecount += 1

            player.add_child(Node.u32("scores_num", scorecount))

        playerdata.add_child(Node.s32("result", 0))
        return playerdata

    def _to_hex(self, number: int) -> str:
        return hex(number)[2:]

    def handle_playerdata_usergamedata_recv_request(self, request: Node) -> Node:
        playerdata = Node.void("playerdata")

        player = Node.void("player")
        playerdata.add_child(player)

        refid = request.child_value("data/refid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
            links = self.data.local.user.get_links(self.game, self.version, userid)
            dancemates = len([l for l in links if l.type == "dancemate"])

            # Dancemates are extremely weird, the game doesn't seem to send the extid or refid of
            # the person you played with, only a space-padded representation of their name. So, we
            # store the name at lookup to correlate names back to profiles on save.
            if profile:
                name_padded = profile.get_str("name")
                while len(name_padded) < 10:
                    name_padded += "_"
                self.cache.set(name_padded.replace(" ", "_"), userid, timeout=30 * Time.SECONDS_IN_MINUTE)

            records = 0
            record = Node.void("record")
            player.add_child(record)

            def danevohex(val: int) -> str:
                return hex(val)[2:]

            if profile is None:
                # Figure out what profiles are being requested
                profiletypes = request.child_value("data/recv_csv").split(",")[::2]
                for ptype in profiletypes:
                    # Just return a default empty node
                    record.add_child(Node.string("d", "<NODATA>"))
                    records += 1

            else:
                # Figure out what profiles are being requested
                profiletypes = request.child_value("data/recv_csv").split(",")[::2]
                usergamedata = profile.get_dict("usergamedata")
                for ptype in profiletypes:
                    if ptype in usergamedata:
                        splits = usergamedata[ptype]["strdata"].split(b",")

                        if ptype == "DATA01":
                            # Common profile stuff.
                            splits[self.DATA01_NAME_OFFSET] = profile.get_str("name").encode("shift-jis")
                            splits[self.DATA01_AREA_OFFSET] = profile.get_str("area").encode("shift-jis")
                            splits[self.DATA01_CLASS_OFFSET] = self._to_hex(profile.get_int("class", 1)).encode(
                                "shift-jis"
                            )
                            splits[self.DATA01_GOLD_OFFSET] = self._to_hex(profile.get_int("gold", 0)).encode(
                                "shift-jis"
                            )
                        elif ptype == "DATA03":
                            # Dance mate stuff, and where scores come back.
                            splits[self.DATA03_DANCE_MATE_OFFSET] = self._to_hex(dancemates).encode("shift-jis")
                        elif ptype == "DATA04":
                            # Cumulative score.
                            splits[self.DATA04_TOTAL_SCORE_EARNED_OFFSET] = self._to_hex(
                                profile.get_int("cumulative_score", 0)
                            ).encode("shift-jis")

                        dnode = Node.string(
                            "d",
                            base64.b64encode(b",".join(splits)).decode("ascii"),
                        )
                        dnode.add_child(
                            Node.string(
                                "bin1",
                                base64.b64encode(usergamedata[ptype]["bindata"]).decode("ascii"),
                            )
                        )
                        record.add_child(dnode)

                    else:
                        # Just return a default empty node
                        record.add_child(Node.string("d", "<NODATA>"))

                    records += 1

            player.add_child(Node.u32("record_num", records))

        playerdata.add_child(Node.s32("result", 0))
        return playerdata

    def handle_playerdata_usergamedata_send_request(self, request: Node) -> Node:
        playerdata = Node.void("playerdata")
        refid = request.child_value("data/refid")

        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
            is_new = False
            if profile is None:
                profile = Profile(self.game, self.version, refid, 0)
                is_new = True
            usergamedata = profile.get_dict("usergamedata")

            for record in request.child("data/record").children:
                if record.name != "d":
                    continue

                strdata = base64.b64decode(record.value)
                bindata = base64.b64decode(record.child_value("bin1"))

                # Update the shop name if this is a new profile, since we know on new profiles that
                # this value came from the game itself.
                if is_new:
                    self.__update_shop_name(strdata)

                # Grab and format the profile objects
                strdatalist = strdata.split(b",")
                profiletype = strdatalist[1].decode("utf-8")
                strdatalist = strdatalist[2:]

                if profiletype == "DATA01":
                    # Extract relevant info so that it's in the profile normally.
                    profile.replace_str("name", strdatalist[self.DATA01_NAME_OFFSET].decode("shift-jis"))
                    profile.replace_int("class", int(strdatalist[self.DATA01_CLASS_OFFSET].decode("shift-jis"), 16))
                    profile.replace_int("gold", int(strdatalist[self.DATA01_GOLD_OFFSET].decode("shift-jis"), 16))
                    profile.replace_str("area", strdatalist[self.DATA01_AREA_OFFSET].decode("shift-jis"))

                elif profiletype == "DATA02":
                    # Extract possible dance mate and link it to the player.
                    potential_dancemate = strdatalist[self.DATA02_DANCE_MATE_NAME_OFFSET].decode("shift-jis")
                    potential_dancemate = potential_dancemate[:10]
                    if potential_dancemate.strip():
                        # First, try to find it in our cache.
                        other_userid = self.cache.get(potential_dancemate.replace(" ", "_"))
                        if other_userid:
                            self.data.local.user.put_link(
                                self.game, self.version, userid, "dancemate", other_userid, {"last_played": Time.now()}
                            )

                elif profiletype == "DATA04":
                    # Keep track of this for fun, because hey, why not?
                    profile.replace_int(
                        "cumulative_score",
                        int(strdatalist[self.DATA04_TOTAL_SCORE_EARNED_OFFSET].decode("shift-jis"), 16),
                    )

                usergamedata[profiletype] = {
                    "strdata": b",".join(strdatalist),
                    "bindata": bindata,
                }

            profile.replace_dict("usergamedata", usergamedata)
            profile.replace_int("write_time", Time.now())
            self.put_profile(userid, profile)

            # Keep track of play statistics across all versions, but don't do it for the initial profile save.
            if not is_new:
                self.update_play_statistics(userid)

            # Now that we've got a fully updated profile to look at, let's see if we can't extract the last played songs
            # and link those to records if they were a record.
            valid_ids = {song.id for song in self.data.local.music.get_all_songs(self.game, self.version)}

            # Grab the last three record blobs from the RDATA chunk if it exists.
            history: List[Dict[str, int]] = []

            if "RDAT01" in usergamedata:
                historydata = usergamedata["RDAT01"]["bindata"]
                if len(historydata) < 3 * 32:
                    historydata += b"\x00" * ((3 * 32) - len(historydata))

                for offset in range(0, 32 * 3, 32):
                    score, params, ts = struct.unpack("<IIQ", historydata[offset : (offset + 16)])
                    if not score and not params and not ts:
                        continue

                    chart = {
                        0: self.CHART_TYPE_LIGHT,
                        1: self.CHART_TYPE_STANDARD,
                        2: self.CHART_TYPE_EXTREME,
                        3: self.CHART_TYPE_STEALTH,
                        4: self.CHART_TYPE_MASTER,
                    }.get((params >> 8) & 0xF)
                    if chart is None:
                        continue

                    grade = {
                        self.GAME_GRADE_FAILED: self.GRADE_FAILED,
                        self.GAME_GRADE_E: self.GRADE_E,
                        self.GAME_GRADE_D: self.GRADE_D,
                        self.GAME_GRADE_C: self.GRADE_C,
                        self.GAME_GRADE_B: self.GRADE_B,
                        self.GAME_GRADE_A: self.GRADE_A,
                        self.GAME_GRADE_AA: self.GRADE_AA,
                        self.GAME_GRADE_AAA: self.GRADE_AAA,
                    }[(params >> 27) & 0x7]

                    history.append(
                        {
                            "id": params & 0xFF,
                            "chart": chart,
                            "score": score,
                            "grade": grade,
                            "combo": (params >> 12) & 0x3FF,
                            "fc": (params >> 30) & 0x3,
                            "ts": ts // 1000,
                        }
                    )

            if "DATA03" in usergamedata:
                strdatalist = usergamedata["DATA03"]["strdata"].split(b",")

                # First two are represented in the hex section.
                first_song_played = int(strdatalist[self.DATA03_FIRST_SONG_OFFSET].decode("shift-jis"), 16)
                second_song_played = int(strdatalist[self.DATA03_SECOND_SONG_OFFSET].decode("shift-jis"), 16)
                first_song_scored = int(strdatalist[self.DATA03_FIRST_HIGH_SCORE_OFFSET].decode("shift-jis"), 16)
                second_song_scored = int(strdatalist[self.DATA03_SECOND_HIGH_SCORE_OFFSET].decode("shift-jis"), 16)

                # They really just stuck this in as floats. I couldn't make this up.
                third_song_played = int(strdatalist[self.DATA03_THIRD_SONG_OFFSET].decode("shift-jis").split(".")[0])
                third_song_scored = int(
                    strdatalist[self.DATA03_THIRD_HIGH_SCORE_OFFSET].decode("shift-jis").split(".")[0]
                )

                songcount = 0
                for possible in [first_song_played, second_song_played, third_song_played]:
                    if possible in valid_ids:
                        songcount += 1

                # Scores are from newest to oldest.
                history = list(reversed(history[:songcount]))

                for stage, played, scored in [
                    (0, first_song_played, first_song_scored),
                    (1, second_song_played, second_song_scored),
                    (2, third_song_played, third_song_scored),
                ]:
                    if played not in valid_ids:
                        # Game might be set to 1 song.
                        continue

                    # Attempt to find the play in our extracted attempts.
                    if stage >= len(history):
                        continue
                    if history[stage]["id"] != played:
                        continue
                    if history[stage]["score"] != scored:
                        continue
                    attempt = history[stage]

                    # First, calculate whether we're going to look at DATA01-05 or DATA11-15.
                    if played < 63:
                        mapping = {
                            "DATA01": self.CHART_TYPE_LIGHT,
                            "DATA02": self.CHART_TYPE_STANDARD,
                            "DATA03": self.CHART_TYPE_EXTREME,
                            "DATA04": self.CHART_TYPE_STEALTH,
                            "DATA05": self.CHART_TYPE_MASTER,
                        }
                        offset = played * 8
                    else:
                        mapping = {
                            "DATA11": self.CHART_TYPE_LIGHT,
                            "DATA12": self.CHART_TYPE_STANDARD,
                            "DATA13": self.CHART_TYPE_EXTREME,
                            "DATA14": self.CHART_TYPE_STEALTH,
                            "DATA15": self.CHART_TYPE_MASTER,
                        }
                        offset = (played - 63) * 8

                    # Now, grab that data and offset into it to decode the record if it is there.
                    for key in mapping:
                        if key not in usergamedata:
                            # Haven't played any charts that filled this in, so the game never sent it, skip this
                            # because it couldn't possibly be it.
                            continue

                        if mapping[key] != attempt["chart"]:
                            # This isn't the right chart for what was played.
                            continue

                        # They could have played some other songs and the game truncated this because it
                        # only ever sends back until the last nonzero value, so we need to fill in the blanks
                        # so to speak with all zero bytes.
                        chunk = usergamedata[key]["bindata"][offset : (offset + 8)]
                        if len(chunk) < 8:
                            chunk = chunk + (b"\x00" * (8 - len(chunk)))

                        record, combo, playmarker, _, stats = struct.unpack("<Ibbbb", chunk)
                        if not playmarker:
                            # This wasn't actually played.
                            continue

                        self.update_score(
                            userid,
                            attempt["ts"],
                            attempt["id"],
                            attempt["chart"],
                            scored,
                            attempt["grade"],
                            attempt["combo"],
                            attempt["fc"] != 0,
                        )

                        # Don't need to update anything else now.
                        break

        playerdata.add_child(Node.s32("result", 0))
        return playerdata
