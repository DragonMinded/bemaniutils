import base64
from typing import Any, Dict
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
    # The first 4 bytes of any history chunk are the score in little endian. The next byte is the
    # song ID. Note that the chart does not appear anywhere in this structure to my knowledge.
    # I have no idea what the rest of the bytes are, but most stay zeros and many are the same
    # no matter what.

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

    DATA03_FIRST_SONG_OFFSET: Final[int] = 13
    DATA03_FIRST_HIGH_SCORE_OFFSET: Final[int] = 14
    DATA03_SECOND_SONG_OFFSET: Final[int] = 15
    DATA03_SECOND_HIGH_SCORE_OFFSET: Final[int] = 16

    DATA04_TOTAL_SCORE_EARNED_OFFSET: Final[int] = 9

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
                            splits[self.DATA01_NAME_OFFSET] = profile.get_str("name").encode('shift-jis')
                            splits[self.DATA01_AREA_OFFSET] = profile.get_str("area").encode('shift-jis')
                            splits[self.DATA01_CLASS_OFFSET] = self._to_hex(profile.get_int("class", 1)).encode('shift-jis')
                            splits[self.DATA01_GOLD_OFFSET] = self._to_hex(profile.get_int("gold", 0)).encode('shift-jis')
                        elif ptype == "DATA04":
                            # Cumulative score.
                            splits[self.DATA04_TOTAL_SCORE_EARNED_OFFSET] = self._to_hex(profile.get_int("cumulative_score", 0)).encode('shift-jis')

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
                    profile.replace_str("name", strdatalist[self.DATA01_NAME_OFFSET].decode('shift-jis'))
                    profile.replace_int("class", int(strdatalist[self.DATA01_CLASS_OFFSET].decode('shift-jis'), 16))
                    profile.replace_int("gold", int(strdatalist[self.DATA01_GOLD_OFFSET].decode('shift-jis'), 16))
                    profile.replace_str("area", strdatalist[self.DATA01_AREA_OFFSET].decode('shift-jis'))
                elif profiletype == "DATA04":
                    # Keep track of this for fun, because hey, why not?
                    profile.replace_int("cumulative_score", int(strdatalist[self.DATA04_TOTAL_SCORE_EARNED_OFFSET].decode('shift-jis'), 16))

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

        playerdata.add_child(Node.s32("result", 0))
        return playerdata
