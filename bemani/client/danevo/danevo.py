import base64
import random
import struct
import time
from typing import Optional, Dict, List

from bemani.client.base import BaseClient
from bemani.protocol import Node


class DanceEvolutionClient(BaseClient):
    NAME1 = "ＴＥＳＴ"
    NAME2 = "ＯＴＨＥＲ"

    def verify_eventlog_write(self, location: str) -> None:
        call = self.call_node()

        # Construct node
        eventlog = Node.void("eventlog")
        call.add_child(eventlog)
        eventlog.set_attribute("method", "write")
        eventlog.add_child(Node.u32("retrycnt", 0))
        data = Node.void("data")
        eventlog.add_child(data)
        data.add_child(Node.string("eventid", "S_PWRON"))
        data.add_child(Node.s32("eventorder", 0))
        data.add_child(Node.u64("pcbtime", int(time.time() * 1000)))
        data.add_child(Node.s64("gamesession", -1))
        data.add_child(Node.string("strdata1", "2.3.4"))
        data.add_child(Node.string("strdata2", ""))
        data.add_child(Node.s64("numdata1", 1))
        data.add_child(Node.s64("numdata2", 0))
        data.add_child(Node.string("locationid", location))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/eventlog/gamesession")
        self.assert_path(resp, "response/eventlog/logsendflg")
        self.assert_path(resp, "response/eventlog/logerrlevel")
        self.assert_path(resp, "response/eventlog/evtidnosendflg")

    def verify_tax_get_phase(self) -> None:
        call = self.call_node()

        tax = Node.void("tax")
        call.add_child(tax)
        tax.set_attribute("method", "get_phase")

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/tax/phase")

    def verify_system_getmaster(self) -> None:
        for datakey in ["ARK_ARR0", "ARK_HAS0", "SONGOPEN", "INFO", "IRDATA", "EVTMSG3", "WEEKLYSO"]:
            call = self.call_node()

            system = Node.void("system")
            call.add_child(system)
            system.set_attribute("method", "getmaster")
            data = Node.void("data")
            system.add_child(data)
            data.add_child(Node.string("gamekind", "KDM"))
            data.add_child(Node.string("datatype", "S_SRVMSG"))
            data.add_child(Node.string("datakey", datakey))

            # Swap with server
            resp = self.exchange("", call)

            # Verify that response is correct
            self.assert_path(resp, "response/system/strdata1")
            self.assert_path(resp, "response/system/strdata2")
            self.assert_path(resp, "response/system/updatedate")
            self.assert_path(resp, "response/system/result")

    def verify_system_convcardnumber(self, cardno: str) -> None:
        call = self.call_node()

        # Construct node
        system = Node.void("system")
        call.add_child(system)
        system.set_attribute("method", "convcardnumber")
        info = Node.void("info")
        system.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        system.add_child(data)
        data.add_child(Node.string("card_id", cardno))
        data.add_child(Node.s32("card_type", 1))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/system/data/card_number")
        self.assert_path(resp, "response/system/result")

    def _get_base_profile_data(self, include_secondary: bool) -> Dict[str, List[bytes]]:
        profiledata = {
            "DATA01": [
                b"1",
                b"0",
                b"1",  # Class offset.
                b"0",  # Earned gold offset.
                b"0",
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",  # Name spot, will be filled in later.
                b"\x96\xa2\x90\xdd\x92\xe8",  # Area spot, hardcoded to "unset".
                b"",  # Arcade name spot, we don't send this in tests.
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "DATA02": [
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",  # Dance Mate name spot, will be filled in later.
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "DATA03": [
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",  # Number of dancemates, ignored on send.
                b"0",
                b"0",
                b"0",
                b"0",
                b"ffffffffffffffff",  # First song ID.
                b"ffffffffffffffff",  # First score ID.
                b"ffffffffffffffff",  # Second song ID.
                b"ffffffffffffffff",  # Second score ID.
                b"-1.000000",
                b"-1.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "DATA04": [
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",  # Total points earned cumulative.
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
            "RDAT01": [
                b"1",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"0.000000",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
                b"",
            ],
        }

        if include_secondary:
            for secondary in ["DATA05", "DATA11", "DATA12", "DATA13", "DATA14", "DATA15"]:
                profiledata[secondary] = [
                    b"1",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"0.000000",
                    b"",
                    b"",
                    b"",
                    b"",
                    b"",
                    b"",
                    b"",
                    b"",
                ]

        return profiledata

    def verify_usergamedata_send(self, ref_id: str, name: str, othername: str, msg_type: str) -> None:
        call = self.call_node()

        # Set up profile write
        profiledata = self._get_base_profile_data(False)

        if msg_type == "new":
            # New profile gets blank name, because we save over it at the end of the round.
            profiledata["DATA01"][2] = b"1"
            profiledata["DATA01"][3] = b"0"
            profiledata["DATA01"][25] = b""

            # New profile gets blank dance mate no matter what.
            profiledata["DATA02"][25] = b""

        elif msg_type == "existing":
            # Existing profile gets our hardcoded name saved.
            profiledata["DATA01"][2] = b"3"
            profiledata["DATA01"][3] = b"145"
            profiledata["DATA01"][25] = name.encode("shift-jis")

            # Existing profile also gets hardcoded other name if present.
            if othername:
                while len(othername) < 10:
                    othername = othername + " "
                profiledata["DATA02"][25] = othername.encode("shift-jis")
            else:
                profiledata["DATA02"][25] = b""

        else:
            raise Exception(f"Unknown message type {msg_type}!")

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_send")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "KDM"))
        data.add_child(Node.u32("datanum", len(profiledata.keys())))
        record = Node.void("record")
        data.add_child(record)
        for ptype in profiledata:
            profile = [b"ffffffff", ptype.encode("shift-jis")] + profiledata[ptype]
            d = Node.string("d", base64.b64encode(b",".join(profile)).decode("ascii"))
            d.add_child(Node.string("bin1", ""))
            record.add_child(d)

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")

    def verify_usergamedata_recv(self, ref_id: str) -> Dict[str, object]:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_recv")
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "KDM"))
        data.add_child(Node.u32("recv_num", 11))
        data.add_child(
            Node.string(
                "recv_csv",
                "DATA01,3fffffffff,DATA02,3fffffffff,DATA03,3fffffffff,DATA04,3fffffffff,DATA05,3fffffffff,RDAT01,3fffffffff,DATA11,3fffffffff,DATA12,3fffffffff,DATA13,3fffffffff,DATA14,3fffffffff,DATA15,3fffffffff",
            )
        )

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")
        self.assert_path(resp, "response/playerdata/player/record/d/bin1")
        self.assert_path(resp, "response/playerdata/player/record_num")

        profiles = 0
        name = ""
        gold = 0
        cls = 0
        dancemates = 0
        total_score = 0

        for child in resp.child("playerdata/player/record").children:
            if child.name != "d":
                continue

            bindata = child.value
            if bindata != "<NODATA>":
                profiledata = base64.b64decode(bindata).split(b",")

                if profiles == 0:
                    cls = int(profiledata[2].decode("shift-jis"), 16)
                    gold = int(profiledata[3].decode("shift-jis"), 16)
                    name = profiledata[25].decode("shift-jis")
                if profiles == 2:
                    dancemates = int(profiledata[8].decode("shift-jis"), 16)
                if profiles == 3:
                    total_score = int(profiledata[9].decode("shift-jis"), 16)

            profiles = profiles + 1

        if profiles != 11:
            raise Exception("Didn't receive all 11 profiles in the right order!")

        return {
            "name": name,
            "gold": gold,
            "class": cls,
            "dancemates": dancemates,
            "total_score": total_score,
        }

    def verify_scores_send(self, ref_id: str, name: str, scores: List[Dict[str, int]]) -> None:
        if len(scores) > 3:
            raise Exception("DanEvo can only save two scores at once!")

        # This is identical to usergamedata_send, but the function was getting out of hand.
        call = self.call_node()

        # Set up profile write
        profiledata = self._get_base_profile_data(True)

        # Existing profile gets our hardcoded name saved.
        profiledata["DATA01"][2] = b"3"
        profiledata["DATA01"][3] = b"145"
        profiledata["DATA01"][25] = name.encode("shift-jis")
        profiledata["DATA02"][25] = b""

        attempts: bytes = b""
        spots: Dict[int, Dict[int, bytes]] = {}
        highest_id: int = 0

        def _to_hex(number: int) -> bytes:
            return hex(number)[2:].encode("shift-jis")

        for offset, score in enumerate(scores):
            sid = score["id"]
            chart = score["chart"]
            if chart not in spots:
                spots[chart] = {}
            spots[chart][sid] = struct.pack(
                "<Ibbbb",
                score["points"],
                score["combo"],
                0x04,
                0x00,
                (score["grade"] << 1) + (0x10 if score["full_combo"] else 0x00),
            )

            highest_id = max(highest_id, sid)

            # Game won't save unless we put things in the right spot.
            if offset == 0:
                profiledata["DATA03"][13] = _to_hex(sid)
                profiledata["DATA03"][14] = _to_hex(score["points"])
            elif offset == 1:
                profiledata["DATA03"][15] = _to_hex(sid)
                profiledata["DATA03"][16] = _to_hex(score["points"])
            elif offset == 2:
                profiledata["DATA03"][17] = str(float(sid)).encode("shift-jis")
                profiledata["DATA03"][18] = str(float(score["points"])).encode("shift-jis")
            else:
                raise Exception("Logic error, can't save more than three scores!")

            # Game won't save unless we have an attempt in RDAT01 as well.
            params = (
                ((sid & 0xFF) << 0)
                | ((chart & 0xF) << 8)
                | ((score["combo"] & 0x3FF) << 12)
                | ((score["grade"] & 0x7) << 27)
                | (0x40000000 if score["full_combo"] else 0x00000000)
            )

            chunk = struct.pack("<IIQ", score["points"], params, int(time.time() * 1000)) + (b"\x00" * 16)
            attempts = chunk + attempts

        # Make binary data blobs.
        blobs: Dict[int, bytes] = {}
        for chart in [0, 1, 2, 3, 4]:
            bdata: List[bytes] = []

            for sid in range(highest_id + 1):
                bdata.append(spots.get(chart, {}).get(sid, b"\x00" * 8))

            blobs[chart] = b"".join(bdata)

        def trimnulls(data: bytes) -> bytes:
            # The game only sends as many bytes as it needs, truncating nulls after
            # the last non-null.
            while data and (data[-1] == 0):
                data = data[:-1]
            return data

        # Split it by profile type.
        profilebindata = {
            "DATA01": trimnulls(blobs[0][:504]),
            "DATA02": trimnulls(blobs[1][:504]),
            "DATA03": trimnulls(blobs[2][:504]),
            "DATA04": trimnulls(blobs[3][:504]),
            "DATA05": trimnulls(blobs[4][:504]),
            "DATA11": trimnulls(blobs[0][504:]),
            "DATA12": trimnulls(blobs[1][504:]),
            "DATA13": trimnulls(blobs[2][504:]),
            "DATA14": trimnulls(blobs[3][504:]),
            "DATA15": trimnulls(blobs[4][504:]),
            "RDAT01": trimnulls(attempts),
        }

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_send")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "KDM"))
        data.add_child(Node.u32("datanum", len(profiledata.keys())))
        record = Node.void("record")
        data.add_child(record)
        for ptype in profiledata:
            profile = [b"ffffffff", ptype.encode("shift-jis")] + profiledata[ptype]
            d = Node.string("d", base64.b64encode(b",".join(profile)).decode("ascii"))
            d.add_child(Node.string("bin1", base64.b64encode(profilebindata[ptype]).decode("ascii")))
            record.add_child(d)

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")

    def verify_scores_recv(self, ref_id: str) -> List[Dict[str, int]]:
        # Note that this uses a completely made up endpoint because otherwise the game
        # completely client-side manages high scores, and we just extract them for display
        # on the front-end. Maybe we should have gone the whole way and round-tripped scores
        # by regenerating the binary record nodes? But it's unclear what some of the values
        # could be and finding the code that generates the score blobs is next to impossible.
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_recvscores")
        playerdata.add_child(Node.u32("retrycnt", 0))
        info = Node.void("info")
        playerdata.add_child(info)
        info.add_child(Node.s32("version", 1))
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("refid", ref_id))
        data.add_child(Node.string("dataid", ref_id))
        data.add_child(Node.string("gamekind", "KDM"))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")

        scores: List[Dict[str, int]] = []
        for child in resp.child("playerdata/player/scores").children:
            if child.name != "score":
                continue

            score: Dict[str, int] = {}
            score["id"] = child.child_value("id")
            score["chart"] = child.child_value("chart")
            score["points"] = child.child_value("points")
            score["grade"] = child.child_value("grade")
            score["combo"] = child.child_value("combo")
            score["full_combo"] = 1 if child.child_value("full_combo") else 0

            scores.append(score)

        return scores

    def verify(self, cardid: Optional[str]) -> None:
        # Verify boot sequence is okay
        self.verify_services_get(
            expected_services=[
                "pcbtracker",
                "pcbevent",
                "local",
                "message",
                "facility",
                "cardmng",
                "package",
                "posevent",
                "pkglist",
                "dlstatus",
                "eacoin",
                "lobby",
                "ntp",
                "keepalive",
            ]
        )
        paseli_enabled = self.verify_pcbtracker_alive()
        self.verify_message_get()
        self.verify_package_list()
        location = self.verify_facility_get()
        self.verify_pcbevent_put()
        self.verify_eventlog_write(location)
        self.verify_tax_get_phase()
        self.verify_system_getmaster()

        # Verify card registration and profile lookup
        if cardid is not None:
            card = cardid
            card2 = None
        else:
            card = self.random_card()
            card2 = self.random_card()
            print(f"Generated random card IDs {card} and {card} for use.")

        if cardid is None:
            self.verify_cardmng_inquire(card, msg_type="unregistered", paseli_enabled=paseli_enabled)
            self.verify_system_convcardnumber(card)

            ref_id = self.verify_cardmng_getrefid(card)
            if len(ref_id) != 16:
                raise Exception(f"Invalid refid '{ref_id}' returned when registering card")
            if ref_id != self.verify_cardmng_inquire(card, msg_type="new", paseli_enabled=paseli_enabled):
                raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

            self.verify_usergamedata_send(ref_id, self.NAME1, "", "new")
            deets = self.verify_usergamedata_recv(ref_id)
            if deets["name"] != "":
                raise Exception("Name stored on profile we just created!")
            if deets["dancemates"] != 0:
                raise Exception("Dance mates on profile we just created!")
            if deets["total_score"] != 0:
                raise Exception("Total score on profile we just created!")
            if deets["gold"] != 0:
                raise Exception("Gold on profile we just created!")
            if deets["class"] != 1:
                raise Exception("Class on profile we just created!")

            self.verify_usergamedata_send(ref_id, self.NAME1, "", "existing")
            deets = self.verify_usergamedata_recv(ref_id)
            if deets["name"] != self.NAME1:
                raise Exception("Name stored on profile we just created!")
            if deets["dancemates"] != 0:
                raise Exception("Dance mates on profile we just created!")
            if deets["total_score"] != 0:
                raise Exception("Total score on profile we just created!")
            if deets["gold"] != 325:
                raise Exception("Gold on profile we just created!")
            if deets["class"] != 3:
                raise Exception("Class on profile we just created!")
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled)

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(card, msg_type="query", paseli_enabled=paseli_enabled):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        if card2 is not None:
            # Create a second profile so we can be dance mates with it.
            other_ref_id = self.verify_cardmng_getrefid(card2)
            self.verify_usergamedata_send(other_ref_id, self.NAME2, "", "new")
            self.verify_usergamedata_send(other_ref_id, self.NAME2, "", "existing")
            self.verify_usergamedata_recv(other_ref_id)

            # Now, have both be dance mates of each other, one at a time.
            self.verify_usergamedata_send(ref_id, self.NAME1, self.NAME2, "existing")
            deets = self.verify_usergamedata_recv(ref_id)
            if deets["name"] != self.NAME1:
                raise Exception("Unexpected name in bagging area!")
            if deets["dancemates"] != 1:
                raise Exception("Didn't make best friends with other profile!")

            deets = self.verify_usergamedata_recv(other_ref_id)
            if deets["name"] != self.NAME2:
                raise Exception("Unexpected name in bagging area!")
            if deets["dancemates"] != 0:
                raise Exception("Shouldn't have a dance mate yet, we didn't save this profile!")

            # And the second one.
            self.verify_usergamedata_send(other_ref_id, self.NAME2, self.NAME1, "existing")
            deets = self.verify_usergamedata_recv(ref_id)
            if deets["name"] != self.NAME1:
                raise Exception("Unexpected name in bagging area!")
            if deets["dancemates"] != 1:
                raise Exception("Didn't make best friends with other profile!")

            deets = self.verify_usergamedata_recv(other_ref_id)
            if deets["name"] != self.NAME2:
                raise Exception("Unexpected name in bagging area!")
            if deets["dancemates"] != 1:
                raise Exception("Didn't make best friends with other profile!")

        if cardid is None:
            scores = self.verify_scores_recv(ref_id)
            if len(scores) > 0:
                raise Exception("Created profile should have no scores associated!")

            # Verify score saving and updating
            for phase in [1, 2]:
                if phase == 1:
                    dummyscores = [
                        # An okay score on a chart
                        {
                            "id": 10,
                            "chart": 4,
                            "grade": 4,
                            "combo": 25,
                            "points": 765432,
                            "full_combo": 0,
                        },
                        # A good score on an easier chart of the same song
                        {
                            "id": 10,
                            "chart": 2,
                            "grade": 6,
                            "combo": 45,
                            "points": 876543,
                            "full_combo": 0,
                        },
                        # A bad score on a hard chart
                        {
                            "id": 87,
                            "chart": 2,
                            "grade": 3,
                            "combo": 5,
                            "points": 654321,
                            "full_combo": 0,
                        },
                        # A terrible score on an easy chart
                        {
                            "id": 89,
                            "chart": 1,
                            "grade": 0,
                            "combo": 1,
                            "points": 123456,
                            "full_combo": 0,
                        },
                    ]
                if phase == 2:
                    dummyscores = [
                        # A better score on the same chart
                        {
                            "id": 10,
                            "chart": 4,
                            "grade": 5,
                            "combo": 99,
                            "points": 888888,
                            "full_combo": 1,
                        },
                        # A worse score on another same chart
                        {
                            "id": 87,
                            "chart": 2,
                            "grade": 1,
                            "combo": 3,
                            "points": 543210,
                            "full_combo": 0,
                            "expected_points": 654321,
                            "expected_grade": 3,
                            "expected_combo": 5,
                        },
                    ]

                scorechunks = [dummyscores[x : (x + 3)] for x in range(0, len(dummyscores), 3)]

                for chunk in scorechunks:
                    self.verify_scores_send(ref_id, self.NAME1, chunk)

                scores = self.verify_scores_recv(ref_id)
                if len(scores) == 0:
                    raise Exception("Expected some scores after saving!")

                for expected in dummyscores:
                    actual = None
                    for received in scores:
                        if received["id"] == expected["id"] and received["chart"] == expected["chart"]:
                            actual = received
                            break

                    if actual is None:
                        raise Exception(f"Didn't find song {expected['id']} chart {expected['chart']} in response!")

                    if "expected_points" in expected:
                        expected_score = expected["expected_points"]
                    else:
                        expected_score = expected["points"]
                    if "expected_grade" in expected:
                        expected_grade = expected["expected_grade"]
                    else:
                        expected_grade = expected["grade"]
                    if "expected_combo" in expected:
                        expected_combo = expected["expected_combo"]
                    else:
                        expected_combo = expected["combo"]
                    if "expected_full_combo" in expected:
                        expected_full_combo = expected["expected_full_combo"]
                    else:
                        expected_full_combo = expected["full_combo"]

                    if actual["points"] != expected_score:
                        raise Exception(
                            f'Expected a score of \'{expected_score}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got score \'{actual["points"]}\''
                        )
                    if actual["grade"] != expected_grade:
                        raise Exception(
                            f'Expected a grade of \'{expected_grade}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got grade \'{actual["grade"]}\''
                        )
                    if actual["combo"] != expected_combo:
                        raise Exception(
                            f'Expected a combo of \'{expected_combo}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got combo \'{actual["combo"]}\''
                        )
                    if actual["full_combo"] != expected_full_combo:
                        raise Exception(
                            f'Expected a full_combo of \'{expected_full_combo}\' for song \'{expected["id"]}\' chart \'{expected["chart"]}\' but got full_combo \'{actual["full_combo"]}\''
                        )

                # Sleep so we don't end up putting in score history on the same second
                time.sleep(1)
        else:
            print("Skipping score checks for existing card")

        # Verify paseli handling
        if paseli_enabled:
            print("PASELI enabled for this PCBID, executing PASELI checks")
        else:
            print("PASELI disabled for this PCBID, skipping PASELI checks")
            return

        sessid, balance = self.verify_eacoin_checkin(card)
        if balance == 0:
            print("Skipping PASELI consume check because card has 0 balance")
        else:
            self.verify_eacoin_consume(sessid, balance, random.randint(0, balance))
        self.verify_eacoin_checkout(sessid)
