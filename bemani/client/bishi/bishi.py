import base64
import time
from typing import Optional

from bemani.client.base import BaseClient
from bemani.protocol import Node


class TheStarBishiBashiClient(BaseClient):
    NAME = "ＴＥＳＴ"

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
        data.add_child(Node.string("strdata1", "1.7.6"))
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

    def verify_system_getmaster(self) -> None:
        call = self.call_node()

        # Construct node
        system = Node.void("system")
        call.add_child(system)
        system.set_attribute("method", "getmaster")
        data = Node.void("data")
        system.add_child(data)
        data.add_child(Node.string("gamekind", "IBB"))
        data.add_child(Node.string("datatype", "S_SRVMSG"))
        data.add_child(Node.string("datakey", "INFO"))

        # Swap with server
        resp = self.exchange("", call)

        # Verify that response is correct
        self.assert_path(resp, "response/system/result")

    def verify_usergamedata_send(self, ref_id: str, msg_type: str) -> None:
        call = self.call_node()

        # Set up profile write
        profiledata = [
            b"ffffffff",
            b"IBBDAT00",
            b"1",
            b"0",
            b"0",
            b"0",
            b"0",
            b"0",
            b"e474c1b",
            b"0",
            b"0",
            b"ff",
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
            b"\x96\xa2\x90\xdd\x92\xe8",
            b"\x8d\x81\x8d`",
            b"",
            b"",
            b"",
        ]

        if msg_type == "new":
            # New profile gets blank name, because we save over it at the end of the round.
            profiledata[27] = b""
        elif msg_type == "existing":
            # Exiting profile gets our hardcoded name saved.
            profiledata[27] = self.NAME.encode("shift-jis")

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_send")
        playerdata.add_child(Node.u32("retrycnt", 0))

        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("eaid", ref_id))
        data.add_child(Node.string("gamekind", "IBB"))
        data.add_child(Node.u32("datanum", 1))
        record = Node.void("record")
        data.add_child(record)
        d = Node.string("d", base64.b64encode(b",".join(profiledata)).decode("ascii"))
        record.add_child(d)
        d.add_child(Node.string("bin1", ""))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")

    def verify_usergamedata_recv(self, ref_id: str) -> str:
        call = self.call_node()

        # Construct node
        playerdata = Node.void("playerdata")
        call.add_child(playerdata)
        playerdata.set_attribute("method", "usergamedata_recv")
        data = Node.void("data")
        playerdata.add_child(data)
        data.add_child(Node.string("eaid", ref_id))
        data.add_child(Node.string("gamekind", "IBB"))
        data.add_child(Node.u32("recv_num", 1))
        data.add_child(Node.string("recv_csv", "IBBDAT00,3fffffffff"))

        # Swap with server
        resp = self.exchange("", call)
        self.assert_path(resp, "response/playerdata/result")
        self.assert_path(resp, "response/playerdata/player/record/d/bin1")
        self.assert_path(resp, "response/playerdata/player/record_num")

        # Grab binary data, parse out name
        bindata = resp.child_value("playerdata/player/record/d")
        profiledata = base64.b64decode(bindata).split(b",")

        # We lob off the first two values in returning profile, so the name is offset by two
        return profiledata[25].decode("shift-jis")

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
        self.verify_system_getmaster()

        # Verify card registration and profile lookup
        if cardid is not None:
            card = cardid
        else:
            card = self.random_card()
            print(f"Generated random card ID {card} for use.")

        if cardid is None:
            self.verify_cardmng_inquire(
                card, msg_type="unregistered", paseli_enabled=paseli_enabled
            )
            ref_id = self.verify_cardmng_getrefid(card)
            if len(ref_id) != 16:
                raise Exception(
                    f"Invalid refid '{ref_id}' returned when registering card"
                )
            if ref_id != self.verify_cardmng_inquire(
                card, msg_type="new", paseli_enabled=paseli_enabled
            ):
                raise Exception(f"Invalid refid '{ref_id}' returned when querying card")
            # Bishi doesn't read a new profile, it just writes out CSV for a blank one
            self.verify_usergamedata_send(ref_id, msg_type="new")
        else:
            print("Skipping new card checks for existing card")
            ref_id = self.verify_cardmng_inquire(
                card, msg_type="query", paseli_enabled=paseli_enabled
            )

        # Verify pin handling and return card handling
        self.verify_cardmng_authpass(ref_id, correct=True)
        self.verify_cardmng_authpass(ref_id, correct=False)
        if ref_id != self.verify_cardmng_inquire(
            card, msg_type="query", paseli_enabled=paseli_enabled
        ):
            raise Exception(f"Invalid refid '{ref_id}' returned when querying card")

        if cardid is None:
            # Verify profile saving
            name = self.verify_usergamedata_recv(ref_id)
            if name != "":
                raise Exception("New profile has a name associated with it!")

            self.verify_usergamedata_send(ref_id, msg_type="existing")
            name = self.verify_usergamedata_recv(ref_id)
            if name != self.NAME:
                raise Exception("Existing profile has no name associated with it!")
        else:
            print("Skipping score checks for existing card")
