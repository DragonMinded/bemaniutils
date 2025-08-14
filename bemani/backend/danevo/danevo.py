import base64
from typing import Any, Dict

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

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {}

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
            root.add_child(Node.string("strdata1", ""))
            root.add_child(Node.string("strdata2", ""))
            root.add_child(Node.u64("updatedate", Time.now() * 1000))
            root.add_child(Node.s32("result", 1))
        else:
            # Unknown message.
            root.add_child(Node.s32("result", 0))

        return root

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
                        dnode = Node.string(
                            "d",
                            base64.b64encode(usergamedata[ptype]["strdata"]).decode("ascii"),
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
            profile = self.get_profile(userid) or Profile(self.game, self.version, refid, 0)
            usergamedata = profile.get_dict("usergamedata")

            for record in request.child("data/record").children:
                if record.name != "d":
                    continue

                strdata = base64.b64decode(record.value)
                bindata = base64.b64decode(record.child_value("bin1"))

                # Grab and format the profile objects
                strdatalist = strdata.split(b",")
                profiletype = strdatalist[1].decode("utf-8")
                strdatalist = strdatalist[2:]

                usergamedata[profiletype] = {
                    "strdata": b",".join(strdatalist),
                    "bindata": bindata,
                }

            profile.replace_dict("usergamedata", usergamedata)
            profile.replace_int("write_time", Time.now())
            self.put_profile(userid, profile)

        playerdata.add_child(Node.s32("result", 0))
        return playerdata
