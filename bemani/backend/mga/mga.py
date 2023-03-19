# vim: set fileencoding=utf-8
import base64
from typing import List

from bemani.backend.mga.base import MetalGearArcadeBase
from bemani.backend.ess import EventLogHandler
from bemani.common import Profile, VersionConstants, Time
from bemani.data import UserID
from bemani.protocol import Node


class MetalGearArcade(
    EventLogHandler,
    MetalGearArcadeBase,
):
    name: str = "Metal Gear Arcade"
    version: int = VersionConstants.MGA

    def __update_shop_name(self, profiledata: bytes) -> None:
        # Figure out the profile type
        csvs = profiledata.split(b",")
        if len(csvs) < 2:
            # Not long enough to care about
            return
        datatype = csvs[1].decode("ascii")
        if datatype != "PLAYDATA":
            # Not the right profile type requested
            return

        # Grab the shop name
        try:
            shopname = csvs[30].decode("shift-jis")
        except Exception:
            return
        self.update_machine_name(shopname)

    def handle_system_getmaster_request(self, request: Node) -> Node:
        # See if we can grab the request
        data = request.child("data")
        if not data:
            root = Node.void("system")
            root.add_child(Node.s32("result", 0))
            return root

        # Figure out what type of messsage this is
        reqtype = data.child_value("datatype")
        reqkey = data.child_value("datakey")

        # System message
        root = Node.void("system")

        if reqtype == "S_SRVMSG" and reqkey == "INFO":
            # Generate system message
            settings1_str = "2011081000:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1"
            settings2_str = "1,1,1,1,1,1,1,1,1,1,1,1,1,1"

            # Send it to the client, making sure to inform the client that it was valid.
            root.add_child(
                Node.string(
                    "strdata1",
                    base64.b64encode(settings1_str.encode("ascii")).decode("ascii"),
                )
            )
            root.add_child(
                Node.string(
                    "strdata2",
                    base64.b64encode(settings2_str.encode("ascii")).decode("ascii"),
                )
            )
            root.add_child(Node.u64("updatedate", Time.now() * 1000))
            root.add_child(Node.s32("result", 1))
        else:
            # Unknown message.
            root.add_child(Node.s32("result", 0))

        return root

    def handle_playerdata_usergamedata_send_request(self, request: Node) -> Node:
        # Look up user by refid
        refid = request.child_value("data/eaid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root = Node.void("playerdata")
            root.add_child(
                Node.s32("result", 1)
            )  # Unclear if this is the right thing to do here.
            return root

        # Extract new profile info from old profile
        oldprofile = self.get_profile(userid)
        is_new = False
        if oldprofile is None:
            oldprofile = Profile(self.game, self.version, refid, 0)
            is_new = True
        newprofile = self.unformat_profile(userid, request, oldprofile, is_new)

        # Write new profile
        self.put_profile(userid, newprofile)

        # Return success!
        root = Node.void("playerdata")
        root.add_child(Node.s32("result", 0))
        return root

    def handle_playerdata_usergamedata_recv_request(self, request: Node) -> Node:
        # Look up user by refid
        refid = request.child_value("data/eaid")
        profiletypes = request.child_value("data/recv_csv").split(",")
        profile = None
        userid = None
        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
        if profile is not None:
            return self.format_profile(userid, profiletypes, profile)
        else:
            root = Node.void("playerdata")
            root.add_child(
                Node.s32("result", 1)
            )  # Unclear if this is the right thing to do here.
            return root

    def format_profile(
        self, userid: UserID, profiletypes: List[str], profile: Profile
    ) -> Node:
        root = Node.void("playerdata")
        root.add_child(Node.s32("result", 0))
        player = Node.void("player")
        root.add_child(player)
        records = 0
        record = Node.void("record")
        player.add_child(record)

        for profiletype in profiletypes:
            if profiletype == "3fffffffff":
                continue
            for j in range(len(profile["strdatas"])):
                strdata = profile["strdatas"][j]
                bindata = profile["bindatas"][j]

                # Figure out the profile type
                csvs = strdata.split(b",")
                if len(csvs) < 2:
                    # Not long enough to care about
                    continue
                datatype = csvs[1].decode("ascii")
                if datatype != profiletype:
                    # Not the right profile type requested
                    continue

                # This is a valid profile node for this type, lets return only the profile values
                strdata = b",".join(csvs[2:])
                d = Node.string("d", base64.b64encode(strdata).decode("ascii"))
                record.add_child(d)
                d.add_child(
                    Node.string("bin1", base64.b64encode(bindata).decode("ascii"))
                )

                # Remember that we had this record
                records = records + 1

        player.add_child(Node.u32("record_num", records))
        return root

    def unformat_profile(
        self, userid: UserID, request: Node, oldprofile: Profile, is_new: bool
    ) -> Profile:
        # Profile save request, data values are base64 encoded.
        # d is a CSV, and bin1 is binary data.
        newprofile = oldprofile.clone()
        strdatas: List[bytes] = []
        bindatas: List[bytes] = []

        record = request.child("data/record")
        for node in record.children:
            if node.name != "d":
                continue

            profile = base64.b64decode(node.value)
            # Update the shop name if this is a new profile, since we know it came
            # from this cabinet. This is the only source of truth for what the
            # cabinet shop name is set to.
            if is_new:
                self.__update_shop_name(profile)
            strdatas.append(profile)
            bindatas.append(base64.b64decode(node.child_value("bin1")))

        newprofile["strdatas"] = strdatas
        newprofile["bindatas"] = bindatas

        # Keep track of play statistics across all versions
        self.update_play_statistics(userid)

        return newprofile
