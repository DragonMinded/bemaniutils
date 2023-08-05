# vim: set fileencoding=utf-8
import base64
from typing import List

from bemani.backend.mga.base import MetalGearArcadeBase
from bemani.backend.ess import EventLogHandler
from bemani.common import ID, Profile, VersionConstants, Time
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

    def handle_playerdata_usergamedata_scorerank_request(self, request: Node) -> Node:
        # Not sure what this should do, looked like a thing to look up global rank
        # but it doesn't always send the player's ID, so possibly useless?
        #
        # The request looks like this:
        # <playerdata method="usergamedata_scorerank">
        #     <data>
        #         <eaid __type="str"></eaid>
        #         <gamekind __type="str">I36</gamekind>
        #         <vkey __type="str"></vkey>
        #         <conditionkey __type="str">HISTATTR</conditionkey>
        #         <score __type="s64">-1</score>
        #     </data>
        # </playerdata>
        root = Node.void("playerdata")
        root.add_child(Node.s32("result", 1))

        rank = Node.void("rank")
        root.add_child(rank)
        rank.add_child(Node.s32("rank", -1))
        rank.add_child(Node.u64("updatetime", Time.now() * 1000))
        return root

    def handle_matching_request_request(self, request: Node) -> Node:
        # Stand up this client as a possible matching host in the future.
        refid = request.child_value("data/eaid")
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root = Node.void("matching")
            root.add_child(
                Node.s32("result", 1)
            )  # Set to guest mode so matching doesn't happen.
            return root

        # Create a lobby with this player as the "host".
        shop_id = ID.parse_machine_id(request.child_value("data/locationid"))
        self.data.local.lobby.put_lobby(
            self.game,
            self.version,
            userid,
            {
                "matchgrp": request.child_value("data/matchgrp"),
                "joinip": request.child_value("data/joinip"),
                "joinport": request.child_value("data/joinport"),
                "localip": request.child_value("data/localip"),
                "localport": request.child_value("data/localport"),
                "waituser": request.child_value("data/waituser"),
                "waittime": request.child_value("data/waittime"),
                "pcbid": self.config.machine.pcbid,
                "lid": shop_id,
            },
        )
        lobby = self.data.local.lobby.get_lobby(
            self.game,
            self.version,
            userid,
        )

        # Now that we've created a lobby for ourselves, tell the game about our host ID.
        root = Node.void("matching")
        root.add_child(
            Node.s32("result", 0)
        )  # Setting this to 1 makes the game think we're a guest instead of host.
        root.add_child(Node.s64("hostid", lobby.get_int("id")))
        root.add_child(Node.string("hostip_g", lobby.get_str("joinip")))
        root.add_child(Node.s32("hostport_g", lobby.get_int("joinport")))
        root.add_child(Node.string("hostip_l", lobby.get_str("localip")))
        root.add_child(Node.s32("hostport_l", lobby.get_int("localport")))
        return root

    def handle_matching_wait_request(self, request: Node) -> Node:
        # Tell the client about up to 8 additional hosts that could be paired to us.

        # If we want to only match against hosts in this shop, this is what we'd use to do it.
        host_id = request.child_value("data/hostid")
        shop_id = ID.parse_machine_id(request.child_value("data/locationid"))

        # List all lobbies out, up to 8 of them. It's unclear whether the game wants to know
        # about it's own lobby or not.
        lobbies = self.data.local.lobby.get_all_lobbies(self.game, self.version)
        lobbycount = 0

        root = Node.void("matching")
        root.add_child(Node.s32("result", 0))
        root.add_child(Node.s32("prwtime", 60))
        matchlist = Node.void("matchlist")
        root.add_child(matchlist)

        for _, lobby in lobbies:
            # TODO: Possibly filter by only locationid matching, if this is enabled
            # in server operator settings.

            record = Node.void("record")
            record.add_child(Node.string("pcbid", lobby.get_str("pcbid")))
            record.add_child(Node.string("statusflg", ""))
            record.add_child(Node.s32("matchgrp", lobby.get_int("matchgrp")))
            record.add_child(Node.s64("hostid", host_id))
            record.add_child(Node.u64("jointime", lobby.get_int("time") * 1000))
            record.add_child(Node.string("connip_g", lobby.get_str("joinip")))
            record.add_child(Node.s32("connport_g", lobby.get_int("joinport")))
            record.add_child(Node.string("connip_l", lobby.get_str("localip")))
            record.add_child(Node.s32("connport_l", lobby.get_int("localport")))
            matchlist.add_child(record)

            lobbycount += 1
            if lobbycount >= 8:
                break

        matchlist.add_child(Node.u32("record_num", lobbycount))

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
