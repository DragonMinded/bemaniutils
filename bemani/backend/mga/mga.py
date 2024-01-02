# vim: set fileencoding=utf-8
import base64
import random
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
            settings1_str = (
                "2011081000:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1"
            )
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
            root.add_child(Node.s32("result", 1))  # Unclear if this is the right thing to do here.
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
            root.add_child(Node.s32("result", 1))  # Unclear if this is the right thing to do here.
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
            root.add_child(Node.s32("result", -1))  # Set to error so matching doesn't happen.
            return root

        # Game sends how long it intends to wait, so we should use that.
        wait_time = request.child_value("data/waittime")

        # Look up active lobbies, see if there was a previous one for us.
        # Matchmaking takes at most 60 seconds, so assume any lobbies older
        # than this are dead.
        lobbies = self.data.local.lobby.get_all_lobbies(self.game, self.version, max_age=wait_time)
        previous_hosted_lobbies = [True for uid, _ in lobbies if uid == userid]
        previous_joined_lobbies = [(uid, lobby) for uid, lobby in lobbies if userid in lobby["participants"]]

        # See if there's a random lobby we can be slotted into. Don't choose potentially
        # our old one, since it will be overwritten by a new entry, if we were ever a host.
        nonfull_lobbies = [(uid, lobby) for uid, lobby in lobbies if len(lobby["participants"]) < lobby["lobbysize"]]

        # Make sure to put our session information somewhere that we can find again.
        self.data.local.lobby.put_play_session_info(
            self.game,
            self.version,
            userid,
            {
                "joinip": request.child_value("data/joinip"),
                "joinport": request.child_value("data/joinport"),
                "localip": request.child_value("data/localip"),
                "localport": request.child_value("data/localport"),
                "pcbid": self.config.machine.pcbid,
            },
        )

        play_session_info = self.data.local.lobby.get_play_session_info(
            self.game,
            self.version,
            userid,
        )

        if (nonfull_lobbies or previous_joined_lobbies) and not previous_hosted_lobbies:
            if previous_joined_lobbies:
                # If we're already "in" a lobby, we should go back to that one.
                uid, lobby = previous_joined_lobbies[0]
            else:
                # Pick a random one, assign ourselves to it.
                uid, lobby = random.choice(nonfull_lobbies)

            # Look up the host's information.
            host_play_session_info = self.data.local.lobby.get_play_session_info(
                self.game,
                self.version,
                uid,
            )

            # Join this lobby.
            participants = set(lobby["participants"])
            participants.add(userid)
            lobby["participants"] = list(participants)
            self.data.local.lobby.put_lobby(self.game, self.version, uid, lobby)

            # Now that we've joined the lobby, tell the game about our host ID.
            root = Node.void("matching")
            root.add_child(
                Node.s32("result", 1)
            )  # Setting this to 1 makes the client consider itself a guest and join a host.
            root.add_child(Node.s64("hostid", lobby.get_int("id")))
            root.add_child(Node.string("hostip_g", host_play_session_info.get_str("joinip")))
            root.add_child(Node.s32("hostport_g", host_play_session_info.get_int("joinport")))
            root.add_child(Node.string("hostip_l", host_play_session_info.get_str("localip")))
            root.add_child(Node.s32("hostport_l", host_play_session_info.get_int("localport")))
            return root

        # The game does weird things if you let it wait as long as its own countdown,
        # so subtract a bit of wiggle-room from the wait time as reported by the game.
        wait_time -= 1

        # Create a lobby with this player as the "host", since there are no non-full lobbies
        # or we were previously a host and want to be one again.
        self.data.local.lobby.put_lobby(
            self.game,
            self.version,
            userid,
            {
                "matchgrp": request.child_value("data/matchgrp"),
                "lobbysize": request.child_value("data/waituser"),
                "waittime": wait_time,
                "createtime": Time.now(),
                "participants": [userid],
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
        )  # Setting this to 0 makes the client consider itself a host and listen for guests.
        root.add_child(Node.s64("hostid", lobby.get_int("id")))
        root.add_child(Node.string("hostip_g", play_session_info.get_str("joinip")))
        root.add_child(Node.s32("hostport_g", play_session_info.get_int("joinport")))
        root.add_child(Node.string("hostip_l", play_session_info.get_str("localip")))
        root.add_child(Node.s32("hostport_l", play_session_info.get_int("localport")))
        return root

    def handle_matching_wait_request(self, request: Node) -> Node:
        host_id = request.child_value("data/hostid")

        # List all lobbies out, find the one that we're either a host or a guest of.
        lobbies = self.data.local.lobby.get_all_lobbies(self.game, self.version)
        info_by_uid = {
            uid: data for uid, data in self.data.local.lobby.get_all_play_session_infos(self.game, self.version)
        }

        # We should be able to filter by host_id that the game gave us.
        joined_lobby = [(uid, lobby) for uid, lobby in lobbies if lobby.get_int("id") == host_id]
        if len(joined_lobby) != 1:
            # This shouldn't happen.
            root = Node.void("matching")
            root.add_child(Node.s32("result", -1))
            return root

        # Calculate creation time, figure out when to join the match after that.
        host_uid, lobby = joined_lobby[0]
        time_left = max(lobby.get_int("waittime") - (Time.now() - lobby.get_int("createtime")), 0)

        root = Node.void("matching")
        root.add_child(Node.s32("result", 0 if time_left > 0 else 1))  # We send 1 to start the match.
        root.add_child(Node.s32("prwtime", time_left))
        matchlist = Node.void("matchlist")
        root.add_child(matchlist)

        playercount = 0
        for uid in lobby["participants"]:
            # Grab player-specific IPs and stuff.
            if uid not in info_by_uid:
                continue
            uinfo = info_by_uid[uid]

            # Technically, the game only takes up to 8 of these records, but we only
            # let users join the lobbies based on the size that the game requests. So,
            # we don't need to worry about that.
            playercount += 1

            record = Node.void("record")
            record.add_child(Node.string("pcbid", uinfo.get_str("pcbid")))
            record.add_child(Node.string("statusflg", ""))
            record.add_child(Node.s32("matchgrp", lobby.get_int("matchgrp")))
            record.add_child(Node.s64("hostid", lobby.get_int("id")))
            record.add_child(Node.u64("jointime", uinfo.get_int("time") * 1000))
            record.add_child(Node.string("connip_g", uinfo.get_str("joinip")))
            record.add_child(Node.s32("connport_g", uinfo.get_int("joinport")))
            record.add_child(Node.string("connip_l", uinfo.get_str("localip")))
            record.add_child(Node.s32("connport_l", uinfo.get_int("localport")))
            matchlist.add_child(record)

        matchlist.add_child(Node.u32("record_num", playercount))

        return root

    def format_profile(self, userid: UserID, profiletypes: List[str], profile: Profile) -> Node:
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
                d.add_child(Node.string("bin1", base64.b64encode(bindata).decode("ascii")))

                # Remember that we had this record
                records = records + 1

        player.add_child(Node.u32("record_num", records))
        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: Profile, is_new: bool) -> Profile:
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
