# vim: set fileencoding=utf-8
import binascii
import copy
import base64
from typing import Any, Dict, List

from bemani.backend.bishi.base import BishiBashiBase
from bemani.backend.ess import EventLogHandler
from bemani.common import ValidatedDict, GameConstants, VersionConstants
from bemani.data import UserID
from bemani.protocol import Node


class TheStarBishiBashi(
    EventLogHandler,
    BishiBashiBase,
):

    name = "The★BishiBashi"
    version = VersionConstants.BISHI_BASHI_TSBB

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            'bools': [
                {
                    'name': 'Force Unlock Characters',
                    'tip': 'Force unlock all characters on select screen.',
                    'category': 'game_config',
                    'setting': 'force_unlock_characters',
                },
            ],
        }

    def __update_shop_name(self, profiledata: bytes) -> None:
        # Figure out the profile type
        csvs = profiledata.split(b',')
        if len(csvs) < 2:
            # Not long enough to care about
            return
        datatype = csvs[1].decode('ascii')
        if datatype != 'IBBDAT00':
            # Not the right profile type requested
            return

        # Grab the shop name
        try:
            shopname = csvs[30].decode('shift-jis')
        except Exception:
            return
        self.update_machine_name(shopname)

    def handle_system_getmaster_request(self, request: Node) -> Node:
        # System message
        root = Node.void('system')
        root.add_child(Node.s32('result', 0))
        return root

    def handle_playerdata_usergamedata_send_request(self, request: Node) -> Node:
        # Look up user by refid
        refid = request.child_value('data/eaid')
        userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is None:
            root = Node.void('playerdata')
            root.add_child(Node.s32('result', 1))  # Unclear if this is the right thing to do here.
            return root

        # Extract new profile info from old profile
        oldprofile = self.get_profile(userid)
        is_new = False
        if oldprofile is None:
            oldprofile = ValidatedDict()
            is_new = True
        newprofile = self.unformat_profile(userid, request, oldprofile, is_new)

        # Write new profile
        self.put_profile(userid, newprofile)

        # Return success!
        root = Node.void('playerdata')
        root.add_child(Node.s32('result', 0))
        return root

    def handle_playerdata_usergamedata_recv_request(self, request: Node) -> Node:
        # Look up user by refid
        refid = request.child_value('data/eaid')
        profiletype = request.child_value('data/recv_csv').split(',')[0]
        profile = None
        userid = None
        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
        if profile is not None:
            return self.format_profile(userid, profiletype, profile)
        else:
            root = Node.void('playerdata')
            root.add_child(Node.s32('result', 1))  # Unclear if this is the right thing to do here.
            return root

    def format_profile(self, userid: UserID, profiletype: str, profile: ValidatedDict) -> Node:
        root = Node.void('playerdata')
        root.add_child(Node.s32('result', 0))
        player = Node.void('player')
        root.add_child(player)
        records = 0

        for i in range(len(profile['strdatas'])):
            strdata = profile['strdatas'][i]
            bindata = profile['bindatas'][i]

            # Figure out the profile type
            csvs = strdata.split(b',')
            if len(csvs) < 2:
                # Not long enough to care about
                continue
            datatype = csvs[1].decode('ascii')
            if datatype != profiletype:
                # Not the right profile type requested
                continue

            game_config = self.get_game_config()
            force_unlock_characters = game_config.get_bool('force_unlock_characters')
            if force_unlock_characters:
                csvs[11] = b'3ffffffffffff'
            else:
                # Reward characters based on playing other games on the network
                hexdata = csvs[11].decode('ascii')
                while (len(hexdata) & 1) != 0:
                    hexdata = '0' + hexdata
                unlock_bits = [b for b in binascii.unhexlify(hexdata)]
                while len(unlock_bits) < 7:
                    unlock_bits.insert(0, 0)

                # Reverse the array, so indexing makes more sense
                unlock_bits = unlock_bits[::-1]

                # Figure out what other games were played by this user
                profiles = self.data.local.user.get_games_played(userid)

                # IIDX
                if len([p for p in profiles if p[0] == GameConstants.IIDX]) > 0:
                    unlock_bits[1] = unlock_bits[1] | 0x10

                # Pop'n
                if len([p for p in profiles if p[0] == GameConstants.POPN_MUSIC]) > 0:
                    unlock_bits[1] = unlock_bits[1] | 0x60

                # Jubeat
                if len([p for p in profiles if p[0] == GameConstants.JUBEAT]) > 0:
                    unlock_bits[2] = unlock_bits[2] | 0x02

                # DDR
                if len([p for p in profiles if p[0] == GameConstants.DDR]) > 0:
                    unlock_bits[6] = unlock_bits[6] | 0x03

                # GFDM characters exist, but this network has no support for
                # GFDM or Gitadora, so the bits were never added.

                # Reconstruct table
                unlock_bits = unlock_bits[::-1]
                csvs[11] = ''.join([f'{x:02x}' for x in unlock_bits]).encode('ascii')

            # This is a valid profile node for this type, lets return only the profile values
            strdata = b','.join(csvs[2:])
            record = Node.void('record')
            player.add_child(record)
            d = Node.string('d', base64.b64encode(strdata).decode('ascii'))
            record.add_child(d)
            d.add_child(Node.string('bin1', base64.b64encode(bindata).decode('ascii')))

            # Remember that we had this record
            records = records + 1

        player.add_child(Node.u32('record_num', records))
        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict, is_new: bool) -> ValidatedDict:
        # Profile save request, data values are base64 encoded.
        # d is a CSV, and bin1 is binary data.
        newprofile = copy.deepcopy(oldprofile)
        strdatas: List[bytes] = []
        bindatas: List[bytes] = []

        record = request.child('data/record')
        for node in record.children:
            if node.name != 'd':
                continue

            profile = base64.b64decode(node.value)
            # Update the shop name if this is a new profile, since we know it came
            # from this cabinet. This is the only source of truth for what the
            # cabinet shop name is set to.
            if is_new:
                self.__update_shop_name(profile)
            strdatas.append(profile)
            bindatas.append(base64.b64decode(node.child_value('bin1')))

        newprofile['strdatas'] = strdatas
        newprofile['bindatas'] = bindatas

        # Keep track of play statistics across all versions
        self.update_play_statistics(userid)

        return newprofile
