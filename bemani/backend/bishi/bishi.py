# vim: set fileencoding=utf-8
import binascii
import base64

try:
    # Python > 3.9
    from collections.abc import Iterable
except ImportError:
    # Python <= 3.9
    from collections import Iterable  # type: ignore

from typing import Any, Dict, List, Sequence, Union

from bemani.backend.bishi.base import BishiBashiBase
from bemani.backend.ess import EventLogHandler
from bemani.common import Profile, GameConstants, VersionConstants, Time
from bemani.data import UserID
from bemani.protocol import Node


class TheStarBishiBashi(
    EventLogHandler,
    BishiBashiBase,
):
    name: str = "The★BishiBashi"
    version: int = VersionConstants.BISHI_BASHI_TSBB

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            "bools": [
                {
                    "name": "Force Unlock All Characters",
                    "tip": "Force unlock all characters on select screen.",
                    "category": "game_config",
                    "setting": "force_unlock_characters",
                },
                {
                    "name": "Unlock Non-Gacha Characters",
                    "tip": "Unlock characters that require playing a different game to unlock.",
                    "category": "game_config",
                    "setting": "force_unlock_eamuse_characters",
                },
                {
                    "name": "Enable DLC levels",
                    "tip": "Enable extra DLC levels on newer cabinets.",
                    "category": "game_config",
                    "setting": "enable_dlc_levels",
                },
            ],
            "strs": [
                {
                    "name": "Scrolling Announcement",
                    "tip": "An announcement that scrolls by in attract mode.",
                    "category": "game_config",
                    "setting": "big_announcement",
                },
            ],
            "longstrs": [
                {
                    "name": "Bulletin Board Announcement",
                    "tip": "An announcement displayed on a bulletin board in attract mode.",
                    "category": "game_config",
                    "setting": "bb_announcement",
                },
            ],
        }

    def __update_shop_name(self, profiledata: bytes) -> None:
        # Figure out the profile type
        csvs = profiledata.split(b",")
        if len(csvs) < 2:
            # Not long enough to care about
            return
        datatype = csvs[1].decode("ascii")
        if datatype != "IBBDAT00":
            # Not the right profile type requested
            return

        # Grab the shop name
        try:
            shopname = csvs[30].decode("shift-jis")
        except Exception:
            return
        self.update_machine_name(shopname)

    def __escape_string(self, data: Union[int, str]) -> str:
        data = str(data)
        data = data.replace("#", "##")
        data = data.replace("\r\n", "#n")
        data = data.replace("\r", "#n")
        data = data.replace("\n", "#n")
        data = data.replace(" ", "#s")
        data = data.replace(",", "#,")
        data = data.replace("=", "#=")
        data = data.replace(";", "#;")
        return data

    def __generate_setting(self, key: str, values: Union[int, str, Sequence[int], Sequence[str]]) -> str:
        if isinstance(values, Iterable) and not isinstance(values, str):
            values = ",".join(self.__escape_string(x) for x in values)
        else:
            values = self.__escape_string(values)
        key = self.__escape_string(key)
        return f"{key}={values}"

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
            # Settings that we can tweak from the server.
            # There's a variety of settings that the game supports, not all of them are figured
            # out. They are documented below.
            #
            # "MAL": 1 - Unlock all DLC levels.
            # "MO": [<levelnum>, <levelnum>, ...] - unlock certain DLC levels by ID. The four
            #                                       DLC levels are as follows:
            #                                         14 - Morse Code
            #                                         51 - PiroPiro
            #                                         60 - Pop'n Music
            #                                         61 - Love Drop
            # "CM": "Arbitrary String" - Scroll the message "Arbitrary String" in attract mode.
            # "IM": "Arbitrary Message" - Display "Arbitrary Message" on a new bulletin in attract mode.
            # "ALL": 1 - Force-unlock all non-gacha characters.
            # "MD": [<int>, <int>, ...] - Unknown setting related to demo mode. Possibly allows server-selection of
            #                             which levels show up?
            # "MQ": 0/1 - Unknown boolean setting that enables recommendation weights I think?
            # "MR": [<int>, <int>, ...] - Unknown setting related to recommendation weights. Only appears to be used
            #                             if "MQ" is set to 1.
            #
            # Additionally, there are a series of settings that are related to character unlocks and BGM selection.
            # I haven't figured out what this setting does, but it might enable gacha-pulls of characters that otherwise
            # require eAmusement plays to unlock? The settings are all in the form of "<key>": <str>. I am not sure what
            # the str value should be. They are reproduced here:
            # "ABB" = "BishiBashi"
            # "ASF" = "Spin Fever"
            # "AEK" = "Eternal Knights 2"
            # "AOD" = "Otomedius"
            # "ABM" = "Beatmania IIDX"
            # "APM" = "pop'n music"
            # "ATB" = "Twinbee"
            # "AGG" = "Good Luck Goemon!"
            # "AGK" = "Ga-Ko Kerotan"
            # "AQM" = "Quiz Magic Academy"
            # "AMF" = "Mahjong Fight Club"
            # "AGF" = "Guitar Freaks"
            # "ADM" = "DrumMania"
            # "AJB" = "Jubeat"
            # "ACL" = "Brain Development Institute Kurukuru Lab"
            # "ASH" = "Silent Hill THE ARCADE"
            # "AHR" = "Horse Riders"
            # "AAD" = "Action Detective"
            # "AWE" = "Winning Eleven"
            # "ACV" = "Ajumajo Dracula (Castlevania)"
            # "AGT" = "GTI Club"
            # "ABH" = "Baseball Heroes"
            # "ADR" = "DanceDanceRevolution"
            # "AGD" = "Gradius"
            # "APD" = "Parodius"
            # "AGC" = "GrandCross Premium"
            # "AXX" = "XeXeX"
            # "ATK" = "TokiMeki Memorial"
            # "AKK" = "Konami"
            # "A--" = "Original"
            settings: Dict[str, Union[int, str, Sequence[int], Sequence[str]]] = {}

            game_config = self.get_game_config()
            enable_dlc_levels = game_config.get_bool("enable_dlc_levels")
            if enable_dlc_levels:
                settings["MAL"] = 1
            force_unlock_characters = game_config.get_bool("force_unlock_eamuse_characters")
            if force_unlock_characters:
                settings["ALL"] = 1
            scrolling_message = game_config.get_str("big_announcement")
            if scrolling_message:
                settings["CM"] = scrolling_message
            bb_message = game_config.get_str("bb_announcement")
            if bb_message:
                settings["IM"] = bb_message

            # Generate system message
            settings_str = ";".join(self.__generate_setting(key, vals) for key, vals in settings.items())

            # Send it to the client, making sure to inform the client that it was valid.
            root.add_child(
                Node.string(
                    "strdata1",
                    base64.b64encode(settings_str.encode("ascii")).decode("ascii"),
                )
            )
            root.add_child(Node.string("strdata2", ""))
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
        profiletype = request.child_value("data/recv_csv").split(",")[0]
        profile = None
        userid = None
        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            profile = self.get_profile(userid)
        if profile is not None:
            return self.format_profile(userid, profiletype, profile)
        else:
            root = Node.void("playerdata")
            root.add_child(Node.s32("result", 1))  # Unclear if this is the right thing to do here.
            return root

    def format_profile(self, userid: UserID, profiletype: str, profile: Profile) -> Node:
        root = Node.void("playerdata")
        root.add_child(Node.s32("result", 0))
        player = Node.void("player")
        root.add_child(player)
        records = 0

        for i in range(len(profile["strdatas"])):
            strdata = profile["strdatas"][i]
            bindata = profile["bindatas"][i]

            # Figure out the profile type
            csvs = strdata.split(b",")
            if len(csvs) < 2:
                # Not long enough to care about
                continue
            datatype = csvs[1].decode("ascii")
            if datatype != profiletype:
                # Not the right profile type requested
                continue

            game_config = self.get_game_config()
            force_unlock_characters = game_config.get_bool("force_unlock_characters")
            if force_unlock_characters:
                csvs[11] = b"3ffffffffffff"
            else:
                # Reward characters based on playing other games on the network
                hexdata = csvs[11].decode("ascii")
                while (len(hexdata) & 1) != 0:
                    hexdata = "0" + hexdata
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
                csvs[11] = "".join([f"{x:02x}" for x in unlock_bits]).encode("ascii")

            # This is a valid profile node for this type, lets return only the profile values
            strdata = b",".join(csvs[2:])
            record = Node.void("record")
            player.add_child(record)
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
