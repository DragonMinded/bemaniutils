# vim: set fileencoding=utf-8
import copy
from typing import Optional

from bemani.backend.popn.base import PopnMusicBase
from bemani.backend.popn.stubs import PopnMusicSengokuRetsuden

from bemani.backend.base import Status
from bemani.common import ValidatedDict, VersionConstants
from bemani.data import Score, UserID
from bemani.protocol import Node


class PopnMusicTuneStreet(PopnMusicBase):

    name = "Pop'n Music TUNE STREET"
    version = VersionConstants.POPN_MUSIC_TUNE_STREET

    # Play modes, as reported by profile save from the game
    GAME_PLAY_MODE_CHALLENGE = 3
    GAME_PLAY_MODE_CHO_CHALLENGE = 4

    # Play flags, as saved into/loaded from the DB
    GAME_PLAY_FLAG_FAILED = 0
    GAME_PLAY_FLAG_CLEARED = 1
    GAME_PLAY_FLAG_FULL_COMBO = 2
    GAME_PLAY_FLAG_PERFECT_COMBO = 3

    # Chart type, as reported by profile save from the game
    GAME_CHART_TYPE_NORMAL = 0
    GAME_CHART_TYPE_HYPER = 1
    GAME_CHART_TYPE_5_BUTTON = 2
    GAME_CHART_TYPE_EX = 3
    GAME_CHART_TYPE_BATTLE_NORMAL = 4
    GAME_CHART_TYPE_BATTLE_HYPER = 5
    GAME_CHART_TYPE_ENJOY_5_BUTTON = 6
    GAME_CHART_TYPE_ENJOY_9_BUTTON = 7

    # Extra chart types supported by Pop'n 19
    CHART_TYPE_OLD_NORMAL = 4
    CHART_TYPE_OLD_HYPER = 5
    CHART_TYPE_OLD_EX = 6
    CHART_TYPE_ENJOY_5_BUTTON = 7
    CHART_TYPE_ENJOY_9_BUTTON = 8
    CHART_TYPE_5_BUTTON = 9

    # Chart type, as packed into a hiscore binary
    GAME_CHART_TYPE_5_BUTTON_POSITION = 0
    GAME_CHART_TYPE_NORMAL_POSITION = 1
    GAME_CHART_TYPE_HYPER_POSITION = 2
    GAME_CHART_TYPE_EX_POSITION = 3
    GAME_CHART_TYPE_CHO_NORMAL_POSITION = 4
    GAME_CHART_TYPE_CHO_HYPER_POSITION = 5
    GAME_CHART_TYPE_CHO_EX_POSITION = 6

    # Highest song ID we can represent
    GAME_MAX_MUSIC_ID = 1045

    def previous_version(self) -> Optional[PopnMusicBase]:
        return PopnMusicSengokuRetsuden(self.data, self.config, self.model)

    def __format_flags_for_score(self, score: Score) -> int:
        # Format song flags (cleared/not, combo flags)
        playedflag = {
            self.CHART_TYPE_5_BUTTON: 0x2000,
            self.CHART_TYPE_OLD_NORMAL: 0x0800,
            self.CHART_TYPE_OLD_HYPER: 0x1000,
            self.CHART_TYPE_OLD_EX: 0x4000,
            self.CHART_TYPE_NORMAL: 0x0800,
            self.CHART_TYPE_HYPER: 0x1000,
            self.CHART_TYPE_EX: 0x4000,
            # We don't have a played flag for these, only cleared/no play
            self.CHART_TYPE_ENJOY_5_BUTTON: 0,
            self.CHART_TYPE_ENJOY_9_BUTTON: 0,
        }[score.chart]
        # Shift value for cleared/failed/combo indicators
        shift = {
            self.CHART_TYPE_5_BUTTON: 4,
            self.CHART_TYPE_OLD_NORMAL: 0,
            self.CHART_TYPE_OLD_HYPER: 2,
            self.CHART_TYPE_OLD_EX: 6,
            self.CHART_TYPE_NORMAL: 0,
            self.CHART_TYPE_HYPER: 2,
            self.CHART_TYPE_EX: 6,
            self.CHART_TYPE_ENJOY_5_BUTTON: 9,
            self.CHART_TYPE_ENJOY_9_BUTTON: 8,
        }[score.chart]
        flags = {
            self.PLAY_MEDAL_CIRCLE_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_DIAMOND_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_STAR_FAILED: self.GAME_PLAY_FLAG_FAILED,
            self.PLAY_MEDAL_EASY_CLEAR: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_CIRCLE_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_DIAMOND_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_STAR_CLEARED: self.GAME_PLAY_FLAG_CLEARED,
            self.PLAY_MEDAL_CIRCLE_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_DIAMOND_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_STAR_FULL_COMBO: self.GAME_PLAY_FLAG_FULL_COMBO,
            self.PLAY_MEDAL_PERFECT: self.GAME_PLAY_FLAG_PERFECT_COMBO,
        }[score.data.get_int('medal')]
        return (flags << shift) | playedflag

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        root = Node.void('playerdata')

        # Format profile
        binary_profile = [0] * 2200

        # Copy name
        name_binary = profile.get_str('name', 'なし').encode('shift-jis')[0:12]
        name_pos = 0
        for byte in name_binary:
            binary_profile[name_pos] = byte
            name_pos = name_pos + 1

        # Copy game mode
        binary_profile[13] = {
            0: 0,
            1: 0,
            2: 1,
            3: 1,
            4: 4,
            5: 2,
        }[profile.get_int('play_mode')]

        # Copy miscelaneous values
        binary_profile[16] = profile.get_int('last_play_flag') & 0xFF
        binary_profile[44] = profile.get_int('option') & 0xFF
        binary_profile[45] = (profile.get_int('option') >> 8) & 0xFF
        binary_profile[46] = (profile.get_int('option') >> 16) & 0xFF
        binary_profile[47] = (profile.get_int('option') >> 24) & 0xFF
        binary_profile[60] = profile.get_int('chara') & 0xFF
        binary_profile[61] = (profile.get_int('chara') >> 8) & 0xFF
        binary_profile[62] = profile.get_int('music') & 0xFF
        binary_profile[63] = (profile.get_int('music') >> 8) & 0xFF
        binary_profile[64] = profile.get_int('sheet') & 0xFF
        binary_profile[65] = profile.get_int('category') & 0xFF
        # This might be the count of friends, since Tune Street *does* support
        # rivals. However, I can no longer get it running on my cabinet or locally
        # so there's no way for me to test.
        binary_profile[67] = profile.get_int('medal_and_friend') & 0xFF

        # Format Scores
        hiscore_array = [0] * int((((self.GAME_MAX_MUSIC_ID * 7) * 17) + 7) / 8)
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart in [
                self.CHART_TYPE_EASY,
            ]:
                continue

            flags = self.__format_flags_for_score(score)

            flags_index = score.id * 2
            binary_profile[108 + flags_index] = binary_profile[108 + flags_index] | (flags & 0xFF)
            binary_profile[109 + flags_index] = binary_profile[109 + flags_index] | ((flags >> 8) & 0xFF)

            if score.chart in [
                self.CHART_TYPE_ENJOY_5_BUTTON,
                self.CHART_TYPE_ENJOY_9_BUTTON,
            ]:
                # We don't return enjoy scores, just the flags that we played them
                continue

            # Format actual score, according to DB chart position
            points = score.points

            hiscore_index = (score.id * 7) + {
                self.CHART_TYPE_5_BUTTON: self.GAME_CHART_TYPE_5_BUTTON_POSITION,
                self.CHART_TYPE_OLD_NORMAL: self.GAME_CHART_TYPE_NORMAL_POSITION,
                self.CHART_TYPE_OLD_HYPER: self.GAME_CHART_TYPE_HYPER_POSITION,
                self.CHART_TYPE_OLD_EX: self.GAME_CHART_TYPE_EX_POSITION,
                self.CHART_TYPE_NORMAL: self.GAME_CHART_TYPE_CHO_NORMAL_POSITION,
                self.CHART_TYPE_HYPER: self.GAME_CHART_TYPE_CHO_HYPER_POSITION,
                self.CHART_TYPE_EX: self.GAME_CHART_TYPE_CHO_EX_POSITION,
            }[score.chart]
            hiscore_byte_pos = int((hiscore_index * 17) / 8)
            hiscore_bit_pos = int((hiscore_index * 17) % 8)
            hiscore_value = points << hiscore_bit_pos
            hiscore_array[hiscore_byte_pos] = hiscore_array[hiscore_byte_pos] | (hiscore_value & 0xFF)
            hiscore_array[hiscore_byte_pos + 1] = hiscore_array[hiscore_byte_pos + 1] | ((hiscore_value >> 8) & 0xFF)
            hiscore_array[hiscore_byte_pos + 2] = hiscore_array[hiscore_byte_pos + 2] | ((hiscore_value >> 16) & 0xFF)

        # Format most played
        most_played = [x[0] for x in self.data.local.music.get_most_played(self.game, self.version, userid, 20)]
        while len(most_played) < 20:
            most_played.append(-1)
        profile_pos = 68
        for musicid in most_played:
            binary_profile[profile_pos] = musicid & 0xFF
            binary_profile[profile_pos + 1] = (musicid >> 8) & 0xFF
            profile_pos = profile_pos + 2

        # Construct final profile
        root.add_child(Node.binary('b', bytes(binary_profile)))
        root.add_child(Node.binary('hiscore', bytes(hiscore_array)))
        root.add_child(Node.binary('town', b''))

        return root

    def format_conversion(self, userid: UserID, profile: ValidatedDict) -> Node:
        root = Node.void('playerdata')

        root.add_child(Node.string('name', profile.get_str('name', 'なし')))
        root.add_child(Node.s16('chara', profile.get_int('chara', -1)))
        root.add_child(Node.s32('option', profile.get_int('option', 0)))
        root.add_child(Node.u8('version', 0))
        root.add_child(Node.u8('kind', 0))
        root.add_child(Node.u8('season', 0))

        medals = [0] * (self.GAME_MAX_MUSIC_ID)
        scores = self.data.remote.music.get_scores(self.game, self.version, userid)
        for score in scores:
            if score.id > self.GAME_MAX_MUSIC_ID:
                continue

            # Skip any scores for chart types we don't support
            if score.chart in [
                self.CHART_TYPE_EASY,
            ]:
                continue

            flags = self.__format_flags_for_score(score)
            medals[score.id] = medals[score.id] | flags
        root.add_child(Node.u16_array('clear_medal', medals))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)

        # Extract the playmode, important for scores later
        playmode = int(request.attribute('play_mode'))
        newprofile.replace_int('play_mode', playmode)

        # Extract profile options
        newprofile.replace_int('chara', int(request.attribute('chara_num')))
        if 'option' in request.attributes:
            newprofile.replace_int('option', int(request.attribute('option')))
        if 'last_play_flag' in request.attributes:
            newprofile.replace_int('last_play_flag', int(request.attribute('last_play_flag')))
        if 'medal_and_friend' in request.attributes:
            newprofile.replace_int('medal_and_friend', int(request.attribute('medal_and_friend')))
        if 'music_num' in request.attributes:
            newprofile.replace_int('music', int(request.attribute('music_num')))
        if 'sheet_num' in request.attributes:
            newprofile.replace_int('sheet', int(request.attribute('sheet_num')))
        if 'category_num' in request.attributes:
            newprofile.replace_int('category', int(request.attribute('category_num')))

        # Keep track of play statistics
        self.update_play_statistics(userid)

        # Extract scores
        for node in request.children:
            if node.name == 'music':
                songid = int(node.attribute('music_num'))
                chart = int(node.attribute('sheet_num'))
                points = int(node.attribute('score'))
                data = int(node.attribute('data'))

                # We never save battle scores
                if chart in [
                    self.GAME_CHART_TYPE_BATTLE_NORMAL,
                    self.GAME_CHART_TYPE_BATTLE_HYPER,
                ]:
                    continue

                # Arrange order to be compatible with future mixes
                if playmode == self.GAME_PLAY_MODE_CHO_CHALLENGE:
                    if chart in [
                        self.GAME_CHART_TYPE_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_9_BUTTON,
                    ]:
                        # We don't save 5 button for cho scores, or enjoy modes
                        continue
                    chart = {
                        self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_NORMAL,
                        self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_HYPER,
                        self.GAME_CHART_TYPE_EX: self.CHART_TYPE_EX,
                    }[chart]
                else:
                    chart = {
                        self.GAME_CHART_TYPE_NORMAL: self.CHART_TYPE_OLD_NORMAL,
                        self.GAME_CHART_TYPE_HYPER: self.CHART_TYPE_OLD_HYPER,
                        self.GAME_CHART_TYPE_5_BUTTON: self.CHART_TYPE_5_BUTTON,
                        self.GAME_CHART_TYPE_EX: self.CHART_TYPE_OLD_EX,
                        self.GAME_CHART_TYPE_ENJOY_5_BUTTON: self.CHART_TYPE_ENJOY_5_BUTTON,
                        self.GAME_CHART_TYPE_ENJOY_9_BUTTON: self.CHART_TYPE_ENJOY_9_BUTTON,
                    }[chart]

                # Extract play flags
                shift = {
                    self.CHART_TYPE_5_BUTTON: 4,
                    self.CHART_TYPE_OLD_NORMAL: 0,
                    self.CHART_TYPE_OLD_HYPER: 2,
                    self.CHART_TYPE_OLD_EX: 6,
                    self.CHART_TYPE_NORMAL: 0,
                    self.CHART_TYPE_HYPER: 2,
                    self.CHART_TYPE_EX: 6,
                    self.CHART_TYPE_ENJOY_5_BUTTON: 9,
                    self.CHART_TYPE_ENJOY_9_BUTTON: 8,
                }[chart]

                if chart in [
                    self.CHART_TYPE_ENJOY_5_BUTTON,
                    self.CHART_TYPE_ENJOY_9_BUTTON,
                ]:
                    # We only store cleared or not played for enjoy mode
                    mask = 0x1
                else:
                    # We store all data for regular charts
                    mask = 0x3

                # Grab flags, map to medals in DB. Choose lowest one for each so
                # a newer pop'n can still improve scores and medals.
                flags = (data >> shift) & mask
                medal = {
                    self.GAME_PLAY_FLAG_FAILED: self.PLAY_MEDAL_CIRCLE_FAILED,
                    self.GAME_PLAY_FLAG_CLEARED: self.PLAY_MEDAL_CIRCLE_CLEARED,
                    self.GAME_PLAY_FLAG_FULL_COMBO: self.PLAY_MEDAL_CIRCLE_FULL_COMBO,
                    self.GAME_PLAY_FLAG_PERFECT_COMBO: self.PLAY_MEDAL_PERFECT,
                }[flags]
                self.update_score(userid, songid, chart, points, medal)

        return newprofile

    def handle_game_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'get':
            # TODO: Hook these up to config so we can change this
            root = Node.void('game')
            root.set_attribute('game_phase', '2')
            root.set_attribute('psp_phase', '2')
            return root

        if method == 'active':
            # Update the name of this cab for admin purposes
            self.update_machine_name(request.attribute('shop_name'))
            return Node.void('game')

        if method == 'taxphase':
            return Node.void('game')

        # Invalid method
        return None

    def handle_playerdata_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'expire':
            return Node.void('playerdata')

        elif method == 'logout':
            return Node.void('playerdata')

        elif method == 'get':
            modelstring = request.attribute('model')
            refid = request.attribute('ref_id')
            root = self.get_profile_by_refid(
                refid,
                self.NEW_PROFILE_ONLY if modelstring is None else self.OLD_PROFILE_ONLY,
            )
            if root is None:
                root = Node.void('playerdata')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'new':
            refid = request.attribute('ref_id')
            name = request.attribute('name')
            root = self.new_profile_by_refid(refid, name)
            if root is None:
                root = Node.void('playerdata')
                root.set_attribute('status', str(Status.NO_PROFILE))
            return root

        elif method == 'set':
            refid = request.attribute('ref_id')

            root = Node.void('playerdata')
            if refid is None:
                return root

            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is None:
                return root

            oldprofile = self.get_profile(userid) or ValidatedDict()
            newprofile = self.unformat_profile(userid, request, oldprofile)

            if newprofile is not None:
                self.put_profile(userid, newprofile)

            return root

        # Invalid method
        return None
