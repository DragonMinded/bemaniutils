import copy
from typing import Any, Dict

from bemani.backend.ess import EventLogHandler
from bemani.backend.museca.base import MusecaBase
from bemani.backend.museca.common import (
    MusecaGameFrozenHandler,
    MusecaGameHiscoreHandler,
    MusecaGameNewHandler,
    MusecaGamePlayEndHandler,
    MusecaGameSaveHandler,
    MusecaGameSaveMusicHandler,
    MusecaGameShopHandler,
)
from bemani.common import Time, VersionConstants, ValidatedDict, ID
from bemani.data import UserID
from bemani.protocol import Node


class Museca1(
    EventLogHandler,
    MusecaGameFrozenHandler,
    MusecaGameHiscoreHandler,
    MusecaGameNewHandler,
    MusecaGamePlayEndHandler,
    MusecaGameSaveHandler,
    MusecaGameSaveMusicHandler,
    MusecaGameShopHandler,
    MusecaBase,
):

    name = "MÚSECA"
    version = VersionConstants.MUSECA

    GAME_LIMITED_LOCKED = 1
    GAME_LIMITED_UNLOCKABLE = 2
    GAME_LIMITED_UNLOCKED = 3

    GAME_CATALOG_TYPE_SONG = 0
    GAME_CATALOG_TYPE_GRAFICA = 15
    GAME_CATALOG_TYPE_MISSION = 16

    GAME_GRADE_DEATH = 0
    GAME_GRADE_POOR = 1
    GAME_GRADE_MEDIOCRE = 2
    GAME_GRADE_GOOD = 3
    GAME_GRADE_GREAT = 4
    GAME_GRADE_EXCELLENT = 5
    GAME_GRADE_SUPERB = 6
    GAME_GRADE_MASTERPIECE = 7

    GAME_CLEAR_TYPE_FAILED = 1
    GAME_CLEAR_TYPE_CLEARED = 2
    GAME_CLEAR_TYPE_FULL_COMBO = 4

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            'bools': [
                {
                    'name': 'Force Song Unlock',
                    'tip': 'Force unlock all songs.',
                    'category': 'game_config',
                    'setting': 'force_unlock_songs',
                },
            ],
        }

    def game_to_db_clear_type(self, clear_type: int) -> int:
        return {
            self.GAME_CLEAR_TYPE_FAILED: self.CLEAR_TYPE_FAILED,
            self.GAME_CLEAR_TYPE_CLEARED: self.CLEAR_TYPE_CLEARED,
            self.GAME_CLEAR_TYPE_FULL_COMBO: self.CLEAR_TYPE_FULL_COMBO,
        }[clear_type]

    def db_to_game_clear_type(self, clear_type: int) -> int:
        return {
            self.CLEAR_TYPE_FAILED: self.GAME_CLEAR_TYPE_FAILED,
            self.CLEAR_TYPE_CLEARED: self.GAME_CLEAR_TYPE_CLEARED,
            self.CLEAR_TYPE_FULL_COMBO: self.GAME_CLEAR_TYPE_FULL_COMBO,
        }[clear_type]

    def game_to_db_grade(self, grade: int) -> int:
        return {
            self.GAME_GRADE_DEATH: self.GRADE_DEATH,
            self.GAME_GRADE_POOR: self.GRADE_POOR,
            self.GAME_GRADE_MEDIOCRE: self.GRADE_MEDIOCRE,
            self.GAME_GRADE_GOOD: self.GRADE_GOOD,
            self.GAME_GRADE_GREAT: self.GRADE_GREAT,
            self.GAME_GRADE_EXCELLENT: self.GRADE_EXCELLENT,
            self.GAME_GRADE_SUPERB: self.GRADE_SUPERB,
            self.GAME_GRADE_MASTERPIECE: self.GRADE_MASTERPIECE,
        }[grade]

    def db_to_game_grade(self, grade: int) -> int:
        return {
            self.GRADE_DEATH: self.GAME_GRADE_DEATH,
            self.GRADE_POOR: self.GAME_GRADE_POOR,
            self.GRADE_MEDIOCRE: self.GAME_GRADE_MEDIOCRE,
            self.GRADE_GOOD: self.GAME_GRADE_GOOD,
            self.GRADE_GREAT: self.GAME_GRADE_GREAT,
            self.GRADE_EXCELLENT: self.GAME_GRADE_EXCELLENT,
            self.GRADE_SUPERB: self.GAME_GRADE_SUPERB,
            self.GRADE_MASTERPIECE: self.GAME_GRADE_MASTERPIECE,
            self.GRADE_PERFECT: self.GAME_GRADE_MASTERPIECE,
        }[grade]

    def handle_game_3_common_request(self, request: Node) -> Node:
        game = Node.void('game_3')
        limited = Node.void('music_limited')
        game.add_child(limited)

        # Song unlock config
        game_config = self.get_game_config()
        if game_config.get_bool('force_unlock_songs'):
            ids = set()
            songs = self.data.local.music.get_all_songs(self.game, self.music_version)
            for song in songs:
                if song.data.get_int('limited') in (self.GAME_LIMITED_LOCKED, self.GAME_LIMITED_UNLOCKABLE):
                    ids.add((song.id, song.chart))

            for (songid, chart) in ids:
                info = Node.void('info')
                limited.add_child(info)
                info.add_child(Node.s32('music_id', songid))
                info.add_child(Node.u8('music_type', chart))
                info.add_child(Node.u8('limited', self.GAME_LIMITED_UNLOCKED))

        # Event config
        event = Node.void('event')
        game.add_child(event)

        def enable_event(eid: int) -> None:
            evt = Node.void('info')
            event.add_child(evt)
            evt.add_child(Node.u32('event_id', eid))

        # Allow PASELI light start
        enable_event(83)

        # If you want song unlock news to show up, enable one of the following:
        # 94 - 5/25/2016 unlocks
        # 95 - 4/27/2016 second unlocks
        # 89 - 4/27/2016 unlocks
        # 87 - 4/13/2016 unlocks
        # 82 - 3/23/2016 second unlocks
        # 80 - 3/23/2016 unlocks
        # 76 - 12/22/2016 unlocks

        return game

    def handle_game_3_exception_request(self, request: Node) -> Node:
        return Node.void('game_3')

    def handle_game_3_load_request(self, request: Node) -> Node:
        refid = request.child_value('refid')
        root = self.get_profile_by_refid(refid)
        if root is not None:
            return root

        # No data succession, there's nothing older than this!
        root = Node.void('game_3')
        root.add_child(Node.u8('result', 1))
        return root

    def handle_game_3_load_m_request(self, request: Node) -> Node:
        refid = request.child_value('dataid')

        if refid is not None:
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
        else:
            userid = None

        if userid is not None:
            scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)
        else:
            scores = []

        # Output to the game
        game = Node.void('game_3')
        new = Node.void('new')
        game.add_child(new)

        for score in scores:
            music = Node.void('music')
            new.add_child(music)
            music.add_child(Node.u32('music_id', score.id))
            music.add_child(Node.u32('music_type', score.chart))
            music.add_child(Node.u32('score', score.points))
            music.add_child(Node.u32('cnt', score.plays))
            music.add_child(Node.u32('clear_type', self.db_to_game_clear_type(score.data.get_int('clear_type'))))
            music.add_child(Node.u32('score_grade', self.db_to_game_grade(score.data.get_int('grade'))))
            stats = score.data.get_dict('stats')
            music.add_child(Node.u32('btn_rate', stats.get_int('btn_rate')))
            music.add_child(Node.u32('long_rate', stats.get_int('long_rate')))
            music.add_child(Node.u32('vol_rate', stats.get_int('vol_rate')))

        return game

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        game = Node.void('game_3')

        # Generic profile stuff
        game.add_child(Node.string('name', profile.get_str('name')))
        game.add_child(Node.string('code', ID.format_extid(profile.get_int('extid'))))
        game.add_child(Node.u32('gamecoin_packet', profile.get_int('packet')))
        game.add_child(Node.u32('gamecoin_block', profile.get_int('block')))
        game.add_child(Node.s16('skill_name_id', profile.get_int('skill_name_id', -1)))
        game.add_child(Node.s32_array('hidden_param', profile.get_int_array('hidden_param', 20)))
        game.add_child(Node.u32('blaster_energy', profile.get_int('blaster_energy')))
        game.add_child(Node.u32('blaster_count', profile.get_int('blaster_count')))

        # Play statistics
        statistics = self.get_play_statistics(userid)
        last_play_date = statistics.get_int_array('last_play_date', 3)
        today_play_date = Time.todays_date()
        if (
            last_play_date[0] == today_play_date[0] and
            last_play_date[1] == today_play_date[1] and
            last_play_date[2] == today_play_date[2]
        ):
            today_count = statistics.get_int('today_plays', 0)
        else:
            today_count = 0
        game.add_child(Node.u32('play_count', statistics.get_int('total_plays', 0)))
        game.add_child(Node.u32('daily_count', today_count))
        game.add_child(Node.u32('play_chain', statistics.get_int('consecutive_days', 0)))

        # Last played stuff
        if 'last' in profile:
            lastdict = profile.get_dict('last')
            last = Node.void('last')
            game.add_child(last)
            last.add_child(Node.s32('music_id', lastdict.get_int('music_id', -1)))
            last.add_child(Node.u8('music_type', lastdict.get_int('music_type')))
            last.add_child(Node.u8('sort_type', lastdict.get_int('sort_type')))
            last.add_child(Node.u8('narrow_down', lastdict.get_int('narrow_down')))
            last.add_child(Node.u8('headphone', lastdict.get_int('headphone')))
            last.add_child(Node.u16('appeal_id', lastdict.get_int('appeal_id', 1001)))
            last.add_child(Node.u16('comment_id', lastdict.get_int('comment_id')))
            last.add_child(Node.u8('gauge_option', lastdict.get_int('gauge_option')))

        # Item unlocks
        itemnode = Node.void('item')
        game.add_child(itemnode)

        game_config = self.get_game_config()
        achievements = self.data.local.user.get_achievements(self.game, self.version, userid)

        for item in achievements:
            if item.type[:5] != 'item_':
                continue
            itemtype = int(item.type[5:])

            if game_config.get_bool('force_unlock_songs') and itemtype == self.GAME_CATALOG_TYPE_SONG:
                # Don't echo unlocked songs, we will add all of them later
                continue

            info = Node.void('info')
            itemnode.add_child(info)
            info.add_child(Node.u8('type', itemtype))
            info.add_child(Node.u32('id', item.id))
            info.add_child(Node.u32('param', item.data.get_int('param')))
            if 'diff_param' in item.data:
                info.add_child(Node.s32('diff_param', item.data.get_int('diff_param')))

        if game_config.get_bool('force_unlock_songs'):
            ids: Dict[int, int] = {}
            songs = self.data.local.music.get_all_songs(self.game, self.music_version)
            for song in songs:
                if song.id not in ids:
                    ids[song.id] = 0

                if song.data.get_int('difficulty') > 0:
                    ids[song.id] = ids[song.id] | (1 << song.chart)

            for itemid in ids:
                if ids[itemid] == 0:
                    continue

                info = Node.void('info')
                itemnode.add_child(info)
                info.add_child(Node.u8('type', self.GAME_CATALOG_TYPE_SONG))
                info.add_child(Node.u32('id', itemid))
                info.add_child(Node.u32('param', ids[itemid]))

        return game

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)

        # Update blaster energy and in-game currencies
        earned_gamecoin_packet = request.child_value('earned_gamecoin_packet')
        if earned_gamecoin_packet is not None:
            newprofile.replace_int('packet', newprofile.get_int('packet') + earned_gamecoin_packet)
        earned_gamecoin_block = request.child_value('earned_gamecoin_block')
        if earned_gamecoin_block is not None:
            newprofile.replace_int('block', newprofile.get_int('block') + earned_gamecoin_block)
        earned_blaster_energy = request.child_value('earned_blaster_energy')
        if earned_blaster_energy is not None:
            newprofile.replace_int('blaster_energy', newprofile.get_int('blaster_energy') + earned_blaster_energy)

        # Miscelaneous stuff
        newprofile.replace_int('blaster_count', request.child_value('blaster_count'))
        newprofile.replace_int('skill_name_id', request.child_value('skill_name_id'))
        newprofile.replace_int_array('hidden_param', 20, request.child_value('hidden_param'))

        # Update user's unlock status if we aren't force unlocked
        game_config = self.get_game_config()

        if request.child('item') is not None:
            for child in request.child('item').children:
                if child.name != 'info':
                    continue

                item_id = child.child_value('id')
                item_type = child.child_value('type')
                param = child.child_value('param')
                diff_param = child.child_value('diff_param')

                if game_config.get_bool('force_unlock_songs') and item_type == self.GAME_CATALOG_TYPE_SONG:
                    # Don't save back songs, because they were force unlocked
                    continue

                if diff_param is not None:
                    paramvals = {
                        'diff_param': diff_param,
                        'param': param,
                    }
                else:
                    paramvals = {
                        'param': param,
                    }

                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    item_id,
                    f'item_{item_type}',
                    paramvals,
                )

        # Grab last information.
        lastdict = newprofile.get_dict('last')
        lastdict.replace_int('headphone', request.child_value('headphone'))
        lastdict.replace_int('appeal_id', request.child_value('appeal_id'))
        lastdict.replace_int('comment_id', request.child_value('comment_id'))
        lastdict.replace_int('music_id', request.child_value('music_id'))
        lastdict.replace_int('music_type', request.child_value('music_type'))
        lastdict.replace_int('sort_type', request.child_value('sort_type'))
        lastdict.replace_int('narrow_down', request.child_value('narrow_down'))
        lastdict.replace_int('gauge_option', request.child_value('gauge_option'))

        # Save back last information gleaned from results
        newprofile.replace_dict('last', lastdict)

        # Keep track of play statistics
        self.update_play_statistics(userid)

        return newprofile
