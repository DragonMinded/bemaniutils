# vim: set fileencoding=utf-8
import copy
import random
import struct
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime
from discord_webhook import DiscordWebhook, DiscordEmbed  # type: ignore

from bemani.backend.iidx.base import IIDXBase
from bemani.backend.iidx.tricoro import IIDXTricoro

from bemani.common import ValidatedDict, VersionConstants, Time, ID
from bemani.data import Data, UserID
from bemani.protocol import Node


class IIDXSpada(IIDXBase):

    name = 'Beatmania IIDX SPADA'
    version = VersionConstants.IIDX_SPADA

    GAME_CLTYPE_SINGLE = 0
    GAME_CLTYPE_DOUBLE = 1

    DAN_STAGES_SINGLE = 4
    DAN_STAGES_DOUBLE = 3

    GAME_CLEAR_STATUS_NO_PLAY = 0
    GAME_CLEAR_STATUS_FAILED = 1
    GAME_CLEAR_STATUS_ASSIST_CLEAR = 2
    GAME_CLEAR_STATUS_EASY_CLEAR = 3
    GAME_CLEAR_STATUS_CLEAR = 4
    GAME_CLEAR_STATUS_HARD_CLEAR = 5
    GAME_CLEAR_STATUS_EX_HARD_CLEAR = 6
    GAME_CLEAR_STATUS_FULL_COMBO = 7

    GAME_GHOST_TYPE_RIVAL = 1
    GAME_GHOST_TYPE_GLOBAL_TOP = 2
    GAME_GHOST_TYPE_GLOBAL_AVERAGE = 3
    GAME_GHOST_TYPE_LOCAL_TOP = 4
    GAME_GHOST_TYPE_LOCAL_AVERAGE = 5
    GAME_GHOST_TYPE_DAN_TOP = 6
    GAME_GHOST_TYPE_DAN_AVERAGE = 7
    GAME_GHOST_TYPE_RIVAL_TOP = 8
    GAME_GHOST_TYPE_RIVAL_AVERAGE = 9

    GAME_GHOST_LENGTH = 64

    GAME_SP_DAN_RANK_7_KYU = 0
    GAME_SP_DAN_RANK_6_KYU = 1
    GAME_SP_DAN_RANK_5_KYU = 2
    GAME_SP_DAN_RANK_4_KYU = 3
    GAME_SP_DAN_RANK_3_KYU = 4
    GAME_SP_DAN_RANK_2_KYU = 5
    GAME_SP_DAN_RANK_1_KYU = 6
    GAME_SP_DAN_RANK_1_DAN = 7
    GAME_SP_DAN_RANK_2_DAN = 8
    GAME_SP_DAN_RANK_3_DAN = 9
    GAME_SP_DAN_RANK_4_DAN = 10
    GAME_SP_DAN_RANK_5_DAN = 11
    GAME_SP_DAN_RANK_6_DAN = 12
    GAME_SP_DAN_RANK_7_DAN = 13
    GAME_SP_DAN_RANK_8_DAN = 14
    GAME_SP_DAN_RANK_9_DAN = 15
    GAME_SP_DAN_RANK_10_DAN = 16
    GAME_SP_DAN_RANK_KAIDEN = 17

    GAME_DP_DAN_RANK_5_KYU = 0
    GAME_DP_DAN_RANK_4_KYU = 1
    GAME_DP_DAN_RANK_3_KYU = 2
    GAME_DP_DAN_RANK_2_KYU = 3
    GAME_DP_DAN_RANK_1_KYU = 4
    GAME_DP_DAN_RANK_1_DAN = 5
    GAME_DP_DAN_RANK_2_DAN = 6
    GAME_DP_DAN_RANK_3_DAN = 7
    GAME_DP_DAN_RANK_4_DAN = 8
    GAME_DP_DAN_RANK_5_DAN = 9
    GAME_DP_DAN_RANK_6_DAN = 10
    GAME_DP_DAN_RANK_7_DAN = 11
    GAME_DP_DAN_RANK_8_DAN = 12
    GAME_DP_DAN_RANK_9_DAN = 13
    GAME_DP_DAN_RANK_10_DAN = 14
    GAME_DP_DAN_RANK_KAIDEN = 15

    FAVORITE_LIST_LENGTH = 20

    def previous_version(self) -> Optional[IIDXBase]:
        return IIDXTricoro(self.data, self.config, self.model)

    @classmethod
    def run_scheduled_work(cls, data: Data, config: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Insert dailies into the DB.
        """
        events = []
        if data.local.network.should_schedule(cls.game, cls.version, 'daily_charts', 'daily'):
            # Generate a new list of three dailies.
            start_time, end_time = data.local.network.get_schedule_duration('daily')
            all_songs = list(set([song.id for song in data.local.music.get_all_songs(cls.game, cls.version)]))
            daily_songs = random.sample(all_songs, 3)
            data.local.game.put_time_sensitive_settings(
                cls.game,
                cls.version,
                'dailies',
                {
                    'start_time': start_time,
                    'end_time': end_time,
                    'music': daily_songs,
                },
            )
            events.append((
                'iidx_daily_charts',
                {
                    'version': cls.version,
                    'music': daily_songs,
                },
            ))

            # Mark that we did some actual work here.
            data.local.network.mark_scheduled(cls.game, cls.version, 'daily_charts', 'daily')
        return events

    @classmethod
    def get_settings(cls) -> Dict[str, Any]:
        """
        Return all of our front-end modifiably settings.
        """
        return {
            'bools': [
                {
                    'name': 'Global Shop Ranking',
                    'tip': 'Return network-wide ranking instead of shop ranking on results screen.',
                    'category': 'game_config',
                    'setting': 'global_shop_ranking',
                },
                {
                    'name': 'Events In Omnimix',
                    'tip': 'Allow events to be enabled at all for Omnimix.',
                    'category': 'game_config',
                    'setting': 'omnimix_events_enabled',
                },
            ],
        }

    def db_to_game_status(self, db_status: int) -> int:
        return {
            self.CLEAR_STATUS_NO_PLAY: self.GAME_CLEAR_STATUS_NO_PLAY,
            self.CLEAR_STATUS_FAILED: self.GAME_CLEAR_STATUS_FAILED,
            self.CLEAR_STATUS_ASSIST_CLEAR: self.GAME_CLEAR_STATUS_ASSIST_CLEAR,
            self.CLEAR_STATUS_EASY_CLEAR: self.GAME_CLEAR_STATUS_EASY_CLEAR,
            self.CLEAR_STATUS_CLEAR: self.GAME_CLEAR_STATUS_CLEAR,
            self.CLEAR_STATUS_HARD_CLEAR: self.GAME_CLEAR_STATUS_HARD_CLEAR,
            self.CLEAR_STATUS_EX_HARD_CLEAR: self.GAME_CLEAR_STATUS_EX_HARD_CLEAR,
            self.CLEAR_STATUS_FULL_COMBO: self.GAME_CLEAR_STATUS_FULL_COMBO,
        }[db_status]

    def game_to_db_status(self, game_status: int) -> int:
        return {
            self.GAME_CLEAR_STATUS_NO_PLAY: self.CLEAR_STATUS_NO_PLAY,
            self.GAME_CLEAR_STATUS_FAILED: self.CLEAR_STATUS_FAILED,
            self.GAME_CLEAR_STATUS_ASSIST_CLEAR: self.CLEAR_STATUS_ASSIST_CLEAR,
            self.GAME_CLEAR_STATUS_EASY_CLEAR: self.CLEAR_STATUS_EASY_CLEAR,
            self.GAME_CLEAR_STATUS_CLEAR: self.CLEAR_STATUS_CLEAR,
            self.GAME_CLEAR_STATUS_HARD_CLEAR: self.CLEAR_STATUS_HARD_CLEAR,
            self.GAME_CLEAR_STATUS_EX_HARD_CLEAR: self.CLEAR_STATUS_EX_HARD_CLEAR,
            self.GAME_CLEAR_STATUS_FULL_COMBO: self.CLEAR_STATUS_FULL_COMBO,
        }[game_status]

    def db_to_game_rank(self, db_dan: int, cltype: int) -> int:
        # Special case for no DAN rank
        if db_dan == -1:
            return -1

        if cltype == self.GAME_CLTYPE_SINGLE:
            return {
                self.DAN_RANK_7_KYU: self.GAME_SP_DAN_RANK_7_KYU,
                self.DAN_RANK_6_KYU: self.GAME_SP_DAN_RANK_6_KYU,
                self.DAN_RANK_5_KYU: self.GAME_SP_DAN_RANK_5_KYU,
                self.DAN_RANK_4_KYU: self.GAME_SP_DAN_RANK_4_KYU,
                self.DAN_RANK_3_KYU: self.GAME_SP_DAN_RANK_3_KYU,
                self.DAN_RANK_2_KYU: self.GAME_SP_DAN_RANK_2_KYU,
                self.DAN_RANK_1_KYU: self.GAME_SP_DAN_RANK_1_KYU,
                self.DAN_RANK_1_DAN: self.GAME_SP_DAN_RANK_1_DAN,
                self.DAN_RANK_2_DAN: self.GAME_SP_DAN_RANK_2_DAN,
                self.DAN_RANK_3_DAN: self.GAME_SP_DAN_RANK_3_DAN,
                self.DAN_RANK_4_DAN: self.GAME_SP_DAN_RANK_4_DAN,
                self.DAN_RANK_5_DAN: self.GAME_SP_DAN_RANK_5_DAN,
                self.DAN_RANK_6_DAN: self.GAME_SP_DAN_RANK_6_DAN,
                self.DAN_RANK_7_DAN: self.GAME_SP_DAN_RANK_7_DAN,
                self.DAN_RANK_8_DAN: self.GAME_SP_DAN_RANK_8_DAN,
                self.DAN_RANK_9_DAN: self.GAME_SP_DAN_RANK_9_DAN,
                self.DAN_RANK_10_DAN: self.GAME_SP_DAN_RANK_10_DAN,
                self.DAN_RANK_KAIDEN: self.GAME_SP_DAN_RANK_KAIDEN,
            }[db_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
                self.DAN_RANK_5_KYU: self.GAME_DP_DAN_RANK_5_KYU,
                self.DAN_RANK_4_KYU: self.GAME_DP_DAN_RANK_4_KYU,
                self.DAN_RANK_3_KYU: self.GAME_DP_DAN_RANK_3_KYU,
                self.DAN_RANK_2_KYU: self.GAME_DP_DAN_RANK_2_KYU,
                self.DAN_RANK_1_KYU: self.GAME_DP_DAN_RANK_1_KYU,
                self.DAN_RANK_1_DAN: self.GAME_DP_DAN_RANK_1_DAN,
                self.DAN_RANK_2_DAN: self.GAME_DP_DAN_RANK_2_DAN,
                self.DAN_RANK_3_DAN: self.GAME_DP_DAN_RANK_3_DAN,
                self.DAN_RANK_4_DAN: self.GAME_DP_DAN_RANK_4_DAN,
                self.DAN_RANK_5_DAN: self.GAME_DP_DAN_RANK_5_DAN,
                self.DAN_RANK_6_DAN: self.GAME_DP_DAN_RANK_6_DAN,
                self.DAN_RANK_7_DAN: self.GAME_DP_DAN_RANK_7_DAN,
                self.DAN_RANK_8_DAN: self.GAME_DP_DAN_RANK_8_DAN,
                self.DAN_RANK_9_DAN: self.GAME_DP_DAN_RANK_9_DAN,
                self.DAN_RANK_10_DAN: self.GAME_DP_DAN_RANK_10_DAN,
                self.DAN_RANK_KAIDEN: self.GAME_DP_DAN_RANK_KAIDEN,
            }[db_dan]
        else:
            raise Exception('Invalid cltype!')

    def game_to_db_rank(self, game_dan: int, cltype: int) -> int:
        # Special case for no DAN rank
        if game_dan == -1:
            return -1

        if cltype == self.GAME_CLTYPE_SINGLE:
            return {
                self.GAME_SP_DAN_RANK_7_KYU: self.DAN_RANK_7_KYU,
                self.GAME_SP_DAN_RANK_6_KYU: self.DAN_RANK_6_KYU,
                self.GAME_SP_DAN_RANK_5_KYU: self.DAN_RANK_5_KYU,
                self.GAME_SP_DAN_RANK_4_KYU: self.DAN_RANK_4_KYU,
                self.GAME_SP_DAN_RANK_3_KYU: self.DAN_RANK_3_KYU,
                self.GAME_SP_DAN_RANK_2_KYU: self.DAN_RANK_2_KYU,
                self.GAME_SP_DAN_RANK_1_KYU: self.DAN_RANK_1_KYU,
                self.GAME_SP_DAN_RANK_1_DAN: self.DAN_RANK_1_DAN,
                self.GAME_SP_DAN_RANK_2_DAN: self.DAN_RANK_2_DAN,
                self.GAME_SP_DAN_RANK_3_DAN: self.DAN_RANK_3_DAN,
                self.GAME_SP_DAN_RANK_4_DAN: self.DAN_RANK_4_DAN,
                self.GAME_SP_DAN_RANK_5_DAN: self.DAN_RANK_5_DAN,
                self.GAME_SP_DAN_RANK_6_DAN: self.DAN_RANK_6_DAN,
                self.GAME_SP_DAN_RANK_7_DAN: self.DAN_RANK_7_DAN,
                self.GAME_SP_DAN_RANK_8_DAN: self.DAN_RANK_8_DAN,
                self.GAME_SP_DAN_RANK_9_DAN: self.DAN_RANK_9_DAN,
                self.GAME_SP_DAN_RANK_10_DAN: self.DAN_RANK_10_DAN,
                self.GAME_SP_DAN_RANK_KAIDEN: self.DAN_RANK_KAIDEN,
            }[game_dan]
        elif cltype == self.GAME_CLTYPE_DOUBLE:
            return {
                self.GAME_DP_DAN_RANK_5_KYU: self.DAN_RANK_5_KYU,
                self.GAME_DP_DAN_RANK_4_KYU: self.DAN_RANK_4_KYU,
                self.GAME_DP_DAN_RANK_3_KYU: self.DAN_RANK_3_KYU,
                self.GAME_DP_DAN_RANK_2_KYU: self.DAN_RANK_2_KYU,
                self.GAME_DP_DAN_RANK_1_KYU: self.DAN_RANK_1_KYU,
                self.GAME_DP_DAN_RANK_1_DAN: self.DAN_RANK_1_DAN,
                self.GAME_DP_DAN_RANK_2_DAN: self.DAN_RANK_2_DAN,
                self.GAME_DP_DAN_RANK_3_DAN: self.DAN_RANK_3_DAN,
                self.GAME_DP_DAN_RANK_4_DAN: self.DAN_RANK_4_DAN,
                self.GAME_DP_DAN_RANK_5_DAN: self.DAN_RANK_5_DAN,
                self.GAME_DP_DAN_RANK_6_DAN: self.DAN_RANK_6_DAN,
                self.GAME_DP_DAN_RANK_7_DAN: self.DAN_RANK_7_DAN,
                self.GAME_DP_DAN_RANK_8_DAN: self.DAN_RANK_8_DAN,
                self.GAME_DP_DAN_RANK_9_DAN: self.DAN_RANK_9_DAN,
                self.GAME_DP_DAN_RANK_10_DAN: self.DAN_RANK_10_DAN,
                self.GAME_DP_DAN_RANK_KAIDEN: self.DAN_RANK_KAIDEN,
            }[game_dan]
        else:
            raise Exception('Invalid cltype!')

    def handle_IIDX21shop_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'getname':
            root = Node.void('IIDX21shop')
            root.set_attribute('cls_opt', '0')
            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            root.set_attribute('opname', machine.name)
            root.set_attribute('pid', '51')
            return root

        if method == 'savename':
            self.update_machine_name(request.attribute('opname'))
            root = Node.void('IIDX21shop')
            return root

        if method == 'sentinfo':
            root = Node.void('IIDX21shop')
            return root

        if method == 'getconvention':
            root = Node.void('IIDX21shop')
            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine.arcade is not None:
                course = self.data.local.machine.get_settings(machine.arcade, self.game, self.music_version, 'shop_course')
            else:
                course = None

            if course is None:
                course = ValidatedDict()

            root.set_attribute('music_0', str(course.get_int('music_0', 20032)))
            root.set_attribute('music_1', str(course.get_int('music_1', 20009)))
            root.set_attribute('music_2', str(course.get_int('music_2', 20015)))
            root.set_attribute('music_3', str(course.get_int('music_3', 20064)))
            root.add_child(Node.bool('valid', course.get_bool('valid')))
            return root

        if method == 'setconvention':
            root = Node.void('IIDX21shop')
            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine.arcade is not None:
                course = ValidatedDict()
                course.replace_int('music_0', request.child_value('music_0'))
                course.replace_int('music_1', request.child_value('music_1'))
                course.replace_int('music_2', request.child_value('music_2'))
                course.replace_int('music_3', request.child_value('music_3'))
                course.replace_bool('valid', request.child_value('valid'))
                self.data.local.machine.put_settings(machine.arcade, self.game, self.music_version, 'shop_course', course)

            return root

        # Invalid method
        return None

    def handle_IIDX21ranking_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'getranker':
            root = Node.void('IIDX21ranking')
            chart = int(request.attribute('clid'))
            if chart not in [
                self.CHART_TYPE_N7,
                self.CHART_TYPE_H7,
                self.CHART_TYPE_A7,
                self.CHART_TYPE_N14,
                self.CHART_TYPE_H14,
                self.CHART_TYPE_A14,
            ]:
                # Chart type 6 is presumably beginner mode, but it crashes the game
                return root

            machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            if machine.arcade is not None:
                course = self.data.local.machine.get_settings(machine.arcade, self.game, self.music_version, 'shop_course')
            else:
                course = None

            if course is None:
                course = ValidatedDict()

            if not course.get_bool('valid'):
                # Shop course not enabled or not present
                return root

            convention = Node.void('convention')
            root.add_child(convention)
            convention.set_attribute('clid', str(chart))
            convention.set_attribute('update_date', str(Time.now() * 1000))

            # Grab all scores for each of the four songs, filter out people who haven't
            # set us as their arcade and then return the top 20 scores (adding all 4 songs).
            songids = [
                course.get_int('music_0'),
                course.get_int('music_1'),
                course.get_int('music_2'),
                course.get_int('music_3'),
            ]

            totalscores: Dict[UserID, int] = {}
            profiles: Dict[UserID, ValidatedDict] = {}
            for songid in songids:
                scores = self.data.local.music.get_all_scores(
                    self.game,
                    self.music_version,
                    songid=songid,
                    songchart=chart,
                )

                for score in scores:
                    if score[0] not in totalscores:
                        totalscores[score[0]] = 0
                        profile = self.get_any_profile(score[0])
                        if profile is None:
                            profile = ValidatedDict()
                        profiles[score[0]] = profile

                    totalscores[score[0]] += score[1].points

            topscores = sorted(
                [
                    (totalscores[userid], profiles[userid])
                    for userid in totalscores
                    if self.user_joined_arcade(machine, profiles[userid])
                ],
                key=lambda tup: tup[0],
                reverse=True,
            )[:20]

            rank = 0
            for topscore in topscores:
                rank = rank + 1

                detail = Node.void('detail')
                convention.add_child(detail)
                detail.set_attribute('name', topscore[1].get_str('name'))
                detail.set_attribute('rank', str(rank))
                detail.set_attribute('score', str(topscore[0]))
                detail.set_attribute('pid', str(topscore[1].get_int('pid')))

                qpro = topscore[1].get_dict('qpro')
                detail.set_attribute('head', str(qpro.get_int('head')))
                detail.set_attribute('hair', str(qpro.get_int('hair')))
                detail.set_attribute('face', str(qpro.get_int('face')))
                detail.set_attribute('body', str(qpro.get_int('body')))
                detail.set_attribute('hand', str(qpro.get_int('hand')))

            return root

        # Invalid method
        return None

    def handle_IIDX21music_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'crate':
            root = Node.void('IIDX21music')
            attempts = self.get_clear_rates()

            all_songs = list(set([song.id for song in self.data.local.music.get_all_songs(self.game, self.music_version)]))
            for song in all_songs:
                clears = []
                fcs = []

                for chart in [0, 1, 2, 3, 4, 5]:
                    placed = False
                    if song in attempts and chart in attempts[song]:
                        values = attempts[song][chart]
                        if values['total'] > 0:
                            clears.append(int((100 * values['clears']) / values['total']))
                            fcs.append(int((100 * values['fcs']) / values['total']))
                            placed = True
                    if not placed:
                        clears.append(101)
                        fcs.append(101)

                clearnode = Node.u8_array('c', clears + fcs)
                clearnode.set_attribute('mid', str(song))
                root.add_child(clearnode)

            return root

        if method == 'getrank':
            cltype = int(request.attribute('cltype'))

            root = Node.void('IIDX21music')
            style = Node.void('style')
            root.add_child(style)
            style.set_attribute('type', str(cltype))

            for rivalid in [-1, 0, 1, 2, 3, 4]:
                if rivalid == -1:
                    attr = 'iidxid'
                else:
                    attr = f'iidxid{rivalid}'

                try:
                    extid = int(request.attribute(attr))
                except Exception:
                    # Invalid extid
                    continue
                userid = self.data.remote.user.from_extid(self.game, self.version, extid)
                if userid is not None:
                    scores = self.data.remote.music.get_scores(self.game, self.music_version, userid)

                    # Grab score data for user/rival
                    scoredata = self.make_score_struct(
                        scores,
                        self.CLEAR_TYPE_SINGLE if cltype == self.GAME_CLTYPE_SINGLE else self.CLEAR_TYPE_DOUBLE,
                        rivalid,
                    )
                    for s in scoredata:
                        root.add_child(Node.s16_array('m', s))

                    # Grab most played for user/rival
                    most_played = [
                        play[0] for play in
                        self.data.local.music.get_most_played(self.game, self.music_version, userid, 20)
                    ]
                    if len(most_played) < 20:
                        most_played.extend([0] * (20 - len(most_played)))
                    best = Node.u16_array('best', most_played)
                    best.set_attribute('rno', str(rivalid))
                    root.add_child(best)

                    if rivalid == -1:
                        # Grab beginner statuses for user only
                        beginnerdata = self.make_beginner_struct(scores)
                        for b in beginnerdata:
                            root.add_child(Node.u16_array('b', b))

            return root

        if method == 'reg':
            extid = int(request.attribute('iidxid'))
            musicid = int(request.attribute('mid'))
            chart = int(request.attribute('clid'))
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

            # See if we need to report global or shop scores
            if self.machine_joined_arcade():
                game_config = self.get_game_config()
                global_scores = game_config.get_bool('global_shop_ranking')
                machine = self.data.local.machine.get_machine(self.config['machine']['pcbid'])
            else:
                # If we aren't in an arcade, we can only show global scores
                global_scores = True
                machine = None

            # First, determine our current ranking before saving the new score
            all_scores = sorted(
                self.data.remote.music.get_all_scores(game=self.game, version=self.music_version, songid=musicid, songchart=chart),
                key=lambda s: (s[1].points, s[1].timestamp),
                reverse=True,
            )
            all_players = {
                uid: prof for (uid, prof) in
                self.get_any_profiles([s[0] for s in all_scores])
            }

            if not global_scores:
                all_scores = [
                    score for score in all_scores
                    if (
                        score[0] == userid or
                        self.user_joined_arcade(machine, all_players[score[0]])
                    )
                ]

            # Find our actual index
            oldindex = None
            for i in range(len(all_scores)):
                if all_scores[i][0] == userid:
                    oldindex = i
                    break

            if userid is not None:
                clear_status = self.game_to_db_status(int(request.attribute('cflg')))
                pgreats = int(request.attribute('pgnum'))
                greats = int(request.attribute('gnum'))
                miss_count = int(request.attribute('mnum'))
                ghost = request.child_value('ghost')
                shopid = ID.parse_machine_id(request.attribute('shopconvid'))

                self.update_score(
                    userid,
                    musicid,
                    chart,
                    clear_status,
                    pgreats,
                    greats,
                    miss_count,
                    ghost,
                    shopid,
                )

            # Calculate and return statistics about this song
            root = Node.void('IIDX21music')
            root.set_attribute('clid', request.attribute('clid'))
            root.set_attribute('mid', request.attribute('mid'))

            attempts = self.get_clear_rates(musicid, chart)
            count = attempts[musicid][chart]['total']
            clear = attempts[musicid][chart]['clears']
            full_combo = attempts[musicid][chart]['fcs']

            if count > 0:
                root.set_attribute('crate', str(int((100 * clear) / count)))
                root.set_attribute('frate', str(int((100 * full_combo) / count)))
            else:
                root.set_attribute('crate', '0')
                root.set_attribute('frate', '0')
            root.set_attribute('rankside', '0')

            if userid is not None:
                # Shop ranking
                shopdata = Node.void('shopdata')
                root.add_child(shopdata)
                shopdata.set_attribute('rank', '-1' if oldindex is None else str(oldindex + 1))

                # Grab the rank of some other players on this song
                ranklist = Node.void('ranklist')
                root.add_child(ranklist)

                all_scores = sorted(
                    self.data.remote.music.get_all_scores(game=self.game, version=self.music_version, songid=musicid, songchart=chart),
                    key=lambda s: (s[1].points, s[1].timestamp),
                    reverse=True,
                )
                missing_players = [
                    uid for (uid, _) in all_scores
                    if uid not in all_players
                ]
                for (uid, prof) in self.get_any_profiles(missing_players):
                    all_players[uid] = prof

                if not global_scores:
                    all_scores = [
                        score for score in all_scores
                        if (
                            score[0] == userid or
                            self.user_joined_arcade(machine, all_players[score[0]])
                        )
                    ]

                # Find our actual index
                ourindex = None
                for i in range(len(all_scores)):
                    if all_scores[i][0] == userid:
                        ourindex = i
                        break
                if ourindex is None:
                    raise Exception('Cannot find our own score after saving to DB!')
                start = ourindex - 4
                end = ourindex + 4
                if start < 0:
                    start = 0
                if end >= len(all_scores):
                    end = len(all_scores) - 1
                relevant_scores = all_scores[start:(end + 1)]

                record_num = start + 1
                for score in relevant_scores:
                    profile = all_players[score[0]]

                    data = Node.void('data')
                    ranklist.add_child(data)
                    data.set_attribute('iidx_id', str(profile.get_int('extid')))
                    data.set_attribute('name', profile.get_str('name'))

                    machine_name = ''
                    if 'shop_location' in profile:
                        shop_id = profile.get_int('shop_location')
                        machine = self.get_machine_by_id(shop_id)
                        if machine is not None:
                            machine_name = machine.name
                    data.set_attribute('opname', machine_name)
                    data.set_attribute('rnum', str(record_num))
                    data.set_attribute('score', str(score[1].points))
                    data.set_attribute('clflg', str(self.db_to_game_status(score[1].data.get_int('clear_status'))))
                    data.set_attribute('pid', str(profile.get_int('pid')))
                    data.set_attribute('myFlg', '1' if score[0] == userid else '0')
                    data.set_attribute('update', '0')

                    data.set_attribute('sgrade', str(
                        self.db_to_game_rank(profile.get_int(self.DAN_RANKING_SINGLE, -1), self.GAME_CLTYPE_SINGLE),
                    ))
                    data.set_attribute('dgrade', str(
                        self.db_to_game_rank(profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.GAME_CLTYPE_DOUBLE),
                    ))

                    qpro = profile.get_dict('qpro')
                    data.set_attribute('head', str(qpro.get_int('head')))
                    data.set_attribute('hair', str(qpro.get_int('hair')))
                    data.set_attribute('face', str(qpro.get_int('face')))
                    data.set_attribute('body', str(qpro.get_int('body')))
                    data.set_attribute('hand', str(qpro.get_int('hand')))

                    record_num = record_num + 1

            return root

        if method == 'breg':
            extid = int(request.attribute('iidxid'))
            musicid = int(request.attribute('mid'))
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

            if userid is not None:
                clear_status = self.game_to_db_status(int(request.attribute('cflg')))
                pgreats = int(request.attribute('pgnum'))
                greats = int(request.attribute('gnum'))

                self.update_score(
                    userid,
                    musicid,
                    self.CHART_TYPE_B7,
                    clear_status,
                    pgreats,
                    greats,
                    -1,
                    b'',
                    None,
                )

            # Return nothing.
            root = Node.void('IIDX21music')
            return root

        if method == 'play':
            musicid = int(request.attribute('mid'))
            chart = int(request.attribute('clid'))
            clear_status = self.game_to_db_status(int(request.attribute('cflg')))

            self.update_score(
                None,  # No userid since its anonymous
                musicid,
                chart,
                clear_status,
                0,  # No ex score
                0,  # No ex score
                0,  # No miss count
                None,  # No ghost
                None,  # No shop for this user
            )

            # Calculate and return statistics about this song
            root = Node.void('IIDX21music')
            root.set_attribute('clid', request.attribute('clid'))
            root.set_attribute('mid', request.attribute('mid'))

            attempts = self.get_clear_rates(musicid, chart)
            count = attempts[musicid][chart]['total']
            clear = attempts[musicid][chart]['clears']
            full_combo = attempts[musicid][chart]['fcs']

            if count > 0:
                root.set_attribute('crate', str(int((100 * clear) / count)))
                root.set_attribute('frate', str(int((100 * full_combo) / count)))
            else:
                root.set_attribute('crate', '0')
                root.set_attribute('frate', '0')

            return root

        if method == 'appoint':
            musicid = int(request.attribute('mid'))
            chart = int(request.attribute('clid'))
            ghost_type = int(request.attribute('ctype'))
            extid = int(request.attribute('iidxid'))
            userid = self.data.remote.user.from_extid(self.game, self.version, extid)

            root = Node.void('IIDX21music')

            if userid is not None:
                # Try to look up previous ghost for user
                my_score = self.data.remote.music.get_score(self.game, self.music_version, userid, musicid, chart)
                if my_score is not None:
                    mydata = Node.binary('mydata', my_score.data.get_bytes('ghost'))
                    mydata.set_attribute('score', str(my_score.points))
                    root.add_child(mydata)

                ghost_score = self.get_ghost(
                    {
                        self.GAME_GHOST_TYPE_RIVAL: self.GHOST_TYPE_RIVAL,
                        self.GAME_GHOST_TYPE_GLOBAL_TOP: self.GHOST_TYPE_GLOBAL_TOP,
                        self.GAME_GHOST_TYPE_GLOBAL_AVERAGE: self.GHOST_TYPE_GLOBAL_AVERAGE,
                        self.GAME_GHOST_TYPE_LOCAL_TOP: self.GHOST_TYPE_LOCAL_TOP,
                        self.GAME_GHOST_TYPE_LOCAL_AVERAGE: self.GHOST_TYPE_LOCAL_AVERAGE,
                        self.GAME_GHOST_TYPE_DAN_TOP: self.GHOST_TYPE_DAN_TOP,
                        self.GAME_GHOST_TYPE_DAN_AVERAGE: self.GHOST_TYPE_DAN_AVERAGE,
                        self.GAME_GHOST_TYPE_RIVAL_TOP: self.GHOST_TYPE_RIVAL_TOP,
                        self.GAME_GHOST_TYPE_RIVAL_AVERAGE: self.GHOST_TYPE_RIVAL_AVERAGE,
                    }.get(ghost_type, self.GHOST_TYPE_NONE),
                    request.attribute('subtype'),
                    self.GAME_GHOST_LENGTH,
                    musicid,
                    chart,
                    userid,
                )

                # Add ghost score if we support it
                if ghost_score is not None:
                    sdata = Node.binary('sdata', ghost_score['ghost'])
                    sdata.set_attribute('score', str(ghost_score['score']))
                    if 'name' in ghost_score:
                        sdata.set_attribute('name', ghost_score['name'])
                    if 'pid' in ghost_score:
                        sdata.set_attribute('pid', str(ghost_score['pid']))
                    if 'extid' in ghost_score:
                        sdata.set_attribute('riidxid', str(ghost_score['extid']))
                    root.add_child(sdata)

            return root

        # Invalid method
        return None

    def handle_IIDX21pc_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'common':
            root = Node.void('IIDX21pc')
            root.set_attribute('expire', '600')

            # TODO: Hook all of these up to config options I guess?
            ir = Node.void('ir')
            root.add_child(ir)
            ir.set_attribute('beat', '2')

            limit = Node.void('limit')
            root.add_child(limit)
            limit.set_attribute('phase', '24')

            # See if we configured event overrides
            if self.machine_joined_arcade():
                game_config = self.get_game_config()
                omni_events = game_config.get_bool('omnimix_events_enabled')
            else:
                # If we aren't in an arcade, we turn off events
                omni_events = False

            if self.omnimix and (not omni_events):
                boss_phase = 0
            else:
                # TODO: Figure out what these map to
                boss_phase = 0

            boss = Node.void('boss')
            root.add_child(boss)
            boss.set_attribute('phase', str(boss_phase))

            boss1 = Node.void('boss1')
            root.add_child(boss1)
            boss1.set_attribute('phase', '1')

            medal = Node.void('medal')
            root.add_child(medal)
            medal.set_attribute('phase', '1')

            vip_black_pass = Node.void('vip_pass_black')
            root.add_child(vip_black_pass)

            cafe = Node.void('cafe')
            root.add_child(cafe)
            cafe.set_attribute('open', '1')

            tricolettepark = Node.void('tricolettepark')
            root.add_child(tricolettepark)
            tricolettepark.set_attribute('open', '0')

            tricolettepark_skip = Node.void('tricolettepark_skip')
            root.add_child(tricolettepark_skip)
            tricolettepark_skip.set_attribute('phase', '1')

            newsong_another = Node.void('newsong_another')
            root.add_child(newsong_another)
            newsong_another.set_attribute('open', '1')

            superstar = Node.void('superstar')
            root.add_child(superstar)
            superstar.set_attribute('phase', '1')

            return root

        if method == 'delete':
            return Node.void('IIDX21pc')

        if method == 'playstart':
            return Node.void('IIDX21pc')

        if method == 'playend':
            return Node.void('IIDX21pc')

        if method == 'oldget':
            refid = request.attribute('rid')
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is not None:
                oldversion = self.previous_version()
                profile = oldversion.get_profile(userid)
            else:
                profile = None

            root = Node.void('IIDX21pc')
            root.set_attribute('status', '1' if profile is None else '0')
            return root

        if method == 'getname':
            refid = request.attribute('rid')
            userid = self.data.remote.user.from_refid(self.game, self.version, refid)
            if userid is not None:
                oldversion = self.previous_version()
                profile = oldversion.get_profile(userid)
            else:
                profile = None
            if profile is None:
                raise Exception(
                    'Should not get here if we have no profile, we should ' +
                    'have returned \'1\' in the \'oldget\' method above ' +
                    'which should tell the game not to present a migration.'
                )

            root = Node.void('IIDX21pc')
            root.set_attribute('name', profile.get_str('name'))
            root.set_attribute('idstr', ID.format_extid(profile.get_int('extid')))
            root.set_attribute('pid', str(profile.get_int('pid')))
            return root

        if method == 'takeover':
            refid = request.attribute('rid')
            name = request.attribute('name')
            pid = int(request.attribute('pid'))
            newprofile = self.new_profile_by_refid(refid, name, pid)

            root = Node.void('IIDX21pc')
            if newprofile is not None:
                root.set_attribute('id', str(newprofile.get_int('extid')))
            return root

        if method == 'reg':
            refid = request.attribute('rid')
            name = request.attribute('name')
            pid = int(request.attribute('pid'))
            profile = self.new_profile_by_refid(refid, name, pid)

            root = Node.void('IIDX21pc')
            if profile is not None:
                root.set_attribute('id', str(profile.get_int('extid')))
                root.set_attribute('id_str', ID.format_extid(profile.get_int('extid')))
            return root

        if method == 'get':
            refid = request.attribute('rid')
            root = self.get_profile_by_refid(refid)
            if root is None:
                root = Node.void('IIDX21pc')
            return root

        if method == 'save':
            extid = int(request.attribute('iidxid'))
            self.put_profile_by_extid(extid, request)

            root = Node.void('IIDX21pc')
            return root

        if method == 'visit':
            root = Node.void('IIDX21pc')
            root.set_attribute('anum', '0')
            root.set_attribute('pnum', '0')
            root.set_attribute('sflg', '0')
            root.set_attribute('pflg', '0')
            root.set_attribute('aflg', '0')
            root.set_attribute('snum', '0')
            return root

        if method == 'shopregister':
            extid = int(request.child_value('iidx_id'))
            location = ID.parse_machine_id(request.child_value('location_id'))

            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
            if userid is not None:
                profile = self.get_profile(userid)
                if profile is None:
                    profile = ValidatedDict()
                profile.replace_int('shop_location', location)
                self.put_profile(userid, profile)

            root = Node.void('IIDX21pc')
            return root

        # Invalid method
        return None

    def handle_IIDX21grade_request(self, request: Node) -> Optional[Node]:
        method = request.attribute('method')

        if method == 'raised':
            extid = int(request.attribute('iidxid'))
            cltype = int(request.attribute('gtype'))
            rank = self.game_to_db_rank(int(request.attribute('gid')), cltype)

            userid = self.data.remote.user.from_extid(self.game, self.version, extid)
            if userid is not None:
                percent = int(request.attribute('achi'))
                stages_cleared = int(request.attribute('cflg'))
                if cltype == self.GAME_CLTYPE_SINGLE:
                    max_stages = self.DAN_STAGES_SINGLE
                else:
                    max_stages = self.DAN_STAGES_DOUBLE
                cleared = stages_cleared == max_stages

                if cltype == self.GAME_CLTYPE_SINGLE:
                    index = self.DAN_RANKING_SINGLE
                else:
                    index = self.DAN_RANKING_DOUBLE

                self.update_rank(
                    userid,
                    index,
                    rank,
                    percent,
                    cleared,
                    stages_cleared,
                )

            # Figure out number of players that played this ranking
            all_achievements = self.data.local.user.get_all_achievements(self.game, self.version)
            num_players = 0
            for [_, ach] in all_achievements:
                if ach.type != index:
                    continue
                if ach.id != rank:
                    continue
                num_players = num_players + 1

            root = Node.void('IIDX21grade')
            root.set_attribute('pnum', str(num_players))
            return root

        # Invalid method
        return None

    def handle_IIDX21pc_eaappliresult_request(self, request: Node) -> Node:
        # first, we register the iidx webhook. this is done by sending all of our money to konami
        if self.config['webhooks'][self.game] is None:
            return Node.void('IIDX21pc')
        webhook = DiscordWebhook(url=self.config['webhooks'][self.game])

        clear_map = {
            self.GAME_CLEAR_STATUS_NO_PLAY: 'NO PLAY',
            self.GAME_CLEAR_STATUS_FAILED: 'FAILED',
            self.GAME_CLEAR_STATUS_ASSIST_CLEAR: 'ASSIST CLEAR',
            self.GAME_CLEAR_STATUS_EASY_CLEAR: 'EASY CLEAR',
            self.GAME_CLEAR_STATUS_CLEAR: 'CLEAR',
            self.GAME_CLEAR_STATUS_HARD_CLEAR: 'HARD CLEAR',
            self.GAME_CLEAR_STATUS_EX_HARD_CLEAR: 'EX HARD CLEAR',
            self.GAME_CLEAR_STATUS_FULL_COMBO: 'FULL COMBO',
        }
        # first we'll grab the data from the packet
        # did = request.child_value('did')
        # rid = request.child_value('rid')
        name = request.child_value('name')
        # qpro_hair = request.child_value('qpro_hair')
        # qpro_head = request.child_value('qpro_head')
        # qpro_body = request.child_value('qpro_body')
        # qpro_hand = request.child_value('qpro_hand')
        music_id = request.child_value('music_id')
        class_id = request.child_value('class_id')
        # no_save = request.child_value('no_save')
        # is_couple = request.child_value('is_couple')
        # target_graph = request.child_value('target_graph')
        target_exscore = request.child_value('target_exscore')
        # pacemaker = request.child_value('pacemaker')
        best_clear = request.child_value('best_clear')
        # best_djlevel = request.child_value('best_djlevel')
        # best_exscore = request.child_value('best_exscore')
        # best_misscount = request.child_value('best_misscount')
        now_clear = request.child_value('now_clear')
        # now_djlevel = request.child_value('now_djlevel')
        now_exscore = request.child_value('now_exscore')
        # now_misscount = request.child_value('now_misscount')
        now_pgreat = request.child_value('now_pgreat')
        now_great = request.child_value('now_great')
        now_good = request.child_value('now_good')
        now_bad = request.child_value('now_bad')
        now_poor = request.child_value('now_poor')
        now_combo = request.child_value('now_combo')
        now_fast = request.child_value('now_fast')
        now_slow = request.child_value('now_slow')
        best_clear_string = clear_map.get(best_clear, 'NO PLAY')
        now_clear_string = clear_map.get(now_clear, 'NO PLAY')
        # let's get the song info first
        song = self.data.local.music.get_song(self.game, self.music_version, music_id, class_id)

        # now we will build up the embed
        now = datetime.now()

        # now, we generate the embed
        scoreembed = DiscordEmbed(title='New IIDX Score!', description="Login to see whole score.", color='fbba08')
        scoreembed.set_footer(text=(now.strftime('Score was recorded on %m/%d/%y at %H:%M:%S')))

        # lets give it an author
        scoreembed.set_author(name=self.config['name'], url=self.config['server']['uri'])
        # Set `inline=False` for the embed field to occupy the whole line
        scoreembed.add_embed_field(name='DJ Name', value=(name), inline=False)
        scoreembed.add_embed_field(name='Song', value=(song.name), inline=False)
        scoreembed.add_embed_field(name='Artist', value=(song.artist), inline=False)
        scoreembed.add_embed_field(name='Difficulty', value=(song.data.get('difficulty', 0)))
        scoreembed.add_embed_field(name='Target EXScore', value=(target_exscore))
        scoreembed.add_embed_field(name='Your EXScore', value=(now_exscore))
        scoreembed.add_embed_field(name='Best Clear', value=best_clear_string)
        scoreembed.add_embed_field(name='Clear Status', value=now_clear_string)
        scoreembed.add_embed_field(name='Note Counts', value='How did you do?', inline=False)
        scoreembed.add_embed_field(name=('Perfect Greats'), value=((now_pgreat)))
        scoreembed.add_embed_field(name=('Greats'), value=((now_great)))
        scoreembed.add_embed_field(name=('Goods'), value=((now_good)))
        scoreembed.add_embed_field(name=('Bads'), value=((now_bad)))
        scoreembed.add_embed_field(name=('Poors'), value=((now_poor)))

        scoreembed.add_embed_field(name='Combo Breaks', value=(now_combo))

        # scoreembed.add_embed_field(name='Timing Stats', value='Were you on time?', inline = False)
        scoreembed.add_embed_field(name=('Slow'), value=((now_slow)))
        scoreembed.add_embed_field(name=('Fast'), value=((now_fast)))

        # add embed object to webhook
        webhook.add_embed(scoreembed)

        # now we send the webhook!
        webhook.execute()

        end = Node.void('IIDX21pc')

        return end

    def format_profile(self, userid: UserID, profile: ValidatedDict) -> Node:
        root = Node.void('IIDX21pc')

        # Look up play stats we bridge to every mix
        play_stats = self.get_play_statistics(userid)

        # Look up judge window adjustments
        judge_dict = profile.get_dict('machine_judge_adjust')
        machine_judge = judge_dict.get_dict(self.config['machine']['pcbid'])

        # Profile data
        pcdata = Node.void('pcdata')
        root.add_child(pcdata)
        pcdata.set_attribute('id', str(profile.get_int('extid')))
        pcdata.set_attribute('idstr', ID.format_extid(profile.get_int('extid')))
        pcdata.set_attribute('name', profile.get_str('name'))
        pcdata.set_attribute('pid', str(profile.get_int('pid')))
        pcdata.set_attribute('spnum', str(play_stats.get_int('single_plays')))
        pcdata.set_attribute('dpnum', str(play_stats.get_int('double_plays')))
        pcdata.set_attribute('sach', str(play_stats.get_int('single_dj_points')))
        pcdata.set_attribute('dach', str(play_stats.get_int('double_dj_points')))
        pcdata.set_attribute('mode', str(profile.get_int('mode')))
        pcdata.set_attribute('pmode', str(profile.get_int('pmode')))
        pcdata.set_attribute('rtype', str(profile.get_int('rtype')))
        pcdata.set_attribute('sp_opt', str(profile.get_int('sp_opt')))
        pcdata.set_attribute('dp_opt', str(profile.get_int('dp_opt')))
        pcdata.set_attribute('dp_opt2', str(profile.get_int('dp_opt2')))
        pcdata.set_attribute('gpos', str(profile.get_int('gpos')))
        pcdata.set_attribute('s_sorttype', str(profile.get_int('s_sorttype')))
        pcdata.set_attribute('d_sorttype', str(profile.get_int('d_sorttype')))
        pcdata.set_attribute('s_pace', str(profile.get_int('s_pace')))
        pcdata.set_attribute('d_pace', str(profile.get_int('d_pace')))
        pcdata.set_attribute('s_gno', str(profile.get_int('s_gno')))
        pcdata.set_attribute('d_gno', str(profile.get_int('d_gno')))
        pcdata.set_attribute('s_gtype', str(profile.get_int('s_gtype')))
        pcdata.set_attribute('d_gtype', str(profile.get_int('d_gtype')))
        pcdata.set_attribute('s_sdlen', str(profile.get_int('s_sdlen')))
        pcdata.set_attribute('d_sdlen', str(profile.get_int('d_sdlen')))
        pcdata.set_attribute('s_sdtype', str(profile.get_int('s_sdtype')))
        pcdata.set_attribute('d_sdtype', str(profile.get_int('d_sdtype')))
        pcdata.set_attribute('s_timing', str(profile.get_int('s_timing')))
        pcdata.set_attribute('d_timing', str(profile.get_int('d_timing')))
        pcdata.set_attribute('s_notes', str(profile.get_float('s_notes')))
        pcdata.set_attribute('d_notes', str(profile.get_float('d_notes')))
        pcdata.set_attribute('s_judge', str(profile.get_int('s_judge')))
        pcdata.set_attribute('d_judge', str(profile.get_int('d_judge')))
        pcdata.set_attribute('s_judgeAdj', str(machine_judge.get_int('single')))
        pcdata.set_attribute('d_judgeAdj', str(machine_judge.get_int('double')))
        pcdata.set_attribute('s_hispeed', str(profile.get_float('s_hispeed')))
        pcdata.set_attribute('d_hispeed', str(profile.get_float('d_hispeed')))
        pcdata.set_attribute('s_liflen', str(profile.get_int('s_lift')))
        pcdata.set_attribute('d_liflen', str(profile.get_int('d_lift')))
        pcdata.set_attribute('s_disp_judge', str(profile.get_int('s_disp_judge')))
        pcdata.set_attribute('d_disp_judge', str(profile.get_int('d_disp_judge')))
        pcdata.set_attribute('s_opstyle', str(profile.get_int('s_opstyle')))
        pcdata.set_attribute('d_opstyle', str(profile.get_int('d_opstyle')))

        # If the user joined a particular shop, let the game know.
        if 'shop_location' in profile:
            shop_id = profile.get_int('shop_location')
            machine = self.get_machine_by_id(shop_id)
            if machine is not None:
                join_shop = Node.void('join_shop')
                root.add_child(join_shop)
                join_shop.set_attribute('joinflg', '1')
                join_shop.set_attribute('join_cflg', '1')
                join_shop.set_attribute('join_id', ID.format_machine_id(machine.id))
                join_shop.set_attribute('join_name', machine.name)

        # Daily recommendations
        entry = self.data.local.game.get_time_sensitive_settings(self.game, self.version, 'dailies')
        if entry is not None:
            packinfo = Node.void('packinfo')
            root.add_child(packinfo)

            pack_id = int(entry['start_time'] / 86400)
            packinfo.set_attribute('pack_id', str(pack_id))
            packinfo.set_attribute('music_0', str(entry['music'][0]))
            packinfo.set_attribute('music_1', str(entry['music'][1]))
            packinfo.set_attribute('music_2', str(entry['music'][2]))
        else:
            # No dailies :(
            pack_id = None

        # Track deller
        deller = Node.void('deller')
        root.add_child(deller)
        deller.set_attribute('deller', str(profile.get_int('deller')))
        deller.set_attribute('rate', '0')

        # Secret flags (shh!)
        secret_dict = profile.get_dict('secret')
        secret = Node.void('secret')
        root.add_child(secret)
        secret.add_child(Node.s64_array('flg1', secret_dict.get_int_array('flg1', 2)))
        secret.add_child(Node.s64_array('flg2', secret_dict.get_int_array('flg2', 2)))
        secret.add_child(Node.s64_array('flg3', secret_dict.get_int_array('flg3', 2)))

        # Tran medals and shit
        achievements = Node.void('achievements')
        root.add_child(achievements)

        # Dailies
        if pack_id is None:
            achievements.set_attribute('pack', '0')
            achievements.set_attribute('pack_comp', '0')
        else:
            daily_played = self.data.local.user.get_achievement(self.game, self.version, userid, pack_id, 'daily')
            if daily_played is None:
                daily_played = ValidatedDict()
            achievements.set_attribute('pack', str(daily_played.get_int('pack_flg')))
            achievements.set_attribute('pack_comp', str(daily_played.get_int('pack_comp')))

        # Weeklies
        achievements.set_attribute('last_weekly', str(profile.get_int('last_weekly')))
        achievements.set_attribute('weekly_num', str(profile.get_int('weekly_num')))

        # Prefecture visit flag
        achievements.set_attribute('visit_flg', str(profile.get_int('visit_flg')))

        # Number of rivals beaten
        achievements.set_attribute('rival_crush', str(profile.get_int('rival_crush')))

        # Tran medals
        achievements.add_child(Node.s64_array('trophy', profile.get_int_array('trophy', 10)))

        # User settings
        settings_dict = profile.get_dict('settings')
        skin = Node.s16_array(
            'skin',
            [
                settings_dict.get_int('frame'),
                settings_dict.get_int('turntable'),
                settings_dict.get_int('burst'),
                settings_dict.get_int('bgm'),
                settings_dict.get_int('flags'),
                settings_dict.get_int('towel'),
                settings_dict.get_int('judge_pos'),
                settings_dict.get_int('voice'),
                settings_dict.get_int('noteskin'),
                settings_dict.get_int('full_combo'),
                settings_dict.get_int('beam'),
                settings_dict.get_int('judge'),
                0,
                settings_dict.get_int('disable_song_preview'),
            ],
        )
        root.add_child(skin)

        # DAN rankings
        grade = Node.void('grade')
        root.add_child(grade)
        grade.set_attribute('sgid', str(self.db_to_game_rank(profile.get_int(self.DAN_RANKING_SINGLE, -1), self.GAME_CLTYPE_SINGLE)))
        grade.set_attribute('dgid', str(self.db_to_game_rank(profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.GAME_CLTYPE_DOUBLE)))
        rankings = self.data.local.user.get_achievements(self.game, self.version, userid)
        for rank in rankings:
            if rank.type == self.DAN_RANKING_SINGLE:
                grade.add_child(Node.u8_array('g', [
                    self.GAME_CLTYPE_SINGLE,
                    self.db_to_game_rank(rank.id, self.GAME_CLTYPE_SINGLE),
                    rank.data.get_int('stages_cleared'),
                    rank.data.get_int('percent'),
                ]))
            if rank.type == self.DAN_RANKING_DOUBLE:
                grade.add_child(Node.u8_array('g', [
                    self.GAME_CLTYPE_DOUBLE,
                    self.db_to_game_rank(rank.id, self.GAME_CLTYPE_DOUBLE),
                    rank.data.get_int('stages_cleared'),
                    rank.data.get_int('percent'),
                ]))

        # Qpro data
        qpro_dict = profile.get_dict('qpro')
        root.add_child(Node.u32_array(
            'qprodata',
            [
                qpro_dict.get_int('head'),
                qpro_dict.get_int('hair'),
                qpro_dict.get_int('face'),
                qpro_dict.get_int('hand'),
                qpro_dict.get_int('body'),
            ],
        ))

        # Rivals
        rlist = Node.void('rlist')
        root.add_child(rlist)
        links = self.data.local.user.get_links(self.game, self.version, userid)
        for link in links:
            rival_type = None
            if link.type == 'sp_rival':
                rival_type = '1'
            elif link.type == 'dp_rival':
                rival_type = '2'
            else:
                # No business with this link type
                continue

            other_profile = self.get_profile(link.other_userid)
            if other_profile is None:
                continue
            other_play_stats = self.get_play_statistics(link.other_userid)

            rival = Node.void('rival')
            rlist.add_child(rival)
            rival.set_attribute('spdp', rival_type)
            rival.set_attribute('id', str(other_profile.get_int('extid')))
            rival.set_attribute('id_str', ID.format_extid(other_profile.get_int('extid')))
            rival.set_attribute('djname', other_profile.get_str('name'))
            rival.set_attribute('pid', str(other_profile.get_int('pid')))
            rival.set_attribute('sg', str(self.db_to_game_rank(other_profile.get_int(self.DAN_RANKING_SINGLE, -1), self.GAME_CLTYPE_SINGLE)))
            rival.set_attribute('dg', str(self.db_to_game_rank(other_profile.get_int(self.DAN_RANKING_DOUBLE, -1), self.GAME_CLTYPE_DOUBLE)))
            rival.set_attribute('sa', str(other_play_stats.get_int('single_dj_points')))
            rival.set_attribute('da', str(other_play_stats.get_int('double_dj_points')))

            # If the user joined a particular shop, let the game know.
            if 'shop_location' in other_profile:
                shop_id = other_profile.get_int('shop_location')
                machine = self.get_machine_by_id(shop_id)
                if machine is not None:
                    shop = Node.void('shop')
                    rival.add_child(shop)
                    shop.set_attribute('name', machine.name)

            qprodata = Node.void('qprodata')
            rival.add_child(qprodata)
            qpro = other_profile.get_dict('qpro')
            qprodata.set_attribute('head', str(qpro.get_int('head')))
            qprodata.set_attribute('hair', str(qpro.get_int('hair')))
            qprodata.set_attribute('face', str(qpro.get_int('face')))
            qprodata.set_attribute('body', str(qpro.get_int('body')))
            qprodata.set_attribute('hand', str(qpro.get_int('hand')))

        # Step up mode
        step_dict = profile.get_dict('step')
        step = Node.void('step')
        root.add_child(step)
        step.set_attribute('damage', str(step_dict.get_int('damage')))
        step.set_attribute('defeat', str(step_dict.get_int('defeat')))
        step.set_attribute('progress', str(step_dict.get_int('progress')))
        step.set_attribute('round', str(step_dict.get_int('round')))
        step.set_attribute('sp_mission', str(step_dict.get_int('sp_mission')))
        step.set_attribute('dp_mission', str(step_dict.get_int('dp_mission')))
        step.set_attribute('sp_level', str(step_dict.get_int('sp_level')))
        step.set_attribute('dp_level', str(step_dict.get_int('dp_level')))
        step.set_attribute('sp_mplay', str(step_dict.get_int('sp_mplay')))
        step.set_attribute('dp_mplay', str(step_dict.get_int('dp_mplay')))
        step.set_attribute('last_select', str(step_dict.get_int('last_select')))
        step.add_child(Node.binary('album', step_dict.get_bytes('album', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')))

        # Favorites
        favorite = Node.void('favorite')
        root.add_child(favorite)
        favorite_dict = profile.get_dict('favorite')

        sp_mlist = b''
        sp_clist = b''
        singles_list = favorite_dict['single'] if 'single' in favorite_dict else []
        for single in singles_list:
            sp_mlist = sp_mlist + struct.pack('<L', single['id'])
            sp_clist = sp_clist + struct.pack('B', single['chart'])
        while len(sp_mlist) < (4 * self.FAVORITE_LIST_LENGTH):
            sp_mlist = sp_mlist + b'\x00\x00\x00\x00'
        while len(sp_clist) < self.FAVORITE_LIST_LENGTH:
            sp_clist = sp_clist + b'\x00'

        dp_mlist = b''
        dp_clist = b''
        doubles_list = favorite_dict['double'] if 'double' in favorite_dict else []
        for double in doubles_list:
            dp_mlist = dp_mlist + struct.pack('<L', double['id'])
            dp_clist = dp_clist + struct.pack('B', double['chart'])
        while len(dp_mlist) < (4 * self.FAVORITE_LIST_LENGTH):
            dp_mlist = dp_mlist + b'\x00\x00\x00\x00'
        while len(dp_clist) < self.FAVORITE_LIST_LENGTH:
            dp_clist = dp_clist + b'\x00'

        favorite.add_child(Node.binary('sp_mlist', sp_mlist))
        favorite.add_child(Node.binary('sp_clist', sp_clist))
        favorite.add_child(Node.binary('dp_mlist', dp_mlist))
        favorite.add_child(Node.binary('dp_clist', dp_clist))

        # Orb data
        orb_data = Node.void('orb_data')
        root.add_child(orb_data)
        orb_data.set_attribute('rest_orb', str(profile.get_int('orbs')))

        # Link5 data
        if 'link5' in profile:
            # Don't provide link5 if we haven't saved it, so the game can
            # initialize it properly.
            link5_dict = profile.get_dict('link5')
            link5 = Node.void('link5')
            root.add_child(link5)
            for attr in [
                'qpro',
                'glass',
                'treasure',  # Doesn't seem to be saved
                'beautiful',
                'quaver',
                'castle',
                'flip',
                'titans',
                'exusia',
                'waxing',
                'sampling',
                'beachside',
                'cuvelia',
                'reunion',
                'bad',
                'turii',
                'anisakis',
                'second',
                'whydidyou',
                'china',
                'fallen',
                'broken',
                'summer',
                'sakura',
                'wuv',
                'survival',
                'thunder',
                'qproflg',  # Doesn't seem to be saved
                'glassflg',  # Doesn't seem to be saved
                'reflec_data',  # Doesn't seem to be saved
            ]:
                link5.set_attribute(attr, str(link5_dict.get_int(attr)))

        # Boss1 data
        if 'boss1' in profile:
            # Don't provide boss1 if we haven't saved it, so the game can
            # initialize it properly.
            boss1_dict = profile.get_dict('boss1')
            boss1 = Node.void('boss1')
            root.add_child(boss1)
            for attr in [
                'stamina',
                'attack',
                'item_flg',
                'item_flg2',
                'pick',
                'row0',
                'row1',
                'row2',
                'row3',
                'column0',
                'column1',
                'column2',
                'column3',
                'map',
                'job',
                'general',
                'battle',
                'boss0_n',
                'boss0_h',
                'boss0_a',
                'boss1_n',
                'boss1_h',
                'boss1_a',
                'boss2_n',
                'boss2_h',
                'boss2_a',
                'item1',
                'item2',
                'item3',
                'boss_scene',
                'boss0_damage',
                'boss1_damage',
                'boss2_damage',
                'boss3_damage',
                'boss4_damage',
                'boss5_damage',
                'boss6_damage',
            ]:
                boss1.set_attribute(attr, str(boss1_dict.get_int(attr)))
            boss1.add_child(Node.s32_array('level', boss1_dict.get_int_array('level', 7)))
            if 'durability' in boss1_dict:
                boss1.add_child(Node.binary('durability', boss1_dict.get_bytes('durability')))

        return root

    def unformat_profile(self, userid: UserID, request: Node, oldprofile: ValidatedDict) -> ValidatedDict:
        newprofile = copy.deepcopy(oldprofile)
        play_stats = self.get_play_statistics(userid)

        # Track play counts
        cltype = int(request.attribute('cltype'))
        if cltype == self.GAME_CLTYPE_SINGLE:
            play_stats.increment_int('single_plays')
        if cltype == self.GAME_CLTYPE_DOUBLE:
            play_stats.increment_int('double_plays')

        # Track DJ points
        play_stats.replace_int('single_dj_points', int(request.attribute('s_achi')))
        play_stats.replace_int('double_dj_points', int(request.attribute('d_achi')))

        # Profile settings
        newprofile.replace_int('mode', int(request.attribute('mode')))
        newprofile.replace_int('pmode', int(request.attribute('pmode')))
        newprofile.replace_int('rtype', int(request.attribute('rtype')))
        newprofile.replace_int('s_lift', int(request.attribute('s_lift')))
        newprofile.replace_int('d_lift', int(request.attribute('d_lift')))
        newprofile.replace_int('sp_opt', int(request.attribute('sp_opt')))
        newprofile.replace_int('dp_opt', int(request.attribute('dp_opt')))
        newprofile.replace_int('dp_opt2', int(request.attribute('dp_opt2')))
        newprofile.replace_int('gpos', int(request.attribute('gpos')))
        newprofile.replace_int('s_sorttype', int(request.attribute('s_sorttype')))
        newprofile.replace_int('d_sorttype', int(request.attribute('d_sorttype')))
        newprofile.replace_int('s_pace', int(request.attribute('s_pace')))
        newprofile.replace_int('d_pace', int(request.attribute('d_pace')))
        newprofile.replace_int('s_gno', int(request.attribute('s_gno')))
        newprofile.replace_int('d_gno', int(request.attribute('d_gno')))
        newprofile.replace_int('s_gtype', int(request.attribute('s_gtype')))
        newprofile.replace_int('d_gtype', int(request.attribute('d_gtype')))
        newprofile.replace_int('s_sdlen', int(request.attribute('s_sdlen')))
        newprofile.replace_int('d_sdlen', int(request.attribute('d_sdlen')))
        newprofile.replace_int('s_sdtype', int(request.attribute('s_sdtype')))
        newprofile.replace_int('d_sdtype', int(request.attribute('d_sdtype')))
        newprofile.replace_int('s_timing', int(request.attribute('s_timing')))
        newprofile.replace_int('d_timing', int(request.attribute('d_timing')))
        newprofile.replace_float('s_notes', float(request.attribute('s_notes')))
        newprofile.replace_float('d_notes', float(request.attribute('d_notes')))
        newprofile.replace_int('s_judge', int(request.attribute('s_judge')))
        newprofile.replace_int('d_judge', int(request.attribute('d_judge')))
        newprofile.replace_float('s_hispeed', float(request.attribute('s_hispeed')))
        newprofile.replace_float('d_hispeed', float(request.attribute('d_hispeed')))
        newprofile.replace_int('s_disp_judge', int(request.attribute('s_disp_judge')))
        newprofile.replace_int('d_disp_judge', int(request.attribute('d_disp_judge')))
        newprofile.replace_int('s_opstyle', int(request.attribute('s_opstyle')))
        newprofile.replace_int('d_opstyle', int(request.attribute('d_opstyle')))

        # Update judge window adjustments per-machine
        judge_dict = newprofile.get_dict('machine_judge_adjust')
        machine_judge = judge_dict.get_dict(self.config['machine']['pcbid'])
        machine_judge.replace_int('single', int(request.attribute('s_judgeAdj')))
        machine_judge.replace_int('double', int(request.attribute('d_judgeAdj')))
        judge_dict.replace_dict(self.config['machine']['pcbid'], machine_judge)
        newprofile.replace_dict('machine_judge_adjust', judge_dict)

        # Secret flags saving
        secret = request.child('secret')
        if secret is not None:
            secret_dict = newprofile.get_dict('secret')
            secret_dict.replace_int_array('flg1', 2, secret.child_value('flg1'))
            secret_dict.replace_int_array('flg2', 2, secret.child_value('flg2'))
            secret_dict.replace_int_array('flg3', 2, secret.child_value('flg3'))
            newprofile.replace_dict('secret', secret_dict)

        # Basic achievements
        achievements = request.child('achievements')
        if achievements is not None:
            newprofile.replace_int('visit_flg', int(achievements.attribute('visit_flg')))
            newprofile.replace_int('last_weekly', int(achievements.attribute('last_weekly')))
            newprofile.replace_int('weekly_num', int(achievements.attribute('weekly_num')))

            pack_id = int(achievements.attribute('pack_id'))
            if pack_id > 0:
                self.data.local.user.put_achievement(
                    self.game,
                    self.version,
                    userid,
                    pack_id,
                    'daily',
                    {
                        'pack_flg': int(achievements.attribute('pack_flg')),
                        'pack_comp': int(achievements.attribute('pack_comp')),
                    },
                )

            trophies = achievements.child('trophy')
            if trophies is not None:
                # We only load the first 10 in profile load.
                newprofile.replace_int_array('trophy', 10, trophies.value[:10])

        # Deller saving
        deller = request.child('deller')
        if deller is not None:
            newprofile.replace_int('deller', newprofile.get_int('deller') + int(deller.attribute('deller')))

        # Favorites saving
        favorite = request.child('favorite')
        if favorite is not None:
            single_music_bin = favorite.child_value('sp_mlist')
            single_chart_bin = favorite.child_value('sp_clist')
            double_music_bin = favorite.child_value('dp_mlist')
            double_chart_bin = favorite.child_value('dp_clist')

            singles = []
            doubles = []
            for i in range(self.FAVORITE_LIST_LENGTH):
                singles.append({
                    'id': struct.unpack('<L', single_music_bin[(i * 4):((i + 1) * 4)])[0],
                    'chart': struct.unpack('B', single_chart_bin[i:(i + 1)])[0],
                })
                doubles.append({
                    'id': struct.unpack('<L', double_music_bin[(i * 4):((i + 1) * 4)])[0],
                    'chart': struct.unpack('B', double_chart_bin[i:(i + 1)])[0],
                })

            # Filter out empty charts
            singles = [single for single in singles if single['id'] != 0]
            doubles = [double for double in doubles if double['id'] != 0]

            newprofile.replace_dict(
                'favorite',
                {
                    'single': singles,
                    'double': doubles,
                },
            )

        # Step-up mode
        step = request.child('step')
        if step is not None:
            step_dict = newprofile.get_dict('step')
            step_dict.replace_int('damage', int(step.attribute('damage')))
            step_dict.replace_int('defeat', int(step.attribute('defeat')))
            step_dict.replace_int('progress', int(step.attribute('progress')))
            step_dict.replace_int('round', int(step.attribute('round')))
            step_dict.replace_int('sp_mission', int(step.attribute('sp_mission')))
            step_dict.replace_int('dp_mission', int(step.attribute('dp_mission')))
            step_dict.replace_int('sp_level', int(step.attribute('sp_level')))
            step_dict.replace_int('dp_level', int(step.attribute('dp_level')))
            step_dict.replace_int('sp_mplay', int(step.attribute('sp_mplay')))
            step_dict.replace_int('dp_mplay', int(step.attribute('dp_mplay')))
            step_dict.replace_int('last_select', int(step.attribute('last_select')))
            step_dict.replace_bytes('album', step.value)
            newprofile.replace_dict('step', step_dict)

        # Orb data saving
        orb_data = request.child('orb_data')
        if orb_data is not None:
            orbs = newprofile.get_int('orbs')
            orbs = orbs + int(orb_data.attribute('add_orb'))
            if orb_data.child_value('use_vip_pass'):
                orbs = 0
            newprofile.replace_int('orbs', orbs)

        # Link5 data
        link5 = request.child('link5')
        if link5 is not None:
            link5_dict = newprofile.get_dict('link5')
            for attr in [
                'qpro',
                'glass',
                'beautiful',
                'quaver',
                'castle',
                'flip',
                'titans',
                'exusia',
                'waxing',
                'sampling',
                'beachside',
                'cuvelia',
                'reunion',
                'bad',
                'turii',
                'anisakis',
                'second',
                'whydidyou',
                'china',
                'fallen',
                'broken',
                'summer',
                'sakura',
                'wuv',
                'survival',
                'thunder',
            ]:
                link5_dict.replace_int(attr, int(link5.attribute(attr)))
            newprofile.replace_dict('link5', link5_dict)

        # Boss1 data
        boss1 = request.child('boss1')
        if boss1 is not None:
            boss1_dict = newprofile.get_dict('boss1')
            for attr in [
                'stamina',
                'attack',
                'item_flg',
                'item_flg2',
                'pick',
                'row0',
                'row1',
                'row2',
                'row3',
                'column0',
                'column1',
                'column2',
                'column3',
                'map',
                'job',
                'general',
                'battle',
                'boss0_n',
                'boss0_h',
                'boss0_a',
                'boss1_n',
                'boss1_h',
                'boss1_a',
                'boss2_n',
                'boss2_h',
                'boss2_a',
                'boss_scene',
                'boss0_damage',
                'boss1_damage',
                'boss2_damage',
                'boss3_damage',
                'boss4_damage',
                'boss5_damage',
                'boss6_damage',
            ]:
                boss1_dict.replace_int(attr, int(boss1.attribute(attr)))
            level = boss1.child_value('level')
            if level is not None:
                boss1_dict.replace_int_array('level', 7, level[:7])
            durability = boss1.child_value('durability')
            if durability is not None:
                boss1_dict.replace_bytes('durability', durability)
            newprofile.replace_dict('boss1', boss1_dict)

        # Keep track of play statistics across all mixes
        self.update_play_statistics(userid, play_stats)

        return newprofile
