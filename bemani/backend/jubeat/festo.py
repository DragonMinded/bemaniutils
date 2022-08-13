# vim: set fileencoding=utf-8
from typing import Dict, List, Optional

from bemani.backend.jubeat.base import JubeatBase
from bemani.backend.jubeat.common import (
    JubeatDemodataGetNewsHandler,
    JubeatLoggerReportHandler,
)
from bemani.backend.jubeat.clan import JubeatClan

from bemani.common import VersionConstants
from bemani.protocol import Node


class JubeatFesto(
    JubeatDemodataGetNewsHandler,
    JubeatLoggerReportHandler,
    JubeatBase
):

    name: str = 'Jubeat Festo'
    version: int = VersionConstants.JUBEAT_FESTO

    EVENTS: Dict[int, Dict[str, bool]] = {
        5: {
            'enabled': False,
        },
        6: {
            'enabled': False,
        },
        # Something to do with maintenance mode?
        15: {
            'enabled': True,
        },
        22: {
            'enabled': False,
        },
        23: {
            'enabled': False,
        },
        33: {
            'enabled': False,
        },
        101: {
            'enabled': False,
        },
        102: {
            'enabled': False,
        },
        103: {
            'enabled': False,
        },
        104: {
            'enabled': False,
        },
        105: {
            'enabled': False,
        },
        106: {
            'enabled': False,
        },
        107: {
            'enabled': False,
        },
        108: {
            'enabled': False,
        },
        109: {
            'enabled': False,
        },
    }

    # Return the netlog service so that Festo doesn't crash on coin-in.
    extra_services: List[str] = [
        'netlog',
    ]

    def previous_version(self) -> Optional[JubeatBase]:
        return JubeatClan(self.data, self.config, self.model)

    def __get_global_info(self) -> Node:
        info = Node.void('info')

        # Event info.
        event_info = Node.void('event_info')
        info.add_child(event_info)
        for event in self.EVENTS:
            evt = Node.void('event')
            event_info.add_child(evt)
            evt.set_attribute('type', str(event))
            evt.add_child(Node.u8('state', 1 if self.EVENTS[event]['enabled'] else 0))

        # Each of the following two sections should have zero or more child nodes (no
        # particular name) which look like the following:
        #     <node>
        #         <id __type="s32">songid</id>
        #         <stime __type="str">start time?</stime>
        #         <etime __type="str">end time?</etime>
        #     </node>
        # Share music?
        share_music = Node.void('share_music')
        info.add_child(share_music)

        genre_def_music = Node.void('genre_def_music')
        info.add_child(genre_def_music)

        weekly_music = Node.void('weekly_music')
        info.add_child(weekly_music)
        weekly_music.add_child(Node.s32("value", 0))

        # The following section should have zero or more child nodes (no particular
        # name) which look like the following, with a song ID in the node's id attribute:
        #     <node id="" />
        weekly_music_list = Node.void('music_list')
        weekly_music.add_child(weekly_music_list)

        info.add_child(Node.s32_array(
            'black_jacket_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        # Mapping of what music is allowed by default, if this is set to all 0's
        # then the game will crash because it can't figure out what default song
        # to choose for new player sort.
        info.add_child(Node.s32_array(
            'white_music_list',
            [
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
                -1, -1, -1, -1,
            ],
        ))

        info.add_child(Node.s32_array(
            'add_default_music_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        info.add_child(Node.s32_array(
            'open_music_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        info.add_child(Node.s32_array(
            'shareable_music_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        info.add_child(Node.s32_array(
            'hot_music_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        info.add_child(Node.s32_array(
            'white_marker_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        info.add_child(Node.s32_array(
            'white_theme_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        jbox = Node.void('jbox')
        info.add_child(jbox)
        jbox.add_child(Node.s32('point', 0))
        emblem = Node.void('emblem')
        jbox.add_child(emblem)
        normal = Node.void('normal')
        emblem.add_child(normal)
        premium = Node.void('premium')
        emblem.add_child(premium)
        normal.add_child(Node.s16('index', 2))
        premium.add_child(Node.s16('index', 1))

        born = Node.void('born')
        info.add_child(born)
        born.add_child(Node.s8('status', 0))
        born.add_child(Node.s16('year', 0))

        expert_option = Node.void('expert_option')
        info.add_child(expert_option)
        expert_option.add_child(Node.bool('is_available', True))

        # TODO: Make this configurable.
        konami_logo_50th = Node.void('konami_logo_50th')
        info.add_child(konami_logo_50th)
        konami_logo_50th.add_child(Node.bool('is_available', True))

        # TODO: Make this configurable.
        all_music_matching = Node.void('all_music_matching')
        info.add_child(all_music_matching)
        all_music_matching.add_child(Node.bool('is_available', True))

        question_list = Node.void('question_list')
        info.add_child(question_list)

        department = Node.void('department')
        info.add_child(department)
        department.add_child(Node.void('shop_list'))

        # TODO: team_batle

        # TODO: qr

        # TODO: course_list

        # TODO: emo_list

        # TODO: hike_event

        # TODO: tip_list

        # TODO: festo_dungeon

        # TODO: travel

        # TODO: stamp

        return info

    def handle_demodata_get_info_request(self, request: Node) -> Node:
        root = Node.void('demodata')
        data = Node.void('data')
        root.add_child(data)

        info = Node.void('info')
        data.add_child(info)

        # This is the same stuff set in the common info, so if we ever do make this
        # configurable, I think we'll need to return the same thing in both spots.
        info.add_child(Node.s32_array(
            'black_jacket_list',
            [
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ))

        return root

    def handle_demodata_get_jbox_list_request(self, request: Node) -> Node:
        root = Node.void('demodata')
        return root

    def handle_ins_netlog_request(self, request: Node) -> Node:
        root = Node.void('ins')
        return root

    def handle_shopinfo_regist_request(self, request: Node) -> Node:
        # Update the name of this cab for admin purposes
        self.update_machine_name(request.child_value('shop/name'))

        shopinfo = Node.void('shopinfo')

        data = Node.void('data')
        shopinfo.add_child(data)
        data.add_child(Node.u32('cabid', 1))
        data.add_child(Node.string('locationid', 'nowhere'))
        data.add_child(Node.u8('tax_phase', 1))

        facility = Node.void('facility')
        data.add_child(facility)
        facility.add_child(Node.u32('exist', 1))

        data.add_child(self.__get_global_info())

        return shopinfo
