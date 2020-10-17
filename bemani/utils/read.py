# vim: set fileencoding=utf-8

import csv  # type: ignore
import argparse
import copy
import io
import jaconv  # type: ignore
import json
import os
import pefile  # type: ignore
import struct
import yaml  # type: ignore
import xml.etree.ElementTree as ET
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy.engine.result import ResultProxy  # type: ignore
from sqlalchemy.orm import sessionmaker  # type: ignore
from sqlalchemy.sql import text  # type: ignore
from sqlalchemy.exc import IntegrityError  # type: ignore
from typing import Any, Dict, List, Optional, Tuple

from bemani.common import GameConstants, VersionConstants, DBConstants, Time
from bemani.format import ARC, IFS, IIDXChart, IIDXMusicDB
from bemani.data import Server, Song
from bemani.data.interfaces import APIProviderInterface
from bemani.data.api.music import GlobalMusicData
from bemani.data.api.game import GlobalGameData
from bemani.data.mysql.music import MusicData
from bemani.data.mysql.user import UserData


class ReadAPI(APIProviderInterface):
    def __init__(self, server: str, token: str) -> None:
        self.__server = server
        self.__token = token

    def get_all_servers(self) -> List[Server]:
        return [
            Server(
                0,
                Time.now(),
                self.__server,
                self.__token,
                False,
                False,
            )
        ]


class ImportBase:

    def __init__(
        self,
        config: Dict[str, Any],
        game: str,
        version: Optional[int],
        no_combine: bool,
        update: bool,
    ) -> None:
        self.game = game
        self.version = version
        self.update = update
        self.no_combine = no_combine
        self.__config = config
        self.__url = f"mysql://{config['database']['user']}:{config['database']['password']}@{config['database']['address']}/{config['database']['database']}?charset=utf8mb4"
        self.__engine = create_engine(self.__url)  # type: ignore
        self.__sessionmanager = sessionmaker(self.__engine)
        self.__conn = self.__engine.connect()
        self.__session = self.__sessionmanager(bind=self.__conn)
        self.__batch = False

    def start_batch(self) -> None:
        self.__batch = True

    def finish_batch(self) -> None:
        self.__session.commit()
        self.__batch = False

    def execute(self, sql: str, params: Optional[Dict[str, Any]]=None) -> ResultProxy:
        if not self.__batch:
            raise Exception('Logic error, cannot execute outside of a batch!')

        if self.__config['database'].get('read_only', False):
            # See if this is an insert/update/delete
            for write_statement in [
                "insert into ",
                "update ",
                "delete from ",
            ]:
                if write_statement in sql.lower():
                    raise Exception('Read-only mode is active!')
        return self.__session.execute(text(sql), params if params is not None else {})

    def remote_music(self, server: str, token: str) -> GlobalMusicData:
        api = ReadAPI(server, token)
        user = UserData(self.__config, self.__session)
        music = MusicData(self.__config, self.__session)
        return GlobalMusicData(api, user, music)

    def remote_game(self, server: str, token: str) -> GlobalGameData:
        api = ReadAPI(server, token)
        return GlobalGameData(api)

    def get_next_music_id(self) -> int:
        cursor = self.execute("SELECT MAX(id) AS next_id FROM `music`")
        result = cursor.fetchone()
        try:
            return result['next_id'] + 1
        except TypeError:
            # Nothing in DB
            return 1

    def get_music_id_for_song(self, songid: int, chart: int, version: Optional[int]=None) -> Optional[int]:
        if version is None:
            # Normal lookup
            if self.version is None:
                raise Exception('Cannot get music ID for song when operating on all versions!')
            version = self.version
            sql = (
                "SELECT id FROM `music` WHERE songid = :songid AND chart = :chart AND game = :game AND version != :version"
            )
        else:
            # Specific version lookup
            sql = (
                "SELECT id FROM `music` WHERE songid = :songid AND chart = :chart AND game = :game AND version = :version"
            )

        cursor = self.execute(sql, {'songid': songid, 'chart': chart, 'game': self.game, 'version': version})
        if cursor.rowcount != 0:
            result = cursor.fetchone()
            return result['id']
        else:
            return None

    def get_music_id_for_song_data(
        self,
        title: Optional[str],
        artist: Optional[str],
        genre: Optional[str],
        chart: int,
        version: Optional[int]=None,
    ) -> Optional[int]:
        frags = []
        if title is not None:
            frags.append("name = :title")
        if artist is not None:
            frags.append("artist = :artist")
        if genre is not None:
            frags.append("genre = :genre")
        frags.append("chart = :chart")
        frags.append("game = :game")

        if version is None:
            # Normal lookup
            if self.version is None:
                raise Exception('Cannot get music ID for song when operating on all versions!')
            version = self.version
            frags.append("version != :version")
        else:
            frags.append("version = :version")

        sql = "SELECT id FROM `music` WHERE " + " AND ".join(frags)
        cursor = self.execute(sql, {'title': title, 'artist': artist, 'genre': genre, 'chart': chart, 'game': self.game, 'version': version})
        if cursor.rowcount != 0:
            result = cursor.fetchone()
            return result['id']
        else:
            return None

    def insert_music_id_for_song(
        self,
        musicid: int,
        songid: int,
        chart: int,
        name: Optional[str]=None,
        artist: Optional[str]=None,
        genre: Optional[str]=None,
        data: Optional[Dict[str, Any]]=None,
        version: Optional[int]=None,
    ) -> None:
        version = version if version is not None else self.version
        if version is None:
            raise Exception('Cannot get insert new song when operating on all versions!')
        if data is None:
            jsondata = '{}'
        else:
            jsondata = json.dumps(data)
        try:
            sql = (
                "INSERT INTO `music` (id, songid, chart, game, version, name, artist, genre, data) " +
                "VALUES (:id, :songid, :chart, :game, :version, :name, :artist, :genre, :data)"
            )
            self.execute(
                sql,
                {
                    'id': musicid,
                    'songid': songid,
                    'chart': chart,
                    'game': self.game,
                    'version': version,
                    'name': name,
                    'artist': artist,
                    'genre': genre,
                    'data': jsondata
                },
            )
        except IntegrityError:
            if self.update:
                print("Entry already existed, so updating information!")
                self.update_metadata_for_song(songid, chart, name, artist, genre, data, version)
            else:
                print("Entry already existed, so skip creating a second one!")

    def update_metadata_for_song(
        self,
        songid: int,
        chart: int,
        name: Optional[str]=None,
        artist: Optional[str]=None,
        genre: Optional[str]=None,
        data: Optional[Dict[str, Any]]=None,
        version: Optional[int]=None,
    ) -> None:
        if data is None:
            jsondata = None
        else:
            jsondata = json.dumps(data)
        version = version if version is not None else self.version

        updates = []
        if jsondata is not None:
            updates.append("data = :data")
        if name is not None:
            updates.append("name = :name")
        if artist is not None:
            updates.append("artist = :artist")
        if genre is not None:
            updates.append("genre = :genre")
        if len(updates) == 0:
            return
        sql = f"UPDATE `music` SET {', '.join(updates)} WHERE songid = :songid AND chart = :chart AND game = :game"
        if version is not None:
            sql = sql + " AND version = :version"
        self.execute(
            sql,
            {
                'songid': songid,
                'chart': chart,
                'game': self.game,
                'version': version,
                'name': name,
                'artist': artist,
                'genre': genre,
                'data': jsondata
            },
        )

    def update_metadata_for_music_id(
        self,
        musicid: int,
        name: Optional[str]=None,
        artist: Optional[str]=None,
        genre: Optional[str]=None,
        data: Optional[Dict[str, Any]]=None,
        version: Optional[int]=None,
    ) -> None:
        if data is None:
            jsondata = None
        else:
            jsondata = json.dumps(data)
        version = version if version is not None else self.version

        updates = []
        if jsondata is not None:
            updates.append("data = :data")
        if name is not None:
            updates.append("name = :name")
        if artist is not None:
            updates.append("artist = :artist")
        if genre is not None:
            updates.append("genre = :genre")
        if len(updates) == 0:
            return
        sql = f"UPDATE `music` SET {', '.join(updates)} WHERE id = :musicid AND game = :game"
        if version is not None:
            sql = sql + " AND version = :version"
        self.execute(
            sql,
            {
                'musicid': musicid,
                'game': self.game,
                'version': version,
                'name': name,
                'artist': artist,
                'genre': genre,
                'data': jsondata
            },
        )

    def insert_catalog_entry(
        self,
        cattype: str,
        catid: int,
        data: Optional[Dict[str, Any]]=None,
    ) -> None:
        if data is None:
            jsondata = '{}'
        else:
            jsondata = json.dumps(data)
        try:
            sql = (
                "INSERT INTO `catalog` (game, version, type, id, data) " +
                "VALUES (:game, :version, :type, :id, :data)"
            )
            self.execute(
                sql,
                {
                    'id': catid,
                    'type': cattype,
                    'game': self.game,
                    'version': self.version,
                    'data': jsondata
                },
            )
        except IntegrityError:
            if self.update:
                print("Entry already existed, so updating information!")
                sql = (
                    "UPDATE `catalog` SET data = :data WHERE " +
                    "game = :game AND version = :version AND type = :type AND id = :id"
                )
                self.execute(
                    sql,
                    {
                        'id': catid,
                        'type': cattype,
                        'game': self.game,
                        'version': self.version,
                        'data': jsondata
                    },
                )
            else:
                print("Entry already existed, so skip creating a second one!")

    def close(self) -> None:
        """
        Close any open data connection.
        """
        # Make sure we don't leak connections after finising insertion.
        if self.__batch:
            raise Exception('Logic error, opened a batch without closing!')
        if self.__session is not None:
            self.__session.close()
        if self.__conn is not None:
            self.__conn.close()
            self.__conn = None
        if self.__engine is not None:
            self.__engine.dispose()
            self.__engine = None


class ImportPopn(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        actual_version = {
            '19': VersionConstants.POPN_MUSIC_TUNE_STREET,
            '20': VersionConstants.POPN_MUSIC_FANTASIA,
            '21': VersionConstants.POPN_MUSIC_SUNNY_PARK,
            '22': VersionConstants.POPN_MUSIC_LAPISTORIA,
            '23': VersionConstants.POPN_MUSIC_ECLALE,
            '24': VersionConstants.POPN_MUSIC_USANEKO,
        }.get(version, -1)

        if actual_version == VersionConstants.POPN_MUSIC_TUNE_STREET:
            # Pop'n 19 has extra charts for old play modes (challenge and enjoy mode).
            # Cho challenge is analogous to regular mode in newer games, but Pop'n
            # 19 doesn't have easy charts, just 5 button charts.
            self.charts = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        elif actual_version >= VersionConstants.POPN_MUSIC_FANTASIA:
            # Newer pop'n has charts for easy, normal, hyper, another
            self.charts = [0, 1, 2, 3]
        else:
            raise Exception("Unsupported Pop'n Music version, expected one of the following: 19, 20, 21, 22, 23, 24!")

        super().__init__(config, GameConstants.POPN_MUSIC, actual_version, no_combine, update)

    def scrape(self, infile: str) -> List[Dict[str, Any]]:
        with open(infile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

        pe = pefile.PE(data=data, fast_load=True)

        def virtual_to_physical(offset: int) -> int:
            for section in pe.sections:
                start = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                end = start + section.SizeOfRawData

                if offset >= start and offset < end:
                    return (offset - start) + section.PointerToRawData
            raise Exception(f'Couldn\'t find raw offset for virtual offset 0x{offset:08x}')

        if self.version == VersionConstants.POPN_MUSIC_TUNE_STREET:
            # Based on K39:J:A:A:2010122200

            # Normal offset for music DB, size
            offset = 0x1F68E8
            step = 72
            length = 1048

            # Offset and step of file DB
            file_offset = 0x2D6888
            file_step = 24

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = -1
            english_artist_offset = -1
            extended_genre_offset = -1
            charts_offset = 6
            folder_offset = 7

            # Offsets for normal chart difficulties
            easy_offset = 12
            normal_offset = 10
            hyper_offset = 11
            ex_offset = 13

            # Offsets for battle chart difficulties
            battle_normal_offset = 14
            battle_hyper_offset = 15

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 18
            normal_file_offset = 16
            hyper_file_offset = 17
            ex_file_offset = 19
            battle_normal_file_offset = 20
            battle_hyper_file_offset = 21

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event flags?
                'B'  # Event flags?
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # Easy difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'x'  # ??
                'x'  # ??
                'x'  # ??
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # Easy chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    True,  # Always an easy chart
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        elif self.version == VersionConstants.POPN_MUSIC_FANTASIA:
            # Based on L39:J:A:A:2012091900

            # Normal offset for music DB, size
            offset = 0x1AE240
            step = 160
            length = 1122

            # Offset and step of file DB
            file_offset = 0x273768
            file_step = 24

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = -1
            english_artist_offset = -1
            extended_genre_offset = -1
            charts_offset = 6
            folder_offset = 7

            # Offsets for normal chart difficulties
            easy_offset = 12
            normal_offset = 10
            hyper_offset = 11
            ex_offset = 13

            # Offsets for battle chart difficulties
            battle_normal_offset = 14
            battle_hyper_offset = 15

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 18
            normal_file_offset = 16
            hyper_file_offset = 17
            ex_file_offset = 19
            battle_normal_file_offset = 20
            battle_hyper_file_offset = 21

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event flags?
                'B'  # Event flags?
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # Easy difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'x'  # ??
                'x'  # ??
                'x'  # ??
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # Easy chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    True,  # Always an easy chart
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        elif self.version == VersionConstants.POPN_MUSIC_SUNNY_PARK:
            # Based on M39:J:A:A:2014061900

            # Normal offset for music DB, size
            offset = 0x1FB640
            step = 164
            length = 1280

            # Offset and step of file DB
            file_offset = 0x2E0D20
            file_step = 28

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = 4
            english_artist_offset = 5
            extended_genre_offset = 6
            charts_offset = 9
            folder_offset = 10

            # Offsets for normal chart difficulties
            easy_offset = 13
            normal_offset = 14
            hyper_offset = 15
            ex_offset = 16

            # Offsets for battle chart difficulties
            battle_normal_offset = 17
            battle_hyper_offset = 18

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 19
            normal_file_offset = 20
            hyper_file_offset = 21
            ex_file_offset = 22
            battle_normal_file_offset = 21
            battle_hyper_file_offset = 22

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'I'  # English Title
                'I'  # English Artist
                'I'  # Extended genre?
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event unlocks?
                'H'  # Event unlocks?
                'B'  # Easy difficulty
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'H'  # Easy chart pointer
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    mask & 0x0080000 > 0,  # Easy chart bit
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        elif self.version == VersionConstants.POPN_MUSIC_LAPISTORIA:
            # Based on M39:J:A:A:2015081900

            # Normal offset for music DB, size
            offset = 0x3124B0
            step = 160
            length = 1423

            # Offset and step of file DB
            file_offset = 0x472130
            file_step = 28

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = 4
            english_artist_offset = 5
            extended_genre_offset = -1
            charts_offset = 8
            folder_offset = 9

            # Offsets for normal chart difficulties
            easy_offset = 12
            normal_offset = 13
            hyper_offset = 14
            ex_offset = 15

            # Offsets for battle chart difficulties
            battle_normal_offset = 16
            battle_hyper_offset = 17

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 18
            normal_file_offset = 19
            hyper_file_offset = 20
            ex_file_offset = 21
            battle_normal_file_offset = 22
            battle_hyper_file_offset = 23

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'I'  # English Title
                'I'  # English Artist
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event unlocks?
                'H'  # Event unlocks?
                'B'  # Easy difficulty
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'H'  # Easy chart pointer
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    mask & 0x0080000 > 0,  # Easy chart bit
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        elif self.version == VersionConstants.POPN_MUSIC_ECLALE:
            # Based on M39:J:A:A:2016100500

            # Normal offset for music DB, size
            offset = 0x2DE5C8
            step = 160
            length = 1551

            # Offset and step of file DB
            file_offset = 0x2D1948
            file_step = 32

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = 4
            english_artist_offset = 5
            extended_genre_offset = -1
            charts_offset = 8
            folder_offset = 9

            # Offsets for normal chart difficulties
            easy_offset = 12
            normal_offset = 13
            hyper_offset = 14
            ex_offset = 15

            # Offsets for battle chart difficulties
            battle_normal_offset = 16
            battle_hyper_offset = 17

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 18
            normal_file_offset = 19
            hyper_file_offset = 20
            ex_file_offset = 21
            battle_normal_file_offset = 22
            battle_hyper_file_offset = 23

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'I'  # English Title
                'I'  # English Artist
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event unlocks?
                'H'  # Event unlocks?
                'B'  # Easy difficulty
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'H'  # Easy chart pointer
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    mask & 0x0080000 > 0,  # Easy chart bit
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        elif self.version == VersionConstants.POPN_MUSIC_USANEKO:
            # Based on M39:J:A:A:2018101500

            # Normal offset for music DB, size
            offset = 0x299210
            step = 172
            length = 1704

            # Offset and step of file DB
            file_offset = 0x28AF08
            file_step = 32

            # Standard lookups
            genre_offset = 0
            title_offset = 1
            artist_offset = 2
            comment_offset = 3
            english_title_offset = 4
            english_artist_offset = 5
            extended_genre_offset = -1
            charts_offset = 8
            folder_offset = 9

            # Offsets for normal chart difficulties
            easy_offset = 12
            normal_offset = 13
            hyper_offset = 14
            ex_offset = 15

            # Offsets for battle chart difficulties
            battle_normal_offset = 16
            battle_hyper_offset = 17

            # Offsets into which offset to seek to for file lookups
            easy_file_offset = 18
            normal_file_offset = 19
            hyper_file_offset = 20
            ex_file_offset = 21
            battle_normal_file_offset = 22
            battle_hyper_file_offset = 23

            packedfmt = (
                '<'
                'I'  # Genre
                'I'  # Title
                'I'  # Artist
                'I'  # Comment
                'I'  # English Title
                'I'  # English Artist
                'H'  # ??
                'H'  # ??
                'I'  # Available charts mask
                'I'  # Folder
                'I'  # Event unlocks?
                'I'  # Event unlocks?
                'B'  # Easy difficulty
                'B'  # Normal difficulty
                'B'  # Hyper difficulty
                'B'  # EX difficulty
                'B'  # Battle normal difficulty
                'B'  # Battle hyper difficulty
                'xx'  # Unknown pointer
                'H'  # Easy chart pointer
                'H'  # Normal chart pointer
                'H'  # Hyper chart pointer
                'H'  # EX chart pointer
                'H'  # Battle normal pointer
                'H'  # Battle hyper pointer
                'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            )

            # Offsets into file DB for finding file and folder.
            file_folder_offset = 0
            file_name_offset = 1

            filefmt = (
                '<'
                'I'  # Folder
                'I'  # Filename
                'I'
                'I'
                'I'
                'I'
                'I'
                'I'
            )

            # Decoding function for chart masks
            def available_charts(mask: int) -> Tuple[bool, bool, bool, bool, bool, bool]:
                return (
                    mask & 0x0080000 > 0,  # Easy chart bit
                    True,  # Always a normal chart
                    mask & 0x1000000 > 0,  # Hyper chart bit
                    mask & 0x2000000 > 0,  # Ex chart bit
                    True,  # Always a battle normal chart
                    mask & 0x4000000 > 0,  # Battle hyper chart bit
                )
        else:
            raise Exception(f'Unsupported version {self.version}')

        def read_string(offset: int) -> str:
            # First, translate load offset in memory to disk offset
            offset = virtual_to_physical(offset)

            # Now, grab bytes until we're null-terminated
            bytestring = []
            while data[offset] != 0:
                bytestring.append(data[offset])
                offset = offset + 1

            # Its shift-jis encoded, so decode it now
            return bytes(bytestring).decode('shift_jisx0213')

        def file_chunk(offset: int) -> Tuple[Any, ...]:
            fileoffset = file_offset + (file_step * offset)
            filedata = data[fileoffset:(fileoffset + file_step)]
            return struct.unpack(filefmt, filedata)

        def file_handle(offset: int) -> str:
            chunk = file_chunk(offset)
            return read_string(chunk[file_folder_offset]) + '/' + read_string(chunk[file_name_offset])

        songs = []
        for songid in range(length):
            chunkoffset = offset + (step * songid)
            chunkdata = data[chunkoffset:(chunkoffset + step)]
            unpacked = struct.unpack(packedfmt, chunkdata)
            valid_charts = available_charts(unpacked[charts_offset])
            songinfo = {
                'id': songid,
                'title': read_string(unpacked[title_offset]),
                'artist': read_string(unpacked[artist_offset]),
                'genre': read_string(unpacked[genre_offset]),
                'comment': read_string(unpacked[comment_offset]),
                'title_en': read_string(unpacked[english_title_offset]) if english_title_offset > 0 else '',
                'artist_en': read_string(unpacked[english_artist_offset]) if english_artist_offset > 0 else '',
                'long_genre': read_string(unpacked[extended_genre_offset]) if extended_genre_offset > 0 else '',
                'folder': unpacked[folder_offset],
                'difficulty': {
                    'standard': {
                        'easy': unpacked[easy_offset] if valid_charts[0] else 0,
                        'normal': unpacked[normal_offset] if valid_charts[1] else 0,
                        'hyper': unpacked[hyper_offset] if valid_charts[2] else 0,
                        'ex': unpacked[ex_offset] if valid_charts[3] else 0,
                    },
                    'battle': {
                        'normal': unpacked[battle_normal_offset] if valid_charts[4] else 0,
                        'hyper': unpacked[battle_hyper_offset] if valid_charts[5] else 0,
                    }
                },
                'file': {
                    'standard': {
                        'easy': file_handle(unpacked[easy_file_offset]) if valid_charts[0] else '',
                        'normal': file_handle(unpacked[normal_file_offset]) if valid_charts[1] else '',
                        'hyper': file_handle(unpacked[hyper_file_offset]) if valid_charts[2] else '',
                        'ex': file_handle(unpacked[ex_file_offset]) if valid_charts[3] else '',
                    },
                    'battle': {
                        'normal': file_handle(unpacked[battle_normal_file_offset]) if valid_charts[4] else '',
                        'hyper': file_handle(unpacked[battle_hyper_file_offset]) if valid_charts[5] else '',
                    },
                },
            }

            if (
                songinfo['title'] in ['-', '‐'] and
                songinfo['genre'] in ['-', '‐'] and
                songinfo['artist'] in ['-', '‐'] and
                songinfo['comment'] in ['-', '‐']
            ):
                # This is a removed song
                continue

            if (
                songinfo['title'] == 'ＤＵＭＭＹ' and
                songinfo['artist'] == 'ＤＵＭＭＹ' and
                songinfo['genre'] == 'ＤＵＭＭＹ'
            ):
                # This is a song the intern left in
                continue

            # Fix accent issues with title/artist
            accent_lut: Dict[str, str] = {
                "鵝": "7",
                "圄": "à",
                "圉": "ä",
                "鵤": "Ä",
                "鵑": "👁",
                "鶤": "©",
                "圈": "é",
                "鵐": "ê",
                "鵙": "Ə",
                "鵲": "ë",
                "！": "!",
                "囿": "♥",
                "鶚": "㊙",
                "鶉": "ó",
                "鶇": "ö",
                "鶲": "Ⓟ",
                "鶫": "²",
                "圍": "@",
                "圖": "ţ",
                "鵺": "Ü",
                "囎": ":",
                "囂": "♡",
                "釁": "🐾",
            }

            for orig, rep in accent_lut.items():
                songinfo['title'] = songinfo['title'].replace(orig, rep)
                songinfo['artist'] = songinfo['artist'].replace(orig, rep)
                songinfo['title_en'] = songinfo['title_en'].replace(orig, rep)
                songinfo['artist_en'] = songinfo['artist_en'].replace(orig, rep)
                songinfo['genre'] = songinfo['genre'].replace(orig, rep)
            songs.append(songinfo)

        return songs

    def lookup(self, server: str, token: str) -> List[Dict[str, Any]]:
        # Grab music info from remote server
        music = self.remote_music(server, token)
        songs = music.get_all_songs(self.game, self.version)
        lut: Dict[int, Dict[str, Any]] = {}
        chart_map = {
            0: 'easy',
            1: 'normal',
            2: 'hyper',
            3: 'ex',
        }

        # Format it the way we expect
        for song in songs:
            if song.chart not in chart_map:
                # Ignore charts on songs we don't support/care about.
                continue

            if song.id not in lut:
                lut[song.id] = {
                    'id': song.id,
                    'title': song.name,
                    'artist': song.artist,
                    'genre': song.genre,
                    'comment': "",
                    'title_en': "",
                    'artist_en': "",
                    'long_genre': "",
                    'folder': song.data.get_str('category'),
                    'difficulty': {
                        'standard': {
                            'easy': 0,
                            'normal': 0,
                            'hyper': 0,
                            'ex': 0,
                        },
                        'battle': {
                            'normal': 0,
                            'hyper': 0,
                        }
                    },
                    'file': {
                        'standard': {
                            'easy': "",
                            'normal': "",
                            'hyper': "",
                            'ex': "",
                        },
                        'battle': {
                            'normal': "",
                            'hyper': "",
                        },
                    },
                }
            lut[song.id]['difficulty']['standard'][chart_map[song.chart]] = song.data.get_int('difficulty')

        # Return the reassembled data
        return [val for _, val in lut.items()]

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        chart_map = {
            0: 'easy',
            1: 'normal',
            2: 'hyper',
            3: 'ex',
        }

        for song in songs:
            self.start_batch()
            for chart in self.charts:
                # First, try to find in the DB from another version
                old_id = self.get_music_id_for_song(song['id'], chart)

                # Now, look up metadata
                title = song['title_en'] if len(song['title_en']) > 0 else song['title']
                artist = song['artist_en'] if len(song['artist_en']) > 0 else song['artist']
                genre = song['genre']

                # We only care about easy/normal/hyper/ex, so only provide mappings there
                if chart in chart_map:
                    difficulty = song['difficulty']['standard'][chart_map[chart]]
                else:
                    difficulty = 0

                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {artist} {title} ({song['id']} chart {chart})")
                    next_id = self.get_next_music_id()
                else:
                    print(f"Reused entry for {artist} {title} ({song['id']} chart {chart})")
                    next_id = old_id
                self.insert_music_id_for_song(
                    next_id,
                    song['id'],
                    chart,
                    title,
                    artist,
                    genre,
                    {
                        'category': str(song['folder']),
                        'difficulty': difficulty,
                    },
                )
            self.finish_batch()


class ImportJubeat(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        actual_version = {
            'saucer': VersionConstants.JUBEAT_SAUCER,
            'saucer-fulfill': VersionConstants.JUBEAT_SAUCER_FULFILL,
            'prop': VersionConstants.JUBEAT_PROP,
            'qubell': VersionConstants.JUBEAT_QUBELL,
            'clan': VersionConstants.JUBEAT_CLAN,
            'all': None,  # Special case for importing metadata
        }.get(version, -1)

        if actual_version in [
            None,
            VersionConstants.JUBEAT_SAUCER,
            VersionConstants.JUBEAT_SAUCER_FULFILL,
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
        ]:
            self.charts = [0, 1, 2]
        else:
            raise Exception("Unsupported Jubeat version, expected one of the following: saucer, saucer-fulfill, prop, qubell, clan!")

        super().__init__(config, GameConstants.JUBEAT, actual_version, no_combine, update)

    def scrape(self, xmlfile: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        if self.version is None:
            raise Exception('Can\'t scrape Jubeat database for \'all\' version!')

        try:
            # Probably UTF-8 music DB
            tree = ET.parse(xmlfile)
            root = tree.getroot()
        except ValueError:
            # Probably shift-jis emblems
            with open(xmlfile, 'rb') as xmlhandle:
                xmldata = xmlhandle.read().decode('shift_jisx0213')
            root = ET.fromstring(xmldata)

        songs: List[Dict[str, Any]] = []
        for music_entry in root.find('body') or []:
            songid = int(music_entry.find('music_id').text)
            bpm_min = float(music_entry.find('bpm_min').text)
            bpm_max = float(music_entry.find('bpm_max').text)
            if bpm_max > 0 and bpm_min < 0:
                bpm_min = bpm_max
            difficulties = [
                int(music_entry.find('level_bsc').text),
                int(music_entry.find('level_adv').text),
                int(music_entry.find('level_ext').text),
            ]
            genre = "other"
            for possible_genre in music_entry.find('genre'):
                if int(possible_genre.text) != 0:
                    genre = str(possible_genre.tag)

            songs.append({
                'id': songid,
                # Title/artist aren't in the music data for Jubeat and must be manually populated.
                # This is why there is a separate "import_metadata" and data file.
                'title': None,
                'artist': None,
                'genre': genre,
                'bpm_min': bpm_min,
                'bpm_max': bpm_max,
                'difficulty': {
                    'basic': difficulties[0],
                    'advanced': difficulties[1],
                    'extreme': difficulties[2],
                },
            })

        emblems: List[Dict[str, Any]] = []
        if self.version in {
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
        }:
            for emblem_entry in root.find('emblem_list') or []:
                print(emblem_entry)
                index = int(emblem_entry.find('index').text)
                layer = int(emblem_entry.find('layer').text)
                music_id = int(emblem_entry.find('music_id').text)
                evolved = int(emblem_entry.find('evolved').text)
                rarity = int(emblem_entry.find('rarity').text)
                name = emblem_entry.find('name').text

                emblems.append({
                    'id': index,
                    'layer': layer,
                    'music_id': music_id,
                    'evolved': evolved,
                    'rarity': rarity,
                    'name': name,
                })

        return songs, emblems

    def lookup(self, server: str, token: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        if self.version is None:
            raise Exception('Can\'t look up Jubeat database for \'all\' version!')

        # Grab music info from remote server
        music = self.remote_music(server, token)
        songs = music.get_all_songs(self.game, self.version)
        lut: Dict[int, Dict[str, Any]] = {}
        chart_map = {
            0: 'basic',
            1: 'advanced',
            2: 'extreme',
        }

        # Format it the way we expect
        for song in songs:
            if song.chart not in chart_map:
                # Ignore charts on songs we don't support/care about.
                continue

            if song.id not in lut:
                lut[song.id] = {
                    'id': song.id,
                    'title': song.name,
                    'artist': song.artist,
                    'genre': song.genre,
                    'bpm_min': song.data.get_int('bpm_min'),
                    'bpm_max': song.data.get_int('bpm_max'),
                    'difficulty': {
                        'basic': 0,
                        'advanced': 0,
                        'extreme': 0,
                    },
                }
            lut[song.id]['difficulty'][chart_map[song.chart]] = song.data.get_int('difficulty')

        # Reassemble the data
        reassembled_songs = [val for _, val in lut.items()]

        emblems: List[Dict[str, Any]] = []
        if self.version in {
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
        }:
            game = self.remote_game(server, token)
            for item in game.get_items(self.game, self.version):
                if item.type == "emblem":
                    emblems.append({
                        'id': item.id,
                        'layer': item.data.get_int('layer'),
                        'music_id': item.data.get_int('music_id'),
                        'evolved': item.data.get_int('evolved'),
                        'rarity': item.data.get_int('rarity'),
                        'name': item.data.get_str('name'),
                    })

        return reassembled_songs, emblems

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        if self.version is None:
            raise Exception('Can\'t import Jubeat database for \'all\' version!')

        chart_map: Dict[int, str] = {
            0: 'basic',
            1: 'advanced',
            2: 'extreme',
        }
        for song in songs:
            # Skip over duplicate songs for the "play five different versions of this song
            # across different prefectures" event. The song ID range is 8000301-8000347, so
            # we arbitrarily choose to keep only the first one.
            songid = song['id']
            if songid in set(range(80000302, 80000348)):
                continue

            self.start_batch()
            for chart in self.charts:
                # First, try to find in the DB from another version
                old_id = self.get_music_id_for_song(songid, chart)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {songid} chart {chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {songid} chart {chart}")
                    next_id = old_id
                data = {
                    'difficulty': song['difficulty'][chart_map[chart]],
                    'bpm_min': song['bpm_min'],
                    'bpm_max': song['bpm_max'],
                }
                self.insert_music_id_for_song(next_id, songid, chart, song['title'], song['artist'], song['genre'], data)
            self.finish_batch()

    def import_emblems(self, emblems: List[Dict[str, Any]]) -> None:
        if self.version is None:
            raise Exception('Can\'t import Jubeat database for \'all\' version!')

        self.start_batch()
        for i, emblem in enumerate(emblems):
            # Make importing faster but still do it in chunks
            if (i % 16) == 15:
                self.finish_batch()
                self.start_batch()

            print(f"New catalog entry for {emblem['music_id']}")
            self.insert_catalog_entry(
                'emblem',
                emblem['id'],
                {
                    'layer': emblem['layer'],
                    'music_id': emblem['music_id'],
                    'evolved': emblem['evolved'],
                    'rarity': emblem['rarity'],
                    'name': emblem['name'],
                },
            )

        self.finish_batch()

    def import_metadata(self, tsvfile: str) -> None:
        if self.version is not None:
            raise Exception("Unsupported Jubeat version, expected one of the following: all")

        with open(tsvfile, newline='') as tsvhandle:
            jubeatreader = csv.reader(tsvhandle, delimiter='\t', quotechar='"')  # type: ignore
            for row in jubeatreader:
                songid = int(row[0])
                name = row[1]
                artist = row[2]

                print(f"Setting name/artist for {songid} all charts")
                self.start_batch()
                for chart in self.charts:
                    self.update_metadata_for_song(songid, chart, name, artist)
                self.finish_batch()


class ImportIIDX(ImportBase):

    # Tutorial charts that shouldn't be on the UI
    BANNED_CHARTS = [
        16070,
        16071,
        16072,
        16080,
        16081,
        16082,
    ]

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        if version in ['20', '21', '22', '23', '24', '26']:
            actual_version = {
                '20': VersionConstants.IIDX_TRICORO,
                '21': VersionConstants.IIDX_SPADA,
                '22': VersionConstants.IIDX_PENDUAL,
                '23': VersionConstants.IIDX_COPULA,
                '24': VersionConstants.IIDX_SINOBUZ,
                '26': VersionConstants.IIDX_ROOTAGE,
            }[version]
            self.charts = [0, 1, 2, 3, 4, 5, 6]
        elif version in ['omni-20', 'omni-21', 'omni-22', 'omni-23', 'omni-24']:
            actual_version = {
                'omni-20': VersionConstants.IIDX_TRICORO,
                'omni-21': VersionConstants.IIDX_SPADA,
                'omni-22': VersionConstants.IIDX_PENDUAL,
                'omni-23': VersionConstants.IIDX_COPULA,
                'omni-24': VersionConstants.IIDX_SINOBUZ,
            }[version] + DBConstants.OMNIMIX_VERSION_BUMP
            self.charts = [0, 1, 2, 3, 4, 5, 6]
        elif version == 'all':
            actual_version = None
            self.charts = [0, 1, 2, 3, 4, 5, 6]
        else:
            raise Exception("Unsupported IIDX version, expected one of the following: 20, 21, 22, 23, 24, 26, omni-20, omni-21, omni-22, omni-23, omni-24!")

        super().__init__(config, GameConstants.IIDX, actual_version, no_combine, update)

    def __gather_sound_files(self, directory: str) -> Dict[int, str]:
        files = {}
        for (dirpath, dirnames, filenames) in os.walk(directory):
            for filename in filenames:
                songid, extension = os.path.splitext(filename)
                if extension == '.1' or extension == '.ifs':
                    try:
                        files[int(songid)] = os.path.join(directory, os.path.join(dirpath, filename))
                    except ValueError:
                        # Invalid file
                        pass

            for dirname in dirnames:
                files.update(self.__gather_sound_files(os.path.join(directory, dirname)))

        return files

    def __revivals(self, songid: int, chart: int) -> Optional[int]:
        old_id = self.get_music_id_for_song(songid, chart)
        if old_id is not None:
            return old_id

        # For revivals from older games, these show up as their respective old IDs
        # in Spada Omnimix, but in Pendual Omnimix they're in the Pendual category.
        legacy_to_modern_map = {
            4213: 23066,
            9203: 22068,
            10203: 22052,
            12201: 22039,
            12204: 21201,
            12206: 21064,
            13215: 23077,
            14202: 22025,
            14210: 21068,
            14211: 22069,
            14214: 23070,
            15202: 23069,
            15204: 21063,
            15205: 21065,
            15207: 22028,
            15208: 22049,
            15209: 22043,
            15211: 23060,
            15215: 21062,
            16207: 21067,
            16209: 23062,
            16212: 21066,
            22096: 23030,
            22097: 23051,
        }
        # Some charts were changed, and others kept the same on these
        if chart in [0, 1, 2]:
            legacy_to_modern_map[9206] = 23065

        legacy_songid = legacy_to_modern_map.get(songid)
        if legacy_songid is not None:
            old_id = self.get_music_id_for_song(legacy_songid, chart)
            if old_id is not None:
                return old_id

        modern_to_legacy_map = {
            23066: 4213,
            22068: 9203,
            22052: 10203,
            22039: 12201,
            21201: 12204,
            21064: 12206,
            23077: 13215,
            22025: 14202,
            21068: 14210,
            22069: 14211,
            23070: 14214,
            23069: 15202,
            21063: 15204,
            21065: 15205,
            22028: 15207,
            22049: 15208,
            22043: 15209,
            23060: 15211,
            21062: 15215,
            21067: 16207,
            23062: 16209,
            21066: 16212,
            23030: 22096,
            23051: 22097,
        }
        # Some charts were changed, and others kept the same on tehse
        if chart in [0, 1, 2]:
            modern_to_legacy_map[23065] = 9206

        modern_songid = modern_to_legacy_map.get(songid)
        if modern_songid is not None:
            old_id = self.get_music_id_for_song(modern_songid, chart)
            if old_id is not None:
                return old_id

        # Failed, so create a new one
        return None

    def __charts(self, songid: int, chart: int) -> int:
        # Scripted connection long was set as a hyper in Tricoro omnimix, we
        # need to map the charts to the another in every other version.
        if songid == 12204:
            if chart == 1:
                return 2
            if chart == 2:
                return 1
        return chart

    def scrape(self, binfile: str, assets_dir: Optional[str]) -> List[Dict[str, Any]]:
        if self.version is None:
            raise Exception('Can\'t import IIDX database for \'all\' version!')

        if assets_dir is not None:
            sound_files = self.__gather_sound_files(os.path.abspath(assets_dir))
        else:
            sound_files = None

        bh = open(binfile, 'rb')
        try:
            binarydata = bh.read()
        finally:
            bh.close()

        musicdb = IIDXMusicDB(binarydata)
        songs: List[Dict[str, Any]] = []
        for song in musicdb.songs:
            bpm = (0, 0)
            notecounts = [0, 0, 0, 0, 0, 0]

            if song.id in self.BANNED_CHARTS:
                continue

            if sound_files is not None:
                if song.id in sound_files:
                    # Look up chart info!
                    filename = sound_files[song.id]
                    _, extension = os.path.splitext(filename)
                    data = None

                    if extension == '.1':
                        fp = open(filename, 'rb')
                        data = fp.read()
                        fp.close()
                    else:
                        fp = open(filename, 'rb')
                        ifsdata = fp.read()
                        fp.close()
                        ifs = IFS(ifsdata)
                        for fn in ifs.filenames:
                            _, extension = os.path.splitext(fn)
                            if extension == '.1':
                                data = ifs.read_file(fn)

                    if data is not None:
                        iidxchart = IIDXChart(data)
                        bpm_min, bpm_max = iidxchart.bpm
                        bpm = (bpm_min, bpm_max)
                        notecounts = iidxchart.notecounts
                    else:
                        print(f"Could not find chart information for song {song.id}!")
                else:
                    print(f"No chart information because chart for song {song.id} is missing!")

            songs.append({
                'id': song.id,
                'title': song.title,
                'artist': song.artist,
                'genre': song.genre,
                'bpm_min': bpm[0],
                'bpm_max': bpm[1],
                'difficulty': {
                    'spn': song.difficulties[0],
                    'sph': song.difficulties[1],
                    'spa': song.difficulties[2],
                    'dpn': song.difficulties[3],
                    'dph': song.difficulties[4],
                    'dpa': song.difficulties[5],
                },
                'notecount': {
                    'spn': notecounts[0],
                    'sph': notecounts[1],
                    'spa': notecounts[2],
                    'dpn': notecounts[3],
                    'dph': notecounts[4],
                    'dpa': notecounts[5],
                },
            })
        return songs

    def lookup(self, server: str, token: str) -> List[Dict[str, Any]]:
        if self.version is None:
            raise Exception('Can\'t look up IIDX database for \'all\' version!')

        # Grab music info from remote server
        music = self.remote_music(server, token)
        songs = music.get_all_songs(self.game, self.version)
        lut: Dict[int, Dict[str, Any]] = {}
        chart_map = {
            0: 'spn',
            1: 'sph',
            2: 'spa',
            3: 'dpn',
            4: 'dph',
            5: 'dpa',
        }

        # Format it the way we expect
        for song in songs:
            if song.id in self.BANNED_CHARTS:
                continue
            if song.chart not in chart_map:
                # Ignore charts on songs we don't support/care about.
                continue

            if song.id not in lut:
                lut[song.id] = {
                    'id': song.id,
                    'title': song.name,
                    'artist': song.artist,
                    'genre': song.genre,
                    'bpm_min': song.data.get_int('bpm_min'),
                    'bpm_max': song.data.get_int('bpm_max'),
                    'difficulty': {
                        'spn': 0,
                        'sph': 0,
                        'spa': 0,
                        'dpn': 0,
                        'dph': 0,
                        'dpa': 0,
                    },
                    'notecount': {
                        'spn': 0,
                        'sph': 0,
                        'spa': 0,
                        'dpn': 0,
                        'dph': 0,
                        'dpa': 0,
                    },
                }
            if song.chart in chart_map:
                lut[song.id]['difficulty'][chart_map[song.chart]] = song.data.get_int('difficulty')
                lut[song.id]['notecount'][chart_map[song.chart]] = song.data.get_int('notecount')

        # Return the reassembled data
        return [val for _, val in lut.items()]

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        if self.version is None:
            raise Exception('Can\'t import IIDX database for \'all\' version!')

        # Import each song into our DB
        chart_map = {
            0: 'spn',
            1: 'sph',
            2: 'spa',
            3: 'dpn',
            4: 'dph',
            5: 'dpa',
        }
        for song in songs:
            self.start_batch()
            for chart in self.charts:
                if chart == 6:
                    # Beginner chart
                    songdata: Dict[str, Any] = {}
                else:
                    songdata = {
                        'difficulty': song['difficulty'][chart_map[chart]],
                        'bpm_min': song['bpm_min'],
                        'bpm_max': song['bpm_max'],
                        'notecount': song['notecount'][chart_map[chart]],
                    }
                # First, try to find in the DB from another version
                old_id = self.__revivals(song['id'], self.__charts(song['id'], chart))
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {song['id']} chart {chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {song['id']} chart {chart}")
                    next_id = old_id
                self.insert_music_id_for_song(next_id, song['id'], chart, song['title'], song['artist'], song['genre'], songdata)
            self.finish_batch()

    def import_metadata(self, tsvfile: str) -> None:
        if self.version is not None:
            raise Exception("Unsupported IIDX version, expected one of the following: all")

        with open(tsvfile, newline='') as tsvhandle:
            iidxreader = csv.reader(tsvhandle, delimiter='\t', quotechar='"')  # type: ignore
            for row in iidxreader:
                songid = int(row[0])
                name = row[1]
                artist = row[2]
                genre = row[3]

                if len(name) == 0:
                    name = None
                if len(artist) == 0:
                    artist = None
                if len(genre) == 0:
                    genre = None

                print(f"Setting name/artist/genre for {songid} all charts")
                self.start_batch()
                for chart in self.charts:
                    self.update_metadata_for_song(songid, chart, name, artist, genre)
                self.finish_batch()


class ImportDDR(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        if version in ['12', '13', '14', '15', '16']:
            actual_version = {
                '12': VersionConstants.DDR_X2,
                '13': VersionConstants.DDR_X3_VS_2NDMIX,
                '14': VersionConstants.DDR_2013,
                '15': VersionConstants.DDR_2014,
                '16': VersionConstants.DDR_ACE,
            }[version]
            self.charts = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        else:
            raise Exception("Unsupported DDR version, expected one of the following: 12, 13, 14, 15, 16")

        super().__init__(config, GameConstants.DDR, actual_version, no_combine, update)

    def scrape(self, infile: str) -> List[Dict[str, Any]]:
        with open(infile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

        if self.version == VersionConstants.DDR_X2:
            # Based on JDX:J:A:A:2010111000
            offset = 0x254fc0
            size = 0x14C
            length = 894
            # Basic stuff like ID, bpm, chart difficulties
            unpackfmt = '<xxxxxxxxHHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxHHBBBBBBBBBB'
            # Groove radar
            unpackfmt += 'HHHHHHHHH' * 5
            if len(unpackfmt) < size:
                # Skew is because I'm too lazy to count the Hs above
                skew = 3 + (9 * 5)
                # Just pad it for ease of construction
                unpackfmt = unpackfmt + ('x' * (size - len(unpackfmt) - skew))
            # Basic offsets
            id_offset = 1
            edit_offset = 0
            bpm_min_offset = 3
            bpm_max_offset = 2
            folder_offset = 24  # This is a byte offset into the raw field

            # Single/double difficulty array offsets
            single_difficulties = 4
            double_difficulties = 9

            # Groove gauge offsets
            groove_single_beginner = 22
            groove_single_basic = 14
            groove_single_difficult = 15
            groove_single_expert = 16
            groove_single_challenge = 17

            groove_double_basic = 18
            groove_double_difficult = 19
            groove_double_expert = 20
            groove_double_challenge = 21

            # Relative offsets for each groove gauge value
            voltage = 0
            stream = 9
            air = 18
            chaos = 27
            freeze = 36

            # Folder start version
            folder_start = 12
        elif self.version == VersionConstants.DDR_X3_VS_2NDMIX:
            # Based on KDX:J:A:A:2012112600
            offset = 0x27A4C8
            size = 0x150
            length = 1062
            # Basic stuff like ID, bpm, chart difficulties
            unpackfmt = '<xxxxxxxxHHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxHHBBBBBBBBBB'
            # Groove radar
            unpackfmt += 'HHHHHHHHH' * 5
            if len(unpackfmt) < size:
                # Skew is because I'm too lazy to count the Hs above
                skew = 3 + (9 * 5)
                # Just pad it for ease of construction
                unpackfmt = unpackfmt + ('x' * (size - len(unpackfmt) - skew))
            # Basic offsets
            id_offset = 1
            edit_offset = 0
            bpm_min_offset = 3
            bpm_max_offset = 2
            folder_offset = 24  # This is a byte offset into the raw field

            # Single/double difficulty array offsets
            single_difficulties = 4
            double_difficulties = 9

            # Groove gauge offsets
            groove_single_beginner = 22
            groove_single_basic = 14
            groove_single_difficult = 15
            groove_single_expert = 16
            groove_single_challenge = 17

            groove_double_basic = 18
            groove_double_difficult = 19
            groove_double_expert = 20
            groove_double_challenge = 21

            # Relative offsets for each groove gauge value
            voltage = 0
            stream = 9
            air = 18
            chaos = 27
            freeze = 36

            # Folder start version
            folder_start = 13
        elif self.version == VersionConstants.DDR_2013:
            # Based on MDX:J:A:A:2014032700
            offset = 0x2663D8
            size = 0x1D0
            length = 1238
            # Basic stuff like ID, bpm, chart difficulties
            unpackfmt = '<xxxxxxxxHHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxHHBBBBBBBBBB'
            # Groove radar
            unpackfmt += 'HHHHHHHHH' * 5
            if len(unpackfmt) < size:
                # Skew is because I'm too lazy to count the Hs above
                skew = 3 + (9 * 5)
                # Just pad it for ease of construction
                unpackfmt = unpackfmt + ('x' * (size - len(unpackfmt) - skew))
            # Basic offsets
            id_offset = 1
            edit_offset = 0
            bpm_min_offset = 3
            bpm_max_offset = 2
            folder_offset = 20  # This is a byte offset into the raw field

            # Single/double difficulty array offsets
            single_difficulties = 4
            double_difficulties = 9

            # Groove gauge offsets
            groove_single_beginner = 22
            groove_single_basic = 14
            groove_single_difficult = 15
            groove_single_expert = 16
            groove_single_challenge = 17

            groove_double_basic = 18
            groove_double_difficult = 19
            groove_double_expert = 20
            groove_double_challenge = 21

            # Relative offsets for each groove gauge value
            voltage = 0
            stream = 9
            air = 18
            chaos = 27
            freeze = 36

            # Folder start version
            folder_start = 14
        elif self.version == VersionConstants.DDR_2014:
            # Based on MDX:A:A:A:2015122100
            offset = 0x2B72B0
            size = 0x1D0
            length = 1466
            # Basic stuff like ID, bpm, chart difficulties
            unpackfmt = '<xxxxxxxxHHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxHHBBBBBBBBBB'
            # Groove radar
            unpackfmt += 'HHHHHHHHH' * 5
            if len(unpackfmt) < size:
                # Skew is because I'm too lazy to count the Hs above
                skew = 3 + (9 * 5)
                # Just pad it for ease of construction
                unpackfmt = unpackfmt + ('x' * (size - len(unpackfmt) - skew))
            # Basic offsets
            id_offset = 1
            edit_offset = 0
            bpm_min_offset = 3
            bpm_max_offset = 2
            folder_offset = 20  # This is a byte offset into the raw field

            # Single/double difficulty array offsets
            single_difficulties = 4
            double_difficulties = 9

            # Groove gauge offsets
            groove_single_beginner = 22
            groove_single_basic = 14
            groove_single_difficult = 15
            groove_single_expert = 16
            groove_single_challenge = 17

            groove_double_basic = 18
            groove_double_difficult = 19
            groove_double_expert = 20
            groove_double_challenge = 21

            # Relative offsets for each groove gauge value
            voltage = 0
            stream = 9
            air = 18
            chaos = 27
            freeze = 36

            # Folder start version
            folder_start = 15
        else:
            raise Exception('Unknown game version!')
        songs = []

        for i in range(length):
            start = offset + (i * size)
            end = offset + ((i + 1) * size)
            chunk = data[start:end]

            # First, figure out if it is actually a song
            ssqcode = chunk[0:6].decode('ascii').replace('\0', '').strip()
            if len(ssqcode) == 0:
                continue
            unpacked = struct.unpack(unpackfmt, chunk)
            songinfo = {
                'id': unpacked[id_offset],
                'edit_id': unpacked[edit_offset],
                'ssqcode': ssqcode,
                'difficulty': {
                    'single': {
                        'beginner': unpacked[single_difficulties + 0],
                        'basic': unpacked[single_difficulties + 1],
                        'difficult': unpacked[single_difficulties + 2],
                        'expert': unpacked[single_difficulties + 3],
                        'challenge': unpacked[single_difficulties + 4],
                    },
                    'double': {
                        'beginner': unpacked[double_difficulties + 0],
                        'basic': unpacked[double_difficulties + 1],
                        'difficult': unpacked[double_difficulties + 2],
                        'expert': unpacked[double_difficulties + 3],
                        'challenge': unpacked[double_difficulties + 4],
                    },
                },
                'groove_gauge': {
                    'single': {
                        'beginner': {
                            'voltage': unpacked[groove_single_beginner + voltage],
                            'stream': unpacked[groove_single_beginner + stream],
                            'air': unpacked[groove_single_beginner + air],
                            'chaos': unpacked[groove_single_beginner + chaos],
                            'freeze': unpacked[groove_single_beginner + freeze],
                        },
                        'basic': {
                            'voltage': unpacked[groove_single_basic + voltage],
                            'stream': unpacked[groove_single_basic + stream],
                            'air': unpacked[groove_single_basic + air],
                            'chaos': unpacked[groove_single_basic + chaos],
                            'freeze': unpacked[groove_single_basic + freeze],
                        },
                        'difficult': {
                            'voltage': unpacked[groove_single_difficult + voltage],
                            'stream': unpacked[groove_single_difficult + stream],
                            'air': unpacked[groove_single_difficult + air],
                            'chaos': unpacked[groove_single_difficult + chaos],
                            'freeze': unpacked[groove_single_difficult + freeze],
                        },
                        'expert': {
                            'voltage': unpacked[groove_single_expert + voltage],
                            'stream': unpacked[groove_single_expert + stream],
                            'air': unpacked[groove_single_expert + air],
                            'chaos': unpacked[groove_single_expert + chaos],
                            'freeze': unpacked[groove_single_expert + freeze],
                        },
                        'challenge': {
                            'voltage': unpacked[groove_single_challenge + voltage],
                            'stream': unpacked[groove_single_challenge + stream],
                            'air': unpacked[groove_single_challenge + air],
                            'chaos': unpacked[groove_single_challenge + chaos],
                            'freeze': unpacked[groove_single_challenge + freeze],
                        },
                    },
                    'double': {
                        'beginner': {
                            'voltage': 0,
                            'stream': 0,
                            'air': 0,
                            'chaos': 0,
                            'freeze': 0,
                        },
                        'basic': {
                            'voltage': unpacked[groove_double_basic + voltage],
                            'stream': unpacked[groove_double_basic + stream],
                            'air': unpacked[groove_double_basic + air],
                            'chaos': unpacked[groove_double_basic + chaos],
                            'freeze': unpacked[groove_double_basic + freeze],
                        },
                        'difficult': {
                            'voltage': unpacked[groove_double_difficult + voltage],
                            'stream': unpacked[groove_double_difficult + stream],
                            'air': unpacked[groove_double_difficult + air],
                            'chaos': unpacked[groove_double_difficult + chaos],
                            'freeze': unpacked[groove_double_difficult + freeze],
                        },
                        'expert': {
                            'voltage': unpacked[groove_double_expert + voltage],
                            'stream': unpacked[groove_double_expert + stream],
                            'air': unpacked[groove_double_expert + air],
                            'chaos': unpacked[groove_double_expert + chaos],
                            'freeze': unpacked[groove_double_expert + freeze],
                        },
                        'challenge': {
                            'voltage': unpacked[groove_double_challenge + voltage],
                            'stream': unpacked[groove_double_challenge + stream],
                            'air': unpacked[groove_double_challenge + air],
                            'chaos': unpacked[groove_double_challenge + chaos],
                            'freeze': unpacked[groove_double_challenge + freeze],
                        },
                    },
                },
                'bpm_min': unpacked[bpm_min_offset],
                'bpm_max': unpacked[bpm_max_offset],
                'folder': folder_start - chunk[folder_offset],
            }
            songs.append(songinfo)
        return songs

    def hydrate(self, songs: List[Dict[str, Any]], infile: str) -> List[Dict[str, Any]]:
        tree = ET.parse(infile)
        root = tree.getroot()
        data = {}
        for music_entry in root.find('mdblist'):
            musicid = int(music_entry.attrib['reclink'])
            title = ''
            artist = ''
            title_en = ''
            artist_en = ''

            for child in music_entry:
                if child.tag == 'name':
                    if child.attrib['lang'] == 'ja':
                        title = child.text
                    else:
                        title_en = child.text
                if child.tag == 'artist':
                    if child.attrib['lang'] == 'ja':
                        artist = child.text
                    else:
                        artist_en = child.text

            data[musicid] = {
                'title': title,
                'artist': artist,
                'title_en': title_en,
                'artist_en': artist_en,
            }

        songs = copy.deepcopy(songs)
        for song in songs:
            newdata = data.get(song['id'])
            if newdata is not None:
                song.update(newdata)

        return songs

    def parse_xml(self, arcfile: str) -> List[Dict[str, Any]]:
        with open(arcfile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

        arc = ARC(data)
        if 'data/gamedata/musicdb.xml' in arc.filenames:
            xmldata = arc.read_file('data/gamedata/musicdb.xml')
        else:
            raise Exception('Invalid .arc file provided!')

        xml = xmldata.decode('utf-8')
        root = ET.fromstring(xml)
        songs = []

        if root.tag != 'mdb':
            raise Exception('Invalid musicdb.xml file in .arc!')

        for music_entry in root:
            songid = int(music_entry.find('mcode').text)
            title = music_entry.find('title').text
            artist = music_entry.find('artist').text
            ssqcode = music_entry.find('basename').text
            bpm = int(music_entry.find('bpmmax').text)
            folder = int(music_entry.find('series').text)
            difficulties = [int(x) for x in music_entry.find('diffLv').text.split(' ')]

            # For some reason Ace thinks of itself as 17, and DDR 2013/2014 as 14, 15 and 16
            # somewhat spread out. Fix that here.
            folder = {
                1: 1,
                2: 2,
                3: 3,
                4: 4,
                5: 5,
                6: 6,
                7: 7,
                8: 8,
                9: 9,
                10: 10,
                11: 11,
                12: 12,
                13: 13,
                14: 14,
                15: 15,
                16: 15,
                17: 16,
                18: 17,
            }[folder]

            songinfo = {
                'id': songid,
                'edit_id': songid,
                'ssqcode': ssqcode,
                'title': title,
                'artist': artist,
                'difficulty': {
                    'single': {
                        'beginner': difficulties[0],
                        'basic': difficulties[1],
                        'difficult': difficulties[2],
                        'expert': difficulties[3],
                        'challenge': difficulties[4],
                    },
                    'double': {
                        'beginner': difficulties[5],
                        'basic': difficulties[6],
                        'difficult': difficulties[7],
                        'expert': difficulties[8],
                        'challenge': difficulties[9],
                    },
                },
                'bpm_min': bpm,
                'bpm_max': bpm,
                'folder': folder,
                'groove_gauge': {},
            }

            # Groove information is calculated on the fly, maybe some day we will
            # duplicate that here, but for now, zero it out.
            for playmode in ['single', 'double']:
                songinfo['groove_gauge'][playmode] = {}  # type: ignore

                for charttype in ['beginner', 'basic', 'difficult', 'expert', 'challenge']:
                    songinfo['groove_gauge'][playmode][charttype] = {  # type: ignore
                        'voltage': 0,
                        'stream': 0,
                        'air': 0,
                        'chaos': 0,
                        'freeze': 0,
                    }

            songs.append(songinfo)

        return songs

    def lookup(self, server: str, token: str) -> List[Dict[str, Any]]:
        # Grab music info from remote server
        music = self.remote_music(server, token)
        songs = music.get_all_songs(self.game, self.version)
        lut: Dict[int, Dict[str, Any]] = {}
        chart_map = {
            0: ('single', 'beginner'),
            1: ('single', 'basic'),
            2: ('single', 'difficult'),
            3: ('single', 'expert'),
            4: ('single', 'challenge'),
            5: ('double', 'beginner'),
            6: ('double', 'basic'),
            7: ('double', 'difficult'),
            8: ('double', 'expert'),
            9: ('double', 'challenge'),
        }

        # Format it the way we expect
        for song in songs:
            if song.chart not in chart_map:
                # Ignore charts on songs we don't support/care about.
                continue

            if song.id not in lut:
                lut[song.id] = {
                    'id': song.id,
                    'edit_id': song.data.get_int('edit_id'),
                    'ssqcode': '',
                    'title': song.name,
                    'artist': song.artist,
                    'difficulty': {
                        'single': {
                            'beginner': 0,
                            'basic': 0,
                            'difficult': 0,
                            'expert': 0,
                            'challenge': 0,
                        },
                        'double': {
                            'beginner': 0,
                            'basic': 0,
                            'difficult': 0,
                            'expert': 0,
                            'challenge': 0,
                        },
                    },
                    'groove_gauge': {
                        'single': {
                            'beginner': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'basic': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'difficult': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'expert': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'challenge': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                        },
                        'double': {
                            'beginner': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'basic': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'difficult': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'expert': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                            'challenge': {
                                'voltage': 0,
                                'stream': 0,
                                'air': 0,
                                'chaos': 0,
                                'freeze': 0,
                            },
                        },
                    },
                    'bpm_min': song.data.get_int('bpm_min'),
                    'bpm_max': song.data.get_int('bpm_max'),
                    'folder': song.data.get_int('category'),
                }
            style, chart = chart_map[song.chart]
            lut[song.id]['difficulty'][style][chart] = song.data.get_int('difficulty')
            lut[song.id]['groove_gauge'][style][chart]['air'] = song.data.get_dict('groove').get_int('air')
            lut[song.id]['groove_gauge'][style][chart]['chaos'] = song.data.get_dict('groove').get_int('chaos')
            lut[song.id]['groove_gauge'][style][chart]['freeze'] = song.data.get_dict('groove').get_int('freeze')
            lut[song.id]['groove_gauge'][style][chart]['stream'] = song.data.get_dict('groove').get_int('stream')
            lut[song.id]['groove_gauge'][style][chart]['voltage'] = song.data.get_dict('groove').get_int('voltage')

        # Return the reassembled data
        return [val for _, val in lut.items()]

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        for song in songs:
            self.start_batch()
            for chart in self.charts:
                key = ['beginner', 'basic', 'difficult', 'expert', 'challenge']

                if chart in [0, 1, 2, 3, 4]:
                    # For singles only!
                    difficulty = song['difficulty']['single'][key[chart]]
                    groovestats = song['groove_gauge']['single'][key[chart]]
                elif chart in [5, 6, 7, 8, 9]:
                    # Doubles!
                    difficulty = song['difficulty']['double'][key[chart - 5]]
                    groovestats = song['groove_gauge']['double'][key[chart - 5]]
                else:
                    raise Exception('Unrecognized chart type!')

                if difficulty == 0:
                    # No chart for this difficulty
                    continue

                if song['edit_id'] == 0:
                    raise Exception('Expected non-zero edit id!')

                # DDR is stupid and changes in-game IDs around willy-nilly, but the edit ID is stable.
                # So, create a virtual edit ID entry and link everything to that. We can't just store
                # the edit ID as the real ID because in-game the protocol uses the changing ID.
                old_id = self.get_music_id_for_song(song['edit_id'], chart, version=0)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {song['title']} {song['artist']} ({song['id']} chart {chart})")
                    next_id = self.get_next_music_id()
                else:
                    print(f"Reused entry for {song['title']} {song['artist']} ({song['id']} chart {chart})")
                    next_id = old_id
                # Add the virtual entry we talked about above, so we can link this song in the future.
                self.insert_music_id_for_song(
                    next_id,
                    song['edit_id'],
                    chart,
                    song['title'],
                    song['artist'],
                    None,  # No genres in DDR
                    {
                        'category': song['folder'],
                        'bpm_min': song['bpm_min'],
                        'bpm_max': song['bpm_max'],
                        'difficulty': difficulty,
                        'groove': groovestats,
                        'edit_id': song['edit_id'],
                    },
                    version=0,
                )
                # Add the normal entry so the game finds the song.
                self.insert_music_id_for_song(
                    next_id,
                    song['id'],
                    chart,
                    song['title'],
                    song['artist'],
                    None,  # No genres in DDR
                    {
                        'category': song['folder'],
                        'bpm_min': song['bpm_min'],
                        'bpm_max': song['bpm_max'],
                        'difficulty': difficulty,
                        'groove': groovestats,
                        'edit_id': song['edit_id'],
                    },
                )
            self.finish_batch()


class ImportSDVX(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        actual_version = {
            '1': VersionConstants.SDVX_BOOTH,
            '2': VersionConstants.SDVX_INFINITE_INFECTION,
            '3': VersionConstants.SDVX_GRAVITY_WARS,
            '4': VersionConstants.SDVX_HEAVENLY_HAVEN,
        }.get(version, -1)
        if actual_version == VersionConstants.SDVX_BOOTH:
            self.charts = [0, 1, 2]
        elif actual_version in [VersionConstants.SDVX_INFINITE_INFECTION, VersionConstants.SDVX_GRAVITY_WARS]:
            self.charts = [0, 1, 2, 3]
        elif actual_version == VersionConstants.SDVX_HEAVENLY_HAVEN:
            self.charts = [0, 1, 2, 3, 4]
        else:
            raise Exception("Unsupported SDVX version, expected one of the following: 1, 2, 3, 4!")

        super().__init__(config, GameConstants.SDVX, actual_version, no_combine, update)

    def scrape(self, infile: str) -> List[Dict[str, Any]]:
        with open(infile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

        pe = pefile.PE(data=data, fast_load=True)

        def virtual_to_physical(offset: int) -> int:
            for section in pe.sections:
                start = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                end = start + section.SizeOfRawData

                if offset >= start and offset < end:
                    return (offset - start) + section.PointerToRawData
            raise Exception(f'Couldn\'t find raw offset for virtual offset 0x{offset:08x}')

        if self.version == VersionConstants.SDVX_BOOTH:
            offset = 0xFFF28
            size = 163
            stride = 40
        else:
            raise Exception('Unsupported version for catalog scrape!')

        def read_string(spot: int) -> str:
            # First, translate load offset in memory to disk offset
            spot = virtual_to_physical(spot)

            # Now, grab bytes until we're null-terminated
            bytestring = []
            while data[spot] != 0:
                bytestring.append(data[spot])
                spot = spot + 1

            return bytes(bytestring).decode('shift_jis')

        entries = []
        for i in range(size):
            start = offset + i * stride
            end = offset + (i + 1) * stride
            chunk = data[start:end]

            values = struct.unpack('<IIIIIIIIII', chunk)
            # Price looks to be fixed here, assert it so we catch problems
            if values[3] != values[4]:
                raise Exception('Expected price values to match!')
            entry = {
                'catalogid': values[0],
                'musicid': values[1],
                'chart': values[2],
                'price': values[3],
                'condition_jp': read_string(values[8]),
                'condition_en': read_string(values[9]),
            }
            entries.append(entry)
        return entries

    def import_catalog(self, dllfile: str) -> None:
        entries = self.scrape(dllfile)

        for entry in entries:
            self.start_batch()
            print(f"New catalog entry for {entry['musicid']} chart {entry['chart']}")
            self.insert_catalog_entry(
                'song_unlock',
                entry['catalogid'],
                {
                    'blocks': entry['price'],
                    'musicid': entry['musicid'],
                    'chart': entry['chart'],
                },
            )
            self.finish_batch()

    def import_appeal_cards(self, csvfile: str) -> None:
        with open(csvfile, 'rb') as csvhandle:
            csvdata = csvhandle.read().decode('shift_jisx0213')

        csvstr = io.StringIO(csvdata)
        appealreader = csv.reader(csvstr, delimiter=',', quotechar='"')  # type: ignore
        for row in appealreader:
            appealids = []
            if self.version == VersionConstants.SDVX_INFINITE_INFECTION:
                try:
                    appealids.append(int(row[-5]))
                except (TypeError, ValueError):
                    pass
            elif self.version == VersionConstants.SDVX_GRAVITY_WARS:
                try:
                    appealids.append(int(row[-9]))
                except (TypeError, ValueError):
                    pass
            else:
                raise Exception(f'Cannot import appeal cards for SDVX version {self.version}')

            self.start_batch()
            for appealid in appealids:
                print(f"New catalog entry for appeal card {appealid}")
                self.insert_catalog_entry(
                    'appealcard',
                    appealid,
                    {},
                )
            self.finish_batch()

    def import_music_db_or_appeal_cards(self, xmlfile: str) -> None:
        with open(xmlfile, 'rb') as fp:
            # This is gross, but elemtree won't do it for us so whatever
            bytedata = fp.read()
            strdata = bytedata.decode('shift_jisx0213', errors='replace')
        root = ET.fromstring(strdata)

        for music_entry in root.findall('music'):
            # Grab the ID
            songid = int(music_entry.attrib['id'])
            title = None
            artist = None
            bpm_min = None
            bpm_max = None
            limited = [0, 0, 0, 0, 0]
            difficulties = [0, 0, 0, 0, 0]

            if self.version == VersionConstants.SDVX_BOOTH:
                # Find normal info about the song
                for info in music_entry.findall('info'):
                    if info.attrib['attr'] == 'title_yomigana':
                        title = jaconv.h2z(info.text)
                    if info.attrib['attr'] == 'artist_yomigana':
                        artist = jaconv.h2z(info.text)
                    if info.attrib['attr'] == 'bpm_min':
                        bpm_min = float(info.text)
                    if info.attrib['attr'] == 'bpm_max':
                        bpm_max = float(info.text)
                    if info.attrib['attr'] == 'limited':
                        limited = [int(info.text), int(info.text), int(info.text), int(info.text)]
                # Make sure we got everything
                if title is None or artist is None or bpm_min is None or bpm_max is None:
                    raise Exception(f'Couldn\'t parse info for song {songid}')

                # Grab valid difficulties
                for difficulty in music_entry.findall('difficulty'):
                    # Figure out the actual difficulty
                    offset = {
                        'novice': 0,
                        'advanced': 1,
                        'exhaust': 2,
                    }.get(difficulty.attrib['attr'])
                    if offset is None:
                        continue

                    difficulties[offset] = int(difficulty.find('difnum').text)
            elif self.version in [VersionConstants.SDVX_INFINITE_INFECTION, VersionConstants.SDVX_GRAVITY_WARS]:
                # Find normal info about the song
                info = music_entry.find('info')
                title = info.find('title_name').text
                artist = info.find('artist_name').text
                bpm_min = float(info.find('bpm_min').text) / 100.0
                bpm_max = float(info.find('bpm_max').text) / 100.0

                # Grab valid difficulties
                for difficulty in music_entry.find('difficulty'):
                    # Figure out the actual difficulty
                    offset = {
                        'novice': 0,
                        'advanced': 1,
                        'exhaust': 2,
                        'infinite': 3,
                    }.get(difficulty.tag)
                    if offset is None:
                        continue

                    difficulties[offset] = int(difficulty.find('difnum').text)
                    limited[offset] = int(difficulty.find('limited').text)
            elif self.version == VersionConstants.SDVX_HEAVENLY_HAVEN:
                # Find normal info about the song
                info = music_entry.find('info')
                title = info.find('title_name').text
                artist = info.find('artist_name').text
                bpm_min = float(info.find('bpm_min').text) / 100.0
                bpm_max = float(info.find('bpm_max').text) / 100.0

                # Grab valid difficulties
                for difficulty in music_entry.find('difficulty'):
                    # Figure out the actual difficulty
                    offset = {
                        'novice': 0,
                        'advanced': 1,
                        'exhaust': 2,
                        'infinite': 3,
                        'maximum': 4,
                    }.get(difficulty.tag)
                    if offset is None:
                        continue

                    difficulties[offset] = int(difficulty.find('difnum').text)
                    limited[offset] = int(difficulty.find('limited').text)

            # Fix accent issues with title/artist
            accent_lut: Dict[str, str] = {
                '驩': 'Ø',
                '齲': '♥',
                '齶': '♡',
                '趁': 'Ǣ',
                '騫': 'á',
                '曦': 'à',
                '驫': 'ā',
                '齷': 'é',
                '曩': 'è',
                '䧺': 'ê',
                '骭': 'ü',
            }

            for orig, rep in accent_lut.items():
                title = title.replace(orig, rep)
                artist = artist.replace(orig, rep)

            # Import it
            self.start_batch()
            for chart in self.charts:
                # First, try to find in the DB from another version
                old_id = self.get_music_id_for_song(songid, chart)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {songid} chart {chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {songid} chart {chart}")
                    next_id = old_id
                data = {
                    'limited': limited[chart],
                    'difficulty': difficulties[chart],
                    'bpm_min': bpm_min,
                    'bpm_max': bpm_max,
                }
                self.insert_music_id_for_song(next_id, songid, chart, title, artist, None, data)
            self.finish_batch()

        appealids: List[int] = []
        for appeal_entry in root.findall('card'):
            # Grab the ID
            appealids.append(int(appeal_entry.attrib['id']))

        if appealids:
            self.start_batch()
            for appealid in appealids:
                print(f"New catalog entry for appeal card {appealid}")
                self.insert_catalog_entry(
                    'appealcard',
                    appealid,
                    {},
                )
            self.finish_batch()

    def import_from_server(self, server: str, token: str) -> None:
        # First things first, lets try to import the music DB. We want to make
        # sure that even if the server doesn't respond right, we have a chart
        # entry for every chart for each song we're importing.
        music = self.remote_music(server, token)
        music_lut: Dict[int, Dict[int, Song]] = {}
        for entry in music.get_all_songs(self.game, self.version):
            if entry.id not in music_lut:
                music_lut[entry.id] = {
                    chart: Song(
                        entry.game,
                        entry.version,
                        entry.id,
                        chart,
                        entry.name,
                        entry.artist,
                        entry.genre,
                        {}
                    ) for chart in self.charts
                }
            music_lut[entry.id][entry.chart] = entry

        # Import it
        for _, songs in music_lut.items():
            self.start_batch()
            for _, song in songs.items():
                old_id = self.get_music_id_for_song(song.id, song.chart)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {song.id} chart {song.chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {song.id} chart {song.chart}")
                    next_id = old_id
                data = {
                    'limited': song.data.get_int('limited'),
                    'difficulty': song.data.get_int('difficulty'),
                    'bpm_min': song.data.get_int('bpm_min'),
                    'bpm_max': song.data.get_int('bpm_max'),
                }
                self.insert_music_id_for_song(next_id, song.id, song.chart, song.name, song.artist, None, data)
            self.finish_batch()

        # Now, attempt to insert any catalog items we got for this version.
        game = self.remote_game(server, token)
        self.start_batch()
        for item in game.get_items(self.game, self.version):
            if item.type == "appealcard":
                print(f"New catalog entry for appeal card {item.id}")
                self.insert_catalog_entry(
                    'appealcard',
                    item.id,
                    {},
                )
            elif item.type == "song_unlock":
                print(f"New catalog entry for {item.data.get_int('musicid')} chart {item.data.get_int('chart')}")
                self.insert_catalog_entry(
                    'song_unlock',
                    item.id,
                    {
                        'blocks': item.data.get_int('blocks'),
                        'musicid': item.data.get_int('musicid'),
                        'chart': item.data.get_int('chart'),
                    },
                )
        self.finish_batch()


class ImportMuseca(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        actual_version = {
            '1': VersionConstants.MUSECA,
            '1+1/2': VersionConstants.MUSECA_1_PLUS,
        }.get(version, -1)

        if actual_version in [VersionConstants.MUSECA, VersionConstants.MUSECA_1_PLUS]:
            self.charts = [0, 1, 2, 3]
        else:
            raise Exception("Unsupported Museca version, expected one of the following: 1, 1+1/2!")

        super().__init__(config, GameConstants.MUSECA, actual_version, no_combine, update)

    def import_music_db(self, xmlfile: str) -> None:
        with open(xmlfile, 'rb') as fp:
            # This is gross, but elemtree won't do it for us so whatever
            bytedata = fp.read()
            strdata = bytedata.decode('shift_jisx0213')
        root = ET.fromstring(strdata)

        for music_entry in root.findall('music'):
            # Grab the ID
            songid = int(music_entry.attrib['id'])
            title = None
            artist = None
            bpm_min = None
            bpm_max = None
            limited = [0, 0, 0, 0]
            difficulties = [0, 0, 0, 0]

            # Find normal info about the song
            info = music_entry.find('info')
            title = info.find('title_name').text
            artist = info.find('artist_name').text
            bpm_min = float(info.find('bpm_min').text) / 100.0
            bpm_max = float(info.find('bpm_max').text) / 100.0

            # Grab valid difficulties
            for difficulty in music_entry.find('difficulty'):
                # Figure out the actual difficulty
                offset = {
                    'novice': 0,
                    'advanced': 1,
                    'exhaust': 2,
                    'infinite': 3,
                }.get(difficulty.tag)
                if offset is None:
                    continue

                difficulties[offset] = int(difficulty.find('difnum').text)
                limited[offset] = int(difficulty.find('limited').text)

            # Import it
            self.start_batch()
            for chart in self.charts:
                # First, try to find in the DB from another version
                old_id = self.get_music_id_for_song(songid, chart)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {songid} chart {chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {songid} chart {chart}")
                    next_id = old_id
                data = {
                    'limited': limited[chart],
                    'difficulty': difficulties[chart],
                    'bpm_min': bpm_min,
                    'bpm_max': bpm_max,
                }
                self.insert_music_id_for_song(next_id, songid, chart, title, artist, None, data)
            self.finish_batch()

    def import_from_server(self, server: str, token: str) -> None:
        # First things first, lets try to import the music DB. We want to make
        # sure that even if the server doesn't respond right, we have a chart
        # entry for every chart for each song we're importing.
        music = self.remote_music(server, token)
        music_lut: Dict[int, Dict[int, Song]] = {}
        for entry in music.get_all_songs(self.game, self.version):
            if entry.id not in music_lut:
                music_lut[entry.id] = {
                    chart: Song(
                        entry.game,
                        entry.version,
                        entry.id,
                        chart,
                        entry.name,
                        entry.artist,
                        entry.genre,
                        {}
                    ) for chart in self.charts
                }
            music_lut[entry.id][entry.chart] = entry

        # Import it
        for _, songs in music_lut.items():
            self.start_batch()
            for _, song in songs.items():
                # First, try to find in the DB from another version
                old_id = self.get_music_id_for_song(song.id, song.chart)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {song.id} chart {song.chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {song.id} chart {song.chart}")
                    next_id = old_id
                data = {
                    'limited': song.data.get_int('limited'),
                    'difficulty': song.data.get_int('difficulty'),
                    'bpm_min': song.data.get_int('bpm_min'),
                    'bpm_max': song.data.get_int('bpm_max'),
                }
                self.insert_music_id_for_song(next_id, song.id, song.chart, song.name, song.artist, None, data)
            self.finish_batch()


class ImportReflecBeat(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        # We always have 4 charts, even if we're importing from Colette and below,
        # so that we guarantee a stable song ID. We'll be in trouble if Reflec
        # ever adds a fifth chart.
        if version in ['1', '2', '3', '4', '5', '6']:
            actual_version = {
                '1': VersionConstants.REFLEC_BEAT,
                '2': VersionConstants.REFLEC_BEAT_LIMELIGHT,
                '3': VersionConstants.REFLEC_BEAT_COLETTE,
                '4': VersionConstants.REFLEC_BEAT_GROOVIN,
                '5': VersionConstants.REFLEC_BEAT_VOLZZA,
                '6': VersionConstants.REFLEC_BEAT_VOLZZA_2,
            }[version]
            self.charts = [0, 1, 2, 3]
        else:
            raise Exception("Unsupported ReflecBeat version, expected one of the following: 1, 2, 3, 4, 5, 6")

        super().__init__(config, GameConstants.REFLEC_BEAT, actual_version, no_combine, update)

    def scrape(self, infile: str) -> List[Dict[str, Any]]:
        with open(infile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

        if self.version == VersionConstants.REFLEC_BEAT:
            # Based on KBR:A:A:A:2011112300
            offset = 0xBFBD0
            stride = 280
            max_songs = 93
            max_difficulties = 3

            song_offset = 0x4C
            song_length = 0x40
            # Artists aren't included in this mix.
            artist_offset = None
            artist_length = None
            chart_offset = 0xD5
            chart_length = 0x20
            difficulties_offset = 0xD2
        elif self.version == VersionConstants.REFLEC_BEAT_LIMELIGHT:
            # Based on LBR:A:A:A:2012082900
            offset = 0x132C48
            stride = 220
            max_songs = 191
            max_difficulties = 3

            song_offset = 0x4C
            song_length = 0x40
            # Artists aren't included in this mix.
            artist_offset = None
            artist_length = None
            chart_offset = 0x9B
            chart_length = 0x20
            difficulties_offset = 0x98
        elif self.version == VersionConstants.REFLEC_BEAT_COLETTE:
            # Based on MBR:J:A:A:2014011600
            offset = 0x1E6880
            stride = 468
            max_songs = 443
            max_difficulties = 3

            song_offset = 0x34
            song_length = 0x80
            artist_offset = 0xB4
            artist_length = 0x80
            chart_offset = 0x1b4
            chart_length = 0x20
            difficulties_offset = 0x1A8
        elif self.version == VersionConstants.REFLEC_BEAT_GROOVIN:
            # Based on MBR:J:A:A:2015102100
            offset = 0x212EC0
            stride = 524
            max_songs = 698
            max_difficulties = 4

            song_offset = 0x3C
            song_length = 0x80
            artist_offset = 0xBC
            artist_length = 0x80
            chart_offset = 0x1E8
            chart_length = 0x20
            difficulties_offset = 0x1D0
        elif self.version == VersionConstants.REFLEC_BEAT_VOLZZA:
            # Based on MBR:J:A:A:2016030200
            offset = 0x1A0EC8
            stride = 552
            max_songs = 805
            max_difficulties = 4

            song_offset = 0x38
            song_length = 0x80
            artist_offset = 0xB8
            artist_length = 0x80
            chart_offset = 0x1E4
            chart_length = 0x20
            difficulties_offset = 0x1CC
        elif self.version == VersionConstants.REFLEC_BEAT_VOLZZA_2:
            # Based on MBR:J:A:A:2016100400
            offset = 0x1CBC68
            stride = 552
            max_songs = 850
            max_difficulties = 4

            song_offset = 0x38
            song_length = 0x80
            artist_offset = 0xB8
            artist_length = 0x80
            chart_offset = 0x1E4
            chart_length = 0x20
            difficulties_offset = 0x1CC
        else:
            raise Exception(f'Unsupported ReflecBeat version {self.version}')

        def convert_string(inb: bytes) -> str:
            end = None
            for i in range(len(inb)):
                if inb[i] == 0:
                    end = i
                    break
            if end is None:
                raise Exception('Invalid string!')
            if end == 0:
                return ''

            return inb[:end].decode('shift_jisx0213')

        def convert_version(songid: int, folder: int) -> int:
            if self.version == VersionConstants.REFLEC_BEAT_VOLZZA_2:
                # Reflec Volzza 2 appears from network and DLL perspective to be identical
                # to Volzza 1, including what version the game thinks it is for songs. So,
                # hard code the new song IDs so we can show the difference on the frontend.
                if folder == 5:
                    if songid in [733, 760, 772, 773, 774, 782, 785, 786]:
                        return 6
                    if songid >= 788:
                        return 6

            return folder

        songs = []
        for i in range(max_songs):
            start = offset + (stride * i)
            end = start + stride
            songdata = data[start:end]

            title = convert_string(songdata[song_offset:(song_offset + song_length)])
            if artist_offset is None:
                artist = ''
            else:
                artist = convert_string(songdata[artist_offset:(artist_offset + artist_length)])
            if title == '' and artist == '':
                continue
            songid = struct.unpack('<I', songdata[0:4])[0]
            chart = convert_string(songdata[chart_offset:(chart_offset + chart_length)])
            difficulties = [d for d in songdata[difficulties_offset:(difficulties_offset + max_difficulties)]]
            difficulties = [0 if d == 255 else d for d in difficulties]
            folder = convert_version(songid, int(chart[0]))

            while len(difficulties) < 4:
                difficulties.append(0)

            songs.append({
                'id': songid,
                'title': title,
                'artist': artist,
                'chartid': chart[:4],
                'difficulties': difficulties,
                'folder': folder,
            })
        return songs

    def lookup(self, server: str, token: str) -> List[Dict[str, Any]]:
        # Grab music info from remote server
        music = self.remote_music(server, token)
        songs = music.get_all_songs(self.game, self.version)
        lut: Dict[int, Dict[str, Any]] = {}
        for song in songs:
            if song.id not in lut:
                lut[song.id] = {
                    'id': song.id,
                    'title': song.name,
                    'artist': song.artist,
                    'chartid': song.data.get_str('chart_id'),
                    'difficulties': [0] * len(self.charts),
                    'folder': song.data.get_int('folder'),
                }
            lut[song.id]['difficulties'][song.chart] = song.data.get_int('difficulty')

        # Return the reassembled data
        return [val for _, val in lut.items()]

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        for song in songs:
            self.start_batch()
            for chart in self.charts:
                songid = song['id']
                chartid = song['chartid']

                # ReflecBeat re-numbers some of their songs and overlaps with IDs from older
                # versions, so we need to keep a virtual mapping similar to DDR. Its not good
                # enough to just do title/artist because Reflec also has revival charts that
                # are named the same. Luckily we have internal chart ID to map on!
                old_id = self.get_music_id_for_song_data(None, None, chartid, chart, version=0)
                if self.no_combine or old_id is None:
                    # Insert original
                    print(f"New entry for {songid} chart {chart}")
                    next_id = self.get_next_music_id()
                else:
                    # Insert pointing at same ID so scores transfer
                    print(f"Reused entry for {songid} chart {chart}")
                    next_id = old_id
                if old_id is None:
                    # Add the virtual music entry we talked about above. Use the song ID when we discover
                    # the song, plus the folder as a way to make them unique.
                    self.insert_music_id_for_song(
                        next_id,
                        self.version * 10000 + songid,
                        chart,
                        song['title'],
                        song['artist'],
                        chartid,  # Chart goes into genre for reflec, so we can handle revival charts
                        {
                            'difficulty': song['difficulties'][chart],
                            'folder': song['folder'],
                            'chart_id': chartid,
                        },
                        version=0,
                    )
                else:
                    if self.update:
                        # Force a folder/difficulty update for this song.
                        self.update_metadata_for_music_id(
                            old_id,
                            song['title'],
                            song['artist'],
                            chartid,  # Chart goes into genre for reflec, so we can handle revival charts
                            {
                                'difficulty': song['difficulties'][chart],
                                'folder': song['folder'],
                                'chart_id': chartid,
                            },
                            version=0,
                        )

                # Add the normal entry so the game finds the song.
                self.insert_music_id_for_song(
                    next_id,
                    songid,
                    chart,
                    song['title'],
                    song['artist'],
                    None,  # Reflec Beat has no genres for real songs.
                    {
                        'difficulty': song['difficulties'][chart],
                        'folder': song['folder'],
                        'chart_id': chartid,
                    },
                )
            self.finish_batch()


class ImportDanceEvolution(ImportBase):

    def __init__(
        self,
        config: Dict[str, Any],
        version: str,
        no_combine: bool,
        update: bool,
    ) -> None:
        if version in ['1']:
            actual_version = 1
        else:
            raise Exception("Unsupported Dance Evolution version, expected one of the following: 1")

        super().__init__(config, GameConstants.DANCE_EVOLUTION, actual_version, no_combine, update)

    def scrape(self, infile: str) -> List[Dict[str, Any]]:
        with open(infile, mode="rb") as myfile:
            data = myfile.read()
            myfile.close()

            arc = ARC(data)
            data = arc.read_file('data/song/song_params.plist')

        # First, do a header check like the game does
        if data[0:4] != b'MS02':
            raise Exception("Invalid song params file!")
        if data[4:6] not in [b'BE', b'LE']:
            raise Exception("Invalid song params file!")

        def get_string(offset: int, default: Optional[str] = None) -> str:
            lut_offset = struct.unpack('>I', data[(offset):(offset + 4)])[0]
            if lut_offset == 0:
                if default is None:
                    raise Exception("Expecting a string, got empty!")
                return default
            length = 0
            while data[lut_offset + length] != 0:
                length += 1
            return data[lut_offset:(lut_offset + length)].decode('utf-8').replace("\n", " ")

        def get_int(offset: int) -> int:
            return struct.unpack('>I', data[(offset):(offset + 4)])[0]

        # Now, make sure we know how long the file is
        numsongs = struct.unpack('>I', data[8:12])[0]
        filelen = struct.unpack('>I', data[12:16])[0]
        if filelen != len(data):
            raise Exception("Invalid song params file!")

        # Now, extract the meaningful data for each song
        retval = []
        for i in range(numsongs):
            offset = (i * 128) + 16

            songcode = get_string(offset + 0)  # noqa: F841
            songres1 = get_string(offset + 4)  # noqa: F841
            songres2 = get_string(offset + 8)  # noqa: F841
            bpm_min = get_int(offset + 12)
            bpm_max = get_int(offset + 16)
            copyright = get_string(offset + 24, "")
            title = get_string(offset + 52, 'Unknown song')
            artist = get_string(offset + 56, 'Unknown artist')
            level = get_int(offset + 64)
            charares1 = get_string(offset + 72)  # noqa: F841
            charares2 = get_string(offset + 76)  # noqa: F841
            kana_sort = get_string(offset + 108)

            flag1 = data[offset + 33] != 0x00  # noqa: F841
            flag2 = data[offset + 34] == 0x01  # noqa: F841
            flag3 = data[offset + 34] == 0x02  # noqa: F841
            flag4 = data[offset + 116] != 0x00  # noqa: F841

            # TODO: Get the real music ID from the data, once we have in-game traffic.
            retval.append({
                'id': i,
                'title': title,
                'artist': artist,
                'copyright': copyright or None,
                'sort_key': kana_sort,
                'bpm_min': bpm_min,
                'bpm_max': bpm_max,
                'level': level,
            })

        return retval

    def lookup(self, server: str, token: str) -> List[Dict[str, Any]]:
        # TODO: We never got far enough to support DanEvo in the server, or
        # specify it in BEMAPI. So this is a dead function for now, but maybe
        # some year in the future I'll be able to support this.
        return []

    def import_music_db(self, songs: List[Dict[str, Any]]) -> None:
        for song in songs:
            # Import it
            self.start_batch()

            # First, try to find in the DB from another version
            old_id = self.get_music_id_for_song(song['id'], 0)
            if self.no_combine or old_id is None:
                # Insert original
                print(f"New entry for {song['id']} chart {0}")
                next_id = self.get_next_music_id()
            else:
                # Insert pointing at same ID so scores transfer
                print(f"Reused entry for {song['id']} chart {0}")
                next_id = old_id
            data = {
                'level': song['level'],
                'bpm_min': song['bpm_min'],
                'bpm_max': song['bpm_max'],
            }
            self.insert_music_id_for_song(next_id, song['id'], 0, song['title'], song['artist'], None, data)
            self.finish_batch()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Import Game Music DB')
    parser.add_argument(
        '--series',
        action='store',
        type=str,
        required=True,
        help='The game series we are importing.',
    )
    parser.add_argument(
        '--version',
        dest='version',
        action='store',
        type=str,
        required=True,
        help='The game version we are importing.',
    )
    parser.add_argument(
        '--csv',
        dest='csv',
        action='store',
        type=str,
        help='The CSV file to read, for applicable games.',
    )
    parser.add_argument(
        '--tsv',
        dest='tsv',
        action='store',
        type=str,
        help='The TSV file to read, for applicable games.',
    )
    parser.add_argument(
        '--xml',
        dest='xml',
        action='store',
        type=str,
        help='The game XML file to read, for applicable games.',
    )
    parser.add_argument(
        '--bin',
        dest='bin',
        action='store',
        type=str,
        help='The game binary file to read, for applicable games.',
    )
    parser.add_argument(
        '--assets',
        dest='assets',
        action='store',
        type=str,
        help='The game sound assets directory, for applicable games.',
    )
    parser.add_argument(
        '--no-combine',
        dest='no_combine',
        action='store_true',
        default=False,
        help='Don\'t look for the same music ID in other versions.',
    )
    parser.add_argument(
        '--update',
        dest='update',
        action='store_true',
        default=False,
        help='Overwrite data with updated values when it already exists.',
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Core configuration for importing to DB. Defaults to 'config.yaml'.",
    )
    parser.add_argument(
        "--server",
        type=str,
        help="The remote BEMAPI server to read data from.",
    )
    parser.add_argument(
        "--token",
        type=str,
        help="The access token to use with the remote BEMAPI server.",
    )

    # Parse args, validate invariants.
    args = parser.parse_args()
    if (args.token and not args.server) or (args.server and not args.token):
        raise Exception("Must specify both --server and --token together!")
    if (args.csv or args.tsv or args.xml or args.bin or args.assets) and (args.server or args.token):
        raise Exception("Cannot specify both a remote server and a local file to read from!")

    # Load the config so we can talk to the server
    config = yaml.safe_load(open(args.config))  # type: ignore

    if args.series == GameConstants.POPN_MUSIC:
        popn = ImportPopn(config, args.version, args.no_combine, args.update)
        if args.bin:
            songs = popn.scrape(args.bin)
        elif args.server and args.token:
            songs = popn.lookup(args.server, args.token)
        else:
            raise Exception(
                'No game DLL provided and no remote server specified! Please ' +
                'provide either a --bin or a --server and --token option!'
            )
        popn.import_music_db(songs)
        popn.close()

    elif args.series == GameConstants.JUBEAT:
        jubeat = ImportJubeat(config, args.version, args.no_combine, args.update)
        if args.tsv is not None:
            # Special case for Jubeat, grab the title/artist metadata that was
            # hand-populated since its not in the music DB.
            jubeat.import_metadata(args.tsv)
        else:
            # Normal case, doing a music DB or emblem import.
            if args.xml is not None:
                songs, emblems = jubeat.scrape(args.xml)
            elif args.server and args.token:
                songs, emblems = jubeat.lookup(args.server, args.token)
            else:
                raise Exception(
                    'No music_info.xml or TSV provided and no remote server specified! Please ' +
                    'provide either a --xml, --tsv or a --server and --token option!'
                )
            jubeat.import_music_db(songs)
            jubeat.import_emblems(emblems)
        jubeat.close()

    elif args.series == GameConstants.IIDX:
        iidx = ImportIIDX(config, args.version, args.no_combine, args.update)
        if args.tsv is not None:
            # Special case for IIDX, grab the title/artist metadata that was
            # wrong in the music DB, and correct it.
            iidx.import_metadata(args.tsv)
        else:
            # Normal case, doing a music DB import.
            if args.bin is not None:
                songs = iidx.scrape(args.bin, args.assets)
            elif args.server and args.token:
                songs = iidx.lookup(args.server, args.token)
            else:
                raise Exception(
                    'No music_data.bin or TSV provided and no remote server specified! Please ' +
                    'provide either a --bin, --tsv or a --server and --token option!'
                )
            iidx.import_music_db(songs)
        iidx.close()

    elif args.series == GameConstants.DDR:
        ddr = ImportDDR(config, args.version, args.no_combine, args.update)
        if args.server and args.token:
            songs = ddr.lookup(args.server, args.token)
        else:
            if args.version == '16':
                if args.bin is None:
                    raise Exception('No startup.arc provided!')
                # DDR Ace has a different format altogether
                songs = ddr.parse_xml(args.bin)
            else:
                if args.bin is None:
                    raise Exception('No game DLL provided!')
                if args.xml is None:
                    raise Exception('No game music XML provided!')
                # DDR splits the music DB between the DLL and external XML
                # (Why??), so we must first scrape then hydrate with extra
                # data to get the full DB.
                songs = ddr.scrape(args.bin)
                songs = ddr.hydrate(songs, args.xml)
        ddr.import_music_db(songs)
        ddr.close()

    elif args.series == GameConstants.SDVX:
        sdvx = ImportSDVX(config, args.version, args.no_combine, args.update)
        if args.server and args.token:
            sdvx.import_from_server(args.server, args.token)
        else:
            if args.xml is None and args.bin is None and args.csv is None:
                raise Exception(
                    'No XML file or game DLL or appeal card CSV provided and ' +
                    'no remote server specified! Please provide either a --xml, ' +
                    '--bin, --csv or a --server and --token option!'
                )
            if args.xml is not None:
                sdvx.import_music_db_or_appeal_cards(args.xml)
            if args.bin is not None:
                sdvx.import_catalog(args.bin)
            if args.csv is not None:
                sdvx.import_appeal_cards(args.csv)
        sdvx.close()

    elif args.series == GameConstants.MUSECA:
        museca = ImportMuseca(config, args.version, args.no_combine, args.update)
        if args.server and args.token:
            museca.import_from_server(args.server, args.token)
        elif args.xml is not None:
            museca.import_music_db(args.xml)
        else:
            raise Exception(
                'No music-info.xml provided and no remote server specified! ' +
                'Please provide either a --xml or a --server and --token option!'
            )
        museca.close()

    elif args.series == GameConstants.REFLEC_BEAT:
        reflec = ImportReflecBeat(config, args.version, args.no_combine, args.update)
        if args.bin is not None:
            songs = reflec.scrape(args.bin)
        elif args.server and args.token:
            songs = reflec.lookup(args.server, args.token)
        else:
            raise Exception(
                'No game DLL provided and no remote server specified! ' +
                'Please provide either a --bin or a --server and --token option!'
            )
        reflec.import_music_db(songs)
        reflec.close()

    elif args.series == GameConstants.DANCE_EVOLUTION:
        danevo = ImportDanceEvolution(config, args.version, args.no_combine, args.update)
        if args.server and args.token:
            songs = danevo.lookup(args.server, args.token)
        elif args.bin is not None:
            songs = danevo.scrape(args.bin)
        else:
            raise Exception(
                'No resource_lists.arc provided and no remote server ' +
                'specified! Please provide either a --bin or a ' +
                '--server and --token option!',
            )
        danevo.import_music_db(songs)
        danevo.close()

    else:
        raise Exception('Unsupported game series!')
