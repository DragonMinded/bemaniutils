import copy
import struct
from typing import Dict, List, Tuple


class IIDXSong:
    def __init__(
        self,
        songid: int,
        title: str,
        english_title: str,
        genre: str,
        artist: str,
        difficulties: List[int],
        folder: int,
    ) -> None:
        """
        Initialize a IIDX Song. Everything is self-explanatory except difficulties, which
        is a list of integers representing the difficulty for SPN, SPH, SPA, DPN, DPH, DPA.
        """
        self.id = songid
        self.title = title
        self.english_title = english_title
        self.genre = genre
        self.artist = artist
        self.difficulties = difficulties
        self.folder = folder


class IIDXMusicDB:

    def __init__(self, data: bytes) -> None:
        self.__songs: Dict[int, Tuple[IIDXSong, int]] = {}
        self.__data = data
        self.__parse_db(data)

    def get_new_db(self) -> bytes:
        # Write out a new music DB based on any possible changes to songs
        data = copy.deepcopy(self.__data)

        def format_string(string: str) -> bytes:
            bdata = string.encode('shift-jis')
            if len(bdata) < 64:
                bdata = bdata + (b'\0' * (64 - len(bdata)))
            return bdata

        def copy_over(dst: bytes, src: bytes, base: int, offset: int) -> bytes:
            return dst[:(base + offset)] + src + dst[(base + offset + len(src)):]

        for mid in self.__songs:
            song, offset = self.__songs[mid]
            data = copy_over(data, format_string(song.title), offset, 0)
            data = copy_over(data, format_string(song.english_title), offset, 64)
            data = copy_over(data, format_string(song.genre), offset, 128)
            data = copy_over(data, format_string(song.artist), offset, 192)
            data = copy_over(data, bytes([song.folder]), offset, 280)
            data = copy_over(data, bytes(song.difficulties), offset, 288)
        return data

    def __parse_db(self, data: bytes) -> None:
        # Verify the signature
        sig = struct.unpack_from(
            "<4s",
            data,
            0,
        )
        # Offset and difference lookup (not sure this is always right)
        if data[4] == 0x14:
            offset = 0xa420
            leap = 0x320
        elif data[4] == 0x15:
            offset = 0xabf0
            leap = 0x320
        elif data[4] == 0x16:
            offset = 0xb3c0
            leap = 0x340
        elif data[4] == 0x17:
            offset = 0xbb90
            leap = 0x340
        elif data[4] == 0x18:
            offset = 0xc360
            leap = 0x340
        elif data[4] == 0x19:
            offset = 0xCB30
            leap = 0x340
        elif data[4] == 0x1A:
            offset = 0xD300
            leap = 0x344
        elif data[4] == 0x1B:
            offset = 0xDAD0
            leap = 0x52C
        elif data[4] == 0x1C:
            offset = 0xE2A0
            leap = 0x52C

        if sig[0] != b'IIDX':
            raise Exception(f'Invalid signature \'{sig[0]}\' found!')

        def parse_string(string: bytes) -> str:
            for i in range(len(string)):
                if string[i] == 0:
                    string = string[:i]
                    break

            return string.decode('shift-jis')

        # Load songs
        while True:
            try:
                if data[4] < 0x1B:
                    songdata = struct.unpack_from(
                        "<64s64s64s64s24xB7x6B162xH",
                        data,
                        offset,
                    )
                else:
                    # Heroic Verse and above have a completely different structure for song entries
                    songdata = struct.unpack_from(
                        "<64s64s64s64s24xB7x10B646xH",
                        data,
                        offset,
                    )
            except struct.error:
                # Out of input!
                break

            songoffset = offset
            offset = offset + leap
            if data[4] < 0x1B:
                song = IIDXSong(
                    songdata[11],
                    parse_string(songdata[0]),
                    parse_string(songdata[1]),
                    parse_string(songdata[2]),
                    parse_string(songdata[3]),
                    [songdata[5], songdata[6], songdata[7], songdata[8], songdata[9], songdata[10]],
                    songdata[4],
                )
            else:
                song = IIDXSong(
                    songdata[15],
                    parse_string(songdata[0]),
                    parse_string(songdata[1]),
                    parse_string(songdata[2]),
                    parse_string(songdata[3]),
                    [songdata[6], songdata[7], songdata[8], songdata[11], songdata[12], songdata[13], songdata[5], songdata[9], songdata[10], songdata[14]],
                    songdata[4],
                )
            if song.artist == 'event_data' and song.genre == 'event_data':
                continue
            if data[4] < 0x1B:
                self.__songs[songdata[11]] = (song, songoffset)
            else:
                self.__songs[songdata[15]] = (song, songoffset)

    @property
    def songs(self) -> List[IIDXSong]:
        return sorted([self.__songs[mid][0] for mid in self.__songs], key=lambda song: song.id)

    @property
    def songids(self) -> List[int]:
        return sorted([mid for mid in self.__songs])

    def song(self, songid: int) -> IIDXSong:
        return self.__songs[songid][0]
