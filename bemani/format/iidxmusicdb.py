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
        For IIDX 27 and above, there are 4 additional charts in the difficulties list for
        B7, L7, B14 and L14.
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
        self.__version = self.__parse_db(data)

    def get_new_db(self) -> bytes:
        # Write out a new music DB based on any possible changes to songs
        data = copy.deepcopy(self.__data)

        def format_string(string: str) -> bytes:
            bdata = string.encode("shift-jis")
            if len(bdata) < 64:
                bdata = bdata + (b"\0" * (64 - len(bdata)))
            return bdata

        def copy_over(dst: bytes, src: bytes, base: int, offset: int) -> bytes:
            return dst[: (base + offset)] + src + dst[(base + offset + len(src)) :]

        for mid in self.__songs:
            song, offset = self.__songs[mid]
            data = copy_over(data, format_string(song.title), offset, 0)
            data = copy_over(data, format_string(song.english_title), offset, 64)
            data = copy_over(data, format_string(song.genre), offset, 128)
            data = copy_over(data, format_string(song.artist), offset, 192)
            data = copy_over(data, bytes([song.folder]), offset, 280)
            if self.__version < 27:
                # This is easy.
                data = copy_over(data, bytes(song.difficulties), offset, 288)
            elif self.__version >= 27:
                # This is gross, but I'm too lazy to do it right.
                data = copy_over(data, bytes([song.difficulties[6]]), offset, 288)
                data = copy_over(data, bytes(song.difficulties[0:3]), offset, 289)
                data = copy_over(data, bytes(song.difficulties[7:9]), offset, 292)
                data = copy_over(data, bytes(song.difficulties[3:6]), offset, 294)
                data = copy_over(data, bytes([song.difficulties[9]]), offset, 297)

        return data

    def __parse_string(self, string: bytes) -> str:
        for i in range(len(string)):
            if string[i] == 0:
                string = string[:i]
                break

        return string.decode("shift-jis")

    def __parse_db(self, data: bytes) -> int:
        # Verify the signature
        magic, gameversion, songcount, indexcount = struct.unpack_from(
            "<4sBxxxHHxxxx",
            data,
            0,
        )

        if magic != b"IIDX":
            raise Exception(f"Invalid signature '{magic}' found!")

        # Stride lookup, which appears unfortunately hardcoded in the game DLL.
        leap = {
            20: 0x320,
            21: 0x320,
            22: 0x340,
            23: 0x340,
            24: 0x340,
            25: 0x340,
            26: 0x344,
            27: 0x52C,
            28: 0x52C,
        }.get(gameversion)
        if leap is None:
            raise Exception(f"Unsupported game version {gameversion} found!")

        # Skip past index nodes, which are all 16-bit integers, and past 16 byte header.
        offset = (indexcount * 2) + 0x10

        # Load songs
        for songid in range(songcount):
            songoffset = offset + (songid * leap)
            if gameversion < 27:
                songdata = struct.unpack_from(
                    "<64s64s64s64s24xB7xBBBBBB162xH",
                    data,
                    songoffset,
                )
                song = IIDXSong(
                    songid=songdata[11],
                    title=self.__parse_string(songdata[0]),
                    english_title=self.__parse_string(songdata[1]),
                    genre=self.__parse_string(songdata[2]),
                    artist=self.__parse_string(songdata[3]),
                    difficulties=[
                        songdata[5],
                        songdata[6],
                        songdata[7],
                        songdata[8],
                        songdata[9],
                        songdata[10],
                    ],
                    folder=songdata[4],
                )
            elif gameversion >= 27:
                # Heroic Verse and above have a completely different structure for song entries
                songdata = struct.unpack_from(
                    "<64s64s64s64s24xB7x10B646xH",
                    data,
                    songoffset,
                )
                song = IIDXSong(
                    songid=songdata[15],
                    title=self.__parse_string(songdata[0]),
                    english_title=self.__parse_string(songdata[1]),
                    genre=self.__parse_string(songdata[2]),
                    artist=self.__parse_string(songdata[3]),
                    difficulties=[
                        songdata[6],
                        songdata[7],
                        songdata[8],
                        songdata[11],
                        songdata[12],
                        songdata[13],
                        songdata[5],
                        songdata[9],
                        songdata[10],
                        songdata[14],
                    ],
                    folder=songdata[4],
                )

            if song.artist == "event_data" and song.genre == "event_data":
                continue

            self.__songs[song.id] = (song, songoffset)

        return gameversion

    @property
    def songs(self) -> List[IIDXSong]:
        return sorted(
            [self.__songs[mid][0] for mid in self.__songs], key=lambda song: song.id
        )

    @property
    def songids(self) -> List[int]:
        return sorted([mid for mid in self.__songs])

    def song(self, songid: int) -> IIDXSong:
        return self.__songs[songid][0]
