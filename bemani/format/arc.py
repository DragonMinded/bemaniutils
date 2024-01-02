import struct
from typing import Dict, List, Tuple

from bemani.protocol.lz77 import Lz77


class ARC:
    """
    Class representing an `.arc` file. These are found in DDR Ace, and possibly
    other games that use ESS. Given a serires of bytes, this will allow you to
    query included filenames as well as read the contents of any file inside the
    archive.
    """

    def __init__(self, data: bytes) -> None:
        self.__files: Dict[str, Tuple[int, int, int]] = {}
        self.__data = data
        self.__parse_file(data)

    def __parse_file(self, data: bytes) -> None:
        # Check file header
        if data[0:4] != bytes([0x20, 0x11, 0x75, 0x19]):
            raise Exception("Unknown file format!")

        # Grab header offsets
        (_, numfiles, _) = struct.unpack("<III", data[4:16])

        for fno in range(numfiles):
            start = 16 + (16 * fno)
            end = start + 16
            (nameoffset, fileoffset, uncompressedsize, compressedsize) = struct.unpack("<IIII", data[start:end])
            name = ""

            while data[nameoffset] != 0:
                name = name + data[nameoffset : (nameoffset + 1)].decode("ascii")
                nameoffset = nameoffset + 1

            self.__files[name] = (fileoffset, uncompressedsize, compressedsize)

    @property
    def filenames(self) -> List[str]:
        return [f for f in self.__files]

    def read_file(self, filename: str) -> bytes:
        (fileoffset, uncompressedsize, compressedsize) = self.__files[filename]

        if compressedsize == uncompressedsize:
            # Just stored
            return self.__data[fileoffset : (fileoffset + compressedsize)]
        else:
            # Compressed
            lz77 = Lz77()
            return lz77.decompress(self.__data[fileoffset : (fileoffset + compressedsize)])
