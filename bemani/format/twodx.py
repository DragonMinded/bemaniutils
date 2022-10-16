import struct
from typing import Dict, List, Optional


class TwoDX:
    """
    Packer/unpacker class for a bytestream representing a `.2dx` file.
    """

    def __init__(self, data: Optional[bytes] = None) -> None:
        self.__name: Optional[str] = None
        self.__files: Dict[str, bytes] = {}
        if data is not None:
            self.__parse_file(data)

    def __parse_file(self, data: bytes) -> None:
        # Parse file header
        (name, headerSize, numfiles) = struct.unpack("<16sII", data[0:24])
        self.__name = name.split(b"\x00")[0].decode("ascii")

        if headerSize != (72 + (4 * numfiles)):
            raise Exception("Unrecognized 2dx file header!")

        fileoffsets = struct.unpack(
            "<" + "".join(["I" for _ in range(numfiles)]),
            data[72 : (72 + (4 * numfiles))],
        )
        fileno = 1

        for offset in fileoffsets:
            (
                magic,
                headerSize,
                wavSize,
                _,
                track,
                _,
                attenuation,
                loop,
            ) = struct.unpack(
                "<4sIIhhhhi",
                data[offset : (offset + 24)],
            )

            if magic != b"2DX9":
                raise Exception("Unrecognized entry in file!")
            if headerSize != 24:
                raise Exception("Unrecognized subheader in file!")

            wavOffset = offset + headerSize
            wavData = data[wavOffset : (wavOffset + wavSize)]

            self.__files[f"{self.__name}_{fileno}.wav"] = wavData
            fileno = fileno + 1

    @property
    def name(self) -> str:
        if self.__name is None:
            raise Exception(
                "Logic error, tried to get name of 2dx file before setting it or parsing file!"
            )
        return self.__name

    def set_name(self, name: str) -> None:
        if len(name) <= 16:
            self.__name = name
        else:
            raise Exception("Name of archive too long!")

    @property
    def filenames(self) -> List[str]:
        return [f for f in self.__files]

    def read_file(self, filename: str) -> bytes:
        return self.__files[filename]

    def write_file(self, filename: str, data: bytes) -> None:
        self.__files[filename] = data

    def get_new_data(self) -> bytes:
        if not self.__files:
            raise Exception("No files to write!")
        if not self.__name:
            raise Exception("2dx archive name not set!")

        name = self.__name.encode("ascii")
        while len(name) < 16:
            name = name + b"\x00"
        filedata = [self.__files[x] for x in self.__files]

        # Header length is also the base offset for the first file
        baseoffset = 72 + (4 * len(filedata))
        data = [struct.pack("<16sII", name, baseoffset, len(filedata)) + (b"\x00" * 48)]

        # Calculate offset this will go to
        for bytedata in filedata:
            # Add where this file will go, then calculate the length
            data.append(struct.pack("<I", baseoffset))
            baseoffset = baseoffset + 24 + len(bytedata)

        # Now output the headers and files
        for bytedata in filedata:
            data.append(
                struct.pack(
                    "<4sIIhhhhi",
                    b"2DX9",
                    24,
                    len(bytedata),
                    0x3231,
                    -1,
                    64,
                    1,
                    0,
                )
            )
            data.append(bytedata)

        return b"".join(data)
