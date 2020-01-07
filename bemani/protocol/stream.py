import struct
from typing import List, Optional


class StreamError(Exception):
    """
    An exception thrown when something goes wrong with the stream.
    """


class InputStream:
    """
    A class that treats a binary blob as a stream of bytes to be emitted.
    Makes stream-like algorithms much easier to implement. All accessor
    functions that read data will advance the current position. It is not
    rewindable.
    """

    def __init__(self, data: bytes) -> None:
        """
        Initialize the object. Given a data blob, will set this as the stream
        and set the location to the beginning of the data blob.

        Parameters:
            data - A binary blob to read from.
        """
        self.data = data
        self.pos = 0
        self.left = len(self.data)

    def read_blob(self, blob_size: int) -> Optional[bytes]:
        """
        Given a blob size, read the next blob_size bytes as a binary blob.

        Parameters:
            blob_size - An integer representing the number of bytes to read.

        Returns:
            a binary string representing blob_size bytes from the current location, or None
            if there wasn't enough bytes to satisfy this request.
        """
        if blob_size <= 0:
            return None
        if blob_size <= self.left:
            bytedata = self.data[self.pos:(self.pos + blob_size)]
            self.pos += blob_size
            self.left -= blob_size
            return bytedata
        return None

    def read_byte(self) -> bytes:
        """
        Grab the next byte at the current position. If no byte is available,
        return None.

        Returns:
            a raw byte
        """
        return self.read_blob(1)

    def read_int(self, size: int=1, is_unsigned: bool=True) -> int:
        """
        Grab the next integer of size 'size' at the current position. If not enough
        bytes are available to decode this integer, return None.

        Parameters:
            size - Integer representing the integer size to decode. Valid values are
                   1, 2 and 4 for char, short and int respectively.
            is_unsigned - An optional boolean specifying whether the integer read should be
                          unsigned. Defaults to True.

        Returns:
            a python integer representing the big-endian decoding of the current
            position
        """
        if size == 1:
            data = self.read_blob(1)
            if data is None:
                return None

            if is_unsigned:
                # Fastpath, just use python's own decoder
                return data[0]
            else:
                return struct.unpack('>b', data)[0]
        elif size == 2:
            data = self.read_blob(2)
            if data is None:
                return None

            if is_unsigned:
                return struct.unpack('>H', data)[0]
            else:
                return struct.unpack('>h', data)[0]
        elif size == 4:
            data = self.read_blob(4)
            if data is None:
                return None

            if is_unsigned:
                return struct.unpack('>I', data)[0]
            else:
                return struct.unpack('>i', data)[0]
        else:
            raise StreamError(f'Unsupported size {size}')


class OutputStream:
    """
    A class that treats a binary blob as a stream of bytes to be constructed.
    Makes stream-like algorithms much easier to implement. All accessor
    functions that write data will advance the current position. It is not
    rewindable. When finished writing, access the finished blob by copying from
    data.
    """

    def __init__(self) -> None:
        """
        Initialize the object.
        """
        self.__data: List[bytes] = []
        self.__data_len = 0
        self.__formatted_data: Optional[bytes] = None

    @property
    def data(self) -> bytes:
        if self.__formatted_data is None:
            self.__formatted_data = b''.join(self.__data)
        return self.__formatted_data

    def write_byte(self, byte: bytes) -> None:
        """
        Write a raw byte to the end of the output stream.

        Parameters:
            A byte that should be appended to the current stream.
        """
        self.__data.append(byte)
        self.__data_len = self.__data_len + 1
        self.__formatted_data = None

    def write_int(self, integer: int, size: int=1, is_unsigned: bool=True) -> None:
        """
        Write an integer to the end of the output stream.

        Parameters:
            integer - The integer that should be written to the stream.
            size - The byte size of the integer. Supports 1, 2 and 4 byte
                   integer types.
            is_unsigned - Whether the integer should be written unsigned or
                         signed. Defaults to True.
        """
        if size == 1:
            if is_unsigned:
                self.__data.append(struct.pack('>B', integer))
            else:
                self.__data.append(struct.pack('>b', integer))
            self.__data_len = self.__data_len + 1
        elif size == 2:
            if is_unsigned:
                self.__data.append(struct.pack('>H', integer))
            else:
                self.__data.append(struct.pack('>h', integer))
            self.__data_len = self.__data_len + 2
        elif size == 4:
            if is_unsigned:
                self.__data.append(struct.pack('>I', integer))
            else:
                self.__data.append(struct.pack('>i', integer))
            self.__data_len = self.__data_len + 4
        else:
            raise StreamError(f'Unsupported size {size}')
        self.__formatted_data = None

    def write_pad(self, pad_to: int) -> None:
        """
        Pad the current stream to a byte boundary specified by pad_to.

        Parameters:
            pad_to - An integer specifying the byte alignment that should be present
            after padding is complete. Supports 1, 2, 4, 8, 16 or any other power of
            two padding. After calling this, the next write_byte or write_int will
            be placed on a boundary compatible with the pad_to parameter.
        """
        while (self.__data_len & (pad_to - 1)) != 0:
            self.__data.append(b'\0')
            self.__data_len = self.__data_len + 1
        self.__formatted_data = None
