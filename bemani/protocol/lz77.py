import ctypes
import os
from collections import defaultdict
from typing import Generator, List, MutableMapping, Optional, Set, Tuple


# Attempt to use the faster C++ libraries if they're available
try:
    clib = None
    clib_path = os.path.dirname(os.path.abspath(__file__))
    files = [f for f in os.listdir(clib_path) if f.startswith("lz77alt") and f.endswith(".so")]
    if len(files) > 0:
        clib = ctypes.cdll.LoadLibrary(os.path.join(clib_path, files[0]))
        clib.decompress.argtypes = (ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
        clib.decompress.restype = ctypes.c_int
except Exception:
    clib = None


class LzException(Exception):
    """
    An exception thrown when we encounter an error with Lz77 encoding/decoding.
    """


class Lz77Decompress:
    """
    A class that can decompress an Lz77 stream of data. Notably, this is a different
    variant to the Lz77 found in firebeat executables and BIOS. This is used for
    over-the-wire compression of XML data, as well as compression inside a decent
    amount of file formats found in various Konami games.
    """
    RING_LENGTH = 0x1000

    FLAG_COPY = 1
    FLAG_BACKREF = 0

    def __init__(self, data: bytes, backref: Optional[int] = None) -> None:
        """
        Initialize the object.

        Parameters:
            data - Binary blob representing the data to be decompressed.
        """
        self.eof: bool = False
        self.data: bytes = data
        self.read_pos: int = 0
        self.left: int = len(self.data)
        self.flags: int = 1
        self.write_pos: int = 0
        self.pending_copy_amount: int = 0
        self.pending_copy_pos: int = 0
        self.pending_copy_max: int = 0
        self.ringlength: int = backref or self.RING_LENGTH
        self.ring: bytes = b'\x00' * self.ringlength

    def __ring_read(self, copy_pos: int, copy_len: int) -> Generator[bytes, None, None]:
        """
        Read the next bytes from the backref ring at the current copy position.

        Returns:
            a generator which yields bytes.
        """
        while copy_len > 0:
            if copy_pos + copy_len > self.ringlength:
                # Copy first chunk, let subsequent loop handle the next chunks
                amount = self.ringlength - copy_pos
            else:
                # Copy the whole thing out, we have enough space to do so
                amount = copy_len

            ret = self.ring[copy_pos:(copy_pos + amount)]
            self.__ring_write(ret)
            yield ret

            copy_pos = (copy_pos + amount) % self.ringlength
            copy_len -= amount

    def __ring_write(self, bytedata: bytes) -> None:
        """
        Write bytes into the backref ring.

        Parameters:
            byte - A byte to be written at the current write offset
        """
        while True:
            amount = len(bytedata)
            if amount == 0:
                return
            if amount > (self.ringlength - self.write_pos):
                amount = self.ringlength - self.write_pos

            self.ring = self.ring[:self.write_pos] + bytedata[:amount] + self.ring[(self.write_pos + amount):]
            bytedata = bytedata[amount:]
            self.write_pos = (self.write_pos + amount) % self.ringlength

    def decompress_bytes(self) -> Generator[bytes, None, None]:
        """
        Yield the next byte from the decompressed output. If we are
        in a backref copy, read the next byte from the backref. If
        we aren't, read the next flag to see if we should decode
        a byte directly or if we should start another backref read.
        If we don't have any flags, exit reporting EOF (None). If
        we hit the end of the stream, stop yielding to signify EOF.
        In all cases, whatever byte we read should be added back to
        the backref buffer.

        Returns:
            a generator that yields bytes.
        """
        while not self.eof:
            if self.pending_copy_amount > 0:
                # We had a backref that would have copied more data than we had available
                # in the ringbuffer (because every read, even a backref, adds to the
                # ringbuffer). So, since we read that last time and wrote it to the backbuffer
                # we are safe to read again.
                amount = min(self.pending_copy_amount, self.pending_copy_max)
                yield from self.__ring_read(self.pending_copy_pos, amount)

                # We read this many bytes and are about to write them to the ringbuffer,
                # so bookkeep that.
                self.pending_copy_amount -= amount
                self.pending_copy_max = amount
            else:
                if self.flags == 1:
                    # Load the next byte for processing
                    if self.left == 0:
                        # We have nothing left to read, so skip the
                        # ringbuffer write below and exit early.
                        return
                    else:
                        self.flags = 0x100 | self.data[self.read_pos]
                        self.read_pos += 1
                        self.left -= 1

                # Shift the lowest bit out to be retrieved as a flag
                flag = self.flags & 1
                self.flags >>= 1

                if flag == self.FLAG_COPY:
                    # Figure out how much to pull at once
                    amount = 1
                    while self.flags != 1 and (self.flags & 1) == self.FLAG_COPY:
                        # We would do a copy next time, so pop that flag and just add to our read amount
                        self.flags >>= 1
                        amount += 1

                    # Grab chunk right out of the data source
                    b = self.data[self.read_pos:(self.read_pos + amount)]
                    self.__ring_write(b)
                    yield b

                    self.read_pos += amount
                    self.left -= amount
                elif flag == self.FLAG_BACKREF:
                    yield from self.__read_backref()
                else:
                    raise Exception("Logic error!")

    def __read_backref(self) -> Generator[bytes, None, None]:
        """
        Read a backref chunk. Grab the copy length and copy position
        from the first two bytes and then read the first byte from
        the backref. Sets up variables such that Lz77Decompress.__read()
        can finish copying out of the backref on subsequent calls. Should
        only be called by Lz77Decompress.__read(). If we discover the end
        of stream, we don't generate any bytes and instead set the eof
        flag which terminates the main decompression loop above.

        Returns:
            a generator that yields bytes.
        """
        if self.left == 0:
            self.eof = True
            return
        if self.left == 1:
            raise LzException('Unexpected EOF mid-backref')

        hi = self.data[self.read_pos]
        lo = self.data[self.read_pos + 1]
        self.read_pos += 2
        self.left -= 2

        copy_len = lo & 0xF
        copy_pos = (hi << 4) | (lo >> 4)

        if copy_pos > 0:
            copy_len += 3
            if copy_len > copy_pos:
                # Remember what we have to do left, and the safe
                # amount to copy next time (which is our length,
                # since we are about to write that many butes to
                # the ringbuffer right after reading them).
                self.pending_copy_amount = copy_len - copy_pos
                self.pending_copy_pos = self.write_pos
                self.pending_copy_max = copy_pos

                # Only copy the available bytes
                copy_len = copy_pos

            copy_pos = (self.write_pos - copy_pos)
            while copy_pos < 0:
                copy_pos += self.ringlength
            copy_pos = copy_pos % self.ringlength
            yield from self.__ring_read(copy_pos, copy_len)
        else:
            self.eof = True
            return


class Lz77Compress:
    """
    A class that can compress arbitrary binary data using the Lz77 protocol.
    Note that this does support overlapped backtracks, so for instance the
    string "abcabcabc" will be compressed properly (see unit tests for examples).
    Great care has been taken in optimizing this and then we further optimize
    by using Cython to build, netting us another 40% speed-up. This is important
    because for any given packet we are decompressing and compressing at least
    once, and if we use a proxy to direct traffic, possibly a second time.
    """

    RING_LENGTH = 0x1000

    LOOSE_COMPRESS_THRESHOLD = 1024 * 512

    FLAG_COPY = 1
    FLAG_BACKREF = 0

    def __init__(self, data: bytes, backref: Optional[int] = None) -> None:
        """
        Initialize the object.

        Parameters:
            data - Binary blob representing the data to be decompressed.
        """
        self.data: bytes = data
        self.read_pos: int = 0
        self.left: int = len(self.data)
        self.eof: bool = False
        self.bytes_written: int = 0
        self.ringlength: int = backref or self.RING_LENGTH
        self.locations: MutableMapping[int, Set[int]] = defaultdict(set)
        self.starts: MutableMapping[bytes, Set[int]] = defaultdict(set)
        self.last_start: Tuple[int, int, int] = (0, 0, 0)

        if len(data) > self.LOOSE_COMPRESS_THRESHOLD:
            self.__ring_write = self.__ring_write_starts_only
        else:
            self.__ring_write = self.__ring_write_both

    def __ring_write_starts_only(self, bytedata: bytes) -> None:
        """
        Write bytes into the backref ring.

        Parameters:
            byte - A byte to be written at the current write offset
        """
        for byte in bytedata:
            # Update the start locations hashmap if we're past the beginning
            self.last_start = (self.last_start[1], self.last_start[2], byte)
            if self.bytes_written >= 2:
                self.starts[bytes(self.last_start)].add(self.bytes_written - 2)

            # Keep track of the fact that we wrote this byte.
            self.bytes_written += 1

    def __ring_write_both(self, bytedata: bytes) -> None:
        """
        Write bytes into the backref ring.

        Parameters:
            byte - A byte to be written at the current write offset
        """
        for byte in bytedata:
            # Update the start locations hashmap if we're past the beginning
            self.last_start = (self.last_start[1], self.last_start[2], byte)
            if self.bytes_written >= 2:
                self.starts[bytes(self.last_start)].add(self.bytes_written - 2)

            # Update the rest of the location hashmaps
            self.locations[byte].add(self.bytes_written)

            # Keep track of the fact that we wrote this byte.
            self.bytes_written += 1

    def compress_bytes(self) -> Generator[bytes, None, None]:
        """
        Given the current stream, go through and assemble the next flag byte
        followed by the next chunk of compressed data.
        """
        while not self.eof:
            if self.left == 0:
                # Output a dummy flag and an end of stream marker.
                self.eof = True
                yield b"\x00\x00\x00"
            else:
                # Need to assemble and return the next chunk, which is a flag
                # byte and then 8 instructions.
                flags = 0x0
                flagpos = -1
                data: List[bytes] = [b""] * 8

                for _ in range(8):
                    # Track what flag we're generating data for
                    flagpos += 1

                    if self.left == 0:
                        # Output the end of stream marker, set EOF since we've succeeded
                        # in outputting all flags.
                        flags |= self.FLAG_BACKREF << flagpos
                        data[flagpos] = b"\x00\x00"
                        self.eof = True
                        break
                    elif self.left < 3 or self.bytes_written < 3:
                        # We either don't have enough data written to backref, or we
                        # don't have enough data in the stream that could be made into
                        # a backref.
                        flags |= self.FLAG_COPY << flagpos

                        chunk = self.data[self.read_pos:(self.read_pos + 1)]
                        data[flagpos] = chunk
                        self.__ring_write(chunk)

                        self.read_pos += 1
                        self.left -= 1
                        continue

                    # Figure out the maximum backref we can attempt to find
                    backref_amount = min(self.left, 18)

                    # Iterate over all spots where the first byte equals, and is in range.
                    earliest = max(0, self.bytes_written - (self.ringlength - 1))
                    index = self.data[self.read_pos:(self.read_pos + 3)]
                    updated_backref_locations: Set[int] = set(
                        absolute_pos for absolute_pos in self.starts[index]
                        if absolute_pos >= earliest
                    )
                    self.starts[index] = updated_backref_locations
                    possible_backref_locations: List[int] = list(updated_backref_locations)

                    # Output the data as a copy if we couldn't find a backref
                    if not possible_backref_locations:
                        flags |= self.FLAG_COPY << flagpos

                        chunk = self.data[self.read_pos:(self.read_pos + 1)]
                        data[flagpos] = chunk
                        self.__ring_write(chunk)

                        self.read_pos += 1
                        self.left -= 1
                        continue

                    # Now, find the longest actual backref of our possibilities. We know
                    # we're going to write at least these three bytes, so append it to the
                    # output buffer.
                    start_write_size = self.bytes_written
                    self.__ring_write(index)
                    copy_amount = 3
                    while copy_amount < (backref_amount):
                        # First, let's see if we have any 3-wide chunks to consume.
                        index = self.data[(self.read_pos + copy_amount):(self.read_pos + copy_amount + 3)]
                        locations = self.starts[index]
                        new_backref_locations: List[int] = [
                            absolute_pos for absolute_pos in possible_backref_locations
                            if absolute_pos + copy_amount in locations
                        ]

                        if new_backref_locations:
                            # Mark that we're copying an extra byte from the backref.
                            self.__ring_write(index)
                            copy_amount += 3
                            possible_backref_locations = new_backref_locations
                        else:
                            # Check our existing locations to figure out if we still have
                            # longest prefixes of 1 or 2 left.
                            locations = self.locations[self.data[self.read_pos + copy_amount]]
                            new_backref_locations = [
                                absolute_pos for absolute_pos in possible_backref_locations
                                if absolute_pos + copy_amount in locations
                            ]

                            # If we have no longest prefixes, that means that any of the
                            # previous prefixes are good enough.
                            if not new_backref_locations:
                                break

                            # Mark that we're copying an extra byte from the backref.
                            self.__ring_write(self.data[(self.read_pos + copy_amount):(self.read_pos + copy_amount + 1)])
                            copy_amount += 1
                            possible_backref_locations = new_backref_locations

                    # Now that we have a list of candidates, arbitrarily pick the
                    # first one as our candidate and output it.
                    absolute_pos = possible_backref_locations[0]
                    backref_pos = start_write_size - absolute_pos

                    lo = (copy_amount - 3) & 0xF | ((backref_pos & 0xF) << 4)
                    hi = (backref_pos >> 4) & 0xFF
                    flags |= self.FLAG_BACKREF << flagpos
                    data[flagpos] = bytes([hi, lo])
                    self.read_pos += copy_amount
                    self.left -= copy_amount

                yield bytes([flags]) + b"".join(data)


class Lz77:
    """
    A wrapper class encapsulating Lz77 encoding and decoding.
    """

    # The point at which we consider it better to trade off smaller data
    # sent over the wire for a more computationally expensive compression.
    REAL_COMPRESSION_THRESHOLD = 10 * 1024

    def __init__(self, backref: Optional[int] = None) -> None:
        """
        Initialize the object.
        """
        self.backref = backref

    def decompress(self, data: bytes) -> bytes:
        """
        Given a binary blob, return a new binary blob representing the decompressed data.

        Parameters:
            data - Lz77-compressed binary data

        Returns:
            Raw binary data.
        """
        if clib is not None:
            # Given a maximum backref length of 18, if we had a file that was
            # only backrefs of maximum size. We would get a compression of around
            # (18 * 8) / (2 * 8 + 1), or 8.47. So, allocate 9 times in the output
            # buffer.
            outbuf = b"\0" * (len(data) * 9)
            result = clib.decompress(data, len(data), outbuf, len(outbuf))
            if result >= 0:
                return outbuf[:result]
            elif result == -1:
                raise LzException("Not enough room in output buffer!")
            elif result == -2:
                raise LzException("Unexpected EOF during decompression!")
            elif result == -3:
                raise LzException("Not enough room to write output byte!")
            else:
                raise LzException("Unknown exception in C++ code!")
        else:
            lz = Lz77Decompress(data, backref=self.backref)
            return b''.join(lz.decompress_bytes())

    def compress(self, data: bytes) -> bytes:
        """
        Given a binary blob, return a new binary blob representing the compressed data.

        Parameters:
            data - Raw binary data.

        Returns:
            L7zz-compressed binary data.
        """
        lz = Lz77Compress(data, backref=self.backref)
        return b''.join(lz.compress_bytes())
