import struct
from typing import Optional, List, Dict, Any
from typing_extensions import Final

from bemani.protocol.stream import InputStream, OutputStream
from bemani.protocol.node import Node


class BinaryEncodingException(Exception):
    """
    Generic exception to be thrown when we encounter an issue decoding a binary stream
    """


class PackedOrdering:
    """
    A class that helps us encapsulate Konami's batshit backtracking hole-fill algorithm.
    Everything is aligned on a boundary appropriate for its data size. Strings and arrays are
    forced to be aligned to a 4 byte boundary on account of having an integer length field.
    All of these are padded to 4 bytes in terms of the room they take up in the stream.
    For the things that are 2 byte or 1 byte aligned, we end up sticking them after each other
    in 4 byte increments. That is, to say, if we have a unsigned byte to pack, we reserve 4 bytes
    and stick it in the first byte slot, and if up to three additional bytes come in we will pack
    them after this in sequential order. It would make sense to not pad out strings and arrays and
    store bytes/shorts in these unused locations, but that's not what actually happens. Also note
    that we will never pack bytes after a short or vice versa, even if there is room. This also explains
    the bizarre behavior of not using spare bytes after strings or arrays. I'll emphasize again:
    everything is stored aligned, and in a 4 byte chunk, only similarly-sized objects can be packed. If
    this 4 byte chunk is already partially occupied, we can only add another thing to it if 1) the
    item being added is the same size as the object that exists and 2) the object can be added with
    the correct alignment.

    A simple example:
        [1: byte] [2: byte] [3: integer]
    Packing would look like this (assuming all locations are a byte):
        1 2 0 0 3 3 3 3

    An example:
        [1: byte] [2: string, length 3] [3: short] [4: byte]
    Packing would look like this (assuming all locations are a byte):
        1 4 0 0 2 2 2 2 2 2 2 0 3 3 0 0
    """

    def __init__(self, size: int, allow_expansion: bool = False) -> None:
        """
        Initialize with a known size. If this is to be used to create a packing instead of deduce
        a packing, then allow_expansion should be set to true and new holes will be created when
        needed. If this is to be used for decoding a current packing, allow_expansion should be set
        to False to ensure we don't choose locations outside the buffer.

        Parameters:
            size - Number of bytes to work with as an integer
            allow_expansion - Boolean describing whether to add to the end of the order when needed
        """
        self.order: List[Optional[int]] = []
        self.expand = allow_expansion

        for _ in range(size):
            self.order.append(None)
        self.__orderlen = size
        self.__lastbyte = 0
        self.__lastshort = 0
        self.__lastint = 0

    def __append_empty(self) -> None:
        self.order.append(None)
        self.__orderlen = self.__orderlen + 1

    def mark_used(self, size: int, offset: int, round_to: int = 1) -> None:
        """
        Mark size bytes at offset as being used. If needed, round to the nearest byte/half/integer.

        Parameters:
            size - Number of bytes to mark
            offset - Offset into binary chunk to start marking
            round_to - Optional integer specifying how many bytes to round to. Valid values are 1, 2 and 4
        """
        # Round to nearest value if needed
        while (size & (round_to - 1)) != 0:
            size = size + 1

        # Expand buffer if needed
        if self.expand:
            while self.__orderlen < (size + offset):
                self.__append_empty()

        # Mark buffer as used
        for i in range(size):
            self.order[i + offset] = size

    def get_next_byte(self) -> Optional[int]:
        """
        Returns an integer location where the next byte will be found/stored, respecting Konami logic.
        Will return None if its not possible to find this integer a spot and we aren't expanding.
        """
        # If we expand for additions, make sure we've padded to a 4 byte boundary
        if self.expand:
            while (self.__orderlen & 3) != 0:
                self.__append_empty()

        for i in range(self.__lastbyte, self.__orderlen, 4):
            if self.order[i] is not None:
                # See if this has room for a byte
                for j in range(0, 4):
                    if self.order[i + j] == 1:
                        # This is okay, we can pack after this
                        continue
                    elif self.order[i + j] is None:
                        # This is open, pack here
                        self.__lastbyte = i
                        return i + j
                    else:
                        # This is something else, can't pack here
                        break
            else:
                # Couldn't find optimal packing, pack here
                self.__lastbyte = i
                return i

        if self.expand:
            self.__lastbyte = self.__orderlen
            return self.__orderlen
        else:
            return None

    def get_next_short(self) -> Optional[int]:
        """
        Returns an integer location where the next short will be found/stored, respecting Konami logic.
        Will return None if its not possible to find this integer a spot and we aren't expanding.
        """
        # If we expand for additions, make sure we've padded to a 4 byte boundary
        if self.expand:
            while (self.__orderlen & 3) != 0:
                self.__append_empty()

        for i in range(self.__lastshort, self.__orderlen, 4):
            if self.order[i] is not None:
                for j in range(0, 4, 2):
                    if self.order[i + j] == 2 and self.order[i + j + 1] == 2:
                        # This is okay, we can pack after this
                        continue
                    elif self.order[i + j] is None and self.order[i + j + 1] is None:
                        # This is open, pack here
                        self.__lastshort = i
                        return i + j
                    else:
                        # This is something else, can't pack here
                        break
            else:
                # Couldn't find optimal packing, pack here
                self.__lastshort = i
                return i

        if self.expand:
            self.__lastshort = self.__orderlen
            return self.__orderlen
        else:
            return None

    def get_next_int(self) -> Optional[int]:
        """
        Returns an integer location where the next integer will be found/stored, respecting Konami logic.
        Will return None if its not possible to find this integer a spot and we aren't expanding.
        """
        # If we expand for additions, make sure we've padded to a 4 byte boundary
        if self.expand:
            while (self.__orderlen & 3) != 0:
                self.__append_empty()

        for i in range(self.__lastint, self.__orderlen, 4):
            if self.order[i] is not None:
                continue
            if self.order[i + 1] is not None:
                continue
            if self.order[i + 2] is not None:
                continue
            if self.order[i + 3] is not None:
                continue

            self.__lastint = i
            return i

        if self.expand:
            self.__lastint = self.__orderlen
            return self.__orderlen
        else:
            return None

    @staticmethod
    def node_to_body_ordering(
        node: Node, include_children: bool = True, include_void: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Walk this node, attributes and children in the correct order to create a node
        ordering for the purpose of mapping Node objects to their actual data
        in a binary packet data chunk. We will use this to unpack data to determine the
        values of nodes, or to create the data that goes with these nodes.

        Paramters:
            include_children - Whether this ordering should include children. Defaults to True.
            include_void - Whether this ordering should include positions for void nodes. Defaults
                           to false.

        Returns:
            List of dictionary objects:
                - type - 'attribute' or 'value' to specify that this position in the
                         node walk is a string attribute or a node value
                - node - This Node object, for the purpose of assignment
                - name - The name of the attribute if type is 'attribute' or the name
                         of the node if type is 'value'
                - alignment - The alignment that this particular data object requiers
        """
        ordering = []

        # Include the node itself if it has a value or we include voids
        if node.data_length != 0 or include_void:
            alignment = node.data_length
            if alignment is None:
                # Take care of string types
                alignment = 4
            if alignment > 4:
                # Take care of 64 bit integers that are 32 bit aligned
                alignment = 4

            ordering.append(
                {
                    "type": "value",
                    "node": node,
                    "name": node.name,
                    "alignment": alignment,
                }
            )

        order = sorted(node.attributes.keys())
        for attr in order:
            ordering.append(
                {
                    "type": "attribute",
                    "node": node,
                    "name": attr,
                    "alignment": 4,
                }
            )

        if include_children:
            for child in node.children:
                ordering.extend(PackedOrdering.node_to_body_ordering(child))

        return ordering


class BinaryDecoder:
    """
    A class capable of taking a binary blob and decoding it to a Node tree.
    """

    def __init__(self, data: bytes, encoding: str, compressed: bool) -> None:
        """
        Initialize the object.

        Parameters:
            - data - A binary blob of data to be decoded
            - encoding - A string representing the text encoding for string elements. Should be either
                         'shift-jis', 'euc-jp' or 'utf-8'
        """
        self.stream = InputStream(data)
        self.encoding = encoding
        self.compressed = compressed
        self.executed = False

    def __read_node_name(self) -> str:
        """
        Given the current position in the stream, read the 6-bit-byte packed string name of the
        node.

        Returns:
            A string representing the name in ascii
        """
        length = self.stream.read_int()
        if length is None:
            raise BinaryEncodingException(
                "Ran out of data when attempting to read node name length!"
            )

        if not self.compressed:
            if length < 0x40:
                raise BinaryEncodingException(
                    "Node name length under decompressed minimum"
                )
            elif length < 0x80:
                length -= 0x3F
            else:
                length_ex = self.stream.read_int()
                if length_ex is None:
                    raise BinaryEncodingException(
                        "Ran out of data when attempting to read node name length!"
                    )
                length = (length << 8) | length_ex
                length -= 0x7FBF

            if length > BinaryEncoding.NAME_MAX_DECOMPRESSED:
                raise BinaryEncodingException(
                    "Node name length over decompressed limit"
                )

            name = self.stream.read_blob(length)
            if name is None:
                raise BinaryEncodingException(
                    "Ran out of data when attempting to read node name!"
                )

            return name.decode(self.encoding)

        if length > BinaryEncoding.NAME_MAX_COMPRESSED:
            raise BinaryEncodingException("Node name length over compressed limit")

        binary_length = int(((length * 6) + 7) / 8)

        def int_to_bin(integer: int) -> str:
            val = bin(integer)[2:]
            while len(val) < 8:
                val = "0" + val

            return val

        data = ""
        for _ in range(binary_length):
            next_byte = self.stream.read_int()
            if next_byte is None:
                raise BinaryEncodingException(
                    "Ran out of data when attempting to read node name!"
                )
            data = data + int_to_bin(next_byte)
        data_str = [data[i : (i + 6)] for i in range(0, len(data), 6)]
        data_int = [int(val, 2) for val in data_str]
        ret = "".join([Node.NODE_NAME_CHARS[val] for val in data_int])
        ret = ret[:length]
        return ret

    def __read_node(self, node_type: int) -> Node:
        """
        Given an integer node type, read the node's name, possible attributes
        and children. Will return a Node representing this node. Note
        that calling this on the first node should return a tree of all nodes.

        Returns:
            Node object
        """
        name = self.__read_node_name()
        node = Node(name=name, type=node_type)

        while True:
            child_type = self.stream.read_int()
            if child_type is None:
                raise BinaryEncodingException(
                    "Ran out of data when attempting to read node type!"
                )

            if child_type == Node.END_OF_NODE:
                return node
            elif child_type == Node.ATTR_TYPE:
                key = self.__read_node_name()
                node.set_attribute(key)
            else:
                child = self.__read_node(child_type)
                node.add_child(child)

    def get_tree(self) -> Node:
        """
        Parse the header and body such that we can return a Node tree
        representing the data passed to us.

        Returns:
            Node object
        """
        if self.executed:
            raise BinaryEncodingException(
                "Logic error, should only call this once per instance"
            )
        self.executed = True

        # Read the header first
        header_length = self.stream.read_int(4)
        if header_length is None:
            raise BinaryEncodingException(
                "Ran out of data when attempting to read header length!"
            )

        node_type = self.stream.read_int()
        if node_type is None:
            raise BinaryEncodingException(
                "Ran out of data when attempting to read root node type!"
            )
        root = self.__read_node(node_type)

        eod = self.stream.read_int()
        if eod != Node.END_OF_DOCUMENT:
            raise BinaryEncodingException(f"Unknown node type {eod} at end of document")

        # Skip by any padding
        while self.stream.pos < header_length + 4:
            self.stream.read_byte()

        # Read the body next
        body_length = self.stream.read_int(4)

        if body_length is not None and body_length > 0:
            # We have a body
            body = self.stream.read_blob(body_length)
            if body is None:
                raise BinaryEncodingException("Body has insufficient data")

            ordering = PackedOrdering(body_length)

            values = PackedOrdering.node_to_body_ordering(root)

            for value in values:
                node = value["node"]

                if value["type"] == "attribute":
                    size = None
                    enc = "s"
                    dtype = "str"
                    array = False
                    composite = False
                else:
                    size = node.data_length
                    enc = node.data_encoding
                    dtype = node.data_type
                    array = node.is_array
                    composite = node.is_composite

                if composite and array:
                    raise Exception("Logic error, no support for composite arrays!")

                if not array:
                    # Scalar value
                    alignment = value["alignment"]

                    if alignment == 1:
                        loc = ordering.get_next_byte()
                    elif alignment == 2:
                        loc = ordering.get_next_short()
                    elif alignment == 4:
                        loc = ordering.get_next_int()
                    if loc is None:
                        raise BinaryEncodingException(
                            "Ran out of data when attempting to read node data location!"
                        )

                    if size is None:
                        # The size should be read from the first 4 bytes
                        size = struct.unpack(">I", body[loc : (loc + 4)])[0]
                        ordering.mark_used(size + 4, loc, round_to=4)
                        loc = loc + 4

                        decode_data = body[loc : (loc + size)]
                        decode_value = f">{size}{enc}"
                    else:
                        # The size is built-in
                        ordering.mark_used(size, loc)

                        decode_data = body[loc : (loc + size)]
                        decode_value = f">{enc}"

                    if composite:
                        val_list = list(struct.unpack(decode_value, decode_data))
                        if value["type"] == "attribute":
                            raise Exception(
                                "Logic error, shouldn't have composite attribute type!"
                            )
                        node.set_value(val_list)
                        continue

                    val = struct.unpack(decode_value, decode_data)[0]

                    if dtype == "str":
                        # Need to convert this from encoding to standard string.
                        # Also, need to lob off the trailing null.
                        try:
                            val = val[:-1].decode(self.encoding, "replace")
                        except UnicodeDecodeError:
                            # Nothing we can do here
                            pass

                    if value["type"] == "attribute":
                        node.set_attribute(value["name"], val)
                    else:
                        node.set_value(val)
                else:
                    # Array value
                    loc = ordering.get_next_int()
                    if loc is None:
                        raise BinaryEncodingException(
                            "Ran out of data when attempting to read array length location!"
                        )

                    # The raw size in bytes
                    length = struct.unpack(">I", body[loc : (loc + 4)])[0]
                    elems = int(length / size)

                    ordering.mark_used(length + 4, loc, round_to=4)
                    loc = loc + 4
                    decode_data = body[loc : (loc + length)]
                    decode_value = f">{enc * elems}"

                    val = struct.unpack(decode_value, decode_data)
                    node.set_value([v for v in val])

        return root


class BinaryEncoder:
    """
    A class capable of taking a Node tree and encoding it into a binary format.
    """

    def __init__(self, tree: Node, encoding: str, compressed: bool = True) -> None:
        """
        Initialize the object.

        Parameters:
            tree - A binary blob of data to be decoded
            encoding - A string representing the text encoding for string elements. Should be either
                       'shift-jis', 'euc-jp' or 'utf-8'
        """
        self.stream = OutputStream()
        self.encoding = encoding
        self.tree = tree
        self.__body: List[int] = []
        self.__body_len = 0
        self.executed = False
        self.compressed = compressed

        # Generate the characer LUT
        self.char_lut: Dict[str, int] = {}
        for i in range(len(Node.NODE_NAME_CHARS)):
            self.char_lut[Node.NODE_NAME_CHARS[i]] = i

    def __write_node_name(self, name: str) -> None:
        """
        Given the current position in the stream, write the 6-bit-byte packed string name of the
        node.

        Parameters:
            name - A string name which should be encoded as a node name
        """
        if not self.compressed:
            encoded = name.encode(self.encoding)
            length = len(encoded)

            if length > BinaryEncoding.NAME_MAX_DECOMPRESSED:
                raise BinaryEncodingException(
                    "Node name length over decompressed limit"
                )

            if length < 64:
                self.stream.write_int(length + 0x3F)
            else:
                length += 0x7FBF
                self.stream.write_int((length >> 8) & 0xFF)
                self.stream.write_int(length & 0xFF)
            self.stream.write_blob(encoded)
            return

        def char_to_bin(ch: str) -> str:
            index = self.char_lut[ch]
            val = bin(index)[2:]

            while len(val) < 6:
                val = "0" + val

            return val[-6:]

        # Convert to six bit bytes
        length = len(name)
        data = "".join([char_to_bin(c) for c in name])

        # Pad out the rest with zeros
        while (len(data) & 0x7) != 0:
            data = data + "0"

        # Convert to 8-bit bytes
        data_chunks = [data[i : (i + 8)] for i in range(0, len(data), 8)]
        data_int = [int(val, 2) for val in data_chunks]

        # Output
        self.stream.write_int(length)
        for val in data_int:
            self.stream.write_int(val)

    def __write_node(self, node: Node) -> None:
        """
        Given an integer node type, read the node's name, possible attributes
        and children. Will return a Node representing this node. Note
        that calling this on the first node should return a tree of all nodes.

        Parameters:
            node - A Node which should be encoded.
        """
        to_write = PackedOrdering.node_to_body_ordering(
            node, include_children=False, include_void=True
        )
        for thing in to_write:
            # First, write the type of this node out
            if thing["type"] == "value":
                self.stream.write_int(thing["node"].type)
            else:
                self.stream.write_int(Node.ATTR_TYPE)
            # Now, write the name out
            self.__write_node_name(thing["name"])

        # Now, write out the children
        for child in node.children:
            self.__write_node(child)

        # Now, write out the end of node marker
        self.stream.write_int(Node.END_OF_NODE)

    def __add_data(self, data: bytes, length: int, offset: int) -> None:
        """
        Given some binary data, a length and an offset, add the data to the offset in the
        output body. This function will ensure that any new bytes that aren't copied are
        zero'd out. This includes bytes before the offset as well as any pad bytes after
        the offset + length in order to pad this body to a 4 byte boundary.

        Parameters:
            data - A blob of binary data which should be copied into the output
            length - Number of characters of data to copy
            offset - Offset into the body to start copying
        """
        while self.__body_len < (length + offset):
            self.__body.append(0)
            self.__body_len = self.__body_len + 1

        # Make sure its padded to 4 bytes
        while (self.__body_len & 0x3) != 0:
            self.__body.append(0)
            self.__body_len = self.__body_len + 1

        for i in range(length):
            self.__body[offset + i] = data[i]

    def get_data(self) -> bytes:
        """
        Encode the header and body into binary formrt.

        Returns:
            Binary blob of data that can be decoded by a game.
        """
        if self.executed:
            raise Exception("Logic error, should only call this once per instance")
        self.executed = True

        # Generate the header first
        self.__write_node(self.tree)
        self.stream.write_int(Node.END_OF_DOCUMENT)
        self.stream.write_pad(4)

        header_length = len(self.stream.data)
        header = self.stream.data[:]

        # Generate the body
        values = PackedOrdering.node_to_body_ordering(self.tree)
        if len(values) > 0:
            ordering = PackedOrdering(0, allow_expansion=True)

            for value in values:
                node = value["node"]

                if value["type"] == "attribute":
                    size = None
                    enc = "s"
                    dtype = "str"
                    array = False
                    composite = False
                    val = node.attribute(value["name"])
                else:
                    size = node.data_length
                    enc = node.data_encoding
                    dtype = node.data_type
                    array = node.is_array
                    composite = node.is_composite
                    val = node.value

                if val is None:
                    raise BinaryEncodingException(
                        f'Node \'{value["name"]}\' has invalid value None',
                    )

                if not array:
                    # Scalar value
                    alignment = value["alignment"]

                    if alignment == 1:
                        loc = ordering.get_next_byte()
                    elif alignment == 2:
                        loc = ordering.get_next_short()
                    elif alignment == 4:
                        loc = ordering.get_next_int()
                    if loc is None:
                        raise BinaryEncodingException(
                            "Ran out of data when attempting to allocate node location!"
                        )

                    if dtype == "str":
                        # Need to convert this to encoding from standard string.
                        # Also, need to lob off the trailing null.
                        if not isinstance(val, str):
                            raise BinaryEncodingException(
                                f'Node \'{value["name"]}\' has non-string value!',
                            )

                        try:
                            valbytes = val.encode(self.encoding) + b"\0"
                        except UnicodeEncodeError:
                            raise BinaryEncodingException(
                                f'Node \'{value["name"]}\' has un-encodable string value \'{val}\''
                            )
                        size = len(valbytes)
                        self.__add_data(
                            struct.pack(">I", size) + valbytes, size + 4, loc
                        )
                        ordering.mark_used(size + 4, loc, round_to=4)

                        # We took care of this one
                        continue
                    elif dtype == "bin":
                        # Store raw binary
                        size = len(val)
                        self.__add_data(struct.pack(">I", size) + val, size + 4, loc)
                        ordering.mark_used(size + 4, loc, round_to=4)

                        # We took care of this one
                        continue
                    elif composite:
                        # Array, but not, somewhat silly
                        if size is None:
                            raise Exception(
                                "Logic error, node size not set yet this is not an attribute!"
                            )

                        encode_value = f">{enc}"
                        self.__add_data(struct.pack(encode_value, *val), size, loc)
                        ordering.mark_used(size, loc)

                        # We took care of this one
                        continue
                    elif dtype == "bool":
                        val = 1 if val else 0

                    # The size is built-in, emit it
                    if size is None:
                        raise Exception(
                            "Logic error, node size not set yet this is not an attribute!"
                        )

                    encode_value = f">{enc}"
                    self.__add_data(struct.pack(encode_value, val), size, loc)
                    ordering.mark_used(size, loc)
                else:
                    # Array value
                    loc = ordering.get_next_int()
                    if loc is None:
                        raise BinaryEncodingException(
                            "Ran out of data when attempting allocate array location!"
                        )
                    if size is None:
                        raise Exception(
                            "Logic error, node size not set yet this is not an attribute!"
                        )

                    # The raw size in bytes
                    elems = len(val)
                    length = elems * size

                    # Write out the header (number of bytes taken up)
                    data = struct.pack(">I", length)
                    encode_value = f">{enc}"

                    # Write out data one element at a time
                    for v in val:
                        if dtype == "bool":
                            data = data + struct.pack(encode_value, 1 if v else 0)
                        else:
                            data = data + struct.pack(encode_value, v)

                    self.__add_data(data, length + 4, loc)
                    ordering.mark_used(length + 4, loc, round_to=4)

        return b"".join(
            [
                struct.pack(">I", header_length),
                header,
                struct.pack(">I", self.__body_len),
                bytes(self.__body),
            ]
        )


class BinaryEncoding:
    """
    Wrapper class representing a Binary Encoding.
    """

    MAGIC: Final[int] = 0xA0

    COMPRESSED_WITH_DATA: Final[int] = 0x42
    COMPRESSED_WITHOUT_DATA: Final[int] = 0x43
    DECOMPRESSED_WITH_DATA: Final[int] = 0x45
    DECOMPRESSED_WITHOUT_DATA: Final[int] = 0x46

    NAME_MAX_COMPRESSED: Final[int] = 0x24
    NAME_MAX_DECOMPRESSED: Final[int] = 0x1000

    # The string values should match the constants in EAmuseProtocol.
    # I have no better way to link these than to write this comment,
    # as otherwise we would have a circular dependency.
    ENCODINGS: Final[Dict[int, str]] = {
        0x00: "ascii",
        0x20: "shift-jis-legacy",
        0x60: "euc-jp",
        0x80: "shift-jis",
        0xA0: "utf-8",
    }

    def __init__(self) -> None:
        """
        Initialize the encoding object.
        """
        self.encoding: Optional[str] = None
        self.compressed: bool = True

    def __sanitize_encoding(self, enc: str) -> str:
        """
        Convert an internal encoding value from an externally acceptible value.

        Parameters:
            enc - The encoding as a string as passed from an outside caller

        Returns:
            An encoding string suitable for internal use.
        """
        if enc == "shift-jis-legacy":
            return "shift-jis"
        return enc

    def decode(self, data: bytes, skip_on_exceptions: bool = False) -> Optional[Node]:
        """
        Given a data blob, decode the data with the current encoding. Will
        also set the class property value 'encoding' to the encoding used
        on the last decode.

        Parameters:
            data - Binary blob representing the data to decode

        Returns:
            Node object representing the root of the decoded tree, or None
            if we couldn't decode the object for some reason.
        """
        try:
            data_magic, contents, encoding_raw, encoding_swapped = struct.unpack(
                ">BBBB", data[0:4]
            )
        except struct.error:
            # Couldn't even parse magic
            return None

        if data_magic != BinaryEncoding.MAGIC:
            return None
        if ((~encoding_raw) & 0xFF) != encoding_swapped:
            return None

        self.compressed = contents in [
            BinaryEncoding.COMPRESSED_WITH_DATA,
            BinaryEncoding.COMPRESSED_WITHOUT_DATA,
        ]
        if not self.compressed and contents not in [
            BinaryEncoding.DECOMPRESSED_WITH_DATA,
            BinaryEncoding.DECOMPRESSED_WITHOUT_DATA,
        ]:
            return None

        encoding = BinaryEncoding.ENCODINGS.get(encoding_raw)

        if encoding is not None:
            self.encoding = encoding
            try:
                decoder = BinaryDecoder(
                    data[4:], self.__sanitize_encoding(encoding), self.compressed
                )
                return decoder.get_tree()
            except BinaryEncodingException:
                if skip_on_exceptions:
                    return None
                else:
                    raise
        else:
            return None

    def encode(
        self, tree: Node, encoding: Optional[str] = None, compressed: bool = True
    ) -> bytes:
        """
        Given a tree of Node objects, encode the data with the current encoding.

        Parameters:
            tree - Node tree representing the data to encode
            encoding - The text encoding to use. If None, will try to use the encoding from
                       the last successful decode

        Returns:
            Binary blob representing encoded data
        """
        if encoding is None:
            encoding = self.encoding
        if encoding is None:
            raise BinaryEncodingException("Unknown encoding")

        encoding_magic = None
        for magic, encstr in BinaryEncoding.ENCODINGS.items():
            if encstr == encoding:
                encoding_magic = magic
                break

        if encoding_magic is None:
            raise BinaryEncodingException(f"Invalid text encoding {encoding}")

        encoder = BinaryEncoder(tree, self.__sanitize_encoding(encoding), compressed)
        data = encoder.get_data()
        return (
            struct.pack(
                ">BBBB",
                BinaryEncoding.MAGIC,
                BinaryEncoding.COMPRESSED_WITH_DATA
                if compressed
                else BinaryEncoding.DECOMPRESSED_WITH_DATA,
                encoding_magic,
                (~encoding_magic & 0xFF),
            )
            + data
        )
