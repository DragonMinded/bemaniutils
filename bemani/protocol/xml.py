import copy
import struct
from typing import Any, Dict, Iterator, List, Optional, Tuple
from typing_extensions import Final

from bemani.protocol.stream import InputStream
from bemani.protocol.node import Node


class XmlEncodingException(Exception):
    """
    An exception that is thrown when we encounter an error encoding to or decoding from XML.
    """


class XmlDecoder:
    """
    A hand-rolled XML parser, suitable for parsing old-style XML documents in
    game data or from legacy game traffic. I did consider using lxml and other
    data stores, but they insist on mangling data inside binary/string blobs
    making them unsuitable for a protocol with exact specifications.
    """

    def __init__(self, data: bytes, encoding: str) -> None:
        """
        Initialize the XML decoder.

        Parameters:
            data - String XML data which should be decoded into Nodes.
            encoding - The expected encoding of the XML.
        """
        self.stream = InputStream(data)
        self.root: Optional[Node] = None
        self.current: List[Node] = []
        self.encoding = encoding

    def __start_element(self, tag: bytes, attributes: Dict[str, str]) -> None:
        """
        Called when we encounter an element open tag. Also called when we encounter
        an empty element. Creates a new node with the specified name and attributes.

        Parameters:
            tag - The string tag name.
            attributes - A dictionary keyed by attribute name and whose values are the string
                         attribute values. This attribute values should already be decoded from
                         the XML's encoding.
        """
        data_type = attributes.get("__type")

        array_str = attributes.get("__count")
        if array_str is not None:
            array = True
        else:
            array = False

        if data_type is None:
            # Special case for nodes that don't have a type
            node = Node(name=tag.decode("ascii"), type=Node.NODE_TYPE_VOID)
        else:
            # Get the data value
            type_int = Node.typename_to_type(data_type)
            if type_int is None:
                raise XmlEncodingException(
                    f'Invalid node type {data_type} for node {tag.decode("ascii")}'
                )

            node = Node(name=tag.decode("ascii"), type=type_int, array=array)

        # Now, do the attributes
        for attr in attributes:
            if attr == "__type" or attr == "__count":
                # Skip these, handled
                continue
            else:
                node.set_attribute(attr, attributes[attr])

        self.current.append(node)

    def __end_element(self, tag: bytes) -> None:
        """
        Called when we encounter an element close tag. Also called when we encounter an empty element,
        after __start_element is called. Does bookkeeping related to element order.

        Parameters:
            tag - The string tag name.
        """
        node = self.current.pop()

        if node.name != tag.decode("ascii"):
            raise Exception(
                f'Logic error, expected {tag.decode("ascii")} but got {node.name}'
            )

        if len(self.current) == 0:
            self.root = node
        else:
            parent = self.current[-1]
            parent.add_child(node)

    def __yield_values(self, text: str) -> Iterator[str]:
        value = ""

        for c in text:
            if c.isspace():
                if len(value) > 0:
                    yield value
                    value = ""
            else:
                value = value + c

        if len(value) > 0:
            yield value

    def __text(self, text: bytes) -> None:
        """
        Called when we finish parsing arbitrary non-element text. Note that the text passed in is in
        the XML document's encoding and it is this function's responsibility to decode it.

        Parameters:
            text - String text value of the node, as encoded by the XML document's encoding.
        """
        try:
            value = text.decode(self.encoding)
        except UnicodeDecodeError:
            raise XmlEncodingException("Failed to decode text node with given encoding")

        if len(self.current) > 0:
            data_type = self.current[-1].data_type
            composite = self.current[-1].is_composite
            array = self.current[-1].is_array

            if data_type == "void":
                # We can't handle this
                return

            if data_type == "str":
                # Do nothing, already fine
                value = value.replace("&amp;", "&")
                value = value.replace("&lt;", "<")
                value = value.replace("&gt;", ">")
                value = value.replace("&apos;", "'")
                value = value.replace("&quot;", '"')
                if self.current[-1].value is None:
                    self.current[-1].set_value(value)
                else:
                    self.current[-1].set_value(self.current[-1].value + value)
            elif data_type == "bin":
                # Convert from a hex string
                def hex_to_bin(hexval: str) -> bytes:
                    intval = int(hexval, 16)
                    return struct.pack(">B", intval)

                # Remove any spaces first
                value = "".join([c for c in value if not c.isspace()])
                if self.current[-1].value is None:
                    self.current[-1].set_value(
                        b"".join(
                            [
                                hex_to_bin(value[i : (i + 2)])
                                for i in range(0, len(value), 2)
                            ]
                        )
                    )
                else:
                    self.current[-1].set_value(
                        self.current[-1].value
                        + b"".join(
                            [
                                hex_to_bin(value[i : (i + 2)])
                                for i in range(0, len(value), 2)
                            ]
                        )
                    )
            elif data_type == "ip4":
                # Do nothing, already fine
                self.current[-1].set_value(value)
            elif data_type == "bool":

                def conv_bool(val: str) -> bool:
                    if val and val.lower() in ["0", "false"]:
                        return False
                    else:
                        return True

                if array or composite:
                    self.current[-1].set_value(
                        [conv_bool(v) for v in self.__yield_values(value)]
                    )
                else:
                    self.current[-1].set_value(conv_bool(value))
            elif data_type == "float":
                if array or composite:
                    self.current[-1].set_value(
                        [float(v) for v in self.__yield_values(value)]
                    )
                else:
                    self.current[-1].set_value(float(value))
            else:
                if array or composite:
                    self.current[-1].set_value(
                        [int(v) for v in self.__yield_values(value)]
                    )
                else:
                    self.current[-1].set_value(int(value))

    def __parse_attributes(self, attributes: bytes) -> Dict[str, str]:
        """
        Given a string representing zero or more possible attributes, parse them into
        a dictionary.

        Returns:
            A dictionary keyed by the attribute name and who's values are unescaped strings.
            If no attributes exist, this returns an empty dictionary.
        """
        attr_stream = InputStream(attributes)
        parsed_attrs: Dict[str, str] = {}
        state = "space"
        attr = b""
        val = b""

        def unescape(value: bytes) -> str:
            val = value.decode(self.encoding)
            val = val.replace("&amp;", "&")
            val = val.replace("&lt;", "<")
            val = val.replace("&gt;", ">")
            val = val.replace("&apos;", "'")
            val = val.replace("&quot;", '"')
            val = val.replace("&#13;", "\r")
            return val.replace("&#10;", "\n")

        while True:
            c = attr_stream.read_byte()

            if c is None:
                return parsed_attrs
            if state == "space":
                if not c.isspace():
                    state = "attr"
                    attr = c
            elif state == "attr":
                if c == b"=":
                    attr = attr.strip()
                    state = "valstart"
                else:
                    attr = attr + c
            elif state == "valstart":
                if c == b'"':
                    state = "valdouble"
                    val = b""
                elif c == b"'":
                    state = "valsingle"
                    val = b""
            elif state == "valdouble":
                if c == b'"':
                    state = "space"
                    parsed_attrs[attr.decode("ascii")] = unescape(val)
                else:
                    val = val + c
            elif state == "valsingle":
                if c == b"'":
                    state = "space"
                    parsed_attrs[attr.decode("ascii")] = unescape(val)
                else:
                    val = val + c

    def __split_node(self, content: bytes) -> Tuple[bytes, bytes]:
        node_stream = InputStream(content)
        tag = b""
        attributes = b""
        state = "tag"

        while True:
            c = node_stream.read_byte()

            if c is None:
                break
            if state == "tag":
                if c.isspace():
                    state = "space"
                else:
                    tag = tag + c
            elif state == "space":
                if not c.isspace():
                    attributes = c
                    state = "attributes"
            elif state == "attributes":
                attributes = attributes + c

        return (tag, attributes)

    def __handle_node(self, content: bytes) -> None:
        """
        Called whenever we encounter any node type. Filters out special nodes,
        determines whether this is a start, end or empty node, and fires off
        calls to the respective __start_element and __end_element functions.

        Parameters:
            The node contents, minus the < and > characters. This will be encoded
            in the XML document's encoding.
        """
        if content[:1] == b"?" and content[-1:] == b"?":
            # Special node, parse to get the encoding.
            tag, attributes = self.__split_node(content[1:-1])
            if tag == b"xml":
                attributes_dict = self.__parse_attributes(attributes)
                if "encoding" in attributes_dict:
                    self.encoding = attributes_dict["encoding"]
            return

        if content[:1] == b"/":
            # We got an element end
            self.__end_element(content[1:])
        else:
            # We got a start element
            if content[-1:] == b"/":
                # This is an empty element
                empty = True
                content = content[:-1]
            else:
                # This node has subnodes or text
                empty = False

            tag, attributes = self.__split_node(content)
            self.__start_element(tag, self.__parse_attributes(attributes))
            if empty:
                self.__end_element(tag)

    def get_tree(self) -> Optional[Node]:
        """
        Walk the XML document and parse into nodes.

        Returns:
            A Node object representing the root of the XML document.
        """
        state = "text"
        text = b""
        node = b""

        while True:
            c = self.stream.read_byte()

            if c is None:
                return self.root
            elif state == "text":
                if c == b"<":
                    self.__text(text)
                    state = "node"
                    node = b""
                else:
                    text = text + c
            elif state == "node":
                if c == b">":
                    self.__handle_node(node)
                    state = "text"
                    text = b""
                else:
                    node = node + c


class XmlEncoder:
    def __init__(self, tree: Node, encoding: str) -> None:
        """
        Initialize the XML encoder.

        Parameters:
            tree - A binary blob of data to be decoded
            encoding - A string representing the text encoding for string elements. Should be either
                       'shift-jis', 'euc-jp', 'utf-8' or 'ascii'.
        """
        self.tree = tree
        self.encoding = encoding

    def get_data(self) -> bytes:
        magic = f'<?xml version="1.0" encoding="{self.encoding}"?>'.encode("ascii")
        payload = self.to_xml(self.tree)

        return magic + payload

    def to_xml(self, node: Node) -> bytes:
        """
        Convert this node, attributes and all children to an XML-like representation of the tree.

        Parameters:
            node: A Node representing the root of the tree to be encoded.

        Returns:
            Bytes representing the XML-like data for this node and all children.
        """
        attrs_dict = copy.deepcopy(node.attributes)
        order = sorted(attrs_dict.keys())
        if node.data_length != 0:
            # Represent type and length
            if node.is_array:
                if node.value is None:
                    attrs_dict["__count"] = "0"
                else:
                    attrs_dict["__count"] = str(len(node.value))
                order.insert(0, "__count")
            attrs_dict["__type"] = node.data_type
            order.insert(0, "__type")

        def escape(val: Any, attr: bool = False) -> bytes:
            if isinstance(val, str):
                val = val.replace("&", "&amp;")
                val = val.replace("<", "&lt;")
                val = val.replace(">", "&gt;")
                val = val.replace("'", "&apos;")
                val = val.replace('"', "&quot;")
                if attr:
                    val = val.replace("\r", "&#13;")
                    val = val.replace("\n", "&#10;")

                return val.encode(self.encoding)
            else:
                return str(val).encode("ascii")

        if attrs_dict:
            attrs = b" " + b" ".join(
                [
                    b"".join(
                        [
                            attr.encode("ascii"),
                            b'="',
                            escape(attrs_dict[attr], attr=True),
                            b'"',
                        ]
                    )
                    for attr in order
                ]
            )
        else:
            attrs = b""

        if node.children:
            # Has children nodes
            children = [self.to_xml(child) for child in node.children]
            string = b"".join(
                [
                    b"<",
                    node.name.encode("ascii"),
                    attrs,
                    b">",
                    b"".join(children),
                    b"</",
                    node.name.encode("ascii"),
                    b">",
                ]
            )
        else:
            # Doesn't have children nodes
            if node.data_length == 0:
                # Void node
                string = b"".join(
                    [
                        b"<",
                        node.name.encode("ascii"),
                        attrs,
                        b"/>",
                    ]
                )
            else:
                # Node with values
                if node.is_array or node.is_composite:
                    if node.value is None:
                        vals = ""
                    else:
                        if node.data_type == "bool":
                            vals = " ".join(
                                [("1" if val else "0") for val in node.value]
                            )
                        else:
                            vals = " ".join([str(val) for val in node.value])
                    binary = vals.encode("ascii")
                elif node.data_type == "str":
                    binary = escape(node.value)
                elif node.data_type == "bool":
                    binary = b"1" if node.value else b"0"
                elif node.data_type == "ip4":
                    vals = ".".join([str(val) for val in node.value])
                    binary = vals.encode("ascii")
                elif node.data_type == "bin":
                    # Convert to a hex string
                    def bin_to_hex(binary: int) -> str:
                        val = hex(binary)[2:]
                        while len(val) < 2:
                            val = "0" + val
                        return val

                    vals = "".join([bin_to_hex(v) for v in node.value])
                    binary = vals.encode("ascii")
                else:
                    vals = str(node.value)
                    binary = vals.encode("ascii")

                string = b"".join(
                    [
                        b"<",
                        node.name.encode("ascii"),
                        attrs,
                        b">",
                        binary,
                        b"</",
                        node.name.encode("ascii"),
                        b">",
                    ]
                )

        return string


class XmlEncoding:
    """
    Wrapper class representing an XML encoding.
    """

    # The string values should match the constants in EAmuseProtocol.
    # I have no better way to link these than to write this comment,
    # as otherwise we would have a circular dependency.
    ACCEPTED_ENCODINGS: Final[List[str]] = ["shift-jis", "euc-jp", "utf-8", "ascii"]

    def __init__(self) -> None:
        """
        Initialize the encoding object.
        """
        self.encoding: Optional[str] = None

    def __fix_encoding(self, encoding: str) -> str:
        """
        Given an encoding, try to normalize it, looking for specific ways that
        older games might send it back.

        Parameters:
            encoding - The encoding we want to normalize.

        Returns:
            A new encoding string that is equivalent but normalized.
        """
        encoding = encoding.lower()
        encoding = encoding.replace("_", "-")
        return encoding

    def decode(self, data: bytes, skip_on_exceptions: bool = False) -> Optional[Node]:
        """
        Given a data blob, decode the data with the current encoding. Will set
        the class property value 'encoding' to the encoding used on the last
        decode.

        Parameters:
            data - Blob of text representing the data to decode.

        Returns:
            Node object representing the root of the decoded tree, or None
            if we couldn't decode the object for some reason.
        """
        # Always assume this, unless we get told otherwise in the XML
        self.encoding = "shift-jis"

        # Decode property/value
        try:
            xml = XmlDecoder(data, self.encoding)
            tree = xml.get_tree()
            self.encoding = xml.encoding
            return tree
        except XmlEncodingException:
            if skip_on_exceptions:
                return None
            else:
                raise

    def encode(self, tree: Node, encoding: Optional[str] = None) -> bytes:
        """
        Given a tree of Node objects, encode the data with the current encoding.

        Parameters:
            tree - Node tree representing the data to encode
            encoding - The text encoding to use. If None, will try to use the encoding from
                       the last successful decode

        Returns:
            String blob representing encoded data as XML.
        """
        # Ensure we got the right encoding
        if encoding is None:
            encoding = self.encoding
        if encoding is None:
            raise XmlEncodingException("Unknown encoding")

        encoding = self.__fix_encoding(encoding)
        if encoding not in XmlEncoding.ACCEPTED_ENCODINGS:
            # XML pages only support a few encodings.
            raise XmlEncodingException(f"Invalid text encoding {encoding}")

        xml = XmlEncoder(tree, encoding)
        return xml.get_data()
