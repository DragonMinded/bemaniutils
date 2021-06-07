import copy
import struct
from typing import Any, Dict, List, Optional, Union
from typing_extensions import Final

# Hack to get around mypy's lack of scoping on types.
_renamed_float = float
_renamed_bool = bool


class NodeException(Exception):
    """
    An exception thrown when we encounter an issue with a property node.
    """


class Node:
    """
    An object representing one node in the tree structure of a packet. Nodes can have a number of
    string attributes, and either a value or zero or more children. Note that it is possible and
    supported for a node to not have a value or children. This also includes a decent amount of
    constructor helper classmethods to make constructing a tree from source code easier.
    """
    NODE_NAME_CHARS: Final[str] = "0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

    NODE_TYPE_VOID: Final[int] = 1
    NODE_TYPE_S8: Final[int] = 2
    NODE_TYPE_U8: Final[int] = 3
    NODE_TYPE_S16: Final[int] = 4
    NODE_TYPE_U16: Final[int] = 5
    NODE_TYPE_S32: Final[int] = 6
    NODE_TYPE_U32: Final[int] = 7
    NODE_TYPE_S64: Final[int] = 8
    NODE_TYPE_U64: Final[int] = 9
    NODE_TYPE_BIN: Final[int] = 10
    NODE_TYPE_STR: Final[int] = 11
    NODE_TYPE_IP4: Final[int] = 12
    NODE_TYPE_TIME: Final[int] = 13
    NODE_TYPE_FLOAT: Final[int] = 14
    NODE_TYPE_DOUBLE: Final[int] = 15

    NODE_TYPE_2S8: Final[int] = 16
    NODE_TYPE_2U8: Final[int] = 17
    NODE_TYPE_2S16: Final[int] = 18
    NODE_TYPE_2U16: Final[int] = 19
    NODE_TYPE_2S32: Final[int] = 20
    NODE_TYPE_2U32: Final[int] = 21
    NODE_TYPE_2S64: Final[int] = 22
    NODE_TYPE_2U64: Final[int] = 23
    NODE_TYPE_2FLOAT: Final[int] = 24
    NODE_TYPE_2DOUBLE: Final[int] = 25

    NODE_TYPE_3S8: Final[int] = 26
    NODE_TYPE_3U8: Final[int] = 27
    NODE_TYPE_3S16: Final[int] = 28
    NODE_TYPE_3U16: Final[int] = 29
    NODE_TYPE_3S32: Final[int] = 30
    NODE_TYPE_3U32: Final[int] = 31
    NODE_TYPE_3S64: Final[int] = 32
    NODE_TYPE_3U64: Final[int] = 33
    NODE_TYPE_3FLOAT: Final[int] = 34
    NODE_TYPE_3DOUBLE: Final[int] = 35

    NODE_TYPE_4S8: Final[int] = 36
    NODE_TYPE_4U8: Final[int] = 37
    NODE_TYPE_4S16: Final[int] = 38
    NODE_TYPE_4U16: Final[int] = 39
    NODE_TYPE_4S32: Final[int] = 40
    NODE_TYPE_4U32: Final[int] = 41
    NODE_TYPE_4S64: Final[int] = 42
    NODE_TYPE_4U64: Final[int] = 43
    NODE_TYPE_4FLOAT: Final[int] = 44
    NODE_TYPE_4DOUBLE: Final[int] = 45

    NODE_TYPE_BOOL: Final[int] = 52

    NODE_TYPES: Final[Dict[int, Dict[str, Any]]] = {
        NODE_TYPE_VOID: {
            'name': 'void',
            'enc': '',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_S8: {
            'name': 's8',
            'enc': 'b',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_U8: {
            'name': 'u8',
            'enc': 'B',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_S16: {
            'name': 's16',
            'enc': 'h',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_U16: {
            'name': 'u16',
            'enc': 'H',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_S32: {
            'name': 's32',
            'enc': 'i',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_U32: {
            'name': 'u32',
            'enc': 'I',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_S64: {
            'name': 's64',
            'enc': 'q',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_U64: {
            'name': 'u64',
            'enc': 'Q',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_BIN: {
            'name': 'bin',
            'enc': 's',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_STR: {
            'name': 'str',
            'enc': 's',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_IP4: {
            'name': 'ip4',
            'enc': '4s',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_TIME: {
            'name': 'time',
            'enc': 'I',
            'int': True,
            'composite': False,
        },
        NODE_TYPE_FLOAT: {
            'name': 'float',
            'enc': 'f',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_DOUBLE: {
            'name': 'double',
            'enc': 'd',
            'int': False,
            'composite': False,
        },
        NODE_TYPE_2S8: {
            'name': '2s8',
            'enc': 'bb',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2U8: {
            'name': '2u8',
            'enc': 'BB',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2S16: {
            'name': '2s16',
            'enc': 'hh',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2U16: {
            'name': '2u16',
            'enc': 'HH',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2S32: {
            'name': '2s32',
            'enc': 'ii',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2U32: {
            'name': '2u32',
            'enc': 'II',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2S64: {
            'name': '2s64',
            'enc': 'qq',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2U64: {
            'name': '2u64',
            'enc': 'QQ',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_2FLOAT: {
            'name': '2float',
            'enc': 'ff',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_2DOUBLE: {
            'name': '2double',
            'enc': 'dd',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_3S8: {
            'name': '3s8',
            'enc': 'bbb',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3U8: {
            'name': '3u8',
            'enc': 'BBB',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3S16: {
            'name': '3s16',
            'enc': 'hhh',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3U16: {
            'name': '3u16',
            'enc': 'HHH',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3S32: {
            'name': '3s32',
            'enc': 'iii',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3U32: {
            'name': '3u32',
            'enc': 'III',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3S64: {
            'name': '3s64',
            'enc': 'qqq',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3U64: {
            'name': '3u64',
            'enc': 'QQQ',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_3FLOAT: {
            'name': '3float',
            'enc': 'fff',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_3DOUBLE: {
            'name': '3double',
            'enc': 'ddd',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_4U8: {
            'name': '4u8',
            'enc': 'BBBB',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4S8: {
            'name': '4s8',
            'enc': 'bbbb',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4U16: {
            'name': '4u16',
            'enc': 'HHHH',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4S16: {
            'name': '4s16',
            'enc': 'hhhh',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4S32: {
            'name': '4s32',
            'enc': 'iiii',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4U32: {
            'name': '4u32',
            'enc': 'IIII',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4S64: {
            'name': '4s64',
            'enc': 'qqqq',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4U64: {
            'name': '4u64',
            'enc': 'QQQQ',
            'int': True,
            'composite': True,
        },
        NODE_TYPE_4FLOAT: {
            'name': '4float',
            'enc': 'ffff',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_4DOUBLE: {
            'name': '4double',
            'enc': 'dddd',
            'int': False,
            'composite': True,
        },
        NODE_TYPE_BOOL: {
            'name': 'bool',
            'enc': 'b',
            'int': False,
            'composite': False,
        },
    }
    ARRAY_BIT: Final[int] = 0x40
    ATTR_TYPE: Final[int] = 0x2E
    END_OF_NODE: Final[int] = 0xFE
    END_OF_DOCUMENT: Final[int] = 0xFF

    @staticmethod
    def void(name: str) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_VOID)

    @staticmethod
    def string(name: str, value: str) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_STR, value=value)

    @staticmethod
    def binary(name: str, value: bytes) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_BIN, value=value)

    @staticmethod
    def float(name: str, value: _renamed_float) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_FLOAT, value=value)

    @staticmethod
    def bool(name: str, value: _renamed_bool) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_BOOL, value=value)

    @staticmethod
    def ipv4(name: str, value: str) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_IP4, value=value)

    @staticmethod
    def time(name: str, value: int) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_TIME, value=value)

    @staticmethod
    def u8(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_U8, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U8, value=value)

    @staticmethod
    def s8(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_S8, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S8, value=value)

    @staticmethod
    def u16(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_U16, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U16, value=value)

    @staticmethod
    def s16(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_S16, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S16, value=value)

    @staticmethod
    def u32(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_U32, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U32, value=value)

    @staticmethod
    def s32(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_S32, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S32, value=value)

    @staticmethod
    def u64(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_U64, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U64, value=value)

    @staticmethod
    def s64(name: str, value: int) -> 'Node':
        Node.__validate(Node.NODE_TYPE_S64, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S64, value=value)

    @staticmethod
    def time_array(name: str, values: List[int]) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_TIME, array=True, value=values)

    @staticmethod
    def float_array(name: str, values: List[_renamed_float]) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_FLOAT, array=True, value=values)

    @staticmethod
    def bool_array(name: str, values: List[_renamed_bool]) -> 'Node':
        return Node(name=name, type=Node.NODE_TYPE_BOOL, array=True, value=values)

    @staticmethod
    def u8_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_U8, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U8, array=True, value=values)

    @staticmethod
    def s8_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_S8, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S8, array=True, value=values)

    @staticmethod
    def u16_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_U16, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U16, array=True, value=values)

    @staticmethod
    def s16_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_S16, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S16, array=True, value=values)

    @staticmethod
    def u32_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_U32, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U32, array=True, value=values)

    @staticmethod
    def s32_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_S32, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S32, array=True, value=values)

    @staticmethod
    def u64_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_U64, name, value)
        return Node(name=name, type=Node.NODE_TYPE_U64, array=True, value=values)

    @staticmethod
    def s64_array(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_S64, name, value)
        return Node(name=name, type=Node.NODE_TYPE_S64, array=True, value=values)

    @staticmethod
    def fouru8(name: str, values: List[int]) -> 'Node':
        for value in values:
            Node.__validate(Node.NODE_TYPE_U8, name, value)
        return Node(name=name, type=Node.NODE_TYPE_4U8, value=values)

    @staticmethod
    def typename_to_type(typename: str) -> Optional[int]:
        """
        Given a string typename as would be output in an XML conversion or found
        in the above NODE_TYPES table, return an integer node type that would be
        valid for a binary node.

        Parameters:
            typename - String corresponding to a node type.

        Returns:
            An integer specifying the node type or None if not found.
        """
        for nodetype in Node.NODE_TYPES:
            if typename.lower() == Node.NODE_TYPES[nodetype]['name']:
                return nodetype

        return None

    @staticmethod
    def __validate(nodetype: int, name: str, value: int) -> None:
        if nodetype == Node.NODE_TYPE_U8:
            if value < 0 or value > 255:
                raise NodeException(f'Invalid value {value} for u8 {name}')
        elif nodetype == Node.NODE_TYPE_S8:
            if value < -128 or value > 127:
                raise NodeException(f'Invalid value {value} for s8 {name}')
        elif nodetype == Node.NODE_TYPE_U16:
            if value < 0 or value > 65535:
                raise NodeException(f'Invalid value {value} for u16 {name}')
        elif nodetype == Node.NODE_TYPE_S16:
            if value < -32768 or value > 32767:
                raise NodeException(f'Invalid value {value} for s16 {name}')
        elif nodetype == Node.NODE_TYPE_U32:
            if value < 0 or value > 4294967295:
                raise NodeException(f'Invalid value {value} for u32 {name}')
        elif nodetype == Node.NODE_TYPE_S32:
            if value < -2147483648 or value > 2147483647:
                raise NodeException(f'Invalid value {value} for s32 {name}')
        elif nodetype == Node.NODE_TYPE_U64:
            if value < 0 or value > 18446744073709551615:
                raise NodeException(f'Invalid value {value} for u64 {name}')
        elif nodetype == Node.NODE_TYPE_S64:
            if value < -9223372036854775808 or value > 9223372036854775807:
                raise NodeException(f'Invalid value {value} for s32 {name}')

    def __init__(self, name: Optional[str]=None, type: Optional[int]=None, array: Optional[_renamed_bool]=None, value: Optional[Any]=None) -> None:
        """
        Initialize a node, with an optional name and type.

        Parameters:
            name - A string specifying the name of the node
            type - An integer specifying the type of the node. Should be
                   a valid type as found in Node.NODE_TYPES with
                   an optional Node.ARRAY_BIT set.
            array - A boolean specifying whether or not this node is an array.
                    If not provided, will extract the array bit flag from the
                    type.
            value - A mixed value corresponding to the type that this node should
                    be initialized with.
        """
        self.__name: Optional[str] = None
        self.__array = False
        self.__translated_type: Optional[Dict[str, Any]] = None
        self.__type: Optional[int] = None
        self.__attrs: Dict[str, str] = {}
        self.__value: Any = None
        self.__children: List[Node] = []

        if name is not None:
            self.set_name(name)
        if type is not None:
            self.set_type(type, array=array)
        if value is not None:
            self.set_value(value)

    def set_name(self, name: str) -> None:
        """
        Set the name of the node to a new string.

        Parameters:
            name - A string specifying the node name. Should be made up of only
                NODE_NAME_CHARS characters.
        """
        # Ensure it isn't a violation
        for char in name:
            if char not in Node.NODE_NAME_CHARS:
                raise NodeException(f'Invalid node name {name}')

        self.__name = name

    @property
    def name(self) -> str:
        """
        Get the name of the node as a string.

        Returns:
            A string node name.
        """
        if self.__name is None:
            raise Exception('Logic error, tried to fetch name before setting!')
        return self.__name

    def set_type(self, type: int, array: Optional[_renamed_bool]=None) -> None:
        """
        Set the type of the node to a new integer type, as specified in Node.NODE_TYPES.

        Parameters:
            type - An integer type to set the node type as.
            array - A boolean specifying whether this node is an array or not. If not provided
                    this function will extract the array bit from the provided type integer.
        """
        if array is not None:
            if array:
                type = type | Node.ARRAY_BIT
            else:
                type = type & (~Node.ARRAY_BIT)

        if (type & Node.ARRAY_BIT) != 0:
            self.__array = True

        try:
            self.__translated_type = Node.NODE_TYPES[type & (~Node.ARRAY_BIT)]
            self.__type = type
        except KeyError:
            raise NodeException(f'Unknown node type {type} on node name {self.__name}')

    @property
    def type(self) -> int:
        """
        Returns the underlying data type for this node.

        Returns:
            An integer node type. Should correspond with node types, but note that the array
            bit ARRAY_BIT might be set.
        """
        if self.__type is None:
            raise Exception('Logic error, tried to fetch type before setting!')
        return self.__type

    @property
    def data_type(self) -> str:
        """
        Returns the data type name based on the node's type.

        Returns:
            A string data type name. This string can be fed to typename_to_type to get the original type back.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to fetch data type before setting type!')
        return self.__translated_type['name']

    @property
    def data_length(self) -> Optional[int]:
        """
        Returns the number of bytes used by the encoding, based on the node's type. If this is a binary blob
        or a string, returns None. For array types, this represents the size of one element in bytes.

        Returns:
            An integer data length, or None if this node's element has variable length.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to fetch data length before setting type!')
        if self.__translated_type['name'] in {'bin', 'str'}:
            return None
        return struct.calcsize(self.__translated_type['enc'])

    @property
    def data_encoding(self) -> str:
        """
        Returns the python struct encoding character used to encode/decode this type.

        Returns:
            A character that can be passed to struct.pack or struct.unpack.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to fetch data encoding before setting type!')
        return self.__translated_type['enc']

    def set_attribute(self, attr: str, val: str='') -> None:
        """
        Set an attribute to a particular string value on this node.

        Parameters:
            attr - A string attribute to set on the node.
            val - The string value to set the attribute value to. Defaults to empty string if
                  not provided.
        """
        self.__attrs[attr] = val

    def attribute(self, attr: str, default: Optional[str]=None) -> Optional[str]:
        """
        Get an attribute based on a string, or None if nonexistent.

        Parameters:
            attr - A string attribute to look up.

        Returns:
            The attribute value as a string.
        """
        return self.__attrs.get(attr, default)

    def add_child(self, child: 'Node') -> None:
        """
        Add a child Node to this node.

        Parameters:
            child - A Node to set as a child to this node.
        """
        if not isinstance(child, Node):
            raise NodeException('Invalid child')

        self.__children.append(child)

    def child(self, name: str) -> Optional['Node']:
        """
        Find a child by name.

        Parameters:
            name - String name of the child to find. If one or more
                   slashes is included, traverses each name, looking
                   up that child.

        Returns:
            A Node if a child was found by name, or None if not.
        """
        tree = name.split('/', 1)
        for child in self.__children:
            if child.name == tree[0]:
                if len(tree) == 1:
                    # We don't have any more nodes to traverse.
                    return child
                else:
                    # We have more nodes, try to get the next.
                    return child.child(tree[1])

        # There was no child by this name, return None.
        return None

    def child_value(self, name: str) -> Optional[Any]:
        """
        Find a child by name, and look up its value.

        Parameters:
            name - String name of child to find. Supports slashes similarly
                   to the above child() method.

        Returns:
            A value of the child node if the child was found, or None if not.
            Also returns None if the child is a void node.
        """
        child = self.child(name)
        if child is None:
            return None
        return child.value

    @property
    def children(self) -> List['Node']:
        """
        Wrapper for accessing children.

        Returns:
            A list of Node instances which are children of this Node.
        """
        return self.__children

    @property
    def attributes(self) -> Dict[str, str]:
        """
        Wrapper for accessing attributes.

        Returns:
            A dictionary keyed by attribute name whose values are strings.
        """
        return self.__attrs

    @property
    def is_array(self) -> _renamed_bool:
        """
        Wrapper for accessing array type.

        Returns:
            True if this Node is an array, False otherwise.
        """
        return self.__array

    @property
    def is_composite(self) -> _renamed_bool:
        """
        Returns whether or not this element is a composite type (basically
        an array, but packed differently).

        Returns:
            True if this Node is a composite type, False otherwise.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to fetch composite determination before setting type!')
        return self.__translated_type['composite']

    def set_value(self, val: Any) -> None:
        """
        Sets the value of this node. If this node is an array type (see Node.array boolean), expects an array. If
        not, expects a scalar value.

        Paramters:
            val - A mixed value to set the node to.
        """
        is_array = isinstance(val, (list, tuple))

        if self.__translated_type is None:
            raise Exception('Logic error, tried to set value before setting type!')
        translated_type: Dict[str, Any] = self.__translated_type

        # Handle composite types
        if translated_type['composite']:
            if not is_array:
                raise NodeException('Input is not array, expected array')
            if len(val) != len(translated_type['enc']):
                raise NodeException(f'Input array for {translated_type["name"]} expected to be {len(translated_type["enc"])} elements!')
            is_array = False
        if is_array != self.__array:
            raise NodeException(f'Input {"is" if is_array else "is not"} array, expected {"array" if self.__array else "scalar"}')

        def val_to_str(val: Any) -> Union[str, bytes]:
            if translated_type['name'] == 'bool':
                # Support user-built boolean types
                if val is True:
                    return 'true'
                if val is False:
                    return 'false'

                # Support construction from binary
                return 'true' if val != 0 else 'false'
            elif translated_type['name'] == 'float':
                return str(val)
            elif translated_type['name'] == 'ip4':
                try:
                    # Support construction from binary
                    ip = struct.unpack('BBBB', val)
                    return f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}'
                except (struct.error, TypeError):
                    # Assume that its user-built string?
                    if isinstance(val, str):
                        if len(val.split('.')) == 4:
                            return val

                    raise NodeException(f'Invalid value {val} for IP4 type')
            elif translated_type['int']:
                return str(val)
            else:
                # This could return either a string or bytes.
                return val

        if is_array or translated_type['composite']:
            self.__value = [val_to_str(v) for v in val]
        else:
            self.__value = val_to_str(val)

    @property
    def value(self) -> Any:
        """
        Gets the value of this node. If this node is an array type, returns an array. If no, returns a scalar.

        Returns:
            A mixed value corresponding to this node's value. The returned value will be of the correct data type.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to get value before setting type!')
        translated_type: Dict[str, Any] = self.__translated_type

        def str_to_val(string: Union[str, bytes]) -> Any:
            if translated_type['name'] == 'bool':
                return True if string == 'true' else False
            elif translated_type['name'] == 'float':
                return float(string)
            elif translated_type['name'] == 'ip4':
                if not isinstance(string, str):
                    raise Exception('Logic error, expected a string!')
                ip = [int(tup) for tup in string.split('.')]
                return struct.pack('BBBB', ip[0], ip[1], ip[2], ip[3])
            elif translated_type['int']:
                return int(string)
            else:
                # At this point, we could be a string or bytes.
                return string

        if self.__array or translated_type['composite']:
            return [str_to_val(v) for v in self.__value]
        else:
            return str_to_val(self.__value)

    def __to_xml(self, depth: int) -> str:
        """
        Convert this node, attributes and all children to an XML-like representation of the tree.

        Parameters:
            depth - Number of levels deep into the tree we currently are. If we shouldn't output
                    any depth, this should be set to None.

        Returns:
            A string representing the XML-like data for this node and all children.
        """
        if self.__translated_type is None:
            raise Exception('Logic error, tried to get XML representation before setting type!')
        translated_type: Dict[str, Any] = self.__translated_type

        attrs_dict = copy.deepcopy(self.__attrs)
        order = sorted(attrs_dict.keys())
        if self.data_length != 0:
            # Represent type and length
            if self.__array:
                if self.__value is None:
                    attrs_dict['__count'] = '0'
                else:
                    attrs_dict['__count'] = str(len(self.__value))
                order.insert(0, '__count')
            attrs_dict['__type'] = translated_type['name']
            order.insert(0, '__type')

        def escape(val: Any, attr: _renamed_bool=False) -> str:
            if isinstance(val, str):
                val = val.replace('&', '&amp;')
                val = val.replace('<', '&lt;')
                val = val.replace('>', '&gt;')
                val = val.replace('\'', '&apos;')
                val = val.replace('\"', '&quot;')
                if attr:
                    val = val.replace('\r', '&#13;')
                    val = val.replace('\n', '&#10;')

                return val
            else:
                return str(val)

        if attrs_dict:
            attrs = ' ' + ' '.join([f'{attr}="{escape(attrs_dict[attr], attr=True)}"' for attr in order])
        else:
            attrs = ''

        def get_val() -> str:
            if self.__array or translated_type['composite']:
                if self.__value is None:
                    vals = ''
                else:
                    vals = ' '.join([val for val in self.__value])
            elif translated_type['name'] == 'str':
                vals = escape(self.__value)
            elif translated_type['name'] == 'bin':
                # Convert to a hex string
                def bin_to_hex(binary: int) -> str:
                    val = hex(binary)[2:]
                    while len(val) < 2:
                        val = '0' + val
                    return val

                vals = ''.join([bin_to_hex(v) for v in self.__value])
            else:
                vals = str(self.__value)
            return vals

        if self.__children:
            # Has children nodes
            children = [child.__to_xml(depth=depth + 1) for child in self.__children]

            if self.data_length != 0:
                # Has children and a value
                children = [
                    f'{" " * ((depth + 1) * 4)}{get_val()}\n',
                ] + children

            string = f'{" " * (depth * 4)}<{self.__name}{attrs}>\n{"".join(children)}{" " * (depth * 4)}</{self.__name}>\n'
        else:
            # Doesn't have children nodes
            if self.data_length == 0:
                # Void node
                string = f'{" " * (depth * 4)}<{self.__name}{attrs} />\n'
            else:
                # Node with values
                string = f'{" " * (depth * 4)}<{self.__name}{attrs}>{get_val()}</{self.__name}>\n'

        return string

    def __str__(self) -> str:
        """
        Convenience function to auto-convert this node and children to XML if printed.

        Returns:
            A string that is parseable as valid XML, pretty printed.
        """
        return self.__to_xml(0)

    def __eq__(self, other: object) -> _renamed_bool:
        """
        Convenience function for comparing two nodes.

        Parameters:
            other - Another property node to compare this to.

        Returns:
            True if the name, value, all attributes and children match this node, False otherwise.
        """
        if not isinstance(other, Node):
            return False

        try:
            if self.__name != other.__name:
                return False
            if self.__array != other.__array:
                return False
            if self.__type != other.__type:
                return False

            if not self.__array:
                if self.__value != other.__value:
                    return False
            else:
                if len(self.__value) != len(other.__value):
                    return False

                for i in range(len(self.__value)):
                    if self.__value[i] != other.__value[i]:
                        return False

            for attr in self.__attrs:
                if other.attribute(attr) != self.attribute(attr):
                    return False
            for attr in other.__attrs:
                if self.attribute(attr) != other.attribute(attr):
                    return False

            if len(self.__children) != len(other.__children):
                return False

            for i in range(len(self.__children)):
                if self.__children[i] != other.__children[i]:
                    return False

            return True
        except Exception:
            return False

    def __ne__(self, other: object) -> _renamed_bool:
        """
        Convenience function for comparing two nodes.

        Parameters:
            other - Another Node to compare to.

        Returns:
            True if this node doesn't equal the other node, False if it does equal.
        """
        return not self.__eq__(other)
