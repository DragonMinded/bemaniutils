# vim: set fileencoding=utf-8
import unittest

from bemani.protocol.xml import XmlDecoder


class TestXmlDecoder(unittest.TestCase):
    def test_detect_encoding(self) -> None:
        xml = XmlDecoder(b'<?xml version="1.0" encoding="utf-8"?>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(xml.encoding, "utf-8")
        self.assertEqual(tree, None)

        xml = XmlDecoder(b'<?xml\nversion = "1.0"\tencoding   =   "utf-8"?>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(xml.encoding, "utf-8")
        self.assertEqual(tree, None)

    def test_decode_void(self) -> None:
        xml = XmlDecoder(b"<node></node>", "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "void")
        self.assertEqual(tree.value, None)

        xml = XmlDecoder(b"<node />", "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "void")
        self.assertEqual(tree.value, None)

    def test_decode_attributes(self) -> None:
        xml = XmlDecoder(b'<node attr1="foo" attr2="bar"></node>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {"attr1": "foo", "attr2": "bar"})
        self.assertEqual(tree.data_type, "void")
        self.assertEqual(tree.value, None)

        xml = XmlDecoder(b'<node attr1="foo" attr2="bar" />', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {"attr1": "foo", "attr2": "bar"})
        self.assertEqual(tree.data_type, "void")
        self.assertEqual(tree.value, None)

        xml = XmlDecoder(b'<node\nattr1="foo"\tattr2="bar"/>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {"attr1": "foo", "attr2": "bar"})
        self.assertEqual(tree.data_type, "void")
        self.assertEqual(tree.value, None)

    def test_decode_bin(self) -> None:
        xml = XmlDecoder(b'<node __type="bin">DEADBEEF</node>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "bin")
        self.assertEqual(tree.value, b"\xDE\xAD\xBE\xEF")

        xml = XmlDecoder(b'<node __type="bin">\nDEADBEEF\n</node>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "bin")
        self.assertEqual(tree.value, b"\xDE\xAD\xBE\xEF")

        xml = XmlDecoder(b'<node __type="bin"> D E A D B E E F </node>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "bin")
        self.assertEqual(tree.value, b"\xDE\xAD\xBE\xEF")

    def test_decode_array(self) -> None:
        xml = XmlDecoder(b'<node __type="u32" __count="4">1 2 3 4</node>', "ascii")
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "u32")
        self.assertEqual(tree.value, [1, 2, 3, 4])

        xml = XmlDecoder(
            b'<node __type="u32" __count="4">\n1\n2\n3\n4\n</node>', "ascii"
        )
        tree = xml.get_tree()

        self.assertEqual(tree.children, [])
        self.assertEqual(tree.name, "node")
        self.assertEqual(tree.attributes, {})
        self.assertEqual(tree.data_type, "u32")
        self.assertEqual(tree.value, [1, 2, 3, 4])
