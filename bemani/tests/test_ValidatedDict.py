# vim: set fileencoding=utf-8
import unittest

from bemani.common import ValidatedDict, intish


class TestIntish(unittest.TestCase):
    def test_none(self) -> None:
        self.assertEqual(intish(None), None)

    def test_int(self) -> None:
        self.assertEqual(intish("3"), 3)

    def test_str(self) -> None:
        self.assertEqual(intish("str"), None)


class TestValidatedDict(unittest.TestCase):
    def test_empty_dict(self) -> None:
        # Empty dictionary gets
        validict = ValidatedDict()

        self.assertEqual(validict.get_int("int"), 0)
        self.assertEqual(validict.get_int("int", 2), 2)
        self.assertEqual(validict.get_float("float"), 0.0)
        self.assertEqual(validict.get_float("float", 2.0), 2.0)
        self.assertEqual(validict.get_bool("bool"), False)
        self.assertEqual(validict.get_bool("bool", True), True)
        self.assertEqual(validict.get_str("str"), "")
        self.assertEqual(validict.get_str("str", "test"), "test")
        self.assertEqual(validict.get_bytes("bytes"), b"")
        self.assertEqual(validict.get_bytes("bytes", b"test"), b"test")
        self.assertEqual(validict.get_int_array("int_array", 3), [0, 0, 0])
        self.assertEqual(validict.get_int_array("int_array", 3, [1, 2, 3]), [1, 2, 3])
        self.assertEqual(validict.get_bool_array("bool_array", 2), [False, False])
        self.assertEqual(validict.get_bool_array("bool_array", 2, [False, True]), [False, True])
        self.assertEqual(validict.get_str_array("str_array", 3), ["", "", ""])
        self.assertEqual(validict.get_str_array("str_array", 3, ["1", "2", "3"]), ["1", "2", "3"])
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"", b"", b""])
        self.assertEqual(
            validict.get_bytes_array("bytes_array", 3, [b"1", b"2", b"3"]),
            [b"1", b"2", b"3"],
        )
        self.assertTrue(isinstance(validict.get_dict("dict"), dict))
        self.assertEqual(validict.get_dict("dict").get_int("test"), 0)

    def test_normal_dict(self) -> None:
        # Existing info gets
        validict = ValidatedDict(
            {
                "int": 5,
                "float": 5.5,
                "bool": True,
                "str": "foobar",
                "bytes": b"foobar",
                "int_array": [3, 2, 1],
                "bool_array": [True, False],
                "str_array": ["3", "4", "5"],
                "bytes_array": [b"3", b"5", b"7"],
                "dict": {"test": 123},
            }
        )
        self.assertEqual(validict.get_int("int"), 5)
        self.assertEqual(validict.get_int("int", 2), 5)
        self.assertEqual(validict.get_float("float"), 5.5)
        self.assertEqual(validict.get_float("float", 2.0), 5.5)
        self.assertEqual(validict.get_bool("bool"), True)
        self.assertEqual(validict.get_bool("bool", False), True)
        self.assertEqual(validict.get_str("str"), "foobar")
        self.assertEqual(validict.get_str("str", "test"), "foobar")
        self.assertEqual(validict.get_bytes("bytes"), b"foobar")
        self.assertEqual(validict.get_bytes("bytes", b"test"), b"foobar")
        self.assertEqual(validict.get_int_array("int_array", 3), [3, 2, 1])
        self.assertEqual(validict.get_int_array("int_array", 3, [1, 2, 3]), [3, 2, 1])
        self.assertEqual(validict.get_bool_array("bool_array", 2), [True, False])
        self.assertEqual(validict.get_bool_array("bool_array", 2, [False, True]), [True, False])
        self.assertEqual(validict.get_str_array("str_array", 3), ["3", "4", "5"])
        self.assertEqual(validict.get_str_array("str_array", 3, ["1", "2", "3"]), ["3", "4", "5"])
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"3", b"5", b"7"])
        self.assertEqual(
            validict.get_bytes_array("bytes_array", 3, [b"1", b"2", b"3"]),
            [b"3", b"5", b"7"],
        )
        self.assertTrue(isinstance(validict.get_dict("dict"), dict))
        self.assertEqual(validict.get_dict("dict").get_int("test"), 123)

    def test_default_on_invalid(self) -> None:
        # Default on invalid info stored
        validict = ValidatedDict(
            {
                "int": "five",
                "float": "five",
                "bool": "true",
                "str": 123,
                "bytes": "str",
                "int_array": [3, 2, 1, 0],
                "bool_array": [True, False],
                "str_array": ["3", "2", "1", "0"],
                "bytes_array": [b"3", b"2", b"1", b"0"],
                "dict": "not_a_dict",
            }
        )
        self.assertEqual(validict.get_int("int"), 0)
        self.assertEqual(validict.get_int("int", 2), 2)
        self.assertEqual(validict.get_float("float"), 0.0)
        self.assertEqual(validict.get_float("float", 2.0), 2.0)
        self.assertEqual(validict.get_bool("bool"), False)
        self.assertEqual(validict.get_bool("bool", True), True)
        self.assertEqual(validict.get_str("str"), "")
        self.assertEqual(validict.get_str("str", "test"), "test")
        self.assertEqual(validict.get_bytes("bytes"), b"")
        self.assertEqual(validict.get_bytes("bytes", b"test"), b"test")
        self.assertEqual(validict.get_int_array("int_array", 3), [0, 0, 0])
        self.assertEqual(validict.get_int_array("int_array", 3, [1, 2, 3]), [1, 2, 3])
        self.assertEqual(validict.get_bool_array("bool_array", 3), [False, False, False])
        self.assertEqual(
            validict.get_bool_array("bool_array", 3, [False, True, True]),
            [False, True, True],
        )
        self.assertEqual(validict.get_str_array("str_array", 3), ["", "", ""])
        self.assertEqual(validict.get_str_array("str_array", 3, ["1", "2", "3"]), ["1", "2", "3"])
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"", b"", b""])
        self.assertEqual(
            validict.get_bytes_array("bytes_array", 3, [b"1", b"2", b"3"]),
            [b"1", b"2", b"3"],
        )
        self.assertTrue(isinstance(validict.get_dict("dict"), dict))
        self.assertEqual(validict.get_dict("dict").get_int("test"), 0)

    def test_replace_int(self) -> None:
        # Verify replace int
        validict = ValidatedDict(
            {
                "int": 5,
            }
        )
        validict.replace_int("int", 3)
        self.assertEqual(validict.get_int("int"), 3)
        validict.replace_int("int", None)
        self.assertEqual(validict.get_int("int"), 3)
        validict.replace_int("int", "three")
        self.assertEqual(validict.get_int("int"), 3)

    def test_replace_float(self) -> None:
        # Verify replace float
        validict = ValidatedDict(
            {
                "float": 5.0,
            }
        )
        validict.replace_float("float", 3.0)
        self.assertEqual(validict.get_float("float"), 3.0)
        validict.replace_float("float", None)
        self.assertEqual(validict.get_float("float"), 3.0)
        validict.replace_float("float", "three")
        self.assertEqual(validict.get_float("float"), 3.0)

    def test_replace_bool(self) -> None:
        # Verify replace bool
        validict = ValidatedDict(
            {
                "bool": False,
            }
        )
        validict.replace_bool("bool", True)
        self.assertEqual(validict.get_bool("bool"), True)
        validict.replace_bool("bool", None)
        self.assertEqual(validict.get_bool("bool"), True)
        validict.replace_bool("bool", "three")
        self.assertEqual(validict.get_bool("bool"), True)

    def test_replace_str(self) -> None:
        # Verify replace str
        validict = ValidatedDict(
            {
                "str": "blah",
            }
        )
        validict.replace_str("str", "foobar")
        self.assertEqual(validict.get_str("str"), "foobar")
        validict.replace_str("str", None)
        self.assertEqual(validict.get_str("str"), "foobar")
        validict.replace_str("str", 5)
        self.assertEqual(validict.get_str("str"), "foobar")

    def test_replace_bytes(self) -> None:
        # Verify replace bytes
        validict = ValidatedDict(
            {
                "bytes": "blah",
            }
        )
        validict.replace_bytes("bytes", b"foobar")
        self.assertEqual(validict.get_bytes("bytes"), b"foobar")
        validict.replace_bytes("bytes", None)
        self.assertEqual(validict.get_bytes("bytes"), b"foobar")
        validict.replace_bytes("bytes", 5)
        self.assertEqual(validict.get_bytes("bytes"), b"foobar")

    def test_replace_int_array(self) -> None:
        # Verify replace int_array
        validict = ValidatedDict({"int_array": [1, 2, 3]})
        validict.replace_int_array("int_array", 3, [3, 2, 1])
        self.assertEqual(validict.get_int_array("int_array", 3), [3, 2, 1])
        validict.replace_int_array("int_array", 3, None)
        self.assertEqual(validict.get_int_array("int_array", 3), [3, 2, 1])
        validict.replace_int_array("int_array", 3, "bla")
        self.assertEqual(validict.get_int_array("int_array", 3), [3, 2, 1])
        validict.replace_int_array("int_array", 3, [3, 2, 1, 0])
        self.assertEqual(validict.get_int_array("int_array", 3), [3, 2, 1])

    def test_replace_bool_array(self) -> None:
        # Verify replace bool_array
        validict = ValidatedDict(
            {
                "bool_array": [False, True],
            }
        )
        validict.replace_bool_array("bool_array", 2, [True, False])
        self.assertEqual(validict.get_bool_array("bool_array", 2), [True, False])
        validict.replace_bool_array("bool_array", 2, None)
        self.assertEqual(validict.get_bool_array("bool_array", 2), [True, False])
        validict.replace_bool_array("bool_array", 2, "bla")
        self.assertEqual(validict.get_bool_array("bool_array", 2), [True, False])
        validict.replace_bool_array("bool_array", 2, [True, True, True])
        self.assertEqual(validict.get_bool_array("bool_array", 2), [True, False])

    def test_replace_str_array(self) -> None:
        # Verify replace str_array
        validict = ValidatedDict({"str_array": ["1", "2", "3"]})
        validict.replace_str_array("str_array", 3, ["3", "2", "1"])
        self.assertEqual(validict.get_str_array("str_array", 3), ["3", "2", "1"])
        validict.replace_str_array("str_array", 3, None)
        self.assertEqual(validict.get_str_array("str_array", 3), ["3", "2", "1"])
        validict.replace_str_array("str_array", 3, "bla")
        self.assertEqual(validict.get_str_array("str_array", 3), ["3", "2", "1"])
        validict.replace_str_array("str_array", 3, ["3", "2", "1", "0"])
        self.assertEqual(validict.get_str_array("str_array", 3), ["3", "2", "1"])

    def test_replace_bytes_array(self) -> None:
        # Verify replace bytes_array
        validict = ValidatedDict({"bytes_array": [b"1", b"2", b"3"]})
        validict.replace_bytes_array("bytes_array", 3, [b"3", b"2", b"1"])
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"3", b"2", b"1"])
        validict.replace_bytes_array("bytes_array", 3, None)
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"3", b"2", b"1"])
        validict.replace_bytes_array("bytes_array", 3, "bla")
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"3", b"2", b"1"])
        validict.replace_bytes_array("bytes_array", 3, [b"3", b"2", b"1", b"0"])
        self.assertEqual(validict.get_bytes_array("bytes_array", 3), [b"3", b"2", b"1"])

    def test_replace_dict(self) -> None:
        # Verify replace dict
        validict = ValidatedDict(
            {
                "dict": {},
            }
        )
        validict.replace_dict("dict", {"yay": "bla"})
        self.assertTrue(isinstance(validict.get_dict("dict"), dict))
        self.assertEqual(validict.get_dict("dict").get_str("yay"), "bla")
        validict.replace_dict("dict", None)
        self.assertEqual(validict.get_dict("dict").get_str("yay"), "bla")
        validict.replace_dict("dict", "three")
        self.assertEqual(validict.get_dict("dict").get_str("yay"), "bla")

    def test_increment_int(self) -> None:
        # Verify increment_int
        validict = ValidatedDict(
            {
                "int": 5,
                "int2": "str",
            }
        )
        validict.increment_int("int")
        self.assertEqual(validict.get_int("int"), 6)
        validict.increment_int("int2")
        self.assertEqual(validict.get_int("int2"), 1)
        validict.increment_int("int3")
        self.assertEqual(validict.get_int("int3"), 1)
