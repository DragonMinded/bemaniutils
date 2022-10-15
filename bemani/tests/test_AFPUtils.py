# vim: set fileencoding=utf-8
import unittest

from bemani.utils.afputils import parse_intlist, adjust_background_loop


class TestAFPUtils(unittest.TestCase):
    def test_parse_intlist(self) -> None:
        # Simple
        self.assertEqual(
            parse_intlist("5"),
            [5],
        )

        # Comma separated
        self.assertEqual(
            parse_intlist("5,7,9"),
            [5, 7, 9],
        )

        # Range
        self.assertEqual(
            parse_intlist("5-9"),
            [5, 6, 7, 8, 9],
        )

        # Duplicate
        self.assertEqual(
            parse_intlist("5,7,7,9"),
            [5, 7, 9],
        )

        # Overlapping range
        self.assertEqual(
            parse_intlist("5-9,8-10"),
            [5, 6, 7, 8, 9, 10],
        )

        # Out of order
        self.assertEqual(
            parse_intlist("5,3,1"),
            [1, 3, 5],
        )

        # All manner of combos
        self.assertEqual(
            parse_intlist("5,13-17,23,9,27-29,23,33"),
            [5, 9, 13, 14, 15, 16, 17, 23, 27, 28, 29, 33],
        )

    def test_adjust_background_loop(self) -> None:
        # No adjustment
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=None,
                background_loop_end=None,
                background_loop_offset=None,
            ),
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )

        # Specify start
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=6,
                background_loop_end=None,
                background_loop_offset=None,
            ),
            [6, 7, 8, 9, 10],
        )

        # Specify end
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5],
                background_loop_start=None,
                background_loop_end=5,
                background_loop_offset=None,
            ),
            [1, 2, 3, 4, 5],
        )

        # Specify start and end
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=5,
                background_loop_end=9,
                background_loop_offset=None,
            ),
            [5, 6, 7, 8, 9],
        )

        # Specify loop offset
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=None,
                background_loop_end=None,
                background_loop_offset=7,
            ),
            [7, 8, 9, 10, 1, 2, 3, 4, 5, 6],
        )

        # Specify start and loop offset
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=6,
                background_loop_end=None,
                background_loop_offset=8,
            ),
            [8, 9, 10, 6, 7],
        )

        # Specify end and loop offset
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5],
                background_loop_start=None,
                background_loop_end=5,
                background_loop_offset=3,
            ),
            [3, 4, 5, 1, 2],
        )

        # Specify start, end and loop offset
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=5,
                background_loop_end=9,
                background_loop_offset=6,
            ),
            [6, 7, 8, 9, 5],
        )

        # Only one frame.
        self.assertEqual(
            adjust_background_loop(
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                background_loop_start=5,
                background_loop_end=5,
                background_loop_offset=None,
            ),
            [5],
        )
