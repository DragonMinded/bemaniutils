# vim: set fileencoding=utf-8
import struct
import unittest
import random
from unittest.mock import Mock
from typing import List

from bemani.backend.iidx.pendual import IIDXPendual
from bemani.data import Score


class TestIIDXPendual(unittest.TestCase):
    def __make_score(self, ghost: List[int]) -> Score:
        return Score(
            0,
            0,
            0,
            sum(ghost),
            1234567890,
            1234567890,
            0,
            1,
            {
                "ghost": bytes(ghost),
            },
        )

    def test_average_no_scores(self) -> None:
        base = IIDXPendual(Mock(), Mock(), Mock())
        self.assertEqual(
            base.delta_score([], 3),
            (None, None),
        )

    def test_average_identity(self) -> None:
        base = IIDXPendual(Mock(), Mock(), Mock())
        self.assertEqual(
            base.delta_score(
                [
                    self.__make_score([10, 20, 30]),
                ],
                3,
            ),
            (60, struct.pack("bbb", *[-10, 0, 10])),
        )

    def test_average_basic(self) -> None:
        base = IIDXPendual(Mock(), Mock(), Mock())
        self.assertEqual(
            base.delta_score(
                [
                    self.__make_score([10, 20, 30]),
                    self.__make_score([0, 0, 0]),
                ],
                3,
            ),
            (30, struct.pack("bbb", *[-5, 0, 5])),
        )

    def test_average_complex(self) -> None:
        base = IIDXPendual(Mock(), Mock(), Mock())
        self.assertEqual(
            base.delta_score(
                [
                    self.__make_score([10, 20, 30]),
                    self.__make_score([20, 30, 40]),
                    self.__make_score([30, 40, 50]),
                ],
                3,
            ),
            (90, struct.pack("bbb", *[-10, 0, 10])),
        )

    def test_average_always_zero(self) -> None:
        base = IIDXPendual(Mock(), Mock(), Mock())
        ex_score, ghost = base.delta_score(
            [
                self.__make_score([random.randint(0, 10) for _ in range(64)]),
                self.__make_score([random.randint(0, 10) for _ in range(64)]),
            ],
            64,
        )
        self.assertEqual(sum(struct.unpack("b" * 64, ghost)), 0)
