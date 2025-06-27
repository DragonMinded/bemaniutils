# vim: set fileencoding=utf-8
from abc import ABC
import unittest

from bemani.common import Parallel


class TestParallel(unittest.TestCase):
    def test_empty(self) -> None:
        results = Parallel.execute([])
        self.assertEqual(results, [])
        results = Parallel.map(lambda x: x, [])
        self.assertEqual(results, [])
        results = Parallel.call([])
        self.assertEqual(results, [])
        results = Parallel.flatten([])
        self.assertEqual(results, [])

    def test_basic(self) -> None:
        results = Parallel.execute(
            [
                lambda: 1,
                lambda: 2,
                lambda: 3,
                lambda: 4,
                lambda: 5,
            ]
        )
        self.assertEqual(results, [1, 2, 3, 4, 5])

    def test_function(self) -> None:
        def fun(x: int) -> int:
            return -x

        results = Parallel.execute(
            [
                lambda: fun(1),
                lambda: fun(2),
                lambda: fun(3),
                lambda: fun(4),
                lambda: fun(5),
            ]
        )
        self.assertEqual(results, [-1, -2, -3, -4, -5])

    def test_map(self) -> None:
        def fun(x: int) -> int:
            return x * 2

        results = Parallel.map(fun, [1, 2, 3, 4, 5])
        self.assertEqual(results, [2, 4, 6, 8, 10])

    def test_call(self) -> None:
        def fun1(x: int) -> int:
            return x * 10

        def fun2(x: int) -> int:
            return -x * 10

        def fun3(x: int) -> int:
            return x * 2

        def fun4(x: int) -> int:
            return -x * 2

        def fun5(x: int) -> int:
            return x

        results = Parallel.call([fun1, fun2, fun3, fun4, fun5], 2)
        self.assertEqual(results, [20, -20, 4, -4, 2])

    def test_class(self) -> None:
        class Base(ABC):
            def fun(self, x: int) -> int: ...

        class A(Base):
            def fun(self, x: int) -> int:
                return x * 10

        class B(Base):
            def fun(self, x: int) -> int:
                return x * 20

        class C(Base):
            def fun(self, x: int) -> int:
                return x * 30

        class D(Base):
            def fun(self, x: int) -> int:
                return x * 40

        class E(Base):
            def fun(self, x: int) -> int:
                return x * 50

        classes = [A(), B(), C(), D(), E()]
        results = Parallel.call([c.fun for c in classes], 2)
        self.assertEqual(results, [20, 40, 60, 80, 100])

    def test_flatten(self) -> None:
        results = Parallel.flatten([[1, 2, 3], [4, 5, 6], [7, 8, 9], []])
        self.assertEqual(results, [1, 2, 3, 4, 5, 6, 7, 8, 9])
