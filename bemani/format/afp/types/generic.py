import math

from typing import Any, Dict, List, Tuple


class Color:
    # An RGBA color, represented as a series of floats between 0.0 and 1.0.
    # These can be multiplied or added against other colors to perform various
    # blending operations.
    def __init__(self, r: float, g: float, b: float, a: float) -> None:
        self.r = r
        self.g = g
        self.b = b
        self.a = a

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'r': self.r,
            'g': self.g,
            'b': self.b,
            'a': self.a,
        }

    def multiply(self, other: "Color") -> "Color":
        return Color(
            r=self.r * other.r,
            g=self.g * other.g,
            b=self.b * other.b,
            a=self.a * other.a,
        )

    def add(self, other: "Color") -> "Color":
        return Color(
            r=self.r + other.r,
            g=self.g + other.g,
            b=self.b + other.b,
            a=self.a + other.a,
        )

    def as_tuple(self) -> Tuple[int, int, int, int]:
        return (
            int(self.r * 255),
            int(self.g * 255),
            int(self.b * 255),
            int(self.a * 255),
        )

    def __repr__(self) -> str:
        return f"r: {round(self.r, 5)}, g: {round(self.g, 5)}, b: {round(self.b, 5)}, a: {round(self.a, 5)}"


class Point:
    # A simple 3D point. For ease of construction, the Z can be left out
    # at which point it is assumed to be zero.
    def __init__(self, x: float, y: float, z: float = 0.0) -> None:
        self.x = x
        self.y = y
        self.z = z

    @staticmethod
    def identity() -> "Point":
        return Point(0.0, 0.0, 0.0)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'x': self.x,
            'y': self.y,
            'z': self.z,
        }

    def as_tuple(self) -> Tuple[int, int, int]:
        return (int(round(self.x, 5)), int(round(self.y, 5)), int(round(self.z, 5)))

    def add(self, other: "Point") -> "Point":
        x = self.x + other.x
        y = self.y + other.y
        z = self.z + other.z
        return Point(x, y, z)

    def subtract(self, other: "Point") -> "Point":
        x = self.x - other.x
        y = self.y - other.y
        z = self.z - other.z
        return Point(x, y, z)

    def __repr__(self) -> str:
        return f"x: {round(self.x, 5)}, y: {round(self.y, 5)}, z: {round(self.z, 5)}"


class Rectangle:
    # A 2D rectangle, represented by its left/right/top/bottom bounds.
    def __init__(self, left: float, top: float, bottom: float, right: float) -> None:
        self.left = left
        self.top = top
        self.bottom = bottom
        self.right = right

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'left': self.left,
            'top': self.top,
            'bottom': self.bottom,
            'right': self.right,
        }

    @property
    def width(self) -> float:
        return self.right - self.left

    @property
    def height(self) -> float:
        return self.bottom - self.top

    def __repr__(self) -> str:
        return f"left: {round(self.left, 5)}, top: {round(self.top, 5)}, bottom: {round(self.bottom, 5)}, right: {round(self.right, 5)}"

    @staticmethod
    def Empty() -> "Rectangle":
        return Rectangle(left=0.0, right=0.0, top=0.0, bottom=0.0)


class Matrix:
    # A transformation matrix that can be used to calculate both affine and perspective
    # transforms. This is a 4x4 matrix where the final column is assumed to be 0, 0, 0, 1.
    # Note that for ease of construction and use with 2D-only parts of the rendering engine
    # this is capable of being used as a standard 2D affine transformation matrix, as documented
    # in the next paragraph.

    # The classic SWF matrix. Technically it is missing the third column, but that
    # column never changes and thus can be omitted. Includes operations for multiplying
    # 2D points as well as other matrixes and inverting itself. This is how SWF (and
    # as a result, AFP) performs its affine transformations on objects that are placed.
    #
    # The matrix, if laid out, looks as follows:
    #
    # | a  b  0 |
    # | c  d  0 |
    # | tx ty 1 |

    def __init__(
        self, *,
        a11: float, a12: float, a13: float,
        a21: float, a22: float, a23: float,
        a31: float, a32: float, a33: float,
        a41: float, a42: float, a43: float,
    ) -> None:
        self.a11 = a11
        self.a12 = a12
        self.a13 = a13
        self.a21 = a21
        self.a22 = a22
        self.a23 = a23
        self.a31 = a31
        self.a32 = a32
        self.a33 = a33
        self.a41 = a41
        self.a42 = a42
        self.a43 = a43

    @staticmethod
    def identity() -> "Matrix":
        return Matrix(
            a11=1.0, a12=0.0, a13=0.0,
            a21=0.0, a22=1.0, a23=0.0,
            a31=0.0, a32=0.0, a33=1.0,
            a41=0.0, a42=0.0, a43=0.0,
        )

    @staticmethod
    def affine(*, a: float, b: float, c: float, d: float, tx: float, ty: float) -> "Matrix":
        return Matrix(
            a11=a, a12=b, a13=0.0,
            a21=c, a22=d, a23=0.0,
            a31=0.0, a32=0.0, a33=1.0,
            a41=tx, a42=ty, a43=0.0,
        )

    def __is_affine(self) -> bool:
        return (
            round(abs(self.a13), 5) == 0.0 and
            round(abs(self.a23), 5) == 0.0 and
            round(abs(self.a31), 5) == 0.0 and
            round(abs(self.a32), 5) == 0.0 and
            round(self.a33, 5) == 1.0 and
            round(abs(self.a43), 5) == 0.0
        )

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if self.__is_affine:
            return {
                'a': self.a,
                'b': self.b,
                'c': self.c,
                'd': self.d,
                'tx': self.tx,
                'ty': self.ty,
            }
        else:
            return {
                'a11': self.a11,
                'a12': self.a12,
                'a13': self.a13,
                'a21': self.a21,
                'a22': self.a22,
                'a23': self.a23,
                'a31': self.a31,
                'a32': self.a32,
                'a33': self.a33,
                'a41': self.a41,
                'a42': self.a42,
                'a43': self.a43,
            }

    @property
    def xscale(self) -> float:
        return math.sqrt((self.a11 * self.a11) + (self.a12 * self.a12) + (self.a13 * self.a13))

    @property
    def yscale(self) -> float:
        return math.sqrt((self.a21 * self.a21) + (self.a22 * self.a22) + (self.a23 * self.a23))

    @property
    def a(self) -> float:
        return self.a11

    @a.setter
    def a(self, val: float) -> None:
        self.a11 = val

    @property
    def b(self) -> float:
        return self.a12

    @b.setter
    def b(self, val: float) -> None:
        self.a12 = val

    @property
    def c(self) -> float:
        return self.a21

    @c.setter
    def c(self, val: float) -> None:
        self.a21 = val

    @property
    def d(self) -> float:
        return self.a22

    @d.setter
    def d(self, val: float) -> None:
        self.a22 = val

    @property
    def tx(self) -> float:
        return self.a41

    @tx.setter
    def tx(self, val: float) -> None:
        self.a41 = val

    @property
    def ty(self) -> float:
        return self.a42

    @ty.setter
    def ty(self, val: float) -> None:
        self.a42 = val

    @property
    def tz(self) -> float:
        return self.a43

    @tz.setter
    def tz(self, val: float) -> None:
        self.a43 = val

    def multiply_point(self, point: Point) -> Point:
        return Point(
            x=(self.a11 * point.x) + (self.a21 * point.y) + (self.a31 * point.z) + self.a41,
            y=(self.a12 * point.x) + (self.a22 * point.y) + (self.a32 * point.z) + self.a42,
            z=(self.a13 * point.x) + (self.a23 * point.y) + (self.a33 * point.z) + self.a43,
        )

    def translate(self, point: Point) -> "Matrix":
        new_point = self.multiply_point(point)
        return Matrix(
            a11=self.a11,
            a12=self.a12,
            a13=self.a13,
            a21=self.a21,
            a22=self.a22,
            a23=self.a23,
            a31=self.a31,
            a32=self.a32,
            a33=self.a33,
            a41=new_point.x,
            a42=new_point.y,
            a43=new_point.z,
        )

    def multiply(self, other: "Matrix") -> "Matrix":
        return Matrix(
            a11=self.a11 * other.a11 + self.a12 * other.a21 + self.a13 * other.a31,
            a12=self.a11 * other.a12 + self.a12 * other.a22 + self.a13 * other.a32,
            a13=self.a11 * other.a13 + self.a12 * other.a23 + self.a13 * other.a33,

            a21=self.a21 * other.a11 + self.a22 * other.a21 + self.a23 * other.a31,
            a22=self.a21 * other.a12 + self.a22 * other.a22 + self.a23 * other.a32,
            a23=self.a21 * other.a13 + self.a22 * other.a23 + self.a23 * other.a33,

            a31=self.a31 * other.a11 + self.a32 * other.a21 + self.a33 * other.a31,
            a32=self.a31 * other.a12 + self.a32 * other.a22 + self.a33 * other.a32,
            a33=self.a31 * other.a13 + self.a32 * other.a23 + self.a33 * other.a33,

            a41=self.a41 * other.a11 + self.a42 * other.a21 + self.a43 * other.a31 + other.a41,
            a42=self.a41 * other.a12 + self.a42 * other.a22 + self.a43 * other.a32 + other.a42,
            a43=self.a41 * other.a13 + self.a42 * other.a23 + self.a43 * other.a33 + other.a43,
        )

    def inverse(self) -> "Matrix":
        # Use gauss-jordan eliminiation to invert the matrix.
        size = 4
        m = [
            [self.a11, self.a12, self.a13, 0.0],
            [self.a21, self.a22, self.a23, 0.0],
            [self.a31, self.a32, self.a33, 0.0],
            [self.a41, self.a42, self.a43, 1.0],
        ]
        inverse: List[List[float]] = [[1 if row == col else 0 for col in range(size)] for row in range(size)]

        # First, get upper triangle of the matrix.
        for col in range(size):
            if col < size - 1:
                numbers = [m[row][col] for row in range(col, size)]
                if all(n == 0 for n in numbers):
                    print("HOO!")
                    raise ZeroDivisionError(f"Matrix({self}) cannot be inverted!")

                # Reorder the matrix until all nonzero numbers are at the top.
                for row in range(col, size - 1):
                    # First, make sure all non-zero values are at the top.
                    nrow = row - col
                    if numbers[nrow] == 0:
                        # Put this at the end.
                        numbers = [
                            *numbers[:nrow],
                            *numbers[(nrow + 1):],
                            numbers[nrow],
                        ]
                        m = [
                            *m[:row],
                            *m[(row + 1):],
                            m[row],
                        ]
                        inverse = [
                            *inverse[:row],
                            *inverse[(row + 1):],
                            inverse[row],
                        ]
                    row += 1

            # Now, figure out what multiplier we need to make every
            # other entry zero.
            major = m[col][col]

            for row in range(size):
                if row == col:
                    continue
                if m[row][col] != 0:
                    factor = -(m[row][col] / major)

                    m = [
                        *m[:row],
                        [m[row][i] + m[col][i] * factor for i in range(size)],
                        *m[(row + 1):],
                    ]
                    inverse = [
                        *inverse[:row],
                        [inverse[row][i] + inverse[col][i] * factor for i in range(size)],
                        *inverse[(row + 1):],
                    ]

            # Finally, divide the current column to make it a unit.
            factor = 1 / m[col][col]
            m = [
                *m[:col],
                [e * factor for e in m[col]],
                *m[(col + 1):],
            ]
            inverse = [
                *inverse[:col],
                [e * factor for e in inverse[col]],
                *inverse[(col + 1):],
            ]

        # Technically the rest of the matrix that we don't care about could have values other
        # than 0.0, 0.0, 0.0, 1.0 but in practice that's because of floating point errors
        # accumulating so we simply trust the math and discard those values.
        return Matrix(
            a11=inverse[0][0], a12=inverse[0][1], a13=inverse[0][2],
            a21=inverse[1][0], a22=inverse[1][1], a23=inverse[1][2],
            a31=inverse[2][0], a32=inverse[2][1], a33=inverse[2][2],
            a41=inverse[3][0], a42=inverse[3][1], a43=inverse[3][2],
        )

    def __repr__(self) -> str:
        if self.__is_affine:
            return f"a: {round(self.a, 5)}, b: {round(self.b, 5)}, c: {round(self.c, 5)}, d: {round(self.d, 5)}, tx: {round(self.tx, 5)}, ty: {round(self.ty, 5)}"
        else:
            return "; ".join([
                f"a11: {round(self.a11, 5)}, a12: {round(self.a12, 5)}, a13: {round(self.a13, 5)}",
                f"a21: {round(self.a21, 5)}, a22: {round(self.a22, 5)}, a23: {round(self.a23, 5)}",
                f"a31: {round(self.a31, 5)}, a32: {round(self.a32, 5)}, a33: {round(self.a33, 5)}",
                f"a41: {round(self.a41, 5)}, a42: {round(self.a42, 5)}, a43: {round(self.a43, 5)}",
            ])
