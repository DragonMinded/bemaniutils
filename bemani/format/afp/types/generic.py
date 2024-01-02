import colorsys
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
            "r": self.r,
            "g": self.g,
            "b": self.b,
            "a": self.a,
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

    def as_hsl(self) -> "HSL":
        h, l, s = colorsys.rgb_to_hls(self.r, self.g, self.b)
        return HSL(h, s, l)

    def as_tuple(self) -> Tuple[int, int, int, int]:
        return (
            int(self.r * 255),
            int(self.g * 255),
            int(self.b * 255),
            int(self.a * 255),
        )

    def __repr__(self) -> str:
        return f"r: {round(self.r, 5)}, g: {round(self.g, 5)}, b: {round(self.b, 5)}, a: {round(self.a, 5)}"


class HSL:
    # A hue/saturation/lightness color shift, represented as a series of floats between
    # -1.0 and 1.0. The hue represents a percentage along the polar coordinates,
    # 0.0 being 0 degrees, -1.0 being -360 degrees and 1.0 being 360 degrees. The
    # saturation and lightness values representing actual normalized percentages where
    # a lightness of 100 would be written as 1.0.
    def __init__(self, h: float, s: float, l: float) -> None:
        self.h = h
        self.s = s
        self.l = l

    @property
    def is_identity(self) -> bool:
        return self.h == 0.0 and self.s == 0.0 and self.l == 0.0

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "h": self.h,
            "s": self.s,
            "l": self.l,
        }

    def add(self, other: "HSL") -> "HSL":
        # Not entirely sure this is correct, but we don't have any animations to compare to.
        # Basically, not sure if HSL colorspace is linear in this way, but as long as no
        # animations try to stack multiple HSL shift effects this shouldn't matter.
        return HSL(h=self.h + other.h, s=self.s + other.s, l=self.l + other.l)

    def as_rgb(self) -> "Color":
        h = self.h
        while h < 0.0:
            h += 1.0
        while h > 1.0:
            h -= 1.0

        s = min(max(self.s, 0.0), 1.0)
        l = min(max(self.l, 0.0), 1.0)
        r, g, b = colorsys.hls_to_rgb(h, l, s)
        return Color(r, g, b, 1.0)

    def as_tuple(self) -> Tuple[int, int, int]:
        h = int(self.h * 360)
        while h < 0:
            h += 360
        while h > 360:
            h -= 360

        s = min(max(int(self.s), -100), 100)
        l = min(max(int(self.l), -100), 100)
        return (h, s, l)

    def __repr__(self) -> str:
        return f"h: {round(self.h, 5)}, s: {round(self.s, 5)}, l: {round(self.l, 5)}"


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
            "x": self.x,
            "y": self.y,
            "z": self.z,
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
            "left": self.left,
            "top": self.top,
            "bottom": self.bottom,
            "right": self.right,
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
        self,
        *,
        a11: float,
        a12: float,
        a13: float,
        a21: float,
        a22: float,
        a23: float,
        a31: float,
        a32: float,
        a33: float,
        a41: float,
        a42: float,
        a43: float,
    ) -> None:
        self.__a11 = a11
        self.__a12 = a12
        self.__a13 = a13
        self.__a21 = a21
        self.__a22 = a22
        self.__a23 = a23
        self.__a31 = a31
        self.__a32 = a32
        self.__a33 = a33
        self.__a41 = a41
        self.__a42 = a42
        self.__a43 = a43
        self.__scale_set = True
        self.__rotate_set = True
        self.__translate_xy_set = True
        self.__translate_z_set = True
        self.__3d_grid_set = True

    @staticmethod
    def identity() -> "Matrix":
        new = Matrix(
            a11=1.0,
            a12=0.0,
            a13=0.0,
            a21=0.0,
            a22=1.0,
            a23=0.0,
            a31=0.0,
            a32=0.0,
            a33=1.0,
            a41=0.0,
            a42=0.0,
            a43=0.0,
        )
        new.__scale_set = False
        new.__rotate_set = False
        new.__translate_xy_set = False
        new.__translate_z_set = False
        new.__3d_grid_set = False
        return new

    @staticmethod
    def affine(*, a: float, b: float, c: float, d: float, tx: float, ty: float) -> "Matrix":
        return Matrix(
            a11=a,
            a12=b,
            a13=0.0,
            a21=c,
            a22=d,
            a23=0.0,
            a31=0.0,
            a32=0.0,
            a33=1.0,
            a41=tx,
            a42=ty,
            a43=0.0,
        )

    def to_affine(self) -> "Matrix":
        # Copy over just the affine bits.
        new = Matrix(
            a11=self.a11,
            a12=self.a12,
            a13=0.0,
            a21=self.a21,
            a22=self.a22,
            a23=0.0,
            a31=0.0,
            a32=0.0,
            a33=1.0,
            a41=self.a41,
            a42=self.a42,
            a43=0.0,
        )

        # Copy over tracking flags for affine, but unset the perspective ones.
        new.__scale_set = self.__scale_set
        new.__rotate_set = self.__rotate_set
        new.__translate_xy_set = self.__translate_xy_set
        new.__3d_grid_set = False
        new.__translate_z_set = False

        # Now return the new affine transform.
        return new

    @property
    def __is_affine(self) -> bool:
        return (
            round(abs(self.__a13), 5) == 0.0
            and round(abs(self.__a23), 5) == 0.0
            and round(abs(self.__a31), 5) == 0.0
            and round(abs(self.__a32), 5) == 0.0
            and round(self.__a33, 5) == 1.0
            and round(abs(self.__a43), 5) == 0.0
        )

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if self.__is_affine:
            return {
                "a": self.__a11,
                "b": self.__a12,
                "c": self.__a21,
                "d": self.__a22,
                "tx": self.__a41,
                "ty": self.__a42,
            }
        else:
            return {
                "a11": self.__a11,
                "a12": self.__a12,
                "a13": self.__a13,
                "a21": self.__a21,
                "a22": self.__a22,
                "a23": self.__a23,
                "a31": self.__a31,
                "a32": self.__a32,
                "a33": self.__a33,
                "tx": self.__a41,
                "ty": self.__a42,
                "tz": self.__a43,
            }

    def update(self, other: "Matrix", is_perspective: bool) -> "Matrix":
        new = Matrix(
            a11=self.__a11,
            a12=self.__a12,
            a13=self.__a13,
            a21=self.__a21,
            a22=self.__a22,
            a23=self.__a23,
            a31=self.__a31,
            a32=self.__a32,
            a33=self.__a33,
            a41=self.__a41,
            a42=self.__a42,
            a43=self.__a43,
        )

        if not (
            other.__scale_set
            or other.__rotate_set
            or other.__3d_grid_set
            or other.__translate_xy_set
            or other.__translate_z_set
        ):
            # Special case for uninitialized matrix that might need updating.
            if is_perspective:
                # Full perspective copy-over.
                new.__a11 = other.__a11
                new.__a12 = other.__a12
                new.__a13 = other.__a13
                new.__a21 = other.__a21
                new.__a22 = other.__a22
                new.__a23 = other.__a23
                new.__a31 = other.__a31
                new.__a32 = other.__a32
                new.__a33 = other.__a33
                new.__a41 = other.__a41
                new.__a42 = other.__a42
                new.__a43 = other.__a43
            else:
                # Simple affine copy-over.
                new.__a11 = other.__a11
                new.__a22 = other.__a22
                new.__a12 = other.__a12
                new.__a21 = other.__a21
                new.__a41 = other.__a41
                new.__a42 = other.__a42

        else:
            # Use object tracking to set only what changed.
            if other.__3d_grid_set and is_perspective:
                new.__a11 = other.__a11
                new.__a12 = other.__a12
                new.__a13 = other.__a13
                new.__a21 = other.__a21
                new.__a22 = other.__a22
                new.__a23 = other.__a23
                new.__a31 = other.__a31
                new.__a32 = other.__a32
                new.__a33 = other.__a33
            else:
                if other.__scale_set:
                    new.__a11 = other.__a11
                    new.__a22 = other.__a22
                if other.__rotate_set:
                    new.__a12 = other.__a12
                    new.__a21 = other.__a21

            if other.__translate_xy_set:
                new.__a41 = other.__a41
                new.__a42 = other.__a42
            if other.__translate_z_set and is_perspective:
                new.__a43 = other.__a43

        return new

    @property
    def xscale(self) -> float:
        return math.sqrt((self.__a11 * self.__a11) + (self.__a12 * self.__a12) + (self.__a13 * self.__a13))

    @property
    def yscale(self) -> float:
        return math.sqrt((self.__a21 * self.__a21) + (self.__a22 * self.__a22) + (self.__a23 * self.__a23))

    @property
    def zscale(self) -> float:
        return math.sqrt((self.__a31 * self.__a31) + (self.__a32 * self.__a32) + (self.__a33 * self.__a33))

    @property
    def a(self) -> float:
        return self.__a11

    @a.setter
    def a(self, val: float) -> None:
        self.__scale_set = True
        self.__a11 = val

    @property
    def b(self) -> float:
        return self.__a12

    @b.setter
    def b(self, val: float) -> None:
        self.__rotate_set = True
        self.__a12 = val

    @property
    def c(self) -> float:
        return self.__a21

    @c.setter
    def c(self, val: float) -> None:
        self.__rotate_set = True
        self.__a21 = val

    @property
    def d(self) -> float:
        return self.__a22

    @d.setter
    def d(self, val: float) -> None:
        self.__scale_set = True
        self.__a22 = val

    @property
    def tx(self) -> float:
        return self.__a41

    @tx.setter
    def tx(self, val: float) -> None:
        self.__translate_xy_set = True
        self.__a41 = val

    @property
    def ty(self) -> float:
        return self.__a42

    @ty.setter
    def ty(self, val: float) -> None:
        self.__translate_xy_set = True
        self.__a42 = val

    @property
    def tz(self) -> float:
        return self.__a43

    @tz.setter
    def tz(self, val: float) -> None:
        self.__translate_z_set = True
        self.__a43 = val

    @property
    def a11(self) -> float:
        return self.__a11

    @a11.setter
    def a11(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__scale_set = True
        self.__a11 = val

    @property
    def a12(self) -> float:
        return self.__a12

    @a12.setter
    def a12(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__rotate_set = True
        self.__a12 = val

    @property
    def a13(self) -> float:
        return self.__a13

    @a13.setter
    def a13(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__a13 = val

    @property
    def a21(self) -> float:
        return self.__a21

    @a21.setter
    def a21(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__rotate_set = True
        self.__a21 = val

    @property
    def a22(self) -> float:
        return self.__a22

    @a22.setter
    def a22(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__scale_set = True
        self.__a22 = val

    @property
    def a23(self) -> float:
        return self.__a23

    @a23.setter
    def a23(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__a23 = val

    @property
    def a31(self) -> float:
        return self.__a31

    @a31.setter
    def a31(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__a31 = val

    @property
    def a32(self) -> float:
        return self.__a32

    @a32.setter
    def a32(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__a32 = val

    @property
    def a33(self) -> float:
        return self.__a33

    @a33.setter
    def a33(self, val: float) -> None:
        self.__3d_grid_set = True
        self.__a33 = val

    @property
    def a41(self) -> float:
        return self.__a41

    @a41.setter
    def a41(self, val: float) -> None:
        self.__translate_xy_set = True
        self.__a41 = val

    @property
    def a42(self) -> float:
        return self.__a42

    @a42.setter
    def a42(self, val: float) -> None:
        self.__translate_xy_set = True
        self.__a42 = val

    @property
    def a43(self) -> float:
        return self.__a43

    @a43.setter
    def a43(self, val: float) -> None:
        self.__translate_z_set = True
        self.__a43 = val

    def multiply_point(self, point: Point) -> Point:
        return Point(
            x=(self.__a11 * point.x) + (self.__a21 * point.y) + (self.__a31 * point.z) + self.__a41,
            y=(self.__a12 * point.x) + (self.__a22 * point.y) + (self.__a32 * point.z) + self.__a42,
            z=(self.__a13 * point.x) + (self.__a23 * point.y) + (self.__a33 * point.z) + self.__a43,
        )

    def translate(self, point: Point) -> "Matrix":
        new_point = self.multiply_point(point)
        return Matrix(
            a11=self.__a11,
            a12=self.__a12,
            a13=self.__a13,
            a21=self.__a21,
            a22=self.__a22,
            a23=self.__a23,
            a31=self.__a31,
            a32=self.__a32,
            a33=self.__a33,
            a41=new_point.x,
            a42=new_point.y,
            a43=new_point.z,
        )

    def multiply(self, other: "Matrix") -> "Matrix":
        return Matrix(
            a11=self.__a11 * other.__a11 + self.__a12 * other.__a21 + self.__a13 * other.__a31,
            a12=self.__a11 * other.__a12 + self.__a12 * other.__a22 + self.__a13 * other.__a32,
            a13=self.__a11 * other.__a13 + self.__a12 * other.__a23 + self.__a13 * other.__a33,
            a21=self.__a21 * other.__a11 + self.__a22 * other.__a21 + self.__a23 * other.__a31,
            a22=self.__a21 * other.__a12 + self.__a22 * other.__a22 + self.__a23 * other.__a32,
            a23=self.__a21 * other.__a13 + self.__a22 * other.__a23 + self.__a23 * other.__a33,
            a31=self.__a31 * other.__a11 + self.__a32 * other.__a21 + self.__a33 * other.__a31,
            a32=self.__a31 * other.__a12 + self.__a32 * other.__a22 + self.__a33 * other.__a32,
            a33=self.__a31 * other.__a13 + self.__a32 * other.__a23 + self.__a33 * other.__a33,
            a41=self.__a41 * other.__a11 + self.__a42 * other.__a21 + self.__a43 * other.__a31 + other.__a41,
            a42=self.__a41 * other.__a12 + self.__a42 * other.__a22 + self.__a43 * other.__a32 + other.__a42,
            a43=self.__a41 * other.__a13 + self.__a42 * other.__a23 + self.__a43 * other.__a33 + other.__a43,
        )

    def inverse(self) -> "Matrix":
        try:
            return self.__inverse_impl()
        except ZeroDivisionError:
            pass

        raise ZeroDivisionError(f"Matrix({self}) cannot be inverted!")

    def __inverse_impl(self) -> "Matrix":
        # Use gauss-jordan eliminiation to invert the matrix.
        size = 4
        m = [
            [self.__a11, self.__a12, self.__a13, 0.0],
            [self.__a21, self.__a22, self.__a23, 0.0],
            [self.__a31, self.__a32, self.__a33, 0.0],
            [self.__a41, self.__a42, self.__a43, 1.0],
        ]
        inverse: List[List[float]] = [[1 if row == col else 0 for col in range(size)] for row in range(size)]

        for col in range(size):
            # First, get upper triangle of the matrix.
            if col < size - 1:
                numbers = [m[row][col] for row in range(col, size)]
                if all(n == 0 for n in numbers):
                    raise ZeroDivisionError(f"Matrix({self}) cannot be inverted!")

                # Reorder the matrix until all nonzero numbers are at the top.
                nonzeros_m = []
                nonzeros_inverse = []
                zeros_m = []
                zeros_inverse = []

                for row in range(size):
                    nrow = row - col
                    if nrow < 0:
                        # This is above the current part of the triangle, just
                        # include it as-is without reordering.
                        nonzeros_m.append(m[row])
                        nonzeros_inverse.append(inverse[row])
                        continue

                    if numbers[nrow] == 0:
                        # Put this at the end.
                        zeros_m.append(m[row])
                        zeros_inverse.append(inverse[row])
                    else:
                        nonzeros_m.append(m[row])
                        nonzeros_inverse.append(inverse[row])

                m = [
                    *nonzeros_m,
                    *zeros_m,
                ]
                inverse = [
                    *nonzeros_inverse,
                    *zeros_inverse,
                ]

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
                        *m[(row + 1) :],
                    ]
                    inverse = [
                        *inverse[:row],
                        [inverse[row][i] + inverse[col][i] * factor for i in range(size)],
                        *inverse[(row + 1) :],
                    ]

            # Finally, divide the current column to make it a unit.
            factor = 1 / m[col][col]
            m = [
                *m[:col],
                [e * factor for e in m[col]],
                *m[(col + 1) :],
            ]
            inverse = [
                *inverse[:col],
                [e * factor for e in inverse[col]],
                *inverse[(col + 1) :],
            ]

        # Technically the rest of the matrix that we don't care about could have values other
        # than 0.0, 0.0, 0.0, 1.0 but in practice that's because of floating point errors
        # accumulating so we simply trust the math and discard those values.
        return Matrix(
            a11=inverse[0][0],
            a12=inverse[0][1],
            a13=inverse[0][2],
            a21=inverse[1][0],
            a22=inverse[1][1],
            a23=inverse[1][2],
            a31=inverse[2][0],
            a32=inverse[2][1],
            a33=inverse[2][2],
            a41=inverse[3][0],
            a42=inverse[3][1],
            a43=inverse[3][2],
        )

    def __repr__(self) -> str:
        if self.__is_affine:
            return f"a: {round(self.__a11, 5)}, b: {round(self.__a12, 5)}, c: {round(self.__a21, 5)}, d: {round(self.__a22, 5)}, tx: {round(self.__a41, 5)}, ty: {round(self.__a42, 5)}"
        else:
            return "; ".join(
                [
                    f"a11: {round(self.__a11, 5)}, a12: {round(self.__a12, 5)}, a13: {round(self.__a13, 5)}",
                    f"a21: {round(self.__a21, 5)}, a22: {round(self.__a22, 5)}, a23: {round(self.__a23, 5)}",
                    f"a31: {round(self.__a31, 5)}, a32: {round(self.__a32, 5)}, a33: {round(self.__a33, 5)}",
                    f"tx:  {round(self.__a41, 5)}, ty:  {round(self.__a42, 5)}, tz:  {round(self.__a43, 5)}",
                ]
            )
