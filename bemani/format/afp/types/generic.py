from typing import Any, Dict, Tuple


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
    # A simple 2D point.
    def __init__(self, x: float, y: float) -> None:
        self.x = x
        self.y = y

    @staticmethod
    def identity() -> "Point":
        return Point(0.0, 0.0)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'x': self.x,
            'y': self.y,
        }

    def as_tuple(self) -> Tuple[int, int]:
        return (int(self.x), int(self.y))

    def add(self, other: "Point") -> "Point":
        x = self.x + other.x
        y = self.y + other.y
        return Point(x, y)

    def subtract(self, other: "Point") -> "Point":
        x = self.x - other.x
        y = self.y - other.y
        return Point(x, y)

    def __repr__(self) -> str:
        return f"x: {round(self.x, 5)}, y: {round(self.y, 5)}"


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

    def __init__(self, a: float, b: float, c: float, d: float, tx: float, ty: float) -> None:
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.tx = tx
        self.ty = ty

    @staticmethod
    def identity() -> "Matrix":
        return Matrix(a=1.0, b=0.0, c=0.0, d=1.0, tx=0.0, ty=0.0)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'a': self.a,
            'b': self.b,
            'c': self.c,
            'd': self.d,
            'tx': self.tx,
            'ty': self.ty,
        }

    def multiply_point(self, point: Point) -> Point:
        return Point(
            x=(self.a * point.x) + (self.c * point.y) + self.tx,
            y=(self.b * point.x) + (self.d * point.y) + self.ty,
        )

    def translate(self, point: Point) -> "Matrix":
        new_point = self.multiply_point(point)
        return Matrix(
            a=self.a,
            b=self.b,
            c=self.c,
            d=self.d,
            tx=new_point.x,
            ty=new_point.y,
        )

    def multiply(self, other: "Matrix") -> "Matrix":
        return Matrix(
            a=self.a * other.a + self.b * other.c,
            b=self.a * other.b + self.b * other.d,
            c=self.c * other.a + self.d * other.c,
            d=self.c * other.b + self.d * other.d,
            tx=self.tx * other.a + self.ty * other.c + other.tx,
            ty=self.tx * other.b + self.ty * other.d + other.ty,
        )

    def inverse(self) -> "Matrix":
        denom = (self.a * self.d - self.b * self.c)

        try:
            return Matrix(
                a=self.d / denom,
                b=-self.b / denom,
                c=-self.c / denom,
                d=self.a / denom,
                tx=(self.c * self.ty - self.d * self.tx) / denom,
                ty=-(self.a * self.ty - self.b * self.tx) / denom,
            )
        except ZeroDivisionError:
            pass

        # This happens if one of the scaling factors is zero.
        raise ZeroDivisionError(f"Matrix({self}) cannot be inverted!")

    def __repr__(self) -> str:
        return f"a: {round(self.a, 5)}, b: {round(self.b, 5)}, c: {round(self.c, 5)}, d: {round(self.d, 5)}, tx: {round(self.tx, 5)}, ty: {round(self.ty, 5)}"
