from PIL import Image  # type: ignore
from typing import Optional

from ..types import Color, Point, Matrix


def affine_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    transform: Matrix,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = ...,
    enable_aa: bool = ...,
) -> Image.Image:
    ...


def perspective_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    transform: Matrix,
    camera: Point,
    focal_length: float,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = ...,
    enable_aa: bool = ...,
) -> Image.Image:
    ...
