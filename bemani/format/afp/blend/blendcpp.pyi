from PIL import Image
from typing import Optional

from ..types import Color, HSL, Point, Matrix


def affine_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    transform: Matrix,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = ...,
    aa_mode: int = ...
) -> Image.Image:
    ...


def perspective_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    transform: Matrix,
    camera: Point,
    focal_length: float,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = ...,
    aa_mode: int = ...
) -> Image.Image:
    ...
