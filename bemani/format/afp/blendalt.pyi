from PIL import Image  # type: ignore
from typing import Optional, Tuple

from .types.generic import Color, Matrix, Point

def affine_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    transform: Matrix,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = False,
) -> Image.Image:
    ...
