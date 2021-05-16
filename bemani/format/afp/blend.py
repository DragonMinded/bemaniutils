from typing import Tuple

from .types.generic import Color


def clamp(color: float) -> int:
    return min(max(0, round(color)), 255)


def blend_normal(
    # RGBA color tuple representing what's already at the dest.
    dest: Tuple[int, int, int, int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Tuple[int, int, int, int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Tuple[int, int, int, int]:
    # "Normal" blend mode, which is just alpha blending. Various games use the DX
    # equation Src * As + Dst * (1 - As). We premultiply Dst by Ad as well, since
    # we are blitting onto a destination that could have transparency.

    # Calculate multiplicative and additive colors against the source.
    src = (
        clamp((src[0] * mult_color.r) + add_color[0]),
        clamp((src[1] * mult_color.g) + add_color[1]),
        clamp((src[2] * mult_color.b) + add_color[2]),
        clamp((src[3] * mult_color.a) + add_color[3]),
    )

    # Short circuit for speed.
    if src[3] == 0:
        return dest
    if src[3] == 255:
        return src

    # Calculate alpha blending.
    srcpercent = src[3] / 255.0
    destpercent = dest[3] / 255.0
    destremainder = 1.0 - srcpercent
    return (
        clamp((dest[0] * destpercent * destremainder) + (src[0] * srcpercent)),
        clamp((dest[1] * destpercent * destremainder) + (src[1] * srcpercent)),
        clamp((dest[2] * destpercent * destremainder) + (src[2] * srcpercent)),
        clamp(255 * (srcpercent + destpercent * destremainder)),
    )


def blend_addition(
    # RGBA color tuple representing what's already at the dest.
    dest: Tuple[int, int, int, int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Tuple[int, int, int, int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Tuple[int, int, int, int]:
    # "Addition" blend mode, which is used for fog/clouds/etc. Various games use the DX
    # equation Src * As + Dst * 1. It appears jubeat does not premultiply the source
    # by its alpha component.

    # Calculate multiplicative and additive colors against the source.
    src = (
        clamp((src[0] * mult_color.r) + add_color[0]),
        clamp((src[1] * mult_color.g) + add_color[1]),
        clamp((src[2] * mult_color.b) + add_color[2]),
        clamp((src[3] * mult_color.a) + add_color[3]),
    )

    # Short circuit for speed.
    if src[3] == 0:
        return dest

    # Calculate alpha blending.
    srcpercent = src[3] / 255.0
    return (
        clamp(dest[0] + (src[0] * srcpercent)),
        clamp(dest[1] + (src[1] * srcpercent)),
        clamp(dest[2] + (src[2] * srcpercent)),
        clamp(dest[3] + (255 * srcpercent)),
    )


def blend_subtraction(
    # RGBA color tuple representing what's already at the dest.
    dest: Tuple[int, int, int, int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Tuple[int, int, int, int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Tuple[int, int, int, int]:
    # "Subtraction" blend mode, used for darkening an image. Various games use the DX
    # equation Dst * 1 - Src * As. It appears jubeat does not premultiply the source
    # by its alpha component much like the "additive" blend above..

    # Calculate multiplicative and additive colors against the source.
    src = (
        clamp((src[0] * mult_color.r) + add_color[0]),
        clamp((src[1] * mult_color.g) + add_color[1]),
        clamp((src[2] * mult_color.b) + add_color[2]),
        clamp((src[3] * mult_color.a) + add_color[3]),
    )

    # Short circuit for speed.
    if src[3] == 0:
        return dest

    # Calculate alpha blending.
    srcpercent = src[3] / 255.0
    return (
        clamp(dest[0] - (src[0] * srcpercent)),
        clamp(dest[1] - (src[1] * srcpercent)),
        clamp(dest[2] - (src[2] * srcpercent)),
        clamp(dest[3] - (255 * srcpercent)),
    )


def blend_multiply(
    # RGBA color tuple representing what's already at the dest.
    dest: Tuple[int, int, int, int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Tuple[int, int, int, int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Tuple[int, int, int, int]:
    # "Multiply" blend mode, used for darkening an image. Various games use the DX
    # equation Src * 0 + Dst * Src. It appears jubeat uses the alternative formula
    # Src * Dst + Dst * (1 - As) which reduces to the first equation as long as the
    # source alpha is always 255.

    # Calculate multiplicative and additive colors against the source.
    src = (
        clamp((src[0] * mult_color.r) + add_color[0]),
        clamp((src[1] * mult_color.g) + add_color[1]),
        clamp((src[2] * mult_color.b) + add_color[2]),
        clamp((src[3] * mult_color.a) + add_color[3]),
    )

    # Short circuit for speed.
    if src[3] == 0:
        return dest

    # Calculate alpha blending.
    return (
        clamp(255 * ((dest[0] / 255.0) * (src[0] / 255.0))),
        clamp(255 * ((dest[1] / 255.0) * (src[1] / 255.0))),
        clamp(255 * ((dest[2] / 255.0) * (src[2] / 255.0))),
        clamp(255 * ((dest[3] / 255.0) * (src[3] / 255.0))),
    )
