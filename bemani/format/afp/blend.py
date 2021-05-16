from PIL import Image  # type: ignore
from typing import List, Tuple

from .types.generic import Color, Matrix, Point


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


def affine_composite(
    img: Image.Image,
    add_color: Tuple[int, int, int, int],
    mult_color: Color,
    transform: Matrix,
    inverse: Matrix,
    origin: Point,
    blendfunc: int,
    texture: Image.Image,
) -> List[Tuple[int, int, int, int]]:
    # Get the data in an easier to manipulate and faster to update fashion.
    imgmap = list(img.getdata())
    texmap = list(texture.getdata())

    # Warn if we have an unsupported blend.
    if blendfunc not in {0, 2, 3, 8, 9, 70}:
        print(f"WARNING: Unsupported blend {blendfunc}")

    # These are calculated properties and caching them outside of the loop
    # speeds things up a bit.
    imgwidth = img.width
    imgheight = img.height
    texwidth = texture.width
    texheight = texture.height

    # Calculate the maximum range of update this texture can possibly reside in.
    pix1 = transform.multiply_point(Point.identity().subtract(origin))
    pix2 = transform.multiply_point(Point.identity().subtract(origin).add(Point(texwidth, 0)))
    pix3 = transform.multiply_point(Point.identity().subtract(origin).add(Point(0, texheight)))
    pix4 = transform.multiply_point(Point.identity().subtract(origin).add(Point(texwidth, texheight)))

    # Map this to the rectangle we need to sweep in the rendering image.
    minx = max(int(min(pix1.x, pix2.x, pix3.x, pix4.x)), 0)
    maxx = min(int(max(pix1.x, pix2.x, pix3.x, pix4.x)) + 1, imgwidth)
    miny = max(int(min(pix1.y, pix2.y, pix3.y, pix4.y)), 0)
    maxy = min(int(max(pix1.y, pix2.y, pix3.y, pix4.y)) + 1, imgheight)

    for imgy in range(miny, maxy):
        for imgx in range(minx, maxx):
            # Determine offset
            imgoff = imgx + (imgy * imgwidth)

            # Blit this pixel.
            imgmap[imgoff] = affine_blend_point(imgx, imgy, imgwidth, imgheight, add_color, mult_color, imgmap[imgoff], inverse, origin, blendfunc, texwidth, texheight, texmap)

    return imgmap

def affine_blend_point(
    imgx: int,
    imgy: int,
    imgwidth: int,
    imgheight: int,
    add_color: Tuple[int, int, int, int],
    mult_color: Color,
    dest_color: Tuple[int, int, int, int],
    inverse: Matrix,
    origin: Point,
    blendfunc: int,
    texwidth: int,
    texheight: int,
    texmap: List[Tuple[int, int, int, int]],
) -> Tuple[int, int, int, int]:
    # Calculate what texture pixel data goes here.
    texloc = inverse.multiply_point(Point(float(imgx), float(imgy))).add(origin)
    texx, texy = texloc.as_tuple()

    # If we're out of bounds, don't update.
    if texx < 0 or texy < 0 or texx >= texwidth or texy >= texheight:
        return dest_color

    # Blend it.
    texoff = texx + (texy * texwidth)

    if blendfunc == 3:
        return blend_multiply(dest_color, texmap[texoff], mult_color, add_color)
    # TODO: blend mode 4, which is "screen" blending according to SWF references. I've only seen this
    # in Jubeat and it implements it using OpenGL equation Src * (1 - Dst) + Dst * 1.
    # TODO: blend mode 5, which is "lighten" blending according to SWF references. Jubeat does not
    # premultiply by alpha, but the GL/DX equation is max(Src * As, Dst * 1).
    # TODO: blend mode 6, which is "darken" blending according to SWF references. Jubeat does not
    # premultiply by alpha, but the GL/DX equation is min(Src * As, Dst * 1).
    # TODO: blend mode 10, which is "invert" according to SWF references. The only game I could find
    # that implemented this had equation Src * (1 - Dst) + Dst * (1 - As).
    # TODO: blend mode 13, which is "overlay" according to SWF references. The equation seems to be
    # Src * Dst + Dst * Src but Jubeat thinks it should be Src * Dst + Dst * (1 - As).
    elif blendfunc == 8:
        return blend_addition(dest_color, texmap[texoff], mult_color, add_color)
    elif blendfunc == 9 or blendfunc == 70:
        return blend_subtraction(dest_color, texmap[texoff], mult_color, add_color)
    # TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
    # Src * (1 - Dst) + Dst * (1 - Src).
    else:
        return blend_normal(dest_color, texmap[texoff], mult_color, add_color)
