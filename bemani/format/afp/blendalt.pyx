from PIL import Image  # type: ignore
from typing import Tuple

from .types.generic import Color, Matrix, Point

cdef extern struct intcolor_t:
    unsigned char r;
    unsigned char g;
    unsigned char b;
    unsigned char a;

cdef extern struct floatcolor_t:
    float r;
    float g;
    float b;
    float a;

cdef extern struct matrix_t:
    float a;
    float b;
    float c;
    float d;
    float tx;
    float ty;

cdef extern struct point_t:
    float x;
    float y;

cdef extern int affine_composite_fast(
    unsigned char *imgdata,
    unsigned int imgwidth,
    unsigned int imgheight,
    unsigned int minx,
    unsigned int maxx,
    unsigned int miny,
    unsigned int maxy,
    intcolor_t add_color,
    floatcolor_t mult_color,
    matrix_t inverse,
    point_t origin,
    int blendfunc,
    unsigned char *texdata,
    unsigned int texwidth,
    unsigned int texheight,
    int single_threaded
)

def affine_composite(
    img: Image.Image,
    add_color: Tuple[int, int, int, int],
    mult_color: Color,
    transform: Matrix,
    origin: Point,
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = False,
) -> Image.Image:
    # Calculate the inverse so we can map canvas space back to texture space.
    try:
        inverse = transform.inverse()
    except ZeroDivisionError:
        # If this happens, that means one of the scaling factors was zero, making
        # this object invisible. We can ignore this since the object should not
        # be drawn.
        print(f"WARNING: Transform Matrix {transform} has zero scaling factor, making it non-invertible!")
        return img

    if blendfunc not in {0, 2, 3, 8, 9, 70}:
        print(f"WARNING: Unsupported blend {blendfunc}")
        return img

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

    if maxx <= 0 or maxy <= 0:
        # This image is entirely off the screen!
        return img

    # Grab the raw image data.
    imgbytes = img.tobytes('raw', 'RGBA')
    texbytes = texture.tobytes('raw', 'RGBA')

    # Convert classes to C structs.
    cdef intcolor_t c_addcolor = intcolor_t(r=add_color[0], g=add_color[1], b=add_color[2], a=add_color[3])
    cdef floatcolor_t c_multcolor = floatcolor_t(r=mult_color.r, g=mult_color.g, b=mult_color.b, a=mult_color.a)
    cdef matrix_t c_inverse = matrix_t(a=inverse.a, b=inverse.b, c=inverse.c, d=inverse.d, tx=inverse.tx, ty=inverse.ty)
    cdef point_t c_origin = point_t(x=origin.x, y=origin.y)

    # Call the C++ function.
    errors = affine_composite_fast(
        imgbytes,
        imgwidth,
        imgheight,
        minx,
        maxx,
        miny,
        maxy,
        c_addcolor,
        c_multcolor,
        c_inverse,
        c_origin,
        blendfunc,
        texbytes,
        texwidth,
        texheight,
        single_threaded,
    )
    if errors != 0:
        raise Exception("Error raised in C++!")

    # We blitted in-place, return that.
    return Image.frombytes('RGBA', (imgwidth, imgheight), imgbytes)
