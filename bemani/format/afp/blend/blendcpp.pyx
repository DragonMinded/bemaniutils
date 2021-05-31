import multiprocessing
from PIL import Image  # type: ignore
from typing import Optional, Tuple

from ..types import Color, Matrix, Point

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
    unsigned char *maskdata,
    unsigned int imgwidth,
    unsigned int imgheight,
    unsigned int minx,
    unsigned int maxx,
    unsigned int miny,
    unsigned int maxy,
    floatcolor_t add_color,
    floatcolor_t mult_color,
    matrix_t inverse,
    int blendfunc,
    unsigned char *texdata,
    unsigned int texwidth,
    unsigned int texheight,
    unsigned int threads,
    unsigned int enable_aa,
)

def affine_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    transform: Matrix,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = False,
    enable_aa: bool = True,
) -> Image.Image:
    # Calculate the inverse so we can map canvas space back to texture space.
    try:
        inverse = transform.inverse()
    except ZeroDivisionError:
        # If this happens, that means one of the scaling factors was zero, making
        # this object invisible. We can ignore this since the object should not
        # be drawn.
        return img

    if blendfunc not in {0, 1, 2, 3, 8, 9, 70, 256, 257}:
        print(f"WARNING: Unsupported blend {blendfunc}")
        return img

    # These are calculated properties and caching them outside of the loop
    # speeds things up a bit.
    imgwidth = img.width
    imgheight = img.height
    texwidth = texture.width
    texheight = texture.height

    # Calculate the maximum range of update this texture can possibly reside in.
    pix1 = transform.multiply_point(Point.identity())
    pix2 = transform.multiply_point(Point.identity().add(Point(texwidth, 0)))
    pix3 = transform.multiply_point(Point.identity().add(Point(0, texheight)))
    pix4 = transform.multiply_point(Point.identity().add(Point(texwidth, texheight)))

    # Map this to the rectangle we need to sweep in the rendering image.
    minx = max(int(min(pix1.x, pix2.x, pix3.x, pix4.x)), 0)
    maxx = min(int(max(pix1.x, pix2.x, pix3.x, pix4.x)) + 1, imgwidth)
    miny = max(int(min(pix1.y, pix2.y, pix3.y, pix4.y)), 0)
    maxy = min(int(max(pix1.y, pix2.y, pix3.y, pix4.y)) + 1, imgheight)

    if maxx <= minx or maxy <= miny:
        # This image is entirely off the screen!
        return img

    # Grab the raw image data.
    imgbytes = img.tobytes('raw', 'RGBA')
    texbytes = texture.tobytes('raw', 'RGBA')

    # Grab the mask data.
    if mask is not None:
        alpha = mask.split()[-1]
        maskdata = alpha.tobytes('raw', 'L')
    else:
        maskdata = None
    cdef unsigned char *maskbytes = NULL
    if maskdata is not None:
        maskbytes = maskdata

    # Convert classes to C structs.
    cdef floatcolor_t c_addcolor = floatcolor_t(r=add_color.r, g=add_color.g, b=add_color.b, a=add_color.a)
    cdef floatcolor_t c_multcolor = floatcolor_t(r=mult_color.r, g=mult_color.g, b=mult_color.b, a=mult_color.a)
    cdef matrix_t c_inverse = matrix_t(a=inverse.a, b=inverse.b, c=inverse.c, d=inverse.d, tx=inverse.tx, ty=inverse.ty)
    cdef unsigned int threads = 1 if single_threaded else multiprocessing.cpu_count()

    # Call the C++ function.
    errors = affine_composite_fast(
        imgbytes,
        maskbytes,
        imgwidth,
        imgheight,
        minx,
        maxx,
        miny,
        maxy,
        c_addcolor,
        c_multcolor,
        c_inverse,
        blendfunc,
        texbytes,
        texwidth,
        texheight,
        threads,
        1 if enable_aa else 0,
    )
    if errors != 0:
        raise Exception("Error raised in C++!")

    # We blitted in-place, return that. There seems to be a reference bug in Cython
    # when called from compiled mypyc code, so if we don't assign to a local variable
    # first this function appears to return None.
    img = Image.frombytes('RGBA', (imgwidth, imgheight), imgbytes)
    return img
