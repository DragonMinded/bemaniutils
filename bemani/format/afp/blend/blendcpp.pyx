import multiprocessing
from PIL import Image
from typing import Optional, Tuple

from ..types import Color, HSL, Matrix, Point, AAMode
from .perspective import perspective_calculate

cdef extern struct floatcolor_t:
    double r;
    double g;
    double b;
    double a;

cdef extern struct hslcolor_t:
    double h;
    double s;
    double l;

cdef extern struct matrix_t:
    double a11;
    double a12;
    double a13;
    double a21;
    double a22;
    double a23;
    double a31;
    double a32;
    double a33;
    double a41;
    double a42;
    double a43;

cdef extern int composite_fast(
    unsigned char *imgbytes,
    unsigned char *maskbytes,
    unsigned int imgwidth,
    unsigned int imgheight,
    unsigned int minx,
    unsigned int maxx,
    unsigned int miny,
    unsigned int maxy,
    floatcolor_t add_color,
    floatcolor_t mult_color,
    hslcolor_t hsl_shift,
    double xscale,
    double yscale,
    matrix_t inverse,
    int use_perspective,
    int blendfunc,
    unsigned char *texbytes,
    unsigned int texwidth,
    unsigned int texheight,
    unsigned int threads,
    unsigned int aa_mode
)

def affine_composite(
    img: Image.Image,
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    transform: Matrix,
    mask: Optional[Image.Image],
    blendfunc: int,
    texture: Image.Image,
    single_threaded: bool = False,
    aa_mode: int = AAMode.SSAA_OR_BILINEAR,
) -> Image.Image:
    if blendfunc not in {0, 1, 2, 3, 8, 9, 13, 70, 256, 257}:
        print(f"WARNING: Unsupported blend {blendfunc}")
        return img

    # Calculate the inverse so we can map canvas space back to texture space.
    try:
        inverse = transform.inverse()
    except ZeroDivisionError:
        # If this happens, that means one of the scaling factors was zero, making
        # this object invisible. We can ignore this since the object should not
        # be drawn.
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
    cdef hslcolor_t c_hslcolor = hslcolor_t(h=hsl_shift.h, s=hsl_shift.s, l=hsl_shift.l)
    cdef matrix_t c_inverse = matrix_t(
        a11=inverse.a11, a12=inverse.a12, a13=inverse.a13,
        a21=inverse.a21, a22=inverse.a22, a23=inverse.a23,
        a31=inverse.a31, a32=inverse.a32, a33=inverse.a33,
        a41=inverse.a41, a42=inverse.a42, a43=inverse.a43,
    )
    cdef unsigned int threads = 1 if single_threaded else multiprocessing.cpu_count()

    # Call the C++ function.
    errors = composite_fast(
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
        c_hslcolor,
        transform.xscale,
        transform.yscale,
        c_inverse,
        0,
        blendfunc,
        texbytes,
        texwidth,
        texheight,
        threads,
        aa_mode,
    )
    if errors != 0:
        raise Exception("Error raised in C++!")

    # We blitted in-place, return that. There seems to be a reference bug in Cython
    # when called from compiled mypyc code, so if we don't assign to a local variable
    # first this function appears to return None.
    img = Image.frombytes('RGBA', (imgwidth, imgheight), imgbytes)
    return img


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
    single_threaded: bool = False,
    aa_mode: int = AAMode.SSAA_ONLY,
) -> Image.Image:
    if blendfunc not in {0, 1, 2, 3, 8, 9, 13, 70, 256, 257}:
        print(f"WARNING: Unsupported blend {blendfunc}")
        return img

    # These are calculated properties and caching them outside of the loop
    # speeds things up a bit.
    imgwidth = img.width
    imgheight = img.height
    texwidth = texture.width
    texheight = texture.height

    # Get the perspective-correct inverse matrix for looking up texture coordinates.
    inverse_matrix, minx, miny, maxx, maxy = perspective_calculate(imgwidth, imgheight, texwidth, texheight, transform, camera, focal_length)
    if inverse_matrix is None:
        # This texture is entirely off of the screen.
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
    cdef hslcolor_t c_hslcolor = hslcolor_t(h=hsl_shift.h, s=hsl_shift.s, l=hsl_shift.l)
    cdef matrix_t c_inverse = matrix_t(
        a11=inverse_matrix.a11, a12=inverse_matrix.a12, a13=inverse_matrix.a13,
        a21=inverse_matrix.a21, a22=inverse_matrix.a22, a23=inverse_matrix.a23,
        a31=inverse_matrix.a31, a32=inverse_matrix.a32, a33=inverse_matrix.a33,
        a41=inverse_matrix.a41, a42=inverse_matrix.a42, a43=inverse_matrix.a43,
    )
    cdef unsigned int threads = 1 if single_threaded else multiprocessing.cpu_count()

    # Call the C++ function.
    errors = composite_fast(
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
        c_hslcolor,
        transform.xscale,
        transform.yscale,
        c_inverse,
        1,
        blendfunc,
        texbytes,
        texwidth,
        texheight,
        threads,
        aa_mode,
    )
    if errors != 0:
        raise Exception("Error raised in C++!")

    # We blitted in-place, return that. There seems to be a reference bug in Cython
    # when called from compiled mypyc code, so if we don't assign to a local variable
    # first this function appears to return None.
    img = Image.frombytes('RGBA', (imgwidth, imgheight), imgbytes)
    return img
