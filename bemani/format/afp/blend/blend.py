import multiprocessing
import signal
from PIL import Image
from typing import Any, Callable, List, Optional, Sequence, Union

from ..types import Color, HSL, Matrix, Point, AAMode
from .perspective import perspective_calculate


def clamp(color: float) -> int:
    return min(max(0, round(color)), 255)


def blend_normal(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # "Normal" blend mode, which is just alpha blending. Various games use the DX
    # equation Src * As + Dst * (1 - As). We premultiply Dst by Ad as well, since
    # we are blitting onto a destination that could have transparency. Once we are
    # done, we divide out the premultiplied Ad in order to put the pixes back to
    # their full blended values since we are not setting the destination alpha to 1.0.
    # This enables partial transparent backgrounds to work properly.

    # Short circuit for speed.
    if src[3] == 0:
        return dest
    if src[3] == 255:
        return src

    # Calculate alpha blending.
    srcpercent = src[3] / 255.0
    destpercent = dest[3] / 255.0
    srcremainder = 1.0 - srcpercent
    new_alpha = max(min(0.0, srcpercent + destpercent * srcremainder), 1.0)
    return (
        clamp(((dest[0] * destpercent * srcremainder) + (src[0] * srcpercent)) / new_alpha),
        clamp(((dest[1] * destpercent * srcremainder) + (src[1] * srcpercent)) / new_alpha),
        clamp(((dest[2] * destpercent * srcremainder) + (src[2] * srcpercent)) / new_alpha),
        clamp(255 * new_alpha),
    )


def blend_addition(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # "Addition" blend mode, which is used for fog/clouds/etc. Various games use the DX
    # equation Src * As + Dst * 1. It appears jubeat does not premultiply the source
    # by its alpha component.

    # Short circuit for speed.
    if src[3] == 0:
        return dest

    # Calculate final color blending.
    srcpercent = src[3] / 255.0
    return (
        clamp(dest[0] + (src[0] * srcpercent)),
        clamp(dest[1] + (src[1] * srcpercent)),
        clamp(dest[2] + (src[2] * srcpercent)),
        # Additive blending doesn't actually make sense on semi-transparent destinations,
        # as that implies that the semi-transparent pixel will be later displayed on top
        # of something else. That doesn't work since additive blending needs to non-linearly
        # mix with the destination. So, in reality, we should be doing what subtractive
        # blending does and keeping the destination alpha (which should always be 255),
        # but if somebody renders an animation with additive blending meant to go over a
        # background onto a transparent or semi-transparent background this will make the
        # resulting graphic look more correct.
        clamp(dest[3] + (255 * srcpercent)),
    )


def blend_subtraction(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # "Subtraction" blend mode, used for darkening an image. Various games use the DX
    # equation Dst * 1 - Src * As. It appears jubeat does not premultiply the source
    # by its alpha component much like the "additive" blend above..

    # Short circuit for speed.
    if src[3] == 0:
        return dest

    # Calculate final color blending.
    srcpercent = src[3] / 255.0
    return (
        clamp(dest[0] - (src[0] * srcpercent)),
        clamp(dest[1] - (src[1] * srcpercent)),
        clamp(dest[2] - (src[2] * srcpercent)),
        dest[3],
    )


def blend_multiply(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # "Multiply" blend mode, used for darkening an image. Various games use the DX
    # equation Src * 0 + Dst * Src. It appears jubeat uses the alternative formula
    # Src * Dst + Dst * (1 - As) which reduces to the first equation as long as the
    # source alpha is always 255.

    # Calculate final color blending.
    src_alpha = src[3] / 255.0
    src_remainder = 1.0 - src_alpha
    return (
        clamp((255 * ((dest[0] / 255.0) * (src[0] / 255.0) * src_alpha)) + (dest[0] * src_remainder)),
        clamp((255 * ((dest[1] / 255.0) * (src[1] / 255.0) * src_alpha)) + (dest[1] * src_remainder)),
        clamp((255 * ((dest[2] / 255.0) * (src[2] / 255.0) * src_alpha)) + (dest[2] * src_remainder)),
        dest[3],
    )


def blend_overlay(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # "Overlay" blend mode. Various games use the DX equation Src * Dst + Dst * Src. It appears that
    # jubeat uses the alternative formula Src * Dst + Dst * (1 - As).

    # Calculate final color blending.
    return (
        clamp((255 * (2.0 * (dest[0] / 255.0) * (src[0] / 255.0)))),
        clamp((255 * (2.0 * (dest[1] / 255.0) * (src[1] / 255.0)))),
        clamp((255 * (2.0 * (dest[2] / 255.0) * (src[2] / 255.0)))),
        dest[3],
    )


def blend_mask_create(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # Mask creating just allows a pixel to be drawn if the source image has a nonzero
    # alpha, according to the SWF spec.
    if src[3] != 0:
        return (255, 0, 0, 255)
    else:
        return (0, 0, 0, 0)


def blend_mask_combine(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
) -> Sequence[int]:
    # Mask blending just takes the source and destination and ands them together, making
    # a final mask that is the intersection of the original mask and the new mask. The
    # reason we even have a color component to this is for debugging visibility.
    if dest[3] != 0 and src[3] != 0:
        return (255, 0, 0, 255)
    else:
        return (0, 0, 0, 0)


def blend_point(
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    # This should be a sequence of exactly 4 values, either bytes or a tuple.
    src_color: Sequence[int],
    # This should be a sequence of exactly 4 values, either bytes or a tuple.
    dest_color: Sequence[int],
    blendfunc: int,
) -> Sequence[int]:
    # Calculate multiplicative and additive colors against the source.
    src_color = (
        clamp((src_color[0] * mult_color.r) + (255 * add_color.r)),
        clamp((src_color[1] * mult_color.g) + (255 * add_color.g)),
        clamp((src_color[2] * mult_color.b) + (255 * add_color.b)),
        clamp((src_color[3] * mult_color.a) + (255 * add_color.a)),
    )

    # Only add in HSL shift effects if they exist, since its expensive to
    # convert and shift. Also I'm not sure if this should be done before or
    # after the add and multiply.
    if not hsl_shift.is_identity:
        hslcolor = Color(src_color[0] / 255, src_color[1] / 255, src_color[2] / 255, 1.0).as_hsl()
        hslcolor = hslcolor.add(hsl_shift)
        newcolor = hslcolor.as_rgb()

        src_color = (
            clamp(newcolor.r * 255),
            clamp(newcolor.g * 255),
            clamp(newcolor.b * 255),
            src_color[3],
        )

    if blendfunc == 3:
        return blend_multiply(dest_color, src_color)
    # TODO: blend mode 4, which is "screen" blending according to SWF references. I've only seen this
    # in Jubeat and it implements it using OpenGL equation Src * (1 - Dst) + Dst * 1.
    # TODO: blend mode 5, which is "lighten" blending according to SWF references. Jubeat does not
    # premultiply by alpha, but the GL/DX equation is max(Src * As, Dst * 1).
    # TODO: blend mode 6, which is "darken" blending according to SWF references. Jubeat does not
    # premultiply by alpha, but the GL/DX equation is min(Src * As, Dst * 1).
    elif blendfunc == 8:
        return blend_addition(dest_color, src_color)
    elif blendfunc == 9 or blendfunc == 70:
        return blend_subtraction(dest_color, src_color)
    # TODO: blend mode 10, which is "invert" according to SWF references. The only game I could find
    # that implemented this had equation Src * (1 - Dst) + Dst * (1 - As).
    if blendfunc == 13:
        return blend_overlay(dest_color, src_color)
    # TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
    # Src * (1 - Dst) + Dst * (1 - Src).
    elif blendfunc == 256:
        # Dummy blend function for calculating masks.
        return blend_mask_combine(dest_color, src_color)
    elif blendfunc == 257:
        # Dummy blend function for calculating masks.
        return blend_mask_create(dest_color, src_color)
    else:
        return blend_normal(dest_color, src_color)


def pixel_renderer(
    imgx: int,
    imgy: int,
    imgwidth: int,
    imgheight: int,
    texwidth: int,
    texheight: int,
    xscale: float,
    yscale: float,
    callback: Callable[[Point], Optional[Point]],
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    blendfunc: int,
    imgbytes: Union[bytes, bytearray],
    texbytes: Union[bytes, bytearray],
    maskbytes: Optional[Union[bytes, bytearray]],
    aa_mode: int,
) -> Sequence[int]:
    # Determine offset
    maskoff = imgx + (imgy * imgwidth)
    imgoff = maskoff * 4

    if maskbytes is not None and maskbytes[maskoff] == 0:
        # This pixel is masked off!
        return imgbytes[imgoff : (imgoff + 4)]

    if aa_mode != AAMode.NONE:
        r = 0
        g = 0
        b = 0
        a = 0
        count = 0
        denom = 0

        # Essentially what we're doing here is calculating the scale, clamping it at 1.0 as the
        # minimum and then setting the AA sample swing accordingly. This has the effect of anti-aliasing
        # scaled up images a bit softer than would otherwise be achieved.
        if aa_mode == AAMode.UNSCALED_SSAA_ONLY:
            xswing = 0.5
            yswing = 0.5
        else:
            xswing = 0.5 * max(1.0, xscale)
            yswing = 0.5 * max(1.0, yscale)

        xpoints = [
            0.5 - xswing,
            0.5 - (xswing / 2.0),
            0.5,
            0.5 + (xswing / 2.0),
            0.5 + xswing,
        ]
        ypoints = [
            0.5 - yswing,
            0.5 - (yswing / 2.0),
            0.5,
            0.5 + (yswing / 2.0),
            0.5 + yswing,
        ]

        # First, figure out if we can use bilinear resampling.
        bilinear = False
        if aa_mode == AAMode.SSAA_OR_BILINEAR and xscale >= 1.0 and yscale >= 1.0:
            aaloc = callback(Point(imgx + 0.5, imgy + 0.5))
            if aaloc is not None:
                aax, aay, _ = aaloc.as_tuple()
                if not (aax <= 0 or aay <= 0 or aax >= (texwidth - 1) or aay >= (texheight - 1)):
                    bilinear = True

        # Now perform the desired AA operation.
        if bilinear:
            # Calculate the pixel we're after, and what percentage into the pixel we are.
            texloc = callback(Point(imgx + 0.5, imgy + 0.5))
            if texloc is None:
                raise Exception("Logic error!")
            aax, aay, _ = texloc.as_tuple()
            aaxrem = texloc.x - aax
            aayrem = texloc.y - aay

            # Find the four pixels that we can interpolate from. The first number is the x, and second is y.
            tex00 = (aax + (aay * texwidth)) * 4
            tex10 = tex00 + 4
            tex01 = (aax + ((aay + 1) * texwidth)) * 4
            tex11 = tex01 + 4

            # Calculate various scaling factors based on alpha and percentage.
            tex00percent = texbytes[tex00 + 3] / 255.0
            tex10percent = texbytes[tex10 + 3] / 255.0
            tex01percent = texbytes[tex01 + 3] / 255.0
            tex11percent = texbytes[tex11 + 3] / 255.0

            y0percent = (tex00percent * (1.0 - aaxrem)) + (tex10percent * aaxrem)
            y1percent = (tex01percent * (1.0 - aaxrem)) + (tex11percent * aaxrem)
            finalpercent = (y0percent * (1.0 - aayrem)) + (y1percent * aayrem)

            if finalpercent <= 0.0:
                # This pixel would be blank, so we avoid dividing by zero.
                average = [255, 255, 255, 0]
            else:
                # Interpolate in the X direction on both Y axis.
                y0r = (texbytes[tex00] * tex00percent * (1.0 - aaxrem)) + (texbytes[tex10] * tex10percent * aaxrem)
                y0g = (texbytes[tex00 + 1] * tex00percent * (1.0 - aaxrem)) + (
                    texbytes[tex10 + 1] * tex10percent * aaxrem
                )
                y0b = (texbytes[tex00 + 2] * tex00percent * (1.0 - aaxrem)) + (
                    texbytes[tex10 + 2] * tex10percent * aaxrem
                )

                y1r = (texbytes[tex01] * tex01percent * (1.0 - aaxrem)) + (texbytes[tex11] * tex11percent * aaxrem)
                y1g = (texbytes[tex01 + 1] * tex01percent * (1.0 - aaxrem)) + (
                    texbytes[tex11 + 1] * tex11percent * aaxrem
                )
                y1b = (texbytes[tex01 + 2] * tex01percent * (1.0 - aaxrem)) + (
                    texbytes[tex11 + 2] * tex11percent * aaxrem
                )

                # Now interpolate the Y direction to get the final pixel value.
                average = [
                    int(((y0r * (1.0 - aayrem)) + (y1r * aayrem)) / finalpercent),
                    int(((y0g * (1.0 - aayrem)) + (y1g * aayrem)) / finalpercent),
                    int(((y0b * (1.0 - aayrem)) + (y1b * aayrem)) / finalpercent),
                    int(finalpercent * 255),
                ]
        else:
            for addy in ypoints:
                for addx in xpoints:
                    xloc = imgx + addx
                    yloc = imgy + addy
                    if xloc < 0.0 or yloc < 0.0 or xloc >= imgwidth or yloc >= imgheight:
                        continue

                    texloc = callback(Point(xloc, yloc))
                    denom += 1

                    if texloc is None:
                        continue

                    aax, aay, _ = texloc.as_tuple()

                    # If we're out of bounds, don't update. Factor this in, however, so we can get partial
                    # transparency to the pixel that is already there.
                    if aax < 0 or aay < 0 or aax >= texwidth or aay >= texheight:
                        continue

                    # Grab the values to average, for SSAA. Make sure to factor in alpha as a poor-man's
                    # blend to ensure that partial transparency pixel values don't unnecessarily factor
                    # into average calculations.
                    texoff = (aax + (aay * texwidth)) * 4

                    # If this is a fully transparent pixel, the below formulas work out to adding nothing
                    # so we should skip this altogether.
                    if texbytes[texoff + 3] == 0:
                        continue

                    apercent = texbytes[texoff + 3] / 255.0
                    r += int(texbytes[texoff] * apercent)
                    g += int(texbytes[texoff + 1] * apercent)
                    b += int(texbytes[texoff + 2] * apercent)
                    a += texbytes[texoff + 3]
                    count += 1

            if count == 0:
                # None of the samples existed in-bounds.
                return imgbytes[imgoff : (imgoff + 4)]

            # Average the pixels. Make sure to divide out the alpha in preparation for blending.
            alpha = a // denom

            if alpha == 0:
                average = [255, 255, 255, alpha]
            else:
                apercent = alpha / 255.0
                average = [
                    int((r / denom) / apercent),
                    int((g / denom) / apercent),
                    int((b / denom) / apercent),
                    alpha,
                ]

        # Finally, blend it with the destination.
        return blend_point(
            add_color,
            mult_color,
            hsl_shift,
            average,
            imgbytes[imgoff : (imgoff + 4)],
            blendfunc,
        )
    else:
        # Calculate what texture pixel data goes here.
        texloc = callback(Point(imgx + 0.5, imgy + 0.5))
        if texloc is None:
            return imgbytes[imgoff : (imgoff + 4)]

        texx, texy, _ = texloc.as_tuple()

        # If we're out of bounds, don't update.
        if texx < 0 or texy < 0 or texx >= texwidth or texy >= texheight:
            return imgbytes[imgoff : (imgoff + 4)]

        # Blend it.
        texoff = (texx + (texy * texwidth)) * 4
        return blend_point(
            add_color,
            mult_color,
            hsl_shift,
            texbytes[texoff : (texoff + 4)],
            imgbytes[imgoff : (imgoff + 4)],
            blendfunc,
        )


def affine_line_renderer(
    work: multiprocessing.Queue,
    results: multiprocessing.Queue,
    minx: int,
    maxx: int,
    imgwidth: int,
    imgheight: int,
    texwidth: int,
    texheight: int,
    inverse: Matrix,
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    blendfunc: int,
    imgbytes: Union[bytes, bytearray],
    texbytes: Union[bytes, bytearray],
    maskbytes: Optional[Union[bytes, bytearray]],
    aa_mode: int,
) -> None:
    while True:
        imgy = work.get()
        if imgy is None:
            return

        rowbytes = bytearray(imgbytes[(imgy * imgwidth * 4) : ((imgy + 1) * imgwidth * 4)])
        for imgx in range(imgwidth):
            if imgx < minx or imgx >= maxx:
                # No need to even consider this pixel.
                continue
            else:
                # Blit new pixel into the correct range.
                rowbytes[(imgx * 4) : ((imgx + 1) * 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    1.0 / inverse.xscale,
                    1.0 / inverse.yscale,
                    lambda point: inverse.multiply_point(point),
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    aa_mode,
                )

        results.put((imgy, bytes(rowbytes)))


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
    # Calculate the inverse so we can map canvas space back to texture space.
    try:
        inverse = transform.inverse()
    except ZeroDivisionError:
        # If this happens, that means one of the scaling factors was zero, making
        # this object invisible. We can ignore this since the object should not
        # be drawn.
        return img

    # Warn if we have an unsupported blend.
    if blendfunc not in {0, 1, 2, 3, 8, 9, 13, 70, 256, 257}:
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

    cores = multiprocessing.cpu_count()
    if single_threaded or cores < 2:
        # Get the data in an easier to manipulate and faster to update fashion.
        imgbytearray = bytearray(img.tobytes("raw", "RGBA"))
        texbytes = texture.tobytes("raw", "RGBA")
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes("raw", "L")
        else:
            maskbytes = None

        # We don't have enough CPU cores to bother multiprocessing.
        for imgy in range(miny, maxy):
            for imgx in range(minx, maxx):
                # Determine offset
                imgoff = (imgx + (imgy * imgwidth)) * 4
                imgbytearray[imgoff : (imgoff + 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    1.0 / inverse.xscale,
                    1.0 / inverse.yscale,
                    lambda point: inverse.multiply_point(point),
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytearray,
                    texbytes,
                    maskbytes,
                    aa_mode,
                )

        img = Image.frombytes("RGBA", (imgwidth, imgheight), bytes(imgbytearray))
    else:
        imgbytes = img.tobytes("raw", "RGBA")
        texbytes = texture.tobytes("raw", "RGBA")
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes("raw", "L")
        else:
            maskbytes = None

        # Let's spread the load across multiple processors.
        procs: List[multiprocessing.Process] = []
        work: multiprocessing.Queue = multiprocessing.Queue()
        results: multiprocessing.Queue = multiprocessing.Queue()
        expected: int = 0
        interrupted: bool = False

        def ctrlc(sig: Any, frame: Any) -> None:
            nonlocal interrupted
            interrupted = True

        previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, ctrlc)

        for _ in range(cores):
            proc = multiprocessing.Process(
                target=affine_line_renderer,
                args=(
                    work,
                    results,
                    minx,
                    maxx,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    inverse,
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    aa_mode,
                ),
            )
            procs.append(proc)
            proc.start()

        for imgy in range(miny, maxy):
            work.put(imgy)
            expected += 1

        lines: List[bytes] = [
            imgbytes[x : (x + (imgwidth * 4))]
            for x in range(
                0,
                imgwidth * imgheight * 4,
                imgwidth * 4,
            )
        ]
        for _ in range(expected):
            imgy, result = results.get()
            lines[imgy] = result

        for _proc in procs:
            work.put(None)
        for proc in procs:
            proc.join()

        signal.signal(signal.SIGINT, previous_handler)
        if interrupted:
            raise KeyboardInterrupt()

        img = Image.frombytes("RGBA", (imgwidth, imgheight), b"".join(lines))
    return img


def perspective_line_renderer(
    work: multiprocessing.Queue,
    results: multiprocessing.Queue,
    minx: int,
    maxx: int,
    imgwidth: int,
    imgheight: int,
    texwidth: int,
    texheight: int,
    xscale: float,
    yscale: float,
    inverse: Matrix,
    add_color: Color,
    mult_color: Color,
    hsl_shift: HSL,
    blendfunc: int,
    imgbytes: Union[bytes, bytearray],
    texbytes: Union[bytes, bytearray],
    maskbytes: Optional[Union[bytes, bytearray]],
    aa_mode: int,
) -> None:
    def perspective_inverse(imgpoint: Point) -> Optional[Point]:
        # Calculate the texture coordinate with our perspective interpolation.
        texdiv = inverse.multiply_point(imgpoint)
        if texdiv.z <= 0.0:
            return None

        return Point(texdiv.x / texdiv.z, texdiv.y / texdiv.z)

    while True:
        imgy = work.get()
        if imgy is None:
            return

        rowbytes = bytearray(imgbytes[(imgy * imgwidth * 4) : ((imgy + 1) * imgwidth * 4)])
        for imgx in range(imgwidth):
            if imgx < minx or imgx >= maxx:
                # No need to even consider this pixel.
                continue
            else:
                # Blit new pixel into the correct range.
                rowbytes[(imgx * 4) : ((imgx + 1) * 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    xscale,
                    yscale,
                    perspective_inverse,
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    aa_mode,
                )

        results.put((imgy, bytes(rowbytes)))


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
    # Warn if we have an unsupported blend.
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
    inverse_matrix, minx, miny, maxx, maxy = perspective_calculate(
        imgwidth, imgheight, texwidth, texheight, transform, camera, focal_length
    )
    if inverse_matrix is None:
        # This texture is entirely off of the screen.
        return img

    def perspective_inverse(imgpoint: Point) -> Optional[Point]:
        # Calculate the texture coordinate with our perspective interpolation.
        texdiv = inverse_matrix.multiply_point(imgpoint)
        if texdiv.z <= 0.0:
            return None

        return Point(texdiv.x / texdiv.z, texdiv.y / texdiv.z)

    cores = multiprocessing.cpu_count()
    if single_threaded or cores < 2:
        # Get the data in an easier to manipulate and faster to update fashion.
        imgbytearray = bytearray(img.tobytes("raw", "RGBA"))
        texbytes = texture.tobytes("raw", "RGBA")
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes("raw", "L")
        else:
            maskbytes = None

        # We don't have enough CPU cores to bother multiprocessing.
        for imgy in range(miny, maxy):
            for imgx in range(minx, maxx):
                # Determine offset
                imgoff = (imgx + (imgy * imgwidth)) * 4
                imgbytearray[imgoff : (imgoff + 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    transform.xscale,
                    transform.yscale,
                    perspective_inverse,
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytearray,
                    texbytes,
                    maskbytes,
                    aa_mode,
                )

        img = Image.frombytes("RGBA", (imgwidth, imgheight), bytes(imgbytearray))
    else:
        imgbytes = img.tobytes("raw", "RGBA")
        texbytes = texture.tobytes("raw", "RGBA")
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes("raw", "L")
        else:
            maskbytes = None

        # Let's spread the load across multiple processors.
        procs: List[multiprocessing.Process] = []
        work: multiprocessing.Queue = multiprocessing.Queue()
        results: multiprocessing.Queue = multiprocessing.Queue()
        expected: int = 0
        interrupted: bool = False

        def ctrlc(sig: Any, frame: Any) -> None:
            nonlocal interrupted
            interrupted = True

        previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, ctrlc)

        for _ in range(cores):
            proc = multiprocessing.Process(
                target=perspective_line_renderer,
                args=(
                    work,
                    results,
                    minx,
                    maxx,
                    imgwidth,
                    imgheight,
                    texwidth,
                    texheight,
                    transform.xscale,
                    transform.yscale,
                    inverse_matrix,
                    add_color,
                    mult_color,
                    hsl_shift,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    aa_mode,
                ),
            )
            procs.append(proc)
            proc.start()

        for imgy in range(miny, maxy):
            work.put(imgy)
            expected += 1

        lines: List[bytes] = [
            imgbytes[x : (x + (imgwidth * 4))]
            for x in range(
                0,
                imgwidth * imgheight * 4,
                imgwidth * 4,
            )
        ]
        for _ in range(expected):
            imgy, result = results.get()
            lines[imgy] = result

        for _proc in procs:
            work.put(None)
        for proc in procs:
            proc.join()

        signal.signal(signal.SIGINT, previous_handler)
        if interrupted:
            raise KeyboardInterrupt()

        img = Image.frombytes("RGBA", (imgwidth, imgheight), b"".join(lines))
    return img
