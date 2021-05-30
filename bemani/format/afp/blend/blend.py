import multiprocessing
import signal
from PIL import Image  # type: ignore
from typing import Any, List, Optional, Sequence, Union

from ..types import Color, Matrix, Point


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
        clamp(255 * new_alpha)
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
    return (
        clamp(255 * ((dest[0] / 255.0) * (src[0] / 255.0))),
        clamp(255 * ((dest[1] / 255.0) * (src[1] / 255.0))),
        clamp(255 * ((dest[2] / 255.0) * (src[2] / 255.0))),
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

    if blendfunc == 3:
        return blend_multiply(dest_color, src_color)
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
        return blend_addition(dest_color, src_color)
    elif blendfunc == 9 or blendfunc == 70:
        return blend_subtraction(dest_color, src_color)
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

    # Warn if we have an unsupported blend.
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

    cores = multiprocessing.cpu_count()
    if single_threaded or cores < 2:
        # Get the data in an easier to manipulate and faster to update fashion.
        imgbytes = bytearray(img.tobytes('raw', 'RGBA'))
        texbytes = texture.tobytes('raw', 'RGBA')
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes('raw', 'L')
        else:
            maskbytes = None

        # We don't have enough CPU cores to bother multiprocessing.
        for imgy in range(miny, maxy):
            for imgx in range(minx, maxx):
                # Determine offset
                imgoff = (imgx + (imgy * imgwidth)) * 4
                imgbytes[imgoff:(imgoff + 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    texwidth,
                    texheight,
                    inverse,
                    add_color,
                    mult_color,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    enable_aa,
                )

        img = Image.frombytes('RGBA', (imgwidth, imgheight), bytes(imgbytes))
    else:
        imgbytes = img.tobytes('raw', 'RGBA')
        texbytes = texture.tobytes('raw', 'RGBA')
        if mask:
            alpha = mask.split()[-1]
            maskbytes = alpha.tobytes('raw', 'L')
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
                target=line_renderer,
                args=(
                    work,
                    results,
                    minx,
                    maxx,
                    imgwidth,
                    texwidth,
                    texheight,
                    inverse,
                    add_color,
                    mult_color,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    enable_aa,
                ),
            )
            procs.append(proc)
            proc.start()

        for imgy in range(miny, maxy):
            work.put(imgy)
            expected += 1

        lines: List[bytes] = [
            imgbytes[x:(x + (imgwidth * 4))]
            for x in range(
                0,
                imgwidth * imgheight * 4,
                imgwidth * 4,
            )
        ]
        for _ in range(expected):
            imgy, result = results.get()
            lines[imgy] = result

        for proc in procs:
            work.put(None)
        for proc in procs:
            proc.join()

        signal.signal(signal.SIGINT, previous_handler)
        if interrupted:
            raise KeyboardInterrupt()

        img = Image.frombytes('RGBA', (imgwidth, imgheight), b''.join(lines))
    return img


def line_renderer(
    work: multiprocessing.Queue,
    results: multiprocessing.Queue,
    minx: int,
    maxx: int,
    imgwidth: int,
    texwidth: int,
    texheight: int,
    inverse: Matrix,
    add_color: Color,
    mult_color: Color,
    blendfunc: int,
    imgbytes: Union[bytes, bytearray],
    texbytes: Union[bytes, bytearray],
    maskbytes: Optional[Union[bytes, bytearray]],
    enable_aa: bool,
) -> None:
    while True:
        imgy = work.get()
        if imgy is None:
            return

        rowbytes = bytearray(imgbytes[(imgy * imgwidth * 4):((imgy + 1) * imgwidth * 4)])
        for imgx in range(imgwidth):
            if imgx < minx or imgx >= maxx:
                # No need to even consider this pixel.
                continue
            else:
                # Blit new pixel into the correct range.
                rowbytes[(imgx * 4):((imgx + 1) * 4)] = pixel_renderer(
                    imgx,
                    imgy,
                    imgwidth,
                    texwidth,
                    texheight,
                    inverse,
                    add_color,
                    mult_color,
                    blendfunc,
                    imgbytes,
                    texbytes,
                    maskbytes,
                    enable_aa,
                )

        results.put((imgy, bytes(rowbytes)))


def pixel_renderer(
    imgx: int,
    imgy: int,
    imgwidth: int,
    texwidth: int,
    texheight: int,
    inverse: Matrix,
    add_color: Color,
    mult_color: Color,
    blendfunc: int,
    imgbytes: Union[bytes, bytearray],
    texbytes: Union[bytes, bytearray],
    maskbytes: Optional[Union[bytes, bytearray]],
    enable_aa: bool,
) -> Sequence[int]:
    # Determine offset
    maskoff = imgx + (imgy * imgwidth)
    imgoff = maskoff * 4

    if maskbytes is not None and maskbytes[maskoff] == 0:
        # This pixel is masked off!
        return imgbytes[imgoff:(imgoff + 4)]

    if enable_aa:
        r = 0
        g = 0
        b = 0
        a = 0
        count = 0

        xswing = abs(0.5 / inverse.a)
        yswing = abs(0.5 / inverse.d)

        xpoints = [0.5 - xswing, 0.5 - (xswing / 2.0), 0.5, 0.5 + (xswing / 2.0), 0.5 + xswing]
        ypoints = [0.5 - yswing, 0.5 - (yswing / 2.0), 0.5, 0.5 + (yswing / 2.0), 0.5 + yswing]

        for addy in ypoints:
            for addx in xpoints:
                texloc = inverse.multiply_point(Point(imgx + addx, imgy + addy))
                aax, aay = texloc.as_tuple()

                # If we're out of bounds, don't update.
                if aax < 0 or aay < 0 or aax >= texwidth or aay >= texheight:
                    continue

                # Grab the values to average, for SSAA.
                texoff = (aax + (aay * texwidth)) * 4
                r += texbytes[texoff]
                g += texbytes[texoff + 1]
                b += texbytes[texoff + 2]
                a += texbytes[texoff + 3]
                count += 1

        if count == 0:
            # None of the samples existed in-bounds.
            return imgbytes[imgoff:(imgoff + 4)]

        # Average the pixels.
        average = [r // count, g // count, b // count, a // count]
        return blend_point(add_color, mult_color, average, imgbytes[imgoff:(imgoff + 4)], blendfunc)
    else:
        # Calculate what texture pixel data goes here.
        texloc = inverse.multiply_point(Point(imgx + 0.5, imgy + 0.5))
        texx, texy = texloc.as_tuple()

        # If we're out of bounds, don't update.
        if texx < 0 or texy < 0 or texx >= texwidth or texy >= texheight:
            return imgbytes[imgoff:(imgoff + 4)]

        # Blend it.
        texoff = (texx + (texy * texwidth)) * 4
        return blend_point(add_color, mult_color, texbytes[texoff:(texoff + 4)], imgbytes[imgoff:(imgoff + 4)], blendfunc)
