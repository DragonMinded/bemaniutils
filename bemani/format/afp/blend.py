import multiprocessing
import signal
from PIL import Image  # type: ignore
from typing import Any, List, Sequence, Tuple

from .types.generic import Color, Matrix, Point


def clamp(color: float) -> int:
    return min(max(0, round(color)), 255)


def blend_normal(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Sequence[int]:
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
    srcremaineder = 1.0 - srcpercent
    new_alpha = (srcpercent + destpercent * srcremaineder)
    return (
        clamp(((dest[0] * destpercent * srcremaineder) + (src[0] * srcpercent)) / new_alpha),
        clamp(((dest[1] * destpercent * srcremaineder) + (src[1] * srcpercent)) / new_alpha),
        clamp(((dest[2] * destpercent * srcremaineder) + (src[2] * srcpercent)) / new_alpha),
        clamp(255 * new_alpha)
    )


def blend_addition(
    # RGBA color tuple representing what's already at the dest.
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Sequence[int]:
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
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Sequence[int]:
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
    dest: Sequence[int],
    # RGBA color tuple representing the source we want to blend to the dest.
    src: Sequence[int],
    # A pre-scaled color where all values are 0.0-1.0, used to calculate the final color.
    mult_color: Color,
    # A RGBA color tuple where all values are 0-255, used to calculate the final color.
    add_color: Tuple[int, int, int, int],
) -> Sequence[int]:
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
    single_threaded: bool = False,
) -> Image.Image:
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

    cores = multiprocessing.cpu_count()
    if single_threaded or cores < 2:
        # Get the data in an easier to manipulate and faster to update fashion.
        imgmap = list(img.getdata())
        texmap = list(texture.getdata())

        # We don't have enough CPU cores to bother multiprocessing.
        for imgy in range(miny, maxy):
            for imgx in range(minx, maxx):
                # Determine offset
                imgoff = imgx + (imgy * imgwidth)

                # Calculate what texture pixel data goes here.
                texloc = inverse.multiply_point(Point(float(imgx), float(imgy))).add(origin)
                texx, texy = texloc.as_tuple()

                # If we're out of bounds, don't update.
                if texx < 0 or texy < 0 or texx >= texwidth or texy >= texheight:
                    continue

                # Blend it.
                texoff = texx + (texy * texwidth)
                imgmap[imgoff] = affine_blend_impl(add_color, mult_color, texmap[texoff], imgmap[imgoff], blendfunc)

        img.putdata(imgmap)
    else:
        imgbytes = img.tobytes('raw', 'RGBA')
        texbytes = texture.tobytes('raw', 'RGBA')

        # Let's spread the load across multiple processors.
        procs: List[multiprocessing.Process] = []
        work: multiprocessing.Queue = multiprocessing.Queue()
        results: multiprocessing.Queue = multiprocessing.Queue()
        expected: int = 0
        interrupted: bool = False

        def ctrlc(sig: Any, frame: Any) -> None:
            nonlocal interrupted
            interrupted = True

        original_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, ctrlc)

        for _ in range(cores):
            proc = multiprocessing.Process(
                target=pixel_renderer,
                args=(
                    work,
                    results,
                    minx,
                    maxx,
                    imgwidth,
                    texwidth,
                    texheight,
                    inverse,
                    origin,
                    add_color,
                    mult_color,
                    blendfunc,
                    imgbytes,
                    texbytes,
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

        signal.signal(signal.SIGINT, original_handler)
        if interrupted:
            raise KeyboardInterrupt()

        img = Image.frombytes('RGBA', (imgwidth, imgheight), b''.join(lines))
    return img


def pixel_renderer(
    work: multiprocessing.Queue,
    results: multiprocessing.Queue,
    minx: int,
    maxx: int,
    imgwidth: int,
    texwidth: int,
    texheight: int,
    inverse: Matrix,
    origin: Point,
    add_color: Tuple[int, int, int, int],
    mult_color: Color,
    blendfunc: int,
    imgbytes: bytes,
    texbytes: bytes,
) -> None:
    while True:
        imgy = work.get()
        if imgy is None:
            return

        result: List[Sequence[int]] = []
        for imgx in range(imgwidth):
            # Determine offset
            imgoff = imgx + (imgy * imgwidth)
            if imgx < minx or imgx >= maxx:
                result.append(imgbytes[(imgoff * 4):((imgoff + 1) * 4)])
                continue

            # Calculate what texture pixel data goes here.
            texloc = inverse.multiply_point(Point(float(imgx), float(imgy))).add(origin)
            texx, texy = texloc.as_tuple()

            # If we're out of bounds, don't update.
            if texx < 0 or texy < 0 or texx >= texwidth or texy >= texheight:
                result.append(imgbytes[(imgoff * 4):((imgoff + 1) * 4)])
                continue

            # Blend it.
            texoff = texx + (texy * texwidth)
            result.append(affine_blend_impl(add_color, mult_color, texbytes[(texoff * 4):((texoff + 1) * 4)], imgbytes[(imgoff * 4):((imgoff + 1) * 4)], blendfunc))

        linebytes = bytes([channel for pixel in result for channel in pixel])
        results.put((imgy, linebytes))


def affine_blend_impl(
    add_color: Tuple[int, int, int, int],
    mult_color: Color,
    # This should be a sequence of exactly 4 values, either bytes or a tuple.
    src_color: Sequence[int],
    # This should be a sequence of exactly 4 values, either bytes or a tuple.
    dest_color: Sequence[int],
    blendfunc: int,
) -> Sequence[int]:
    if blendfunc == 3:
        return blend_multiply(dest_color, src_color, mult_color, add_color)
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
        return blend_addition(dest_color, src_color, mult_color, add_color)
    elif blendfunc == 9 or blendfunc == 70:
        return blend_subtraction(dest_color, src_color, mult_color, add_color)
    # TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
    # Src * (1 - Dst) + Dst * (1 - Src).
    else:
        return blend_normal(dest_color, src_color, mult_color, add_color)
