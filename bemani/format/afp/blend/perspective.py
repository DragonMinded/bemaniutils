from typing import Dict, List, Optional, Tuple

from ..types import Matrix, Point


def perspective_calculate(
    imgwidth: int,
    imgheight: int,
    texwidth: int,
    texheight: int,
    transform: Matrix,
    camera: Point,
    focal_length: float,
) -> Tuple[Optional[Matrix], int, int, int, int]:
    # Arbitrarily choose three points on the texture to create a pair of vectors
    # so that we can interpolate backwards. This isn't as simple as inverting the
    # view matrix like in affine compositing because dividing by Z makes the
    # perspective transform non-linear. So instead we interpolate 1/Z, u/Z and
    # v/Z since those ARE linear, and work backwards from there.
    xy: List[Point] = []
    uvz: Dict[Point, Point] = {}
    minz: Optional[float] = None
    maxz: Optional[float] = None
    for texx, texy in [
        (0, 0),
        (texwidth, 0),
        (0, texheight),
        # Include this just to get a good upper bounds for where the texture
        # will be drawn.
        (texwidth, texheight),
    ]:
        imgloc = transform.multiply_point(Point(texx, texy))
        distance = imgloc.z - camera.z
        imgx = ((imgloc.x - camera.x) * (focal_length / distance)) + camera.x
        imgy = ((imgloc.y - camera.y) * (focal_length / distance)) + camera.y

        if minz is None:
            minz = distance
        else:
            minz = min(distance, minz)
        if maxz is None:
            maxz = distance
        else:
            maxz = max(distance, maxz)

        xy_point = Point(imgx, imgy)
        xy.append(xy_point)
        uvz[xy_point] = Point(
            texx / distance,
            texy / distance,
            1 / distance,
        )

    # Clip out anything that is completely off screen.
    if minz is None or maxz is None:
        raise Exception("Logic error!")

    # Calculate the maximum range of update this texture can possibly reside in.
    minx = max(int(min(p.x for p in xy)), 0)
    maxx = min(int(max(p.x for p in xy)) + 1, imgwidth)
    miny = max(int(min(p.y for p in xy)), 0)
    maxy = min(int(max(p.y for p in xy)) + 1, imgheight)

    if minz <= 0.0 and maxz <= 0.0:
        # This is entirely behind the camera, clip it.
        return (None, minx, miny, maxx, maxy)

    if minx >= imgwidth or maxx < 0 or miny >= imgheight or maxy < 0:
        # This is entirely off screen, clip it.
        return (None, minx, miny, maxx, maxy)

    if minz < 0.0 and maxz > 0.0:
        # This clips through the camera, default to drawing the whole image.
        minx = 0
        maxx = imgwidth
        miny = 0
        maxy = imgheight

    # Now that we have three points, construct a matrix that allows us to calculate
    # what amount of each u/z, v/z and 1/z vector we need to interpolate values. The
    # below matrix gives us an affine transform that will convert a point that's in
    # the range 0, 0 to 1, 1 to a point inside the parallellogram that is made by
    # projecting the two vectors we got from calculating the three texture points above.
    xy_matrix = Matrix.affine(
        a=xy[1].x - xy[0].x,
        b=xy[1].y - xy[0].y,
        c=xy[2].x - xy[0].x,
        d=xy[2].y - xy[0].y,
        tx=xy[0].x,
        ty=xy[0].y,
    )

    # We invert that above, which gives us a matrix that can take screen space (imgx,
    # imgy) and gives us instead those ratios, which allows us to then interpolate the
    # u/z, v/z and 1/z values.
    try:
        xy_matrix = xy_matrix.inverse()
    except ZeroDivisionError:
        # This can't be inverted, so this shouldn't be displayed.
        return (None, minx, miny, maxx, maxy)

    # We construct a second matrix, which interpolates coordinates in the range of
    # 0, 0 to 1, 1 and gives us back the u/z, v/z and 1/z values.
    uvz_matrix = Matrix(
        a11=uvz[xy[1]].x - uvz[xy[0]].x,
        a12=uvz[xy[1]].y - uvz[xy[0]].y,
        a13=uvz[xy[1]].z - uvz[xy[0]].z,
        a21=uvz[xy[2]].x - uvz[xy[0]].x,
        a22=uvz[xy[2]].y - uvz[xy[0]].y,
        a23=uvz[xy[2]].z - uvz[xy[0]].z,
        a31=0.0,
        a32=0.0,
        a33=0.0,
        a41=uvz[xy[0]].x,
        a42=uvz[xy[0]].y,
        a43=uvz[xy[0]].z,
    )

    # Finally, we can combine the two matrixes to do the interpolation all at once.
    inverse_matrix = xy_matrix.multiply(uvz_matrix)
    return (inverse_matrix, minx, miny, maxx, maxy)
