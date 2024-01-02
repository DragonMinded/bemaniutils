import os
import struct
from typing import Any, Dict, List, Optional

from .types import Color, Point, Rectangle
from .util import descramble_text


class Shape:
    def __init__(
        self,
        name: str,
        data: bytes,
    ) -> None:
        self.name = name
        self.data = data

        # Vertex points outlining this shape. These are in pixels and the rectangle they outline
        # should match the size of the texture in pixels.
        self.vertex_points: List[Point] = []

        # Texture points, as used alongside vertex chunks when the shape contains a texture. These
        # are in floating points that when multiplied by the width and height of the original
        # texture sheet that the texture was taken from (multiplied by two), should match the uvrect
        # of the texture exactly.
        self.tex_points: List[Point] = []

        # Colors for texture points, if they exist in the file.
        self.tex_colors: List[Color] = []

        # Actual shape drawing parameters.
        self.draw_params: List[DrawParams] = []

        # Bounds of the shape.
        self.bounds: Rectangle = Rectangle.Empty()

        # Whether this is parsed.
        self.parsed = False

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vertex_points": [p.as_dict(*args, **kwargs) for p in self.vertex_points],
            "tex_points": [p.as_dict(*args, **kwargs) for p in self.tex_points],
            "tex_colors": [c.as_dict(*args, **kwargs) for c in self.tex_colors],
            "draw_params": [d.as_dict(*args, **kwargs) for d in self.draw_params],
            "bounds": self.bounds.as_dict(args, kwargs),
        }

    def __repr__(self) -> str:
        return os.linesep.join(
            [
                *[f"vertex point: {vertex}" for vertex in self.vertex_points],
                *[f"tex point: {tex}" for tex in self.tex_points],
                *[f"tex color: {color}" for color in self.tex_colors],
                *[f"draw params: {params}" for params in self.draw_params],
                *[f"bounds: {self.bounds}"],
            ]
        )

    def get_until_null(self, offset: int) -> bytes:
        out = b""
        while self.data[offset] != 0:
            out += self.data[offset : (offset + 1)]
            offset += 1
        return out

    def parse(self, text_obfuscated: bool = True) -> None:
        # First, grab the header bytes.
        magic = self.data[0:4]

        if magic == b"D2EG":
            endian = "<"
        elif magic == b"GE2D":
            endian = ">"
        else:
            raise Exception("Invalid magic value in GE2D structure!")

        # There are two integers at 0x4 and 0x8 which are basically file versions.

        filesize, fileflags = struct.unpack(f"{endian}II", self.data[12:20])
        if filesize != len(self.data):
            raise Exception("Unexpected file size for GE2D structure!")

        geo_has_bounds_floats = bool(fileflags & 0x4)
        vertex_well_formed_rectangle = bool(fileflags & 0x8)
        if fileflags & ~0xC:
            raise Exception(f"Unexpected file flags {fileflags} in GE2D structure!")

        (
            vertex_count,
            tex_count,
            color_count,
            label_count,
            render_params_count,
            _,
        ) = struct.unpack(
            f"{endian}HHHHHH",
            self.data[20:32],
        )

        (
            vertex_offset,
            tex_offset,
            color_offset,
            label_offset,
            render_params_offset,
        ) = struct.unpack(
            f"{endian}IIIII",
            self.data[32:52],
        )

        vertex_points: List[Point] = []
        if vertex_offset != 0:
            # If fileflags & 0x8 is set, these go in clockwise order starting at the top left
            # point and there are only 8 of them, making a rectangle.
            for vertexno in range(vertex_count):
                vertexno_offset = vertex_offset + (8 * vertexno)
                x, y = struct.unpack(f"{endian}ff", self.data[vertexno_offset : vertexno_offset + 8])
                vertex_points.append(Point(x, y))
        self.vertex_points = vertex_points

        tex_points: List[Point] = []
        if tex_offset != 0:
            for texno in range(tex_count):
                texno_offset = tex_offset + (8 * texno)
                x, y = struct.unpack(f"{endian}ff", self.data[texno_offset : texno_offset + 8])
                tex_points.append(Point(x, y))
        self.tex_points = tex_points

        colors: List[Color] = []
        if color_offset != 0:
            for colorno in range(color_count):
                colorno_offset = color_offset + (4 * colorno)
                rgba = struct.unpack(f"{endian}I", self.data[colorno_offset : colorno_offset + 4])[0]
                color = Color(
                    a=(rgba & 0xFF) / 255.0,
                    b=((rgba >> 8) & 0xFF) / 255.0,
                    g=((rgba >> 16) & 0xFF) / 255.0,
                    r=((rgba >> 24) & 0xFF) / 255.0,
                )
                colors.append(color)
        self.tex_colors = colors

        labels: List[str] = []
        if label_offset != 0:
            for labelno in range(label_count):
                labelno_offset = label_offset + (4 * labelno)
                labelptr = struct.unpack(f"{endian}I", self.data[labelno_offset : labelno_offset + 4])[0]

                bytedata = self.get_until_null(labelptr)
                labels.append(descramble_text(bytedata, text_obfuscated))

        # Parse rectangle bounds.
        if geo_has_bounds_floats:
            left, right, top, bottom = struct.unpack(f"{endian}ffff", self.data[52:68])
            self.bounds = Rectangle(
                left=left,
                right=right,
                top=top,
                bottom=bottom,
            )
        elif vertex_well_formed_rectangle:
            self.bounds = Rectangle(
                left=vertex_points[0].x,
                right=vertex_points[1].x,
                top=vertex_points[0].y,
                bottom=vertex_points[2].y,
            )
        else:
            if vertex_points:
                self.bounds.left = vertex_points[0].x
                self.bounds.right = vertex_points[0].x
                self.bounds.top = vertex_points[0].y
                self.bounds.bottom = vertex_points[0].y

            for pt in vertex_points:
                if pt.x < self.bounds.left:
                    self.bounds.left = pt.x
                if pt.x > self.bounds.right:
                    self.bounds.right = pt.x
                if pt.y < self.bounds.top:
                    self.bounds.top = pt.y
                if pt.y > self.bounds.bottom:
                    self.bounds.bottom = pt.y

        draw_params: List[DrawParams] = []
        if render_params_offset != 0:
            # The actual render parameters for the shape. This dictates how the texture values
            # are used when drawing shapes, whether to use a blend value or draw a primitive, etc.
            for render_paramsno in range(render_params_count):
                render_paramsno_offset = render_params_offset + (16 * render_paramsno)
                (
                    mode,
                    flags,
                    tex1,
                    tex2,
                    trianglecount,
                    unk,
                    rgba,
                    triangleoffset,
                ) = struct.unpack(
                    f"{endian}BBBBHHII",
                    self.data[(render_paramsno_offset) : (render_paramsno_offset + 16)],
                )

                if mode != 4:
                    raise Exception("Unexpected mode in GE2D structure!")
                if (flags & 0x2) and not labels:
                    raise Exception("GE2D structure has a texture, but no region labels present!")
                if (flags & 0x2) and (tex1 == 0xFF):
                    raise Exception("GE2D structure requests a texture, but no texture pointer present!")
                if tex2 != 0xFF:
                    raise Exception("GE2D structure requests a second texture, but we don't support this!")
                if unk != 0x0:
                    raise Exception("Unhandled unknown data in GE2D structure!")

                color = Color(
                    a=(rgba & 0xFF) / 255.0,
                    b=((rgba >> 8) & 0xFF) / 255.0,
                    g=((rgba >> 16) & 0xFF) / 255.0,
                    r=((rgba >> 24) & 0xFF) / 255.0,
                )

                verticies: List[int] = []
                for render_paramstriangleno in range(trianglecount):
                    render_paramstriangleno_offset = triangleoffset + (2 * render_paramstriangleno)
                    tex_offset = struct.unpack(
                        f"{endian}H",
                        self.data[render_paramstriangleno_offset : (render_paramstriangleno_offset + 2)],
                    )[0]
                    verticies.append(tex_offset)

                # Seen bits are 0x1, 0x2, 0x4, 0x8 so far.
                # 0x1 Is a "this shape is instantiable/drawable" bit.
                # 0x2 Is the shape having a texture.
                # 0x4 Is the shape having a texture color per texture point.
                # 0x8 Is "draw background color/blend" flag.
                # 0x40 Is a "normalize texture coordinates" flag. It performs the below algorithm.

                if (flags & (0x2 | 0x40)) == (0x2 | 0x40):
                    # The tex offsets point at the tex vals parsed above, and are used in conjunction with
                    # texture/region metrics to calcuate some offsets. First, the region left/right/top/bottom
                    # is divided by 2 (looks like a scaling of 2 for regions to textures is hardcoded) and then
                    # divided by the texture width/height (as relevant). The returned metrics are in texture space
                    # where 0.0 is the origin and 1.0 is the furthest right/down. The metrics are then multiplied
                    # by the texture point pairs that appear above, meaning they should be treated as percentages.
                    pass

                draw_params.append(
                    DrawParams(
                        flags=flags,
                        region=labels[tex1] if (flags & 0x2) else None,
                        vertexes=verticies if (flags & 0x6) else [],
                        blend=color if (flags & 0x8) else None,
                    )
                )
        self.draw_params = draw_params
        self.parsed = True


class DrawParams:
    def __init__(
        self,
        flags: int,
        region: Optional[str] = None,
        vertexes: List[int] = [],
        blend: Optional[Color] = None,
    ) -> None:
        self.flags = flags
        self.region = region
        self.vertexes = vertexes
        self.blend = blend

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "flags": self.flags,
            "region": self.region,
            "vertexes": self.vertexes,
            "blend": self.blend.as_dict(*args, **kwargs) if self.blend else None,
        }

    def __repr__(self) -> str:
        flagbits: List[str] = []
        if self.flags & 0x1:
            flagbits.append("(Instantiable)")
        if self.flags & 0x2:
            flagbits.append("(Includes Texture)")
        if self.flags & 0x4:
            flagbits.append("(Includes Texture Color)")
        if self.flags & 0x8:
            flagbits.append("(Includes Blend Color)")
        if self.flags & 0x40:
            flagbits.append("(Needs Tex Point Normalization)")

        flagspart = f"flags: {hex(self.flags)} {' '.join(flagbits)}"
        if self.flags & 0x2:
            texpart = f", region: {self.region}, vertexes: {', '.join(str(x) for x in self.vertexes)}"
        else:
            texpart = ""

        if self.flags & 0x8:
            blendpart = f", blend: {self.blend}"
        else:
            blendpart = ""

        return f"{flagspart}{texpart}{blendpart}"
