from typing import Dict, List, Tuple, Optional, Union
from PIL import Image  # type: ignore

from .swf import SWF, Frame, Tag, AP2ShapeTag, AP2DefineSpriteTag, AP2PlaceObjectTag, AP2RemoveObjectTag, AP2DoActionTag, AP2DefineFontTag, AP2DefineEditTextTag
from .types import Color, Matrix, Point
from .geo import Shape, DrawParams
from .util import VerboseOutput


class RegisteredClip:
    # A movie clip that we are rendering, frame by frame. These are manifest by the root
    # SWF as well as AP2DefineSpriteTags which are essentially embedded movie clips. The
    # tag_id is the AP2DefineSpriteTag that created us, or None if this is the clip for
    # the root of the movie.
    def __init__(self, tag_id: Optional[int], frames: List[Frame], tags: List[Tag]) -> None:
        self.tag_id = tag_id
        self.frames = frames
        self.tags = tags

    def __repr__(self) -> str:
        return f"RegisteredClip(tag_id={self.tag_id})"


class RegisteredShape:
    # A shape that we are rendering, as placed by some placed clip somewhere.
    def __init__(self, tag_id: int, vertex_points: List[Point], tex_points: List[Point], tex_colors: List[Color], draw_params: List[DrawParams]) -> None:
        self.tag_id = tag_id
        self.vertex_points: List[Point] = vertex_points
        self.tex_points: List[Point] = tex_points
        self.tex_colors: List[Color] = tex_colors
        self.draw_params: List[DrawParams] = draw_params

    def __repr__(self) -> str:
        return f"RegisteredShape(tag_id={self.tag_id}, vertex_points={self.vertex_points}, tex_points={self.tex_points}, tex_colors={self.tex_colors}, draw_params={self.draw_params})"


class PlacedObject:
    # An object that occupies the screen at some depth.
    def __init__(self, object_id: int, depth: int, rotation_offset: Point, transform: Matrix, mult_color: Color, add_color: Color, blend: int) -> None:
        self.__object_id = object_id
        self.__depth = depth
        self.rotation_offset = rotation_offset
        self.transform = transform
        self.mult_color = mult_color
        self.add_color = add_color
        self.blend = blend

    @property
    def source(self) -> Union[RegisteredClip, RegisteredShape]:
        raise NotImplementedError("Only implemented in subclass!")

    @property
    def depth(self) -> int:
        return self.__depth

    @property
    def object_id(self) -> int:
        return self.__object_id

    def __repr__(self) -> str:
        return f"PlacedObject(object_id={self.object_id}, depth={self.depth})"


class PlacedShape(PlacedObject):
    # A shape that occupies its parent clip at some depth. Placed by an AP2PlaceObjectTag
    # referencing an AP2ShapeTag.
    def __init__(self, object_id: int, depth: int, rotation_offset: Point, transform: Matrix, mult_color: Color, add_color: Color, blend: int, source: RegisteredShape) -> None:
        super().__init__(object_id, depth, rotation_offset, transform, mult_color, add_color, blend)
        self.__source = source

    @property
    def source(self) -> RegisteredShape:
        return self.__source

    def __repr__(self) -> str:
        return f"PlacedShape(object_id={self.object_id}, depth={self.depth}, source={self.source})"


class PlacedClip(PlacedObject):
    # A movieclip that occupies its parent clip at some depth. Placed by an AP2PlaceObjectTag
    # referencing an AP2DefineSpriteTag. Essentially an embedded movie clip.
    def __init__(self, object_id: int, depth: int, rotation_offset: Point, transform: Matrix, mult_color: Color, add_color: Color, blend: int, source: RegisteredClip) -> None:
        super().__init__(object_id, depth, rotation_offset, transform, mult_color, add_color, blend)
        self.placed_objects: List[PlacedObject] = []
        self.frame: int = 0
        self.__source = source

    @property
    def source(self) -> RegisteredClip:
        return self.__source

    def advance(self) -> None:
        if self.frame < len(self.source.frames):
            self.frame += 1

    @property
    def finished(self) -> bool:
        return self.frame == len(self.source.frames)

    @property
    def running(self) -> bool:
        for obj in self.placed_objects:
            if isinstance(obj, PlacedClip) and obj.running:
                return True
        return not self.finished

    def __repr__(self) -> str:
        return f"PlacedClip(object_id={self.object_id}, depth={self.depth}, source={self.source}, frame={self.frame}, total_frames={len(self.source.frames)}, running={self.running}, finished={self.finished})"


class AFPRenderer(VerboseOutput):
    def __init__(self, shapes: Dict[str, Shape] = {}, textures: Dict[str, Image.Image] = {}, swfs: Dict[str, SWF] = {}) -> None:
        super().__init__()

        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Image.Image] = textures
        self.swfs: Dict[str, SWF] = swfs

        # Internal render parameters.
        self.__registered_objects: Dict[int, Union[RegisteredShape, RegisteredClip]] = {}

    def add_shape(self, name: str, data: Shape) -> None:
        # Register a named shape with the renderer.
        if not data.parsed:
            data.parse()
        self.shapes[name] = data

    def add_texture(self, name: str, data: Image.Image) -> None:
        # Register a named texture (already loaded PIL image) with the renderer.
        self.textures[name] = data.convert("RGBA")

    def add_swf(self, name: str, data: SWF) -> None:
        # Register a named SWF with the renderer.
        if not data.parsed:
            data.parse()
        self.swfs[name] = data

    def render_path(self, path: str, background_color: Optional[Color] = None, verbose: bool = False) -> Tuple[int, List[Image.Image]]:
        # Given a path to a SWF root animation or an exported animation inside a SWF,
        # attempt to render it to a list of frames, one per image.
        components = path.split(".")

        if len(components) > 2:
            raise Exception('Expected a path in the form of "moviename" or "moviename.exportedtag"!')

        for name, swf in self.swfs.items():
            if swf.exported_name == components[0]:
                # This is the SWF we care about.
                with self.debugging(verbose):
                    swf.color = background_color or swf.color
                    return self.__render(swf, components[1] if len(components) > 1 else None)

        raise Exception(f'{path} not found in registered SWFs!')

    def list_paths(self, verbose: bool = False) -> List[str]:
        # Given the loaded animations, return a list of possible paths to render.
        paths: List[str] = []

        for name, swf in self.swfs.items():
            paths.append(swf.exported_name)

            for export_tag in swf.exported_tags:
                paths.append(f"{swf.exported_name}.{export_tag}")

        return paths

    def __place(self, tag: Tag, operating_clip: PlacedClip, prefix: str = "") -> Tuple[Optional[PlacedClip], bool]:
        # "Place" a tag on the screen. Most of the time, this means performing the action of the tag,
        # such as defining a shape (registering it with our shape list) or adding/removing an object.
        if isinstance(tag, AP2ShapeTag):
            self.vprint(f"{prefix}    Loading {tag.reference} into object slot {tag.id}")

            if tag.reference not in self.shapes:
                raise Exception(f"Cannot find shape reference {tag.reference}!")
            if tag.id in self.__registered_objects:
                raise Exception(f"Cannot register {tag.reference} as object slot {tag.id} is already taken!")

            self.__registered_objects[tag.id] = RegisteredShape(
                tag.id,
                self.shapes[tag.reference].vertex_points,
                self.shapes[tag.reference].tex_points,
                self.shapes[tag.reference].tex_colors,
                self.shapes[tag.reference].draw_params,
            )

            # Didn't place a new clip, didn't change anything.
            return None, False

        elif isinstance(tag, AP2DefineSpriteTag):
            self.vprint(f"{prefix}    Loading Sprite into object slot {tag.id}")

            if tag.id in self.__registered_objects:
                raise Exception(f"Cannot register sprite as object slot {tag.id} is already taken!")

            # Register a new clip that we might reference to execute.
            self.__registered_objects[tag.id] = RegisteredClip(tag.id, tag.frames, tag.tags)

            # Didn't place a new clip, didn't change anything.
            return None, False

        elif isinstance(tag, AP2PlaceObjectTag):
            if tag.update:
                for i in range(len(operating_clip.placed_objects) - 1, -1, -1):
                    obj = operating_clip.placed_objects[i]

                    if obj.object_id == tag.object_id and obj.depth == tag.depth:
                        new_mult_color = tag.mult_color or obj.mult_color
                        new_add_color = tag.add_color or obj.add_color
                        new_transform = tag.transform or obj.transform
                        new_rotation_offset = tag.rotation_offset or obj.rotation_offset
                        new_blend = tag.blend or obj.blend

                        if tag.source_tag_id is not None and tag.source_tag_id != obj.source.tag_id:
                            # This completely updates the pointed-at object.
                            self.vprint(f"{prefix}    Replacing Object source {obj.source.tag_id} with {tag.source_tag_id} on object with Object ID {tag.object_id} onto Depth {tag.depth}")

                            newobj = self.__registered_objects[tag.source_tag_id]
                            if isinstance(newobj, RegisteredShape):
                                operating_clip.placed_objects[i] = PlacedShape(
                                    obj.object_id,
                                    obj.depth,
                                    new_rotation_offset,
                                    new_transform,
                                    new_mult_color,
                                    new_add_color,
                                    new_blend,
                                    newobj,
                                )

                                # Didn't place a new clip, changed the parent clip.
                                return None, True
                            elif isinstance(newobj, RegisteredClip):
                                new_clip = PlacedClip(
                                    tag.object_id,
                                    tag.depth,
                                    new_rotation_offset,
                                    new_transform,
                                    new_mult_color,
                                    new_add_color,
                                    new_blend,
                                    newobj,
                                )
                                operating_clip.placed_objects[i] = new_clip

                                # Placed a new clip, changed the parent.
                                return new_clip, True
                            else:
                                raise Exception(f"Unrecognized object with Tag ID {tag.source_tag_id}!")
                        else:
                            # As far as I can tell, pretty much only color and matrix stuff can be updated.
                            self.vprint(f"{prefix}    Updating Object ID {tag.object_id} on Depth {tag.depth}")
                            obj.mult_color = new_mult_color
                            obj.add_color = new_add_color
                            obj.transform = new_transform
                            obj.rotation_offset = new_rotation_offset
                            obj.blend = new_blend
                            return None, True

                # Didn't place a new clip, did change something.
                print(f"WARNING: Couldn't find tag {tag.object_id} on depth {tag.depth} to update!")
                return None, False
            else:
                if tag.source_tag_id is None:
                    raise Exception("Cannot place a tag with no source ID and no update flags!")

                # TODO: Handle ON_LOAD triggers for this object. Many of these are just calls into
                # the game to set the current frame that we're on, but sometimes its important.

                if tag.source_tag_id in self.__registered_objects:
                    self.vprint(f"{prefix}    Placing Object {tag.source_tag_id} with Object ID {tag.object_id} onto Depth {tag.depth}")

                    newobj = self.__registered_objects[tag.source_tag_id]
                    if isinstance(newobj, RegisteredShape):
                        operating_clip.placed_objects.append(
                            PlacedShape(
                                tag.object_id,
                                tag.depth,
                                tag.rotation_offset or Point.identity(),
                                tag.transform or Matrix.identity(),
                                tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                                tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                                tag.blend or 0,
                                newobj,
                            )
                        )

                        # Didn't place a new clip, changed the parent clip.
                        return None, True
                    elif isinstance(newobj, RegisteredClip):
                        placed_clip = PlacedClip(
                            tag.object_id,
                            tag.depth,
                            tag.rotation_offset or Point.identity(),
                            tag.transform or Matrix.identity(),
                            tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                            tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                            tag.blend or 0,
                            newobj,
                        )
                        operating_clip.placed_objects.append(placed_clip)

                        # Placed a new clip, changed the parent.
                        return placed_clip, True
                    else:
                        raise Exception(f"Unrecognized object with Tag ID {tag.source_tag_id}!")

                raise Exception(f"Cannot find a shape or sprite with Tag ID {tag.source_tag_id}!")

        elif isinstance(tag, AP2RemoveObjectTag):
            self.vprint(f"{prefix}    Removing Object ID {tag.object_id} from Depth {tag.depth}")

            if tag.object_id != 0:
                # Remove the identified object by object ID and depth.
                # Remember removed objects so we can stop any clips.
                removed_objects = [
                    obj for obj in operating_clip.placed_objects
                    if obj.object_id == tag.object_id and obj.depth == tag.depth
                ]

                # Get rid of the objects that we're removing from the master list.
                operating_clip.placed_objects = [
                    obj for obj in operating_clip.placed_objects
                    if not(obj.object_id == tag.object_id and obj.depth == tag.depth)
                ]
            else:
                # Remove the last placed object at this depth. The placed objects list isn't
                # ordered so much as apppending to the list means the last placed object at a
                # depth comes last.
                removed_objects = []
                for i in range(len(operating_clip.placed_objects)):
                    real_index = len(operating_clip.placed_objects) - (i + 1)

                    if operating_clip.placed_objects[real_index].depth == tag.depth:
                        removed_objects = operating_clip.placed_objects[real_index:(real_index + 1)]
                        operating_clip.placed_objects = operating_clip.placed_objects[:real_index] + operating_clip.placed_objects[(real_index + 1):]
                        break

            if not removed_objects:
                print(f"WARNING: Couldn't find object to remove by ID {tag.object_id} and depth {tag.depth}!")

            # Didn't place a new clip, changed parent clip.
            return None, True

        elif isinstance(tag, AP2DoActionTag):
            print("WARNING: Unhandled DO_ACTION tag!")

            # Didn't place a new clip.
            return None, False

        elif isinstance(tag, AP2DefineFontTag):
            print("WARNING: Unhandled DEFINE_FONT tag!")

            # Didn't place a new clip.
            return None, False

        elif isinstance(tag, AP2DefineEditTextTag):
            print("WARNING: Unhandled DEFINE_EDIT_TEXT tag!")

            # Didn't place a new clip.
            return None, False

        else:
            raise Exception(f"Failed to process tag: {tag}")

    def __render_object(self, img: Image.Image, renderable: PlacedObject, parent_transform: Matrix, parent_origin: Point) -> None:
        # Compute the affine transformation matrix for this object.
        transform = parent_transform.multiply(renderable.transform)

        # Calculate the inverse so we can map canvas space back to texture space.
        try:
            inverse = transform.inverse()
        except ZeroDivisionError:
            # If this happens, that means one of the scaling factors was zero, making
            # this object invisible. We can ignore this since the object should not
            # be drawn.
            print(f"WARNING: Transform Matrix {transform} has zero scaling factor, making it non-invertible!")
            return

        # Render individual shapes if this is a sprite.
        if isinstance(renderable, PlacedClip):
            # This is a sprite placement reference.
            objs = sorted(
                renderable.placed_objects,
                key=lambda obj: obj.depth,
            )
            for obj in objs:
                self.vprint(f"    Rendering placed object ID {obj.object_id} from sprite {obj.source.tag_id} onto Depth {obj.depth}")
                self.__render_object(img, obj, transform, parent_origin.add(renderable.rotation_offset))
        elif isinstance(renderable, PlacedShape):
            # This is a shape draw reference.
            shape = renderable.source

            # Calculate add color if it is present.
            add_color = (renderable.add_color or Color(0.0, 0.0, 0.0, 0.0)).as_tuple()
            mult_color = renderable.mult_color or Color(1.0, 1.0, 1.0, 1.0)
            blend = renderable.blend or 0

            # Now, render out shapes.
            for params in shape.draw_params:
                if not (params.flags & 0x1):
                    # Not instantiable, don't render.
                    return

                if params.flags & 0x8:
                    # TODO: Need to support blending and UV coordinate colors here.
                    print(f"WARNING: Unhandled shape blend color {params.blend}")
                if params.flags & 0x4:
                    # TODO: Need to support blending and UV coordinate colors here.
                    print("WARNING: Unhandled UV coordinate color!")

                texture = None
                if params.flags & 0x2:
                    # We need to look up the texture for this.
                    if params.region not in self.textures:
                        raise Exception(f"Cannot find texture reference {params.region}!")
                    texture = self.textures[params.region]

                if texture is not None:
                    # If the origin is not specified, assume it is the center of the texture.
                    # TODO: Setting the rotation offset to Point(texture.width / 2, texture.height / 2)
                    # when we don't have a rotation offset works for Bishi but breaks other games.
                    # Perhaps there's a tag flag for this?
                    origin = parent_origin.add(renderable.rotation_offset)

                    # See if we can cheat and use the faster blitting method.
                    if (
                        add_color == (0, 0, 0, 0) and
                        mult_color.r == 1.0 and
                        mult_color.g == 1.0 and
                        mult_color.b == 1.0 and
                        mult_color.a == 1.0 and
                        transform.b == 0.0 and
                        transform.c == 0.0 and
                        transform.a == 1.0 and
                        transform.d == 1.0 and
                        blend == 0
                    ):
                        # We can!
                        cutin = transform.multiply_point(Point.identity().subtract(origin))
                        cutoff = Point.identity()
                        if cutin.x < 0:
                            cutoff.x = -cutin.x
                            cutin.x = 0
                        if cutin.y < 0:
                            cutoff.y = -cutin.y
                            cutin.y = 0

                        img.alpha_composite(texture, cutin.as_tuple(), cutoff.as_tuple())
                    else:
                        # Now, render out the texture.
                        imgmap = list(img.getdata())
                        texmap = list(texture.getdata())

                        # Calculate the maximum range of update this texture can possibly reside in.
                        pix1 = transform.multiply_point(Point.identity().subtract(origin))
                        pix2 = transform.multiply_point(Point.identity().subtract(origin).add(Point(texture.width, 0)))
                        pix3 = transform.multiply_point(Point.identity().subtract(origin).add(Point(0, texture.height)))
                        pix4 = transform.multiply_point(Point.identity().subtract(origin).add(Point(texture.width, texture.height)))

                        # Map this to the rectangle we need to sweep in the rendering image.
                        minx = max(int(min(pix1.x, pix2.x, pix3.x, pix4.x)), 0)
                        maxx = min(int(max(pix1.x, pix2.x, pix3.x, pix4.x)) + 1, img.width)
                        miny = max(int(min(pix1.y, pix2.y, pix3.y, pix4.y)), 0)
                        maxy = min(int(max(pix1.y, pix2.y, pix3.y, pix4.y)) + 1, img.height)

                        announced = False
                        for imgy in range(miny, maxy):
                            for imgx in range(minx, maxx):
                                # Determine offset
                                imgoff = imgx + (imgy * img.width)

                                # Calculate what texture pixel data goes here.
                                texloc = inverse.multiply_point(Point(float(imgx), float(imgy))).add(origin)
                                texx, texy = texloc.as_tuple()

                                # If we're out of bounds, don't update.
                                if texx < 0 or texy < 0 or texx >= texture.width or texy >= texture.height:
                                    continue

                                # Blend it.
                                texoff = texx + (texy * texture.width)

                                if blend == 0 or blend == 2:
                                    imgmap[imgoff] = self.__blend_normal(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                                elif blend == 3:
                                    imgmap[imgoff] = self.__blend_multiply(imgmap[imgoff], texmap[texoff], mult_color, add_color)
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
                                elif blend == 8:
                                    imgmap[imgoff] = self.__blend_addition(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                                elif blend == 9 or blend == 70:
                                    imgmap[imgoff] = self.__blend_subtraction(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                                # TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
                                # Src * (1 - Dst) + Dst * (1 - Src).
                                else:
                                    if not announced:
                                        # Don't print it for every pixel.
                                        print(f"WARNING: Unsupported blend {blend}")
                                        announced = True
                                    imgmap[imgoff] = self.__blend_normal(imgmap[imgoff], texmap[texoff], mult_color, add_color)

                        img.putdata(imgmap)
        else:
            raise Exception(f"Unknown placed object type to render {renderable}!")

    def __clamp(self, color: Union[float, int]) -> int:
        return min(max(0, round(color)), 255)

    def __blend_normal(
        self,
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
            self.__clamp((src[0] * mult_color.r) + add_color[0]),
            self.__clamp((src[1] * mult_color.g) + add_color[1]),
            self.__clamp((src[2] * mult_color.b) + add_color[2]),
            self.__clamp((src[3] * mult_color.a) + add_color[3]),
        )

        # Short circuit for speed.
        if src[3] == 0:
            return dest
        if src[3] == 255:
            return src

        # Calculate alpha blending.
        srcpercent = (float(src[3]) / 255.0)
        destpercent = (float(dest[3]) / 255.0)
        destremainder = 1.0 - srcpercent
        return (
            self.__clamp((float(dest[0]) * destpercent * destremainder) + (float(src[0]) * srcpercent)),
            self.__clamp((float(dest[1]) * destpercent * destremainder) + (float(src[1]) * srcpercent)),
            self.__clamp((float(dest[2]) * destpercent * destremainder) + (float(src[2]) * srcpercent)),
            self.__clamp(255 * (srcpercent + destpercent * destremainder)),
        )

    def __blend_addition(
        self,
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
            self.__clamp((src[0] * mult_color.r) + add_color[0]),
            self.__clamp((src[1] * mult_color.g) + add_color[1]),
            self.__clamp((src[2] * mult_color.b) + add_color[2]),
            self.__clamp((src[3] * mult_color.a) + add_color[3]),
        )

        # Short circuit for speed.
        if src[3] == 0:
            return dest

        # Calculate alpha blending.
        srcpercent = (float(src[3]) / 255.0)
        return (
            self.__clamp(dest[0] + (float(src[0]) * srcpercent)),
            self.__clamp(dest[1] + (float(src[1]) * srcpercent)),
            self.__clamp(dest[2] + (float(src[2]) * srcpercent)),
            self.__clamp(dest[3] + (255 * srcpercent)),
        )

    def __blend_subtraction(
        self,
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
            self.__clamp((src[0] * mult_color.r) + add_color[0]),
            self.__clamp((src[1] * mult_color.g) + add_color[1]),
            self.__clamp((src[2] * mult_color.b) + add_color[2]),
            self.__clamp((src[3] * mult_color.a) + add_color[3]),
        )

        # Short circuit for speed.
        if src[3] == 0:
            return dest

        # Calculate alpha blending.
        srcpercent = (float(src[3]) / 255.0)
        return (
            self.__clamp(dest[0] - (float(src[0]) * srcpercent)),
            self.__clamp(dest[1] - (float(src[1]) * srcpercent)),
            self.__clamp(dest[2] - (float(src[2]) * srcpercent)),
            self.__clamp(dest[3] - (255 * srcpercent)),
        )

    def __blend_multiply(
        self,
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
            self.__clamp((src[0] * mult_color.r) + add_color[0]),
            self.__clamp((src[1] * mult_color.g) + add_color[1]),
            self.__clamp((src[2] * mult_color.b) + add_color[2]),
            self.__clamp((src[3] * mult_color.a) + add_color[3]),
        )

        # Short circuit for speed.
        if src[3] == 0:
            return dest

        # Calculate alpha blending.
        return (
            self.__clamp(255 * ((float(dest[0]) / 255.0) * (float(src[0]) / 255.0))),
            self.__clamp(255 * ((float(dest[1]) / 255.0) * (float(src[1]) / 255.0))),
            self.__clamp(255 * ((float(dest[2]) / 255.0) * (float(src[2]) / 255.0))),
            self.__clamp(255 * ((float(dest[3]) / 255.0) * (float(src[3]) / 255.0))),
        )

    def __process_tags(self, clip: PlacedClip, prefix: str = "  ") -> bool:
        self.vprint(f"{prefix}Handling placed clip {clip.object_id} at depth {clip.depth}")

        # Track whether anything in ourselves or our children changes during this processing.
        changed = False

        # Clips that are part of our own placed objects which we should handle.
        child_clips = [c for c in clip.placed_objects if isinstance(c, PlacedClip)]

        # Execute each tag in the frame.
        if not clip.finished:
            frame = clip.source.frames[clip.frame]
            tags = clip.source.tags[frame.start_tag_offset:(frame.start_tag_offset + frame.num_tags)]

            for tagno, tag in enumerate(tags):
                # Perform the action of this tag.
                self.vprint(f"{prefix}  Sprite Tag ID: {clip.source.tag_id}, Current Tag: {frame.start_tag_offset + tagno}, Num Tags: {frame.num_tags}")
                new_clip, clip_changed = self.__place(tag, clip, prefix=prefix)
                changed = changed or clip_changed

                # If we create a new movie clip, process it as well for this frame.
                if new_clip:
                    changed = self.__process_tags(new_clip, prefix=prefix + "  ") or changed

        # Now, handle each of the existing clips.
        for child in child_clips:
            changed = self.__process_tags(child, prefix=prefix + "  ") or changed

        # Now, advance the frame for this clip.
        clip.advance()

        self.vprint(f"{prefix}Finished handling placed clip {clip.object_id} at depth {clip.depth}")

        # Return if anything was modified.
        return changed

    def __find_renderable(self, clip: PlacedClip, tag: Optional[int]) -> Optional[PlacedClip]:
        if clip.source.tag_id == tag:
            return clip

        for obj in clip.placed_objects:
            if isinstance(obj, PlacedClip):
                maybe = self.__find_renderable(obj, tag)
                if maybe is not None:
                    return maybe

        return None

    def __render(self, swf: SWF, export_tag: Optional[str]) -> Tuple[int, List[Image.Image]]:
        # If we are rendering an exported tag, we want to perform the actions of the
        # rest of the SWF but not update any layers as a result.
        visible_tag = None
        if export_tag is not None:
            # Make sure this tag is actually present in the SWF.
            if export_tag not in swf.exported_tags:
                raise Exception(f'{export_tag} is not exported by {swf.exported_name}!')
            visible_tag = swf.exported_tags[export_tag]

        # TODO: We have to resolve imports.

        # Now, let's go through each frame, performing actions as necessary.
        spf = 1.0 / swf.fps
        frames: List[Image.Image] = []
        frameno: int = 0

        # Create a root clip for the movie to play.
        root_clip = PlacedClip(
            -1,
            -1,
            Point.identity(),
            Matrix.identity(),
            Color(1.0, 1.0, 1.0, 1.0),
            Color(0.0, 0.0, 0.0, 0.0),
            0,
            RegisteredClip(
                None,
                swf.frames,
                swf.tags,
            ),
        )

        # Reset any registered objects.
        self.__registered_objects = {}

        try:
            while root_clip.running:
                # Create a new image to render into.
                time = spf * float(frameno)
                color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
                self.vprint(f"Rendering Frame {frameno} ({time}s)")

                # Go through all registered clips, place all needed tags.
                changed = self.__process_tags(root_clip)

                if changed or frameno == 0:
                    # Now, render out the placed objects. We sort by depth so that we can
                    # get the layering correct, but its important to preserve the original
                    # insertion order for delete requests.
                    curimage = Image.new("RGBA", (swf.location.width, swf.location.height), color=color.as_tuple())

                    clip = self.__find_renderable(root_clip, visible_tag)
                    if clip:
                        for obj in sorted(clip.placed_objects, key=lambda obj: obj.depth):
                            self.vprint(f"  Rendering placed object ID {obj.object_id} from sprite {obj.source.tag_id} onto Depth {obj.depth}")
                            self.__render_object(curimage, obj, root_clip.transform, root_clip.rotation_offset)
                else:
                    # Nothing changed, make a copy of the previous render.
                    self.vprint("  Using previous frame render")
                    curimage = frames[-1].copy()

                # Advance our bookkeeping.
                frames.append(curimage)
                frameno += 1
        except KeyboardInterrupt:
            # Allow ctrl-c to end early and render a partial animation.
            print(f"WARNING: Interrupted early, will render only {len(frames)} of animation!")

        return int(spf * 1000.0), frames
