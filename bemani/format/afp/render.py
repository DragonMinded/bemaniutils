from typing import Dict, List, Tuple, Optional, Union
from PIL import Image  # type: ignore

from .blend import affine_composite
from .swf import SWF, Frame, Tag, AP2ShapeTag, AP2DefineSpriteTag, AP2PlaceObjectTag, AP2RemoveObjectTag, AP2DoActionTag, AP2DefineFontTag, AP2DefineEditTextTag, AP2PlaceCameraTag
from .types import Color, Matrix, Point, Rectangle
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
        self.rectangle: Optional[Image.image] = None

    def __repr__(self) -> str:
        return f"RegisteredShape(tag_id={self.tag_id}, vertex_points={self.vertex_points}, tex_points={self.tex_points}, tex_colors={self.tex_colors}, draw_params={self.draw_params})"


class RegisteredDummy:
    # An imported tag that we could not find.
    def __init__(self, tag_id: int) -> None:
        self.tag_id = tag_id

    def __repr__(self) -> str:
        return f"RegisteredDummy(tag_id={self.tag_id})"


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
    def source(self) -> Union[RegisteredClip, RegisteredShape, RegisteredDummy]:
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

    def __repr__(self) -> str:
        return f"PlacedClip(object_id={self.object_id}, depth={self.depth}, source={self.source}, frame={self.frame}, total_frames={len(self.source.frames)}, finished={self.finished})"


class PlacedDummy(PlacedObject):
    # A reference to an object we can't find because we're missing the import.
    def __init__(self, object_id: int, depth: int, rotation_offset: Point, transform: Matrix, mult_color: Color, add_color: Color, blend: int, source: RegisteredDummy) -> None:
        super().__init__(object_id, depth, rotation_offset, transform, mult_color, add_color, blend)
        self.__source = source

    @property
    def source(self) -> RegisteredDummy:
        return self.__source


class AFPRenderer(VerboseOutput):
    def __init__(self, shapes: Dict[str, Shape] = {}, textures: Dict[str, Image.Image] = {}, swfs: Dict[str, SWF] = {}, single_threaded: bool = False) -> None:
        super().__init__()

        # Options for rendering
        self.__single_threaded = single_threaded

        # Library of shapes (draw instructions), textures (actual images) and swfs (us and other files for imports).
        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Image.Image] = textures
        self.swfs: Dict[str, SWF] = swfs

        # Internal render parameters.
        self.__registered_objects: Dict[int, Union[RegisteredShape, RegisteredClip, RegisteredDummy]] = {}

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

    def render_path(
        self,
        path: str,
        background_color: Optional[Color] = None,
        only_depths: Optional[List[int]] = None,
        movie_transform: Matrix = Matrix.identity(),
        verbose: bool = False,
    ) -> Tuple[int, List[Image.Image]]:
        # Given a path to a SWF root animation, attempt to render it to a list of frames.
        for name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                with self.debugging(verbose):
                    swf.color = background_color or swf.color
                    return self.__render(swf, only_depths, movie_transform)

        raise Exception(f'{path} not found in registered SWFs!')

    def compute_path_location(
        self,
        path: str,
    ) -> Rectangle:
        # Given a path to a SWF root animation, find its bounding rectangle.
        for name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                return swf.location

        raise Exception(f'{path} not found in registered SWFs!')

    def list_paths(self, verbose: bool = False) -> List[str]:
        # Given the loaded animations, return a list of possible paths to render.
        paths: List[str] = []

        for name, swf in self.swfs.items():
            paths.append(swf.exported_name)

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
                            elif isinstance(newobj, RegisteredDummy):
                                operating_clip.placed_objects[i] = PlacedDummy(
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
                        # TODO: Handle ON_LOAD triggers for this object. Many of these are just calls into
                        # the game to set the current frame that we're on, but sometimes its important.
                        for flags, code in tag.triggers.items():
                            for bytecode in code:
                                print("WARNING: Unhandled PLACE_OBJECT trigger!")
                                if self.verbose:
                                    print(bytecode.decompile())

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
                    elif isinstance(newobj, RegisteredDummy):
                        operating_clip.placed_objects.append(
                            PlacedDummy(
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
            if self.verbose:
                print(tag.bytecode.decompile())

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

        elif isinstance(tag, AP2PlaceCameraTag):
            print("WARNING: Unhandled PLACE_CAMERA tag!")

            # Didn't place a new clip.
            return None, False

        else:
            raise Exception(f"Failed to process tag: {tag}")

    def __render_object(
        self,
        img: Image.Image,
        renderable: PlacedObject,
        parent_transform: Matrix,
        only_depths: Optional[List[int]] = None,
        prefix: str="",
    ) -> Image.Image:
        self.vprint(f"{prefix}  Rendering placed object ID {renderable.object_id} from sprite {renderable.source.tag_id} onto Depth {renderable.depth}")

        # Compute the affine transformation matrix for this object.
        transform = renderable.transform.multiply(parent_transform).translate(Point.identity().subtract(renderable.rotation_offset))

        # Render individual shapes if this is a sprite.
        if isinstance(renderable, PlacedClip):
            if only_depths is not None:
                if renderable.depth not in only_depths:
                    if renderable.depth != -1:
                        # Not on the correct depth plane.
                        return img
                    new_only_depths = only_depths
                else:
                    new_only_depths = None
            else:
                new_only_depths = None

            # This is a sprite placement reference. Make sure that we render lower depths
            # first, but preserved placed order as well.
            depths = set(obj.depth for obj in renderable.placed_objects)
            for depth in sorted(depths):
                for obj in renderable.placed_objects:
                    if obj.depth != depth:
                        continue
                    img = self.__render_object(img, obj, transform, only_depths=new_only_depths, prefix=prefix + " ")
        elif isinstance(renderable, PlacedShape):
            if only_depths is not None and renderable.depth not in only_depths:
                # Not on the correct depth plane.
                return img

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
                    return img

                if params.flags & 0x4:
                    # TODO: Need to support blending and UV coordinate colors here.
                    print("WARNING: Unhandled UV coordinate color!")

                texture = None
                if params.flags & 0x2:
                    # We need to look up the texture for this.
                    if params.region not in self.textures:
                        raise Exception(f"Cannot find texture reference {params.region}!")
                    texture = self.textures[params.region]

                    if params.flags & 0x8:
                        # TODO: This texture gets further blended somehow? Not sure this is ever used.
                        print(f"WARNING: Unhandled texture blend color {params.blend}")
                elif params.flags & 0x8:
                    if shape.rectangle is None:
                        # This is a raw rectangle. Its possible that the number of vertex points is
                        # not 4, or that the four points in the vertex_points aren't the four corners
                        # of a rectangle, but let's assume that doesn't happen for now.
                        x_points = set(p.x for p in shape.vertex_points)
                        y_points = set(p.y for p in shape.vertex_points)
                        left = min(x_points)
                        right = max(x_points)
                        top = min(y_points)
                        bottom = max(y_points)

                        shape.rectangle = Image.new('RGBA', (int(right - left), int(bottom - top)), (params.blend.as_tuple()))
                    texture = shape.rectangle

                if texture is not None:
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
                        (blend == 0 or blend == 2)
                    ):
                        # We can!
                        cutin = transform.multiply_point(Point.identity())
                        cutoff = Point.identity()
                        if cutin.x < 0:
                            cutoff.x = -cutin.x
                            cutin.x = 0
                        if cutin.y < 0:
                            cutoff.y = -cutin.y
                            cutin.y = 0

                        img.alpha_composite(texture, cutin.as_tuple(), cutoff.as_tuple())
                    else:
                        # We can't, so do the slow render that's correct.
                        img = affine_composite(img, add_color, mult_color, transform, blend, texture, single_threaded=self.__single_threaded)
        elif isinstance(renderable, PlacedDummy):
            # Nothing to do!
            pass
        else:
            raise Exception(f"Unknown placed object type to render {renderable}!")

        return img

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

    def __handle_imports(self, swf: SWF) -> Dict[int, Union[RegisteredShape, RegisteredClip, RegisteredDummy]]:
        external_objects: Dict[int, Union[RegisteredShape, RegisteredClip, RegisteredDummy]] = {}

        # Go through, recursively resolve imports for all SWF files.
        for tag_id, imp in swf.imported_tags.items():
            for name, other in self.swfs.items():
                if other.exported_name == imp.swf:
                    # This SWF should have the tag reference.
                    if imp.tag not in other.exported_tags:
                        print(f"WARNING: {swf.exported_name} imports {imp} but that import is not in {other.exported_name}!")
                        external_objects[tag_id] = RegisteredDummy(tag_id)
                        break
                    else:
                        external_objects[tag_id] = self.__find_import(other, other.exported_tags[imp.tag])
                        break
            else:
                print(f"WARNING: {swf.exported_name} imports {imp} but that SWF is not in our library!")
                external_objects[tag_id] = RegisteredDummy(tag_id)

        # Fix up tag IDs to point at our local definition of them.
        for tid in external_objects:
            external_objects[tid].tag_id = tid

        # Return our newly populated registered object table containing all imports!
        return external_objects

    def __find_import(self, swf: SWF, tag_id: int) -> Union[RegisteredShape, RegisteredClip, RegisteredDummy]:
        if tag_id in swf.imported_tags:
            external_objects = self.__handle_imports(swf)
            if tag_id not in external_objects:
                raise Exception(f"Logic error, tag ID {tag_id} is an export for {swf.exported_name} but we didn't populate it!")
            return external_objects[tag_id]

        # We need to do a basic placement to find the registered object so we can return it.
        root_clip = RegisteredClip(
            None,
            swf.frames,
            swf.tags,
        )

        tag = self.__find_tag(root_clip, tag_id)
        if tag is None:
            print(f"WARNING: {swf.exported_name} exports {swf.imported_tags[tag_id]} but does not manifest an object!")
            return RegisteredDummy(tag_id)
        return tag

    def __find_tag(self, clip: RegisteredClip, tag_id: int) -> Optional[Union[RegisteredShape, RegisteredClip, RegisteredDummy]]:
        # Fake-execute this clip to find the tag we need to manifest.
        for frame in clip.frames:
            tags = clip.tags[frame.start_tag_offset:(frame.start_tag_offset + frame.num_tags)]

            for tagno, tag in enumerate(tags):
                # Attempt to place any tags.
                if isinstance(tag, AP2ShapeTag):
                    if tag.id == tag_id:
                        # We need to be able to see this shape to place it.
                        if tag.reference not in self.shapes:
                            raise Exception(f"Cannot find shape reference {tag.reference}!")

                        # This matched, so this is the import.
                        return RegisteredShape(
                            tag.id,
                            self.shapes[tag.reference].vertex_points,
                            self.shapes[tag.reference].tex_points,
                            self.shapes[tag.reference].tex_colors,
                            self.shapes[tag.reference].draw_params,
                        )

                elif isinstance(tag, AP2DefineSpriteTag):
                    new_clip = RegisteredClip(tag.id, tag.frames, tag.tags)

                    if tag.id == tag_id:
                        # This matched, so it is the clip that we want to export.
                        return new_clip

                    # Recursively look in this as well.
                    maybe_tag = self.__find_tag(new_clip, tag_id)
                    if maybe_tag is not None:
                        return maybe_tag

        # We didn't find the tag we were after.
        return None

    def __render(self, swf: SWF, only_depths: Optional[List[int]], movie_transform: Matrix) -> Tuple[int, List[Image.Image]]:
        # First, let's attempt to resolve imports.
        self.__registered_objects = self.__handle_imports(swf)

        # Initialize overall frame advancement stuff.
        spf = 1.0 / swf.fps
        frames: List[Image.Image] = []
        frameno: int = 0

        # Calculate actual size based on given movie transform.
        actual_size = movie_transform.multiply_point(Point(swf.location.width, swf.location.height)).as_tuple()

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

        # Now play the frames of the root clip.
        try:
            while not root_clip.finished:
                # Create a new image to render into.
                time = spf * frameno
                color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
                self.vprint(f"Rendering frame {frameno}/{len(root_clip.source.frames)} ({round(time, 2)}s)")

                # Go through all registered clips, place all needed tags.
                changed = self.__process_tags(root_clip)

                if changed or frameno == 0:
                    # Now, render out the placed objects.
                    curimage = Image.new("RGBA", actual_size, color=color.as_tuple())
                    curimage = self.__render_object(curimage, root_clip, movie_transform, only_depths=only_depths)
                else:
                    # Nothing changed, make a copy of the previous render.
                    self.vprint("  Using previous frame render")
                    curimage = frames[-1].copy()

                # Advance our bookkeeping.
                frames.append(curimage)
                frameno += 1
        except KeyboardInterrupt:
            # Allow ctrl-c to end early and render a partial animation.
            print(f"WARNING: Interrupted early, will render only {len(frames)}/{len(root_clip.source.frames)} frames of animation!")

        return int(spf * 1000.0), frames
