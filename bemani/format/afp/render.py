from typing import Dict, List, Tuple, Optional, Union
from PIL import Image  # type: ignore

from .blend import affine_composite
from .swf import SWF, Frame, Tag, AP2ShapeTag, AP2DefineSpriteTag, AP2PlaceObjectTag, AP2RemoveObjectTag, AP2DoActionTag, AP2DefineFontTag, AP2DefineEditTextTag, AP2PlaceCameraTag
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

    def __repr__(self) -> str:
        return f"PlacedClip(object_id={self.object_id}, depth={self.depth}, source={self.source}, frame={self.frame}, total_frames={len(self.source.frames)}, finished={self.finished})"


class AFPRenderer(VerboseOutput):
    def __init__(self, shapes: Dict[str, Shape] = {}, textures: Dict[str, Image.Image] = {}, swfs: Dict[str, SWF] = {}, single_threaded: bool = False) -> None:
        super().__init__()

        # Options for rendering
        self.__single_threaded = single_threaded

        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Image.Image] = textures

        # TODO: We have to resolve imports.
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

    def render_path(self, path: str, background_color: Optional[Color] = None, verbose: bool = False, only_depths: Optional[List[int]] = None) -> Tuple[int, List[Image.Image]]:
        # Given a path to a SWF root animation, attempt to render it to a list of frames.
        for name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                with self.debugging(verbose):
                    swf.color = background_color or swf.color
                    return self.__render(swf, only_depths=only_depths)

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
        parent_origin: Point,
        only_depths: Optional[List[int]] = None,
        prefix: str="",
    ) -> Image.Image:
        self.vprint(f"{prefix}  Rendering placed object ID {renderable.object_id} from sprite {renderable.source.tag_id} onto Depth {renderable.depth}")

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
            return img

        # Render individual shapes if this is a sprite.
        if isinstance(renderable, PlacedClip):
            # This is a sprite placement reference.
            objs = sorted(
                renderable.placed_objects,
                key=lambda obj: obj.depth,
            )
            for obj in objs:
                img = self.__render_object(img, obj, transform, parent_origin.add(renderable.rotation_offset), only_depths=only_depths, prefix=prefix + " ")
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
                    return img
                if only_depths is not None and renderable.depth not in only_depths:
                    # Not on the correct depth plane.
                    return img

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
                        (blend == 0 or blend == 2)
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
                        # We can't, so do the slow render that's correct.
                        img = affine_composite(img, add_color, mult_color, transform, inverse, origin, blend, texture, single_threaded=self.__single_threaded)
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

    def __render(self, swf: SWF, only_depths: Optional[List[int]] = None) -> Tuple[int, List[Image.Image]]:
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
            while not root_clip.finished:
                # Create a new image to render into.
                time = spf * frameno
                color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
                self.vprint(f"Rendering frame {frameno}/{len(root_clip.source.frames)} ({round(time, 2)}s)")

                # Go through all registered clips, place all needed tags.
                changed = self.__process_tags(root_clip)

                if changed or frameno == 0:
                    # Now, render out the placed objects. We sort by depth so that we can
                    # get the layering correct, but its important to preserve the original
                    # insertion order for delete requests.
                    curimage = Image.new("RGBA", (int(swf.location.width), int(swf.location.height)), color=color.as_tuple())
                    curimage = self.__render_object(curimage, root_clip, root_clip.transform, root_clip.rotation_offset, only_depths=only_depths)
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
