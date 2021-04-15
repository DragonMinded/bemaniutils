from typing import Any, Dict, List, Tuple, Optional
from PIL import Image  # type: ignore

from .swf import SWF, Frame, Tag, AP2ShapeTag, AP2DefineSpriteTag, AP2PlaceObjectTag, AP2RemoveObjectTag, AP2DoActionTag
from .types import Color, Matrix, Point
from .geo import Shape
from .util import VerboseOutput


class Clip:
    def __init__(self, tag_id: Optional[int], frames: List[Frame], tags: List[Tag]) -> None:
        self.tag_id = tag_id
        self.frames = frames
        self.tags = tags
        self.frameno = 0

    def frame(self) -> Frame:
        return self.frames[self.frameno]

    def advance(self) -> None:
        if not self.finished():
            self.frameno += 1

    def finished(self) -> bool:
        return self.frameno == len(self.frames)

    def running(self) -> bool:
        return not self.finished()


class PlacedObject:
    def __init__(self, parent_sprite: Optional[int], tag: AP2PlaceObjectTag) -> None:
        self.parent_sprite = parent_sprite
        self.tag = tag


class AFPRenderer(VerboseOutput):
    def __init__(self, shapes: Dict[str, Shape] = {}, textures: Dict[str, Any] = {}, swfs: Dict[str, SWF] = {}) -> None:
        super().__init__()

        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Any] = textures
        self.swfs: Dict[str, SWF] = swfs

        # Internal render parameters
        self.__visible_tag: Optional[int] = None
        self.__ided_tags: Dict[int, Tag] = {}
        self.__registered_shapes: Dict[int, Shape] = {}
        self.__placed_objects: List[PlacedObject] = []

    def add_shape(self, name: str, data: Shape) -> None:
        if not data.parsed:
            data.parse()
        self.shapes[name] = data

    def add_texture(self, name: str, data: Any) -> None:
        self.textures[name] = data

    def add_swf(self, name: str, data: SWF) -> None:
        if not data.parsed:
            data.parse()
        self.swfs[name] = data

    def render_path(self, path: str, verbose: bool = False) -> Tuple[int, List[Any]]:
        components = path.split(".")

        if len(components) > 2:
            raise Exception('Expected a path in the form of "moviename" or "moviename.exportedtag"!')

        for name, swf in self.swfs.items():
            if swf.exported_name == components[0]:
                # This is the SWF we care about.
                with self.debugging(verbose):
                    return self.__render(swf, components[1] if len(components) > 1 else None)

        raise Exception(f'{path} not found in registered SWFs!')

    def __place(self, tag: Tag, parent_sprite: Optional[int], prefix: str = "") -> List[Clip]:
        if isinstance(tag, AP2ShapeTag):
            self.vprint(f"{prefix}    Loading {tag.reference} into shape slot {tag.id}")

            if tag.reference not in self.shapes:
                raise Exception(f"Cannot find shape reference {tag.reference}!")

            self.__registered_shapes[tag.id] = self.shapes[tag.reference]
            return []
        elif isinstance(tag, AP2DefineSpriteTag):
            self.vprint(f"{prefix}    Registering Sprite Tag {tag.id}")

            # Register a new clip that we have to execute.
            clip = Clip(tag.id, tag.frames, tag.tags)
            clips: List[Clip] = [clip]

            # Now, we need to run the first frame of this clip, since that's this frame.
            if clip.running():
                frame = clip.frame()
                if frame.num_tags > 0:
                    self.vprint(f"{prefix}      First Frame Initialization, Start Frame: {frame.start_tag_offset}, Num Frames: {frame.num_tags}")
                    for child in clip.tags[frame.start_tag_offset:(frame.start_tag_offset + frame.num_tags)]:
                        clips.extend(self.__place(child, parent_sprite=tag.id, prefix="    "))

            # Finally, return the new clips we registered.
            return clips
        elif isinstance(tag, AP2PlaceObjectTag):
            if tag.update:
                self.vprint(f"{prefix}    Updating Object ID {tag.object_id} on Depth {tag.depth}")
                updated = False

                for obj in self.__placed_objects:
                    if obj.tag.object_id == tag.object_id and obj.tag.depth == tag.depth:
                        # As far as I can tell, pretty much only color and matrix stuff can be updated.
                        obj.tag.mult_color = tag.mult_color or obj.tag.mult_color
                        obj.tag.add_color = tag.add_color or obj.tag.add_color
                        obj.tag.transform = tag.transform or obj.tag.transform
                        obj.tag.rotation_offset = tag.rotation_offset or obj.tag.rotation_offset
                        updated = True

                if not updated:
                    raise Exception("Couldn't find tag to update!")
            else:
                self.vprint(f"{prefix}    Placing Object ID {tag.object_id} onto Depth {tag.depth}")

                self.__placed_objects.append(PlacedObject(parent_sprite, tag))

            # TODO: Handle triggers for this object.
            return []
        elif isinstance(tag, AP2RemoveObjectTag):
            self.vprint(f"{prefix}    Removing Object ID {tag.object_id} from Depth {tag.depth}")

            if tag.object_id != 0:
                # Remove the identified object by object ID and depth.
                self.__placed_objects = [
                    o for o in self.__placed_objects
                    if o.tag.object_id == tag.object_id and o.tag.depth == tag.depth
                ]
            else:
                # Remove the last placed object at this depth.
                for i in range(len(self.__placed_objects)):
                    real_index = len(self.__placed_objects) - (i + 1)

                    if self.__placed_objects[real_index].tag.depth == tag.depth:
                        self.__placed_objects = self.__placed_objects[:real_index] + self.__placed_objects[(real_index + 1):]
                        break

            return []
        elif isinstance(tag, AP2DoActionTag):
            print("WARNING: Unhandled DO_ACTION tag!")
            return []
        else:
            raise Exception(f"Failed to process tag: {tag}")

    def __render_object(self, img: Any, tag: AP2PlaceObjectTag, parent_transform: Matrix, parent_origin: Point) -> Any:
        if tag.source_tag_id is None:
            self.vprint("    Nothing to render!")
            return img

        # Double check supported options.
        if tag.mult_color or tag.add_color:
            print(f"WARNING: Unhandled color blend request Mult: {tag.mult_color} Add: {tag.add_color}!")

        # Look up the affine transformation matrix and rotation/origin.
        transform = tag.transform or Matrix.identity()
        origin = tag.rotation_offset or Point.identity()

        # TODO: Need to do actual affine transformations here.
        if transform.b != 0.0 or transform.c != 0.0 or transform.a != 1.0 or transform.d != 1.0:
            print("WARNING: Unhandled affine transformation request!")
        if parent_transform.b != 0.0 or parent_transform.c != 0.0 or parent_transform.a != 1.0 or parent_transform.d != 1.0:
            print("WARNING: Unhandled affine transformation request!")
        offset = parent_transform.multiply_point(transform.multiply_point(Point.identity().subtract(origin).subtract(parent_origin)))

        # Look up source shape.
        if tag.source_tag_id not in self.__registered_shapes:
            # This is probably a sprite placement reference.
            for obj in self.__placed_objects:
                if obj.parent_sprite == tag.source_tag_id:
                    self.vprint(f"    Rendering placed object ID {obj.tag.object_id} from sprite {obj.parent_sprite} onto Depth {obj.tag.depth}")
                    img = self.__render_object(img, obj.tag, transform, origin)
            return img
        shape = self.__registered_shapes[tag.source_tag_id]

        for params in shape.draw_params:
            if not (params.flags & 0x1):
                # Not instantiable, don't render.
                return img

            if params.flags & 0x4 or params.flags & 0x8:
                raise Exception("Don't support shape blend or uv coordinate color yet!")

            texture = None
            if params.flags & 0x2:
                # We need to look up the texture for this.
                if params.region not in self.textures:
                    raise Exception(f"Cannot find texture reference {params.region}!")
                texture = self.textures[params.region]

            # Now, render out the texture.
            cutin = Point(offset.x, offset.y)
            cutoff = Point.identity()
            if cutin.x < 0:
                cutoff.x = -cutin.x
                cutin.x = 0
            if cutin.y < 0:
                cutoff.y = -cutin.y
                cutin.y = 0

            img.alpha_composite(texture, cutin.as_tuple(), cutoff.as_tuple())
        return img

    def __render(self, swf: SWF, export_tag: Optional[str]) -> Tuple[int, List[Any]]:
        # If we are rendering only an exported tag, we want to perform the actions of the
        # rest of the SWF but not update any layers as a result.
        self.__visible_tag = None
        if export_tag is not None:
            # Make sure this tag is actually present in the SWF.
            if export_tag not in swf.exported_tags:
                raise Exception(f'{export_tag} is not exported by {swf.exported_name}!')
            self.__visible_tag = swf.exported_tags[export_tag]

        # Now, we need to make an index of each ID'd tag.
        self.__ided_tags = {}

        def get_children(tag: Tag) -> List[Tag]:
            children: List[Tag] = []

            for child in tag.children():
                children.extend(get_children(child))
            children.append(tag)
            return children

        all_children: List[Tag] = []
        for tag in swf.tags:
            all_children.extend(get_children(tag))

        for child in all_children:
            if child.id is not None:
                if child.id in self.__ided_tags:
                    raise Exception(f"Already have a Tag ID {child.id}!")
                self.__ided_tags[child.id] = child

        # TODO: Now, we have to resolve imports.
        pass

        # Now, let's go through each frame, performing actions as necessary.
        spf = 1.0 / swf.fps
        frames: List[Any] = []
        frameno: int = 0
        clips: List[Clip] = [Clip(None, swf.frames, swf.tags)]

        # Reset any registered shapes.
        self.__registered_shapes = {}

        while any(c.running() for c in clips):
            # Create a new image to render into.
            time = spf * float(frameno)
            color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
            curimage = Image.new("RGBA", (swf.location.width, swf.location.height), color=color.as_tuple())
            self.vprint(f"Rendering Frame {frameno} ({time}s)")

            # Go through all registered clips, place all needed tags.
            newclips: List[Clip] = []
            for clip in clips:
                if clip.finished():
                    continue

                frame = clip.frame()
                if frame.num_tags > 0:
                    self.vprint(f"  Sprite Tag ID: {clip.tag_id}, Start Frame: {frame.start_tag_offset}, Num Frames: {frame.num_tags}")
                    for tag in clip.tags[frame.start_tag_offset:(frame.start_tag_offset + frame.num_tags)]:
                        newclips.extend(self.__place(tag, parent_sprite=clip.tag_id))

            # Add any new clips that we should process next frame.
            clips.extend(newclips)

            # Now, render out the placed objects.
            for obj in sorted(self.__placed_objects, key=lambda o: o.tag.depth):
                if self.__visible_tag != obj.parent_sprite:
                    continue

                self.vprint(f"  Rendering placed object ID {obj.tag.object_id} from sprite {obj.parent_sprite} onto Depth {obj.tag.depth}")
                curimage = self.__render_object(curimage, obj.tag, Matrix.identity(), Point.identity())

            # Advance all the clips and frame now that we processed and rendered them.
            for clip in clips:
                clip.advance()
            frames.append(curimage)
            frameno += 1

        return int(spf * 1000.0), frames
