from typing import Dict, List, Tuple, Optional, Union
from PIL import Image  # type: ignore

from .swf import SWF, Frame, Tag, AP2ShapeTag, AP2DefineSpriteTag, AP2PlaceObjectTag, AP2RemoveObjectTag, AP2DoActionTag, AP2DefineFontTag, AP2DefineEditTextTag
from .types import Color, Matrix, Point
from .geo import Shape
from .util import VerboseOutput


class Clip:
    # A movie clip that we are rendering, frame by frame. These are manifest by the root
    # SWF as well as AP2DefineSpriteTags which are essentially embedded movie clips. The
    # tag_id is the AP2DefineSpriteTag that created us, or None if this is the clip for
    # the root of the movie.
    def __init__(self, tag_id: Optional[int], frames: List[Frame], tags: List[Tag]) -> None:
        self.tag_id = tag_id
        self.frames = frames
        self.tags = tags
        self.frameno = 0
        self.__last_frameno = -1
        self.__finished = False

    def clone(self) -> "Clip":
        return Clip(
            self.tag_id,
            self.frames,
            self.tags,
        )

    @property
    def frame(self) -> Frame:
        # The current frame object.
        if self.frameno >= len(self.frames):
            raise Exception("Logic error!")
        return self.frames[self.frameno]

    def advance(self) -> None:
        # Advance the clip by one frame after we finished processing that frame.
        if self.running:
            self.frameno += 1

    def clear(self) -> None:
        # Clear the dirty flag on this clip until we advance to the next frame.
        self.__last_frameno = self.frameno

    def remove(self) -> None:
        # Schedule this clip to be removed.
        self.__finished = True

    @property
    def finished(self) -> bool:
        # Whether we've hit the end of the clip and should get rid of this object or not.
        return (self.__finished or (self.frameno == len(self.frames)))

    @property
    def running(self) -> bool:
        return not self.finished

    @property
    def dirty(self) -> bool:
        # Whether we are in need of processing this frame or not.
        return self.running and (self.frameno != self.__last_frameno)

    def __repr__(self) -> str:
        return f"Clip(tag_id={self.tag_id}, frames={len(self.frames)}, frameno={self.frameno}, running={self.running}, dirty={self.dirty})"


class PlacedObject:
    # An object that occupies the screen at some depth. Placed by an AP2PlaceObjectTag
    # that is inside the root SWF or an AP2DefineSpriteTag (essentially an embedded
    # movie clip).
    def __init__(self, parent_clip: Clip, tag: AP2PlaceObjectTag, drawable: Union[Clip, Shape]) -> None:
        self.parent_clip = parent_clip
        # TODO: Get rid of tag reference, instead grab the variables we need.
        self.tag = tag
        self.drawable = drawable

    @property
    def depth(self) -> int:
        return self.tag.depth

    @property
    def object_id(self) -> int:
        return self.tag.object_id

    def __repr__(self) -> str:
        return f"PlacedObject(parent_clip={self.parent_clip}, object_id={self.object_id}, depth={self.depth})"


class AFPRenderer(VerboseOutput):
    def __init__(self, shapes: Dict[str, Shape] = {}, textures: Dict[str, Image.Image] = {}, swfs: Dict[str, SWF] = {}) -> None:
        super().__init__()

        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Image.Image] = textures
        self.swfs: Dict[str, SWF] = swfs

        # Internal render parameters
        self.__visible_tag: Optional[int] = None
        self.__registered_shapes: Dict[int, Shape] = {}
        self.__registered_sprites: Dict[int, Clip] = {}
        self.__placed_objects: List[PlacedObject] = []
        self.__clips: List[Clip] = []

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

    def __place(self, tag: Tag, parent_clip: Clip, prefix: str = "") -> List[Clip]:
        # "Place" a tag on the screen. Most of the time, this means performing the action of the tag,
        # such as defining a shape (registering it with our shape list) or adding/removing an object.
        if isinstance(tag, AP2ShapeTag):
            self.vprint(f"{prefix}    Loading {tag.reference} into shape slot {tag.id}")

            if tag.reference not in self.shapes:
                raise Exception(f"Cannot find shape reference {tag.reference}!")
            if tag.id in self.__registered_shapes:
                raise Exception(f"Cannot register {tag.reference} as shape slot {tag.id} is already taken!")

            self.__registered_shapes[tag.id] = self.shapes[tag.reference]

            # No additional movie clips were spawned.
            return []
        elif isinstance(tag, AP2DefineSpriteTag):
            self.vprint(f"{prefix}    Loading Sprite into sprite slot {tag.id}")

            if tag.id in self.__registered_sprites:
                raise Exception(f"Cannot register sprite as sprite slot {tag.id} is already taken!")

            # Register a new clip that we might reference to execute.
            self.__registered_sprites[tag.id] = Clip(tag.id, tag.frames, tag.tags)

            # We didn't add the clip to our processing target yet.
            return []
        elif isinstance(tag, AP2PlaceObjectTag):
            if tag.update:
                self.vprint(f"{prefix}    Updating Object ID {tag.object_id} on Depth {tag.depth}")
                updated = False

                for obj in self.__placed_objects:
                    if obj.object_id == tag.object_id and obj.depth == tag.depth:
                        # As far as I can tell, pretty much only color and matrix stuff can be updated.
                        obj.tag.mult_color = tag.mult_color or obj.tag.mult_color
                        obj.tag.add_color = tag.add_color or obj.tag.add_color
                        obj.tag.transform = tag.transform or obj.tag.transform
                        obj.tag.rotation_offset = tag.rotation_offset or obj.tag.rotation_offset
                        updated = True

                if not updated:
                    print(f"WARNING: Couldn't find tag {tag.object_id} on depth {tag.depth} to update!")

                # We finished!
                return []
            else:
                if tag.source_tag_id is None:
                    raise Exception("Cannot place a tag with no source ID and no update flags!")

                # TODO: Handle ON_LOAD triggers for this object. Many of these are just calls into
                # the game to set the current frame that we're on, but sometimes its important.

                if tag.source_tag_id in self.__registered_sprites:
                    # This is a sprite placement reference. We need to start this
                    # clip so that we can process its own animation frames in order to reference
                    # its objects when rendering.

                    self.vprint(f"{prefix}    Placing Sprite {tag.source_tag_id} with Object ID {tag.object_id} onto Depth {tag.depth}")
                    new_clip = self.__registered_sprites[tag.source_tag_id].clone()
                    self.__placed_objects.append(PlacedObject(parent_clip, tag, new_clip))

                    return [new_clip]

                if tag.source_tag_id in self.__registered_shapes:
                    self.vprint(f"{prefix}    Placing Shape {tag.source_tag_id} with Object ID {tag.object_id} onto Depth {tag.depth}")
                    self.__placed_objects.append(PlacedObject(parent_clip, tag, self.__registered_shapes[tag.source_tag_id]))

                    return []

                raise Exception(f"Cannot find a shape or sprite with Tag ID {tag.source_tag_id}!")
        elif isinstance(tag, AP2RemoveObjectTag):
            self.vprint(f"{prefix}    Removing Object ID {tag.object_id} from Depth {tag.depth}")

            if tag.object_id != 0:
                # Remove the identified object by object ID and depth.
                # Remember removed objects so we can stop any clips.
                removed_objects = [
                    obj for obj in self.__placed_objects
                    if obj.object_id == tag.object_id and obj.depth == tag.depth
                ]

                # Get rid of the objects that we're removing from the master list.
                self.__placed_objects = [
                    obj for obj in self.__placed_objects
                    if not(obj.object_id == tag.object_id and obj.depth == tag.depth)
                ]
            else:
                # Remove the last placed object at this depth. The placed objects list isn't
                # ordered so much as apppending to the list means the last placed object at a
                # depth comes last.
                removed_objects = []
                for i in range(len(self.__placed_objects)):
                    real_index = len(self.__placed_objects) - (i + 1)

                    if self.__placed_objects[real_index].depth == tag.depth:
                        removed_objects = self.__placed_objects[real_index:(real_index + 1)]
                        self.__placed_objects = self.__placed_objects[:real_index] + self.__placed_objects[(real_index + 1):]
                        break

            if not removed_objects:
                print(f"WARNING: Couldn't find object to remove by ID {tag.object_id} and depth {tag.depth}!")

            # Now, if we removed a sprite, go through and drop all of its children.
            while removed_objects:
                # Keep track of new clips that we need to drop.
                new_removed_objects = []

                for obj in removed_objects:
                    if obj.tag.source_tag_id in self.__registered_sprites:
                        # This is a sprite placement reference, stop the clip.
                        for clip in self.__clips:
                            if clip is obj.drawable:
                                clip.remove()

                        # Log what we're killing, schedule child clips for removal as well.
                        for o in self.__placed_objects:
                            if o.parent_clip is obj.drawable:
                                self.vprint(f"{prefix}    Removing Object ID {o.tag.object_id} from Depth {o.tag.depth} after removing sprite with ID {tag.object_id} and depth {tag.depth}")
                                new_removed_objects.append(o)

                        # Kill any objects placed by this clip.
                        self.__placed_objects = [
                            o for o in self.__placed_objects
                            if not(o.parent_clip is obj.drawable)
                        ]

                # Now, do it again.
                removed_objects = new_removed_objects

            return []
        elif isinstance(tag, AP2DoActionTag):
            print("WARNING: Unhandled DO_ACTION tag!")
            return []
        elif isinstance(tag, AP2DefineFontTag):
            print("WARNING: Unhandled DEFINE_FONT tag!")
            return []
        elif isinstance(tag, AP2DefineEditTextTag):
            print("WARNING: Unhandled DEFINE_EDIT_TEXT tag!")
            return []
        else:
            raise Exception(f"Failed to process tag: {tag}")

    def __render_object(self, img: Image.Image, renderable: PlacedObject, parent_transform: Matrix, parent_origin: Point) -> None:
        if renderable.tag.source_tag_id is None:
            self.vprint("    Nothing to render!")
            return

        # Look up the affine transformation matrix for this object.
        transform = parent_transform.multiply(renderable.tag.transform or Matrix.identity())

        # Calculate the inverse so we can map canvas space back to texture space.
        try:
            inverse = transform.inverse()
        except ZeroDivisionError:
            print(f"WARNING: Transform Matrix {transform} has zero scaling factor, making it non-invertible!")
            return

        # Render individual shapes if this is a sprite.
        if renderable.tag.source_tag_id in self.__registered_sprites:
            # This is a sprite placement reference.
            objs = sorted(
                [o for o in self.__placed_objects if o.parent_clip is renderable.drawable],
                key=lambda obj: obj.depth,
            )
            for obj in objs:
                self.vprint(f"    Rendering placed object ID {obj.object_id} from sprite {obj.parent_clip.tag_id} onto Depth {obj.depth}")
                self.__render_object(img, obj, transform, parent_origin.add(renderable.tag.rotation_offset or Point.identity()))

            return

        # This is a shape draw reference.
        shape = self.__registered_shapes[renderable.tag.source_tag_id]

        # Calculate add color if it is present.
        add_color = (renderable.tag.add_color or Color(0.0, 0.0, 0.0, 0.0)).as_tuple()
        mult_color = renderable.tag.mult_color or Color(1.0, 1.0, 1.0, 1.0)
        blend = renderable.tag.blend or 0

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
                origin = parent_origin.add(renderable.tag.rotation_offset or Point.identity())

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

                            if blend == 0:
                                imgmap[imgoff] = self.__blend_normal(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                            elif blend == 8:
                                imgmap[imgoff] = self.__blend_additive(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                            elif blend == 9:
                                imgmap[imgoff] = self.__blend_subtractive(imgmap[imgoff], texmap[texoff], mult_color, add_color)
                            else:
                                print(f"WARNING: Unsupported blend {blend}")
                                imgmap[imgoff] = self.__blend_normal(imgmap[imgoff], texmap[texoff], mult_color, add_color)

                    img.putdata(imgmap)

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

    def __blend_additive(
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

    def __blend_subtractive(
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

    def __render(self, swf: SWF, export_tag: Optional[str]) -> Tuple[int, List[Image.Image]]:
        # If we are rendering an exported tag, we want to perform the actions of the
        # rest of the SWF but not update any layers as a result.
        self.__visible_tag = None
        if export_tag is not None:
            # Make sure this tag is actually present in the SWF.
            if export_tag not in swf.exported_tags:
                raise Exception(f'{export_tag} is not exported by {swf.exported_name}!')
            self.__visible_tag = swf.exported_tags[export_tag]

        # TODO: We have to resolve imports.

        # Now, let's go through each frame, performing actions as necessary.
        spf = 1.0 / swf.fps
        frames: List[Image.Image] = []
        frameno: int = 0

        # Reset any registered clips.
        self.__clips = [Clip(None, swf.frames, swf.tags)] if len(swf.frames) > 0 else []

        # Reset any registered shapes.
        self.__registered_shapes = {}
        self.__registered_sprites = {}

        try:
            while any(c.running for c in self.__clips):
                # Create a new image to render into.
                time = spf * float(frameno)
                color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
                self.vprint(f"Rendering Frame {frameno} ({time}s)")

                # Go through all registered clips, place all needed tags.
                changed = False
                while any(c.dirty for c in self.__clips):
                    newclips: List[Clip] = []
                    for clip in self.__clips:
                        # See if the clip needs handling (might have been placed and needs to run).
                        if clip.dirty and clip.frame.current_tag < clip.frame.num_tags:
                            self.vprint(f"  Sprite Tag ID: {clip.tag_id}, Current Frame: {clip.frame.start_tag_offset + clip.frame.current_tag}, Num Frames: {clip.frame.num_tags}")
                            newclips.extend(self.__place(clip.tags[clip.frame.start_tag_offset + clip.frame.current_tag], parent_clip=clip))
                            clip.frame.current_tag += 1
                            changed = True

                        if clip.dirty and clip.frame.current_tag == clip.frame.num_tags:
                            # We handled this clip.
                            clip.clear()

                    # Add any new clips that we should process next frame.
                    self.__clips.extend(newclips)

                if changed or frameno == 0:
                    # Now, render out the placed objects. We sort by depth so that we can
                    # get the layering correct, but its important to preserve the original
                    # insertion order for delete requests.
                    curimage = Image.new("RGBA", (swf.location.width, swf.location.height), color=color.as_tuple())
                    for obj in sorted(self.__placed_objects, key=lambda obj: obj.depth):
                        if self.__visible_tag != obj.parent_clip.tag_id:
                            continue

                        self.vprint(f"  Rendering placed object ID {obj.object_id} from sprite {obj.parent_clip.tag_id} onto Depth {obj.depth}")
                        self.__render_object(curimage, obj, Matrix.identity(), Point.identity())
                else:
                    # Nothing changed, make a copy of the previous render.
                    self.vprint("  Using previous frame render")
                    curimage = frames[-1].copy()

                # Advance all the clips and frame now that we processed and rendered them.
                for clip in self.__clips:
                    if clip.dirty:
                        raise Exception("Logic error!")
                    clip.advance()
                frames.append(curimage)
                frameno += 1

                # Garbage collect any clips that we're finished with.
                removed_referenced_tag = False
                for c in self.__clips:
                    if c.finished:
                        if self.__visible_tag == c.tag_id:
                            removed_referenced_tag = True

                        self.vprint(f"  Removing clip based on Tag ID {clip.tag_id} because it is finished playing.")

                self.__clips = [c for c in self.__clips if not c.finished]

                # Exit early if we removed all tags we would be rendering.
                if removed_referenced_tag and self.__clips:
                    if not any(c.tag_id == self.__visible_tag for c in self.__clips):
                        self.vprint("Finishing early because the tag we are rendering has deconstructed.")
                        break
        except KeyboardInterrupt:
            # Allow ctrl-c to end early and render a partial animation.
            print(f"WARNING: Interrupted early, will render only {len(frames)} of animation!")

        return int(spf * 1000.0), frames
