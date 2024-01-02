from typing import Any, Dict, Generator, List, Set, Tuple, Optional, Union
from PIL import Image

from .blend import affine_composite, perspective_composite
from .swf import (
    SWF,
    Frame,
    Tag,
    AP2ShapeTag,
    AP2DefineSpriteTag,
    AP2PlaceObjectTag,
    AP2RemoveObjectTag,
    AP2DoActionTag,
    AP2DefineFontTag,
    AP2DefineEditTextTag,
    AP2DefineMorphShapeTag,
    AP2PlaceCameraTag,
    AP2ImageTag,
)
from .decompile import ByteCode
from .types import (
    Color,
    HSL,
    Matrix,
    Point,
    Rectangle,
    AAMode,
    AP2Trigger,
    AP2Action,
    PushAction,
    StoreRegisterAction,
    StringConstant,
    Register,
    NULL,
    UNDEFINED,
    GLOBAL,
    ROOT,
    PARENT,
    THIS,
    CLIP,
)
from .geo import Shape, DrawParams
from .util import VerboseOutput


class RegisteredClip:
    # A movie clip that we are rendering, frame by frame. These are manifest by the root
    # SWF as well as AP2DefineSpriteTags which are essentially embedded movie clips. The
    # tag_id is the AP2DefineSpriteTag that created us, or None if this is the clip for
    # the root of the movie.
    def __init__(
        self,
        tag_id: Optional[int],
        frames: List[Frame],
        tags: List[Tag],
        labels: Dict[str, int],
    ) -> None:
        self.tag_id = tag_id
        self.frames = frames
        self.tags = tags
        self.labels = labels

    def __repr__(self) -> str:
        return f"RegisteredClip(tag_id={self.tag_id})"

    @property
    def reference(self) -> str:
        return "anonymous sprite"


class RegisteredShape:
    # A shape that we are rendering, as placed by some placed clip somewhere.
    def __init__(
        self,
        tag_id: int,
        reference: str,
        vertex_points: List[Point],
        tex_points: List[Point],
        tex_colors: List[Color],
        draw_params: List[DrawParams],
    ) -> None:
        self.tag_id = tag_id
        self.__reference = reference
        self.vertex_points: List[Point] = vertex_points
        self.tex_points: List[Point] = tex_points
        self.tex_colors: List[Color] = tex_colors
        self.draw_params: List[DrawParams] = draw_params
        self.rectangle: Optional[Image.Image] = None

    @property
    def reference(self) -> str:
        textures = {dp.region for dp in self.draw_params if dp.region is not None}
        if textures:
            vals = ", ".join(textures)
            return f"{self.__reference}, {vals}"
        else:
            return f"{self.__reference}, untextured"

    def __repr__(self) -> str:
        return f"RegisteredShape(tag_id={self.tag_id}, reference={self.reference} vertex_points={self.vertex_points}, tex_points={self.tex_points}, tex_colors={self.tex_colors}, draw_params={self.draw_params})"


class RegisteredImage:
    # An image that we should draw directly.
    def __init__(self, tag_id: int, reference: str) -> None:
        self.tag_id = tag_id
        self.reference = reference

    def __repr__(self) -> str:
        return f"RegisteredImage(tag_id={self.tag_id}, reference={self.reference})"


class RegisteredDummy:
    # An imported tag that we could not find.
    def __init__(self, tag_id: int) -> None:
        self.tag_id = tag_id

    def __repr__(self) -> str:
        return f"RegisteredDummy(tag_id={self.tag_id})"

    @property
    def reference(self) -> str:
        return "anonymous dummy"


class Mask:
    def __init__(self, bounds: Rectangle) -> None:
        self.bounds = bounds
        self.rectangle: Optional[Image.Image] = None


class PlacedObject:
    # An object that occupies the screen at some depth.
    def __init__(
        self,
        object_id: int,
        depth: int,
        rotation_origin: Point,
        transform: Matrix,
        projection: int,
        mult_color: Color,
        add_color: Color,
        hsl_shift: HSL,
        blend: int,
        mask: Optional[Mask],
    ) -> None:
        self.__object_id = object_id
        self.__depth = depth
        self.rotation_origin = rotation_origin
        self.transform = transform
        self.projection = projection
        self.mult_color = mult_color
        self.add_color = add_color
        self.hsl_shift = hsl_shift
        self.blend = blend
        self.mask = mask
        self.visible: bool = True

    @property
    def source(
        self,
    ) -> Union[RegisteredClip, RegisteredShape, RegisteredImage, RegisteredDummy]:
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
    def __init__(
        self,
        object_id: int,
        depth: int,
        rotation_origin: Point,
        transform: Matrix,
        projection: int,
        mult_color: Color,
        add_color: Color,
        hsl_shift: HSL,
        blend: int,
        mask: Optional[Mask],
        source: RegisteredShape,
    ) -> None:
        super().__init__(
            object_id,
            depth,
            rotation_origin,
            transform,
            projection,
            mult_color,
            add_color,
            hsl_shift,
            blend,
            mask,
        )
        self.__source = source

    @property
    def source(self) -> RegisteredShape:
        return self.__source

    def __repr__(self) -> str:
        return f"PlacedShape(object_id={self.object_id}, depth={self.depth}, source={self.source})"


class PlacedClip(PlacedObject):
    # A movieclip that occupies its parent clip at some depth. Placed by an AP2PlaceObjectTag
    # referencing an AP2DefineSpriteTag. Essentially an embedded movie clip.
    def __init__(
        self,
        object_id: int,
        depth: int,
        rotation_origin: Point,
        transform: Matrix,
        projection: int,
        mult_color: Color,
        add_color: Color,
        hsl_shift: HSL,
        blend: int,
        mask: Optional[Mask],
        source: RegisteredClip,
    ) -> None:
        super().__init__(
            object_id,
            depth,
            rotation_origin,
            transform,
            projection,
            mult_color,
            add_color,
            hsl_shift,
            blend,
            mask,
        )
        self.placed_objects: List[PlacedObject] = []
        self.frame: int = 0
        self.unplayed_tags: List[int] = [i for i in range(len(source.tags))]
        self.__source = source

        # Dynamic properties that are adjustable by SWF bytecode.
        self.playing: bool = True
        self.requested_frame: Optional[int] = None
        self.visible_frame: int = -1

        # Root clip resizing, which we don't really support.
        self.__width = 0
        self.__height = 0

    @property
    def source(self) -> RegisteredClip:
        return self.__source

    def __check_visible(self) -> None:
        if self.visible_frame >= 0 and self.frame >= self.visible_frame:
            self.visible = True
            self.visible_frame = -1

    def advance(self) -> None:
        if self.frame < len(self.source.frames):
            self.frame += 1
        self.__check_visible()

    def rewind(self) -> None:
        self.frame = 0
        self.unplayed_tags = [i for i in range(len(self.__source.tags))]
        self.placed_objects = []
        self.__check_visible()

    @property
    def finished(self) -> bool:
        return self.frame == len(self.source.frames)

    def __repr__(self) -> str:
        return (
            f"PlacedClip(object_id={self.object_id}, depth={self.depth}, source={self.source}, frame={self.frame}, "
            + f"requested_frame={self.requested_frame}, total_frames={len(self.source.frames)}, playing={self.playing}, "
            + f"finished={self.finished})"
        )

    def __resolve_frame(self, frame: Any) -> Optional[int]:
        if isinstance(frame, int):
            return frame
        if isinstance(frame, str):
            if frame in self.__source.labels:
                return self.__source.labels[frame]
        return None

    # The following are attributes and functions necessary to support some simple bytecode.
    def gotoAndStop(self, frame: Any) -> None:
        actual_frame = self.__resolve_frame(frame)
        if actual_frame is None:
            print(f"WARNING: Unrecognized frame {frame} to gotoAndStop function!")
            return
        if actual_frame <= 0:
            actual_frame = 1
        if actual_frame > len(self.source.frames):
            actual_frame = len(self.source.frames)
        self.requested_frame = actual_frame
        self.playing = False

    def gotoAndPlay(self, frame: Any) -> None:
        actual_frame = self.__resolve_frame(frame)
        if actual_frame is None:
            print(f"WARNING: Non-integer frame {frame} to gotoAndPlay function!")
            return
        if actual_frame <= 0:
            actual_frame = 1
        if actual_frame > len(self.source.frames):
            actual_frame = len(self.source.frames)
        self.requested_frame = actual_frame
        self.playing = True

    def stop(self) -> None:
        self.playing = False

    def play(self) -> None:
        self.playing = True

    def setInvisibleUntil(self, frame: Any) -> None:
        actual_frame = self.__resolve_frame(frame)
        if actual_frame is None:
            print(f"WARNING: Non-integer frame {frame} to setInvisibleUntil function!")
            return
        actual_frame += self.frameOffset - 1
        self.visible = False
        if actual_frame <= 0:
            actual_frame = 1
        if actual_frame > len(self.source.frames):
            actual_frame = len(self.source.frames)
        self.visible_frame = actual_frame
        self.__check_visible()

    @property
    def frameOffset(self) -> int:
        return self.requested_frame or self.frame

    @frameOffset.setter
    def frameOffset(self, val: Any) -> None:
        actual_frame = self.__resolve_frame(val)
        if actual_frame is None:
            print(f"WARNING: Non-integer frameOffset {val} to frameOffset attribute!")
            return
        if actual_frame < 0:
            actual_frame = 0
        if actual_frame >= len(self.source.frames):
            actual_frame = len(self.source.frames) - 1
        self.requested_frame = actual_frame + 1

    @property
    def _visible(self) -> int:
        return 1 if self.visible else 0

    @_visible.setter
    def _visible(self, val: Any) -> None:
        self.visible = val != 0

    @property
    def _width(self) -> int:
        calculated_width = self.__width
        for obj in self.placed_objects:
            if isinstance(obj, PlacedClip):
                calculated_width = max(calculated_width, obj._width)
        return calculated_width

    @_width.setter
    def _width(self, val: Any) -> None:
        self.__width = val

    @property
    def _height(self) -> int:
        calculated_height = self.__height
        for obj in self.placed_objects:
            if isinstance(obj, PlacedClip):
                calculated_height = max(calculated_height, obj._height)
        return calculated_height

    @_height.setter
    def _height(self, val: Any) -> None:
        self.__height = val


class PlacedImage(PlacedObject):
    # An image that occupies its parent clip at some depth. Placed by an AP2PlaceObjectTag
    # referencing an AP2ImageTag.
    def __init__(
        self,
        object_id: int,
        depth: int,
        rotation_origin: Point,
        transform: Matrix,
        projection: int,
        mult_color: Color,
        add_color: Color,
        hsl_shift: HSL,
        blend: int,
        mask: Optional[Mask],
        source: RegisteredImage,
    ) -> None:
        super().__init__(
            object_id,
            depth,
            rotation_origin,
            transform,
            projection,
            mult_color,
            add_color,
            hsl_shift,
            blend,
            mask,
        )
        self.__source = source

    @property
    def source(self) -> RegisteredImage:
        return self.__source

    def __repr__(self) -> str:
        return f"PlacedImage(object_id={self.object_id}, depth={self.depth}, source={self.source})"


class PlacedDummy(PlacedObject):
    # A reference to an object we can't find because we're missing the import.
    def __init__(
        self,
        object_id: int,
        depth: int,
        rotation_origin: Point,
        transform: Matrix,
        projection: int,
        mult_color: Color,
        add_color: Color,
        hsl_shift: HSL,
        blend: int,
        mask: Optional[Mask],
        source: RegisteredDummy,
    ) -> None:
        super().__init__(
            object_id,
            depth,
            rotation_origin,
            transform,
            projection,
            mult_color,
            add_color,
            hsl_shift,
            blend,
            mask,
        )
        self.__source = source

    @property
    def source(self) -> RegisteredDummy:
        return self.__source


class PlacedCamera:
    def __init__(self, center: Point, focal_length: float) -> None:
        self.center = center
        self.focal_length = focal_length
        self.adjusted = False


class Global:
    def __init__(self, root: PlacedClip, clip: PlacedClip) -> None:
        self.root = root
        self.clip = clip

    def getInstanceAtDepth(self, depth: Any) -> Any:
        if not isinstance(depth, int):
            return UNDEFINED

        # For some reason, it looks like internally the depth of all objects is
        # stored added to -0x4000, so let's reverse that.
        depth = depth + 0x4000

        for obj in self.clip.placed_objects:
            if obj.depth == depth:
                return obj

        print(f"WARNING: Could not find object at depth {depth}!")
        return UNDEFINED

    def deepGotoAndPlay(self, frame: Any) -> Any:
        # This is identical to regular gotoAndPlay, however it also recursively
        # goes through and sets all child clips playing as well.
        try:
            meth = getattr(self.clip, "gotoAndPlay")

            # Call it, set the return on the stack.
            retval = meth(frame)

            # Recursively go through any children of "clip" and call play
            # on them as well.
            def play_children(obj: Any) -> None:
                if isinstance(obj, PlacedClip):
                    obj.play()
                    for child in obj.placed_objects:
                        play_children(child)

            play_children(self.clip)
            return retval
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call gotoAndPlay({frame}) on {self.clip} but that method doesn't exist!")
            return UNDEFINED

    def __find_parent(self, parent: PlacedClip, child: PlacedClip) -> Optional[PlacedClip]:
        for obj in parent.placed_objects:
            if obj is child:
                # This is us, so the parent is our parent.
                return parent
            if isinstance(obj, PlacedClip):
                maybe_parent = self.__find_parent(obj, child)
                if maybe_parent is not None:
                    return maybe_parent

        return None

    def find_parent(self, child: PlacedClip) -> Optional[PlacedClip]:
        return self.__find_parent(self.root, child)


class AEPLib:
    def aep_set_rect_mask(self, thisptr: Any, left: Any, right: Any, top: Any, bottom: Any) -> None:
        if (
            not isinstance(left, (int, float))
            or not isinstance(right, (int, float))
            or not isinstance(top, (int, float))
            or not isinstance(bottom, (int, float))
        ):
            print(
                f"WARNING: Ignoring aeplib.aep_set_rect_mask call with invalid parameters {left}, {right}, {top}, {bottom}!"
            )
            return
        if isinstance(thisptr, PlacedObject):
            thisptr.mask = Mask(
                Rectangle(
                    left=float(left),
                    right=float(right),
                    top=float(top),
                    bottom=float(bottom),
                ),
            )
        else:
            print(f"WARNING: Ignoring aeplib.aep_set_rect_mask call with unrecognized target {thisptr}!")

    def aep_set_set_frame(self, thisptr: Any, frame: Any) -> None:
        # This appears to be some sort of callback that the game or other animations can use to figure out
        # what frame of animation is currently happening. Whenever I've seen it, it is with the 'frame' set
        # to an integer value that matches the currently rendering frame in the render loop. I think its
        # safe to ignore this, but if we ever create animations it might be necessary to add calls to this.
        pass

    def aep_set_frame_control(self, thisptr: Any, depth: Any, frame: Any) -> None:
        if not isinstance(thisptr, PlacedClip):
            print(f"WARNING: Ignoring aeplib.aep_set_frame_control with unrecognized current object {thisptr}!")
            return

        for obj in thisptr.placed_objects:
            if obj.depth == depth:
                if not isinstance(obj, PlacedClip):
                    print(f"WARNING: Ignoring aeplib.aep_set_frame_control called on object {obj} at depth {depth}!")
                    return

                obj.setInvisibleUntil(frame)
                return

        print(f"WARNING: Ignoring aeplib.aep_set_frame_control called on nonexistent object at depth {depth}!")

    def gotoAndPlay(self, thisptr: Any, frame: Any) -> Any:
        # This appears to be a wrapper to allow calling gotoAndPlay on clips.
        try:
            meth = getattr(thisptr, "gotoAndPlay")

            # Call it, set the return on the stack.
            return meth(frame)
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call gotoAndPlay({frame}) on {thisptr} but that method doesn't exist!")
            return UNDEFINED

    def gotoAndStop(self, thisptr: Any, frame: Any) -> Any:
        # This appears to be a wrapper to allow calling gotoAndStop on clips.
        try:
            meth = getattr(thisptr, "gotoAndStop")

            # Call it, set the return on the stack.
            return meth(frame)
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call gotoAndStop({frame}) on {thisptr} but that method doesn't exist!")
            return UNDEFINED

    def deepGotoAndPlay(self, thisptr: Any, frame: Any) -> Any:
        # This is identical to regular gotoAndPlay, however it also recursively
        # goes through and sets all child clips playing as well.
        try:
            meth = getattr(thisptr, "gotoAndPlay")

            # Call it, set the return on the stack.
            retval = meth(frame)

            # Recursively go through any children of "thisptr" and call play
            # on them as well.
            def play_children(obj: Any) -> None:
                if isinstance(obj, PlacedClip):
                    obj.play()
                    for child in obj.placed_objects:
                        play_children(child)

            play_children(thisptr)
            return retval
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call gotoAndPlay({frame}) on {thisptr} but that method doesn't exist!")
            return UNDEFINED

    def deepGotoAndStop(self, thisptr: Any, frame: Any) -> Any:
        # This is identical to regular gotoAndStop, however it also recursively
        # goes through and sets all child clips stopped as well.
        try:
            meth = getattr(thisptr, "gotoAndStop")

            # Call it, set the return on the stack.
            retval = meth(frame)

            # Recursively go through any children of "thisptr" and call stop
            # on them as well.
            def stop_children(obj: Any) -> None:
                if isinstance(obj, PlacedClip):
                    obj.stop()
                    for child in obj.placed_objects:
                        stop_children(child)

            stop_children(thisptr)
            return retval
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call gotoAndStop({frame}) on {thisptr} but that method doesn't exist!")
            return UNDEFINED

    def play(self, thisptr: Any) -> Any:
        # This appears to be a wrapper to allow calling play on clips.
        try:
            meth = getattr(thisptr, "play")

            # Call it, set the return on the stack.
            return meth()
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call play() on {thisptr} but that method doesn't exist!")
            return UNDEFINED

    def stop(self, thisptr: Any) -> Any:
        # This appears to be a wrapper to allow calling stop on clips.
        try:
            meth = getattr(thisptr, "stop")

            # Call it, set the return on the stack.
            return meth()
        except AttributeError:
            # Function does not exist!
            print(f"WARNING: Tried to call stop() on {thisptr} but that method doesn't exist!")
            return UNDEFINED


class ASDLib:
    def sound_play(self, sound: Any) -> None:
        if not isinstance(sound, str):
            print(f"WARNING: Ignoring asdlib.sound_play call with invalid parameters {sound}!")
        print(f"WARNING: Requested sound {sound} be played but we don't support sound yet!")


MissingThis = object()


class AFPRenderer(VerboseOutput):
    def __init__(
        self,
        shapes: Dict[str, Shape] = {},
        textures: Dict[str, Image.Image] = {},
        swfs: Dict[str, SWF] = {},
        single_threaded: bool = False,
        enable_aa: bool = False,
    ) -> None:
        super().__init__()

        # Options for rendering
        self.__single_threaded = single_threaded
        self.__enable_aa = enable_aa

        # Library of shapes (draw instructions), textures (actual images) and swfs (us and other files for imports).
        self.shapes: Dict[str, Shape] = shapes
        self.textures: Dict[str, Image.Image] = textures
        self.swfs: Dict[str, SWF] = swfs

        # Internal render parameters.
        self.__registered_objects: Dict[
            int,
            Union[RegisteredShape, RegisteredClip, RegisteredImage, RegisteredDummy],
        ] = {}
        self.__root: Optional[PlacedClip] = None
        self.__camera: Optional[PlacedCamera] = None

        # List of imports that we provide stub implementations for.
        self.__stubbed_swfs: Set[str] = {
            "aeplib.aeplib",
            "aeplib.__Packages.aeplib",
        }

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
        background_image: Optional[List[Image.Image]] = None,
        only_depths: Optional[List[int]] = None,
        only_frames: Optional[List[int]] = None,
        movie_transform: Matrix = Matrix.identity(),
        overridden_width: Optional[float] = None,
        overridden_height: Optional[float] = None,
        verbose: bool = False,
    ) -> Generator[Image.Image, None, None]:
        # Given a path to a SWF root animation, attempt to render it to a list of frames.
        for _name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                with self.debugging(verbose):
                    swf.color = background_color or swf.color
                    yield from self.__render(
                        swf,
                        only_depths,
                        only_frames,
                        movie_transform,
                        background_image,
                        overridden_width,
                        overridden_height,
                    )
                    return

        raise Exception(f"{path} not found in registered SWFs!")

    def compute_path_location(
        self,
        path: str,
    ) -> Rectangle:
        # Given a path to a SWF root animation, find its bounding rectangle.
        for _name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                return swf.location

        raise Exception(f"{path} not found in registered SWFs!")

    def compute_path_frames(
        self,
        path: str,
    ) -> int:
        # Given a path to a SWF root animation, figure out how many frames are
        # in that root path with no regard to bytecode 'stop()' commands.
        for _name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                return len(swf.frames)

        raise Exception(f"{path} not found in registered SWFs!")

    def compute_path_frame_duration(
        self,
        path: str,
    ) -> int:
        # Given a path to a SWF root animation, figure out how many milliseconds are
        # occupied by each frame.
        for _name, swf in self.swfs.items():
            if swf.exported_name == path:
                # This is the SWF we care about.
                spf = 1.0 / swf.fps
                return int(spf * 1000.0)

        raise Exception(f"{path} not found in registered SWFs!")

    def compute_path_size(
        self,
        path: str,
    ) -> Rectangle:
        # Given a path to a SWF root animation, figure out what the dimensions
        # of the SWF are.
        for _name, swf in self.swfs.items():
            if swf.exported_name == path:
                return swf.location

        raise Exception(f"{path} not found in registered SWFs!")

    def list_paths(self, verbose: bool = False) -> Generator[str, None, None]:
        # Given the loaded animations, return a list of possible paths to render.
        for _name, swf in self.swfs.items():
            yield swf.exported_name

    def __execute_bytecode(
        self,
        bytecode: ByteCode,
        clip: PlacedClip,
        thisptr: Optional[Any] = MissingThis,
        prefix: str = "",
    ) -> None:
        if self.__root is None:
            raise Exception("Logic error, executing bytecode outside of a rendering movie clip!")

        thisobj = clip if (thisptr is MissingThis) else thisptr
        globalobj = Global(self.__root, clip)
        location: int = 0
        stack: List[Any] = []
        variables: Dict[str, Any] = {
            "aeplib": AEPLib(),
            "asdlib": ASDLib(),
        }
        registers: List[Any] = [UNDEFINED] * 256

        self.vprint(f"{prefix}Bytecode engine starting.", component="bytecode")

        while location < len(bytecode.actions):
            action = bytecode.actions[location]

            if action.opcode == AP2Action.END:
                # End the execution.
                self.vprint(f"{prefix}  Ending bytecode execution.", component="bytecode")
                break
            elif action.opcode == AP2Action.GET_VARIABLE:
                varname = stack.pop()

                # Look up the variable, put it on the stack.
                if varname in variables:
                    stack.append(variables[varname])
                else:
                    stack.append(UNDEFINED)
            elif action.opcode == AP2Action.SET_MEMBER:
                # Grab what we're about to do.
                set_value = stack.pop()
                attribute = stack.pop()
                obj = stack.pop()

                if not hasattr(obj, attribute):
                    print(
                        f"WARNING: Tried to set attribute {attribute} on {obj} to {set_value} but that attribute doesn't exist!"
                    )
                else:
                    self.vprint(
                        f"{prefix}  Setting attribute {attribute} on {obj} to {set_value}",
                        component="bytecode",
                    )
                    setattr(obj, attribute, set_value)
            elif action.opcode == AP2Action.CALL_METHOD:
                # Grab the method name.
                methname = stack.pop()

                # Grab the object to perform the call on.
                obj = stack.pop()

                # Grab the parameters to pass to the function.
                num_params = stack.pop()
                if not isinstance(num_params, int):
                    raise Exception("Logic error, cannot get number of parameters to method call!")
                params = []
                for _ in range(num_params):
                    params.append(stack.pop())

                # Look up the python function we're calling.
                try:
                    self.vprint(
                        f"{prefix}  Calling method {methname}({', '.join(repr(s) for s in params)}) on {obj}",
                        component="bytecode",
                    )
                    meth = getattr(obj, methname)

                    # Call it, set the return on the stack.
                    stack.append(meth(*params))
                except AttributeError:
                    # Function does not exist!
                    print(
                        f"WARNING: Tried to call {methname}({', '.join(repr(s) for s in params)}) on {obj} but that method doesn't exist!"
                    )
                    stack.append(UNDEFINED)
            elif action.opcode == AP2Action.CALL_FUNCTION:
                # Grab the method name.
                funcname = stack.pop()

                # Grab the parameters to pass to the function.
                num_params = stack.pop()
                if not isinstance(num_params, int):
                    raise Exception("Logic error, cannot get number of parameters to function call!")
                params = []
                for _ in range(num_params):
                    params.append(stack.pop())

                # Look up the python function we're calling.
                try:
                    self.vprint(
                        f"{prefix}  Calling global function {funcname}({', '.join(repr(s) for s in params)})",
                        component="bytecode",
                    )
                    func = getattr(globalobj, funcname)

                    # Call it, set the return on the stack.
                    stack.append(func(*params))
                except AttributeError:
                    # Function does not exist!
                    print(
                        f"WARNING: Tried to call {funcname}({', '.join(repr(s) for s in params)}) on {globalobj} but that function doesn't exist!"
                    )
                    stack.append(UNDEFINED)
            elif isinstance(action, PushAction):
                for obj in action.objects:
                    if isinstance(obj, Register):
                        stack.append(registers[obj.no])
                    elif isinstance(obj, StringConstant):
                        if obj.alias:
                            stack.append(obj.alias)
                        else:
                            stack.append(StringConstant.property_to_name(obj.const))
                    elif obj is NULL:
                        stack.append(None)
                    elif obj is THIS:
                        stack.append(thisobj)
                    elif obj is GLOBAL:
                        stack.append(globalobj)
                    elif obj is ROOT:
                        stack.append(self.__root)
                    elif obj is CLIP:
                        # I am not sure this is correct? Maybe it works out
                        # in circumstances where "THIS" is pointed at something
                        # else, such as defined function calls maybe?
                        stack.append(clip)
                    elif obj is PARENT:
                        # Find the parent of this clip.
                        stack.append(globalobj.find_parent(clip) or UNDEFINED)
                    else:
                        stack.append(obj)
            elif isinstance(action, StoreRegisterAction):
                set_value = stack.pop()
                if action.preserve_stack:
                    stack.append(set_value)

                for reg in action.registers:
                    registers[reg.no] = set_value
            elif action.opcode == AP2Action.POP:
                stack.pop()
            else:
                print(f"WARNING: Unhandled opcode {action} with stack {stack}")

            # Next opcode!
            location += 1

        self.vprint(f"{prefix}Bytecode engine finished.", component="bytecode")

    def __place(self, tag: Tag, operating_clip: PlacedClip, prefix: str = "") -> Tuple[Optional[PlacedClip], bool]:
        # "Place" a tag on the screen. Most of the time, this means performing the action of the tag,
        # such as defining a shape (registering it with our shape list) or adding/removing an object.
        if isinstance(tag, AP2ShapeTag):
            self.vprint(
                f"{prefix}    Loading {tag.reference} shape into object slot {tag.id}",
                component="tags",
            )

            if tag.reference not in self.shapes:
                raise Exception(f"Cannot find shape reference {tag.reference}!")

            self.__registered_objects[tag.id] = RegisteredShape(
                tag.id,
                tag.reference,
                self.shapes[tag.reference].vertex_points,
                self.shapes[tag.reference].tex_points,
                self.shapes[tag.reference].tex_colors,
                self.shapes[tag.reference].draw_params,
            )

            # Didn't place a new clip, didn't change anything.
            return None, False

        elif isinstance(tag, AP2ImageTag):
            self.vprint(
                f"{prefix}    Loading {tag.reference} image into object slot {tag.id}",
                component="tags",
            )

            if tag.reference not in self.textures:
                raise Exception(f"Cannot find texture reference {tag.reference}!")

            self.__registered_objects[tag.id] = RegisteredImage(
                tag.id,
                tag.reference,
            )

            # Didn't place a new clip, didn't change anything.
            return None, False

        elif isinstance(tag, AP2DefineSpriteTag):
            self.vprint(
                f"{prefix}    Loading anonymous sprite into object slot {tag.id}",
                component="tags",
            )

            # Register a new clip that we might reference to execute.
            self.__registered_objects[tag.id] = RegisteredClip(tag.id, tag.frames, tag.tags, tag.labels)

            # Didn't place a new clip, didn't change anything.
            return None, False

        elif isinstance(tag, AP2PlaceObjectTag):
            if tag.unrecognized_options:
                if tag.source_tag_id is not None:
                    print(
                        f"WARNING: Place object tag referencing {tag.source_tag_id} includes unparsed options and might not display properly!"
                    )
                else:
                    print(
                        f"WARNING: Place object tag on depth {tag.depth} includes unparsed options and might not display properly!"
                    )

            if tag.update:
                for i in range(len(operating_clip.placed_objects) - 1, -1, -1):
                    obj = operating_clip.placed_objects[i]

                    if obj.object_id == tag.object_id and obj.depth == tag.depth:
                        new_mult_color = tag.mult_color or obj.mult_color
                        new_add_color = tag.add_color or obj.add_color
                        new_hsl_shift = tag.hsl_shift or obj.hsl_shift
                        new_transform = (
                            obj.transform.update(
                                tag.transform,
                                tag.projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE,
                            )
                            if (tag.transform is not None and tag.projection != AP2PlaceObjectTag.PROJECTION_NONE)
                            else obj.transform
                        )
                        new_rotation_origin = tag.rotation_origin or obj.rotation_origin
                        new_blend = tag.blend or obj.blend
                        new_projection = (
                            tag.projection if tag.projection != AP2PlaceObjectTag.PROJECTION_NONE else obj.projection
                        )

                        if tag.source_tag_id is not None and tag.source_tag_id != obj.source.tag_id:
                            # This completely updates the pointed-at object.
                            newobj = self.__registered_objects[tag.source_tag_id]
                            self.vprint(
                                f"{prefix}    Replacing Object source {obj.source.tag_id} ({obj.source.reference}) with {tag.source_tag_id} ({newobj.reference}) on object with Object ID {tag.object_id} onto Depth {tag.depth}",
                                component="tags",
                            )

                            if isinstance(newobj, RegisteredShape):
                                operating_clip.placed_objects[i] = PlacedShape(
                                    obj.object_id,
                                    obj.depth,
                                    new_rotation_origin,
                                    new_transform,
                                    new_projection,
                                    new_mult_color,
                                    new_add_color,
                                    new_hsl_shift,
                                    new_blend,
                                    obj.mask,
                                    newobj,
                                )

                                # Didn't place a new clip, changed the parent clip.
                                return None, True
                            elif isinstance(newobj, RegisteredImage):
                                operating_clip.placed_objects[i] = PlacedImage(
                                    obj.object_id,
                                    obj.depth,
                                    new_rotation_origin,
                                    new_transform,
                                    new_projection,
                                    new_mult_color,
                                    new_add_color,
                                    new_hsl_shift,
                                    new_blend,
                                    obj.mask,
                                    newobj,
                                )

                                # Didn't place a new clip, changed the parent clip.
                                return None, True
                            elif isinstance(newobj, RegisteredClip):
                                new_clip = PlacedClip(
                                    tag.object_id,
                                    tag.depth,
                                    new_rotation_origin,
                                    new_transform,
                                    new_projection,
                                    new_mult_color,
                                    new_add_color,
                                    new_hsl_shift,
                                    new_blend,
                                    obj.mask,
                                    newobj,
                                )
                                operating_clip.placed_objects[i] = new_clip

                                # Placed a new clip, changed the parent.
                                return new_clip, True
                            elif isinstance(newobj, RegisteredDummy):
                                operating_clip.placed_objects[i] = PlacedDummy(
                                    obj.object_id,
                                    obj.depth,
                                    new_rotation_origin,
                                    new_transform,
                                    new_projection,
                                    new_mult_color,
                                    new_add_color,
                                    new_hsl_shift,
                                    new_blend,
                                    obj.mask,
                                    newobj,
                                )

                                # Didn't place a new clip, changed the parent clip.
                                return None, True
                            else:
                                raise Exception(f"Unrecognized object with Tag ID {tag.source_tag_id}!")
                        else:
                            # As far as I can tell, pretty much only color and matrix stuff can be updated.
                            self.vprint(
                                f"{prefix}    Updating Object ID {tag.object_id} ({obj.source.reference}) on Depth {tag.depth}",
                                component="tags",
                            )
                            obj.mult_color = new_mult_color
                            obj.add_color = new_add_color
                            obj.hsl_shift = new_hsl_shift
                            obj.transform = new_transform
                            obj.rotation_origin = new_rotation_origin
                            obj.projection = new_projection
                            obj.blend = new_blend
                            return None, True

                # Didn't place a new clip, did change something.
                print(f"WARNING: Couldn't find tag {tag.object_id} on depth {tag.depth} to update!")
                return None, False
            else:
                if tag.source_tag_id is None:
                    raise Exception("Cannot place a tag with no source ID and no update flags!")

                if tag.source_tag_id in self.__registered_objects:
                    newobj = self.__registered_objects[tag.source_tag_id]
                    self.vprint(
                        f"{prefix}    Placing Object {tag.source_tag_id} ({newobj.reference}) with Object ID {tag.object_id} onto Depth {tag.depth}",
                        component="tags",
                    )

                    if isinstance(newobj, RegisteredShape):
                        operating_clip.placed_objects.append(
                            PlacedShape(
                                tag.object_id,
                                tag.depth,
                                tag.rotation_origin or Point.identity(),
                                tag.transform or Matrix.identity(),
                                tag.projection,
                                tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                                tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                                tag.hsl_shift or HSL(0.0, 0.0, 0.0),
                                tag.blend or 0,
                                None,
                                newobj,
                            )
                        )

                        # Didn't place a new clip, changed the parent clip.
                        return None, True
                    elif isinstance(newobj, RegisteredImage):
                        operating_clip.placed_objects.append(
                            PlacedImage(
                                tag.object_id,
                                tag.depth,
                                tag.rotation_origin or Point.identity(),
                                tag.transform or Matrix.identity(),
                                tag.projection,
                                tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                                tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                                tag.hsl_shift or HSL(0.0, 0.0, 0.0),
                                tag.blend or 0,
                                None,
                                newobj,
                            )
                        )

                        # Didn't place a new clip, changed the parent clip.
                        return None, True
                    elif isinstance(newobj, RegisteredClip):
                        placed_clip = PlacedClip(
                            tag.object_id,
                            tag.depth,
                            tag.rotation_origin or Point.identity(),
                            tag.transform or Matrix.identity(),
                            tag.projection,
                            tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                            tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                            tag.hsl_shift or HSL(0.0, 0.0, 0.0),
                            tag.blend or 0,
                            None,
                            newobj,
                        )
                        operating_clip.placed_objects.append(placed_clip)

                        for flags, code in tag.triggers.items():
                            if flags & AP2Trigger.ON_LOAD:
                                for bytecode in code:
                                    self.__execute_bytecode(bytecode, placed_clip, prefix=prefix + "      ")
                            else:
                                print("WARNING: Unhandled PLACE_OBJECT trigger with flags {flags}!")

                        # Placed a new clip, changed the parent.
                        return placed_clip, True
                    elif isinstance(newobj, RegisteredDummy):
                        operating_clip.placed_objects.append(
                            PlacedDummy(
                                tag.object_id,
                                tag.depth,
                                tag.rotation_origin or Point.identity(),
                                tag.transform or Matrix.identity(),
                                tag.projection,
                                tag.mult_color or Color(1.0, 1.0, 1.0, 1.0),
                                tag.add_color or Color(0.0, 0.0, 0.0, 0.0),
                                tag.hsl_shift or HSL(0.0, 0.0, 0.0),
                                tag.blend or 0,
                                None,
                                newobj,
                            )
                        )

                        # Didn't place a new clip, changed the parent clip.
                        return None, True
                    else:
                        raise Exception(f"Unrecognized object with Tag ID {tag.source_tag_id}!")

                raise Exception(f"Cannot find a shape or sprite with Tag ID {tag.source_tag_id}!")

        elif isinstance(tag, AP2RemoveObjectTag):
            self.vprint(
                f"{prefix}    Removing Object ID {tag.object_id} from Depth {tag.depth}",
                component="tags",
            )

            if tag.object_id != 0:
                # Remove the identified object by object ID and depth.
                # Remember removed objects so we can stop any clips.
                removed_objects = [
                    obj
                    for obj in operating_clip.placed_objects
                    if obj.object_id == tag.object_id and obj.depth == tag.depth
                ]

                # Get rid of the objects that we're removing from the master list.
                operating_clip.placed_objects = [
                    obj
                    for obj in operating_clip.placed_objects
                    if not (obj.object_id == tag.object_id and obj.depth == tag.depth)
                ]
            else:
                # Remove the last placed object at this depth. The placed objects list isn't
                # ordered so much as apppending to the list means the last placed object at a
                # depth comes last.
                removed_objects = []
                for i in range(len(operating_clip.placed_objects)):
                    real_index = len(operating_clip.placed_objects) - (i + 1)

                    if operating_clip.placed_objects[real_index].depth == tag.depth:
                        removed_objects = operating_clip.placed_objects[real_index : (real_index + 1)]
                        operating_clip.placed_objects = (
                            operating_clip.placed_objects[:real_index]
                            + operating_clip.placed_objects[(real_index + 1) :]
                        )
                        break

            if not removed_objects:
                print(f"WARNING: Couldn't find object to remove by ID {tag.object_id} and depth {tag.depth}!")

            # TODO: Handle ON_UNLOAD triggers for this object. I don't think I've ever seen one
            # on any object so this might be a pedantic request.

            # Didn't place a new clip, changed parent clip.
            return None, True

        elif isinstance(tag, AP2DoActionTag):
            self.vprint(f"{prefix}    Execution action tag.", component="tags")
            self.__execute_bytecode(tag.bytecode, operating_clip, prefix=prefix + "      ")

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

        elif isinstance(tag, AP2DefineMorphShapeTag):
            print("WARNING: Unhandled DEFINE_MORPH_SHAPE tag!")

            self.__registered_objects[tag.id] = RegisteredDummy(
                tag.id,
            )

            # Didn't place a new clip.
            return None, False

        elif isinstance(tag, AP2PlaceCameraTag):
            self.vprint(f"{prefix}    Place camera tag.", component="tags")
            self.__camera = PlacedCamera(
                tag.center,
                tag.focal_length,
            )

            # Didn't place a new clip.
            return None, False

        else:
            raise Exception(f"Failed to process tag: {tag}")

    def __apply_mask(
        self,
        parent_mask: Image.Image,
        transform: Matrix,
        projection: int,
        mask: Mask,
    ) -> Image.Image:
        if mask.rectangle is None:
            # Calculate the new mask rectangle.
            mask.rectangle = affine_composite(
                Image.new(
                    "RGBA",
                    (int(mask.bounds.right), int(mask.bounds.bottom)),
                    (0, 0, 0, 0),
                ),
                Color(0.0, 0.0, 0.0, 0.0),
                Color(1.0, 1.0, 1.0, 1.0),
                HSL(0.0, 0.0, 0.0),
                Matrix.identity().translate(Point(mask.bounds.left, mask.bounds.top)),
                None,
                0,
                Image.new(
                    "RGBA",
                    (int(mask.bounds.width), int(mask.bounds.height)),
                    (255, 0, 0, 255),
                ),
                single_threaded=self.__single_threaded,
                aa_mode=AAMode.NONE,
            )

        # Draw the mask onto a new image.
        if projection == AP2PlaceObjectTag.PROJECTION_AFFINE:
            calculated_mask = affine_composite(
                Image.new("RGBA", (parent_mask.width, parent_mask.height), (0, 0, 0, 0)),
                Color(0.0, 0.0, 0.0, 0.0),
                Color(1.0, 1.0, 1.0, 1.0),
                HSL(0.0, 0.0, 0.0),
                transform,
                None,
                257,
                mask.rectangle,
                single_threaded=self.__single_threaded,
                aa_mode=AAMode.NONE,
            )
        elif projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE:
            if self.__camera is None:
                print("WARNING: Element requests perspective projection but no camera exists!")
                calculated_mask = affine_composite(
                    Image.new("RGBA", (parent_mask.width, parent_mask.height), (0, 0, 0, 0)),
                    Color(0.0, 0.0, 0.0, 0.0),
                    Color(1.0, 1.0, 1.0, 1.0),
                    HSL(0.0, 0.0, 0.0),
                    transform,
                    None,
                    257,
                    mask.rectangle,
                    single_threaded=self.__single_threaded,
                    aa_mode=AAMode.NONE,
                )
            else:
                calculated_mask = perspective_composite(
                    Image.new("RGBA", (parent_mask.width, parent_mask.height), (0, 0, 0, 0)),
                    Color(0.0, 0.0, 0.0, 0.0),
                    Color(1.0, 1.0, 1.0, 1.0),
                    HSL(0.0, 0.0, 0.0),
                    transform,
                    self.__camera.center,
                    self.__camera.focal_length,
                    None,
                    257,
                    mask.rectangle,
                    single_threaded=self.__single_threaded,
                    aa_mode=AAMode.NONE,
                )

        # Composite it onto the current mask.
        return affine_composite(
            parent_mask.copy(),
            Color(0.0, 0.0, 0.0, 0.0),
            Color(1.0, 1.0, 1.0, 1.0),
            HSL(0.0, 0.0, 0.0),
            Matrix.identity(),
            None,
            256,
            calculated_mask,
            single_threaded=self.__single_threaded,
            aa_mode=AAMode.NONE,
        )

    def __render_object(
        self,
        img: Image.Image,
        renderable: PlacedObject,
        parent_transform: Matrix,
        parent_projection: int,
        parent_mask: Image.Image,
        parent_mult_color: Color,
        parent_add_color: Color,
        parent_hsl_shift: HSL,
        parent_blend: int,
        only_depths: Optional[List[int]] = None,
        prefix: str = "",
    ) -> Image.Image:
        if not renderable.visible:
            self.vprint(
                f"{prefix}  Ignoring invisible placed object ID {renderable.object_id} from sprite {renderable.source.tag_id} ({renderable.source.reference}) on Depth {renderable.depth}",
                component="render",
            )
            return img

        self.vprint(
            f"{prefix}  Rendering placed object ID {renderable.object_id} from sprite {renderable.source.tag_id} ({renderable.source.reference}) onto Depth {renderable.depth}",
            component="render",
        )

        # Compute the affine transformation matrix for this object.
        transform = renderable.transform.multiply(parent_transform).translate(
            Point.identity().subtract(renderable.rotation_origin)
        )
        projection = (
            AP2PlaceObjectTag.PROJECTION_PERSPECTIVE
            if parent_projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE
            else renderable.projection
        )

        # Calculate blending and blend color if it is present.
        mult_color = (renderable.mult_color or Color(1.0, 1.0, 1.0, 1.0)).multiply(parent_mult_color)
        add_color = (
            (renderable.add_color or Color(0.0, 0.0, 0.0, 0.0)).multiply(parent_mult_color).add(parent_add_color)
        )
        hsl_shift = (renderable.hsl_shift or HSL(0.0, 0.0, 0.0)).add(parent_hsl_shift)
        blend = renderable.blend or 0
        if parent_blend not in {0, 1, 2} and blend in {0, 1, 2}:
            blend = parent_blend

        if renderable.mask:
            mask = self.__apply_mask(parent_mask, transform, projection, renderable.mask)
        else:
            mask = parent_mask

        if projection == AP2PlaceObjectTag.PROJECTION_AFFINE:
            projection_string = "affine projection"
        elif projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE:
            projection_string = "perspective projection"
        else:
            projection_string = "no projection"

        if blend == 3:
            blend_string = "multiply"
        elif blend == 8:
            blend_string = "addition"
        elif blend == 9 or blend == 70:
            blend_string = "subtraction"
        elif blend == 13:
            blend_string = "overlay"
        else:
            blend_string = "normal"

        # Render individual shapes if this is a sprite.
        if isinstance(renderable, PlacedClip):
            new_only_depths: Optional[List[int]] = None
            if only_depths is not None:
                if renderable.depth not in only_depths:
                    if renderable.depth != -1:
                        # Not on the correct depth plane.
                        return img
                    new_only_depths = only_depths

            self.vprint(
                f"{prefix}    Rendered object uses {projection_string} with transform [{transform}]",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object uses {blend_string} with {mult_color} and {add_color} colors",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object applies a HSL shift of {hsl_shift}",
                component="render",
            )

            # This is a sprite placement reference. Make sure that we render lower depths
            # first, but preserved placed order as well.
            depths = set(obj.depth for obj in renderable.placed_objects)
            for depth in sorted(depths):
                for obj in renderable.placed_objects:
                    if obj.depth != depth:
                        continue
                    img = self.__render_object(
                        img,
                        obj,
                        transform,
                        projection,
                        mask,
                        mult_color,
                        add_color,
                        hsl_shift,
                        blend,
                        only_depths=new_only_depths,
                        prefix=prefix + "  ",
                    )
        elif isinstance(renderable, PlacedShape):
            if only_depths is not None and renderable.depth not in only_depths:
                # Not on the correct depth plane.
                return img

            self.vprint(
                f"{prefix}    Rendered object uses {projection_string} with transform [{transform}]",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object uses {blend_string} with {mult_color} and {add_color} colors",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object applies a HSL shift of {hsl_shift}",
                component="render",
            )

            # This is a shape draw reference.
            shape = renderable.source

            # Now, render out shapes.
            for params in shape.draw_params:
                if not (params.flags & 0x1):
                    # Not instantiable, don't render.
                    return img

                if params.flags & 0x4:
                    # TODO: Need to support blending and UV coordinate colors here.
                    print("WARNING: Unhandled UV coordinate color!")

                texture = None
                rectangle = False
                if params.flags & 0x2:
                    # We need to look up the texture for this.
                    if params.region not in self.textures:
                        raise Exception(f"Cannot find texture reference {params.region}!")
                    texture = self.textures[params.region]

                    if params.flags & 0x8:
                        # TODO: This texture gets further blended somehow? Not sure this is ever used.
                        print(f"WARNING: Unhandled texture blend color {params.blend}!")
                elif params.flags & 0x8:
                    if shape.rectangle is None:
                        # This is a raw rectangle. Its possible that the number of vertex points is
                        # not 4, or that the four points in the vertex_points aren't the four corners
                        # of a rectangle, but let's assume that doesn't happen for now.
                        if len(shape.vertex_points) != 4:
                            print("WARNING: Unsupported non-rectangle shape!")
                        if params.blend is None:
                            raise Exception("Logic error, rectangle without a blend color!")

                        x_points = set(p.x for p in shape.vertex_points)
                        y_points = set(p.y for p in shape.vertex_points)
                        left = min(x_points)
                        right = max(x_points)
                        top = min(y_points)
                        bottom = max(y_points)

                        # Make sure that the four corners are aligned.
                        bad = False
                        for point in x_points:
                            if point not in {left, right}:
                                bad = True
                                break
                        for point in y_points:
                            if point not in {top, bottom}:
                                bad = True
                                break
                        if bad:
                            print("WARNING: Unsupported non-rectangle shape!")

                        shape.rectangle = Image.new(
                            "RGBA",
                            (int(right - left), int(bottom - top)),
                            (params.blend.as_tuple()),
                        )
                    texture = shape.rectangle
                    rectangle = True

                if texture is not None:
                    if projection == AP2PlaceObjectTag.PROJECTION_AFFINE:
                        if self.__enable_aa:
                            aamode = AAMode.UNSCALED_SSAA_ONLY if rectangle else AAMode.SSAA_OR_BILINEAR
                        else:
                            aamode = AAMode.NONE

                        img = affine_composite(
                            img,
                            add_color,
                            mult_color,
                            hsl_shift,
                            transform,
                            mask,
                            blend,
                            texture,
                            single_threaded=self.__single_threaded,
                            aa_mode=aamode,
                        )
                    elif projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE:
                        if self.__camera is None:
                            if self.__enable_aa:
                                aamode = AAMode.UNSCALED_SSAA_ONLY if rectangle else AAMode.SSAA_OR_BILINEAR
                            else:
                                aamode = AAMode.NONE

                            print("WARNING: Element requests perspective projection but no camera exists!")
                            img = affine_composite(
                                img,
                                add_color,
                                mult_color,
                                hsl_shift,
                                transform,
                                mask,
                                blend,
                                texture,
                                single_threaded=self.__single_threaded,
                                aa_mode=aamode,
                            )
                        else:
                            if self.__enable_aa:
                                aamode = AAMode.UNSCALED_SSAA_ONLY if rectangle else AAMode.SSAA_ONLY
                            else:
                                aamode = AAMode.NONE

                            img = perspective_composite(
                                img,
                                add_color,
                                mult_color,
                                hsl_shift,
                                transform,
                                self.__camera.center,
                                self.__camera.focal_length,
                                mask,
                                blend,
                                texture,
                                single_threaded=self.__single_threaded,
                                aa_mode=aamode,
                            )

        elif isinstance(renderable, PlacedImage):
            if only_depths is not None and renderable.depth not in only_depths:
                # Not on the correct depth plane.
                return img

            self.vprint(
                f"{prefix}    Rendered object uses {projection_string} with transform [{transform}]",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object uses {blend_string} with {mult_color} and {add_color} colors",
                component="render",
            )
            self.vprint(
                f"{prefix}    Rendered object applies a HSL shift of {hsl_shift}",
                component="render",
            )

            # This is a shape draw reference.
            texture = self.textures[renderable.source.reference]
            if projection == AP2PlaceObjectTag.PROJECTION_AFFINE:
                img = affine_composite(
                    img,
                    add_color,
                    mult_color,
                    hsl_shift,
                    transform,
                    mask,
                    blend,
                    texture,
                    single_threaded=self.__single_threaded,
                    aa_mode=AAMode.SSAA_OR_BILINEAR if self.__enable_aa else AAMode.NONE,
                )
            elif projection == AP2PlaceObjectTag.PROJECTION_PERSPECTIVE:
                if self.__camera is None:
                    print("WARNING: Element requests perspective projection but no camera exists!")
                    img = affine_composite(
                        img,
                        add_color,
                        mult_color,
                        hsl_shift,
                        transform,
                        mask,
                        blend,
                        texture,
                        single_threaded=self.__single_threaded,
                        aa_mode=AAMode.SSAA_OR_BILINEAR if self.__enable_aa else AAMode.NONE,
                    )
                else:
                    img = perspective_composite(
                        img,
                        add_color,
                        mult_color,
                        hsl_shift,
                        transform,
                        self.__camera.center,
                        self.__camera.focal_length,
                        mask,
                        blend,
                        texture,
                        single_threaded=self.__single_threaded,
                        aa_mode=AAMode.SSAA_ONLY if self.__enable_aa else AAMode.NONE,
                    )
        elif isinstance(renderable, PlacedDummy):
            # Nothing to do!
            pass
        else:
            raise Exception(f"Unknown placed object type to render {renderable}!")

        return img

    def __is_dirty(self, clip: PlacedClip) -> bool:
        # If we are dirty ourselves, then the clip is definitely dirty.
        if clip.requested_frame is not None:
            return True

        # If one of our children is dirty, then we are dirty.
        for child in clip.placed_objects:
            if isinstance(child, PlacedClip):
                if self.__is_dirty(child):
                    return True

        # None of our children (or their children, etc...) or ourselves is dirty.
        return False

    def __process_tags(self, clip: PlacedClip, only_dirty: bool, prefix: str = "  ") -> bool:
        self.vprint(
            f"{prefix}Handling {'dirty updates on ' if only_dirty else ''}placed clip {clip.object_id} at depth {clip.depth}",
            component="tags",
        )

        # Track whether anything in ourselves or our children changes during this processing.
        changed = False

        # Make sure to set the requested frame if it isn't set by an external force.
        if clip.requested_frame is None:
            if not clip.playing or only_dirty or (clip.finished and clip is self.__root):
                # We aren't playing this clip because its either paused or finished,
                # or it isn't dirty and we're doing dirty updates only. So, we don't
                # need to advance to any frame.
                clip.requested_frame = clip.frame
            elif clip.finished:
                # Rewind the clip to the beginning, loop it.
                clip.rewind()
                clip.requested_frame = clip.frame + 1
            else:
                # We need to do as many things as we need to get to the next frame.
                clip.requested_frame = clip.frame + 1

        while True:
            # First, see if we need to rewind the clip if we were requested to go backwards
            # during some bytecode update in this loop.
            if clip.frame > clip.requested_frame:
                # Rewind this clip to the beginning so we can replay until the requested frame.
                if clip is self.__root:
                    print("WARNING: Root clip was rewound, its possible this animation plays forever!")
                clip.rewind()

            self.vprint(
                f"{prefix}  Processing frame {clip.frame} on our way to frame {clip.requested_frame}",
                component="tags",
            )

            # Clips that are part of our own placed objects which we should handle.
            child_clips = [c for c in clip.placed_objects if isinstance(c, PlacedClip)]

            # Execute each tag in the frame if we need to move forward to a new frame.
            if clip.frame != clip.requested_frame:
                frame = clip.source.frames[clip.frame]
                orphans: List[Tag] = []
                played_tags: Set[int] = set()

                # See if we have any orphans that need to be placed before this frame will work.
                for unplayed_tag in clip.unplayed_tags:
                    if unplayed_tag < frame.start_tag_offset:
                        self.vprint(
                            f"{prefix}  Including orphaned tag {unplayed_tag} in frame evaluation",
                            component="tags",
                        )
                        played_tags.add(unplayed_tag)
                        orphans.append(clip.source.tags[unplayed_tag])

                for tagno in range(frame.start_tag_offset, frame.start_tag_offset + frame.num_tags):
                    played_tags.add(tagno)

                # Check these off our future todo list.
                clip.unplayed_tags = [t for t in clip.unplayed_tags if t not in played_tags]

                # Grab the normal list of tags, add to the orphans.
                tags = orphans + clip.source.tags[frame.start_tag_offset : (frame.start_tag_offset + frame.num_tags)]
                for tagno, tag in enumerate(tags):
                    # Perform the action of this tag.
                    self.vprint(
                        f"{prefix}  Sprite Tag ID: {clip.source.tag_id} ({clip.source.reference}), Current Tag: {frame.start_tag_offset + tagno}, Num Tags: {frame.num_tags}",
                        component="tags",
                    )
                    new_clip, clip_changed = self.__place(tag, clip, prefix=prefix)
                    changed = changed or clip_changed

                    # If we create a new movie clip, process it as well for this frame.
                    if new_clip:
                        # These are never dirty-only updates as they're fresh-placed.
                        changed = self.__process_tags(new_clip, False, prefix=prefix + "  ") or changed

                # Now, advance the frame for this clip since we processed the frame.
                clip.advance()

            # Now, handle each of the existing clips.
            for child in child_clips:
                changed = self.__process_tags(child, only_dirty, prefix=prefix + "  ") or changed

            # See if we're done with this clip.
            if clip.frame == clip.requested_frame:
                clip.requested_frame = None
                break

        self.vprint(
            f"{prefix}Finished handling {'dirty updates on ' if only_dirty else ''}placed clip {clip.object_id} at depth {clip.depth}",
            component="tags",
        )

        # Return if anything was modified.
        return changed

    def __handle_imports(
        self, swf: SWF
    ) -> Dict[int, Union[RegisteredShape, RegisteredClip, RegisteredImage, RegisteredDummy]]:
        external_objects: Dict[
            int,
            Union[RegisteredShape, RegisteredClip, RegisteredImage, RegisteredDummy],
        ] = {}

        # Go through, recursively resolve imports for all SWF files.
        for tag_id, imp in swf.imported_tags.items():
            for _name, other in self.swfs.items():
                if other.exported_name == imp.swf:
                    # This SWF should have the tag reference.
                    if imp.tag not in other.exported_tags:
                        print(
                            f"WARNING: {swf.exported_name} imports {imp} but that import is not in {other.exported_name}!"
                        )
                        external_objects[tag_id] = RegisteredDummy(tag_id)
                        break
                    else:
                        external_objects[tag_id] = self.__find_import(other, other.exported_tags[imp.tag])
                        break
            else:
                # Only display a warning if we don't have our own stub implementation of this SWF.
                if repr(imp) not in self.__stubbed_swfs:
                    print(f"WARNING: {swf.exported_name} imports {imp} but that SWF is not in our library!")
                external_objects[tag_id] = RegisteredDummy(tag_id)

        # Fix up tag IDs to point at our local definition of them.
        for tid in external_objects:
            external_objects[tid].tag_id = tid

        # Return our newly populated registered object table containing all imports!
        return external_objects

    def __find_import(
        self, swf: SWF, tag_id: int
    ) -> Union[RegisteredShape, RegisteredClip, RegisteredImage, RegisteredDummy]:
        if tag_id in swf.imported_tags:
            external_objects = self.__handle_imports(swf)
            if tag_id not in external_objects:
                raise Exception(
                    f"Logic error, tag ID {tag_id} is an export for {swf.exported_name} but we didn't populate it!"
                )
            return external_objects[tag_id]

        # We need to do a basic placement to find the registered object so we can return it.
        root_clip = RegisteredClip(
            None,
            swf.frames,
            swf.tags,
            swf.labels,
        )

        tag = self.__find_tag(root_clip, tag_id)
        if tag is None:
            print(f"WARNING: {swf.exported_name} exports {swf.imported_tags[tag_id]} but does not manifest an object!")
            return RegisteredDummy(tag_id)
        return tag

    def __find_tag(
        self, clip: RegisteredClip, tag_id: int
    ) -> Optional[Union[RegisteredShape, RegisteredClip, RegisteredImage, RegisteredDummy]]:
        # Fake-execute this clip to find the tag we need to manifest.
        for frame in clip.frames:
            tags = clip.tags[frame.start_tag_offset : (frame.start_tag_offset + frame.num_tags)]

            for tag in tags:
                # Attempt to place any tags.
                if isinstance(tag, AP2ShapeTag):
                    if tag.id == tag_id:
                        # We need to be able to see this shape to place it.
                        if tag.reference not in self.shapes:
                            raise Exception(f"Cannot find shape reference {tag.reference}!")

                        # This matched, so this is the import.
                        return RegisteredShape(
                            tag.id,
                            tag.reference,
                            self.shapes[tag.reference].vertex_points,
                            self.shapes[tag.reference].tex_points,
                            self.shapes[tag.reference].tex_colors,
                            self.shapes[tag.reference].draw_params,
                        )

                elif isinstance(tag, AP2ImageTag):
                    if tag.id == tag_id:
                        # We need to be able to see this shape to place it.
                        if tag.reference not in self.textures:
                            raise Exception(f"Cannot find texture reference {tag.reference}!")

                        # This matched, so this is the import.
                        return RegisteredImage(
                            tag.id,
                            tag.reference,
                        )

                elif isinstance(tag, AP2DefineSpriteTag):
                    new_clip = RegisteredClip(tag.id, tag.frames, tag.tags, tag.labels)

                    if tag.id == tag_id:
                        # This matched, so it is the clip that we want to export.
                        return new_clip

                    # Recursively look in this as well.
                    maybe_tag = self.__find_tag(new_clip, tag_id)
                    if maybe_tag is not None:
                        return maybe_tag

        # We didn't find the tag we were after.
        return None

    def __render(
        self,
        swf: SWF,
        only_depths: Optional[List[int]],
        only_frames: Optional[List[int]],
        movie_transform: Matrix,
        background_image: Optional[List[Image.Image]],
        overridden_width: Optional[float],
        overridden_height: Optional[float],
    ) -> Generator[Image.Image, None, None]:
        # First, let's attempt to resolve imports.
        self.__registered_objects = self.__handle_imports(swf)

        # Initialize overall frame advancement stuff.
        last_rendered_frame: Optional[Image.Image] = None
        frameno: int = 0

        # Calculate actual size based on given movie transform.
        actual_width = overridden_width or swf.location.width
        actual_height = overridden_height or swf.location.height
        resized_width, resized_height, _ = movie_transform.multiply_point(Point(actual_width, actual_height)).as_tuple()

        if round(swf.location.top, 2) != 0.0 or round(swf.location.left, 2) != 0.0:
            # TODO: If the location top/left is nonzero, we need move the root transform
            # so that the correct viewport is rendered.
            print("WARNING: Root clip requested to play not in top-left corner!")

        # Create a root clip for the movie to play.
        root_clip = PlacedClip(
            -1,
            -1,
            Point.identity(),
            Matrix.identity(),
            AP2PlaceObjectTag.PROJECTION_AFFINE,
            Color(1.0, 1.0, 1.0, 1.0),
            Color(0.0, 0.0, 0.0, 0.0),
            HSL(0.0, 0.0, 0.0),
            0,
            None,
            RegisteredClip(
                None,
                swf.frames,
                swf.tags,
                swf.labels,
            ),
        )
        root_clip._width = int(actual_width)
        root_clip._height = int(actual_height)
        last_width = actual_width
        last_height = actual_height
        self.__root = root_clip

        # If we have a background image, add it to the root clip.
        background_object = RegisteredImage(-1, "INVALID_REFERENCE_NAME")
        background_container: Optional[PlacedImage] = None
        background_frames = 0

        if background_image:
            # Stretch the images to make sure they fit the entire frame.
            imgwidth = background_image[0].width
            imgheight = background_image[0].height
            background_matrix = Matrix.affine(
                a=actual_width / imgwidth,
                b=0,
                c=0,
                d=actual_height / imgheight,
                tx=0,
                ty=0,
            )
            background_frames = len(background_image)

            # Register the background images with the texture library.
            for background_frame in range(background_frames):
                if (
                    background_image[background_frame].width != imgwidth
                    or background_image[background_frame].height != imgheight
                ):
                    raise Exception(
                        f"Frame {background_frame + 1} of background image sequence has different dimensions than others!"
                    )
                name = f"{swf.exported_name}_inserted_background_{background_frame}"
                self.textures[name] = background_image[background_frame].convert("RGBA")

            # Place an instance of this background on the root clip.
            background_container = PlacedImage(
                -1,
                -1,
                Point.identity(),
                background_matrix,
                AP2PlaceObjectTag.PROJECTION_AFFINE,
                Color(1.0, 1.0, 1.0, 1.0),
                Color(0.0, 0.0, 0.0, 0.0),
                HSL(0.0, 0.0, 0.0),
                0,
                None,
                background_object,
            )
            root_clip.placed_objects.append(background_container)

        # Create the root mask for where to draw the root clip.
        movie_mask = Image.new("RGBA", (resized_width, resized_height), color=(255, 0, 0, 255))

        # These could possibly be overwritten from an external source of we wanted.
        actual_mult_color = Color(1.0, 1.0, 1.0, 1.0)
        actual_add_color = Color(0.0, 0.0, 0.0, 0.0)
        actual_hsl_shift = HSL(0.0, 0.0, 0.0)
        actual_blend = 0

        max_frame: Optional[int] = None
        if only_frames:
            max_frame = max(only_frames)

        # Now play the frames of the root clip.
        try:
            while root_clip.playing and not root_clip.finished:
                # Create a new image to render into.
                self.vprint(
                    f"Rendering frame {frameno + 1}/{len(root_clip.source.frames)}",
                    component="core",
                )

                # Go through all registered clips, place all needed tags.
                changed = self.__process_tags(root_clip, False)
                while self.__is_dirty(root_clip):
                    changed = self.__process_tags(root_clip, True) or changed

                # Calculate a new background frame if needed.
                if background_container is not None and background_frames > 0:
                    # First, make sure we're still placed in the root clip, which can be undone
                    # if it is rewound.
                    for obj in root_clip.placed_objects:
                        if obj is background_container:
                            break
                    else:
                        self.vprint("Root clip was rewound, re-placing background image on clip.")
                        root_clip.placed_objects.append(background_container)

                    # Now, update the background image if we need to.
                    background_frame = frameno % background_frames
                    name = f"{swf.exported_name}_inserted_background_{background_frame}"
                    if background_object.reference != name:
                        background_object.reference = name
                        changed = True

                # Adjust camera based on the movie's scaling.
                if self.__camera is not None and not self.__camera.adjusted:
                    self.__camera.center = movie_transform.multiply_point(self.__camera.center)
                    self.__camera.adjusted = True

                # If we're only rendering some frames, don't bother to do the draw operations
                # if we aren't going to return the frame.
                if only_frames and (frameno + 1) not in only_frames:
                    self.vprint(
                        f"Skipped rendering frame {frameno + 1}/{len(root_clip.source.frames)}",
                        component="core",
                    )
                    last_rendered_frame = None
                    frameno += 1
                    continue

                if changed or last_rendered_frame is None:
                    if last_width != root_clip._width or last_height != root_clip._height:
                        last_width = root_clip._width
                        last_height = root_clip._height
                        if root_clip._width > actual_width or root_clip._height > actual_height:
                            print(
                                f"WARNING: Root clip requested to resize to {last_width}x{last_height} which overflows root canvas!"
                            )

                    # Now, render out the placed objects.
                    color = swf.color or Color(0.0, 0.0, 0.0, 0.0)
                    curimage = Image.new("RGBA", (resized_width, resized_height), color=color.as_tuple())
                    curimage = self.__render_object(
                        curimage,
                        root_clip,
                        movie_transform,
                        AP2PlaceObjectTag.PROJECTION_AFFINE,
                        movie_mask,
                        actual_mult_color,
                        actual_add_color,
                        actual_hsl_shift,
                        actual_blend,
                        only_depths=only_depths,
                    )
                else:
                    # Nothing changed, make a copy of the previous render.
                    self.vprint("  Using previous frame render", component="core")
                    curimage = last_rendered_frame.copy()

                # Return that frame, advance our bookkeeping.
                self.vprint(
                    f"Finished rendering frame {frameno + 1}/{len(root_clip.source.frames)}",
                    component="core",
                )
                last_rendered_frame = curimage
                frameno += 1
                yield curimage

                # See if we should bail because we passed the last requested frame.
                if max_frame is not None and frameno == max_frame:
                    break
        except KeyboardInterrupt:
            # Allow ctrl-c to end early and render a partial animation.
            print(
                f"WARNING: Interrupted early, will render only {frameno}/{len(root_clip.source.frames)} frames of animation!"
            )

        # Clean up
        self.__root = None
