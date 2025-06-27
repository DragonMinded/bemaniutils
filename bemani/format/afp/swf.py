import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple
from typing_extensions import Final

from .decompile import ByteCode
from .types import (
    Matrix,
    Color,
    HSL,
    Point,
    Rectangle,
    AP2Action,
    AP2Tag,
    AP2Trigger,
    DefineFunction2Action,
    InitRegisterAction,
    StoreRegisterAction,
    JumpAction,
    WithAction,
    PushAction,
    AddNumVariableAction,
    AddNumRegisterAction,
    IfAction,
    GetURL2Action,
    StartDragAction,
    GotoFrame2Action,
    Register,
    StringConstant,
    NULL,
    UNDEFINED,
    THIS,
    ROOT,
    PARENT,
    CLIP,
    GLOBAL,
)
from .util import TrackedCoverage, VerboseOutput


class NamedTagReference:
    def __init__(self, swf_name: str, tag_name: str) -> None:
        self.swf = swf_name
        self.tag = tag_name

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "swf": self.swf,
            "tag": self.tag,
        }

    def __repr__(self) -> str:
        return f"{self.swf}.{self.tag}"


class TagPointer:
    # A pointer to a tag in this SWF by Tag ID and containing an optional initialization bytecode
    # to run for this tag when it is placed/executed.
    def __init__(self, id: Optional[int], init_bytecode: Optional[ByteCode] = None) -> None:
        self.id = id
        self.init_bytecode = init_bytecode

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "id": self.id,
            "init_bytecode": self.init_bytecode.as_dict(*args, **kwargs) if self.init_bytecode else None,
        }


class Frame:
    def __init__(self, start_tag_offset: int, num_tags: int, imported_tags: List[TagPointer] = []) -> None:
        # The start tag offset into the tag list where we should begin placing/executing tags for this frame.
        self.start_tag_offset = start_tag_offset

        # The number of tags to pace/execute during this frame.
        self.num_tags = num_tags

        # A list of any imported tags that are to be placed this frame.
        self.imported_tags = imported_tags or []

        # The current tag we're processing, if any.
        self.current_tag = 0

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "start_tag_offset": self.start_tag_offset,
            "num_tags": self.num_tags,
            "imported_tags": [i.as_dict(*args, **kwargs) for i in self.imported_tags],
        }


class Tag:
    # Any tag that can appear in the SWF. All tags will subclass from this for their behavior.
    def __init__(self, id: Optional[int]) -> None:
        self.id = id

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.__class__.__name__,
        }


class AP2ShapeTag(Tag):
    id: int

    def __init__(self, id: int, reference: str) -> None:
        super().__init__(id)

        # The reference is the name of a shape (geo structure) that defines this primitive or sprite.
        self.reference = reference

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "reference": self.reference,
        }


class AP2ImageTag(Tag):
    id: int

    def __init__(self, id: int, reference: str) -> None:
        super().__init__(id)

        # The reference is the name of a texture that will be displayed directly.
        self.reference = reference

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "reference": self.reference,
        }


class AP2DefineFontTag(Tag):
    id: int

    def __init__(
        self,
        id: int,
        fontname: str,
        xml_prefix: str,
        heights: List[int],
        text_indexes: List[int],
    ) -> None:
        super().__init__(id)

        # The font name is just the pretty name of the font.
        self.fontname = fontname

        # The XML prefix is the reference into any font XML to look up individual
        # glyphs for a font in a texture map.
        self.xml_prefix = xml_prefix

        # The list of heights are concatenated with the above XML prefix and the
        # unicode glyph you want to display, to find the corresponding location
        # in the texture map.
        self.heights = heights

        # The list of text indexes are concatenated with the above prefix and height
        # as a hex value to grab the actual character location in the font. It can
        # be interpreted as an ascii value using chr() most of the time.
        self.text_indexes = text_indexes

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "fontname": self.fontname,
            "xml_prefix": self.xml_prefix,
            "heights": self.heights,
            "text_indexes": self.text_indexes,
        }


class AP2TextChar:
    def __init__(self, font_text_index: int, width: float) -> None:
        # Given the parent line's font, this is an offset into the font's text indexes.
        # This allows you to look up what actual character is being displayed at this
        # location.
        self.font_text_index = font_text_index

        # This is the width of the character. Don't know why this isn't looked up in
        # the font?
        self.width = width

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "font_text_index": self.font_text_index,
            "width": self.width,
        }


class AP2TextLine:
    def __init__(
        self,
        font_tag: Optional[int],
        height: int,
        xpos: float,
        ypos: float,
        entries: List[AP2TextChar],
    ) -> None:
        self.font_tag = font_tag
        self.font_height = height
        self.xpos = xpos
        self.ypos = ypos
        self.entries = entries

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "font_tag": self.font_tag,
            "font_height": self.font_height,
            "xpos": self.xpos,
            "ypos": self.ypos,
            "entries": [e.as_dict(*args, **kwargs) for e in self.entries],
        }


class AP2DefineMorphShapeTag(Tag):
    id: int

    def __init__(self, id: int) -> None:
        # TODO: I need to figure out what morph shapes actually DO, and take the
        # values that I parsed out store them here...
        super().__init__(id)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
        }


class AP2DefineButtonTag(Tag):
    id: int

    def __init__(self, id: int) -> None:
        # TODO: I need to figure out what buttons actually DO, and take the
        # values that I parsed out store them here...
        super().__init__(id)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
        }


class AP2PlaceCameraTag(Tag):
    def __init__(self, camera_id: int, center: Optional[Point], focal_length: float) -> None:
        super().__init__(None)

        # This is not actually Tag ID, just a way to refer to the camera. Confusing, I know.
        # Probably this happened when they hacked 3D into the format.
        self.camera_id = camera_id
        self.center = center
        self.focal_length = focal_length

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "camera_id": self.camera_id,
            "center": self.center.as_dict(*args, **kwargs) if self.center is not None else None,
            "focal_length": self.focal_length,
        }


class AP2DefineTextTag(Tag):
    id: int

    def __init__(self, id: int, lines: List[AP2TextLine]) -> None:
        super().__init__(id)

        self.lines = lines

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "lines": [line.as_dict(*args, **kwargs) for line in self.lines],
        }


class AP2DoActionTag(Tag):
    def __init__(self, bytecode: ByteCode) -> None:
        # Do Action Tags are not identified by any tag ID.
        super().__init__(None)

        # The bytecode is the actual execution that we expect to perform once
        # this tag is placed/executed.
        self.bytecode = bytecode

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "bytecode": self.bytecode.as_dict(*args, **kwargs),
        }


class AP2PlaceObjectTag(Tag):
    PROJECTION_NONE: Final[int] = 0
    PROJECTION_AFFINE: Final[int] = 1
    PROJECTION_PERSPECTIVE: Final[int] = 2

    def __init__(
        self,
        object_id: int,
        depth: int,
        src_tag_id: Optional[int],
        movie_name: Optional[str],
        label_name: Optional[int],
        blend: Optional[int],
        update: bool,
        transform: Optional[Matrix],
        rotation_origin: Optional[Point],
        projection: int,
        mult_color: Optional[Color],
        add_color: Optional[Color],
        hsl_shift: Optional[HSL],
        triggers: Dict[int, List[ByteCode]],
        unrecognized_options: bool,
    ) -> None:
        # Place Object Tags are not identified by any tag ID.
        super().__init__(None)

        # The object ID that we should associate with this object, for removal
        # and presumably update and other uses. Not the same as Tag ID.
        self.object_id = object_id

        # The depth (level) that we should remove objects from.
        self.depth = depth

        # The source tag ID (should point at an AP2ShapeTag or AP2SpriteTag by ID) if present.
        self.source_tag_id = src_tag_id

        # The name of the object this should be placed in, if present.
        self.movie_name = movie_name

        # A name index, possibly referred to later by a Name Reference tag section.
        self.label_name = label_name

        # The blend mode of this object, if present.
        self.blend = blend

        # Whether this is an object update (True) or a new object (False).
        self.update = update

        # Whether there is a transform matrix to apply before placing/updating this object or not.
        self.transform = transform
        self.rotation_origin = rotation_origin

        # What projection system to use when displaying this object.
        self.projection = projection

        # If there is a color to blend with the sprite/shape when drawing.
        self.mult_color = mult_color

        # If there is a color to add with the sprite/shape when drawing.
        self.add_color = add_color

        # If there is a hue/saturation/lightness shift effect when drawing.
        self.hsl_shift = hsl_shift

        # List of triggers for this object, and their respective bytecodes to execute when the trigger
        # fires.
        self.triggers = triggers

        # Whether this tag has unrecognized options applied to it.
        self.unrecognized_options = unrecognized_options

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "object_id": self.object_id,
            "depth": self.depth,
            "source_tag_id": self.source_tag_id,
            "movie_name": self.movie_name,
            "label_name": self.label_name,
            "blend": self.blend,
            "update": self.update,
            "transform": self.transform.as_dict(*args, **kwargs) if self.transform is not None else None,
            "rotation_origin": (
                self.rotation_origin.as_dict(*args, **kwargs) if self.rotation_origin is not None else None
            ),
            "projection": (
                "none"
                if self.projection == self.PROJECTION_NONE
                else ("affine" if self.projection == self.PROJECTION_AFFINE else "perspective")
            ),
            "mult_color": self.mult_color.as_dict(*args, **kwargs) if self.mult_color is not None else None,
            "add_color": self.add_color.as_dict(*args, **kwargs) if self.add_color is not None else None,
            "hsl_shift": self.hsl_shift.as_dict(*args, **kwargs) if self.hsl_shift else None,
            "triggers": {i: [b.as_dict(*args, **kwargs) for b in t] for (i, t) in self.triggers.items()},
        }

    def __repr__(self) -> str:
        return f"AP2PlaceObjectTag(object_id={self.object_id}, depth={self.depth})"


class AP2RemoveObjectTag(Tag):
    def __init__(self, object_id: int, depth: int) -> None:
        # Remove Object Tags are not identified by any tag ID.
        super().__init__(None)

        # The object ID that we should remove, or 0 if we should only remove by depth.
        self.object_id = object_id

        # The depth (level) that we should remove objects from.
        self.depth = depth

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "object_id": self.object_id,
            "depth": self.depth,
        }


class AP2DefineSpriteTag(Tag):
    id: int

    def __init__(self, id: int, tags: List[Tag], frames: List[Frame], labels: Dict[str, int]) -> None:
        super().__init__(id)

        # The list of tags that this sprite consists of. Sprites are, much like vanilla
        # SWFs, basically entire SWF movies embedded in them.
        self.tags = tags

        # The list of frames this SWF occupies.
        self.frames = frames

        # A list of strings pointing at frame numbers as used in bytecode.
        self.labels = labels

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "tags": [t.as_dict(*args, **kwargs) for t in self.tags],
            "frames": [f.as_dict(*args, **kwargs) for f in self.frames],
            "labels": self.labels,
        }


class AP2DefineEditTextTag(Tag):
    id: int

    def __init__(
        self,
        id: int,
        font_tag_id: int,
        font_height: int,
        rect: Rectangle,
        color: Color,
        default_text: Optional[str] = None,
    ) -> None:
        super().__init__(id)

        # The ID of the Ap2DefineFontTag that we want to use for the text.
        self.font_tag_id = font_tag_id

        # The height we want to select for the text (must be one of the heights in
        # the referenced Ap2DefineFontTag tag).
        self.font_height = font_height

        # The bounding rectangle for this exit text control.
        self.rect = rect

        # The text color we want to use when displaying the text.
        self.color = color

        # The default text that should be present in the control when it is initially placed/executed.
        self.default_text = default_text

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "font_tag_id": self.font_tag_id,
            "font_height": self.font_height,
            "rect": self.rect.as_dict(*args, **kwargs),
            "color": self.color.as_dict(*args, **kwargs),
            "default_text": self.default_text,
        }


class SWF(VerboseOutput, TrackedCoverage):
    def __init__(
        self,
        name: str,
        data: bytes,
        descramble_info: bytes = b"",
    ) -> None:
        # First, init the coverage engine.
        super().__init__()

        # Name of this SWF, according to the container it was extracted from.
        self.name: str = name

        # Name of this SWF, as referenced by other SWFs that require imports from it.
        self.exported_name: str = ""

        # Full, unparsed data for this SWF, as well as the descrambling headers.
        self.data: bytes = data
        self.descramble_info: bytes = descramble_info

        # Data version of this SWF.
        self.data_version: int = 0

        # Container version of this SWF.
        self.container_version: int = 0

        # The requested frames per second this SWF plays at.
        self.fps: float = 0.0

        # Background color of this SWF movie.
        self.color: Optional[Color] = None

        # Location of this SWF in screen space.
        self.location: Rectangle = Rectangle.Empty()

        # Exported tags, indexed by their name and pointing to the Tag ID that name identifies.
        self.exported_tags: Dict[str, int] = {}

        # Imported tags, indexed by their Tag ID, and pointing at the SWF asset and exported tag name.
        self.imported_tags: Dict[int, NamedTagReference] = {}

        # Actual tags for this SWF, ordered by their appearance in the file.
        self.tags: List[Tag] = []

        # Frames of this SWF, with the tag offset in the above list and number of tags to
        # "execute" that frame.
        self.frames: List[Frame] = []

        # Reference LUT for mapping object reference IDs and frame numbers to names a used in bytecode.
        self.labels: Dict[str, int] = {}

        # SWF string table. This is used for faster lookup of strings as well as
        # tracking which strings in the table have been parsed correctly.
        self.__strings: Dict[int, Tuple[str, bool]] = {}

        # Whether this is parsed or not.
        self.parsed = False

    def print_coverage(self, *args: Any, **kwargs: Any) -> None:
        # First print uncovered bytes
        super().print_coverage(*args, **kwargs)

        # Now, print uncovered strings
        for offset, (string, covered) in self.__strings.items():
            if covered:
                continue

            print(f"Uncovered string: {hex(offset)} - {string}", file=sys.stderr)

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "name": self.name,
            "exported_name": self.exported_name,
            "data_version": self.data_version,
            "container_version": self.container_version,
            "fps": self.fps,
            "color": self.color.as_dict(*args, **kwargs) if self.color is not None else None,
            "location": self.location.as_dict(*args, **kwargs),
            "exported_tags": self.exported_tags,
            "imported_tags": {i: self.imported_tags[i].as_dict(*args, **kwargs) for i in self.imported_tags},
            "tags": [t.as_dict(*args, **kwargs) for t in self.tags],
            "frames": [f.as_dict(*args, **kwargs) for f in self.frames],
            "labels": self.labels,
        }

    def __parse_bytecode(
        self,
        bytecode_name: Optional[str],
        datachunk: bytes,
        string_offsets: List[int] = [],
        prefix: str = "",
    ) -> ByteCode:
        # First, we need to check if this is a SWF-style bytecode or an AP2 bytecode.
        ap2_sentinel = struct.unpack("<B", datachunk[0:1])[0]

        if ap2_sentinel != 0xFF:
            raise Exception("Encountered SWF-style bytecode but we don't support this!")

        # Now, we need to grab the flags byte which tells us how to find the actual bytecode.
        flags = struct.unpack("<B", datachunk[1:2])[0]

        if flags & 0x1:
            # There is an offset pointer telling us where the data is as well as string offset tables.
            string_offsets_count = struct.unpack("<H", datachunk[2:4])[0]

            # We don't want to overwrite the global ones with our current ones.
            if not string_offsets:
                string_offsets = list(
                    struct.unpack(
                        "<" + ("H" * string_offsets_count),
                        datachunk[4 : (4 + (2 * string_offsets_count))],
                    )
                )

            offset_ptr = (string_offsets_count + 2) * 2
        else:
            # The data directly follows, no pointer.
            offset_ptr = 2

        self.vprint(
            f"{prefix}    Flags: {hex(flags)}, ByteCode Actual Offset: {hex(offset_ptr)}",
            component="bytecode",
        )

        # Actually parse out the opcodes:
        actions: List[AP2Action] = []
        while offset_ptr < len(datachunk):
            # We leave it up to the individual opcode handlers to increment the offset pointer. By default, parameterless
            # opcodes increase by one. Everything else increases by its own amount. Opcode parsing here is done in big-endian
            # as the game code seems to always parse big-endian values.
            opcode = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
            action_name = AP2Action.action_to_name(opcode)
            lineno = offset_ptr

            if opcode in AP2Action.actions_without_params():
                # Simple opcodes need no parsing, they can go directly onto the stack.
                self.vprint(f"{prefix}      {lineno}: {action_name}", component="bytecode")
                offset_ptr += 1
                actions.append(AP2Action(lineno, opcode))
            elif opcode == AP2Action.DEFINE_FUNCTION2:
                (
                    function_flags,
                    funcname_offset,
                    bytecode_offset,
                    _,
                    bytecode_count,
                ) = struct.unpack(
                    ">HHHBH",
                    datachunk[(offset_ptr + 1) : (offset_ptr + 10)],
                )

                if funcname_offset == 0:
                    funcname = None
                else:
                    funcname = self.__get_string(funcname_offset)
                offset_ptr += 10 + (3 * bytecode_offset)

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Flags: {hex(function_flags)}, Name: {funcname or '<anonymous function>'}, ByteCode Offset: {hex(bytecode_offset)}, ByteCode Length: {hex(bytecode_count)}",
                    component="bytecode",
                )

                # No name for this chunk, it will only ever be decompiled and printed in the context of another
                # chunk.
                function = self.__parse_bytecode(
                    None,
                    datachunk[offset_ptr : (offset_ptr + bytecode_count)],
                    string_offsets=string_offsets,
                    prefix=prefix + "    ",
                )

                self.vprint(f"{prefix}      END_{action_name}", component="bytecode")

                actions.append(DefineFunction2Action(lineno, funcname, function_flags, function))
                offset_ptr += bytecode_count
            elif opcode == AP2Action.PUSH:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}", component="bytecode")

                objects: List[Any] = []

                while obj_count > 0:
                    obj_to_create = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                    offset_ptr += 1

                    if obj_to_create == 0x0:
                        # Integer "0" object.
                        objects.append(0)
                        self.vprint(f"{prefix}        INTEGER: 0", component="bytecode")
                    elif obj_to_create == 0x1:
                        # Float object, represented internally as a double.
                        fval = struct.unpack(">f", datachunk[offset_ptr : (offset_ptr + 4)])[0]
                        objects.append(fval)
                        offset_ptr += 4

                        self.vprint(f"{prefix}        FLOAT: {fval}", component="bytecode")
                    elif obj_to_create == 0x2:
                        # Null pointer object.
                        objects.append(NULL)
                        self.vprint(f"{prefix}        NULL", component="bytecode")
                    elif obj_to_create == 0x3:
                        # Undefined constant.
                        objects.append(UNDEFINED)
                        self.vprint(f"{prefix}        UNDEFINED", component="bytecode")
                    elif obj_to_create == 0x4:
                        # Register value.
                        regno = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                        objects.append(Register(regno))
                        offset_ptr += 1

                        self.vprint(
                            f"{prefix}        REGISTER NO: {regno}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x5:
                        # Boolean "TRUE" object.
                        objects.append(True)
                        self.vprint(f"{prefix}        BOOLEAN: True", component="bytecode")
                    elif obj_to_create == 0x6:
                        # Boolean "FALSE" object.
                        objects.append(False)
                        self.vprint(f"{prefix}        BOOLEAN: False", component="bytecode")
                    elif obj_to_create == 0x7:
                        # Integer object.
                        ival = struct.unpack(">i", datachunk[offset_ptr : (offset_ptr + 4)])[0]
                        objects.append(ival)
                        offset_ptr += 4

                        self.vprint(f"{prefix}        INTEGER: {ival}", component="bytecode")
                    elif obj_to_create == 0x8:
                        # String constant object.
                        const_offset = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        objects.append(const)
                        offset_ptr += 1

                        self.vprint(
                            f"{prefix}        STRING CONST: {const}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x9:
                        # String constant, but with 16 bits for the offset. Probably not used except
                        # on the largest files.
                        const_offset = struct.unpack(">H", datachunk[offset_ptr : (offset_ptr + 2)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        objects.append(const)
                        offset_ptr += 2

                        self.vprint(
                            f"{prefix}        STRING CONST: {const}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0xA:
                        # NaN constant.
                        objects.append(float("nan"))
                        self.vprint(f"{prefix}        NAN", component="bytecode")
                    elif obj_to_create == 0xB:
                        # Infinity constant.
                        objects.append(float("inf"))
                        self.vprint(f"{prefix}        INFINITY", component="bytecode")
                    elif obj_to_create == 0xC:
                        # Pointer to "this" object, whatever currently is executing the bytecode.
                        objects.append(THIS)
                        self.vprint(f"{prefix}        POINTER TO THIS", component="bytecode")
                    elif obj_to_create == 0xD:
                        # Pointer to "root" object, which is the movieclip this bytecode exists in.
                        objects.append(ROOT)
                        self.vprint(f"{prefix}        POINTER TO ROOT", component="bytecode")
                    elif obj_to_create == 0xE:
                        # Pointer to "parent" object, whatever currently is executing the bytecode.
                        # This seems to be the parent of the movie clip, or the current movieclip
                        # if that isn't set.
                        objects.append(PARENT)
                        self.vprint(f"{prefix}        POINTER TO PARENT", component="bytecode")
                    elif obj_to_create == 0xF:
                        # Current movie clip.
                        objects.append(CLIP)
                        self.vprint(
                            f"{prefix}        POINTER TO CURRENT MOVIECLIP",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x10:
                        # Property constant with no alias.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x100
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        PROPERTY CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x11:
                        # Property constant referencing a string table entry.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x100
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        PROPERTY CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x12:
                        # Same as above, but with allowance for a 16-bit constant offset.
                        propertyval, reference = struct.unpack(">BH", datachunk[offset_ptr : (offset_ptr + 3)])
                        propertyval += 0x100
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 3
                        self.vprint(
                            f"{prefix}        PROPERTY CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x13:
                        # Class property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x300
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        CLASS CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x14:
                        # Class property constant with alias.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x300
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        CLASS CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    # One would expect 0x15 to be identical to 0x12 but for class properties instead. However, it appears
                    # that this has been omitted from game binaries.
                    elif obj_to_create == 0x16:
                        # Func property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x400
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        FUNC CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x17:
                        # Func property name referencing a string table entry.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x400
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        FUNC CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    # Same comment with 0x15 applies here with 0x18.
                    elif obj_to_create == 0x19:
                        # Other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x200
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        OTHER CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x1A:
                        # Other property name referencing a string table entry.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x200
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        OTHER CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    # Same comment with 0x15 and 0x18 applies here with 0x1b.
                    elif obj_to_create == 0x1C:
                        # Event property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x500
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        EVENT CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x1D:
                        # Event property name referencing a string table entry.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x500
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        EVENT CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    # Same comment with 0x15, 0x18 and 0x1b applies here with 0x1e.
                    elif obj_to_create == 0x1F:
                        # Key constants.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x600
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        KEY CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x20:
                        # Key property name referencing a string table entry.
                        propertyval, reference = struct.unpack(">BB", datachunk[offset_ptr : (offset_ptr + 2)])
                        propertyval += 0x600
                        referenceval = self.__get_string(string_offsets[reference])
                        objects.append(StringConstant(propertyval, referenceval))

                        offset_ptr += 2
                        self.vprint(
                            f"{prefix}        KEY CONST NAME: {StringConstant.property_to_name(propertyval)}, ALIAS: {referenceval}",
                            component="bytecode",
                        )
                    # Same comment with 0x15, 0x18, 0x1b and 0x1e applies here with 0x21.
                    elif obj_to_create == 0x22:
                        # Pointer to global object.
                        objects.append(GLOBAL)
                        self.vprint(
                            f"{prefix}        POINTER TO GLOBAL OBJECT",
                            component="bytecode",
                        )
                    elif obj_to_create == 0x23:
                        # Negative infinity.
                        objects.append(float("-inf"))
                        self.vprint(f"{prefix}        -INFINITY", component="bytecode")
                    elif obj_to_create == 0x24:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x700
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        ETC2 CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x25 and 0x26 are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x24.
                    elif obj_to_create == 0x27:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x800
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        ORGFUNC2 CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x28 and 0x29 are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x27.
                    elif obj_to_create == 0x2A:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0x900
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        ETCFUNC2 CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x2b and 0x2c are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x2a.
                    elif obj_to_create == 0x2D:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0xA00
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        EVENT2 CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x2e and 0x2f are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x2d.
                    elif obj_to_create == 0x30:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0xB00
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        EVENT METHOD CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x31 and 0x32 are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x30.
                    elif obj_to_create == 0x33:
                        # Signed 64 bit integer init. Uses special "S64" type.
                        int64 = struct.unpack(">q", datachunk[offset_ptr : (offset_ptr + 8)])
                        objects.append(int64)
                        offset_ptr += 8

                        self.vprint(f"{prefix}        INTEGER: {int64}", component="bytecode")
                    elif obj_to_create == 0x34:
                        # Some other property names.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0xC00
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        GENERIC CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x35 and 0x36 are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x34.
                    elif obj_to_create == 0x37:
                        # Integer object but one byte.
                        ival = struct.unpack(">b", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                        objects.append(ival)
                        offset_ptr += 1

                        self.vprint(f"{prefix}        INTEGER: {ival}", component="bytecode")
                    elif obj_to_create == 0x38:
                        # Some other property names.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0] + 0xD00
                        objects.append(StringConstant(propertyval))
                        offset_ptr += 1
                        self.vprint(
                            f"{prefix}        GENERIC2 CONST NAME: {StringConstant.property_to_name(propertyval)}",
                            component="bytecode",
                        )
                    # Possibly in newer binaries, 0x39 and 0x3a are implemented as 8-bit and 16-bit alias pointer
                    # versions of 0x38.
                    else:
                        raise Exception(f"Unsupported object {hex(obj_to_create)} to push!")

                    obj_count -= 1

                self.vprint(f"{prefix}      END_{action_name}", component="bytecode")

                actions.append(PushAction(lineno, objects))
            elif opcode == AP2Action.INIT_REGISTER:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}", component="bytecode")

                init_registers: List[Register] = []
                while obj_count > 0:
                    register_no = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                    init_registers.append(Register(register_no))
                    offset_ptr += 1
                    obj_count -= 1

                    self.vprint(
                        f"{prefix}        REGISTER NO: {register_no}",
                        component="bytecode",
                    )
                self.vprint(f"{prefix}      END_{action_name}", component="bytecode")

                actions.append(InitRegisterAction(lineno, init_registers))
            elif opcode == AP2Action.STORE_REGISTER:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}", component="bytecode")

                store_registers: List[Register] = []
                while obj_count > 0:
                    register_no = struct.unpack(">B", datachunk[offset_ptr : (offset_ptr + 1)])[0]
                    store_registers.append(Register(register_no))
                    offset_ptr += 1
                    obj_count -= 1

                    self.vprint(
                        f"{prefix}        REGISTER NO: {register_no}",
                        component="bytecode",
                    )
                self.vprint(f"{prefix}      END_{action_name}", component="bytecode")

                actions.append(StoreRegisterAction(lineno, store_registers, preserve_stack=True))
            elif opcode == AP2Action.STORE_REGISTER2:
                register_no = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}", component="bytecode")
                self.vprint(f"{prefix}        REGISTER NO: {register_no}", component="bytecode")
                self.vprint(f"{prefix}      END_{action_name}", component="bytecode")

                actions.append(StoreRegisterAction(lineno, [Register(register_no)], preserve_stack=False))
            elif opcode == AP2Action.IF:
                jump_if_true_offset = struct.unpack(">h", datachunk[(offset_ptr + 1) : (offset_ptr + 3)])[0]
                jump_if_true_offset += lineno + 3
                offset_ptr += 3

                self.vprint(
                    f"{prefix}      {lineno}: Offset If True: {jump_if_true_offset}",
                    component="bytecode",
                )
                actions.append(IfAction(lineno, IfAction.COMP_IS_TRUE, jump_if_true_offset))
            elif opcode == AP2Action.IF2:
                if2_type, jump_if_true_offset = struct.unpack(">Bh", datachunk[(offset_ptr + 1) : (offset_ptr + 4)])
                jump_if_true_offset += lineno + 4
                offset_ptr += 4

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} {IfAction.comparison_to_str(if2_type)}, Offset If True: {jump_if_true_offset}",
                    component="bytecode",
                )
                actions.append(IfAction(lineno, if2_type, jump_if_true_offset))
            elif opcode == AP2Action.JUMP:
                jump_offset = struct.unpack(">h", datachunk[(offset_ptr + 1) : (offset_ptr + 3)])[0]
                jump_offset += lineno + 3
                offset_ptr += 3

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Offset: {jump_offset}",
                    component="bytecode",
                )
                actions.append(JumpAction(lineno, jump_offset))
            elif opcode == AP2Action.WITH:
                skip_offset = struct.unpack(">H", datachunk[(offset_ptr + 1) : (offset_ptr + 3)])[0]
                offset_ptr += 3

                # TODO: I have absolutely no idea what the data which exists in the bytecode buffer at this point
                # represents...
                unknown_data = datachunk[offset_ptr : (offset_ptr + skip_offset)]
                offset_ptr += skip_offset
                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Unknown Data Length: {skip_offset}",
                    component="bytecode",
                )
                actions.append(WithAction(lineno, unknown_data))
            elif opcode == AP2Action.ADD_NUM_VARIABLE:
                amount_to_add = struct.unpack(">b", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Add Value: {amount_to_add}",
                    component="bytecode",
                )
                actions.append(AddNumVariableAction(lineno, amount_to_add))
            elif opcode == AP2Action.GET_URL2:
                get_url_action = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} URL Action: {get_url_action >> 6}",
                    component="bytecode",
                )
                actions.append(GetURL2Action(lineno, get_url_action >> 6))
            elif opcode == AP2Action.START_DRAG:
                constraint = struct.unpack(">b", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Constrain Mouse: {'yes' if constraint > 0 else ('no' if constraint == 0 else 'check stack')}",
                    component="bytecode",
                )
                actions.append(
                    StartDragAction(
                        lineno,
                        constrain=True if constraint > 0 else (False if constraint == 0 else None),
                    )
                )
            elif opcode == AP2Action.ADD_NUM_REGISTER:
                register_no, amount_to_add = struct.unpack(">Bb", datachunk[(offset_ptr + 1) : (offset_ptr + 3)])
                offset_ptr += 3

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} Register No: {register_no}, Add Value: {amount_to_add}",
                    component="bytecode",
                )
                actions.append(AddNumRegisterAction(lineno, Register(register_no), amount_to_add))
            elif opcode == AP2Action.GOTO_FRAME2:
                flags = struct.unpack(">B", datachunk[(offset_ptr + 1) : (offset_ptr + 2)])[0]
                offset_ptr += 2

                if flags & 0x1:
                    post = "STOP"
                else:
                    post = "PLAY"

                if flags & 0x2:
                    # Additional frames to add on top of stack value.
                    additional_frames = struct.unpack(">H", datachunk[offset_ptr : (offset_ptr + 2)])[0]
                    offset_ptr += 2
                else:
                    additional_frames = 0

                self.vprint(
                    f"{prefix}      {lineno}: {action_name} AND {post} Additional Frames: {additional_frames}",
                    component="bytecode",
                )
                actions.append(GotoFrame2Action(lineno, additional_frames, stop=bool(flags & 0x1)))
            else:
                raise Exception(f"Can't advance, no handler for opcode {opcode} ({hex(opcode)})!")

        return ByteCode(bytecode_name, actions, offset_ptr)

    def __parse_tag(
        self,
        ap2_version: int,
        afp_version: int,
        ap2data: bytes,
        tagid: int,
        size: int,
        dataoffset: int,
        tag_parent_sprite: Optional[int],
        tag_frame: str,
        prefix: str = "",
    ) -> Tag:
        if tagid == AP2Tag.AP2_SHAPE:
            if size != 4:
                raise Exception(f"Invalid shape size {size}")

            unknown, shape_id = struct.unpack("<HH", ap2data[dataoffset : (dataoffset + 4)])
            self.add_coverage(dataoffset, size)

            # I'm not sure what the unknown value is. It doesn't seem to be parsed by either BishiBashi or Jubeat
            # when I've looked, but it does appear to be non-zero sometimes in Pop'n Music animations.
            shape_reference = f"{self.exported_name}_shape{shape_id}"
            self.vprint(
                f"{prefix}    Tag ID: {shape_id}, AFP Reference: {shape_reference}, Unknown: {unknown}",
                component="tags",
            )

            return AP2ShapeTag(shape_id, shape_reference)
        elif tagid == AP2Tag.AP2_DEFINE_SPRITE:
            sprite_flags, sprite_id = struct.unpack("<HH", ap2data[dataoffset : (dataoffset + 4)])
            self.add_coverage(dataoffset, 4)

            if sprite_flags & 1 == 0:
                # This is an old-style tag, it has data directly following the header.
                subtags_offset = dataoffset + 4
            else:
                # This is a new-style tag, it has a relative data pointer.
                subtags_offset = struct.unpack("<I", ap2data[(dataoffset + 4) : (dataoffset + 8)])[0] + dataoffset
                self.add_coverage(dataoffset + 4, 4)

            self.vprint(f"{prefix}    Tag ID: {sprite_id}", component="tags")
            tags, frames, labels = self.__parse_tags(
                ap2_version,
                afp_version,
                ap2data,
                subtags_offset,
                sprite_id,
                prefix="      " + prefix,
            )

            return AP2DefineSpriteTag(sprite_id, tags, frames, labels)
        elif tagid == AP2Tag.AP2_DEFINE_FONT:
            (
                unk,
                font_id,
                fontname_offset,
                xml_prefix_offset,
                text_index_count,
                height_count,
            ) = struct.unpack("<HHHHHH", ap2data[dataoffset : (dataoffset + 12)])
            self.add_coverage(dataoffset, 12)

            fontname = self.__get_string(fontname_offset)
            xml_prefix = self.__get_string(xml_prefix_offset)

            self.vprint(
                f"{prefix}    Tag ID: {font_id}, Unknown: {unk}, Font Name: {fontname}, "
                f"XML Prefix: {xml_prefix}, Text Index Entries: {text_index_count}, Height Entries: {height_count}",
                component="tags",
            )

            text_indexes: List[int] = []
            for i in range(text_index_count):
                entry_offset = dataoffset + 12 + (i * 2)
                entry_value = struct.unpack("<H", ap2data[entry_offset : (entry_offset + 2)])[0]
                text_indexes.append(entry_value)
                self.add_coverage(entry_offset, 2)

                self.vprint(
                    f"{prefix}      Text Index: {i}: {entry_value} ({chr(entry_value)})",
                    component="tags",
                )

            heights: List[int] = []
            for i in range(height_count):
                entry_offset = dataoffset + 12 + (text_index_count * 2) + (i * 2)
                entry_value = struct.unpack("<H", ap2data[entry_offset : (entry_offset + 2)])[0]
                heights.append(entry_value)
                self.add_coverage(entry_offset, 2)

                self.vprint(f"{prefix}      Height: {entry_value}", component="tags")

            return AP2DefineFontTag(font_id, fontname, xml_prefix, heights, text_indexes)
        elif tagid == AP2Tag.AP2_DO_ACTION:
            datachunk = ap2data[dataoffset : (dataoffset + size)]
            bytecode = self.__parse_bytecode(
                f"on_enter_{f'sprite_{tag_parent_sprite}' if tag_parent_sprite is not None else 'main'}_{tag_frame}",
                datachunk,
                prefix=prefix,
            )
            self.add_coverage(dataoffset, size)

            return AP2DoActionTag(bytecode)
        elif tagid == AP2Tag.AP2_PLACE_OBJECT:
            # Allow us to keep track of what we've consumed.
            datachunk = ap2data[dataoffset : (dataoffset + size)]
            flags, depth, object_id = struct.unpack("<IHH", datachunk[0:8])
            self.add_coverage(dataoffset, 8)
            running_pointer = 8

            # Make sure we grab the second half of flags as well, since this is read first for
            # newer games.
            if flags & 0x80000000:
                more_flags = struct.unpack("<I", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                flags = flags | (more_flags << 32)
                unhandled_flags = flags & ~0x80000000
            else:
                unhandled_flags = flags

            self.vprint(
                f"{prefix}    Flags: {hex(flags)}, Object ID: {object_id}, Depth: {depth}",
                component="tags",
            )
            unrecognized_options = False

            if flags & 0x2:
                # Has a shape component.
                unhandled_flags &= ~0x2
                src_tag_id = struct.unpack("<H", datachunk[running_pointer : (running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                self.vprint(f"{prefix}    Source Tag ID: {src_tag_id}", component="tags")
            else:
                src_tag_id = None

            label_name = None
            if flags & 0x10:
                unhandled_flags &= ~0x10
                label_name = struct.unpack("<H", datachunk[running_pointer : (running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2

                self.vprint(f"{prefix}    Frame Label ID: {label_name}", component="tags")

            movie_name = None
            if flags & 0x20:
                # Has movie name component.
                unhandled_flags &= ~0x20
                nameoffset = struct.unpack("<H", datachunk[running_pointer : (running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                movie_name = self.__get_string(nameoffset)
                running_pointer += 2
                self.vprint(f"{prefix}    Movie Name: {movie_name}", component="tags")

            if flags & 0x40:
                unhandled_flags &= ~0x40
                unk3 = struct.unpack("<H", datachunk[running_pointer : (running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                unrecognized_options = True
                self.vprint(f"{prefix}    Unk3: {hex(unk3)}", component="tags")

            if flags & 0x20000:
                # Has blend component.
                unhandled_flags &= ~0x20000
                blend = struct.unpack("<B", datachunk[running_pointer : (running_pointer + 1)])[0]
                self.add_coverage(dataoffset + running_pointer, 1)
                running_pointer += 1
                self.vprint(f"{prefix}    Blend: {hex(blend)}", component="tags")
            else:
                blend = None

            # Due to possible misalignment, we need to realign.
            misalignment = running_pointer & 3
            if misalignment > 0:
                catchup = 4 - misalignment
                self.add_coverage(dataoffset + running_pointer, catchup)
                running_pointer += catchup

            # Handle transformation matrix.
            transform = Matrix.identity()
            scale_set = False
            rotate_set = False

            if flags & 0x100:
                # Has scale component.
                unhandled_flags &= ~0x100
                a_int, d_int = struct.unpack("<ii", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.a = float(a_int) / 1024.0
                transform.d = float(d_int) / 1024.0
                scale_set = True

                self.vprint(
                    f"{prefix}    Transform Matrix A: {transform.a}, D: {transform.d}",
                    component="tags",
                )

            if flags & 0x200:
                # Has rotate component.
                unhandled_flags &= ~0x200
                b_int, c_int = struct.unpack("<ii", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.b = float(b_int) / 1024.0
                transform.c = float(c_int) / 1024.0
                rotate_set = True

                self.vprint(
                    f"{prefix}    Transform Matrix B: {transform.b}, C: {transform.c}",
                    component="tags",
                )

            if flags & 0x400:
                # Has translate component.
                unhandled_flags &= ~0x400
                tx_int, ty_int = struct.unpack("<ii", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.tx = float(tx_int) / 20.0
                transform.ty = float(ty_int) / 20.0

                self.vprint(
                    f"{prefix}    Transform Matrix TX: {transform.tx}, TY: {transform.ty}",
                    component="tags",
                )

            # Handle object colors
            multcolor = Color(1.0, 1.0, 1.0, 1.0)
            addcolor = Color(0.0, 0.0, 0.0, 0.0)
            multdisplayed = False
            adddisplayed = False

            if flags & 0x800:
                # Multiplicative color present.
                unhandled_flags &= ~0x800
                r, g, b, a = struct.unpack("<hhhh", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                multcolor.r = float(r) / 255.0
                multcolor.g = float(g) / 255.0
                multcolor.b = float(b) / 255.0
                multcolor.a = float(a) / 255.0
                self.vprint(f"{prefix}    Mult Color: {multcolor}", component="tags")
                multdisplayed = True

            if flags & 0x1000:
                # Additive color present.
                unhandled_flags &= ~0x1000
                r, g, b, a = struct.unpack("<hhhh", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                addcolor.r = float(r) / 255.0
                addcolor.g = float(g) / 255.0
                addcolor.b = float(b) / 255.0
                addcolor.a = float(a) / 255.0
                self.vprint(f"{prefix}    Add Color: {addcolor}", component="tags")
                adddisplayed = True

            if flags & 0x2000:
                # Multiplicative color present, smaller integers.
                unhandled_flags &= ~0x2000
                rgba = struct.unpack("<I", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                multcolor.r = float((rgba >> 24) & 0xFF) / 255.0
                multcolor.g = float((rgba >> 16) & 0xFF) / 255.0
                multcolor.b = float((rgba >> 8) & 0xFF) / 255.0
                multcolor.a = float(rgba & 0xFF) / 255.0
                self.vprint(f"{prefix}    Mult Color: {multcolor}", component="tags")
                multdisplayed = True

            if flags & 0x4000:
                # Additive color present, smaller integers.
                unhandled_flags &= ~0x4000
                rgba = struct.unpack("<I", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                addcolor.r = float((rgba >> 24) & 0xFF) / 255.0
                addcolor.g = float((rgba >> 16) & 0xFF) / 255.0
                addcolor.b = float((rgba >> 8) & 0xFF) / 255.0
                addcolor.a = float(rgba & 0xFF) / 255.0
                self.vprint(f"{prefix}    Add Color: {addcolor}", component="tags")
                adddisplayed = True

            # For easier debugging, display the default color when the color
            # is being used.
            if flags & 0x8:
                if not multdisplayed:
                    self.vprint(f"{prefix}    Mult Color: {multcolor}", component="tags")
                if not adddisplayed:
                    self.vprint(f"{prefix}    Add Color: {addcolor}", component="tags")

            bytecodes: Dict[int, List[ByteCode]] = {}
            if flags & 0x80:
                # Object event triggers.
                unhandled_flags &= ~0x80
                event_flags, event_size = struct.unpack("<II", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)

                if event_flags != 0:
                    _, count = struct.unpack("<HH", datachunk[(running_pointer + 8) : (running_pointer + 12)])
                    self.add_coverage(dataoffset + running_pointer + 8, 4)

                    # The game does not seem to care about length here, but we do, so let's calculate
                    # offsets and use that for lengths.
                    bytecode_offsets: List[int] = []
                    for evt in range(count):
                        evt_offset = running_pointer + 12 + (evt * 8)
                        bytecode_offset = (
                            struct.unpack("<H", datachunk[(evt_offset + 6) : (evt_offset + 8)])[0] + evt_offset
                        )
                        bytecode_offsets.append(bytecode_offset)
                    bytecode_offsets.append(event_size + running_pointer)

                    beginning_to_end: Dict[int, int] = {}
                    for i, bytecode_offset in enumerate(bytecode_offsets[:-1]):
                        beginning_to_end[bytecode_offset] = bytecode_offsets[i + 1]

                    self.vprint(f"{prefix}    Event Triggers, Count: {count}", component="tags")
                    for evt in range(count):
                        evt_offset = running_pointer + 12 + (evt * 8)
                        evt_flags, _, keycode, bytecode_offset = struct.unpack(
                            "<IBBH", datachunk[evt_offset : (evt_offset + 8)]
                        )
                        self.add_coverage(dataoffset + evt_offset, 8)

                        events: List[str] = []
                        if evt_flags & AP2Trigger.ON_LOAD:
                            events.append("ON_LOAD")
                        if evt_flags & AP2Trigger.ON_ENTER_FRAME:
                            events.append("ON_ENTER_FRAME")
                        if evt_flags & AP2Trigger.ON_UNLOAD:
                            events.append("ON_UNLOAD")
                        if evt_flags & AP2Trigger.ON_MOUSE_MOVE:
                            events.append("ON_MOUSE_MOVE")
                        if evt_flags & AP2Trigger.ON_MOUSE_DOWN:
                            events.append("ON_MOUSE_DOWN")
                        if evt_flags & AP2Trigger.ON_MOUSE_UP:
                            events.append("ON_MOUSE_UP")
                        if evt_flags & AP2Trigger.ON_KEY_DOWN:
                            events.append("ON_KEY_DOWN")
                        if evt_flags & AP2Trigger.ON_KEY_UP:
                            events.append("ON_KEY_UP")
                        if evt_flags & AP2Trigger.ON_DATA:
                            events.append("ON_DATA")
                        if evt_flags & AP2Trigger.ON_PRESS:
                            events.append("ON_PRESS")
                        if evt_flags & AP2Trigger.ON_RELEASE:
                            events.append("ON_RELEASE")
                        if evt_flags & AP2Trigger.ON_RELEASE_OUTSIDE:
                            events.append("ON_RELEASE_OUTSIDE")
                        if evt_flags & AP2Trigger.ON_ROLL_OVER:
                            events.append("ON_ROLL_OVER")
                        if evt_flags & AP2Trigger.ON_ROLL_OUT:
                            events.append("ON_ROLL_OUT")

                        bytecode_offset += evt_offset
                        bytecode_length = beginning_to_end[bytecode_offset] - bytecode_offset

                        self.vprint(
                            f"{prefix}      Flags: {hex(evt_flags)} ({', '.join(events)}), KeyCode: {hex(keycode)}, ByteCode Offset: {hex(dataoffset + bytecode_offset)}, Length: {bytecode_length}",
                            component="tags",
                        )
                        bytecode = self.__parse_bytecode(
                            f"on_tag_{object_id}_event",
                            datachunk[bytecode_offset : (bytecode_offset + bytecode_length)],
                            prefix=prefix + "    ",
                        )
                        self.add_coverage(dataoffset + bytecode_offset, bytecode_length)

                        bytecodes[evt_flags] = [*bytecodes.get(evt_flags, []), bytecode]

                running_pointer += event_size

            if flags & 0x10000:
                # Some sort of filter data? Not sure what this is either. Needs more investigation
                # if I encounter files with it. This seems to match up with SWF documentation on
                # filters. Still have yet to see any files with it.
                unhandled_flags &= ~0x10000
                count, filter_size = struct.unpack("<HH", datachunk[running_pointer : (running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += filter_size
                unrecognized_options = True

                # TODO: This is not understood at all. I need to find data that uses it to continue.
                # running_pointer + 4 starts a series of shorts (exactly count of them) which are
                # all in the range of 0-7, corresponding to some sort of filter. They get sizes
                # looked up and I presume there's data following this corresponding to those sizes.
                # I don't know however as I've not encountered data with this bit.
                self.vprint(
                    f"{prefix}    Unknown Filter data Count: {count}, Size: {filter_size}",
                    component="tags",
                )

            rotation_origin = Point(0.0, 0.0, 0.0)
            rotation_origin_set = False

            if flags & 0x1000000:
                # I am certain that this is the rotation origin, as treating it as such works for
                # basically all files.
                unhandled_flags &= ~0x1000000
                x, y = struct.unpack("<ii", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                rotation_origin.x = float(x) / 20.0
                rotation_origin.y = float(y) / 20.0
                rotation_origin_set = True

                self.vprint(
                    f"{prefix}    Rotation XY Origin: {rotation_origin.x}, {rotation_origin.y}",
                    component="tags",
                )

            if flags & 0x200000000:
                # This is Z rotation origin.
                unhandled_flags &= ~0x200000000
                z_int = struct.unpack("<i", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                rotation_origin.z = float(z_int) / 20.0
                rotation_origin_set = True

                self.vprint(
                    f"{prefix}    Rotation Z Origin: {rotation_origin.z}",
                    component="tags",
                )

            if flags & 0x2000000:
                # Same as above, but initializing to 0, 0, 0 instead of from data.
                unhandled_flags &= ~0x2000000

                rotation_origin.x = 0.0
                rotation_origin.y = 0.0
                rotation_origin.z = 0.0
                rotation_origin_set = True

                self.vprint(
                    f"{prefix}    Rotation XYZ Origin: {rotation_origin.x}, {rotation_origin.y}, {rotation_origin.z}",
                    component="tags",
                )

            if flags & 0x40000:
                # This appears in newer IIDX to be an alternative method for populating
                # transform scaling.
                unhandled_flags &= ~0x40000

                # This is a bit nasty, but the newest version of data we see in
                # Bishi with this flag set is 0x8, and the oldest version in DDR
                # PS3 is also 0x8. Newer AFP versions do something with this flag
                # but Bishi straight-up ignores it (no code to even check it), so
                # we must use a heuristic for determining if this is parseable...
                if running_pointer == len(datachunk):
                    pass
                else:
                    a_int, d_int = struct.unpack("<hh", datachunk[running_pointer : (running_pointer + 4)])
                    self.add_coverage(dataoffset + running_pointer, 4)
                    running_pointer += 4

                    transform.a = float(a_int) / 32768.0
                    transform.d = float(d_int) / 32768.0
                    scale_set = True

                    self.vprint(
                        f"{prefix}    Transform Matrix A: {transform.a}, D: {transform.d}",
                        component="tags",
                    )

            if flags & 0x80000:
                # This appears in newer IIDX to be an alternative method for populating
                # transform rotation.
                unhandled_flags &= ~0x80000
                b_int, c_int = struct.unpack("<hh", datachunk[running_pointer : (running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                transform.b = float(b_int) / 32768.0
                transform.c = float(c_int) / 32768.0
                rotate_set = True

                self.vprint(
                    f"{prefix}    Transform Matrix B: {transform.b}, C: {transform.c}",
                    component="tags",
                )

            if flags & 0x100000:
                # TODO: Some unknown short.
                unhandled_flags &= ~0x100000
                unk_4 = struct.unpack("<H", datachunk[running_pointer : (running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                unrecognized_options = True

                self.vprint(f"{prefix}    Unk 4: {unk_4}", component="tags")

            # Due to possible misalignment, we need to realign.
            misalignment = running_pointer & 3
            if misalignment > 0:
                catchup = 4 - misalignment
                self.add_coverage(dataoffset + running_pointer, catchup)
                running_pointer += catchup

            if flags & 0x8000000:
                # This is the translation offset "z" for a 3D transform matrix.
                unhandled_flags &= ~0x8000000
                tz_int = struct.unpack("<i", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                transform.tz = tz_int / 20.0

                self.vprint(f"{prefix}    Translate Z offset: {transform.tz}", component="tags")

            if flags & 0x10000000:
                # This is a 3x3 grid of initializers for a 3D transform matrix. It appears that
                # files also include the A/D and B/C pairs that match the correct locations in
                # previous transform parsing sections, possibly for backwards compatibility?
                unhandled_flags &= ~0x10000000
                ints = struct.unpack("<iiiiiiiii", datachunk[running_pointer : (running_pointer + 36)])
                self.add_coverage(dataoffset + running_pointer, 36)
                running_pointer += 36

                floats = [x / 1024.0 for x in ints]

                # Due to the way the format works, a/b/c/d can be more accurately specified in
                # some extended flag nodes above than they can be here. So, we favor those values
                # if they were set.
                if not scale_set:
                    transform.a11 = floats[0]
                    transform.a22 = floats[4]
                if not rotate_set:
                    transform.a12 = floats[1]
                    transform.a21 = floats[3]

                transform.a13 = floats[2]
                transform.a23 = floats[5]
                transform.a31 = floats[6]
                transform.a32 = floats[7]
                transform.a33 = floats[8]

                self.vprint(
                    f"{prefix}    3D Transform Matrix: {', '.join(str(f) for f in floats)}",
                    component="tags",
                )

            # HSL shift data.
            hue: Optional[int] = None
            saturation: Optional[int] = None
            lightness: Optional[int] = None

            if flags & 0x20000000:
                # Looks like Hue/Lightness/Saturation shift, matching after effects in the limits.
                # First value is degrees to shift the hue, second and third values I'm not sure if
                # its saturation then lightness or lightness then saturation but both have limits of
                # -100 to 100 in after effects and the file that I found with this option chooses
                # 0 for each.
                unhandled_flags &= ~0x20000000
                hue, saturation, lightness = struct.unpack("<hbb", datachunk[running_pointer : (running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                # TODO: Need to confirm whether 2 and 3 options are saturation and lightness or
                # lightness and saturation. Should be easy if we ever find an animation using either
                # of these values.
                self.vprint(
                    f"{prefix}    HSL Shift: {hue}, {saturation}, {lightness}",
                    component="tags",
                )

            if flags & 0x400000000:
                # There's some serious hanky-panky going on here. The first 4 bytes are a bitmask,
                # and we advance past data based on some calculation of the number of bits set.
                # I'll need to run into some data using this to figure out what the heck is going on.
                raise Exception("TODO")

            if flags & 0x800000000:
                unhandled_flags &= ~0x800000000
                bitmask = struct.unpack("<I", datachunk[running_pointer : (running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                self.vprint(f"{prefix}    Unknown Data Flags: {hex(bitmask)}", component="tags")

                # I have no idea what any of this is either, so I am duplicating game logic in the
                # hopes that someday it makes sense.
                for bit in range(32):
                    if bool(bitmask & (1 << bit)):
                        unk_flags, unk_size = struct.unpack("<HH", datachunk[running_pointer : (running_pointer + 4)])
                        self.add_coverage(dataoffset + running_pointer, 4)
                        running_pointer += 4

                        chunk_size = (
                            # Either 2 or 6, depending on unk_flags & 0x10 set.
                            (((unk_flags & 0x10) | 0x8) >> 2)
                            *
                            # Either 1 or 2, depending on unk_flags & 0x1 set.
                            ((unk_flags & 1) + 1)
                            *
                            # Raw size as read from the header above.
                            unk_size
                            *
                            # I assume this is some number of shorts, much like many other
                            # file formats, so this is why all of these counts are doubled.
                            2
                        )

                        self.vprint(
                            f"{prefix}      WTF: {hex(unk_flags)}, {unk_size}, {chunk_size}",
                            component="tags",
                        )

                        # Skip past data.
                        running_pointer += chunk_size
                unrecognized_options = True

            if flags & 0x1000000000:
                # I have no idea what this is, but the two shorts that it pulls out are assigned
                # to the same variables as those in 0x2000000000, so they're obviously linked.
                unhandled_flags &= ~0x1000000000
                unk1, unk2, unk3 = struct.unpack("<Ihh", datachunk[running_pointer : (running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8
                unrecognized_options = True

                self.vprint(
                    f"{prefix}    Unknown New Data: {unk1}, {unk2}, {unk3}",
                    component="tags",
                )

            if flags & 0x2000000000:
                # I have no idea what this is, but the two shorts that it pulls out are assigned
                # to the same variables as those in 0x1000000000, so they're obviously linked.
                unhandled_flags &= ~0x2000000000
                unk1, unk2, unk3 = struct.unpack("<Hhh", datachunk[running_pointer : (running_pointer + 6)])
                self.add_coverage(dataoffset + running_pointer, 6)
                running_pointer += 6
                unrecognized_options = True

                self.vprint(
                    f"{prefix}    Unknown New Data: {unk1}, {unk2}, {unk3}",
                    component="tags",
                )

            # Due to possible misalignment, we need to realign.
            misalignment = running_pointer & 3
            if misalignment > 0:
                catchup = 4 - misalignment
                self.add_coverage(dataoffset + running_pointer, catchup)
                running_pointer += catchup

            if flags & 0x4000000000:
                raise Exception("TODO")

            projection = AP2PlaceObjectTag.PROJECTION_NONE
            unhandled_flags &= ~0x400000D

            # This flag states whether we are creating a new object on this depth, or updating one.
            if flags & 0x1:
                self.vprint(f"{prefix}    Update object request", component="tags")
                update_request = True
            else:
                self.vprint(f"{prefix}    Create object request", component="tags")
                update_request = False

            if flags & 0x18000004:
                # Technically only flag 0x4 is the "use transform matrix" flag, but when they
                # added perspective to the format, they also just made setting the TZ or the
                # 3x3 transform portion of a 4x4 matrix equivalent. So if those exist, this
                # implicitly is enabled.
                self.vprint(f"{prefix}    Use transform matrix", component="tags")
                projection = AP2PlaceObjectTag.PROJECTION_AFFINE
                transform_information = True
            else:
                self.vprint(f"{prefix}    Ignore transform matrix", component="tags")
                transform_information = False

            if flags & 0x8:
                self.vprint(f"{prefix}    Use color information", component="tags")
                color_information = True
            else:
                self.vprint(f"{prefix}    Ignore color information", component="tags")
                color_information = False

            if flags & 0x4000000:
                self.vprint(f"{prefix}    Use 3D transform system", component="tags")
                projection = AP2PlaceObjectTag.PROJECTION_PERSPECTIVE
            else:
                self.vprint(f"{prefix}    Use 2D transform system", component="tags")

                # Unset any previously set 3D transforms. Files shouldn't include both 3D
                # transforms AND the old 2D transform flag, but let's respect that bit.
                rotation_origin.z = 0.0
                transform = transform.to_affine()

            self.vprint(f"{prefix}    Final transform: {transform}", component="tags")

            if unhandled_flags != 0:
                raise Exception(f"Did not handle {hex(unhandled_flags)} flag bits!")
            if running_pointer < size:
                raise Exception(
                    f"Did not consume {size - running_pointer} bytes ({[hex(x) for x in datachunk[running_pointer:]]}) in object instantiation!"
                )
            if running_pointer != size:
                raise Exception("Logic error!")

            return AP2PlaceObjectTag(
                object_id,
                depth,
                src_tag_id=src_tag_id,
                movie_name=movie_name,
                label_name=label_name,
                blend=blend,
                update=update_request,
                transform=transform if transform_information else None,
                rotation_origin=rotation_origin if rotation_origin_set else None,
                projection=projection,
                mult_color=multcolor if color_information else None,
                add_color=addcolor if color_information else None,
                hsl_shift=HSL(hue / 360.0, saturation / 100.0, lightness / 100.0) if hue is not None else None,
                triggers=bytecodes,
                unrecognized_options=unrecognized_options,
            )
        elif tagid == AP2Tag.AP2_REMOVE_OBJECT:
            if size != 4:
                raise Exception(f"Invalid shape size {size}")

            object_id, depth = struct.unpack("<HH", ap2data[dataoffset : (dataoffset + 4)])
            self.vprint(f"{prefix}    Object ID: {object_id}, Depth: {depth}", component="tags")
            self.add_coverage(dataoffset, 4)

            return AP2RemoveObjectTag(object_id, depth)
        elif tagid == AP2Tag.AP2_DEFINE_TEXT:
            (
                flags,
                text_id,
                text_data_count,
                sub_data_total_count,
                text_data_offset,
                sub_data_base_offset,
            ) = struct.unpack(
                "<HHHHHH",
                ap2data[dataoffset : (dataoffset + 12)],
            )
            self.add_coverage(dataoffset, 12)

            # TODO: There are some flags bits here that I do not understand.
            if flags not in {0x0, 0x4}:
                raise Exception(f"Unexpected flags {hex(flags)} in AP2_DEFINE_TEXT!")

            extra_data = 12 + (20 * text_data_count) + (4 * sub_data_total_count)
            if size < extra_data:
                raise Exception(f"Unexpected size {size}, expected at least {extra_data} for AP2_DEFINE_TEXT!")
            if size > extra_data:
                # There seems to be some amount of data left over at the end, not sure what it
                # is or does. I don't see any references to it being used in the tag loader.
                pass

            self.vprint(
                f"{prefix}    Tag ID: {text_id}, Count of Entries: {text_data_count}, Count of Sub Entries: {sub_data_total_count}",
                component="tags",
            )
            lines: List[AP2TextLine] = []
            for i in range(text_data_count):
                chunk_data_offset = dataoffset + text_data_offset + (20 * i)
                (
                    chunk_flags,
                    sub_data_count,
                    font_tag,
                    font_height,
                    xpos,
                    ypos,
                    sub_data_offset,
                    rgba,
                ) = struct.unpack(
                    "<IHHHHHHI",
                    ap2data[chunk_data_offset : (chunk_data_offset + 20)],
                )
                self.add_coverage(chunk_data_offset, 20)

                if not (chunk_flags & 0x1):
                    xpos = 0.0
                else:
                    xpos = float(xpos) / 20.0
                if not (chunk_flags & 0x2):
                    ypos = 0.0
                else:
                    ypos = float(ypos) / 20.0
                if not (chunk_flags & 0x8):
                    font_tag = None

                color = Color(
                    float(rgba & 0xFF) / 255.0,
                    float((rgba >> 8) & 0xFF) / 255.0,
                    float((rgba >> 16) & 0xFF) / 255.0,
                    float((rgba >> 24) & 0xFF) / 255.0,
                )

                self.vprint(
                    f"{prefix}      Font Tag: {font_tag}, Font Height: {font_height}, X: {xpos}, Y: {ypos}, Count of Sub-Entries: {sub_data_count}, Color: {color}",
                    component="tags",
                )

                base_offset = dataoffset + (sub_data_offset * 4) + sub_data_base_offset
                offsets: List[AP2TextChar] = []
                for i in range(sub_data_count):
                    sub_chunk_offset = base_offset + (i * 4)
                    font_text_index, xoff = struct.unpack(
                        "<HH",
                        ap2data[sub_chunk_offset : (sub_chunk_offset + 4)],
                    )
                    self.add_coverage(sub_chunk_offset, 4)

                    entry_width = round(float(xoff) / 20.0, 5)
                    offsets.append(AP2TextChar(font_text_index, entry_width))

                    self.vprint(
                        f"{prefix}        Font Text Index: {font_text_index}, X: {xpos}, Width: {entry_width}",
                        component="tags",
                    )

                    # Make room for next character.
                    xpos = round(xpos + entry_width, 5)

                lines.append(
                    AP2TextLine(
                        font_tag,
                        font_height,
                        xpos,
                        ypos,
                        offsets,
                    )
                )

            return AP2DefineTextTag(text_id, lines)
        elif tagid == AP2Tag.AP2_DEFINE_EDIT_TEXT:
            if size != 44:
                raise Exception(f"Invalid size {size} to get data from AP2_DEFINE_EDIT_TEXT!")

            (
                flags,
                edit_text_id,
                defined_font_tag_id,
                font_height,
                unk_str2_offset,
            ) = struct.unpack("<IHHHH", ap2data[dataoffset : (dataoffset + 12)])
            self.add_coverage(dataoffset, 12)

            unk1, unk2, unk3, unk4 = struct.unpack("<HHHH", ap2data[(dataoffset + 12) : (dataoffset + 20)])
            self.add_coverage(dataoffset + 12, 8)

            (
                rgba,
                f1,
                f2,
                f3,
                f4,
                variable_name_offset,
                default_text_offset,
            ) = struct.unpack("<IiiiiHH", ap2data[(dataoffset + 20) : (dataoffset + 44)])
            self.add_coverage(dataoffset + 20, 24)

            self.vprint(
                f"{prefix}    Tag ID: {edit_text_id}, Font Tag: {defined_font_tag_id}, Height Selection: {font_height}, Flags: {hex(flags)}",
                component="tags",
            )

            unk_string2 = self.__get_string(unk_str2_offset) or None
            self.vprint(f"{prefix}      Unk String: {unk_string2}", component="tags")

            rect = Rectangle(f1 / 20.0, f2 / 20.0, f3 / 20.0, f4 / 20.0)
            self.vprint(f"{prefix}      Rectangle: {rect}", component="tags")

            variable_name = self.__get_string(variable_name_offset) or None
            self.vprint(f"{prefix}      Variable Name: {variable_name}", component="tags")

            color = Color(
                r=(rgba & 0xFF) / 255.0,
                g=((rgba >> 8) & 0xFF) / 255.0,
                b=((rgba >> 16) & 0xFF) / 255.0,
                a=((rgba >> 24) & 0xFF) / 255.0,
            )
            self.vprint(f"{prefix}      Text Color: {color}", component="tags")

            self.vprint(
                f"{prefix}      Unk1: {unk1}, Unk2: {unk2}, Unk3: {unk3}, Unk4: {unk4}",
                component="tags",
            )

            # flags & 0x20 means something with offset 16-18.
            # flags & 0x200 is unk str below is a HTML tag.

            if flags & 0x80:
                # Has some sort of string pointer.
                default_text = self.__get_string(default_text_offset) or None
                self.vprint(f"{prefix}      Default Text: {default_text}", component="tags")
            else:
                default_text = None

            return AP2DefineEditTextTag(
                edit_text_id,
                defined_font_tag_id,
                font_height,
                rect,
                color,
                default_text=default_text,
            )
        elif tagid == AP2Tag.AP2_DEFINE_MORPH_SHAPE:
            (
                unk1,
                unk2,
                define_shape_id,
                _0x2c_count,
                _0x2e_count,
                another_count,
            ) = struct.unpack("<HHHHHH", ap2data[dataoffset : (dataoffset + 12)])
            self.add_coverage(dataoffset, 12)

            _0x2c_offset, _0x2e_offset, another_offset = struct.unpack(
                "<HHH", ap2data[(dataoffset + 44) : (dataoffset + 50)]
            )
            self.add_coverage(dataoffset + 44, 6)

            self.vprint(
                f"{prefix}    Tag ID: {define_shape_id}, Unk1: {unk1}, Unk2: {unk2}, Count1: {_0x2c_count}, Count2: {_0x2e_count}, Another Count: {another_count}",
                component="tags",
            )

            for label, off, sz in [
                ("0x2c", _0x2c_offset, _0x2c_count),
                ("0x2e", _0x2e_offset, _0x2e_count),
            ]:
                for i in range(sz):
                    short_offset = dataoffset + off + (2 * i)
                    loc = struct.unpack("<H", ap2data[short_offset : (short_offset + 2)])[0]
                    self.add_coverage(short_offset, 2)

                    chunk_offset = dataoffset + loc
                    flags, unk3, unk4 = struct.unpack("<HBB", ap2data[chunk_offset : (chunk_offset + 4)])
                    self.add_coverage(chunk_offset, 4)
                    chunk_offset += 4

                    self.vprint(
                        f"{prefix}      {label} Flags: {hex(flags)}, Unk3: {unk3}, Unk4-1: {(unk4 >> 2) & 0x3}, Unk4-2: {(unk4 & 0x3)}",
                        component="tags",
                    )

                    unprocessed_flags = flags
                    if flags & 0x1:
                        int1, int2 = struct.unpack("<HH", ap2data[chunk_offset : (chunk_offset + 4)])
                        self.add_coverage(chunk_offset, 4)
                        chunk_offset += 4
                        unprocessed_flags &= ~0x1

                        # TODO: In game, 20.0 is divided by int1 cast to float, then int2 cast to float divided by 20.0 is
                        # subtracted from the first value, and that is multiplied by some percentage, and then the
                        # second value is added back in.

                        self.vprint(
                            f"{prefix}        Unknown Int1: {int1}, Int2: {int2}",
                            component="tags",
                        )

                    if flags & 0x12:
                        intval, src_ptr = struct.unpack("<HH", ap2data[chunk_offset : (chunk_offset + 4)])
                        self.add_coverage(chunk_offset, 4)
                        chunk_offset += 4
                        unprocessed_flags &= ~0x12

                        self.vprint(
                            f"{prefix}        Unknown Float: {float(intval) / 20.0}, Source Bitmap ID: {src_ptr}",
                            component="tags",
                        )

                    if flags & 0x4:
                        rgba1, rgba2 = struct.unpack("<II", ap2data[chunk_offset : (chunk_offset + 8)])
                        self.add_coverage(chunk_offset, 8)
                        chunk_offset += 8
                        unprocessed_flags &= ~0x4

                        color1 = Color(
                            r=(rgba1 & 0xFF) / 255.0,
                            g=((rgba1 >> 8) & 0xFF) / 255.0,
                            b=((rgba1 >> 16) & 0xFF) / 255.0,
                            a=((rgba1 >> 24) & 0xFF) / 255.0,
                        )

                        color2 = Color(
                            r=(rgba2 & 0xFF) / 255.0,
                            g=((rgba2 >> 8) & 0xFF) / 255.0,
                            b=((rgba2 >> 16) & 0xFF) / 255.0,
                            a=((rgba2 >> 24) & 0xFF) / 255.0,
                        )

                        self.vprint(
                            f"{prefix}        Start Color: {color1}, End Color: {color2}",
                            component="tags",
                        )

                    if flags & 0x8:
                        (
                            a1,
                            d1,
                            a2,
                            d2,
                            b1,
                            c1,
                            b2,
                            c2,
                            tx1,
                            ty1,
                            tx2,
                            ty2,
                        ) = struct.unpack("<IIIIIIIIIIII", ap2data[chunk_offset : (chunk_offset + 48)])
                        self.add_coverage(chunk_offset, 48)
                        chunk_offset += 48
                        unprocessed_flags &= ~0x4

                        matrix1 = Matrix.affine(
                            a=a1,
                            b=b1,
                            c=c1,
                            d=d1,
                            tx=tx1,
                            ty=ty1,
                        )

                        matrix2 = Matrix.affine(
                            a=a2,
                            b=b2,
                            c=c2,
                            d=d2,
                            tx=tx2,
                            ty=ty2,
                        )

                        self.vprint(
                            f"{prefix}        Start Matrix: {matrix1}, End Matrix: {matrix2}",
                            component="tags",
                        )

                    if flags & 0x20:
                        # TODO: This is kinda complicated and I don't see any data using it yet, looks like it
                        # has a 2-byte count, a 2 byte offset, and passes in whether flags bits 0x80 and 0x300
                        # are set.
                        raise Exception("TODO, this whole section!")

                    if unprocessed_flags:
                        raise Exception(f"Failed to process flags {hex(unprocessed_flags)}")

            for i in range(another_count):
                short_offset = dataoffset + another_offset + (2 * i)
                loc = struct.unpack("<H", ap2data[short_offset : (short_offset + 2)])[0]
                self.add_coverage(short_offset, 2)

                chunk_offset = dataoffset + loc
                unk5, some_count, a, b, c, unk6, i1, i2, i3, i4 = struct.unpack(
                    "<HHBBBBHHHH", ap2data[chunk_offset : (chunk_offset + 16)]
                )
                self.add_coverage(chunk_offset, 16)
                chunk_offset += 16

                f1 = float(i1) / 20.0
                f2 = float(i2) / 20.0
                f3 = float(i3) / 20.0
                f4 = float(i4) / 20.0

                self.vprint(
                    f"{prefix}      Unk5: {unk5}, Unk6: {unk6}, F1: {f1}, F2: {f2}, F3: {f3}, F4: {f4}, ABC: {a} {b} {c}, Count: {some_count}",
                    component="tags",
                )

                for _ in range(some_count):
                    shorts = struct.unpack("<HHHHHHHH", ap2data[chunk_offset : (chunk_offset + 16)])
                    self.add_coverage(chunk_offset, 16)
                    chunk_offset += 16

                    fv1 = float(shorts[0] + i1) / 20.0
                    fv2 = float(shorts[1] + i2) / 20.0
                    fv3 = float(shorts[2] + i3) / 20.0
                    fv4 = float(shorts[3] + i4) / 20.0
                    fv5 = float(shorts[0] + i1 + shorts[4]) / 20.0
                    fv6 = float(shorts[1] + i2 + shorts[5]) / 20.0
                    fv7 = float(shorts[2] + i3 + shorts[6]) / 20.0
                    fv8 = float(shorts[3] + i4 + shorts[7]) / 20.0

                    self.vprint(
                        f"{prefix}        Floats: {fv1} {fv2} {fv3} {fv4} {fv5} {fv6} {fv7} {fv8}",
                        component="tags",
                    )

            return AP2DefineMorphShapeTag(define_shape_id)
        elif tagid == AP2Tag.AP2_DEFINE_BUTTON:
            flags, button_id, source_tags_count, bytecode_count = struct.unpack(
                "<HHHH", ap2data[dataoffset : (dataoffset + 8)]
            )
            self.add_coverage(dataoffset, 8)

            self.vprint(
                f"{prefix}    Tag ID: {button_id}, Flags: {hex(flags)}, Source Tags Count: {source_tags_count}, Unknown Count: {bytecode_count}",
                component="tags",
            )
            running_offset = dataoffset + 8

            for _ in range(source_tags_count):
                loc = struct.unpack("<H", ap2data[running_offset : (running_offset + 2)])[0]
                self.add_coverage(running_offset, 2)
                running_offset += 2

                chunk_offset = dataoffset + loc
                status_bitmask, depth, src_tag_id = struct.unpack("<IHH", ap2data[chunk_offset : (chunk_offset + 8)])
                self.add_coverage(chunk_offset, 8)

                chunk_offset += 8
                rest_of_bitmask = status_bitmask & (
                    ~(0x20 + 0x100 + 0x200 + 0x400 + 0x800 + 0x1000 + 0x2000 + 0x4000 + 0x8000)
                )

                self.vprint(
                    f"{prefix}      Offset: {hex(loc)}, Flags: {hex(status_bitmask)}, Source Flags: {hex(rest_of_bitmask)}, Depth: {depth}, Source Tag ID: {src_tag_id}",
                    component="tags",
                )

                # Parse the bitmask
                if status_bitmask & 0x20:
                    # Blend parameter:
                    blend = struct.unpack("<B", ap2data[chunk_offset : (chunk_offset + 1)])[0]
                    self.add_coverage(chunk_offset, 4)
                    chunk_offset += 4
                    self.vprint(f"{prefix}        Blend: {hex(blend)}", component="tags")
                else:
                    blend = None

                transform = Matrix.identity()

                if status_bitmask & 0x100:
                    # Parse scale component of matrix.
                    a_int, d_int = struct.unpack("<ii", ap2data[chunk_offset : (chunk_offset + 8)])
                    self.add_coverage(chunk_offset, 8)
                    chunk_offset += 8

                    transform.a = float(a_int) / 1024.0
                    transform.d = float(d_int) / 1024.0
                    self.vprint(
                        f"{prefix}        Transform Matrix A: {transform.a}, D: {transform.d}",
                        component="tags",
                    )

                if status_bitmask & 0x200:
                    # Parse rotate component of matrix.
                    b_int, c_int = struct.unpack("<ii", ap2data[chunk_offset : (chunk_offset + 8)])
                    self.add_coverage(chunk_offset, 8)
                    chunk_offset += 8

                    transform.b = float(b_int) / 1024.0
                    transform.c = float(c_int) / 1024.0
                    self.vprint(
                        f"{prefix}        Transform Matrix B: {transform.b}, C: {transform.c}",
                        component="tags",
                    )

                if status_bitmask & 0x400:
                    # Parse transpose component of matrix.
                    tx_int, ty_int = struct.unpack("<ii", ap2data[chunk_offset : (chunk_offset + 8)])
                    self.add_coverage(chunk_offset, 8)
                    chunk_offset += 8

                    transform.tx = float(tx_int) / 20.0
                    transform.ty = float(ty_int) / 20.0
                    self.vprint(
                        f"{prefix}        Transform Matrix TX: {transform.tx}, TY: {transform.ty}",
                        component="tags",
                    )

                # Handle object colors
                multcolor = Color(1.0, 1.0, 1.0, 1.0)
                addcolor = Color(0.0, 0.0, 0.0, 0.0)

                if flags & 0x800:
                    # Multiplicative color present.
                    r, g, b, a = struct.unpack("<HHHH", ap2data[chunk_offset : (chunk_offset + 8)])
                    self.add_coverage(chunk_offset, 8)
                    chunk_offset += 8

                    multcolor.r = float(r) / 255.0
                    multcolor.g = float(g) / 255.0
                    multcolor.b = float(b) / 255.0
                    multcolor.a = float(a) / 255.0
                    self.vprint(f"{prefix}        Mult Color: {multcolor}", component="tags")

                if flags & 0x1000:
                    # Additive color present.
                    r, g, b, a = struct.unpack("<HHHH", ap2data[chunk_offset : (chunk_offset + 8)])
                    self.add_coverage(chunk_offset, 8)
                    chunk_offset += 8

                    addcolor.r = float(r) / 255.0
                    addcolor.g = float(g) / 255.0
                    addcolor.b = float(b) / 255.0
                    addcolor.a = float(a) / 255.0
                    self.vprint(f"{prefix}        Add Color: {addcolor}", component="tags")

                if flags & 0x2000:
                    # Multiplicative color present, smaller integers.
                    rgba = struct.unpack("<I", ap2data[chunk_offset : (chunk_offset + 4)])[0]
                    self.add_coverage(chunk_offset, 4)
                    chunk_offset += 4

                    multcolor.r = float((rgba >> 24) & 0xFF) / 255.0
                    multcolor.g = float((rgba >> 16) & 0xFF) / 255.0
                    multcolor.b = float((rgba >> 8) & 0xFF) / 255.0
                    multcolor.a = float(rgba & 0xFF) / 255.0
                    self.vprint(f"{prefix}        Mult Color: {multcolor}", component="tags")

                if flags & 0x4000:
                    # Additive color present, smaller integers.
                    rgba = struct.unpack("<I", ap2data[chunk_offset : (chunk_offset + 4)])[0]
                    self.add_coverage(chunk_offset, 4)
                    chunk_offset += 4

                    addcolor.r = float((rgba >> 24) & 0xFF) / 255.0
                    addcolor.g = float((rgba >> 16) & 0xFF) / 255.0
                    addcolor.b = float((rgba >> 8) & 0xFF) / 255.0
                    addcolor.a = float(rgba & 0xFF) / 255.0
                    self.vprint(f"{prefix}        Add Color: {addcolor}", component="tags")

                if flags & 0x8000:
                    # Some sort of filter data? Not sure what this is either. Needs more investigation
                    # if I encounter files with it.
                    count, filter_size = struct.unpack("<HH", ap2data[chunk_offset : (chunk_offset + 4)])
                    self.add_coverage(chunk_offset, 4)
                    running_pointer += filter_size

                    # TODO: This is not understood at all. I need to find data that uses it to continue.
                    # running_pointer + 4 starts a series of shorts (exactly count of them) which are
                    # all in the range of 0-7, corresponding to some sort of filter. They get sizes
                    # looked up and I presume there's data following this corresponding to those sizes.
                    # I don't know however as I've not encountered data with this bit.
                    self.vprint(
                        f"{prefix}        Unknown Filter data Count: {count}, Size: {filter_size}",
                        component="tags",
                    )

            for _ in range(bytecode_count):
                loc = struct.unpack("<H", ap2data[running_offset : (running_offset + 2)])[0]
                self.add_coverage(running_offset, 2)
                running_offset += 2

                chunk_offset = dataoffset + loc
                status_bitmask, keycode = struct.unpack("<HBxxxxx", ap2data[chunk_offset : (chunk_offset + 8)])
                self.add_coverage(chunk_offset, 8)

                # TODO: chunk_offset + 8 is a bytecode chunk that needs to be processed with __parse_bytecode
                # but we don't know the length. The game just parses until it hits the end of the buffer or
                # an END tag.

                self.vprint(
                    f"{prefix}      Offset: {hex(loc)}, Bytecode Bitmask: {hex(status_bitmask)}, Keycode: {keycode}",
                    component="tags",
                )
                raise Exception("TODO: Need to examine this section further if I find data with it!")

            # Looks like sound data is either there for 4 button statuses or not there.
            if flags & 0x2:
                sound_count = 4
            else:
                sound_count = 0

            for _ in range(sound_count):
                loc = struct.unpack("<H", ap2data[running_offset : (running_offset + 2)])[0]
                self.add_coverage(running_offset, 2)
                running_offset += 2

                chunk_offset = dataoffset + loc
                unk1, sound_source_tag = struct.unpack("<HH", ap2data[chunk_offset : (chunk_offset + 4)])
                self.add_coverage(chunk_offset, 4)

                self.vprint(
                    f"{prefix}      Offset: {hex(loc)}, Sound Unk1: {unk1}, Source Tag ID: {sound_source_tag}",
                    component="tags",
                )
                raise Exception("TODO: Need to examine this section further if I find data with it!")

            return AP2DefineButtonTag(button_id)
        elif tagid == AP2Tag.AP2_PLACE_CAMERA:
            (
                flags,
                camera_id,
            ) = struct.unpack("<HH", ap2data[dataoffset : (dataoffset + 4)])
            self.add_coverage(dataoffset, 4)
            running_data_ptr = dataoffset + 4

            self.vprint(
                f"{prefix}    Flags: {hex(flags)}, Camera ID: {camera_id}",
                component="tags",
            )

            center = None
            if flags & 0x1:
                i1, i2, i3 = struct.unpack("<iii", ap2data[running_data_ptr : (running_data_ptr + 12)])
                self.add_coverage(running_data_ptr, 12)
                running_data_ptr += 12

                # This is the camera's X/Y/Z position in the scene, looking "down" at the canvas.
                center = Point(i1 / 20.0, i2 / 20.0, i3 / 20.0)
                self.vprint(f"{prefix}      Camera Center: {center}", component="tags")

            focal_length = 0.0
            if flags & 0x2:
                i4 = struct.unpack("<i", ap2data[running_data_ptr : (running_data_ptr + 4)])[0]
                self.add_coverage(running_data_ptr, 4)
                running_data_ptr += 4

                # This is the focal length of the camera, used to construct the FOV.
                focal_length = i4 / 20.0

                self.vprint(f"{prefix}      Focal Length: {focal_length}", component="tags")

            if dataoffset + size != running_data_ptr:
                raise Exception(f"Failed to parse {dataoffset + size - running_data_ptr} bytes of data!")

            return AP2PlaceCameraTag(camera_id, center, focal_length)
        elif tagid == AP2Tag.AP2_IMAGE:
            if size != 8:
                raise Exception(f"Invalid size {size} to get data from AP2_IMAGE!")
            flags, image_id, image_str_ptr = struct.unpack("<IHH", ap2data[dataoffset : (dataoffset + 8)])
            image_str = self.__get_string(image_str_ptr)
            self.add_coverage(dataoffset, 8)

            if flags & 0x2:
                # This looks like we prepend "SWFA-" to the file name.
                image_str = f"SWFA-{image_str}"

            self.vprint(
                f"{prefix}    Tag ID: {image_id}, Flags: {hex(flags)}, String: {image_str}",
                component="tags",
            )

            return AP2ImageTag(image_id, image_str)
        else:
            self.vprint(
                f"Unknown tag {hex(tagid)} with data {ap2data[dataoffset:(dataoffset + size)]!r}",
                component="tags",
            )
            raise Exception(f"Unimplemented tag {hex(tagid)}!")

    def __parse_tags(
        self,
        ap2_version: int,
        afp_version: int,
        ap2data: bytes,
        tags_base_offset: int,
        sprite: Optional[int],
        prefix: str = "",
    ) -> Tuple[List[Tag], List[Frame], Dict[str, int]]:
        (
            name_reference_flags,
            name_reference_count,
            frame_count,
            tags_count,
            name_reference_offset,
            frame_offset,
            tags_offset,
        ) = struct.unpack("<HHIIIII", ap2data[tags_base_offset : (tags_base_offset + 24)])
        self.add_coverage(tags_base_offset, 24)

        # Fix up pointers.
        tags_offset += tags_base_offset
        name_reference_offset += tags_base_offset
        frame_offset += tags_base_offset

        # First, parse frames.
        frames: List[Frame] = []
        tag_to_frame: Dict[int, str] = {}
        self.vprint(f"{prefix}Number of Frames: {frame_count}", component="tags")
        for i in range(frame_count):
            frame_info = struct.unpack("<I", ap2data[frame_offset : (frame_offset + 4)])[0]
            self.add_coverage(frame_offset, 4)

            start_tag_offset = frame_info & 0xFFFFF
            num_tags_to_play = (frame_info >> 20) & 0xFFF
            frames.append(Frame(start_tag_offset, num_tags_to_play))

            self.vprint(
                f"{prefix}  Frame Start Tag: {start_tag_offset}, Count: {num_tags_to_play}",
                component="tags",
            )
            for j in range(num_tags_to_play):
                if start_tag_offset + j in tag_to_frame:
                    raise Exception("Logic error!")
                tag_to_frame[start_tag_offset + j] = f"frame_{i}"
            frame_offset += 4

        # Now, parse regular tags.
        tags: List[Tag] = []
        self.vprint(f"{prefix}Number of Tags: {tags_count}", component="tags")
        for i in range(tags_count):
            tag = struct.unpack("<I", ap2data[tags_offset : (tags_offset + 4)])[0]
            self.add_coverage(tags_offset, 4)

            tagid = (tag >> 22) & 0x3FF
            size = tag & 0x3FFFFF

            if size > 0x200000:
                raise Exception(f"Invalid tag size {size} ({hex(size)})")

            self.vprint(
                f"{prefix}  Tag: {hex(tagid)} ({AP2Tag.tag_to_name(tagid)}), Size: {hex(size)}, Offset: {hex(tags_offset + 4)}",
                component="tags",
            )
            tags.append(
                self.__parse_tag(
                    ap2_version,
                    afp_version,
                    ap2data,
                    tagid,
                    size,
                    tags_offset + 4,
                    sprite,
                    tag_to_frame.get(i, "orphan"),
                    prefix=prefix,
                )
            )
            tags_offset += (
                (size + 3) & 0xFFFFFFFC
            ) + 4  # Skip past tag header and data, rounding to the nearest 4 bytes.

        # Finally, parse frame labels
        self.vprint(
            f"{prefix}Number of Frame Labels: {name_reference_count}, Flags: {hex(name_reference_flags)}",
            component="tags",
        )
        labels: Dict[str, int] = {}
        for _ in range(name_reference_count):
            frameno, stringoffset = struct.unpack("<HH", ap2data[name_reference_offset : (name_reference_offset + 4)])
            strval = self.__get_string(stringoffset)
            self.add_coverage(name_reference_offset, 4)
            labels[strval] = frameno

            self.vprint(f"{prefix}  Frame Number: {frameno}, Name: {strval}", component="tags")
            name_reference_offset += 4

        return tags, frames, labels

    def __descramble(self, scrambled_data: bytes, descramble_info: bytes) -> bytes:
        swap_len = {
            1: 2,
            2: 4,
            3: 8,
        }

        data = bytearray(scrambled_data)
        data_offset = 0
        for i in range(0, len(descramble_info), 2):
            swapword = struct.unpack("<H", descramble_info[i : (i + 2)])[0]
            if swapword == 0:
                break

            offset = (swapword & 0x7F) * 2
            swap_type = (swapword >> 13) & 0x7
            loops = (swapword >> 7) & 0x3F
            data_offset += offset

            if swap_type == 0:
                # Just jump forward based on loops
                data_offset += 256 * loops
                continue

            if swap_type not in swap_len:
                raise Exception(f"Unknown swap type {swap_type}!")

            # Reverse the bytes
            for _ in range(loops + 1):
                data[data_offset : (data_offset + swap_len[swap_type])] = data[
                    data_offset : (data_offset + swap_len[swap_type])
                ][::-1]
                data_offset += swap_len[swap_type]

        return bytes(data)

    def __descramble_stringtable(self, scrambled_data: bytes, stringtable_offset: int, stringtable_size: int) -> bytes:
        data = bytearray(scrambled_data)
        curstring: List[int] = []
        curloc = stringtable_offset

        addition = 128
        for i in range(stringtable_size):
            byte = (data[stringtable_offset + i] - addition) & 0xFF
            data[stringtable_offset + i] = byte
            addition += 1

            if byte == 0:
                if curstring:
                    # We found a string!
                    self.__strings[curloc - stringtable_offset] = (
                        bytes(curstring).decode("utf8"),
                        False,
                    )
                    curloc = stringtable_offset + i + 1
                    curstring = []
                curloc = stringtable_offset + i + 1
            else:
                curstring.append(byte)

        if curstring:
            raise Exception("Logic error!")

        if 0 in self.__strings:
            raise Exception("Should not include null string!")

        return bytes(data)

    def __get_string(self, offset: int) -> str:
        if offset == 0:
            return ""

        self.__strings[offset] = (self.__strings[offset][0], True)
        return self.__strings[offset][0]

    def parse(self, verbose: bool = False) -> None:
        with self.covered(len(self.data), verbose):
            with self.debugging(verbose):
                self.__parse(verbose)

    def __parse(self, verbose: bool) -> None:
        # First, use the byteswap header to descramble the data.
        data = self.__descramble(self.data, self.descramble_info)

        # Start with the basic file header.
        (
            magic,
            length,
            version,
            nameoffset,
            flags,
            left,
            right,
            top,
            bottom,
        ) = struct.unpack("<4sIHHIHHHH", data[0:24])
        self.add_coverage(0, 24)

        ap2_data_version = magic[0] & 0xFF
        magic = bytes([magic[3] & 0x7F, magic[2] & 0x7F, magic[1] & 0x7F, 0x0])
        if magic != b"AP2\x00":
            raise Exception(f"Unrecognzied magic {magic}!")
        if length != len(data):
            raise Exception(f"Unexpected length in AFP header, {length} != {len(data)}!")
        if ap2_data_version not in [7, 8, 9, 10]:
            raise Exception(f"Unsupported AP2 container version {ap2_data_version}!")
        if version != 0x200:
            raise Exception(f"Unsupported AP2 version {version}!")

        # The container version is analogous to the SWF file version. I'm pretty sure it
        # dictates certain things like what properties are available. These appear strictly
        # additive so we don't concern ourselves with this.
        self.container_version = ap2_data_version

        # The data version is basically used for how to parse tags. There was an older data
        # version 0x100 that used more SWF-like bit-packed tags and while lots of code exists
        # to parse this, the AP2 libraries will reject SWF data with this version.
        self.data_version = version

        # As far as I can tell, most things only care about the width and height of this
        # movie, and I think the Shapes are rendered based on the width/height. However, it
        # can have a non-zero x/y offset and I think this is used when rendering multiple
        # movie clips?
        self.location = Rectangle(left=left, right=right, top=top, bottom=bottom)

        if flags & 0x1:
            # This appears to be the animation background color.
            rgba = struct.unpack("<I", data[28:32])[0]
            self.color = Color(
                r=(rgba & 0xFF) / 255.0,
                g=((rgba >> 8) & 0xFF) / 255.0,
                b=((rgba >> 16) & 0xFF) / 255.0,
                a=((rgba >> 24) & 0xFF) / 255.0,
            )
        else:
            self.color = None
        self.add_coverage(28, 4)

        if flags & 0x2:
            # FPS can be either an integer or a float.
            self.fps = struct.unpack("<i", data[24:28])[0] / 1024.0
        else:
            self.fps = struct.unpack("<f", data[24:28])[0]
        self.add_coverage(24, 4)

        if flags & 0x4:
            # This seems related to imported tags.
            imported_tag_initializers_offset = struct.unpack("<I", data[56:60])[0]
            self.add_coverage(56, 4)
        else:
            # Imported tag initializer bytecode not present.
            imported_tag_initializers_offset = None

        # String table
        stringtable_offset, stringtable_size = struct.unpack("<II", data[48:56])
        self.add_coverage(48, 8)

        # Descramble string table.
        data = self.__descramble_stringtable(data, stringtable_offset, stringtable_size)
        self.add_coverage(stringtable_offset, stringtable_size)

        # Get exported SWF name.
        self.exported_name = self.__get_string(nameoffset)
        self.vprint(f"{os.linesep}AFP name: {self.name}", component="core")
        self.vprint(f"Container Version: {hex(self.container_version)}", component="core")
        self.vprint(f"Version: {hex(self.data_version)}", component="core")
        self.vprint(f"Exported Name: {self.exported_name}", component="core")
        self.vprint(f"SWF Flags: {hex(flags)}", component="core")
        if flags & 0x1:
            self.vprint(f"  0x1: Movie background color: {self.color}", component="core")
        else:
            self.vprint("  0x1: No movie background color", component="core")
        if flags & 0x2:
            self.vprint("  0x2: FPS is an integer", component="core")
        else:
            self.vprint("  0x2: FPS is a float", component="core")
        if flags & 0x4:
            self.vprint("  0x4: Imported tag initializer section present", component="core")
        else:
            self.vprint("  0x4: Imported tag initializer section not present", component="core")
        self.vprint(
            f"Dimensions: {int(self.location.width)}x{int(self.location.height)}",
            component="core",
        )
        self.vprint(f"Requested FPS: {self.fps}", component="core")

        # Exported assets
        num_exported_assets = struct.unpack("<H", data[32:34])[0]
        asset_offset = struct.unpack("<I", data[40:44])[0]
        self.add_coverage(32, 2)
        self.add_coverage(40, 4)

        # Parse exported asset tag names and their tag IDs.
        self.exported_tags = {}
        self.vprint(f"Number of Exported Tags: {num_exported_assets}", component="tags")
        for assetno in range(num_exported_assets):
            asset_tag_id, asset_string_offset = struct.unpack("<HH", data[asset_offset : (asset_offset + 4)])
            self.add_coverage(asset_offset, 4)
            asset_offset += 4

            asset_name = self.__get_string(asset_string_offset)
            self.exported_tags[asset_name] = asset_tag_id

            self.vprint(
                f"  {assetno}: Tag Name: {asset_name}, Tag ID: {asset_tag_id}",
                component="tags",
            )

        # Tag sections
        tags_offset = struct.unpack("<I", data[36:40])[0]
        self.add_coverage(36, 4)
        self.tags, self.frames, self.labels = self.__parse_tags(ap2_data_version, version, data, tags_offset, None)

        # Imported tags sections
        imported_tags_count = struct.unpack("<h", data[34:36])[0]
        imported_tags_offset = struct.unpack("<I", data[44:48])[0]
        imported_tags_data_offset = imported_tags_offset + 4 * imported_tags_count
        self.add_coverage(34, 2)
        self.add_coverage(44, 4)

        self.vprint(f"Number of Imported Tags: {imported_tags_count}", component="tags")
        self.imported_tags = {}
        for _ in range(imported_tags_count):
            # First grab the SWF this is importing from, and the number of assets being imported.
            swf_name_offset, count = struct.unpack("<HH", data[imported_tags_offset : (imported_tags_offset + 4)])
            self.add_coverage(imported_tags_offset, 4)

            swf_name = self.__get_string(swf_name_offset)
            self.vprint(f"  Source SWF: {swf_name}", component="tags")

            # Now, grab the actual asset names being imported.
            for _ in range(count):
                asset_id_no, asset_name_offset = struct.unpack(
                    "<HH",
                    data[imported_tags_data_offset : (imported_tags_data_offset + 4)],
                )
                self.add_coverage(imported_tags_data_offset, 4)

                asset_name = self.__get_string(asset_name_offset)
                self.imported_tags[asset_id_no] = NamedTagReference(swf_name=swf_name, tag_name=asset_name)

                self.vprint(
                    f"    Tag ID: {asset_id_no}, Requested Asset: {asset_name}",
                    component="tags",
                )

                imported_tags_data_offset += 4

            imported_tags_offset += 4

        # This appears to be bytecode to execute on a per-frame basis. We execute this every frame and
        # only execute up to the point where we equal the current frame.
        if imported_tag_initializers_offset is not None:
            unk1, length = struct.unpack(
                "<HH",
                data[imported_tag_initializers_offset : (imported_tag_initializers_offset + 4)],
            )
            self.add_coverage(imported_tag_initializers_offset, 4)

            self.vprint(
                f"Imported Tag Initializer Offset: {hex(imported_tag_initializers_offset)}, Length: {length}",
                component="tags",
            )

            for i in range(length):
                item_offset = imported_tag_initializers_offset + 4 + (i * 12)
                (
                    tag_id,
                    frame,
                    action_bytecode_offset,
                    action_bytecode_length,
                ) = struct.unpack("<HHII", data[item_offset : (item_offset + 12)])
                self.add_coverage(item_offset, 12)

                bytecode: Optional[ByteCode] = None
                if action_bytecode_length != 0:
                    self.vprint(
                        f"  Tag ID: {tag_id}, Frame: {frame}, ByteCode Offset: {hex(action_bytecode_offset + imported_tag_initializers_offset)}",
                        component="tags",
                    )
                    bytecode_data = data[
                        (action_bytecode_offset + imported_tag_initializers_offset) : (
                            action_bytecode_offset + imported_tag_initializers_offset + action_bytecode_length
                        )
                    ]
                    bytecode = self.__parse_bytecode(f"on_import_tag_{tag_id}", bytecode_data)
                else:
                    self.vprint(
                        f"  Tag ID: {tag_id}, Frame: {frame}, No ByteCode Present",
                        component="tags",
                    )

                # Add it to the frame's instructions
                if frame >= len(self.frames):
                    raise Exception(f"Unexpected frame {frame}, we only have {len(self.frames)} frames in this movie!")
                self.frames[frame].imported_tags.append(TagPointer(tag_id, bytecode))

        if verbose:
            self.print_coverage()

        self.parsed = True
