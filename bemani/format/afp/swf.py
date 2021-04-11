from hashlib import md5
import os
import struct
import sys
from typing import Any, Dict, List, Tuple

from .types import Matrix, Color, Point, Rectangle
from .types import AP2Action, AP2Tag, AP2Property
from .util import TrackedCoverage, VerboseOutput, _hex


class SWF(TrackedCoverage, VerboseOutput):
    def __init__(
        self,
        name: str,
        data: bytes,
        descramble_info: bytes = b"",
    ) -> None:
        # First, init the coverage engine.
        super().__init__()

        # Now, initialize parsed data.
        self.name = name
        self.exported_name = ""
        self.data = data
        self.descramble_info = descramble_info

        # Initialize string table. This is used for faster lookup of strings
        # as well as tracking which strings in the table have been parsed correctly.
        self.strings: Dict[int, Tuple[str, bool]] = {}

    def print_coverage(self) -> None:
        # First print uncovered bytes
        super().print_coverage()

        # Now, print uncovered strings
        for offset, (string, covered) in self.strings.items():
            if covered:
                continue

            print(f"Uncovered string: {hex(offset)} - {string}", file=sys.stderr)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'data': "".join(_hex(x) for x in self.data),
            'descramble_info': "".join(_hex(x) for x in self.descramble_info),
        }

    def __parse_bytecode(self, datachunk: bytes, string_offsets: List[int] = [], prefix: str = "") -> None:
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
                string_offsets = list(struct.unpack("<" + ("H" * string_offsets_count), datachunk[4:(4 + (2 * string_offsets_count))]))

            offset_ptr = (string_offsets_count + 2) * 2
        else:
            # The data directly follows, no pointer.
            offset_ptr = 2
        start_offset = offset_ptr

        self.vprint(f"{prefix}    Flags: {hex(flags)}, Bytecode Actual Offset: {hex(offset_ptr)}")

        # Actually parse out the opcodes:
        while offset_ptr < len(datachunk):
            # We leave it up to the individual opcode handlers to increment the offset pointer. By default, parameterless
            # opcodes increase by one. Everything else increases by its own amount. Opcode parsing here is done in big-endian
            # as the game code seems to always parse big-endian values.
            opcode = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
            action_name = AP2Action.action_to_name(opcode)

            # Because the starting offset is non-zero, we calculate this here as a convenience for displaying. It means
            # that line numbers for opcodes start at 0 but we have to fix up offsets for jumps by the start_offset.
            lineno = offset_ptr - start_offset

            if opcode in AP2Action.actions_without_params():
                self.vprint(f"{prefix}      {lineno}: {action_name}")
                offset_ptr += 1
            elif opcode == AP2Action.DEFINE_FUNCTION2:
                function_flags, funcname_offset, bytecode_offset, _, bytecode_count = struct.unpack(
                    ">HHHBH",
                    datachunk[(offset_ptr + 1):(offset_ptr + 10)],
                )

                if funcname_offset == 0:
                    funcname = "<anonymous function>"
                else:
                    funcname = self.__get_string(funcname_offset)
                offset_ptr += 10 + (3 * bytecode_offset)

                self.vprint(f"{prefix}      {lineno}: {action_name} Flags: {hex(function_flags)}, Name: {funcname}, Bytecode Offset: {hex(bytecode_offset)}, Bytecode Length: {hex(bytecode_count)}")
                self.__parse_bytecode(datachunk[offset_ptr:(offset_ptr + bytecode_count)], string_offsets=string_offsets, prefix=prefix + "    ")
                self.vprint(f"{prefix}      END_{action_name}")

                offset_ptr += bytecode_count
            elif opcode == AP2Action.PUSH:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}")

                while obj_count > 0:
                    obj_to_create = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                    offset_ptr += 1

                    if obj_to_create == 0x0:
                        # Integer "0" object.
                        self.vprint(f"{prefix}        INTEGER: 0")
                    elif obj_to_create == 0x1:
                        # Float object, represented internally as a double.
                        fval = struct.unpack(">f", datachunk[offset_ptr:(offset_ptr + 4)])[0]
                        offset_ptr += 4

                        self.vprint(f"{prefix}        FLOAT: {fval}")
                    elif obj_to_create == 0x2:
                        # Null pointer object.
                        self.vprint(f"{prefix}        NULL")
                    elif obj_to_create == 0x3:
                        # Undefined constant.
                        self.vprint(f"{prefix}        UNDEFINED")
                    elif obj_to_create == 0x4:
                        # Register value.
                        regno = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        offset_ptr += 1

                        self.vprint(f"{prefix}        REGISTER NO: {regno}")
                    elif obj_to_create == 0x5:
                        # Boolean "TRUE" object.
                        self.vprint(f"{prefix}        BOOLEAN: True")
                    elif obj_to_create == 0x6:
                        # Boolean "FALSE" object.
                        self.vprint(f"{prefix}        BOOLEAN: False")
                    elif obj_to_create == 0x7:
                        # Integer object.
                        ival = struct.unpack(">I", datachunk[offset_ptr:(offset_ptr + 4)])[0]
                        offset_ptr += 4

                        self.vprint(f"{prefix}        INTEGER: {ival}")
                    elif obj_to_create == 0x8:
                        # String constant object.
                        const_offset = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        offset_ptr += 1

                        self.vprint(f"{prefix}        STRING CONST: {const}")
                    elif obj_to_create == 0x9:
                        # String constant, but with 16 bits for the offset. Probably not used except
                        # on the largest files.
                        const_offset = struct.unpack(">H", datachunk[offset_ptr:(offset_ptr + 2)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        offset_ptr += 2

                        self.vprint(f"{prefix}        STRING_CONTS: {const}")
                    elif obj_to_create == 0xa:
                        # NaN constant.
                        self.vprint(f"{prefix}        NAN")
                    elif obj_to_create == 0xb:
                        # Infinity constant.
                        self.vprint(f"{prefix}        INFINITY")
                    elif obj_to_create == 0xc:
                        # Pointer to "this" object, whatever currently is executing the bytecode.
                        self.vprint(f"{prefix}        POINTER TO THIS")
                    elif obj_to_create == 0xd:
                        # Pointer to "root" object, which is the movieclip this bytecode exists in.
                        self.vprint(f"{prefix}        POINTER TO ROOT")
                    elif obj_to_create == 0xe:
                        # Pointer to "parent" object, whatever currently is executing the bytecode.
                        # This seems to be the parent of the movie clip, or the current movieclip
                        # if that isn't set.
                        self.vprint(f"{prefix}        POINTER TO PARENT")
                    elif obj_to_create == 0xf:
                        # Current movie clip.
                        self.vprint(f"{prefix}        POINTER TO CURRENT MOVIECLIP")
                    elif obj_to_create == 0x10:
                        # Unknown property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x100
                        offset_ptr += 1
                        self.vprint(f"{prefix}        PROPERTY CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x13:
                        # Class property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x300
                        offset_ptr += 1
                        self.vprint(f"{prefix}        CLASS CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x16:
                        # Func property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x400
                        offset_ptr += 1
                        self.vprint(f"{prefix}        FUNC CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x19:
                        # Other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x200
                        offset_ptr += 1
                        self.vprint(f"{prefix}        OTHER CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x1c:
                        # Event property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x500
                        offset_ptr += 1
                        self.vprint(f"{prefix}        EVENT CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x1f:
                        # Key constants.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x600
                        offset_ptr += 1
                        self.vprint(f"{prefix}        KEY CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x22:
                        # Pointer to global object.
                        self.vprint(f"{prefix}        POINTER TO GLOBAL OBJECT")
                    elif obj_to_create == 0x24:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x700
                        offset_ptr += 1
                        self.vprint(f"{prefix}        ETC2 CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x27:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x800
                        offset_ptr += 1
                        self.vprint(f"{prefix}        ORGFUNC2 CONST NAME: {AP2Property.property_to_name(propertyval)}")
                    elif obj_to_create == 0x37:
                        # Integer object but one byte.
                        ival = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        offset_ptr += 1

                        self.vprint(f"{prefix}        INTEGER: {ival}")
                    else:
                        raise Exception(f"Unsupported object {hex(obj_to_create)} to push!")

                    obj_count -= 1

                self.vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.STORE_REGISTER:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}")

                while obj_count > 0:
                    register_no = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                    offset_ptr += 1
                    obj_count -= 1

                    self.vprint(f"{prefix}        REGISTER NO: {register_no}")
                self.vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.STORE_REGISTER2:
                register_no = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name}")
                self.vprint(f"{prefix}        REGISTER NO: {register_no}")
                self.vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.IF:
                jump_if_true_offset = struct.unpack(">H", datachunk[(offset_ptr + 1):(offset_ptr + 3)])[0]
                offset_ptr += 3

                # TODO: This can jump outside of a function definition, most commonly seen when jumping to an
                # "END" pointer at the end of a chunk. We need to handle this. We probably need function lines
                # to be absolute instead of relative.
                jump_if_true_offset += offset_ptr - start_offset

                self.vprint(f"{prefix}      {lineno}: Offset If True: {jump_if_true_offset}")
            elif opcode == AP2Action.IF2:
                if2_type, jump_if_true_offset = struct.unpack(">BH", datachunk[(offset_ptr + 1):(offset_ptr + 4)])
                offset_ptr += 4

                # TODO: This can jump outside of a function definition, most commonly seen when jumping to an
                # "END" pointer at the end of a chunk. We need to handle this. We probably need function lines
                # to be absolute instead of relative.
                jump_if_true_offset += offset_ptr - start_offset

                if2_typestr = {
                    0: "==",
                    1: "!=",
                    2: "<",
                    3: ">",
                    4: "<=",
                    5: ">=",
                    6: "!",
                    7: "BITAND",
                    8: "BITNOTAND",
                    9: "STRICT ==",
                    10: "STRICT !=",
                    11: "IS UNDEFINED",
                    12: "IS NOT UNDEFINED",
                }[if2_type]

                self.vprint(f"{prefix}      {lineno}: {action_name} {if2_typestr}, Offset If True: {jump_if_true_offset}")
            elif opcode == AP2Action.JUMP:
                jump_offset = struct.unpack(">H", datachunk[(offset_ptr + 1):(offset_ptr + 3)])[0]
                offset_ptr += 3

                # TODO: This can jump outside of a function definition, most commonly seen when jumping to an
                # "END" pointer at the end of a chunk. We need to handle this. We probably need function lines
                # to be absolute instead of relative.
                jump_offset += offset_ptr - start_offset
                self.vprint(f"{prefix}      {lineno}: {action_name} Offset: {jump_offset}")
            elif opcode == AP2Action.ADD_NUM_VARIABLE:
                amount_to_add = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name} Add Value: {amount_to_add}")
            elif opcode == AP2Action.START_DRAG:
                constraint = struct.unpack(">b", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                self.vprint(f"{prefix}      {lineno}: {action_name} Constrain Mouse: {'yes' if constraint > 0 else ('no' if constraint == 0 else 'check stack')}")
            elif opcode == AP2Action.ADD_NUM_REGISTER:
                register_no, amount_to_add = struct.unpack(">BB", datachunk[(offset_ptr + 1):(offset_ptr + 3)])
                offset_ptr += 3

                self.vprint(f"{prefix}      {lineno}: {action_name} Register No: {register_no}, Add Value: {amount_to_add}")
            elif opcode == AP2Action.GOTO_FRAME2:
                flags = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                if flags & 0x1:
                    post = "STOP"
                else:
                    post = "PLAY"

                if flags & 0x2:
                    # Additional frames to add on top of stack value.
                    additional_frames = struct.unpack(">H", datachunk[offset_ptr:(offset_ptr + 2)])[0]
                    offset_ptr += 2
                else:
                    additional_frames = 0

                self.vprint(f"{prefix}      {lineno}: {action_name} AND {post} Additional Frames: {additional_frames}")
            else:
                raise Exception(f"Can't advance, no handler for opcode {opcode} ({hex(opcode)})!")

    def __parse_tag(self, ap2_version: int, afp_version: int, ap2data: bytes, tagid: int, size: int, dataoffset: int, prefix: str = "") -> None:
        if tagid == AP2Tag.AP2_SHAPE:
            if size != 4:
                raise Exception(f"Invalid shape size {size}")

            _, shape_id = struct.unpack("<HH", ap2data[dataoffset:(dataoffset + 4)])
            self.add_coverage(dataoffset, size)

            shape_reference = f"{self.exported_name}_shape{shape_id}"
            self.vprint(f"{prefix}    Tag ID: {shape_id}, AFP Reference: {shape_reference}, IFS GEO Filename: {md5(shape_reference.encode('utf-8')).hexdigest()}")
        elif tagid == AP2Tag.AP2_DEFINE_SPRITE:
            sprite_flags, sprite_id = struct.unpack("<HH", ap2data[dataoffset:(dataoffset + 4)])
            self.add_coverage(dataoffset, 4)

            if sprite_flags & 1 == 0:
                # This is an old-style tag, it has data directly following the header.
                subtags_offset = dataoffset + 4
            else:
                # This is a new-style tag, it has a relative data pointer.
                subtags_offset = struct.unpack("<I", ap2data[(dataoffset + 4):(dataoffset + 8)])[0] + dataoffset
                self.add_coverage(dataoffset + 4, 4)

            self.vprint(f"{prefix}    Tag ID: {sprite_id}")
            self.__parse_tags(ap2_version, afp_version, ap2data, subtags_offset, prefix="      " + prefix)
        elif tagid == AP2Tag.AP2_DEFINE_FONT:
            unk, font_id, fontname_offset, xml_prefix_offset, data_offset, data_count = struct.unpack("<HHHHHH", ap2data[dataoffset:(dataoffset + 12)])
            self.add_coverage(dataoffset, 12)

            fontname = self.__get_string(fontname_offset)
            xml_prefix = self.__get_string(xml_prefix_offset)

            self.vprint(f"{prefix}    Tag ID: {font_id}, Font Name: {fontname}, XML Prefix: {xml_prefix}, Entries: {data_count}")

            for i in range(data_count):
                entry_offset = dataoffset + 12 + (data_offset * 2) + (i * 2)
                entry_value = struct.unpack("<H", ap2data[entry_offset:(entry_offset + 2)])[0]
                self.add_coverage(entry_offset, 2)

                self.vprint(f"{prefix}      Height: {entry_value}")
        elif tagid == AP2Tag.AP2_DO_ACTION:
            datachunk = ap2data[dataoffset:(dataoffset + size)]
            self.__parse_bytecode(datachunk, prefix=prefix)
            self.add_coverage(dataoffset, size)
        elif tagid == AP2Tag.AP2_PLACE_OBJECT:
            # Allow us to keep track of what we've consumed.
            datachunk = ap2data[dataoffset:(dataoffset + size)]
            flags, depth, object_id = struct.unpack("<IHH", datachunk[0:8])
            self.add_coverage(dataoffset, 8)

            self.vprint(f"{prefix}    Flags: {hex(flags)}, Object ID: {object_id}, Depth: {depth}")

            running_pointer = 8
            unhandled_flags = flags

            if flags & 0x2:
                unhandled_flags &= ~0x2
                src_tag_id = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                self.vprint(f"{prefix}    Source Tag ID: {src_tag_id}")

            if flags & 0x10:
                unhandled_flags &= ~0x10
                unk2 = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                self.vprint(f"{prefix}    Unk2: {hex(unk2)}")

            if flags & 0x20:
                unhandled_flags &= ~0x20
                nameoffset = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                name = self.__get_string(nameoffset)
                running_pointer += 2
                self.vprint(f"{prefix}    Name: {name}")

            if flags & 0x40:
                unhandled_flags &= ~0x40
                unk3 = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                self.add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                self.vprint(f"{prefix}    Unk3: {hex(unk3)}")

            if flags & 0x20000:
                unhandled_flags &= ~0x20000
                blend = struct.unpack("<B", datachunk[running_pointer:(running_pointer + 1)])[0]
                self.add_coverage(dataoffset + running_pointer, 1)
                running_pointer += 1
                self.vprint(f"{prefix}    Blend: {hex(blend)}")

            # Due to possible misalignment, we need to realign.
            misalignment = running_pointer & 3
            if misalignment > 0:
                catchup = 4 - misalignment
                self.add_coverage(dataoffset + running_pointer, catchup)
                running_pointer += catchup

            # Handle transformation matrix.
            transform = Matrix.identity()

            if flags & 0x100:
                unhandled_flags &= ~0x100
                a_int, d_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.a = float(a_int) * 0.0009765625
                transform.d = float(d_int) * 0.0009765625
                self.vprint(f"{prefix}    Transform Matrix A: {transform.a}, D: {transform.d}")

            if flags & 0x200:
                unhandled_flags &= ~0x200
                b_int, c_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.b = float(b_int) * 0.0009765625
                transform.c = float(c_int) * 0.0009765625
                self.vprint(f"{prefix}    Transform Matrix B: {transform.b}, C: {transform.c}")

            if flags & 0x400:
                unhandled_flags &= ~0x400
                tx_int, ty_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.tx = float(tx_int) / 20.0
                transform.ty = float(tx_int) / 20.0
                self.vprint(f"{prefix}    Transform Matrix TX: {transform.tx}, TY: {transform.ty}")

            # Handle object colors
            color = Color(1.0, 1.0, 1.0, 1.0)
            acolor = Color(1.0, 1.0, 1.0, 1.0)

            if flags & 0x800:
                unhandled_flags &= ~0x800
                r, g, b, a = struct.unpack("<HHHH", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                color.r = float(r) * 0.003921569
                color.g = float(g) * 0.003921569
                color.b = float(b) * 0.003921569
                color.a = float(a) * 0.003921569
                self.vprint(f"{prefix}    Color: {color}")

            if flags & 0x1000:
                unhandled_flags &= ~0x1000
                r, g, b, a = struct.unpack("<HHHH", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                acolor.r = float(r) * 0.003921569
                acolor.g = float(g) * 0.003921569
                acolor.b = float(b) * 0.003921569
                acolor.a = float(a) * 0.003921569
                self.vprint(f"{prefix}    AColor: {color}")

            if flags & 0x2000:
                unhandled_flags &= ~0x2000
                rgba = struct.unpack("<I", datachunk[running_pointer:(running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                color.r = float((rgba >> 24) & 0xFF) * 0.003921569
                color.g = float((rgba >> 16) & 0xFF) * 0.003921569
                color.b = float((rgba >> 8) & 0xFF) * 0.003921569
                color.a = float(rgba & 0xFF) * 0.003921569
                self.vprint(f"{prefix}    Color: {color}")

            if flags & 0x4000:
                unhandled_flags &= ~0x4000
                rgba = struct.unpack("<I", datachunk[running_pointer:(running_pointer + 4)])[0]
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                acolor.r = float((rgba >> 24) & 0xFF) * 0.003921569
                acolor.g = float((rgba >> 16) & 0xFF) * 0.003921569
                acolor.b = float((rgba >> 8) & 0xFF) * 0.003921569
                acolor.a = float(rgba & 0xFF) * 0.003921569
                self.vprint(f"{prefix}    AColor: {color}")

            if flags & 0x80:
                # Object event triggers.
                unhandled_flags &= ~0x80
                event_flags, event_size = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)

                if event_flags != 0:
                    _, count = struct.unpack("<HH", datachunk[(running_pointer + 8):(running_pointer + 12)])
                    self.add_coverage(dataoffset + running_pointer + 8, 4)

                    # The game does not seem to care about length here, but we do, so let's calculate
                    # offsets and use that for lengths.
                    bytecode_offsets: List[int] = []
                    for evt in range(count):
                        evt_offset = running_pointer + 12 + (evt * 8)
                        bytecode_offset = struct.unpack("<H", datachunk[(evt_offset + 6):(evt_offset + 8)])[0] + evt_offset
                        bytecode_offsets.append(bytecode_offset)
                    bytecode_offsets.append(event_size + running_pointer)

                    beginning_to_end: Dict[int, int] = {}
                    for i, bytecode_offset in enumerate(bytecode_offsets[:-1]):
                        beginning_to_end[bytecode_offset] = bytecode_offsets[i + 1]

                    self.vprint(f"{prefix}    Event Triggers, Count: {count}")
                    for evt in range(count):
                        evt_offset = running_pointer + 12 + (evt * 8)
                        evt_flags, _, keycode, bytecode_offset = struct.unpack("<IBBH", datachunk[evt_offset:(evt_offset + 8)])
                        self.add_coverage(dataoffset + evt_offset, 8)

                        events: List[str] = []
                        if evt_flags & 0x1:
                            events.append("ON_LOAD")
                        if evt_flags & 0x2:
                            events.append("ON_ENTER_FRAME")
                        if evt_flags & 0x4:
                            events.append("ON_UNLOAD")
                        if evt_flags & 0x8:
                            events.append("ON_MOUSE_MOVE")
                        if evt_flags & 0x10:
                            events.append("ON_MOUSE_DOWN")
                        if evt_flags & 0x20:
                            events.append("ON_MOUSE_UP")
                        if evt_flags & 0x40:
                            events.append("ON_KEY_DOWN")
                        if evt_flags & 0x80:
                            events.append("ON_KEY_UP")
                        if evt_flags & 0x100:
                            events.append("ON_DATA")
                        if evt_flags & 0x400:
                            events.append("ON_PRESS")
                        if evt_flags & 0x800:
                            events.append("ON_RELEASE")
                        if evt_flags & 0x1000:
                            events.append("ON_RELEASE_OUTSIDE")
                        if evt_flags & 0x2000:
                            events.append("ON_ROLL_OVER")
                        if evt_flags & 0x4000:
                            events.append("ON_ROLL_OUT")

                        bytecode_offset += evt_offset
                        bytecode_length = beginning_to_end[bytecode_offset] - bytecode_offset

                        self.vprint(f"{prefix}      Flags: {hex(evt_flags)} ({', '.join(events)}), KeyCode: {hex(keycode)}, Bytecode Offset: {hex(dataoffset + bytecode_offset)}, Length: {bytecode_length}")
                        self.__parse_bytecode(datachunk[bytecode_offset:(bytecode_offset + bytecode_length)], prefix=prefix + "    ")
                        self.add_coverage(dataoffset + bytecode_offset, bytecode_length)

                running_pointer += event_size

            if flags & 0x10000:
                # Some sort of filter data? Not sure what this is either. Needs more investigation
                # if I encounter files with it.
                unhandled_flags &= ~0x10000
                count, filter_size = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += filter_size

                # TODO: This is not understood at all. I need to find data that uses it to continue.
                # running_pointer + 4 starts a series of shorts (exactly count of them) which are
                # all in the range of 0-7, corresponding to some sort of filter. They get sizes
                # looked up and I presume there's data following this corresponding to those sizes.
                # I don't know however as I've not encountered data with this bit.
                self.vprint(f"{prefix}    Unknown Filter data Count: {count}, Size: {filter_size}")

            if flags & 0x1000000:
                # Some sort of point, perhaps an x, y offset for the object?
                unhandled_flags &= ~0x1000000
                x, y = struct.unpack("<ff", datachunk[running_pointer:(running_pointer + 8)])
                self.add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                # TODO: This doesn't seem right when run past Pop'n Music data.
                point = Point(x / 20.0, y / 20.0)
                self.vprint(f"{prefix}    Point: {point}")

            if flags & 0x2000000:
                # Same as above, but initializing to 0, 0 instead of from data.
                unhandled_flags &= ~0x2000000
                point = Point(0.0, 0.0)
                self.vprint(f"{prefix}    Point: {point}")

            if flags & 0x40000:
                # Some pair of shorts, not sure, its in DDR PS3 data.
                unhandled_flags &= ~0x40000
                x, y = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                # TODO: I have no idea what these are.
                point = Point(x * 3.051758e-05, y * 3.051758e-05)
                self.vprint(f"{prefix}    Point: {point}")

            if flags & 0x80000:
                # Some pair of shorts, not sure, its in DDR PS3 data.
                unhandled_flags &= ~0x80000
                x, y = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                self.add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                # TODO: I have no idea what these are.
                point = Point(x * 3.051758e-05, y * 3.051758e-05)
                self.vprint(f"{prefix}    Point: {point}")

            # This flag states whether we are creating a new object on this depth, or updating one.
            unhandled_flags &= ~0xD
            if flags & 0x1:
                self.vprint(f"{prefix}    Update object request")
            else:
                self.vprint(f"{prefix}    Create object request")
            if flags & 0x4:
                self.vprint(f"{prefix}    Use transform matrix")
            else:
                self.vprint(f"{prefix}    Ignore transform matrix")
            if flags & 0x4:
                self.vprint(f"{prefix}    Use color information")
            else:
                self.vprint(f"{prefix}    Ignore color information")

            if unhandled_flags != 0:
                raise Exception(f"Did not handle {hex(unhandled_flags)} flag bits!")
            if running_pointer < size:
                raise Exception(f"Did not consume {size - running_pointer} bytes ({[hex(x) for x in datachunk[running_pointer:]]}) in object instantiation!")
            if running_pointer != size:
                raise Exception("Logic error!")

        elif tagid == AP2Tag.AP2_REMOVE_OBJECT:
            if size != 4:
                raise Exception(f"Invalid shape size {size}")

            object_id, depth = struct.unpack("<HH", ap2data[dataoffset:(dataoffset + 4)])
            self.vprint(f"{prefix}    Object ID: {object_id}, Depth: {depth}")
            self.add_coverage(dataoffset, 4)
        elif tagid == AP2Tag.AP2_DEFINE_EDIT_TEXT:
            if size != 44:
                raise Exception("Invalid size {size} to get data from AP2_DEFINE_EDIT_TEXT!")

            flags, edit_text_id, defined_font_tag_id, font_height, unk_str2_offset = struct.unpack("<IHHHH", ap2data[dataoffset:(dataoffset + 12)])
            self.add_coverage(dataoffset, 12)

            unk1, unk2, unk3, unk4 = struct.unpack("<HHHH", ap2data[(dataoffset + 12):(dataoffset + 20)])
            self.add_coverage(dataoffset + 12, 8)

            rgba, f1, f2, f3, f4, variable_name_offset, default_text_offset = struct.unpack("<IiiiiHH", ap2data[(dataoffset + 20):(dataoffset + 44)])
            self.add_coverage(dataoffset + 20, 24)

            self.vprint(f"{prefix}    Tag ID: {edit_text_id}, Font Tag: {defined_font_tag_id}, Height Selection: {font_height}, Flags: {hex(flags)}")

            unk_string2 = self.__get_string(unk_str2_offset) or None
            self.vprint(f"{prefix}      Unk String: {unk_string2}")

            rect = Rectangle(f1 / 20.0, f2 / 20.0, f3 / 20.0, f4 / 20.0)
            self.vprint(f"{prefix}      Rectangle: {rect}")

            variable_name = self.__get_string(variable_name_offset) or None
            self.vprint(f"{prefix}      Variable Name: {variable_name}")

            color = Color(
                r=(rgba & 0xFF) / 255.0,
                g=((rgba >> 8) & 0xFF) / 255.0,
                b=((rgba >> 16) & 0xFF) / 255.0,
                a=((rgba >> 24) & 0xFF) / 255.0,
            )
            self.vprint(f"{prefix}      Text Color: {color}")

            self.vprint(f"{prefix}      Unk1: {unk1}, Unk2: {unk2}, Unk3: {unk3}, Unk4: {unk4}")

            # flags & 0x20 means something with offset 16-18.
            # flags & 0x200 is unk str below is a HTML tag.

            if flags & 0x80:
                # Has some sort of string pointer.
                default_text = self.__get_string(default_text_offset) or None
                self.vprint(f"{prefix}      Default Text: {default_text}")
        else:
            raise Exception(f"Unimplemented tag {hex(tagid)}!")

    def __parse_tags(self, ap2_version: int, afp_version: int, ap2data: bytes, tags_base_offset: int, prefix: str = "") -> None:
        unknown_tags_flags, unknown_tags_count, frame_count, tags_count, unknown_tags_offset, frame_offset, tags_offset = struct.unpack(
            "<HHIIIII",
            ap2data[tags_base_offset:(tags_base_offset + 24)]
        )
        self.add_coverage(tags_base_offset, 24)

        # Fix up pointers.
        tags_offset += tags_base_offset
        unknown_tags_offset += tags_base_offset
        frame_offset += tags_base_offset

        # First, parse regular tags.
        self.vprint(f"{prefix}Number of Tags: {tags_count}")
        for i in range(tags_count):
            tag = struct.unpack("<I", ap2data[tags_offset:(tags_offset + 4)])[0]
            self.add_coverage(tags_offset, 4)

            tagid = (tag >> 22) & 0x3FF
            size = tag & 0x3FFFFF

            if size > 0x200000:
                raise Exception(f"Invalid tag size {size} ({hex(size)})")

            self.vprint(f"{prefix}  Tag: {hex(tagid)} ({AP2Tag.tag_to_name(tagid)}), Size: {hex(size)}, Offset: {hex(tags_offset + 4)}")
            self.__parse_tag(ap2_version, afp_version, ap2data, tagid, size, tags_offset + 4, prefix=prefix)
            tags_offset += ((size + 3) & 0xFFFFFFFC) + 4  # Skip past tag header and data, rounding to the nearest 4 bytes.

        # Now, parse frames.
        self.vprint(f"{prefix}Number of Frames: {frame_count}")
        for i in range(frame_count):
            frame_info = struct.unpack("<I", ap2data[frame_offset:(frame_offset + 4)])[0]
            self.add_coverage(frame_offset, 4)

            start_tag_id = frame_info & 0xFFFFF
            num_tags_to_play = (frame_info >> 20) & 0xFFF

            self.vprint(f"{prefix}  Frame Start Tag: {hex(start_tag_id)}, Count: {num_tags_to_play}")
            frame_offset += 4

        # Now, parse unknown tags? I have no idea what these are, but they're referencing strings that
        # are otherwise unused.
        self.vprint(f"{prefix}Number of Unknown Tags: {unknown_tags_count}, Flags: {hex(unknown_tags_flags)}")
        for i in range(unknown_tags_count):
            unk1, stringoffset = struct.unpack("<HH", ap2data[unknown_tags_offset:(unknown_tags_offset + 4)])
            strval = self.__get_string(stringoffset)
            self.add_coverage(unknown_tags_offset, 4)

            self.vprint(f"{prefix}  Unknown Tag: {hex(unk1)} Name: {strval}")
            unknown_tags_offset += 4

    def __descramble(self, scrambled_data: bytes, descramble_info: bytes) -> bytes:
        swap_len = {
            1: 2,
            2: 4,
            3: 8,
        }

        data = bytearray(scrambled_data)
        data_offset = 0
        for i in range(0, len(descramble_info), 2):
            swapword = struct.unpack("<H", descramble_info[i:(i + 2)])[0]
            if swapword == 0:
                break

            offset = (swapword & 0x7F) * 2
            swap_type = (swapword >> 13) & 0x7
            loops = ((swapword >> 7) & 0x3F)
            data_offset += offset

            if swap_type == 0:
                # Just jump forward based on loops
                data_offset += 256 * loops
                continue

            if swap_type not in swap_len:
                raise Exception(f"Unknown swap type {swap_type}!")

            # Reverse the bytes
            for _ in range(loops + 1):
                data[data_offset:(data_offset + swap_len[swap_type])] = data[data_offset:(data_offset + swap_len[swap_type])][::-1]
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
                    self.strings[curloc - stringtable_offset] = (bytes(curstring).decode('utf8'), False)
                    curloc = stringtable_offset + i + 1
                    curstring = []
                curloc = stringtable_offset + i + 1
            else:
                curstring.append(byte)

        if curstring:
            raise Exception("Logic error!")

        if 0 in self.strings:
            raise Exception("Should not include null string!")

        return bytes(data)

    def __get_string(self, offset: int) -> str:
        if offset == 0:
            return ""

        self.strings[offset] = (self.strings[offset][0], True)
        return self.strings[offset][0]

    def parse(self, verbose: bool = False) -> None:
        with self.covered(len(self.data), verbose):
            with self.debugging(verbose):
                self.__parse(verbose)

    def __parse(self, verbose: bool) -> None:
        # First, use the byteswap header to descramble the data.
        data = self.__descramble(self.data, self.descramble_info)

        # Start with the basic file header.
        magic, length, version, nameoffset, flags, left, right, top, bottom = struct.unpack("<4sIHHIHHHH", data[0:24])
        width = right - left
        height = bottom - top
        self.add_coverage(0, 24)

        ap2_data_version = magic[0] & 0xFF
        magic = bytes([magic[3] & 0x7F, magic[2] & 0x7F, magic[1] & 0x7F, 0x0])
        if magic != b'AP2\x00':
            raise Exception(f"Unrecognzied magic {magic}!")
        if length != len(data):
            raise Exception(f"Unexpected length in AFP header, {length} != {len(data)}!")
        if ap2_data_version not in [8, 9, 10]:
            raise Exception(f"Unsupported AP2 container version {ap2_data_version}!")
        if version != 0x200:
            raise Exception(f"Unsupported AP2 version {version}!")

        if flags & 0x1:
            # This appears to be the animation background color.
            rgba = struct.unpack("<I", data[28:32])[0]
            swf_color = Color(
                r=(rgba & 0xFF) / 255.0,
                g=((rgba >> 8) & 0xFF) / 255.0,
                b=((rgba >> 16) & 0xFF) / 255.0,
                a=((rgba >> 24) & 0xFF) / 255.0,
            )
        else:
            swf_color = None
        self.add_coverage(28, 4)

        if flags & 0x2:
            # FPS can be either an integer or a float.
            fps = struct.unpack("<i", data[24:28])[0] * 0.0009765625
        else:
            fps = struct.unpack("<f", data[24:28])[0]
        self.add_coverage(24, 4)

        if flags & 0x4:
            # This seems related to imported tags.
            imported_tag_initializers_offset = struct.unpack("<I", data[56:60])[0]
            self.add_coverage(56, 4)
        else:
            # Unknown offset is not present.
            imported_tag_initializers_offset = None

        # String table
        stringtable_offset, stringtable_size = struct.unpack("<II", data[48:56])
        self.add_coverage(48, 8)

        # Descramble string table.
        data = self.__descramble_stringtable(data, stringtable_offset, stringtable_size)
        self.add_coverage(stringtable_offset, stringtable_size)

        # Get exported SWF name.
        self.exported_name = self.__get_string(nameoffset)
        self.add_coverage(nameoffset + stringtable_offset, len(self.exported_name) + 1, unique=False)
        self.vprint(f"{os.linesep}AFP name: {self.name}")
        self.vprint(f"Container Version: {hex(ap2_data_version)}")
        self.vprint(f"Version: {hex(version)}")
        self.vprint(f"Exported Name: {self.exported_name}")
        self.vprint(f"SWF Flags: {hex(flags)}")
        if flags & 0x1:
            self.vprint(f"  0x1: Movie background color: {swf_color}")
        else:
            self.vprint("  0x2: No movie background color")
        if flags & 0x2:
            self.vprint("  0x2: FPS is an integer")
        else:
            self.vprint("  0x2: FPS is a float")
        if flags & 0x4:
            self.vprint("  0x4: Imported tag initializer section present")
        else:
            self.vprint("  0x4: Imported tag initializer section not present")
        self.vprint(f"Dimensions: {width}x{height}")
        self.vprint(f"Requested FPS: {fps}")

        # Exported assets
        num_exported_assets = struct.unpack("<H", data[32:34])[0]
        asset_offset = struct.unpack("<I", data[40:44])[0]
        self.add_coverage(32, 2)
        self.add_coverage(40, 4)

        # Parse exported asset tag names and their tag IDs.
        self.vprint(f"Number of Exported Tags: {num_exported_assets}")
        for assetno in range(num_exported_assets):
            asset_data_offset, asset_string_offset = struct.unpack("<HH", data[asset_offset:(asset_offset + 4)])
            self.add_coverage(asset_offset, 4)
            asset_offset += 4

            asset_name = self.__get_string(asset_string_offset)
            self.add_coverage(asset_string_offset + stringtable_offset, len(asset_name) + 1, unique=False)
            self.vprint(f"  {assetno}: Tag Name: {asset_name} Tag ID: {asset_data_offset}")

        # Tag sections
        tags_offset = struct.unpack("<I", data[36:40])[0]
        self.add_coverage(36, 4)
        self.__parse_tags(ap2_data_version, version, data, tags_offset)

        # Imported tags sections
        imported_tags_count = struct.unpack("<h", data[34:36])[0]
        imported_tags_offset = struct.unpack("<I", data[44:48])[0]
        imported_tags_data_offset = imported_tags_offset + 4 * imported_tags_count
        self.add_coverage(34, 2)
        self.add_coverage(44, 4)

        self.vprint(f"Number of Imported Tags: {imported_tags_count}")
        for i in range(imported_tags_count):
            # First grab the SWF this is importing from, and the number of assets being imported.
            swf_name_offset, count = struct.unpack("<HH", data[imported_tags_offset:(imported_tags_offset + 4)])
            self.add_coverage(imported_tags_offset, 4)

            swf_name = self.__get_string(swf_name_offset)
            self.add_coverage(swf_name_offset + stringtable_offset, len(swf_name) + 1, unique=False)
            self.vprint(f"  Source SWF: {swf_name}")

            # Now, grab the actual asset names being imported.
            for j in range(count):
                asset_id_no, asset_name_offset = struct.unpack("<HH", data[imported_tags_data_offset:(imported_tags_data_offset + 4)])
                self.add_coverage(imported_tags_data_offset, 4)

                asset_name = self.__get_string(asset_name_offset)
                self.add_coverage(asset_name_offset + stringtable_offset, len(asset_name) + 1, unique=False)
                self.vprint(f"    Tag ID: {asset_id_no}, Requested Asset: {asset_name}")

                imported_tags_data_offset += 4

            imported_tags_offset += 4

        # This appears to be bytecode to execute on a per-frame basis. We execute this every frame and
        # only execute up to the point where we equal the current frame.
        if imported_tag_initializers_offset is not None:

            unk1, length = struct.unpack("<HH", data[imported_tag_initializers_offset:(imported_tag_initializers_offset + 4)])
            self.add_coverage(imported_tag_initializers_offset, 4)

            self.vprint(f"Imported Tag Initializer Offset: {hex(imported_tag_initializers_offset)}, Length: {length}")

            for i in range(length):
                item_offset = imported_tag_initializers_offset + 4 + (i * 12)
                tag_id, frame, action_bytecode_offset, action_bytecode_length = struct.unpack("<HHII", data[item_offset:(item_offset + 12)])
                self.add_coverage(item_offset, 12)

                if action_bytecode_length != 0:
                    self.vprint(f"  Tag ID: {tag_id}, Frame: {frame}, Bytecode Offset: {hex(action_bytecode_offset + imported_tag_initializers_offset)}")
                    bytecode_data = data[(action_bytecode_offset + imported_tag_initializers_offset):(action_bytecode_offset + imported_tag_initializers_offset + action_bytecode_length)]
                    self.__parse_bytecode(bytecode_data)
                else:
                    self.vprint(f"  Tag ID: {tag_id}, Frame: {frame}, No Bytecode Present")

        if verbose:
            self.print_coverage()
