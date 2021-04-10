import io
from hashlib import md5
import os
import struct
import sys
from PIL import Image  # type: ignore
from typing import Any, Dict, List, Optional, Set, Tuple

from bemani.format.dxt import DXTBuffer
from bemani.protocol.binary import BinaryEncoding
from bemani.protocol.lz77 import Lz77
from bemani.protocol.node import Node


def _hex(data: int) -> str:
    hexval = hex(data)[2:]
    if len(hexval) == 1:
        return "0" + hexval
    return hexval


class PMAN:
    def __init__(
        self,
        entries: List[str] = [],
        ordering: List[int] = [],
        flags1: int = 0,
        flags2: int = 0,
        flags3: int = 0,
    ) -> None:
        self.entries = entries
        self.ordering = ordering
        self.flags1 = flags1
        self.flags2 = flags2
        self.flags3 = flags3

    def as_dict(self) -> Dict[str, Any]:
        return {
            'flags': [self.flags1, self.flags2, self.flags3],
            'entries': self.entries,
            'ordering': self.ordering,
        }


class Texture:
    def __init__(
        self,
        name: str,
        width: int,
        height: int,
        fmt: int,
        header_flags1: int,
        header_flags2: int,
        header_flags3: int,
        fmtflags: int,
        rawdata: bytes,
        compressed: Optional[bytes],
        imgdata: Any,
    ) -> None:
        self.name = name
        self.width = width
        self.height = height
        self.fmt = fmt
        self.header_flags1 = header_flags1
        self.header_flags2 = header_flags2
        self.header_flags3 = header_flags3
        self.fmtflags = fmtflags
        self.raw = rawdata
        self.compressed = compressed
        self.img = imgdata

    def as_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'width': self.width,
            'height': self.height,
            'fmt': self.fmt,
            'header_flags': [self.header_flags1, self.header_flags2, self.header_flags3],
            'fmt_flags': self.fmtflags,
            'raw': "".join(_hex(x) for x in self.raw),
            'compressed': "".join(_hex(x) for x in self.compressed) if self.compressed is not None else None,
        }


class TextureRegion:
    def __init__(self, textureno: int, left: int, top: int, right: int, bottom: int) -> None:
        self.textureno = textureno
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    def as_dict(self) -> Dict[str, Any]:
        return {
            'texture': self.textureno,
            'left': self.left,
            'top': self.top,
            'right': self.right,
            'bottom': self.bottom,
        }

    def __repr__(self) -> str:
        return (
            f"texture: {self.textureno}, " +
            f"left: {self.left / 2}, " +
            f"top: {self.top / 2}, " +
            f"right: {self.right / 2}, " +
            f"bottom: {self.bottom / 2}, " +
            f"width: {(self.right - self.left) / 2}, " +
            f"height: {(self.bottom - self.top) / 2}"
        )


class Matrix:
    def __init__(self, a: float, b: float, c: float, d: float, tx: float, ty: float) -> None:
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.tx = tx
        self.ty = ty

    @staticmethod
    def identity() -> "Matrix":
        return Matrix(1.0, 0.0, 0.0, 1.0, 0.0, 0.0)

    def __repr__(self) -> str:
        return f"a: {round(self.a, 5)}, b: {round(self.b, 5)}, c: {round(self.c, 5)}, d: {round(self.d, 5)}, tx: {round(self.tx, 5)}, ty: {round(self.ty, 5)}"


class Color:
    def __init__(self, r: float, g: float, b: float, a: float) -> None:
        self.r = r
        self.g = g
        self.b = b
        self.a = a

    def as_dict(self) -> Dict[str, Any]:
        return {
            'r': self.r,
            'g': self.g,
            'b': self.b,
            'a': self.a,
        }

    def __repr__(self) -> str:
        return f"r: {round(self.r, 5)}, g: {round(self.g, 5)}, b: {round(self.b, 5)}, a: {round(self.a, 5)}"


class Point:
    def __init__(self, x: float, y: float) -> None:
        self.x = x
        self.y = y

    def as_dict(self) -> Dict[str, Any]:
        return {
            'x': self.x,
            'y': self.y,
        }

    def __repr__(self) -> str:
        return f"x: {round(self.x, 5)}, y: {round(self.y, 5)}"


class Rectangle:
    def __init__(self, left: float, top: float, bottom: float, right: float) -> None:
        self.left = left
        self.top = top
        self.bottom = bottom
        self.right = right

    def as_dict(self) -> Dict[str, Any]:
        return {
            'left': self.left,
            'top': self.top,
            'bottom': self.bottom,
            'right': self.right,
        }

    def __repr__(self) -> str:
        return f"left: {round(self.left, 5)}, top: {round(self.top, 5)}, bottom: {round(self.bottom, 5)}, right: {round(self.right, 5)}"


class AP2Tag:
    END = 0x0
    SHOW_FRAME = 0x1
    DEFINE_SHAPE = 0x2
    PLACE_OBJECT = 0x4
    REMOVE_OBJECT = 0x5
    DEFINE_BITS = 0x6
    DEFINE_BUTTON = 0x7
    JPEG_TABLES = 0x8
    BACKGROUND_COLOR = 0x9
    DEFINE_FONT = 0xa
    DEFINE_TEXT = 0xb
    DO_ACTION = 0xc
    DEFINE_FONT_INFO = 0xd
    DEFINE_SOUND = 0xe
    START_SOUND = 0xf
    DEFINE_BUTTON_SOUND = 0x11
    SOUND_STREAM_HEAD = 0x12
    SOUND_STREAM_BLOCK = 0x13
    DEFINE_BITS_LOSSLESS = 0x14
    DEFINE_BITS_JPEG2 = 0x15
    DEFINE_SHAPE2 = 0x16
    DEFINE_BUTTON_CXFORM = 0x17
    PROTECT = 0x18
    PLACE_OBJECT2 = 0x1a
    REMOVE_OBJECT2 = 0x1c
    DEFINE_SHAPE3 = 0x20
    DEFINE_TEXT2 = 0x21
    DEFINE_BUTTON2 = 0x22
    DEFINE_BITS_JPEG3 = 0x23
    DEFINE_BITS_LOSSLESS2 = 0x24
    DEFINE_EDIT_TEXT = 0x25
    DEFINE_SPRITE = 0x27
    FRAME_LABEL = 0x2b
    SOUND_STREAM_HEAD2 = 0x2d
    DEFINE_MORPH_SHAPE = 0x2e
    DEFINE_FONT2 = 0x30
    EXPORT_ASSETS = 0x38
    IMPORT_ASSETS = 0x39
    DO_INIT_ACTION = 0x3b
    DEFINE_VIDEO_STREAM = 0x3c
    VIDEO_FRAME = 0x3d
    DEFINE_FONT_INFO2 = 0x3e
    ENABLE_DEBUGGER2 = 0x40
    SCRIPT_LIMITS = 0x41
    SET_TAB_INDEX = 0x42
    PLACE_OBJECT3 = 0x46
    IMPORT_ASSETS2 = 0x47
    DEFINE_FONT3 = 0x4b
    METADATA = 0x4d
    DEFINE_SCALING_GRID = 0x4e
    DEFINE_SHAPE4 = 0x53
    DEFINE_MORPH_SHAPE2 = 0x54
    SCENE_LABEL = 0x56
    AFP_IMAGE = 0x64
    AFP_DEFINE_SOUND = 0x65
    AFP_SOUND_STREAM_BLOCK = 0x66
    AFP_DEFINE_FONT = 0x67
    AFP_DEFINE_SHAPE = 0x68
    AEP_PLACE_OBJECT = 0x6e
    AP2_DEFINE_FONT = 0x78
    AP2_DEFINE_SPRITE = 0x79
    AP2_DO_ACTION = 0x7a
    AP2_DEFINE_BUTTON = 0x7b
    AP2_DEFINE_BUTTON_SOUND = 0x7c
    AP2_DEFINE_TEXT = 0x7d
    AP2_DEFINE_EDIT_TEXT = 0x7e
    AP2_PLACE_OBJECT = 0x7f
    AP2_REMOVE_OBJECT = 0x80
    AP2_START_SOUND = 0x81
    AP2_DEFINE_MORPH_SHAPE = 0x82
    AP2_IMAGE = 0x83
    AP2_SHAPE = 0x84
    AP2_SOUND = 0x85
    AP2_VIDEO = 0x86

    @classmethod
    def tag_to_name(cls, tagid: int) -> str:
        resources: Dict[int, str] = {
            cls.END: 'END',
            cls.SHOW_FRAME: 'SHOW_FRAME',
            cls.DEFINE_SHAPE: 'DEFINE_SHAPE',
            cls.PLACE_OBJECT: 'PLACE_OBJECT',
            cls.REMOVE_OBJECT: 'REMOVE_OBJECT',
            cls.DEFINE_BITS: 'DEFINE_BITS',
            cls.DEFINE_BUTTON: 'DEFINE_BUTTON',
            cls.JPEG_TABLES: 'JPEG_TABLES',
            cls.BACKGROUND_COLOR: 'BACKGROUND_COLOR',
            cls.DEFINE_FONT: 'DEFINE_FONT',
            cls.DEFINE_TEXT: 'DEFINE_TEXT',
            cls.DO_ACTION: 'DO_ACTION',
            cls.DEFINE_FONT_INFO: 'DEFINE_FONT_INFO',
            cls.DEFINE_SOUND: 'DEFINE_SOUND',
            cls.START_SOUND: 'START_SOUND',
            cls.DEFINE_BUTTON_SOUND: 'DEFINE_BUTTON_SOUND',
            cls.SOUND_STREAM_HEAD: 'SOUND_STREAM_HEAD',
            cls.SOUND_STREAM_BLOCK: 'SOUND_STREAM_BLOCK',
            cls.DEFINE_BITS_LOSSLESS: 'DEFINE_BITS_LOSSLESS',
            cls.DEFINE_BITS_JPEG2: 'DEFINE_BITS_JPEG2',
            cls.DEFINE_SHAPE2: 'DEFINE_SHAPE2',
            cls.DEFINE_BUTTON_CXFORM: 'DEFINE_BUTTON_CXFORM',
            cls.PROTECT: 'PROTECT',
            cls.PLACE_OBJECT2: 'PLACE_OBJECT2',
            cls.REMOVE_OBJECT2: 'REMOVE_OBJECT2',
            cls.DEFINE_SHAPE3: 'DEFINE_SHAPE3',
            cls.DEFINE_TEXT2: 'DEFINE_TEXT2',
            cls.DEFINE_BUTTON2: 'DEFINE_BUTTON2',
            cls.DEFINE_BITS_JPEG3: 'DEFINE_BITS_JPEG3',
            cls.DEFINE_BITS_LOSSLESS2: 'DEFINE_BITS_LOSSLESS2',
            cls.DEFINE_EDIT_TEXT: 'DEFINE_EDIT_TEXT',
            cls.DEFINE_SPRITE: 'DEFINE_SPRITE',
            cls.FRAME_LABEL: 'FRAME_LABEL',
            cls.SOUND_STREAM_HEAD2: 'SOUND_STREAM_HEAD2',
            cls.DEFINE_MORPH_SHAPE: 'DEFINE_MORPH_SHAPE',
            cls.DEFINE_FONT2: 'DEFINE_FONT2',
            cls.EXPORT_ASSETS: 'EXPORT_ASSETS',
            cls.IMPORT_ASSETS: 'IMPORT_ASSETS',
            cls.DO_INIT_ACTION: 'DO_INIT_ACTION',
            cls.DEFINE_VIDEO_STREAM: 'DEFINE_VIDEO_STREAM',
            cls.VIDEO_FRAME: 'VIDEO_FRAME',
            cls.DEFINE_FONT_INFO2: 'DEFINE_FONT_INFO2',
            cls.ENABLE_DEBUGGER2: 'ENABLE_DEBUGGER2',
            cls.SCRIPT_LIMITS: 'SCRIPT_LIMITS',
            cls.SET_TAB_INDEX: 'SET_TAB_INDEX',
            cls.PLACE_OBJECT3: 'PLACE_OBJECT3',
            cls.IMPORT_ASSETS2: 'IMPORT_ASSETS2',
            cls.DEFINE_FONT3: 'DEFINE_FONT3',
            cls.DEFINE_SCALING_GRID: 'DEFINE_SCALING_GRID',
            cls.METADATA: 'METADATA',
            cls.DEFINE_SHAPE4: 'DEFINE_SHAPE4',
            cls.DEFINE_MORPH_SHAPE2: 'DEFINE_MORPH_SHAPE2',
            cls.SCENE_LABEL: 'SCENE_LABEL',
            cls.AFP_IMAGE: 'AFP_IMAGE',
            cls.AFP_DEFINE_SOUND: 'AFP_DEFINE_SOUND',
            cls.AFP_SOUND_STREAM_BLOCK: 'AFP_SOUND_STREAM_BLOCK',
            cls.AFP_DEFINE_FONT: 'AFP_DEFINE_FONT',
            cls.AFP_DEFINE_SHAPE: 'AFP_DEFINE_SHAPE',
            cls.AEP_PLACE_OBJECT: 'AEP_PLACE_OBJECT',
            cls.AP2_DEFINE_FONT: 'AP2_DEFINE_FONT',
            cls.AP2_DEFINE_SPRITE: 'AP2_DEFINE_SPRITE',
            cls.AP2_DO_ACTION: 'AP2_DO_ACTION',
            cls.AP2_DEFINE_BUTTON: 'AP2_DEFINE_BUTTON',
            cls.AP2_DEFINE_BUTTON_SOUND: 'AP2_DEFINE_BUTTON_SOUND',
            cls.AP2_DEFINE_TEXT: 'AP2_DEFINE_TEXT',
            cls.AP2_DEFINE_EDIT_TEXT: 'AP2_DEFINE_EDIT_TEXT',
            cls.AP2_PLACE_OBJECT: 'AP2_PLACE_OBJECT',
            cls.AP2_REMOVE_OBJECT: 'AP2_REMOVE_OBJECT',
            cls.AP2_START_SOUND: 'AP2_START_SOUND',
            cls.AP2_DEFINE_MORPH_SHAPE: 'AP2_DEFINE_MORPH_SHAPE',
            cls.AP2_IMAGE: 'AP2_IMAGE',
            cls.AP2_SHAPE: 'AP2_SHAPE',
            cls.AP2_SOUND: 'AP2_SOUND',
            cls.AP2_VIDEO: 'AP2_VIDEO',
        }

        return resources.get(tagid, f"<UNKNOWN {hex(tagid)}>")


class AP2Action:
    # End bytecode processing
    END = 0

    # Advance movieclip to next frame.
    NEXT_FRAME = 1

    # Rewind movieclip to previous frame.
    PREVIOUS_FRAME = 2

    # Play the movieclip.
    PLAY = 3

    # Stop the movieclip.
    STOP = 4

    # Stop all sound from the movie clip.
    STOP_SOUND = 5

    # Pop two objects from the stack, subtract them, push the result to the stack.
    SUBTRACT = 7

    # Pop two objects from the stack, multiply them, push the result to the stack.
    MULTIPLY = 8

    # Pop two objects from the stack, divide them, push the result to the stack.
    DIVIDE = 9

    # Pop an object from the stack, boolean negate it, push the result to the stack.
    NOT = 12

    # Pop an object from the stack, discard it.
    POP = 13

    # Pop an object off the stack, use that as a string to look up a variable, push
    # that variable's value onto the stack.
    GET_VARIABLE = 14

    # Pop two objects from the stack, if the second object is a string or const, define a
    # variable with that name equal to the first object.
    SET_VARIABLE = 15

    # Similar to get variable.
    GET_PROPERTY = 16

    # Simiar to set variable.
    SET_PROPERTY = 17

    # Clone a sprite that's specified on the stack.
    CLONE_SPRITE = 18

    # Remove a sprite as specified on the stack.
    REMOVE_SPRITE = 19

    # Print a trace of the current object on the stack, and pop it.
    TRACE = 20

    # Start dragging an object. It pops a value from the stack to set as the drag target.
    # It pops a second boolean value from the stack to specify if the drag target should be
    # locked to the mouse. One opcode specifies that we pop 4 more values from the stack
    # as a rectangle to constrain the mouse if the opcode is > 0, that we don't constrain
    # at all if the opcode is 0, or that we pop another boolean from the stack and constrain
    # if that value is true.
    START_DRAG = 21

    # End dragging the current drag target that was started with START_DRAG.
    END_DRAG = 22

    # Pop an object from the stack and throw it as an exception.
    THROW = 23

    # Pop an object from the stack, and an object representing a class. If the first
    # object is an instance of the class, push it back. Otherwise, push back a null.
    CAST_OP = 24

    # Unclear exactly what this does on the stack, the implementation seems wrong.
    IMPLEMENTS_OP = 25

    # Get the current playback position as an integer number of milliseconds, pushed to the stack.
    GET_TIME = 26

    # Pops two values from the stack to look up what to delete.
    DELETE = 27

    # Delete a variable as defined on the stack. Pops that variable name.
    DELETE2 = 28

    # Pop two objects from the stack, and then define a local variable just like "SET_VARIABLE"
    # but in the scope of the current movieclip or function.
    DEFINE_LOCAL = 29

    # Call a function. Similar to CALL_METHOD but with only one pop for the function name.
    CALL_FUNCTION = 30

    # Return the top of the stack as the return value of the function.
    RETURN = 31

    # Pop two numbers, modulo them, push them back to the stack.
    MODULO = 32

    # Create a new object, I haven't figured out what it pushes and pops from the stack yet.
    NEW_OBJECT = 33

    # Define a variable in the local movieclip or function, without a value.
    DEFINE_LOCAL2 = 34

    # Init an array from the stack. I haven't figured out what it needs to push and pop.
    INIT_ARRAY = 35

    # Init an object from the stack.
    INIT_OBJECT = 36

    # Pop an object off the stack, push the type of the object as a string.
    TYPEOF = 37

    # Pop an item off the stack, and if it is a movieclip, push the string path. If it isn't
    # a movieclip, push an undefined object onto the stack.
    TARGET_PATH = 38

    # Add two values on the stack, popping them and pushing the result.
    ADD2 = 39

    # Pops two values from the stack, and pushes a boolean representing whether one is less than
    # the other. If they cannot be compared, pushes an "Undefined" object onto the stack instead.
    LESS2 = 40

    # Pop two objects from the stack, get their string equivalent, and push a boolean onto the
    # stack if those strings match.
    EQUALS2 = 41

    # Pops the top of the stack, converts it to an integer object, and pushes it. If it can't
    # convert, instead pushes a "NaN" object.
    TO_NUMBER = 42

    # Pops the top of the stack, converts the object to its string equivalent, and pushes it.
    TO_STRING = 43

    # Takes the top of the stack and duplicates the object before pushing that object to the stack.
    PUSH_DUPLICATE = 44

    STACK_SWAP = 45

    # Get a member value and place it on the stack.
    GET_MEMBER = 46

    # Set member, popping three values from the stack.
    SET_MEMBER = 47

    # Increment value on stack.
    INCREMENT = 48

    # Decrement value on stack.
    DECREMENT = 49

    # Call method. Pops two values from the stack to lookup an object method, another value from the
    # stack for the number of params, and then that many values from the stack as function parameters.
    CALL_METHOD = 50

    NEW_METHOD = 51
    INSTANCEOF = 52
    ENUMERATE2 = 53

    # Pop two values from the stack, bitwise and them, push the result.
    BIT_AND = 54

    # Pop two values from the stack, bitwise or them, push the result.
    BIT_OR = 55

    # Pop two values from the stack, bitwise xor them, push the result.
    BIT_XOR = 56

    # Pop the amount to left shift, and an integer from the stack, push the result.
    BIT_L_SHIFT = 57

    # Pop the amount to right shift, and an integer from the stack, push the result.
    BIT_R_SHIFT = 58

    # Same as above but unsigned. It appears that games implement this identically to BIT_U_R_SHIFT.
    BIT_U_R_SHIFT = 59

    # Pop two values from the stack, push a boolean set to true if the values are strictly equal.
    STRICT_EQUALS = 60

    # Pop two objects off the stack, push a boolean object for whether the first object is greater tha
    # the second or not.
    GREATER = 61

    EXTENDS = 62

    # Pop a value from the stack and store it in a register specified by the opcode param. Also push
    # it back onto the stack.
    STORE_REGISTER = 63

    # Define a function based on parameters on the stack. This reads the next 9 bytes of the bytecode
    # as parameters, and uses that to read the next N bytes of bytecode as the function definition.
    DEFINE_FUNCTION2 = 64

    WITH = 66

    # Push an object onto the stack. Creates objects based on the bytecode parameters and pushes
    # them onto the stack.
    PUSH = 67

    # Unconditional jump based on bytecode value.
    JUMP = 68

    GET_URL2 = 69

    # Pops a value from the stack, jumps to offset from opcode params if value is truthy.
    IF = 70

    # Go to frame specified by top of stack, popping that value from the stack. Also specifies
    # flags for whether to play or stop when going to that frame, and additional frames to advance
    # in opcode params.
    GOTO_FRAME2 = 71

    GET_TARGET = 72

    # Given a subtype of check and a positive offset to jump to on true, perform a conditional check.
    # Pops two values from the stack for all equality checks except for undefined checks, which pop
    # one value.
    IF2 = 73

    # Similar to STORE_REGISTER but does not preserve the value on the stack afterwards.
    STORE_REGISTER2 = 74

    INIT_REGISTER = 75

    # Similar to ADD_NUM_VARIABLE, but operating on a register number instead of the stack. Takes
    # two params from opcodes, one for the register number and one for the addition value.
    ADD_NUM_REGISTER = 76

    # Add a number dictated by an opcode param to the variable on the stack, popping the variable
    # name.
    ADD_NUM_VARIABLE = 77

    @classmethod
    def action_to_name(cls, actionid: int) -> str:
        resources: Dict[int, str] = {
            cls.END: 'END',
            cls.NEXT_FRAME: 'NEXT_FRAME',
            cls.PREVIOUS_FRAME: 'PREVIOUS_FRAME',
            cls.PLAY: 'PLAY',
            cls.STOP: 'STOP',
            cls.STOP_SOUND: 'STOP_SOUND',
            cls.SUBTRACT: 'SUBTRACT',
            cls.MULTIPLY: 'MULTIPLY',
            cls.DIVIDE: 'DIVIDE',
            cls.NOT: 'NOT',
            cls.POP: 'POP',
            cls.GET_VARIABLE: 'GET_VARIABLE',
            cls.SET_VARIABLE: 'SET_VARIABLE',
            cls.GET_PROPERTY: 'GET_PROPERTY',
            cls.SET_PROPERTY: 'SET_PROPERTY',
            cls.CLONE_SPRITE: 'CLONE_SPRITE',
            cls.REMOVE_SPRITE: 'REMOVE_SPRITE',
            cls.TRACE: 'TRACE',
            cls.START_DRAG: 'START_DRAG',
            cls.END_DRAG: 'END_DRAG',
            cls.THROW: 'THROW',
            cls.CAST_OP: 'CAST_OP',
            cls.IMPLEMENTS_OP: 'IMPLEMENTS_OP',
            cls.GET_TIME: 'GET_TIME',
            cls.DELETE: 'DELETE',
            cls.DELETE2: 'DELETE2',
            cls.DEFINE_LOCAL: 'DEFINE_LOCAL',
            cls.CALL_FUNCTION: 'CALL_FUNCTION',
            cls.RETURN: 'RETURN',
            cls.MODULO: 'MODULO',
            cls.NEW_OBJECT: 'NEW_OBJECT',
            cls.DEFINE_LOCAL2: 'DEFINE_LOCAL2',
            cls.INIT_ARRAY: 'INIT_ARRAY',
            cls.INIT_OBJECT: 'INIT_OBJECT',
            cls.TYPEOF: 'TYPEOF',
            cls.TARGET_PATH: 'TARGET_PATH',
            cls.ADD2: 'ADD2',
            cls.LESS2: 'LESS2',
            cls.EQUALS2: 'EQUALS2',
            cls.TO_NUMBER: 'TO_NUMBER',
            cls.TO_STRING: 'TO_STRING',
            cls.PUSH_DUPLICATE: 'PUSH_DUPLICATE',
            cls.STACK_SWAP: 'STACK_SWAP',
            cls.GET_MEMBER: 'GET_MEMBER',
            cls.SET_MEMBER: 'SET_MEMBER',
            cls.INCREMENT: 'INCREMENT',
            cls.DECREMENT: 'DECREMENT',
            cls.CALL_METHOD: 'CALL_METHOD',
            cls.NEW_METHOD: 'NEW_METHOD',
            cls.INSTANCEOF: 'INSTANCEOF',
            cls.ENUMERATE2: 'ENUMERATE2',
            cls.BIT_AND: 'BIT_AND',
            cls.BIT_OR: 'BIT_OR',
            cls.BIT_XOR: 'BIT_XOR',
            cls.BIT_L_SHIFT: 'BIT_L_SHIFT',
            cls.BIT_R_SHIFT: 'BIT_R_SHIFT',
            cls.BIT_U_R_SHIFT: 'BIT_U_R_SHIFT',
            cls.STRICT_EQUALS: 'STRICT_EQUALS',
            cls.GREATER: 'GREATER',
            cls.EXTENDS: 'EXTENDS',
            cls.STORE_REGISTER: 'STORE_REGISTER',
            cls.DEFINE_FUNCTION2: 'DEFINE_FUNCTION2',
            cls.WITH: 'WITH',
            cls.PUSH: 'PUSH',
            cls.JUMP: 'JUMP',
            cls.GET_URL2: 'GET_URL2',
            cls.IF: 'IF',
            cls.GOTO_FRAME2: 'GOTO_FRAME2',
            cls.GET_TARGET: 'GET_TARGET',
            cls.IF2: 'IF2',
            cls.STORE_REGISTER2: 'STORE_REGISTER2',
            cls.INIT_REGISTER: 'INIT_REGISTER',
            cls.ADD_NUM_REGISTER: 'ADD_NUM_REGISTER',
            cls.ADD_NUM_VARIABLE: 'ADD_NUM_VARIABLE',
        }

        return resources.get(actionid, f"<UNKNOWN {actionid}>")

    @classmethod
    def actions_without_params(cls) -> Set[int]:
        return {
            cls.END,
            cls.NEXT_FRAME,
            cls.PREVIOUS_FRAME,
            cls.PLAY,
            cls.STOP,
            cls.STOP_SOUND,
            cls.ADD2,
            cls.SUBTRACT,
            cls.MULTIPLY,
            cls.DIVIDE,
            cls.MODULO,
            cls.NOT,
            cls.BIT_AND,
            cls.BIT_OR,
            cls.BIT_XOR,
            cls.BIT_L_SHIFT,
            cls.BIT_R_SHIFT,
            cls.BIT_U_R_SHIFT,
            cls.STRICT_EQUALS,
            cls.GREATER,
            cls.LESS2,
            cls.EQUALS2,
            cls.CLONE_SPRITE,
            cls.REMOVE_SPRITE,
            cls.TRACE,
            cls.TYPEOF,
            cls.TARGET_PATH,
            cls.THROW,
            cls.CAST_OP,
            cls.IMPLEMENTS_OP,
            cls.GET_TIME,
            cls.RETURN,
            cls.POP,
            cls.PUSH_DUPLICATE,
            cls.DELETE,
            cls.DELETE2,
            cls.NEW_OBJECT,
            cls.INIT_ARRAY,
            cls.INIT_OBJECT,
            cls.END_DRAG,
            cls.GET_VARIABLE,
            cls.SET_VARIABLE,
            cls.INCREMENT,
            cls.DECREMENT,
            cls.DEFINE_LOCAL,
            cls.DEFINE_LOCAL2,
            cls.GET_MEMBER,
            cls.SET_MEMBER,
            cls.GET_PROPERTY,
            cls.SET_PROPERTY,
            cls.CALL_METHOD,
            cls.CALL_FUNCTION,
            cls.TO_NUMBER,
            cls.TO_STRING,
        }


class AP2ObjectType:
    UNDEFINED = 0x0
    NAN = 0x1
    BOOLEAN = 0x2
    INTEGER = 0x3
    S64 = 0x4
    FLOAT = 0x5
    DOUBLE = 0x6
    STRING = 0x7
    POINTER = 0x8
    OBJECT = 0x9
    INFINITY = 0xa
    CONST_STRING = 0xb
    BUILT_IN_FUNCTION = 0xc


class AP2PointerType:
    # The type of the object if it is an AP2ObjectType.POINTER or AP2ObjectType.OBJECT
    UNDEFINED = 0x0
    AFP_TEXT = 0x1
    AFP_RECT = 0x2
    AFP_SHAPE = 0x3
    DRAG = 0x4
    MATRIX = 0x5
    POINT = 0x6
    GETTER_SETTER_PROPERTY = 0x7
    FUNCTION_WITH_PROTOTYPE = 0x8
    ROW_DATA = 0x20

    object_W = 0x50
    movieClip_W = 0x51
    sound_W = 0x52
    color_W = 0x53
    date_W = 0x54
    array_W = 0x55
    xml_W = 0x56
    xmlNode_W = 0x57
    textFormat_W = 0x58
    sharedObject_W = 0x59
    sharedObjectData_W = 0x5a
    textField_W = 0x5b
    xmlAttrib_W = 0x5c
    bitmapdata_W = 0x5d
    matrix_W = 0x5e
    point_W = 0x5f
    ColorMatrixFilter_W = 0x60
    String_W = 0x61
    Boolean_W = 0x62
    Number_W = 0x63
    function_W = 0x64
    prototype_W = 0x65
    super_W = 0x66
    transform_W = 0x68
    colorTransform_W = 0x69
    rectangle_W = 0x6a

    # All of these can have prototypes, not sure what the "C" stands for.
    Object_C = 0x78
    MovieClip_C = 0x79
    Sound_C = 0x7a
    Color_C = 0x7b
    Date_C = 0x7c
    Array_C = 0x7d
    XML_C = 0x7e
    XMLNode_C = 0x7f
    TextFormat_C = 0x80
    TextField_C = 0x83
    BitmapData_C = 0x85
    matrix_C = 0x86
    point_C = 0x87
    String_C = 0x89
    Boolean_C = 0x8a
    Number_C = 0x8b
    Function_C = 0x8c
    aplib_C = 0x8f
    transform_C = 0x90
    colorTransform_C = 0x91
    rectangle_C = 0x92
    asdlib_C = 0x93
    XMLController_C = 0x94
    eManager_C = 0x95

    stage_O = 0xa0
    math_O = 0xa1
    key_O = 0xa2
    mouse_O = 0xa3
    system_O = 0xa4
    sharedObject_O = 0xa5
    flash_O = 0xa6
    global_O = 0xa7
    display_P = 0xb4
    geom_P = 0xb5
    filtesr_P = 0xb6


class AP2PropertyType:
    __PROPERTIES: List[Tuple[int, str]] = [
        # Seems to be properties on every object.
        (0x100, '_x'),
        (0x101, '_y'),
        (0x102, '_xscale'),
        (0x103, '_yscale'),
        (0x104, '_currentframe'),
        (0x105, '_totalframes'),
        (0x106, '_alpha'),
        (0x107, '_visible'),
        (0x108, '_width'),
        (0x109, '_height'),
        (0x10a, '_rotation'),
        (0x10b, '_target'),
        (0x10c, '_framesloaded'),
        (0x10d, '_name'),
        (0x10e, '_droptarget'),
        (0x10f, '_url'),
        (0x110, '_highquality'),
        (0x111, '_focusrect'),
        (0x112, '_soundbuftime'),
        (0x113, '_quality'),
        (0x114, '_xmouse'),
        (0x115, '_ymouse'),
        (0x116, '_z'),

        # Global properties on every object.
        (0x120, 'this'),
        (0x121, '_root'),
        (0x122, '_parent'),
        (0x123, '_global'),
        (0x124, 'arguments'),

        # Object properties?
        (0x140, 'blendMode'),
        (0x141, 'enabled'),
        (0x142, 'hitArea'),
        (0x143, '_lockroot'),
        (0x144, '$version'),
        (0x145, 'numChildren'),
        (0x146, 'transform'),
        (0x147, 'graphics'),
        (0x148, 'loaderInfo'),
        (0x149, 'mask'),
        (0x14a, 'upState'),
        (0x14b, 'overState'),
        (0x14c, 'downState'),
        (0x14d, 'hitTestState'),
        (0x14e, 'doubleClickEnabled'),
        (0x14f, 'cacheAsBitmap'),
        (0x150, 'scrollRect'),
        (0x151, 'opaqueBackground'),
        (0x152, 'tabChildren'),
        (0x153, 'tabEnabled'),
        (0x154, 'tabIndex'),
        (0x155, 'mouseEnabled'),
        (0x156, 'mouseChildren'),
        (0x157, 'buttonMode'),
        (0x158, 'useHandCursor'),

        # Text input properties.
        (0x160, 'textWidth'),
        (0x161, 'textHeight'),
        (0x162, 'text'),
        (0x163, 'autoSize'),
        (0x164, 'textColor'),
        (0x165, 'selectable'),
        (0x166, 'multiline'),
        (0x167, 'wordWrap'),
        (0x168, 'border'),
        (0x169, 'borderColor'),
        (0x16a, 'background'),
        (0x16b, 'backgroundColor'),
        (0x16c, 'embedFonts'),
        (0x16d, 'defaultTextFormat'),
        (0x16e, 'htmlText'),
        (0x16f, 'mouseWheelEnabled'),
        (0x170, 'maxChars'),
        (0x171, 'sharpness'),
        (0x172, 'thickness'),
        (0x173, 'antiAliasType'),
        (0x174, 'gridFitType'),
        (0x175, 'maxScrollH'),
        (0x176, 'maxScrollV'),
        (0x177, 'restrict'),
        (0x178, 'numLines'),

        # Color properties?
        (0x180, 'ra'),
        (0x181, 'rb'),
        (0x182, 'ga'),
        (0x183, 'gb'),
        (0x184, 'ba'),
        (0x185, 'bb'),
        (0x186, 'aa'),
        (0x187, 'ab'),

        # Text properties?
        (0x1a0, 'font'),
        (0x1a1, 'size'),
        (0x1a2, 'color'),
        (0x1a3, 'bold'),
        (0x1a4, 'italic'),
        (0x1a5, 'underline'),
        (0x1a6, 'url'),
        (0x1a7, 'target'),
        (0x1a8, 'align'),
        (0x1a9, 'leftMargin'),
        (0x1aa, 'rightMargin'),
        (0x1ab, 'indent'),
        (0x1ac, 'leading'),
        (0x1ad, 'letterSpacing'),

        # Who the fuck knows...
        (0x1c0, 'a'),
        (0x1c1, 'b'),
        (0x1c2, 'c'),
        (0x1c3, 'd'),
        (0x1c4, 'e'),
        (0x1c5, 'f'),
        (0x1c6, 'g'),
        (0x1c7, 'h'),
        (0x1c8, 'i'),
        (0x1c9, 'j'),
        (0x1ca, 'k'),
        (0x1cb, 'l'),
        (0x1cc, 'm'),
        (0x1cd, 'n'),
        (0x1ce, 'o'),
        (0x1cf, 'p'),
        (0x1d0, 'q'),
        (0x1d1, 'r'),
        (0x1d2, 's'),
        (0x1d3, 't'),
        (0x1d4, 'u'),
        (0x1d5, 'v'),
        (0x1d6, 'w'),
        (0x1d7, 'x'),
        (0x1d8, 'y'),
        (0x1d9, 'z'),
        (0x1da, 'tx'),
        (0x1db, 'ty'),
        (0x1dc, 'length'),
        (0x1dd, 'ignoreWhite'),
        (0x1de, 'loaded'),
        (0x1df, 'childNodes'),
        (0x1e0, 'firstChild'),
        (0x1e1, 'nodeValue'),
        (0x1e2, 'nextSibling'),
        (0x1e3, 'nodeName'),
        (0x1e4, 'nodeType'),
        (0x1e5, 'attributes'),
        (0x1e6, '__count'),
        (0x1e7, '__type'),
        (0x1e8, 'width'),
        (0x1e9, 'height'),
        (0x1ea, 'useCodepage'),
        (0x1eb, 'duration'),
        (0x1ec, 'position'),
        (0x1ed, 'matrixType'),
        (0x1ee, 'matrix'),
        (0x1ef, 'prototype'),
        (0x1f0, '__proto__'),
        (0x1f1, 'xMin'),
        (0x1f2, 'xMax'),
        (0x1f3, 'yMin'),
        (0x1f4, 'yMax'),
        (0x1f5, 'lastChild'),
        (0x1f6, 'parentNode'),
        (0x1f7, 'previousSibling'),
        (0x1f8, 'callee'),
        (0x1f9, 'caller'),
        (0x1fa, 'colorTransform'),
        (0x1fb, 'concatenatedColorTransform'),
        (0x1fc, 'concatenatedMatrix'),
        (0x1fd, 'pixelBounds'),
        (0x1fe, 'matrix3D'),
        (0x1ff, 'perspectiveProjection'),

        # Commands and object references?
        (0x200, 'FSCommand:fullscreen'),
        (0x201, 'FSCommand:showmenu'),
        (0x202, 'FSCommand:allowscale'),
        (0x203, 'FSCommand:quit'),
        (0x204, 'NaN'),
        (0x205, 'Infinity'),
        (0x206, 'number'),
        (0x207, 'boolean'),
        (0x208, 'string'),
        (0x209, 'object'),
        (0x20a, 'movieclip'),
        (0x20b, 'null'),
        (0x20c, 'undefined'),
        (0x20d, 'function'),
        (0x20e, 'normal'),
        (0x20f, 'layer'),
        (0x210, 'darken'),
        (0x211, 'multiply'),
        (0x212, 'lighten'),
        (0x213, 'screen'),
        (0x214, 'overlay'),
        (0x215, 'hardlight'),
        (0x216, 'subtract'),
        (0x217, 'difference'),
        (0x218, 'invert'),
        (0x219, 'alpha'),
        (0x21a, 'erase'),
        (0x21b, '/'),
        (0x21c, '..'),
        (0x21d, 'linear'),
        (0x21e, 'radial'),
        (0x21f, 'none'),
        (0x220, 'square'),
        (0x221, 'miter'),
        (0x222, 'bevel'),
        (0x223, 'left'),
        (0x224, 'right'),
        (0x225, 'center'),
        (0x226, 'box'),
        (0x227, 'reflect'),
        (0x228, 'repeat'),
        (0x229, 'RGB'),
        (0x22a, 'linearRGB'),
        (0x22b, 'justify'),
        (0x22c, 'shader'),
        (0x22d, 'vertical'),
        (0x22e, 'horizontal'),
        (0x22f, 'pad'),
        (0x230, 'evenOdd'),
        (0x231, 'nonZero'),
        (0x232, 'negative'),
        (0x233, 'positive'),
        (0x234, 'xml'),
        (0x235, 'B'),
        (0x236, 'BL'),
        (0x237, 'BR'),
        (0x238, 'L'),
        (0x239, 'R'),
        (0x23a, 'T'),
        (0x23b, 'TL'),
        (0x23c, 'TR'),
        (0x23d, 'exactFit'),
        (0x23e, 'noBorder'),
        (0x23f, 'noScale'),
        (0x240, 'showAll'),
        (0x241, 'easeInSine'),
        (0x242, 'easeOutSine'),
        (0x243, 'easeInOutSine'),
        (0x244, 'easeOutInSine'),
        (0x245, 'easeInQuad'),
        (0x246, 'easeOutQuad'),
        (0x247, 'easeInOutQuad'),
        (0x248, 'easeOutInQuad'),
        (0x249, 'easeInFlash'),
        (0x24a, 'easeOutFlash'),
        (0x24b, 'element'),
        (0x24c, 'dynamic'),
        (0x24d, 'binary'),
        (0x24e, 'variables'),
        (0x24f, 'LB'),
        (0x250, 'RB'),
        (0x251, 'LT'),
        (0x252, 'RT'),
        (0x253, ''),
        (0x254, 'arrow'),
        (0x255, 'auto'),
        (0x256, 'button'),
        (0x257, 'hand'),
        (0x258, 'ibeam'),
        (0x259, 'advanced'),
        (0x25a, 'pixel'),
        (0x25b, 'subpixel'),
        (0x25c, 'full'),
        (0x25d, 'inner'),
        (0x25e, 'outer'),
        (0x25f, 'easeInBack'),
        (0x260, 'easeOutBack'),
        (0x261, 'easeInOutBack'),
        (0x262, 'easeOutInBack'),
        (0x263, 'registerClassConstructor'),
        (0x264, 'setter'),
        (0x265, 'getter'),
        (0x266, '???'),
        (0x267, 'aep_dummy'),
        (0x268, 'kind'),
        (0x269, '_kind'),
        (0x26a, 'org'),
        (0x26b, 'flashdevelop'),
        (0x26c, 'utils'),
        (0x26d, 'FlashConnect'),
        (0x26e, 'path'),
        (0x26f, 'if'),
        (0x270, 'notif'),
        (0x271, 'not'),
        (0x272, 'A'),
        (0x273, 'dmy0273'),
        (0x274, 'C'),
        (0x275, 'D'),
        (0x276, 'dmy0276'),
        (0x277, 'F'),
        (0x278, 'G'),
        (0x279, 'H'),
        (0x27a, 'I'),
        (0x27b, 'J'),
        (0x27c, 'K'),
        (0x27d, 'dmy027d'),
        (0x27e, 'M'),
        (0x27f, 'N'),
        (0x280, 'O'),
        (0x281, 'P'),
        (0x282, 'Q'),
        (0x283, 'dmy0283'),
        (0x284, 'S'),
        (0x285, 'dmy0285'),
        (0x286, 'U'),
        (0x287, 'V'),
        (0x288, 'W'),
        (0x289, 'X'),
        (0x28a, 'Y'),
        (0x28b, 'Z'),
        (0x28c, 'fullscreen'),
        (0x28d, 'showmenu'),
        (0x28e, 'allowscale'),
        (0x28f, 'quit'),
        (0x290, 'true'),
        (0x291, 'false'),
        (0x292, 'clamp'),
        (0x293, 'ignore'),
        (0x294, 'wrap'),
        (0x295, 'unknown'),
        (0x296, 'bigEndian'),
        (0x297, 'littleEndian'),
        (0x298, 'fragment'),
        (0x299, 'vertex'),
        (0x29a, 'bgra'),
        (0x29b, 'bgraPacked4444'),
        (0x29c, 'bgrPacked565'),
        (0x29d, 'compressed'),
        (0x29e, 'compressedAlpha'),
        (0x29f, 'bytes4'),
        (0x2a0, 'float1'),
        (0x2a1, 'float2'),
        (0x2a2, 'float3'),
        (0x2a3, 'float4'),
        (0x2a4, 'super'),
        (0x2a5, 'axisAngle'),
        (0x2a6, 'eulerAngles'),
        (0x2a7, 'quaternion'),
        (0x2a8, 'orientationStyle'),

        # Layer depths
        (0x2e0, '_level0'),
        (0x2e1, '_level1'),
        (0x2e2, '_level2'),
        (0x2e3, '_level3'),
        (0x2e4, '_level4'),
        (0x2e5, '_level5'),
        (0x2e6, '_level6'),
        (0x2e7, '_level7'),
        (0x2e8, '_level8'),
        (0x2e9, '_level9'),
        (0x2ea, '_level10'),
        (0x2eb, '_level11'),
        (0x2ec, '_level12'),
        (0x2ed, '_level13'),
        (0x2ee, '_level14'),
        (0x2ef, '_level15'),

        # System objects
        (0x300, 'System'),
        (0x301, 'Stage'),
        (0x302, 'Key'),
        (0x303, 'Math'),
        (0x304, 'flash'),
        (0x305, 'MovieClip'),
        (0x306, 'String'),
        (0x307, 'TextField'),
        (0x308, 'Color'),
        (0x309, 'Date'),
        (0x30a, 'SharedObject'),
        (0x30b, 'Mouse'),
        (0x30c, 'Object'),
        (0x30d, 'Sound'),
        (0x30e, 'Number'),
        (0x30f, 'Array'),
        (0x310, 'XML'),
        (0x311, 'TextFormat'),
        (0x312, 'display'),
        (0x313, 'geom'),
        (0x314, 'Matrix'),
        (0x315, 'Point'),
        (0x316, 'BitmapData'),
        (0x317, 'data'),
        (0x318, 'filters'),
        (0x319, 'ColorMatrixFilter'),
        (0x31a, 'Function'),
        (0x31b, 'XMLNode'),
        (0x31c, 'aplib'),
        (0x31d, 'Transform'),
        (0x31e, 'ColorTransform'),
        (0x31f, 'Rectangle'),
        (0x320, 'asdlib'),
        (0x321, 'XMLController'),
        (0x322, 'eManager'),
        (0x323, 'Error'),
        (0x324, 'MovieClipLoader'),
        (0x325, 'UndefChecker'),
        (0x326, 'int'),
        (0x327, 'uint'),
        (0x328, 'Vector'),
        (0x329, 'Event'),
        (0x32a, 'MouseEvent'),
        (0x32b, 'Matrix3D'),
        (0x32c, 'Keyboard'),
        (0x32d, 'DisplayObject'),
        (0x32e, 'Dictionary'),
        (0x32f, 'BlendMode'),
        (0x330, 'DisplayObjectContainer'),
        (0x331, 'Class'),
        (0x332, 'EventDispatcher'),
        (0x333, 'PerspectiveProjection'),
        (0x334, 'Vector3D'),
        (0x335, 'aplib3'),
        (0x336, 'SoundChannel'),
        (0x337, 'Loader'),
        (0x338, 'URLRequest'),
        (0x339, 'Sprite'),
        (0x33a, 'KeyboardEvent'),
        (0x33b, 'Timer'),
        (0x33c, 'TimerEvent'),
        (0x33d, 'asdlib3'),
        (0x33e, 'eManager3'),
        (0x33f, 'LoaderInfo'),
        (0x340, 'ProgressEvent'),
        (0x341, 'IOErrorEvent'),
        (0x342, 'Graphics'),
        (0x343, 'LineScaleMode'),
        (0x344, 'CapsStyle'),
        (0x345, 'JointStyle'),
        (0x346, 'GradientType'),
        (0x347, 'SpreadMethod'),
        (0x348, 'InterpolationMethod'),
        (0x349, 'GraphicsPathCommand'),
        (0x34a, 'GraphicsPathWinding'),
        (0x34b, 'TriangleCulling'),
        (0x34c, 'GraphicsBitmapFill'),
        (0x34d, 'GraphicsEndFill'),
        (0x34e, 'GraphicsGradientFill'),
        (0x34f, 'GraphicsPath'),
        (0x350, 'GraphicsSolidFill'),
        (0x351, 'GraphicsStroke'),
        (0x352, 'GraphicsTrianglePath'),
        (0x353, 'IGraphicsData'),
        (0x354, 'external'),
        (0x355, 'ExternalInterface'),
        (0x356, 'Scene'),
        (0x357, 'FrameLabel'),
        (0x358, 'Shape'),
        (0x359, 'SimpleButton'),
        (0x35a, 'Bitmap'),
        (0x35b, 'StageQuality'),
        (0x35c, 'InteractiveObject'),
        (0x35d, 'MotionBase'),
        (0x35e, 'KeyframeBase'),
        (0x35f, 'XMLList'),
        (0x360, 'StageAlign'),
        (0x361, 'StageScaleMode'),
        (0x362, 'AnimatorBase'),
        (0x363, 'Animator3D'),
        (0x364, 'URLLoader'),
        (0x365, 'Capabilities'),
        (0x366, 'Aweener'),
        (0x367, 'Aweener3'),
        (0x368, 'SoundTransform'),
        (0x369, 'Namespace'),
        (0x36a, 'RegExp'),
        (0x36b, 'afplib'),
        (0x36c, 'afplib3'),
        (0x36d, 'ByteArray'),
        (0x36e, 'TextFormatAlign'),
        (0x36f, 'TextFieldType'),
        (0x370, 'TextFieldAutoSize'),
        (0x371, 'SecurityErrorEvent'),
        (0x372, 'ApplicationDomain'),
        (0x373, 'TextEvent'),
        (0x374, 'ErrorEvent'),
        (0x375, 'LoaderContext'),
        (0x376, 'QName'),
        (0x377, 'IllegalOperationError'),
        (0x378, 'URLLoaderDataFormat'),
        (0x379, 'Security'),
        (0x37a, 'DropShadowFilter'),
        (0x37b, 'ReferenceError'),
        (0x37c, 'Proxy'),
        (0x37d, 'XMLSocket'),
        (0x37e, 'DataEvent'),
        (0x37f, 'Font'),
        (0x380, 'IEventDispatcher'),
        (0x381, 'LocalConnection'),
        (0x382, 'ActionScriptVersion'),
        (0x383, 'MouseCursor'),
        (0x384, 'TypeError'),
        (0x385, 'FocusEvent'),
        (0x386, 'AntiAliasType'),
        (0x387, 'GridFitType'),
        (0x388, 'ArgumentError'),
        (0x389, 'BitmapFilterType'),
        (0x38a, 'BevelFilter'),
        (0x38b, 'BitmapFilter'),
        (0x38c, 'BitmapFilterQuality'),
        (0x38d, 'XMLController3'),
        (0x38e, 'URLVariables'),
        (0x38f, 'URLRequestMethod'),
        (0x390, 'aeplib'),
        (0x391, 'BlurFilter'),
        (0x392, 'Stage3D'),
        (0x393, 'Context3D'),
        (0x394, 'Multitouch'),
        (0x395, 'Script'),
        (0x396, 'AccessibilityProperties'),
        (0x397, 'StaticText'),
        (0x398, 'MorphShape'),
        (0x399, 'BitmapDataChannel'),
        (0x39a, 'DisplacementMapFilter'),
        (0x39b, 'GlowFilter'),
        (0x39c, 'DisplacementMapFilterMode'),
        (0x39d, 'AnimatorFactoryBase'),
        (0x39e, 'Endian'),
        (0x39f, 'IOError'),
        (0x3a0, 'EOFError'),
        (0x3a1, 'Context3DTextureFormat'),
        (0x3a2, 'Context3DProgramType'),
        (0x3a3, 'TextureBase'),
        (0x3a4, 'VertexBuffer3D'),
        (0x3a5, 'IndexBuffer3D'),
        (0x3a6, 'Program3D'),
        (0x3a7, 'NativeMenuItem'),
        (0x3a8, 'ContextMenuItem'),
        (0x3a9, 'NativeMenu'),
        (0x3aa, 'ContextMenu'),
        (0x3ab, 'ContextMenuEvent'),
        (0x3ac, 'Context3DVertexBufferFormat'),
        (0x3ad, 'TouchEvent'),
        (0x3ae, 'b2Vec2'),
        (0x3af, 'b2Math'),
        (0x3b0, 'b2Transform'),
        (0x3b1, 'b2Mat22'),
        (0x3b2, 'b2Sweep'),
        (0x3b3, 'b2AABB'),
        (0x3b4, 'b2Vec3'),
        (0x3b5, 'b2Mat33'),
        (0x3b6, 'b2DistanceProxy'),
        (0x3b7, 'b2Shape'),
        (0x3b8, 'b2CircleShape'),
        (0x3b9, 'b2PolygonShape'),
        (0x3ba, 'b2MassData'),
        (0x3bb, 'b2DistanceInput'),
        (0x3bc, 'b2DistanceOutput'),
        (0x3bd, 'b2SimplexCache'),
        (0x3be, 'b2Simplex'),
        (0x3bf, 'b2SimplexVertex'),
        (0x3c0, 'b2Distance'),
        (0x3c1, 'Orientation3D'),
        (0x3c2, 'GradientGlowFilter'),
        (0x3c3, 'GradientBevelFilter'),

        # XML functions
        (0x400, 'afp_prop_init'),
        (0x401, 'afp_prop'),
        (0x402, 'afp_prop_dummy'),
        (0x403, 'afp_prop_destroy'),
        (0x404, 'afp_sync'),
        (0x405, 'afp_node_search'),
        (0x406, 'afp_node_value'),
        (0x407, 'afp_node_array_value'),
        (0x408, 'afp_complete'),
        (0x409, 'afp_sound_fade_in'),
        (0x40a, 'afp_sound_fade_out'),
        (0x40b, 'afp_make_gradient_data'),
        (0x40c, 'afp_make_alpha_texture'),
        (0x40d, 'afp_node_set_value'),
        (0x40e, 'afp_node_date_value'),
        (0x40f, 'afp_node_num_value'),
        (0x410, 'afp_node_array_num_value'),
        (0x411, 'afp_node_child'),
        (0x412, 'afp_node_parent'),
        (0x413, 'afp_node_next'),
        (0x414, 'afp_node_prev'),
        (0x415, 'afp_node_last'),
        (0x416, 'afp_node_first'),
        (0x417, 'afp_node_next_same_name'),
        (0x418, 'afp_node_prev_same_name'),
        (0x419, 'afp_node_name'),
        (0x41a, 'afp_node_absolute_path'),
        (0x41b, 'afp_node_has_parent'),
        (0x41c, 'afp_node_has_child'),
        (0x41d, 'afp_node_has_sibling'),
        (0x41e, 'afp_node_has_attrib'),
        (0x41f, 'afp_node_has_same_name_sibling'),

        # System functions
        (0x420, 'updateAfterEvent'),
        (0x421, 'parseInt'),
        (0x422, 'parseFloat'),
        (0x423, 'Boolean'),
        (0x424, 'setInterval'),
        (0x425, 'clearInterval'),
        (0x426, 'escape'),
        (0x427, 'ASSetPropFlags'),
        (0x428, 'unescape'),
        (0x429, 'isNaN'),
        (0x42a, 'isFinite'),
        (0x42b, 'trace'),
        (0x42c, 'addFrameScript'),
        (0x42d, 'getDefinitionByName'),
        (0x42e, 'getTimer'),
        (0x42f, 'setTimeout'),
        (0x430, 'clearTimeout'),
        (0x431, 'escapeMultiByte'),
        (0x432, 'unescapeMultiByte'),
        (0x433, 'getQualifiedClassName'),
        (0x434, 'describeType'),
        (0x435, 'decodeURI'),
        (0x436, 'encodeURI'),
        (0x437, 'decodeURIComponent'),
        (0x438, 'encodeURIComponent'),
        (0x439, 'registerClassAlias'),
        (0x43a, 'getClassByAlias'),
        (0x43b, 'getQualifiedSuperclassName'),
        (0x43c, 'isXMLName'),
        (0x43d, 'fscommand'),

        # Current movie manipulation functions.
        (0x440, 'stop'),
        (0x441, 'play'),
        (0x442, 'gotoAndPlay'),
        (0x443, 'gotoAndStop'),
        (0x444, 'prevFrame'),
        (0x445, 'nextFrame'),
        (0x446, 'createEmptyMovieClip'),
        (0x447, 'duplicateMovieClip'),
        (0x448, 'attachMovie'),
        (0x449, 'attachBitmap'),
        (0x44a, 'removeMovieClip'),
        (0x44b, 'unloadMovie'),
        (0x44c, 'loadMovie'),
        (0x44d, 'loadVariables'),
        (0x44e, 'startDrag'),
        (0x44f, 'stopDrag'),
        (0x450, 'setMask'),
        (0x451, 'hitTest'),
        (0x452, 'lineStyle'),
        (0x453, 'lineGradientStyle'),
        (0x454, 'beginFill'),
        (0x455, 'beginBitmapFill'),
        (0x456, 'endFill'),
        (0x457, 'moveTo'),
        (0x458, 'lineTo'),
        (0x459, 'curveTo'),
        (0x45a, 'clear'),
        (0x45b, 'getBytesLoaded'),
        (0x45c, 'getBytesTotal'),
        (0x45d, 'getDepth'),
        (0x45e, 'getNextHighestDepth'),
        (0x45f, 'swapDepths'),
        (0x460, 'localToGlobal'),
        (0x461, 'beginGradientFill'),
        (0x462, 'getSWFVersion'),
        (0x463, 'getRect'),
        (0x464, 'getBounds'),
        (0x465, 'getInstanceAtDepth'),
        (0x466, 'getURL'),
        (0x467, 'globalToLocal'),
        (0x468, 'nextScene'),
        (0x469, 'prevScene'),
        (0x46a, 'getChildByName'),
        (0x46b, 'getChildIndex'),
        (0x46c, 'addChild'),
        (0x46d, 'removeChildAt'),
        (0x46e, 'getChildAt'),
        (0x46f, 'setChildIndex'),
        (0x470, 'lineBitmapStyle'),
        (0x471, 'hitTestObject'),
        (0x472, 'hitTestPoint'),
        (0x473, 'addChildAt'),
        (0x474, 'removeChild'),
        (0x475, 'swapChildren'),
        (0x476, 'swapChildrenAt'),
        (0x477, 'getObjectsUnderPoint'),
        (0x478, 'createTextField'),
        (0x479, 'local3DToGlobal'),
        (0x47a, 'globalToLocal3D'),

        # System object manipulation functions.
        (0x480, 'toString'),
        (0x481, 'distance'),
        (0x482, 'translate'),
        (0x483, 'rotate'),
        (0x484, 'scale'),
        (0x485, 'clone'),
        (0x486, 'transformPoint'),
        (0x487, 'add'),
        (0x488, 'cos'),
        (0x489, 'sin'),
        (0x48a, 'sqrt'),
        (0x48b, 'atan2'),
        (0x48c, 'log'),
        (0x48d, 'abs'),
        (0x48e, 'floor'),
        (0x48f, 'ceil'),
        (0x490, 'round'),
        (0x491, 'pow'),
        (0x492, 'max'),
        (0x493, 'min'),
        (0x494, 'random'),
        (0x495, 'acos'),
        (0x496, 'asin'),
        (0x497, 'atan'),
        (0x498, 'tan'),
        (0x499, 'exp'),
        (0x49a, 'getRGB'),
        (0x49b, 'setRGB'),
        (0x49c, 'getTransform'),
        (0x49d, 'setTransform'),
        (0x49e, 'fromCharCode'),
        (0x49f, 'substr'),
        (0x4a0, 'substring'),
        (0x4a1, 'toUpperCase'),
        (0x4a2, 'toLowerCase'),
        (0x4a3, 'indexOf'),
        (0x4a4, 'lastIndexOf'),
        (0x4a5, 'charAt'),
        (0x4a6, 'charCodeAt'),
        (0x4a7, 'split'),
        (0x4a8, 'concat'),
        (0x4a9, 'getFullYear'),
        (0x4aa, 'getUTCFullYear'),
        (0x4ab, 'getMonth'),
        (0x4ac, 'getUTCMonth'),
        (0x4ad, 'getDate'),
        (0x4ae, 'getUTCDate'),
        (0x4af, 'getDay'),
        (0x4b0, 'getHours'),
        (0x4b1, 'getUTCHours'),
        (0x4b2, 'getMinutes'),
        (0x4b3, 'getUTCMinutes'),
        (0x4b4, 'getSeconds'),
        (0x4b5, 'getUTCSeconds'),
        (0x4b6, 'getTime'),
        (0x4b7, 'getTimezoneOffset'),
        (0x4b8, 'UTC'),
        (0x4b9, 'createElement'),
        (0x4ba, 'appendChild'),
        (0x4bb, 'createTextNode'),
        (0x4bc, 'parseXML'),
        (0x4bd, 'load'),
        (0x4be, 'hasChildNodes'),
        (0x4bf, 'cloneNode'),
        (0x4c0, 'removeNode'),
        (0x4c1, 'loadInAdvance'),
        (0x4c2, 'createGradientBox'),
        (0x4c3, 'loadBitmap'),
        (0x4c4, 'hide'),
        (0x4c5, 'show'),
        (0x4c6, 'addListener'),
        (0x4c7, 'removeListener'),
        (0x4c8, 'isDown'),
        (0x4c9, 'getCode'),
        (0x4ca, 'getAscii'),
        (0x4cb, 'attachSound'),
        (0x4cc, 'start'),
        (0x4cd, 'getVolume'),
        (0x4ce, 'setVolume'),
        (0x4cf, 'setPan'),
        (0x4d0, 'loadSound'),
        (0x4d1, 'setTextFormat'),
        (0x4d2, 'getTextFormat'),
        (0x4d3, 'push'),
        (0x4d4, 'pop'),
        (0x4d5, 'slice'),
        (0x4d6, 'splice'),
        (0x4d7, 'reverse'),
        (0x4d8, 'sort'),
        (0x4d9, 'flush'),
        (0x4da, 'getLocal'),
        (0x4db, 'shift'),
        (0x4dc, 'unshift'),
        (0x4dd, 'registerClass'),
        (0x4de, 'getUTCDay'),
        (0x4df, 'getMilliseconds'),
        (0x4e0, 'getUTCMilliseconds'),
        (0x4e1, 'addProperty'),
        (0x4e2, 'hasOwnProperty'),
        (0x4e3, 'isPropertyEnumerable'),
        (0x4e4, 'isPrototypeOf'),
        (0x4e5, 'unwatch'),
        (0x4e6, 'valueOf'),
        (0x4e7, 'watch'),
        (0x4e8, 'apply'),
        (0x4e9, 'call'),
        (0x4ea, 'contains'),
        (0x4eb, 'containsPoint'),
        (0x4ec, 'containsRectangle'),
        (0x4ed, 'equals'),
        (0x4ee, 'inflate'),
        (0x4ef, 'inflatePoint'),
        (0x4f0, 'intersection'),
        (0x4f1, 'intersects'),
        (0x4f2, 'isEmpty'),
        (0x4f3, 'offset'),
        (0x4f4, 'offsetPoint'),
        (0x4f5, 'setEmpty'),
        (0x4f6, 'union'),
        (0x4f7, 'interpolate'),
        (0x4f8, 'join'),
        (0x4f9, 'loadClip'),
        (0x4fa, 'getProgress'),
        (0x4fb, 'unloadClip'),
        (0x4fc, 'polar'),
        (0x4fd, 'sortOn'),
        (0x4fe, 'containsRect'),
        (0x4ff, 'getYear'),

        # Event constants
        (0x500, 'onKeyDown'),
        (0x501, 'onKeyUp'),
        (0x502, 'onMouseDown'),
        (0x503, 'onMouseUp'),
        (0x504, 'onMouseMove'),
        (0x505, 'onLoad'),
        (0x506, 'onEnterFrame'),
        (0x507, 'onUnload'),
        (0x508, 'onRollOver'),
        (0x509, 'onRollOut'),
        (0x50a, 'onPress'),
        (0x50b, 'onRelease'),
        (0x50c, 'onReleaseOutside'),
        (0x50d, 'onData'),
        (0x50e, 'onSoundComplete'),
        (0x50f, 'onDragOver'),
        (0x510, 'onDragOut'),
        (0x511, 'onMouseWheel'),
        (0x512, 'onLoadError'),
        (0x513, 'onLoadComplete'),
        (0x514, 'onLoadInit'),
        (0x515, 'onLoadProgress'),
        (0x516, 'onLoadStart'),
        (0x517, 'onComplete'),
        (0x518, 'onCompleteParams'),
        (0x519, 'ononCompleteScope'),
        (0x51a, 'onStart'),
        (0x51b, 'onStartParams'),
        (0x51c, 'onStartScope'),
        (0x51d, 'onUpdate'),
        (0x51e, 'onUpdateParams'),
        (0x51f, 'onUpdateScope'),
        (0x520, 'onKeyPress'),
        (0x521, 'onInitialize'),
        (0x522, 'onConstruct'),
        (0x5c0, 'scaleX'),
        (0x5c1, 'scaleY'),
        (0x5c2, 'currentFrame'),
        (0x5c3, 'totalFrames'),
        (0x5c4, 'visible'),
        (0x5c5, 'rotation'),
        (0x5c6, 'framesLoaded'),
        (0x5c7, 'dropTarget'),
        (0x5c8, 'focusRect'),
        (0x5c9, 'mouseX'),
        (0x5ca, 'mouseY'),
        (0x5cb, 'root'),
        (0x5cc, 'parent'),
        (0x5cd, 'stage'),
        (0x5ce, 'currentLabel'),
        (0x5cf, 'currentLabels'),
        (0x5d0, 'currentFrameLabel'),
        (0x5d1, 'currentScene'),
        (0x5d2, 'scenes'),
        (0x5d3, 'rotationX'),
        (0x5d4, 'rotationY'),
        (0x5d5, 'rotationZ'),
        (0x5d6, 'quality'),
        (0x5d7, 'skewX'),
        (0x5d8, 'skewY'),
        (0x5d9, 'rotationConcat'),
        (0x5da, 'useRotationConcat'),
        (0x5db, 'scaleZ'),
        (0x5dc, 'isPlaying'),

        # Key constants
        (0x600, 'BACKSPACE'),
        (0x601, 'CAPSLOCK'),
        (0x602, 'CONTROL'),
        (0x603, 'DELETEKEY'),
        (0x604, 'DOWN'),
        (0x605, 'END'),
        (0x606, 'ENTER'),
        (0x607, 'ESCAPE'),
        (0x608, 'HOME'),
        (0x609, 'INSERT'),
        (0x60a, 'LEFT'),
        (0x60b, 'PGDN'),
        (0x60c, 'PGUP'),
        (0x60d, 'RIGHT'),
        (0x60e, 'SHIFT'),
        (0x60f, 'SPACE'),
        (0x610, 'TAB'),
        (0x611, 'UP'),
        (0x612, 'ARROW'),
        (0x613, 'AUTO'),
        (0x614, 'BUTTON'),
        (0x615, 'HAND'),
        (0x616, 'IBEAM'),

        # Some sort of sorting constants.
        (0x620, 'CASEINSENSITIVE'),
        (0x621, 'DESCENDING'),
        (0x622, 'UNIQUESORT'),
        (0x623, 'RETURNINDEXEDARRAY'),
        (0x624, 'NUMERIC'),
        (0x640, 'ADD'),
        (0x641, 'ALPHA'),
        (0x642, 'DARKEN'),
        (0x643, 'DIFFERENCE'),
        (0x644, 'ERASE'),
        (0x645, 'HARDLIGHT'),
        (0x646, 'INVERT'),
        (0x647, 'LAYER'),
        (0x648, 'LIGHTEN'),
        (0x649, 'MULTIPLY'),
        (0x64a, 'NORMAL'),
        (0x64b, 'OVERLAY'),
        (0x64c, 'SCREEN'),
        (0x64d, 'SHADER'),
        (0x64e, 'SUBTRACT'),
        (0x660, 'dmy0660'),
        (0x661, 'NONE'),
        (0x662, 'VERTICAL'),
        (0x663, 'HORIZONTAL'),
        (0x664, 'ROUND'),
        (0x665, 'SQUARE'),
        (0x666, 'BEVEL'),
        (0x667, 'MITER'),
        (0x668, 'LINEAR'),
        (0x669, 'RADIAL'),
        (0x66a, 'PAD'),
        (0x66b, 'REFLECT'),
        (0x66c, 'REPEAT'),
        (0x66d, 'LINEAR_RGB'),
        (0x66e, 'NO_OP'),
        (0x66f, 'MOVE_TO'),
        (0x670, 'LINE_TO'),
        (0x671, 'CURVE_TO'),
        (0x672, 'WIDE_MOVE_TO'),
        (0x673, 'WIDE_LINE_TO'),
        (0x674, 'EVEN_ODD'),
        (0x675, 'NON_ZERO'),
        (0x676, 'NEGATIVE'),
        (0x677, 'POSITIVE'),
        (0x678, 'FRAGMENT'),
        (0x679, 'VERTEX'),
        (0x67a, 'BGRA'),
        (0x67b, 'BGRA_PACKED'),
        (0x67c, 'BGR_PACKED'),
        (0x67d, 'COMPRESSED'),
        (0x67e, 'COMPRESSED_ALPHA'),
        (0x67f, 'BYTES_4'),
        (0x680, 'FLOAT_1'),
        (0x681, 'FLOAT_2'),
        (0x682, 'FLOAT_3'),
        (0x683, 'FLOAT_4'),
        (0x684, 'e_unknownShape'),
        (0x685, 'e_circleShape'),
        (0x686, 'e_polygonShape'),
        (0x687, 'e_edgeShape'),
        (0x688, 'e_shapeTypeCount'),
        (0x689, 'CUBIC_CURVE_TO'),
        (0x690, 'BOTTOM'),
        (0x691, 'BOTTOM_LEFT'),
        (0x692, 'BOTTOM_RIGHT'),
        (0x693, 'TOP'),
        (0x694, 'TOP_LEFT'),
        (0x695, 'TOP_RIGHT'),
        (0x696, 'EXACT_FIT'),
        (0x697, 'NO_BORDER'),
        (0x698, 'NO_SCALE'),
        (0x699, 'SHOW_ALL'),
        (0x6a0, 'CENTER'),
        (0x6a1, 'JUSTIFY'),
        (0x6a2, 'dmy06a2'),
        (0x6a3, 'dmy06a3'),
        (0x6a4, 'dmy06a4'),
        (0x6a5, 'dmy06a5'),
        (0x6a6, 'dmy06a6'),
        (0x6a7, 'dmy06a7'),
        (0x6a8, 'dmy06a8'),
        (0x6a9, 'DYNAMIC'),
        (0x6aa, 'INPUT'),
        (0x6ab, 'ADVANCED'),
        (0x6ac, 'PIXEL'),
        (0x6ad, 'SUBPIXEL'),
        (0x6b0, 'BINARY'),
        (0x6b1, 'TEXT'),
        (0x6b2, 'VARIABLES'),
        (0x6c0, 'FULL'),
        (0x6c1, 'INNER'),
        (0x6c2, 'OUTER'),
        (0x6c3, 'RED'),
        (0x6c4, 'GREEN'),
        (0x6c5, 'BLUE'),
        (0x6c6, 'CLAMP'),
        (0x6c7, 'COLOR'),
        (0x6c8, 'IGNORE'),
        (0x6c9, 'WRAP'),
        (0x6d0, 'DELETE'),
        (0x6d1, 'GET'),
        (0x6d2, 'HEAD'),
        (0x6d3, 'OPTIONS'),
        (0x6d4, 'POST'),
        (0x6d5, 'PUT'),
        (0x6d6, 'BIG_ENDIAN'),
        (0x6d7, 'LITTLE_ENDIAN'),
        (0x6d8, 'AXIS_ANGLE'),
        (0x6d9, 'EULER_ANGLES'),
        (0x6da, 'QUATERNION'),
        (0x6f0, 'NUMBER_0'),
        (0x6f1, 'NUMBER_1'),
        (0x6f2, 'NUMBER_2'),
        (0x6f3, 'NUMBER_3'),
        (0x6f4, 'NUMBER_4'),
        (0x6f5, 'NUMBER_5'),
        (0x6f6, 'NUMBER_6'),
        (0x6f7, 'NUMBER_7'),
        (0x6f8, 'NUMBER_8'),
        (0x6f9, 'NUMBER_9'),

        # Shape constants?
        (0x700, 'redMultiplier'),
        (0x701, 'greenMultiplier'),
        (0x702, 'blueMultiplier'),
        (0x703, 'alphaMultiplier'),
        (0x704, 'redOffset'),
        (0x705, 'greenOffset'),
        (0x706, 'blueOffset'),
        (0x707, 'alphaOffset'),
        (0x708, 'rgb'),
        (0x709, 'bottom'),
        (0x70a, 'bottomRight'),
        (0x70b, 'top'),
        (0x70c, 'topLeft'),
        (0x70d, 'LOW'),
        (0x70e, 'MEDIUM'),
        (0x70f, 'HIGH'),
        (0x710, 'BEST'),
        (0x711, 'name'),
        (0x712, 'message'),
        (0x713, 'bytesLoaded'),
        (0x714, 'bytesTotal'),
        (0x715, 'once'),
        (0x716, 'MAX_VALUE'),
        (0x717, 'MIN_VALUE'),
        (0x718, 'NEGATIVE_INFINITY'),
        (0x719, 'POSITIVE_INFINITY'),
        (0x71a, 'stageWidth'),
        (0x71b, 'stageHeight'),
        (0x71c, 'frame'),
        (0x71d, 'numFrames'),
        (0x71e, 'labels'),
        (0x71f, 'currentTarget'),
        (0x720, 'void'),
        (0x721, 'fixed'),
        (0x722, 'rawData'),
        (0x723, 'type'),
        (0x724, 'focalLength'),
        (0x725, 'fieldOfView'),
        (0x726, 'projectionCenter'),
        (0x727, 'E'),
        (0x728, 'LN10'),
        (0x729, 'LN2'),
        (0x72a, 'LOG10E'),
        (0x72b, 'LOG2E'),
        (0x72c, 'PI'),
        (0x72d, 'SQRT1_2'),
        (0x72e, 'SQRT2'),
        (0x72f, 'stageX'),
        (0x730, 'stageY'),
        (0x731, 'localX'),
        (0x732, 'localY'),
        (0x733, 'tintColor'),
        (0x734, 'tintMultiplier'),
        (0x735, 'brightness'),
        (0x736, 'delay'),
        (0x737, 'repeatCount'),
        (0x738, 'currentCount'),
        (0x739, 'running'),
        (0x73a, 'charCode'),
        (0x73b, 'keyCode'),
        (0x73c, 'altKey'),
        (0x73d, 'ctrlKey'),
        (0x73e, 'shiftKey'),
        (0x73f, 'useCodePage'),
        (0x740, 'contentLoaderInfo'),
        (0x741, 'loaderURL'),
        (0x742, 'loader'),
        (0x743, 'fullYear'),
        (0x744, 'fullYearUTC'),
        (0x745, 'month'),
        (0x746, 'monthUTC'),
        (0x747, 'date'),
        (0x748, 'dateUTC'),
        (0x749, 'day'),
        (0x74a, 'dayUTC'),
        (0x74b, 'hours'),
        (0x74c, 'hoursUTC'),
        (0x74d, 'minutes'),
        (0x74e, 'minutesUTC'),
        (0x74f, 'seconds'),
        (0x750, 'secondsUTC'),
        (0x751, 'milliseconds'),
        (0x752, 'millisecondsUTC'),
        (0x753, 'timezoneOffset'),
        (0x754, 'time'),
        (0x755, 'joints'),
        (0x756, 'fill'),
        (0x757, 'colors'),
        (0x758, 'commands'),
        (0x759, 'miterLimit'),
        (0x75a, 'alphas'),
        (0x75b, 'ratios'),
        (0x75c, 'bitmapData'),
        (0x75d, 'vertices'),
        (0x75e, 'uvtData'),
        (0x75f, 'indices'),
        (0x760, 'parameters'),
        (0x761, 'frameRate'),
        (0x762, 'low'),
        (0x763, 'medium'),
        (0x764, 'high'),
        (0x765, 'best'),
        (0x766, 'index'),
        (0x767, 'blank'),
        (0x768, 'is3D'),
        (0x769, 'scaleMode'),
        (0x76a, 'frameEvent'),
        (0x76b, 'motion'),
        (0x76c, 'transformationPoint'),
        (0x76d, 'transformationPointZ'),
        (0x76e, 'sceneName'),
        (0x76f, 'targetParent'),
        (0x770, 'targetName'),
        (0x771, 'initialPosition'),
        (0x772, 'children'),
        (0x773, 'child'),
        (0x774, 'playerType'),
        (0x775, 'os'),
        (0x776, 'capabilities'),
        (0x777, 'transition'),
        (0x778, 'transitionParameters'),
        (0x779, 'useFrames'),
        (0x77a, '_color_redMultiplier'),
        (0x77b, '_color_redOffset'),
        (0x77c, '_color_greenMultiplier'),
        (0x77d, '_color_greenOffset'),
        (0x77e, '_color_blueMultiplier'),
        (0x77f, '_color_blueOffset'),
        (0x780, '_color_alphaMultiplier'),
        (0x781, '_color_alphaOffset'),
        (0x782, '_color'),
        (0x783, 'soundTransform'),
        (0x784, 'volume'),
        (0x785, 'uri'),
        (0x786, 'prefix'),
        (0x787, 'content'),
        (0x788, 'contentType'),
        (0x789, 'swfVersion'),
        (0x78a, 'input'),
        (0x78b, 'source'),
        (0x78c, 'lastIndex'),
        (0x78d, 'stageFocusRect'),
        (0x78e, 'currentDomain'),
        (0x78f, 'applicationDomain'),
        (0x790, 'parentDomain'),
        (0x791, 'dataFormat'),
        (0x792, 'digest'),
        (0x793, 'errorID'),
        (0x794, 'available'),
        (0x795, 'client'),
        (0x796, 'actionScriptVersion'),
        (0x797, 'ACTIONSCRIPT2'),
        (0x798, 'ACTIONSCRIPT3'),
        (0x799, 'delta'),
        (0x79a, 'cursor'),
        (0x79b, 'buttonDown'),
        (0x79c, 'motionArray'),
        (0x79d, 'spanStart'),
        (0x79e, 'spanEnd'),
        (0x79f, 'placeholderName'),
        (0x7a0, 'instanceFactoryClass'),
        (0x7a1, 'instance'),
        (0x7a2, 'method'),
        (0x7a3, 'requestHeaders'),
        (0x7a4, 'info'),
        (0x7a5, 'dotall'),
        (0x7a6, 'extended'),
        (0x7a7, 'global'),
        (0x7a8, 'ignoreCase'),
        (0x7a9, 'X_AXIS'),
        (0x7aa, 'Y_AXIS'),
        (0x7ab, 'Z_AXIS'),
        (0x7ac, 'lengthSquared'),
        (0x7ad, 'dps'),
        (0x7ae, 'from0'),
        (0x7af, '_text'),
        (0x7b0, '_text_sound'),
        (0x7b1, 'blurX'),
        (0x7b2, 'blurY'),
        (0x7b3, 'step'),
        (0x7b4, 'spc'),
        (0x7b5, 'stage3Ds'),
        (0x7b6, 'context3D'),
        (0x7b7, 'version'),
        (0x7b8, 'accessibilityProperties'),
        (0x7b9, 'description'),
        (0x7ba, 'adjustColorBrightness'),
        (0x7bb, 'adjustColorContrast'),
        (0x7bc, 'adjustColorSaturation'),
        (0x7bd, 'adjustColorHue'),
        (0x7be, 'strength'),
        (0x7bf, 'angle'),
        (0x7c0, 'knockout'),
        (0x7c1, 'hideObject'),
        (0x7c2, 'manufacturer'),
        (0x7c3, 'smoothing'),
        (0x7c4, 'rect'),
        (0x7c5, 'transparent'),
        (0x7c6, 'mapBitmap'),
        (0x7c7, 'mapPoint'),
        (0x7c8, 'componentX'),
        (0x7c9, 'componentY'),
        (0x7ca, 'mode'),
        (0x7cb, 'highlightColor'),
        (0x7cc, 'highlightAlpha'),
        (0x7cd, 'shadowColor'),
        (0x7ce, 'shadowAlpha'),
        (0x7cf, 'endian'),
        (0x7d0, '_scale'),
        (0x7d1, 'transitionParams'),
        (0x7d2, '_text_color'),
        (0x7d3, '_text_color_r'),
        (0x7d4, '_text_color_g'),
        (0x7d5, '_text_color_b'),
        (0x7d6, 'cancelable'),
        (0x7d7, 'col1'),
        (0x7d8, 'col2'),
        (0x7d9, 'localCenter'),
        (0x7da, 't0'),
        (0x7db, 'a0'),
        (0x7dc, 'c0'),
        (0x7dd, 'lowerBound'),
        (0x7de, 'upperBound'),
        (0x7df, 'col3'),
        (0x7e0, 'mass'),
        (0x7e1, 'm_vertices'),
        (0x7e2, 'm_vertexCount'),
        (0x7e3, 'm_radius'),
        (0x7e4, 'm_p'),
        (0x7e5, 'm_normals'),
        (0x7e6, 'm_type'),
        (0x7e7, 'm_centroid'),
        (0x7e8, 'proxyA'),
        (0x7e9, 'proxyB'),
        (0x7ea, 'transformA'),
        (0x7eb, 'transformB'),
        (0x7ec, 'useRadii'),
        (0x7ed, 'pointA'),
        (0x7ee, 'pointB'),
        (0x7ef, 'iterations'),
        (0x7f0, 'count'),
        (0x7f1, 'metric'),
        (0x7f2, 'indexA'),
        (0x7f3, 'indexB'),
        (0x7f4, 'determinant'),

        # Some more system functions?
        (0x800, 'sound_play'),
        (0x801, 'sound_stop'),
        (0x802, 'sound_stop_all'),
        (0x803, 'set_top_mc'),
        (0x804, 'set_controlled_XML'),
        (0x805, 'set_config_XML'),
        (0x806, 'set_data_top'),
        (0x807, 'attach_event'),
        (0x808, 'detach_event'),
        (0x809, 'set'),
        (0x80a, 'get'),
        (0x80b, 'ready'),
        (0x80c, 'afp_available'),
        (0x80d, 'controller_available'),
        (0x80e, 'push_state'),
        (0x80f, 'pop_state'),
        (0x810, 'afp_verbose_action'),
        (0x811, 'sound_fadeout'),
        (0x812, 'sound_fadeout_all'),
        (0x813, 'deepPlay'),
        (0x814, 'deepStop'),
        (0x815, 'deepGotoAndPlay'),
        (0x816, 'deepGotoAndStop'),
        (0x817, 'detach_event_all'),
        (0x818, 'detach_event_id'),
        (0x819, 'detach_event_obj'),
        (0x81a, 'get_version'),
        (0x81b, 'get_version_str'),
        (0x81c, 'addAween'),
        (0x81d, 'addCaller'),
        (0x81e, 'registerSpecialProperty'),
        (0x81f, 'registerSpecialPropertySplitter'),
        (0x820, 'registerTransition'),
        (0x821, 'removeAllAweens'),
        (0x822, 'removeAweens'),
        (0x823, 'use_konami_lib'),
        (0x824, 'sound_volume'),
        (0x825, 'sound_volume_all'),
        (0x826, 'afp_verbose_script'),
        (0x827, 'afp_node_check_value'),
        (0x828, 'afp_node_check'),
        (0x829, 'get_version_full_str'),
        (0x82a, 'set_debug'),
        (0x82b, 'num2str_comma'),
        (0x82c, 'areacode2str'),
        (0x82d, 'num2str_period'),
        (0x82e, 'get_columns'),
        (0x82f, 'num2mc'),
        (0x830, 'warning'),
        (0x831, 'fatal'),
        (0x832, 'aep_set_frame_control'),
        (0x833, 'aep_set_rect_mask'),
        (0x834, 'load_movie'),
        (0x835, 'get_movie_clip'),
        (0x836, 'aep_set_set_frame'),
        (0x837, 'deep_goto_play_label'),
        (0x838, 'deep_goto_stop_label'),
        (0x839, 'goto_play_label'),
        (0x83a, 'goto_stop_label'),
        (0x83b, 'goto_play'),
        (0x83c, 'goto_stop'),
        (0x83d, 'set_text'),
        (0x83e, 'get_text_data'),
        (0x83f, 'attach_movie'),
        (0x840, 'attach_bitmap'),
        (0x841, 'create_movie_clip'),
        (0x842, 'set_text_scroll'),
        (0x843, 'set_stage'),
        (0x880, 'flash.system'),
        (0x881, 'flash.display'),
        (0x882, 'flash.text'),
        (0x883, 'fl.motion'),
        (0x884, 'flash.net'),
        (0x885, 'flash.ui'),
        (0x886, 'flash.geom'),
        (0x887, 'flash.filters'),
        (0x888, 'flash.events'),
        (0x889, 'flash.utils'),
        (0x88a, 'flash.media'),
        (0x88b, 'flash.external'),
        (0x88c, 'flash.errors'),
        (0x88d, 'flash.xml'),
        (0x88e, 'flash.display3D'),
        (0x88f, 'flash.accessibility'),
        (0x890, 'flash.display3D.textures'),
        (0x891, 'Box2D.Common.Math'),
        (0x892, 'Box2D.Collision'),
        (0x893, 'Box2D.Collision.Shapes'),

        # Lots of generic function names.
        (0x900, 'setDate'),
        (0x901, 'setUTCDate'),
        (0x902, 'setFullYear'),
        (0x903, 'setUTCFullYear'),
        (0x904, 'setHours'),
        (0x905, 'setUTCHours'),
        (0x906, 'setMilliseconds'),
        (0x907, 'setUTCMilliseconds'),
        (0x908, 'setMinutes'),
        (0x909, 'setUTCMinutes'),
        (0x90a, 'setMonth'),
        (0x90b, 'setUTCMonth'),
        (0x90c, 'setSeconds'),
        (0x90d, 'setUTCSeconds'),
        (0x90e, 'setTime'),
        (0x90f, 'setYear'),
        (0x910, 'addEventListener'),
        (0x911, 'removeEventListener'),
        (0x912, 'match'),
        (0x913, 'replace'),
        (0x914, 'search'),
        (0x915, 'append'),
        (0x916, 'appendRotation'),
        (0x917, 'appendScale'),
        (0x918, 'appendTranslation'),
        (0x919, 'decompose'),
        (0x91a, 'deltaTransformVector'),
        (0x91b, 'identity'),
        (0x91c, 'interpolateTo'),
        (0x91d, 'pointAt'),
        (0x91e, 'prepend'),
        (0x91f, 'prependRotation'),
        (0x920, 'prependScale'),
        (0x921, 'prependTranslation'),
        (0x922, 'recompose'),
        (0x923, 'transformVector'),
        (0x924, 'transformVectors'),
        (0x925, 'transpose'),
        (0x926, 'dispatchEvent'),
        (0x927, 'toMatrix3D'),
        (0x928, 'appendText'),
        (0x929, 'getLineText'),
        (0x92a, 'replaceText'),
        (0x92b, 'propertyIsEnumerable'),
        (0x92c, 'setPropertyIsEnumerable'),
        (0x92d, 'drawCircle'),
        (0x92e, 'drawEllipse'),
        (0x92f, 'drawGraphicsData'),
        (0x930, 'drawPath'),
        (0x931, 'drawRect'),
        (0x932, 'drawRoundRect'),
        (0x933, 'drawTriangles'),
        (0x934, 'copyFrom'),
        (0x935, 'addCallback'),
        (0x936, 'overrideTargetTransform'),
        (0x937, 'addPropertyArray'),
        (0x938, 'getCurrentKeyframe'),
        (0x939, 'getMatrix3D'),
        (0x93a, 'getColorTransform'),
        (0x93b, 'getFilters'),
        (0x93c, 'getValue'),
        (0x93d, 'hasEventListener'),
        (0x93e, 'registerParentFrameHandler'),
        (0x93f, 'processCurrentFrame'),
        (0x940, 'normalize'),
        (0x941, 'elements'),
        (0x942, 'toXMLString'),
        (0x943, 'attribute'),
        (0x944, 'localName'),
        (0x945, 'nodeKind'),
        (0x946, 'exec'),
        (0x947, 'toLocaleString'),
        (0x948, 'invalidate'),
        (0x949, 'getDefinition'),
        (0x94a, 'hasDefinition'),
        (0x94b, 'descendants'),
        (0x94c, 'loadPolicyFile'),
        (0x94d, 'reset'),
        (0x94e, 'callProperty'),
        (0x94f, 'getProperty'),
        (0x950, 'setProperty'),
        (0x951, 'willTrigger'),
        (0x952, 'send'),
        (0x953, 'addTargetInfo'),
        (0x954, 'drawRoundRectComplex'),
        (0x955, 'forEach'),
        (0x956, 'filter'),
        (0x957, 'every'),
        (0x958, 'some'),
        (0x959, 'map'),
        (0x95a, 'test'),
        (0x95b, 'toDateString'),
        (0x95c, 'toLocaleDateString'),
        (0x95d, 'toLocaleTimeString'),
        (0x95e, 'toTimeString'),
        (0x95f, 'toUTCString'),
        (0x960, 'parse'),
        (0x961, 'project'),
        (0x962, 'nearEquals'),
        (0x963, 'scaleBy'),
        (0x964, 'negate'),
        (0x965, 'incrementBy'),
        (0x966, 'decrementBy'),
        (0x967, 'dotProduct'),
        (0x968, 'crossProduct'),
        (0x969, 'angleBetween'),
        (0x96a, 'decode'),
        (0x96b, 'copyColumnFrom'),
        (0x96c, 'copyColumnTo'),
        (0x96d, 'copyRawDataFrom'),
        (0x96e, 'copyRawDataTo'),
        (0x96f, 'copyRowFrom'),
        (0x970, 'copyRowTo'),
        (0x971, 'copyToMatrix3D'),
        (0x972, 'requestContext3D'),
        (0x973, 'initFilters'),
        (0x974, 'addFilterPropertyArray'),
        (0x975, 'setTo'),
        (0x976, 'createBox'),
        (0x977, 'deltaTransformPoint'),
        (0x978, 'writeByte'),
        (0x979, 'writeInt'),
        (0x97a, 'readByte'),
        (0x97b, 'writeBoolean'),
        (0x97c, 'writeDouble'),
        (0x97d, 'readBoolean'),
        (0x97e, 'readDouble'),
        (0x97f, 'writeUnsignedInt'),
        (0x980, 'getVector'),
        (0x981, 'setVector'),
        (0x982, 'unload'),
        (0x983, 'unloadAndStop'),
        (0x984, 'toExponential'),
        (0x985, 'toFixed'),
        (0x986, 'toPrecision'),
        (0x987, 'getNewTextFormat'),
        (0x988, 'SetV'),
        (0x989, 'Set'),
        (0x98a, 'SetZero'),
        (0x98b, 'Make'),
        (0x98c, 'Copy'),
        (0x98d, 'Length'),
        (0x98e, 'LengthSquared'),
        (0x98f, 'Normalize'),
        (0x990, 'Multiply'),
        (0x991, 'GetNegative'),
        (0x992, 'NegativeSelf'),
        (0x993, 'Clamp'),
        (0x994, 'MulX'),
        (0x995, 'Dot'),
        (0x996, 'SubtractVV'),
        (0x997, 'CrossVF'),
        (0x998, 'CrossFV'),
        (0x999, 'MulTMV'),
        (0x99a, 'CrossVV'),
        (0x99b, 'Max'),
        (0x99c, 'MulMV'),
        (0x99d, 'Abs'),
        (0x99e, 'MulXT'),
        (0x99f, 'SetM'),
        (0x9a0, 'AddM'),
        (0x9a1, 'Solve'),
        (0x9a2, 'Add'),
        (0x9a3, 'Min'),
        (0x9a4, 'FromAngle'),
        (0x9a5, 'GetTransform'),
        (0x9a6, 'Advance'),
        (0x9a7, 'GetInverse'),
        (0x9a8, 'Combine'),
        (0x9a9, 'Contains'),
        (0x9aa, 'TestOverlap'),
        (0x9ab, 'GetCenter'),
        (0x9ac, 'Solve22'),
        (0x9ad, 'Solve33'),
        (0x9ae, 'SetLocalPosition'),
        (0x9af, 'ComputeAABB'),
        (0x9b0, 'ComputeMass'),
        (0x9b1, 'GetType'),
        (0x9b2, 'SetAsArray'),
        (0x9b3, 'GetVertex'),
        (0x9b4, 'GetSupport'),
        (0x9b5, 'GetSupportVertex'),
        (0x9b6, 'GetVertexCount'),
        (0x9b7, 'GetVertices'),
        (0x9b8, 'ReadCache'),
        (0x9b9, 'GetClosestPoint'),
        (0x9ba, 'GetSearchDirection'),
        (0x9bb, 'Solve2'),
        (0x9bc, 'Solve3'),
        (0x9bd, 'GetWitnessPoints'),
        (0x9be, 'WriteCache'),
        (0x9bf, 'Distance'),
        (0x9c0, 'cubicCurveTo'),
        (0x9c1, 'wideMoveTo'),
        (0x9c2, 'wideLineTo'),
        (0x9c3, 'insertAt'),
        (0x9c4, 'removeAt'),

        # Seems like more event constants.
        (0xa00, 'CLICK'),
        (0xa01, 'ENTER_FRAME'),
        (0xa02, 'ADDED_TO_STAGE'),
        (0xa03, 'MOUSE_DOWN'),
        (0xa04, 'MOUSE_MOVE'),
        (0xa05, 'MOUSE_OUT'),
        (0xa06, 'MOUSE_OVER'),
        (0xa07, 'MOUSE_UP'),
        (0xa08, 'MOUSE_WHEEL'),
        (0xa09, 'ROLL_OUT'),
        (0xa0a, 'ROLL_OVER'),
        (0xa0b, 'KEY_DOWN'),
        (0xa0c, 'KEY_UP'),
        (0xa0d, 'TIMER'),
        (0xa0e, 'COMPLETE'),
        (0xa0f, 'SOUND_COMPLETE'),
        (0xa10, 'OPEN'),
        (0xa11, 'PROGRESS'),
        (0xa12, 'INIT'),
        (0xa13, 'IO_ERROR'),
        (0xa14, 'TIMER_COMPLETE'),
        (0xa15, 'REMOVED_FROM_STAGE'),
        (0xa16, 'REMOVED'),
        (0xa17, 'FRAME_CONSTRUCTED'),
        (0xa18, 'DOUBLE_CLICK'),
        (0xa19, 'RESIZE'),
        (0xa1a, 'ADDED'),
        (0xa1b, 'TAB_CHILDREN_CHANGE'),
        (0xa1c, 'TAB_ENABLED_CHANGE'),
        (0xa1d, 'TAB_INDEX_CHANGE'),
        (0xa1e, 'EXIT_FRAME'),
        (0xa1f, 'RENDER'),
        (0xa20, 'ACTIVATE'),
        (0xa21, 'DEACTIVATE'),
        (0xa22, 'SECURITY_ERROR'),
        (0xa23, 'ERROR'),
        (0xa24, 'CLOSE'),
        (0xa25, 'DATA'),
        (0xa26, 'CONNECT'),
        (0xa27, 'MOUSE_LEAVE'),
        (0xa28, 'FOCUS_IN'),
        (0xa29, 'FOCUS_OUT'),
        (0xa2a, 'KEY_FOCUS_CHANGE'),
        (0xa2b, 'MOUSE_FOCUS_CHANGE'),
        (0xa2c, 'LINK'),
        (0xa2d, 'TEXT_INPUT'),
        (0xa2e, 'CHANGE'),
        (0xa2f, 'SCROLL'),
        (0xa30, 'CONTEXT3D_CREATE'),
        (0xa31, 'MENU_ITEM_SELECT'),
        (0xa32, 'MENU_SELECT'),
        (0xa33, 'UNLOAD'),
        (0xa34, 'TOUCH_BEGIN'),
        (0xa35, 'TOUCH_END'),
        (0xa36, 'TOUCH_MOVE'),
        (0xa37, 'TOUCH_OUT'),
        (0xa38, 'TOUCH_OVER'),
        (0xa39, 'TOUCH_ROLL_OUT'),
        (0xa3a, 'TOUCH_ROLL_OVER'),
        (0xa3b, 'TOUCH_TAP'),
        (0xa3c, 'CONTEXT_MENU'),
        (0xa3d, 'MIDDLE_CLICK'),
        (0xa3e, 'MIDDLE_MOUSE_DOWN'),
        (0xa3f, 'MIDDLE_MOUSE_UP'),
        (0xa40, 'RELEASE_OUTSIDE'),
        (0xa41, 'RIGHT_CLICK'),
        (0xa42, 'RIGHT_MOUSE_DOWN'),
        (0xa43, 'RIGHT_MOUSE_UP'),

        # Seems like methods on objects tied to events.
        (0xa80, 'click'),
        (0xa81, 'enterFrame'),
        (0xa82, 'addedToStage'),
        (0xa83, 'mouseDown'),
        (0xa84, 'mouseMove'),
        (0xa85, 'mouseOut'),
        (0xa86, 'mouseOver'),
        (0xa87, 'mouseUp'),
        (0xa88, 'mouseWheel'),
        (0xa89, 'rollOut'),
        (0xa8a, 'rollOver'),
        (0xa8b, 'keyDown'),
        (0xa8c, 'keyUp'),
        (0xa8d, 'timer'),
        (0xa8e, 'complete'),
        (0xa8f, 'soundComplete'),
        (0xa90, 'open'),
        (0xa91, 'progress'),
        (0xa92, 'init'),
        (0xa93, 'ioError'),
        (0xa94, 'timerComplete'),
        (0xa95, 'removedFromStage'),
        (0xa96, 'removed'),
        (0xa97, 'frameConstructed'),
        (0xa98, 'doubleClick'),
        (0xa99, 'resize'),
        (0xa9a, 'added'),
        (0xa9b, 'tabChildrenChange'),
        (0xa9c, 'tabEnabledChange'),
        (0xa9d, 'tabIndexChange'),
        (0xa9e, 'exitFrame'),
        (0xa9f, 'render'),
        (0xaa0, 'activate'),
        (0xaa1, 'deactivate'),
        (0xaa2, 'securityError'),
        (0xaa3, 'error'),
        (0xaa4, 'close'),
        (0xaa5, 'udf0aa5'),
        (0xaa6, 'connect'),
        (0xaa7, 'mouseLeave'),
        (0xaa8, 'focusIn'),
        (0xaa9, 'focusOut'),
        (0xaaa, 'keyFocusChange'),
        (0xaab, 'mouseFocusChange'),
        (0xaac, 'link'),
        (0xaad, 'textInput'),
        (0xaae, 'change'),
        (0xaaf, 'scroll'),
        (0xab0, 'context3DCreate'),
        (0xab1, 'menuItemSelect'),
        (0xab2, 'menuSelect'),
        (0xab3, 'udf0ab3'),
        (0xab4, 'touchBegin'),
        (0xab5, 'touchEnd'),
        (0xab6, 'touchMove'),
        (0xab7, 'touchOut'),
        (0xab8, 'touchOver'),
        (0xab9, 'touchRollOut'),
        (0xaba, 'touchRollOver'),
        (0xabb, 'touchTap'),
        (0xabc, 'contextMenu'),
        (0xabd, 'middleClick'),
        (0xabe, 'middleMouseDown'),
        (0xabf, 'middleMouseUp'),
        (0xac0, 'releaseOutside'),
        (0xac1, 'rightClick'),
        (0xac2, 'rightMouseDown'),
        (0xac3, 'rightMouseUp'),

        # Seems like debugging information.
        (0xb00, 'flash.system.System'),
        (0xb01, 'flash.display.Stage'),
        (0xb02, 'udf0b02'),
        (0xb03, 'sme0b03'),
        (0xb04, 'udf0b04'),
        (0xb05, 'flash.display.MovieClip'),
        (0xb06, 'sme0b06'),
        (0xb07, 'flash.text.TextField'),
        (0xb08, 'fl.motion.Color'),
        (0xb09, 'sme0b09'),
        (0xb0a, 'flash.net.SharedObject'),
        (0xb0b, 'flash.ui.Mouse'),
        (0xb0c, 'sme0b0c'),
        (0xb0d, 'flash.media.Sound'),
        (0xb0e, 'sme0b0e'),
        (0xb0f, 'sme0b0f'),
        (0xb10, 'sme0b10'),
        (0xb11, 'flash.text.TextFormat'),
        (0xb12, 'udf0b12'),
        (0xb13, 'udf0b13'),
        (0xb14, 'flash.geom.Matrix'),
        (0xb15, 'flash.geom.Point'),
        (0xb16, 'flash.display.BitmapData'),
        (0xb17, 'udf0b17'),
        (0xb18, 'udf0b18'),
        (0xb19, 'flash.filters.ColorMatrixFilter'),
        (0xb1a, 'sme0b1a'),
        (0xb1b, 'flash.xml.XMLNode'),
        (0xb1c, 'sme0b1c'),
        (0xb1d, 'flash.geom.Transform'),
        (0xb1e, 'flash.geom.ColorTransform'),
        (0xb1f, 'flash.geom.Rectangle'),
        (0xb20, 'sme0b20'),
        (0xb21, 'sme0b21'),
        (0xb22, 'sme0b22'),
        (0xb23, 'sme0b23'),
        (0xb24, 'udf0b24'),
        (0xb25, 'sme0b25'),
        (0xb26, 'sme0b26'),
        (0xb27, 'sme0b27'),
        (0xb28, 'sme0b28'),
        (0xb29, 'flash.events.Event'),
        (0xb2a, 'flash.events.MouseEvent'),
        (0xb2b, 'flash.geom.Matrix3D'),
        (0xb2c, 'flash.ui.Keyboard'),
        (0xb2d, 'flash.display.DisplayObject'),
        (0xb2e, 'flash.utils.Dictionary'),
        (0xb2f, 'flash.display.BlendMode'),
        (0xb30, 'flash.display.DisplayObjectContainer'),
        (0xb31, 'sme0b31'),
        (0xb32, 'flash.events.EventDispatcher'),
        (0xb33, 'flash.geom.PerspectiveProjection'),
        (0xb34, 'flash.geom.Vector3D'),
        (0xb35, 'sme0b35'),
        (0xb36, 'flash.media.SoundChannel'),
        (0xb37, 'flash.display.Loader'),
        (0xb38, 'flash.net.URLRequest'),
        (0xb39, 'flash.display.Sprite'),
        (0xb3a, 'flash.events.KeyboardEvent'),
        (0xb3b, 'flash.utils.Timer'),
        (0xb3c, 'flash.events.TimerEvent'),
        (0xb3d, 'sme0b3d'),
        (0xb3e, 'sme0b3e'),
        (0xb3f, 'flash.display.LoaderInfo'),
        (0xb40, 'flash.events.ProgressEvent'),
        (0xb41, 'flash.events.IOErrorEvent'),
        (0xb42, 'flash.display.Graphics'),
        (0xb43, 'flash.display.LineScaleMode'),
        (0xb44, 'flash.display.CapsStyle'),
        (0xb45, 'flash.display.JointStyle'),
        (0xb46, 'flash.display.GradientType'),
        (0xb47, 'flash.display.SpreadMethod'),
        (0xb48, 'flash.display.InterpolationMethod'),
        (0xb49, 'flash.display.GraphicsPathCommand'),
        (0xb4a, 'flash.display.GraphicsPathWinding'),
        (0xb4b, 'flash.display.TriangleCulling'),
        (0xb4c, 'flash.display.GraphicsBitmapFill'),
        (0xb4d, 'flash.display.GraphicsEndFill'),
        (0xb4e, 'flash.display.GraphicsGradientFill'),
        (0xb4f, 'flash.display.GraphicsPath'),
        (0xb50, 'flash.display.GraphicsSolidFill'),
        (0xb51, 'flash.display.GraphicsStroke'),
        (0xb52, 'flash.display.GraphicsTrianglePath'),
        (0xb53, 'flash.display.IGraphicsData'),
        (0xb54, 'udf0b54'),
        (0xb55, 'flash.external.ExternalInterface'),
        (0xb56, 'flash.display.Scene'),
        (0xb57, 'flash.display.FrameLabel'),
        (0xb58, 'flash.display.Shape'),
        (0xb59, 'flash.display.SimpleButton'),
        (0xb5a, 'flash.display.Bitmap'),
        (0xb5b, 'flash.display.StageQuality'),
        (0xb5c, 'flash.display.InteractiveObject'),
        (0xb5d, 'fl.motion.MotionBase'),
        (0xb5e, 'fl.motion.KeyframeBase'),
        (0xb5f, 'sme0b5f'),
        (0xb60, 'flash.display.StageAlign'),
        (0xb61, 'flash.display.StageScaleMode'),
        (0xb62, 'fl.motion.AnimatorBase'),
        (0xb63, 'fl.motion.Animator3D'),
        (0xb64, 'flash.net.URLLoader'),
        (0xb65, 'flash.system.Capabilities'),
        (0xb66, 'sme0b66'),
        (0xb67, 'sme0b67'),
        (0xb68, 'flash.media.SoundTransform'),
        (0xb69, 'sme0b69'),
        (0xb6a, 'sme0b6a'),
        (0xb6b, 'sme0b6b'),
        (0xb6c, 'sme0b6c'),
        (0xb6d, 'flash.utils.ByteArray'),
        (0xb6e, 'flash.text.TextFormatAlign'),
        (0xb6f, 'flash.text.TextFieldType'),
        (0xb70, 'flash.text.TextFieldAutoSize'),
        (0xb71, 'flash.events.SecurityErrorEvent'),
        (0xb72, 'flash.system.ApplicationDomain'),
        (0xb73, 'flash.events.TextEvent'),
        (0xb74, 'flash.events.ErrorEvent'),
        (0xb75, 'flash.system.LoaderContext'),
        (0xb76, 'sme0b76'),
        (0xb77, 'flash.errors.IllegalOperationError'),
        (0xb78, 'flash.net.URLLoaderDataFormat'),
        (0xb79, 'flash.system.Security'),
        (0xb7a, 'flash.filters.DropShadowFilter'),
        (0xb7b, 'sme0b7b'),
        (0xb7c, 'flash.utils.Proxy'),
        (0xb7d, 'flash.net.XMLSocket'),
        (0xb7e, 'flash.events.DataEvent'),
        (0xb7f, 'flash.text.Font'),
        (0xb80, 'flash.events.IEventDispatcher'),
        (0xb81, 'flash.net.LocalConnection'),
        (0xb82, 'flash.display.ActionScriptVersion'),
        (0xb83, 'flash.ui.MouseCursor'),
        (0xb84, 'sme0b84'),
        (0xb85, 'flash.events.FocusEvent'),
        (0xb86, 'flash.text.AntiAliasType'),
        (0xb87, 'flash.text.GridFitType'),
        (0xb88, 'sme0b88'),
        (0xb89, 'flash.filters.BitmapFilterType'),
        (0xb8a, 'flash.filters.BevelFilter'),
        (0xb8b, 'flash.filters.BitmapFilter'),
        (0xb8c, 'flash.filters.BitmapFilterQuality'),
        (0xb8d, 'sme0b8d'),
        (0xb8e, 'flash.net.URLVariables'),
        (0xb8f, 'flash.net.URLRequestMethod'),
        (0xb90, 'sme0b90'),
        (0xb91, 'flash.filters.BlurFilter'),
        (0xb92, 'flash.display.Stage3D'),
        (0xb93, 'flash.display3D.Context3D'),
        (0xb94, 'flash.ui.Multitouch'),
        (0xb95, 'udf0b95'),
        (0xb96, 'flash.accessibility.AccessibilityProperties'),
        (0xb97, 'flash.text.StaticText'),
        (0xb98, 'flash.display.MorphShape'),
        (0xb99, 'flash.display.BitmapDataChannel'),
        (0xb9a, 'flash.filters.DisplacementMapFilter'),
        (0xb9b, 'flash.filters.GlowFilter'),
        (0xb9c, 'flash.filters.DisplacementMapFilterMode'),
        (0xb9d, 'fl.motion.AnimatorFactoryBase'),
        (0xb9e, 'flash.utils.Endian'),
        (0xb9f, 'flash.errors.IOError'),
        (0xba0, 'flash.errors.EOFError'),
        (0xba1, 'flash.display3D.Context3DTextureFormat'),
        (0xba2, 'flash.display3D.Context3DProgramType'),
        (0xba3, 'flash.display3D.textures.TextureBase'),
        (0xba4, 'flash.display3D.VertexBuffer3D'),
        (0xba5, 'flash.display3D.IndexBuffer3D'),
        (0xba6, 'flash.display3D.Program3D'),
        (0xba7, 'flash.display.NativeMenuItem'),
        (0xba8, 'flash.ui.ContextMenuItem'),
        (0xba9, 'flash.display.NativeMenu'),
        (0xbaa, 'flash.ui.ContextMenu'),
        (0xbab, 'flash.events.ContextMenuEvent'),
        (0xbac, 'flash.display3D.Context3DVertexBufferFormat'),
        (0xbad, 'flash.events.TouchEvent'),
        (0xbae, 'Box2D.Common.Math.b2Vec2'),
        (0xbaf, 'Box2D.Common.Math.b2Math'),
        (0xbb0, 'Box2D.Common.Math.b2Transform'),
        (0xbb1, 'Box2D.Common.Math.b2Mat22'),
        (0xbb2, 'Box2D.Common.Math.b2Sweep'),
        (0xbb3, 'Box2D.Collision.b2AABB'),
        (0xbb4, 'Box2D.Common.Math.b2Vec3'),
        (0xbb5, 'Box2D.Common.Math.b2Mat33'),
        (0xbb6, 'Box2D.Collision.b2DistanceProxy'),
        (0xbb7, 'Box2D.Collision.Shapes.b2Shape'),
        (0xbb8, 'Box2D.Collision.Shapes.b2CircleShape'),
        (0xbb9, 'Box2D.Collision.Shapes.b2PolygonShape'),
        (0xbba, 'Box2D.Collision.Shapes.b2MassData'),
        (0xbbb, 'Box2D.Collision.b2DistanceInput'),
        (0xbbc, 'Box2D.Collision.b2DistanceOutput'),
        (0xbbd, 'Box2D.Collision.b2SimplexCache'),
        (0xbbe, 'Box2D.Collision.b2Simplex'),
        (0xbbf, 'Box2D.Collision.b2SimplexVertex'),
        (0xbc0, 'Box2D.Collision.b2Distance'),
        (0xbc1, 'flash.geom.Orientation3D'),
        (0xbc2, 'flash.filters.GradientGlowFilter'),
        (0xbc3, 'flash.filters.GradientBevelFilter'),

        # More generic constants.
        (0xc00, 'NEARLY_ZERO'),
        (0xc01, 'EXACTLY_ZERO'),
        (0xc02, 'debug_mode'),
        (0xd00, 'm_count'),
        (0xd01, 'wA'),
        (0xd02, 'wB'),
        (0xd03, 'bubbles'),
        (0xd04, 'checkPolicyFile'),
        (0xd05, 'securityDomain'),
        (0xd06, 'spreadMethod'),
        (0xd07, 'interpolationMethod'),
        (0xd08, 'focalPointRatio'),
        (0xd09, 'culling'),
        (0xd0a, 'caps'),
        (0xd0b, 'winding'),
    ]

    @classmethod
    def property_to_name(cls, propid: int) -> str:
        for i, p in cls.__PROPERTIES:
            if i == propid:
                return p
        return f"<UNKNOWN {hex(propid)}>"


class SWF:
    def __init__(
        self,
        name: str,
        data: bytes,
        descramble_info: bytes = b"",
    ) -> None:
        self.name = name
        self.exported_name = ""
        self.data = data
        self.descramble_info = descramble_info

        # Initialize coverage. This is used to help find missed/hidden file
        # sections that we aren't parsing correctly.
        self.coverage: List[bool] = [False] * len(data)

        # Initialize string table. This is used for faster lookup of strings
        # as well as tracking which strings in the table have been parsed correctly.
        self.strings: Dict[int, Tuple[str, bool]] = {}

    def add_coverage(self, offset: int, length: int, unique: bool = True) -> None:
        for i in range(offset, offset + length):
            if self.coverage[i] and unique:
                raise Exception(f"Already covered {hex(offset)}!")
            self.coverage[i] = True

    def print_coverage(self) -> None:
        # First offset that is not coverd in a run.
        start = None

        for offset, covered in enumerate(self.coverage):
            if covered:
                if start is not None:
                    print(f"Uncovered bytes: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)
                    start = None
            else:
                if start is None:
                    start = offset
        if start is not None:
            # Print final range
            offset = len(self.coverage)
            print(f"Uncovered bytes: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)

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

    def __parse_bytecode(self, datachunk: bytes, string_offsets: List[int] = [], prefix: str = "", verbose: bool = False) -> None:
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

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

        vprint(f"{prefix}    Flags: {hex(flags)}, Bytecode Actual Offset: {hex(offset_ptr)}")

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
                vprint(f"{prefix}      {lineno}: {action_name}")
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

                vprint(f"{prefix}      {lineno}: {action_name} Flags: {hex(function_flags)}, Name: {funcname}, Bytecode Offset: {hex(bytecode_offset)}, Bytecode Length: {hex(bytecode_count)}")
                self.__parse_bytecode(datachunk[offset_ptr:(offset_ptr + bytecode_count)], string_offsets=string_offsets, prefix=prefix + "    ", verbose=verbose)
                vprint(f"{prefix}      END_{action_name}")

                offset_ptr += bytecode_count
            elif opcode == AP2Action.PUSH:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                vprint(f"{prefix}      {lineno}: {action_name}")

                while obj_count > 0:
                    obj_to_create = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                    offset_ptr += 1

                    if obj_to_create == 0x0:
                        # Integer "0" object.
                        vprint(f"{prefix}        INTEGER: 0")
                    elif obj_to_create == 0x1:
                        # Float object, represented internally as a double.
                        fval = struct.unpack(">f", datachunk[offset_ptr:(offset_ptr + 4)])[0]
                        offset_ptr += 4

                        vprint(f"{prefix}        FLOAT: {fval}")
                    elif obj_to_create == 0x2:
                        # Null pointer object.
                        vprint(f"{prefix}        NULL")
                    elif obj_to_create == 0x3:
                        # Undefined constant.
                        vprint(f"{prefix}        UNDEFINED")
                    elif obj_to_create == 0x4:
                        # Register value.
                        regno = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        offset_ptr += 1

                        vprint(f"{prefix}        REGISTER NO: {regno}")
                    elif obj_to_create == 0x5:
                        # Boolean "TRUE" object.
                        vprint(f"{prefix}        BOOLEAN: True")
                    elif obj_to_create == 0x6:
                        # Boolean "FALSE" object.
                        vprint(f"{prefix}        BOOLEAN: False")
                    elif obj_to_create == 0x7:
                        # Integer object.
                        ival = struct.unpack(">I", datachunk[offset_ptr:(offset_ptr + 4)])[0]
                        offset_ptr += 4

                        vprint(f"{prefix}        INTEGER: {ival}")
                    elif obj_to_create == 0x8:
                        # String constant object.
                        const_offset = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        offset_ptr += 1

                        vprint(f"{prefix}        STRING CONST: {const}")
                    elif obj_to_create == 0x9:
                        # String constant, but with 16 bits for the offset. Probably not used except
                        # on the largest files.
                        const_offset = struct.unpack(">H", datachunk[offset_ptr:(offset_ptr + 2)])[0]
                        const = self.__get_string(string_offsets[const_offset])
                        offset_ptr += 2

                        vprint(f"{prefix}        STRING_CONTS: {const}")
                    elif obj_to_create == 0xa:
                        # NaN constant.
                        vprint(f"{prefix}        NAN")
                    elif obj_to_create == 0xb:
                        # Infinity constant.
                        vprint(f"{prefix}        INFINITY")
                    elif obj_to_create == 0xc:
                        # Pointer to "this" object, whatever currently is executing the bytecode.
                        vprint(f"{prefix}        POINTER TO THIS")
                    elif obj_to_create == 0xd:
                        # Pointer to "root" object, which is the movieclip this bytecode exists in.
                        vprint(f"{prefix}        POINTER TO ROOT")
                    elif obj_to_create == 0xe:
                        # Pointer to "parent" object, whatever currently is executing the bytecode.
                        # This seems to be the parent of the movie clip, or the current movieclip
                        # if that isn't set.
                        vprint(f"{prefix}        POINTER TO PARENT")
                    elif obj_to_create == 0xf:
                        # Current movie clip.
                        vprint(f"{prefix}        POINTER TO CURRENT MOVIECLIP")
                    elif obj_to_create == 0x10:
                        # Unknown property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x100
                        offset_ptr += 1
                        vprint(f"{prefix}        PROPERTY CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x13:
                        # Class property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x300
                        offset_ptr += 1
                        vprint(f"{prefix}        CLASS CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x16:
                        # Func property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x400
                        offset_ptr += 1
                        vprint(f"{prefix}        FUNC CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x19:
                        # Other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x200
                        offset_ptr += 1
                        vprint(f"{prefix}        OTHER CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x1c:
                        # Event property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x500
                        offset_ptr += 1
                        vprint(f"{prefix}        EVENT CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x1f:
                        # Key constants.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x600
                        offset_ptr += 1
                        vprint(f"{prefix}        KEY CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x22:
                        # Pointer to global object.
                        vprint(f"{prefix}        POINTER TO GLOBAL OBJECT")
                    elif obj_to_create == 0x24:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x700
                        offset_ptr += 1
                        vprint(f"{prefix}        ETC2 CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x27:
                        # Some other property name.
                        propertyval = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0] + 0x800
                        offset_ptr += 1
                        vprint(f"{prefix}        ORGFUNC2 CONST NAME: {AP2PropertyType.property_to_name(propertyval)}")
                    elif obj_to_create == 0x37:
                        # Integer object but one byte.
                        ival = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                        offset_ptr += 1

                        vprint(f"{prefix}        INTEGER: {ival}")
                    else:
                        raise Exception(f"Unsupported object {hex(obj_to_create)} to push!")

                    obj_count -= 1

                vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.STORE_REGISTER:
                obj_count = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                vprint(f"{prefix}      {lineno}: {action_name}")

                while obj_count > 0:
                    register_no = struct.unpack(">B", datachunk[offset_ptr:(offset_ptr + 1)])[0]
                    offset_ptr += 1
                    obj_count -= 1

                    vprint(f"{prefix}        REGISTER NO: {register_no}")
                vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.STORE_REGISTER2:
                register_no = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                vprint(f"{prefix}      {lineno}: {action_name}")
                vprint(f"{prefix}        REGISTER NO: {register_no}")
                vprint(f"{prefix}      END_{action_name}")
            elif opcode == AP2Action.IF:
                jump_if_true_offset = struct.unpack(">H", datachunk[(offset_ptr + 1):(offset_ptr + 3)])[0]
                offset_ptr += 3

                # TODO: This can jump outside of a function definition, most commonly seen when jumping to an
                # "END" pointer at the end of a chunk. We need to handle this. We probably need function lines
                # to be absolute instead of relative.
                jump_if_true_offset += offset_ptr - start_offset

                vprint(f"{prefix}      {lineno}: Offset If True: {jump_if_true_offset}")
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

                vprint(f"{prefix}      {lineno}: {action_name} {if2_typestr}, Offset If True: {jump_if_true_offset}")
            elif opcode == AP2Action.JUMP:
                jump_offset = struct.unpack(">H", datachunk[(offset_ptr + 1):(offset_ptr + 3)])[0]
                offset_ptr += 3

                # TODO: This can jump outside of a function definition, most commonly seen when jumping to an
                # "END" pointer at the end of a chunk. We need to handle this. We probably need function lines
                # to be absolute instead of relative.
                jump_offset += offset_ptr - start_offset
                vprint(f"{prefix}      {lineno}: {action_name} Offset: {jump_offset}")
            elif opcode == AP2Action.ADD_NUM_VARIABLE:
                amount_to_add = struct.unpack(">B", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                vprint(f"{prefix}      {lineno}: {action_name} Add Value: {amount_to_add}")
            elif opcode == AP2Action.START_DRAG:
                constraint = struct.unpack(">b", datachunk[(offset_ptr + 1):(offset_ptr + 2)])[0]
                offset_ptr += 2

                vprint(f"{prefix}      {lineno}: {action_name} Constrain Mouse: {'yes' if constraint > 0 else ('no' if constraint == 0 else 'check stack')}")
            elif opcode == AP2Action.ADD_NUM_REGISTER:
                register_no, amount_to_add = struct.unpack(">BB", datachunk[(offset_ptr + 1):(offset_ptr + 3)])
                offset_ptr += 3

                vprint(f"{prefix}      {lineno}: {action_name} Register No: {register_no}, Add Value: {amount_to_add}")
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

                vprint(f"{prefix}      {lineno}: {action_name} AND {post} Additional Frames: {additional_frames}")
            else:
                raise Exception(f"Can't advance, no handler for opcode {opcode} ({hex(opcode)})!")

    def __parse_tag(self, ap2_version: int, afp_version: int, ap2data: bytes, tagid: int, size: int, dataoffset: int, prefix: str = "", verbose: bool = False) -> None:
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        if tagid == AP2Tag.AP2_SHAPE:
            if size != 4:
                raise Exception(f"Invalid shape size {size}")

            _, shape_id = struct.unpack("<HH", ap2data[dataoffset:(dataoffset + 4)])
            add_coverage(dataoffset, size)

            shape_reference = f"{self.exported_name}_shape{shape_id}"
            vprint(f"{prefix}    Tag ID: {shape_id}, AFP Reference: {shape_reference}, IFS GEO Filename: {md5(shape_reference.encode('utf-8')).hexdigest()}")
        elif tagid == AP2Tag.AP2_DEFINE_SPRITE:
            sprite_flags, sprite_id = struct.unpack("<HH", ap2data[dataoffset:(dataoffset + 4)])
            add_coverage(dataoffset, 4)

            if sprite_flags & 1 == 0:
                # This is an old-style tag, it has data directly following the header.
                subtags_offset = dataoffset + 4
            else:
                # This is a new-style tag, it has a relative data pointer.
                subtags_offset = struct.unpack("<I", ap2data[(dataoffset + 4):(dataoffset + 8)])[0] + dataoffset
                add_coverage(dataoffset + 4, 4)

            vprint(f"{prefix}    Tag ID: {sprite_id}")
            self.__parse_tags(ap2_version, afp_version, ap2data, subtags_offset, prefix="      " + prefix, verbose=verbose)
        elif tagid == AP2Tag.AP2_DEFINE_FONT:
            unk, font_id, fontname_offset, xml_prefix_offset, data_offset, data_count = struct.unpack("<HHHHHH", ap2data[dataoffset:(dataoffset + 12)])
            add_coverage(dataoffset, 12)

            fontname = self.__get_string(fontname_offset)
            xml_prefix = self.__get_string(xml_prefix_offset)

            vprint(f"{prefix}    Tag ID: {font_id}, Font Name: {fontname}, XML Prefix: {xml_prefix}, Entries: {data_count}")

            for i in range(data_count):
                entry_offset = dataoffset + 12 + (data_offset * 2) + (i * 2)
                entry_value = struct.unpack("<H", ap2data[entry_offset:(entry_offset + 2)])[0]
                add_coverage(entry_offset, 2)

                vprint(f"{prefix}      Height: {entry_value}")
        elif tagid == AP2Tag.AP2_DO_ACTION:
            datachunk = ap2data[dataoffset:(dataoffset + size)]
            self.__parse_bytecode(datachunk, prefix=prefix, verbose=verbose)
            add_coverage(dataoffset, size)
        elif tagid == AP2Tag.AP2_PLACE_OBJECT:
            # Allow us to keep track of what we've consumed.
            datachunk = ap2data[dataoffset:(dataoffset + size)]
            flags, depth, object_id = struct.unpack("<IHH", datachunk[0:8])
            add_coverage(dataoffset, 8)

            vprint(f"{prefix}    Flags: {hex(flags)}, Object ID: {object_id}, Depth: {depth}")

            running_pointer = 8
            unhandled_flags = flags

            if flags & 0x2:
                unhandled_flags &= ~0x2
                src_tag_id = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                vprint(f"{prefix}    Source Tag ID: {src_tag_id}")

            if flags & 0x10:
                unhandled_flags &= ~0x10
                unk2 = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                vprint(f"{prefix}    Unk2: {hex(unk2)}")

            if flags & 0x20:
                unhandled_flags &= ~0x20
                nameoffset = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                add_coverage(dataoffset + running_pointer, 2)
                name = self.__get_string(nameoffset)
                running_pointer += 2
                vprint(f"{prefix}    Name: {name}")

            if flags & 0x40:
                unhandled_flags &= ~0x40
                unk3 = struct.unpack("<H", datachunk[running_pointer:(running_pointer + 2)])[0]
                add_coverage(dataoffset + running_pointer, 2)
                running_pointer += 2
                vprint(f"{prefix}    Unk3: {hex(unk3)}")

            if flags & 0x20000:
                unhandled_flags &= ~0x20000
                blend = struct.unpack("<B", datachunk[running_pointer:(running_pointer + 1)])[0]
                add_coverage(dataoffset + running_pointer, 1)
                running_pointer += 1
                vprint(f"{prefix}    Blend: {hex(blend)}")

            # Due to possible misalignment, we need to realign.
            misalignment = running_pointer & 3
            if misalignment > 0:
                catchup = 4 - misalignment
                add_coverage(dataoffset + running_pointer, catchup)
                running_pointer += catchup

            # Handle transformation matrix.
            transform = Matrix.identity()

            if flags & 0x100:
                unhandled_flags &= ~0x100
                a_int, d_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.a = float(a_int) * 0.0009765625
                transform.d = float(d_int) * 0.0009765625
                vprint(f"{prefix}    Transform Matrix A: {transform.a}, D: {transform.d}")

            if flags & 0x200:
                unhandled_flags &= ~0x200
                b_int, c_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.b = float(b_int) * 0.0009765625
                transform.c = float(c_int) * 0.0009765625
                vprint(f"{prefix}    Transform Matrix B: {transform.b}, C: {transform.c}")

            if flags & 0x400:
                unhandled_flags &= ~0x400
                tx_int, ty_int = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                transform.tx = float(tx_int) / 20.0
                transform.ty = float(tx_int) / 20.0
                vprint(f"{prefix}    Transform Matrix TX: {transform.tx}, TY: {transform.ty}")

            # Handle object colors
            color = Color(1.0, 1.0, 1.0, 1.0)
            acolor = Color(1.0, 1.0, 1.0, 1.0)

            if flags & 0x800:
                unhandled_flags &= ~0x800
                r, g, b, a = struct.unpack("<HHHH", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                color.r = float(r) * 0.003921569
                color.g = float(g) * 0.003921569
                color.b = float(b) * 0.003921569
                color.a = float(a) * 0.003921569
                vprint(f"{prefix}    Color: {color}")

            if flags & 0x1000:
                unhandled_flags &= ~0x1000
                r, g, b, a = struct.unpack("<HHHH", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                acolor.r = float(r) * 0.003921569
                acolor.g = float(g) * 0.003921569
                acolor.b = float(b) * 0.003921569
                acolor.a = float(a) * 0.003921569
                vprint(f"{prefix}    AColor: {color}")

            if flags & 0x2000:
                unhandled_flags &= ~0x2000
                rgba = struct.unpack("<I", datachunk[running_pointer:(running_pointer + 4)])[0]
                add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                color.r = float((rgba >> 24) & 0xFF) * 0.003921569
                color.g = float((rgba >> 16) & 0xFF) * 0.003921569
                color.b = float((rgba >> 8) & 0xFF) * 0.003921569
                color.a = float(rgba & 0xFF) * 0.003921569
                vprint(f"{prefix}    Color: {color}")

            if flags & 0x4000:
                unhandled_flags &= ~0x4000
                rgba = struct.unpack("<I", datachunk[running_pointer:(running_pointer + 4)])[0]
                add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                acolor.r = float((rgba >> 24) & 0xFF) * 0.003921569
                acolor.g = float((rgba >> 16) & 0xFF) * 0.003921569
                acolor.b = float((rgba >> 8) & 0xFF) * 0.003921569
                acolor.a = float(rgba & 0xFF) * 0.003921569
                vprint(f"{prefix}    AColor: {color}")

            if flags & 0x80:
                # Object event triggers.
                unhandled_flags &= ~0x80
                event_flags, event_size = struct.unpack("<II", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)

                if event_flags != 0:
                    _, count = struct.unpack("<HH", datachunk[(running_pointer + 8):(running_pointer + 12)])
                    add_coverage(dataoffset + running_pointer + 8, 4)

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

                    vprint(f"{prefix}    Event Triggers, Count: {count}")
                    for evt in range(count):
                        evt_offset = running_pointer + 12 + (evt * 8)
                        evt_flags, _, keycode, bytecode_offset = struct.unpack("<IBBH", datachunk[evt_offset:(evt_offset + 8)])
                        add_coverage(dataoffset + evt_offset, 8)

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

                        vprint(f"{prefix}      Flags: {hex(evt_flags)} ({', '.join(events)}), KeyCode: {hex(keycode)}, Bytecode Offset: {hex(dataoffset + bytecode_offset)}, Length: {bytecode_length}")
                        self.__parse_bytecode(datachunk[bytecode_offset:(bytecode_offset + bytecode_length)], prefix=prefix + "    ", verbose=verbose)
                        add_coverage(dataoffset + bytecode_offset, bytecode_length)

                running_pointer += event_size

            if flags & 0x10000:
                # Some sort of filter data? Not sure what this is either. Needs more investigation
                # if I encounter files with it.
                unhandled_flags &= ~0x10000
                count, filter_size = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                add_coverage(dataoffset + running_pointer, 4)
                running_pointer += filter_size

                # TODO: This is not understood at all. I need to find data that uses it to continue.
                # running_pointer + 4 starts a series of shorts (exactly count of them) which are
                # all in the range of 0-7, corresponding to some sort of filter. They get sizes
                # looked up and I presume there's data following this corresponding to those sizes.
                # I don't know however as I've not encountered data with this bit.
                vprint(f"{prefix}    Unknown Filter data Count: {count}, Size: {filter_size}")

            if flags & 0x1000000:
                # Some sort of point, perhaps an x, y offset for the object?
                unhandled_flags &= ~0x1000000
                x, y = struct.unpack("<ff", datachunk[running_pointer:(running_pointer + 8)])
                add_coverage(dataoffset + running_pointer, 8)
                running_pointer += 8

                # TODO: This doesn't seem right when run past Pop'n Music data.
                point = Point(x / 20.0, y / 20.0)
                vprint(f"{prefix}    Point: {point}")

            if flags & 0x2000000:
                # Same as above, but initializing to 0, 0 instead of from data.
                unhandled_flags &= ~0x2000000
                point = Point(0.0, 0.0)
                vprint(f"{prefix}    Point: {point}")

            if flags & 0x40000:
                # Some pair of shorts, not sure, its in DDR PS3 data.
                unhandled_flags &= ~0x40000
                x, y = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                # TODO: I have no idea what these are.
                point = Point(x * 3.051758e-05, y * 3.051758e-05)
                vprint(f"{prefix}    Point: {point}")

            if flags & 0x80000:
                # Some pair of shorts, not sure, its in DDR PS3 data.
                unhandled_flags &= ~0x80000
                x, y = struct.unpack("<HH", datachunk[running_pointer:(running_pointer + 4)])
                add_coverage(dataoffset + running_pointer, 4)
                running_pointer += 4

                # TODO: I have no idea what these are.
                point = Point(x * 3.051758e-05, y * 3.051758e-05)
                vprint(f"{prefix}    Point: {point}")

            # This flag states whether we are creating a new object on this depth, or updating one.
            unhandled_flags &= ~0xD
            if flags & 0x1:
                vprint(f"{prefix}    Update object request")
            else:
                vprint(f"{prefix}    Create object request")
            if flags & 0x4:
                vprint(f"{prefix}    Use transform matrix")
            else:
                vprint(f"{prefix}    Ignore transform matrix")
            if flags & 0x4:
                vprint(f"{prefix}    Use color information")
            else:
                vprint(f"{prefix}    Ignore color information")

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
            vprint(f"{prefix}    Object ID: {object_id}, Depth: {depth}")
            add_coverage(dataoffset, 4)
        elif tagid == AP2Tag.AP2_DEFINE_EDIT_TEXT:
            if size != 44:
                raise Exception("Invalid size {size} to get data from AP2_DEFINE_EDIT_TEXT!")

            flags, edit_text_id, defined_font_tag_id, font_height, unk_str2_offset = struct.unpack("<IHHHH", ap2data[dataoffset:(dataoffset + 12)])
            add_coverage(dataoffset, 12)

            unk1, unk2, unk3, unk4 = struct.unpack("<HHHH", ap2data[(dataoffset + 12):(dataoffset + 20)])
            add_coverage(dataoffset + 12, 8)

            rgba, f1, f2, f3, f4, variable_name_offset, default_text_offset = struct.unpack("<IiiiiHH", ap2data[(dataoffset + 20):(dataoffset + 44)])
            add_coverage(dataoffset + 20, 24)

            vprint(f"{prefix}    Tag ID: {edit_text_id}, Font Tag: {defined_font_tag_id}, Height Selection: {font_height}, Flags: {hex(flags)}")

            unk_string2 = self.__get_string(unk_str2_offset) or None
            vprint(f"{prefix}      Unk String: {unk_string2}")

            rect = Rectangle(f1 / 20.0, f2 / 20.0, f3 / 20.0, f4 / 20.0)
            vprint(f"{prefix}      Rectangle: {rect}")

            variable_name = self.__get_string(variable_name_offset) or None
            vprint(f"{prefix}      Variable Name: {variable_name}")

            color = Color(
                r=(rgba & 0xFF) / 255.0,
                g=((rgba >> 8) & 0xFF) / 255.0,
                b=((rgba >> 16) & 0xFF) / 255.0,
                a=((rgba >> 24) & 0xFF) / 255.0,
            )
            vprint(f"{prefix}      Text Color: {color}")

            vprint(f"{prefix}      Unk1: {unk1}, Unk2: {unk2}, Unk3: {unk3}, Unk4: {unk4}")

            # flags & 0x20 means something with offset 16-18.
            # flags & 0x200 is unk str below is a HTML tag.

            if flags & 0x80:
                # Has some sort of string pointer.
                default_text = self.__get_string(default_text_offset) or None
                vprint(f"{prefix}      Default Text: {default_text}")
        else:
            raise Exception(f"Unimplemented tag {hex(tagid)}!")

    def __parse_tags(self, ap2_version: int, afp_version: int, ap2data: bytes, tags_base_offset: int, prefix: str = "", verbose: bool = False) -> None:
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        unknown_tags_flags, unknown_tags_count, frame_count, tags_count, unknown_tags_offset, frame_offset, tags_offset = struct.unpack(
            "<HHIIIII",
            ap2data[tags_base_offset:(tags_base_offset + 24)]
        )
        add_coverage(tags_base_offset, 24)

        # Fix up pointers.
        tags_offset += tags_base_offset
        unknown_tags_offset += tags_base_offset
        frame_offset += tags_base_offset

        # First, parse regular tags.
        vprint(f"{prefix}Number of Tags: {tags_count}")
        for i in range(tags_count):
            tag = struct.unpack("<I", ap2data[tags_offset:(tags_offset + 4)])[0]
            add_coverage(tags_offset, 4)

            tagid = (tag >> 22) & 0x3FF
            size = tag & 0x3FFFFF

            if size > 0x200000:
                raise Exception(f"Invalid tag size {size} ({hex(size)})")

            vprint(f"{prefix}  Tag: {hex(tagid)} ({AP2Tag.tag_to_name(tagid)}), Size: {hex(size)}, Offset: {hex(tags_offset + 4)}")
            self.__parse_tag(ap2_version, afp_version, ap2data, tagid, size, tags_offset + 4, prefix=prefix, verbose=verbose)
            tags_offset += ((size + 3) & 0xFFFFFFFC) + 4  # Skip past tag header and data, rounding to the nearest 4 bytes.

        # Now, parse frames.
        vprint(f"{prefix}Number of Frames: {frame_count}")
        for i in range(frame_count):
            frame_info = struct.unpack("<I", ap2data[frame_offset:(frame_offset + 4)])[0]
            add_coverage(frame_offset, 4)

            start_tag_id = frame_info & 0xFFFFF
            num_tags_to_play = (frame_info >> 20) & 0xFFF

            vprint(f"{prefix}  Frame Start Tag: {hex(start_tag_id)}, Count: {num_tags_to_play}")
            frame_offset += 4

        # Now, parse unknown tags? I have no idea what these are, but they're referencing strings that
        # are otherwise unused.
        vprint(f"{prefix}Number of Unknown Tags: {unknown_tags_count}, Flags: {hex(unknown_tags_flags)}")
        for i in range(unknown_tags_count):
            unk1, stringoffset = struct.unpack("<HH", ap2data[unknown_tags_offset:(unknown_tags_offset + 4)])
            strval = self.__get_string(stringoffset)
            add_coverage(unknown_tags_offset, 4)

            vprint(f"{prefix}  Unknown Tag: {hex(unk1)} Name: {strval}")
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
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage

            # Reinitialize coverage.
            self.coverage = [False] * len(self.data)
            self.strings = {}
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        # First, use the byteswap header to descramble the data.
        data = self.__descramble(self.data, self.descramble_info)

        # Start with the basic file header.
        magic, length, version, nameoffset, flags, left, right, top, bottom = struct.unpack("<4sIHHIHHHH", data[0:24])
        width = right - left
        height = bottom - top
        add_coverage(0, 24)

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
        add_coverage(28, 4)

        if flags & 0x2:
            # FPS can be either an integer or a float.
            fps = struct.unpack("<i", data[24:28])[0] * 0.0009765625
        else:
            fps = struct.unpack("<f", data[24:28])[0]
        add_coverage(24, 4)

        if flags & 0x4:
            # This seems related to imported tags.
            imported_tag_initializers_offset = struct.unpack("<I", data[56:60])[0]
            add_coverage(56, 4)
        else:
            # Unknown offset is not present.
            imported_tag_initializers_offset = None

        # String table
        stringtable_offset, stringtable_size = struct.unpack("<II", data[48:56])
        add_coverage(48, 8)

        # Descramble string table.
        data = self.__descramble_stringtable(data, stringtable_offset, stringtable_size)
        add_coverage(stringtable_offset, stringtable_size)

        # Get exported SWF name.
        self.exported_name = self.__get_string(nameoffset)
        add_coverage(nameoffset + stringtable_offset, len(self.exported_name) + 1, unique=False)
        vprint(f"{os.linesep}AFP name: {self.name}")
        vprint(f"Container Version: {hex(ap2_data_version)}")
        vprint(f"Version: {hex(version)}")
        vprint(f"Exported Name: {self.exported_name}")
        vprint(f"SWF Flags: {hex(flags)}")
        if flags & 0x1:
            vprint(f"  0x1: Movie background color: {swf_color}")
        else:
            vprint("  0x2: No movie background color")
        if flags & 0x2:
            vprint("  0x2: FPS is an integer")
        else:
            vprint("  0x2: FPS is a float")
        if flags & 0x4:
            vprint("  0x4: Imported tag initializer section present")
        else:
            vprint("  0x4: Imported tag initializer section not present")
        vprint(f"Dimensions: {width}x{height}")
        vprint(f"Requested FPS: {fps}")

        # Exported assets
        num_exported_assets = struct.unpack("<H", data[32:34])[0]
        asset_offset = struct.unpack("<I", data[40:44])[0]
        add_coverage(32, 2)
        add_coverage(40, 4)

        # Parse exported asset tag names and their tag IDs.
        vprint(f"Number of Exported Tags: {num_exported_assets}")
        for assetno in range(num_exported_assets):
            asset_data_offset, asset_string_offset = struct.unpack("<HH", data[asset_offset:(asset_offset + 4)])
            add_coverage(asset_offset, 4)
            asset_offset += 4

            asset_name = self.__get_string(asset_string_offset)
            add_coverage(asset_string_offset + stringtable_offset, len(asset_name) + 1, unique=False)
            vprint(f"  {assetno}: Tag Name: {asset_name} Tag ID: {asset_data_offset}")

        # Tag sections
        tags_offset = struct.unpack("<I", data[36:40])[0]
        add_coverage(36, 4)
        self.__parse_tags(ap2_data_version, version, data, tags_offset, verbose=verbose)

        # Imported tags sections
        imported_tags_count = struct.unpack("<h", data[34:36])[0]
        imported_tags_offset = struct.unpack("<I", data[44:48])[0]
        imported_tags_data_offset = imported_tags_offset + 4 * imported_tags_count
        add_coverage(34, 2)
        add_coverage(44, 4)

        vprint(f"Number of Imported Tags: {imported_tags_count}")
        for i in range(imported_tags_count):
            # First grab the SWF this is importing from, and the number of assets being imported.
            swf_name_offset, count = struct.unpack("<HH", data[imported_tags_offset:(imported_tags_offset + 4)])
            add_coverage(imported_tags_offset, 4)

            swf_name = self.__get_string(swf_name_offset)
            add_coverage(swf_name_offset + stringtable_offset, len(swf_name) + 1, unique=False)
            vprint(f"  Source SWF: {swf_name}")

            # Now, grab the actual asset names being imported.
            for j in range(count):
                asset_id_no, asset_name_offset = struct.unpack("<HH", data[imported_tags_data_offset:(imported_tags_data_offset + 4)])
                add_coverage(imported_tags_data_offset, 4)

                asset_name = self.__get_string(asset_name_offset)
                add_coverage(asset_name_offset + stringtable_offset, len(asset_name) + 1, unique=False)
                vprint(f"    Tag ID: {asset_id_no}, Requested Asset: {asset_name}")

                imported_tags_data_offset += 4

            imported_tags_offset += 4

        # This appears to be bytecode to execute on a per-frame basis. We execute this every frame and
        # only execute up to the point where we equal the current frame.
        if imported_tag_initializers_offset is not None:

            unk1, length = struct.unpack("<HH", data[imported_tag_initializers_offset:(imported_tag_initializers_offset + 4)])
            add_coverage(imported_tag_initializers_offset, 4)

            vprint(f"Imported Tag Initializer Offset: {hex(imported_tag_initializers_offset)}, Length: {length}")

            for i in range(length):
                item_offset = imported_tag_initializers_offset + 4 + (i * 12)
                tag_id, frame, action_bytecode_offset, action_bytecode_length = struct.unpack("<HHII", data[item_offset:(item_offset + 12)])
                add_coverage(item_offset, 12)

                if action_bytecode_length != 0:
                    vprint(f"  Tag ID: {tag_id}, Frame: {frame}, Bytecode Offset: {hex(action_bytecode_offset + imported_tag_initializers_offset)}")
                    bytecode_data = data[(action_bytecode_offset + imported_tag_initializers_offset):(action_bytecode_offset + imported_tag_initializers_offset + action_bytecode_length)]
                    self.__parse_bytecode(bytecode_data, verbose=verbose)
                else:
                    vprint(f"  Tag ID: {tag_id}, Frame: {frame}, No Bytecode Present")

        if verbose:
            self.print_coverage()


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

    def as_dict(self) -> Dict[str, Any]:
        return {
            'flags': self.flags,
            'region': self.region,
            'vertexes': self.vertexes,
            'blend': self.blend.as_dict() if self.blend else None,
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


class Shape:
    def __init__(
        self,
        name: str,
        data: bytes,
    ) -> None:
        self.name = name
        self.data = data

        # Vertex points outlining this shape.
        self.vertex_points: List[Point] = []

        # Texture points, as used alongside vertex chunks when the shape contains a texture.
        self.tex_points: List[Point] = []

        # Colors for texture points, if they exist in the file.
        self.tex_colors: List[Color] = []

        # Actual shape drawing parameters.
        self.draw_params: List[DrawParams] = []

    def as_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'vertex_points': [p.as_dict() for p in self.vertex_points],
            'tex_points': [p.as_dict() for p in self.tex_points],
            'tex_colors': [c.as_dict() for c in self.tex_colors],
            'draw_params': [d.as_dict() for d in self.draw_params],
        }

    def __repr__(self) -> str:
        return os.linesep.join([
            *[f"vertex point: {vertex}" for vertex in self.vertex_points],
            *[f"tex point: {tex}" for tex in self.tex_points],
            *[f"tex color: {color}" for color in self.tex_colors],
            *[f"draw params: {params}" for params in self.draw_params],
        ])

    def get_until_null(self, offset: int) -> bytes:
        out = b""
        while self.data[offset] != 0:
            out += self.data[offset:(offset + 1)]
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

        filesize = struct.unpack(f"{endian}I", self.data[12:16])[0]
        if filesize != len(self.data):
            raise Exception("Unexpected file size for GE2D structure!")

        # There is an integer at 0x16 which always appears to be zero. It should be
        # file flags, but I don't know what it does since no code I've found cares.
        if self.data[16:20] != b"\0\0\0\0":
            raise Exception("Unhandled flag data bytes in GE2D structure!")

        vertex_count, tex_count, color_count, label_count, render_params_count, _ = struct.unpack(
            f"{endian}HHHHHH",
            self.data[20:32],
        )

        vertex_offset, tex_offset, color_offset, label_offset, render_params_offset = struct.unpack(
            f"{endian}IIIII",
            self.data[32:52],
        )

        vertex_points: List[Point] = []
        if vertex_offset != 0:
            for vertexno in range(vertex_count):
                vertexno_offset = vertex_offset + (8 * vertexno)
                x, y = struct.unpack(f"{endian}ff", self.data[vertexno_offset:vertexno_offset + 8])
                vertex_points.append(Point(x, y))
        self.vertex_points = vertex_points

        tex_points: List[Point] = []
        if tex_offset != 0:
            for texno in range(tex_count):
                texno_offset = tex_offset + (8 * texno)
                x, y = struct.unpack(f"{endian}ff", self.data[texno_offset:texno_offset + 8])
                tex_points.append(Point(x, y))
        self.tex_points = tex_points

        colors: List[Color] = []
        if color_offset != 0:
            for colorno in range(color_count):
                colorno_offset = color_offset + (4 * colorno)
                rgba = struct.unpack(f"{endian}I", self.data[colorno_offset:colorno_offset + 4])[0]
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
                labelptr = struct.unpack(f"{endian}I", self.data[labelno_offset:labelno_offset + 4])[0]

                bytedata = self.get_until_null(labelptr)
                labels.append(AFPFile.descramble_text(bytedata, text_obfuscated))

        draw_params: List[DrawParams] = []
        if render_params_offset != 0:
            # The actual render parameters for the shape. This dictates how the texture values
            # are used when drawing shapes, whether to use a blend value or draw a primitive, etc.
            for render_paramsno in range(render_params_count):
                render_paramsno_offset = render_params_offset + (16 * render_paramsno)
                mode, flags, tex1, tex2, trianglecount, _, rgba, triangleoffset = struct.unpack(
                    f"{endian}BBBBHHII",
                    self.data[(render_paramsno_offset):(render_paramsno_offset + 16)]
                )

                if mode != 4:
                    raise Exception("Unexpected mode in GE2D structure!")
                if (flags & 0x2) and len(labels) == 0:
                    raise Exception("GE2D structure has a texture, but no region labels present!")
                if (flags & 0x2) and (tex1 == 0xFF):
                    raise Exception("GE2D structure requests a texture, but no texture pointer present!")
                if tex2 != 0xFF:
                    raise Exception("GE2D structure requests a second texture, but we don't support this!")

                color = Color(
                    r=(rgba & 0xFF) / 255.0,
                    g=((rgba >> 8) & 0xFF) / 255.0,
                    b=((rgba >> 16) & 0xFF) / 255.0,
                    a=((rgba >> 24) & 0xFF) / 255.0,
                )

                verticies: List[int] = []
                for render_paramstriangleno in range(trianglecount):
                    render_paramstriangleno_offset = triangleoffset + (2 * render_paramstriangleno)
                    tex_offset = struct.unpack(f"{endian}H", self.data[render_paramstriangleno_offset:(render_paramstriangleno_offset + 2)])[0]
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


class Unknown1:
    def __init__(
        self,
        name: str,
        data: bytes,
    ) -> None:
        self.name = name
        self.data = data
        if len(data) != 12:
            raise Exception("Unexpected length for Unknown1 structure!")

    def as_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'data': "".join(_hex(x) for x in self.data),
        }


class Unknown2:
    def __init__(
        self,
        data: bytes,
    ) -> None:
        self.data = data
        if len(data) != 4:
            raise Exception("Unexpected length for Unknown2 structure!")

    def as_dict(self) -> Dict[str, Any]:
        return {
            'data': "".join(_hex(x) for x in self.data),
        }


class AFPFile:
    def __init__(self, contents: bytes, verbose: bool = False) -> None:
        # Initialize coverage. This is used to help find missed/hidden file
        # sections that we aren't parsing correctly.
        self.coverage: List[bool] = [False] * len(contents)

        # Original file data that we parse into structures.
        self.data = contents

        # Font data encoding handler. We keep this around as it manages
        # remembering the actual BinXML encoding.
        self.benc = BinaryEncoding()

        # All of the crap!
        self.endian: str = "<"
        self.features: int = 0
        self.file_flags: bytes = b""
        self.text_obfuscated: bool = False
        self.legacy_lz: bool = False
        self.modern_lz: bool = False

        # If we encounter parts of the file that we don't know how to read
        # or save, we drop into read-only mode and throw if somebody tries
        # to update the file.
        self.read_only: bool = False

        # List of all textures in this file. This is unordered, textures should
        # be looked up by name.
        self.textures: List[Texture] = []

        # Texture mapping, which allows other structures to refer to texture
        # by number instead of name.
        self.texturemap: PMAN = PMAN()

        # List of all regions found inside textures, mapped to their textures
        # using texturenos that can be looked up using the texturemap above.
        # This structure is ordered, and the regionno from the regionmap
        # below can be used to look into this structure.
        self.texture_to_region: List[TextureRegion] = []

        # Region mapping, which allows other structures to refer to regions
        # by number instead of name.
        self.regionmap: PMAN = PMAN()

        # Level data (swf-derivative) and their names found in this file. This is
        # unordered, swfdata should be looked up by name.
        self.swfdata: List[SWF] = []

        # Level data (swf-derivative) mapping, which allows other structures to
        # refer to swfdata by number instead of name.
        self.swfmap: PMAN = PMAN()

        # Font information (mapping for various coepoints to their region in
        # a particular font texture.
        self.fontdata: Optional[Node] = None

        # Shapes(?) with their raw data.
        self.shapes: List[Shape] = []

        # Shape(?) mapping, not understood or used.
        self.shapemap: PMAN = PMAN()

        # Unknown data structures that we have to roundtrip. They correlate to
        # the PMAN structures below.
        self.unknown1: List[Unknown1] = []
        self.unknown2: List[Unknown2] = []

        # Unknown PMAN structures that we have to roundtrip. They correlate to
        # the unknown data structures above.
        self.unk_pman1: PMAN = PMAN()
        self.unk_pman2: PMAN = PMAN()

        # Parse out the file structure.
        self.__parse(verbose)

    def add_coverage(self, offset: int, length: int, unique: bool = True) -> None:
        for i in range(offset, offset + length):
            if self.coverage[i] and unique:
                raise Exception(f"Already covered {hex(offset)}!")
            self.coverage[i] = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            'endian': self.endian,
            'features': self.features,
            'file_flags': "".join(_hex(x) for x in self.file_flags),
            'obfuscated': self.text_obfuscated,
            'legacy_lz': self.legacy_lz,
            'modern_lz': self.modern_lz,
            'textures': [tex.as_dict() for tex in self.textures],
            'texturemap': self.texturemap.as_dict(),
            'textureregion': [reg.as_dict() for reg in self.texture_to_region],
            'regionmap': self.regionmap.as_dict(),
            'swfdata': [data.as_dict() for data in self.swfdata],
            'swfmap': self.swfmap.as_dict(),
            'fontdata': str(self.fontdata) if self.fontdata is not None else None,
            'shapes': [shape.as_dict() for shape in self.shapes],
            'shapemap': self.shapemap.as_dict(),
            'unknown1': [unk.as_dict() for unk in self.unknown1],
            'unknown1map': self.unk_pman1.as_dict(),
            'unknown2': [unk.as_dict() for unk in self.unknown2],
            'unknown2map': self.unk_pman2.as_dict(),
        }

    def print_coverage(self) -> None:
        # First offset that is not coverd in a run.
        start = None

        for offset, covered in enumerate(self.coverage):
            if covered:
                if start is not None:
                    print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)
                    start = None
            else:
                if start is None:
                    start = offset
        if start is not None:
            # Print final range
            offset = len(self.coverage)
            print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)

    @staticmethod
    def cap32(val: int) -> int:
        return val & 0xFFFFFFFF

    @staticmethod
    def poly(val: int) -> int:
        if (val >> 31) & 1 != 0:
            return 0x4C11DB7
        else:
            return 0

    @staticmethod
    def crc32(bytestream: bytes) -> int:
        # Janky 6-bit CRC for ascii names in PMAN structures.
        result = 0
        for byte in bytestream:
            for i in range(6):
                result = AFPFile.poly(result) ^ AFPFile.cap32((result << 1) | ((byte >> i) & 1))
        return result

    @staticmethod
    def descramble_text(text: bytes, obfuscated: bool) -> str:
        if len(text):
            if obfuscated and (text[0] - 0x20) > 0x7F:
                # Gotta do a weird demangling where we swap the
                # top bit.
                return bytes(((x + 0x80) & 0xFF) for x in text).decode('ascii')
            else:
                return text.decode('ascii')
        else:
            return ""

    @staticmethod
    def scramble_text(text: str, obfuscated: bool) -> bytes:
        if obfuscated:
            return bytes(((x + 0x80) & 0xFF) for x in text.encode('ascii')) + b'\0'
        else:
            return text.encode('ascii') + b'\0'

    def get_until_null(self, offset: int) -> bytes:
        out = b""
        while self.data[offset] != 0:
            out += self.data[offset:(offset + 1)]
            offset += 1
        return out

    def descramble_pman(self, offset: int, verbose: bool) -> PMAN:
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        # Unclear what the first three unknowns are, but the fourth
        # looks like it could possibly be two int16s indicating unknown?
        magic, expect_zero, flags1, flags2, numentries, flags3, data_offset = struct.unpack(
            f"{self.endian}4sIIIIII",
            self.data[offset:(offset + 28)],
        )
        add_coverage(offset, 28)

        # I have never seen the first unknown be anything other than zero,
        # so lets lock that down.
        if expect_zero != 0:
            raise Exception("Got a non-zero value for expected zero location in PMAN!")

        if self.endian == "<" and magic != b"PMAN":
            raise Exception("Invalid magic value in PMAN structure!")
        if self.endian == ">" and magic != b"NAMP":
            raise Exception("Invalid magic value in PMAN structure!")

        names: List[Optional[str]] = [None] * numentries
        ordering: List[Optional[int]] = [None] * numentries
        if numentries > 0:
            # Jump to the offset, parse it out
            for i in range(numentries):
                file_offset = data_offset + (i * 12)
                name_crc, entry_no, nameoffset = struct.unpack(
                    f"{self.endian}III",
                    self.data[file_offset:(file_offset + 12)],
                )
                add_coverage(file_offset, 12)

                if nameoffset == 0:
                    raise Exception("Expected name offset in PMAN data!")

                bytedata = self.get_until_null(nameoffset)
                add_coverage(nameoffset, len(bytedata) + 1, unique=False)
                name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                names[entry_no] = name
                ordering[entry_no] = i
                vprint(f"    {entry_no}: {name}, offset: {hex(nameoffset)}")

                if name_crc != AFPFile.crc32(name.encode('ascii')):
                    raise Exception(f"Name CRC failed for {name}")

        for i, name in enumerate(names):
            if name is None:
                raise Exception(f"Didn't get mapping for entry {i + 1}")

        for i, o in enumerate(ordering):
            if o is None:
                raise Exception(f"Didn't get ordering for entry {i + 1}")

        return PMAN(
            entries=names,
            ordering=ordering,
            flags1=flags1,
            flags2=flags2,
            flags3=flags3,
        )

    def __parse(
        self,
        verbose: bool = False,
    ) -> None:
        # Suppress debug text unless asked
        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                print(*args, **kwargs, file=sys.stderr)

            add_coverage = self.add_coverage
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

            def add_coverage(*args: Any, **kwargs: Any) -> None:  # type: ignore
                pass

        # First, check the signature
        if self.data[0:4] == b"2PXT":
            self.endian = "<"
        elif self.data[0:4] == b"TXP2":
            self.endian = ">"
        else:
            raise Exception("Invalid graphic file format!")
        add_coverage(0, 4)

        # Not sure what words 2 and 3 are, they seem to be some sort of
        # version or date?
        self.file_flags = self.data[4:12]
        add_coverage(4, 8)

        # Now, grab the file length, verify that we have the right amount
        # of data.
        length = struct.unpack(f"{self.endian}I", self.data[12:16])[0]
        add_coverage(12, 4)
        if length != len(self.data):
            raise Exception(f"Invalid graphic file length, expecting {length} bytes!")

        # This is always the header length, or the offset of the data payload.
        header_length = struct.unpack(f"{self.endian}I", self.data[16:20])[0]
        add_coverage(16, 4)

        # Now, the meat of the file format. Bytes 20-24 are a bitfield for
        # what parts of the header exist in the file. We need to understand
        # each bit so we know how to skip past each section.
        feature_mask = struct.unpack(f"{self.endian}I", self.data[20:24])[0]
        add_coverage(20, 4)
        header_offset = 24

        # Lots of magic happens if this bit is set.
        self.text_obfuscated = bool(feature_mask & 0x20)
        self.legacy_lz = bool(feature_mask & 0x04)
        self.modern_lz = bool(feature_mask & 0x40000)
        self.features = feature_mask

        if feature_mask & 0x01:
            # List of textures that exist in the file, with pointers to their data.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000001 - textures; count: {length}, offset: {hex(offset)}")

            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, texture_length, texture_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset:(interesting_offset + 12)],
                    )
                    add_coverage(interesting_offset, 12)

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)

                    if name_offset != 0 and texture_offset != 0:
                        if self.legacy_lz:
                            raise Exception("We don't support legacy lz mode!")
                        elif self.modern_lz:
                            # Get size, round up to nearest power of 4
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset:(texture_offset + 8)],
                            )
                            add_coverage(texture_offset, 8)
                            if deflated_size != (texture_length - 8):
                                raise Exception("We got an incorrect length for lz texture!")
                            vprint(f"    {name}, length: {texture_length}, offset: {hex(texture_offset)}, deflated_size: {deflated_size}, inflated_size: {inflated_size}")
                            inflated_size = (inflated_size + 3) & (~3)

                            # Get the data offset.
                            lz_data_offset = texture_offset + 8
                            lz_data = self.data[lz_data_offset:(lz_data_offset + deflated_size)]
                            add_coverage(lz_data_offset, deflated_size)

                            # This takes forever, so skip it if we're pretending.
                            lz77 = Lz77()
                            raw_data = lz77.decompress(lz_data)
                        else:
                            inflated_size, deflated_size = struct.unpack(
                                ">II",
                                self.data[texture_offset:(texture_offset + 8)],
                            )

                            # I'm guessing how raw textures work because I haven't seen them.
                            # I assume they're like the above, so lets put in some asertions.
                            if deflated_size != (texture_length - 8):
                                raise Exception("We got an incorrect length for raw texture!")
                            vprint(f"    {name}, length: {texture_length}, offset: {hex(texture_offset)}, deflated_size: {deflated_size}, inflated_size: {inflated_size}")

                            # Just grab the raw data.
                            lz_data = None
                            raw_data = self.data[(texture_offset + 8):(texture_offset + 8 + deflated_size)]
                            add_coverage(texture_offset, deflated_size + 8)

                        (
                            magic,
                            header_flags1,
                            header_flags2,
                            raw_length,
                            width,
                            height,
                            fmtflags,
                            expected_zero1,
                            expected_zero2,
                        ) = struct.unpack(
                            f"{self.endian}4sIIIHHIII",
                            raw_data[0:32],
                        )
                        if raw_length != len(raw_data):
                            raise Exception("Invalid texture length!")
                        # I have only ever observed the following values across two different games.
                        # Don't want to keep the chunk around so let's assert our assumptions.
                        if (expected_zero1 | expected_zero2) != 0:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        if raw_data[32:44] != b'\0' * 12:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        # This is almost ALWAYS 3, but I've seen it be 1 as well, so I guess we have to
                        # round-trip it if we want to write files back out. I have no clue what it's for.
                        # I've seen it be 1 only on files used for fonts so far, but I am not sure there
                        # is any correlation there.
                        header_flags3 = struct.unpack(f"{self.endian}I", raw_data[44:48])[0]
                        if raw_data[48:64] != b'\0' * 16:
                            raise Exception("Found unexpected non-zero value in texture header!")
                        fmt = fmtflags & 0xFF

                        # Extract flags that the game cares about.
                        # flags1 = (fmtflags >> 24) & 0xFF
                        # flags2 = (fmtflags >> 16) & 0xFF

                        # unk1 = 3 if (flags1 & 0xF == 1) else 1
                        # unk2 = 3 if ((flags1 >> 4) & 0xF == 1) else 1
                        # unk3 = 1 if (flags2 & 0xF == 1) else 2
                        # unk4 = 1 if ((flags2 >> 4) & 0xF == 1) else 2

                        if self.endian == "<" and magic != b"TDXT":
                            raise Exception("Unexpected texture format!")
                        if self.endian == ">" and magic != b"TXDT":
                            raise Exception("Unexpected texture format!")

                        # Since the AFP file format can be found in both big and little endian, its
                        # possible that some of these loaders might need byteswapping on some platforms.
                        # This has been tested on files intended for X86 (little endian).

                        if fmt == 0x0B:
                            # 16-bit 565 color RGB format. Game references D3D9 texture format 23 (R5G6B5).
                            newdata = []
                            for i in range(width * height):
                                pixel = struct.unpack(
                                    f"{self.endian}H",
                                    raw_data[(64 + (i * 2)):(66 + (i * 2))],
                                )[0]

                                # Extract the raw values
                                red = ((pixel >> 0) & 0x1F) << 3
                                green = ((pixel >> 5) & 0x3F) << 2
                                blue = ((pixel >> 11) & 0x1F) << 3

                                # Scale the colors so they fill the entire 8 bit range.
                                red = red | (red >> 5)
                                green = green | (green >> 6)
                                blue = blue | (blue >> 5)

                                newdata.append(
                                    struct.pack("<BBB", blue, green, red)
                                )
                            img = Image.frombytes(
                                'RGB', (width, height), b''.join(newdata), 'raw', 'RGB',
                            )
                        elif fmt == 0x0E:
                            # RGB image, no alpha. Game references D3D9 texture format 22 (R8G8B8).
                            img = Image.frombytes(
                                'RGB', (width, height), raw_data[64:], 'raw', 'RGB',
                            )
                        elif fmt == 0x10:
                            # Seems to be some sort of RGB with color swapping. Game references D3D9 texture
                            # format 21 (A8R8B8G8) but does manual byteswapping.
                            # TODO: Not sure this is correct, need to find sample files.
                            img = Image.frombytes(
                                'RGB', (width, height), raw_data[64:], 'raw', 'BGR',
                            )
                        elif fmt == 0x13:
                            # Some 16-bit texture format. Game references D3D9 texture format 25 (A1R5G5B5).
                            newdata = []
                            for i in range(width * height):
                                pixel = struct.unpack(
                                    f"{self.endian}H",
                                    raw_data[(64 + (i * 2)):(66 + (i * 2))],
                                )[0]

                                # Extract the raw values
                                alpha = 255 if ((pixel >> 15) & 0x1) != 0 else 0
                                red = ((pixel >> 0) & 0x1F) << 3
                                green = ((pixel >> 5) & 0x1F) << 3
                                blue = ((pixel >> 10) & 0x1F) << 3

                                # Scale the colors so they fill the entire 8 bit range.
                                red = red | (red >> 5)
                                green = green | (green >> 5)
                                blue = blue | (blue >> 5)

                                newdata.append(
                                    struct.pack("<BBBB", blue, green, red, alpha)
                                )
                            img = Image.frombytes(
                                'RGBA', (width, height), b''.join(newdata), 'raw', 'RGBA',
                            )
                        elif fmt == 0x15:
                            # RGBA format. Game references D3D9 texture format 21 (A8R8G8B8).
                            # Looks like unlike 0x20 below, the game does some endianness swapping.
                            # TODO: Not sure this is correct, need to find sample files.
                            img = Image.frombytes(
                                'RGBA', (width, height), raw_data[64:], 'raw', 'ARGB',
                            )
                        elif fmt == 0x16:
                            # DXT1 format. Game references D3D9 DXT1 texture format.
                            # Konami seems to have screwed up with DDR PS3 where they
                            # swap every other byte in the format, even though its specified
                            # as little-endian by all DXT1 documentation.
                            dxt = DXTBuffer(width, height)
                            img = Image.frombuffer(
                                'RGBA',
                                (width, height),
                                dxt.DXT1Decompress(raw_data[64:], swap=self.endian != "<"),
                                'raw',
                                'RGBA',
                                0,
                                1,
                            )
                        elif fmt == 0x1A:
                            # DXT5 format. Game references D3D9 DXT5 texture format.
                            # Konami seems to have screwed up with DDR PS3 where they
                            # swap every other byte in the format, even though its specified
                            # as little-endian by all DXT5 documentation.
                            dxt = DXTBuffer(width, height)
                            img = Image.frombuffer(
                                'RGBA',
                                (width, height),
                                dxt.DXT5Decompress(raw_data[64:], swap=self.endian != "<"),
                                'raw',
                                'RGBA',
                                0,
                                1,
                            )
                        elif fmt == 0x1E:
                            # I have no idea what format this is. The game does some byte
                            # swapping but doesn't actually call any texture create calls.
                            # This might be leftover from another game.
                            pass
                        elif fmt == 0x1F:
                            # 16-bit 4-4-4-4 RGBA format. Game references D3D9 texture format 26 (A4R4G4B4).
                            newdata = []
                            for i in range(width * height):
                                pixel = struct.unpack(
                                    f"{self.endian}H",
                                    raw_data[(64 + (i * 2)):(66 + (i * 2))],
                                )[0]

                                # Extract the raw values
                                blue = ((pixel >> 0) & 0xF) << 4
                                green = ((pixel >> 4) & 0xF) << 4
                                red = ((pixel >> 8) & 0xF) << 4
                                alpha = ((pixel >> 12) & 0xF) << 4

                                # Scale the colors so they fill the entire 8 bit range.
                                red = red | (red >> 4)
                                green = green | (green >> 4)
                                blue = blue | (blue >> 4)
                                alpha = alpha | (alpha >> 4)

                                newdata.append(
                                    struct.pack("<BBBB", red, green, blue, alpha)
                                )
                            img = Image.frombytes(
                                'RGBA', (width, height), b''.join(newdata), 'raw', 'RGBA',
                            )
                        elif fmt == 0x20:
                            # RGBA format. Game references D3D9 surface format 21 (A8R8G8B8).
                            img = Image.frombytes(
                                'RGBA', (width, height), raw_data[64:], 'raw', 'BGRA',
                            )
                        else:
                            vprint(f"Unsupported format {hex(fmt)} for texture {name}")
                            img = None

                        self.textures.append(
                            Texture(
                                name,
                                width,
                                height,
                                fmt,
                                header_flags1,
                                header_flags2,
                                header_flags3,
                                fmtflags & 0xFFFFFF00,
                                raw_data[64:],
                                lz_data,
                                img,
                            )
                        )
        else:
            vprint("Bit 0x000001 - textures; NOT PRESENT")

        # Mapping between texture index and the name of the texture.
        if feature_mask & 0x02:
            # Mapping of texture name to texture index. This is used by regions to look up textures.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000002 - texturemapping; offset: {hex(offset)}")

            if offset != 0:
                self.texturemap = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x000002 - texturemapping; NOT PRESENT")

        if feature_mask & 0x04:
            vprint("Bit 0x000004 - legacy lz mode on")
        else:
            vprint("Bit 0x000004 - legacy lz mode off")

        # Mapping between region index and the texture it goes to as well as the
        # region of texture that this particular graphic makes up.
        if feature_mask & 0x08:
            # Mapping between individual graphics and their respective textures.
            # This is 10 bytes per entry. Seems to need both 0x2 (texture index)
            # and 0x10 (region index).
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000008 - regions; count: {length}, offset: {hex(offset)}")

            if offset != 0 and length > 0:
                for i in range(length):
                    descriptor_offset = offset + (10 * i)
                    texture_no, left, top, right, bottom = struct.unpack(
                        f"{self.endian}HHHHH",
                        self.data[descriptor_offset:(descriptor_offset + 10)],
                    )
                    add_coverage(descriptor_offset, 10)

                    if texture_no < 0 or texture_no >= len(self.texturemap.entries):
                        raise Exception(f"Out of bounds texture {texture_no}")

                    # Texture regions are multiplied by a power of 2. Not sure why, but the games I
                    # looked at hardcode a divide by 2 when loading regions.
                    region = TextureRegion(texture_no, left, top, right, bottom)
                    self.texture_to_region.append(region)

                    vprint(f"    {region}, offset: {hex(descriptor_offset)}")
        else:
            vprint("Bit 0x000008 - regions; NOT PRESENT")

        if feature_mask & 0x10:
            # Names of the graphics regions, so we can look into the texture_to_region
            # mapping above. Used by shapes to find the right region offset given a name.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000010 - regionmapping; offset: {hex(offset)}")

            if offset != 0:
                self.regionmap = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x000010 - regionmapping; NOT PRESENT")

        if feature_mask & 0x20:
            vprint("Bit 0x000020 - text obfuscation on")
        else:
            vprint("Bit 0x000020 - text obfuscation off")

        if feature_mask & 0x40:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000040 - unknown; count: {length}, offset: {hex(offset)}")

            if offset != 0 and length > 0:
                for i in range(length):
                    unk_offset = offset + (i * 16)
                    name_offset = struct.unpack(f"{self.endian}I", self.data[unk_offset:(unk_offset + 4)])[0]
                    add_coverage(unk_offset, 4)

                    # The game does some very bizarre bit-shifting. Its clear tha the first value
                    # points at a name structure, but its not in the correct endianness. This replicates
                    # the weird logic seen in game disassembly.
                    name_offset = (((name_offset >> 7) & 0x1FF) << 16) + ((name_offset >> 16) & 0xFFFF)
                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                        vprint(f"    {name}")

                    self.unknown1.append(
                        Unknown1(
                            name=name,
                            data=self.data[(unk_offset + 4):(unk_offset + 16)],
                        )
                    )
                    add_coverage(unk_offset + 4, 12)
        else:
            vprint("Bit 0x000040 - unknown; NOT PRESENT")

        if feature_mask & 0x80:
            # One unknown byte, treated as an offset. This is clearly the mapping for the parsed
            # structures from 0x40, but I don't know what those are.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000080 - unknownmapping; offset: {hex(offset)}")

            # TODO: I have no idea what this is for.
            if offset != 0:
                self.unk_pman1 = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x000080 - unknownmapping; NOT PRESENT")

        if feature_mask & 0x100:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000100 - unknown; count: {length}, offset: {hex(offset)}")

            if offset != 0 and length > 0:
                for i in range(length):
                    unk_offset = offset + (i * 4)
                    self.unknown2.append(
                        Unknown2(self.data[unk_offset:(unk_offset + 4)])
                    )
                    add_coverage(unk_offset, 4)
        else:
            vprint("Bit 0x000100 - unknown; NOT PRESENT")

        if feature_mask & 0x200:
            # One unknown byte, treated as an offset. Almost positive its a string mapping
            # for the above 0x100 structure. That's how this file format appears to work.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000200 - unknownmapping; offset: {hex(offset)}")

            # TODO: I have no idea what this is for.
            if offset != 0:
                self.unk_pman2 = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x000200 - unknownmapping; NOT PRESENT")

        if feature_mask & 0x400:
            # One unknown byte, treated as an offset. I have no idea what this is used for,
            # it seems to be empty data in files that I've looked at, it doesn't go to any
            # structure or mapping.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x000400 - unknown; offset: {hex(offset)}")
        else:
            vprint("Bit 0x000400 - unknown; NOT PRESENT")

        if feature_mask & 0x800:
            # SWF raw data that is loaded and passed to AFP core. It is equivalent to the
            # afp files in an IFS container.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x000800 - swfdata; count: {length}, offset: {hex(offset)}")

            for x in range(length):
                interesting_offset = offset + (x * 12)
                if interesting_offset != 0:
                    name_offset, swf_length, swf_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[interesting_offset:(interesting_offset + 12)],
                    )
                    add_coverage(interesting_offset, 12)
                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                        vprint(f"    {name}, length: {swf_length}, offset: {hex(swf_offset)}")

                    if swf_offset != 0:
                        self.swfdata.append(
                            SWF(
                                name,
                                self.data[swf_offset:(swf_offset + swf_length)]
                            )
                        )
                        add_coverage(swf_offset, swf_length)
        else:
            vprint("Bit 0x000800 - swfdata; NOT PRESENT")

        if feature_mask & 0x1000:
            # A mapping structure that allows looking up SWF data by name.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x001000 - swfmapping; offset: {hex(offset)}")

            if offset != 0:
                self.swfmap = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x001000 - swfmapping; NOT PRESENT")

        if feature_mask & 0x2000:
            # These are shapes as used with the SWF data above. They contain mappings between a
            # loaded texture shape and the region that contains data. They are equivalent to the
            # geo files found in an IFS container.
            length, offset = struct.unpack(f"{self.endian}II", self.data[header_offset:(header_offset + 8)])
            add_coverage(header_offset, 8)
            header_offset += 8

            vprint(f"Bit 0x002000 - shapes; count: {length}, offset: {hex(offset)}")

            for x in range(length):
                shape_base_offset = offset + (x * 12)
                if shape_base_offset != 0:
                    name_offset, shape_length, shape_offset = struct.unpack(
                        f"{self.endian}III",
                        self.data[shape_base_offset:(shape_base_offset + 12)],
                    )
                    add_coverage(shape_base_offset, 12)

                    if name_offset != 0:
                        # Let's decode this until the first null.
                        bytedata = self.get_until_null(name_offset)
                        add_coverage(name_offset, len(bytedata) + 1, unique=False)
                        name = AFPFile.descramble_text(bytedata, self.text_obfuscated)
                    else:
                        name = "<unnamed>"

                    if shape_offset != 0:
                        shape = Shape(
                            name,
                            self.data[shape_offset:(shape_offset + shape_length)],
                        )
                        shape.parse(text_obfuscated=self.text_obfuscated)
                        self.shapes.append(shape)
                        add_coverage(shape_offset, shape_length)

                        vprint(f"    {name}, length: {shape_length}, offset: {hex(shape_offset)}")
                        for line in str(shape).split(os.linesep):
                            vprint(f"        {line}")

        else:
            vprint("Bit 0x002000 - shapes; NOT PRESENT")

        if feature_mask & 0x4000:
            # Mapping so that shapes can be looked up by name to get their offset.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x004000 - shapesmapping; offset: {hex(offset)}")

            if offset != 0:
                self.shapemap = self.descramble_pman(offset, verbose)
        else:
            vprint("Bit 0x004000 - shapesmapping; NOT PRESENT")

        if feature_mask & 0x8000:
            # One unknown byte, treated as an offset. I have no idea what this is because
            # the games I've looked at don't include this bit.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x008000 - unknown; offset: {hex(offset)}")

            # Since I've never seen this, I'm going to assume that it showing up is
            # bad and make things read only.
            self.read_only = True
        else:
            vprint("Bit 0x008000 - unknown; NOT PRESENT")

        if feature_mask & 0x10000:
            # Included font package, BINXRPC encoded. This is basically a texture sheet with an XML
            # pointing at the region in the texture sheet for every renderable character.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            # I am not sure what the unknown byte is for. It always appears as
            # all zeros in all files I've looked at.
            expect_zero, length, binxrpc_offset = struct.unpack(f"{self.endian}III", self.data[offset:(offset + 12)])
            add_coverage(offset, 12)

            vprint(f"Bit 0x010000 - fontinfo; offset: {hex(offset)}, binxrpc offset: {hex(binxrpc_offset)}")

            if expect_zero != 0:
                # If we find non-zero versions of this, then that means updating the file is
                # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                raise Exception("Expected a zero in font package header!")

            if binxrpc_offset != 0:
                self.fontdata = self.benc.decode(self.data[binxrpc_offset:(binxrpc_offset + length)])
                add_coverage(binxrpc_offset, length)
            else:
                self.fontdata = None
        else:
            vprint("Bit 0x010000 - fontinfo; NOT PRESENT")

        if feature_mask & 0x20000:
            # This is the byteswapping headers that allow us to byteswap the SWF data before passing it
            # to AFP core. It is equivalent to the bsi files in an IFS container.
            offset = struct.unpack(f"{self.endian}I", self.data[header_offset:(header_offset + 4)])[0]
            add_coverage(header_offset, 4)
            header_offset += 4

            vprint(f"Bit 0x020000 - swfheaders; offset: {hex(offset)}")

            if offset > 0 and len(self.swfdata) > 0:
                for i in range(len(self.swfdata)):
                    structure_offset = offset + (i * 12)

                    # First word is always zero, as observed. I am not ENTIRELY sure that
                    # the second field is length, but it lines up with everything else
                    # I've observed and seems to make sense.
                    expect_zero, afp_header_length, afp_header = struct.unpack(
                        f"{self.endian}III",
                        self.data[structure_offset:(structure_offset + 12)]
                    )
                    vprint(f"    length: {afp_header_length}, offset: {hex(afp_header)}")
                    add_coverage(structure_offset, 12)

                    if expect_zero != 0:
                        # If we find non-zero versions of this, then that means updating the file is
                        # potentially unsafe as we could rewrite it incorrectly. So, let's assert!
                        raise Exception("Expected a zero in SWF header!")

                    self.swfdata[i].descramble_info = self.data[afp_header:(afp_header + afp_header_length)]
                    add_coverage(afp_header, afp_header_length)
        else:
            vprint("Bit 0x020000 - swfheaders; NOT PRESENT")

        if feature_mask & 0x40000:
            vprint("Bit 0x040000 - modern lz mode on")
        else:
            vprint("Bit 0x040000 - modern lz mode off")

        if feature_mask & 0xFFF80000:
            # We don't know these bits at all!
            raise Exception("Invalid bits set in feature mask!")

        if header_offset != header_length:
            raise Exception("Failed to parse bitfield of header correctly!")
        if verbose:
            self.print_coverage()

        # Now, parse out the SWF data in each of the SWF structures we found.
        for swf in self.swfdata:
            swf.parse(verbose)

    @staticmethod
    def align(val: int) -> int:
        return (val + 3) & 0xFFFFFFFFC

    @staticmethod
    def pad(data: bytes, length: int) -> bytes:
        if len(data) == length:
            return data
        elif len(data) > length:
            raise Exception("Logic error, padding request in data already written!")
        return data + (b"\0" * (length - len(data)))

    def write_strings(self, data: bytes, strings: Dict[str, int]) -> bytes:
        tuples: List[Tuple[str, int]] = [(name, strings[name]) for name in strings]
        tuples = sorted(tuples, key=lambda tup: tup[1])

        for (string, offset) in tuples:
            data = AFPFile.pad(data, offset)
            data += AFPFile.scramble_text(string, self.text_obfuscated)

        return data

    def write_pman(self, data: bytes, offset: int, pman: PMAN, string_offsets: Dict[str, int]) -> bytes:
        # First, lay down the PMAN header
        if self.endian == "<":
            magic = b"PMAN"
        elif self.endian == ">":
            magic = b"NAMP"
        else:
            raise Exception("Logic error, unexpected endianness!")

        # Calculate where various data goes
        data = AFPFile.pad(data, offset)
        payload_offset = offset + 28
        string_offset = payload_offset + (len(pman.entries) * 12)
        pending_strings: Dict[str, int] = {}

        data += struct.pack(
            f"{self.endian}4sIIIIII",
            magic,
            0,
            pman.flags1,
            pman.flags2,
            len(pman.entries),
            pman.flags3,
            payload_offset,
        )

        # Now, lay down the individual entries
        datas: List[bytes] = [b""] * len(pman.entries)
        for entry_no, name in enumerate(pman.entries):
            name_crc = AFPFile.crc32(name.encode('ascii'))

            if name not in string_offsets:
                # We haven't written this string out yet, so put it on our pending list.
                pending_strings[name] = string_offset
                string_offsets[name] = string_offset

                # Room for the null byte!
                string_offset += len(name) + 1

            # Write out the chunk itself.
            datas[pman.ordering[entry_no]] = struct.pack(
                f"{self.endian}III",
                name_crc,
                entry_no,
                string_offsets[name],
            )

        # Write it out in the correct order. Some files are hardcoded in various
        # games so we MUST preserve the order of PMAN entries.
        data += b"".join(datas)

        # Now, put down the strings that were new in this pman structure.
        return self.write_strings(data, pending_strings)

    def unparse(self) -> bytes:
        if self.read_only:
            raise Exception("This file is read-only because we can't parse some of it!")

        # Mapping from various strings found in the file to their offsets.
        string_offsets: Dict[str, int] = {}
        pending_strings: Dict[str, int] = {}

        # The true file header, containing magic, some file flags, file length and
        # header length.
        header: bytes = b''

        # The bitfield structure that dictates what's found in the file and where.
        bitfields: bytes = b''

        # The data itself.
        body: bytes = b''

        # First, plop down the file magic as well as the unknown file flags we
        # roundtripped.
        if self.endian == "<":
            header += b"2PXT"
        elif self.endian == ">":
            header += b"TXP2"
        else:
            raise Exception("Invalid graphic file format!")

        # Not sure what words 2 and 3 are, they seem to be some sort of
        # version or date?
        header += self.data[4:12]

        # We can't plop the length down yet, since we don't know it. So, let's first
        # figure out what our bitfield length is.
        header_length = 0
        if self.features & 0x1:
            header_length += 8
        if self.features & 0x2:
            header_length += 4
        # Bit 0x4 is for lz options.
        if self.features & 0x8:
            header_length += 8
        if self.features & 0x10:
            header_length += 4
        # Bit 0x20 is for text obfuscation options.
        if self.features & 0x40:
            header_length += 8
        if self.features & 0x80:
            header_length += 4
        if self.features & 0x100:
            header_length += 8
        if self.features & 0x200:
            header_length += 4
        if self.features & 0x400:
            header_length += 4
        if self.features & 0x800:
            header_length += 8
        if self.features & 0x1000:
            header_length += 4
        if self.features & 0x2000:
            header_length += 8
        if self.features & 0x4000:
            header_length += 4
        if self.features & 0x8000:
            header_length += 4
        if self.features & 0x10000:
            header_length += 4
        if self.features & 0x20000:
            header_length += 4
        # Bit 0x40000 is for lz options.

        # We keep this indirection because we want to do our best to preserve
        # the file order we observe in actual files. So, that means writing data
        # out of order of when it shows in the header, and as such we must remember
        # what chunks go where. We key by feature bitmask so its safe to have empties.
        bitchunks = [b""] * 32

        # Pad out the body for easier calculations below
        body = AFPFile.pad(body, 24 + header_length)

        # Start laying down various file pieces.
        texture_to_update_offset: Dict[str, Tuple[int, bytes]] = {}
        if self.features & 0x01:
            # List of textures that exist in the file, with pointers to their data.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[0] = struct.pack(f"{self.endian}II", len(self.textures), offset)

            # Now, calculate how long each texture is and formulate the data itself.
            name_to_length: Dict[str, int] = {}

            # Now, possibly compress and lay down textures.
            for texture in self.textures:
                # Construct the TXDT texture format from our parsed results.
                if self.endian == "<":
                    magic = b"TDXT"
                elif self.endian == ">":
                    magic != b"TXDT"
                else:
                    raise Exception("Unexpected texture format!")

                fmtflags = (texture.fmtflags & 0xFFFFFF00) | (texture.fmt & 0xFF)

                raw_texture = struct.pack(
                    f"{self.endian}4sIIIHHIII",
                    magic,
                    texture.header_flags1,
                    texture.header_flags2,
                    64 + len(texture.raw),
                    texture.width,
                    texture.height,
                    fmtflags,
                    0,
                    0,
                ) + (b'\0' * 12) + struct.pack(
                    f"{self.endian}I", texture.header_flags3,
                ) + (b'\0' * 16) + texture.raw

                if self.legacy_lz:
                    raise Exception("We don't support legacy lz mode!")
                elif self.modern_lz:
                    if texture.compressed:
                        # We didn't change this texture, use the original compression.
                        compressed_texture = texture.compressed
                    else:
                        # We need to compress the raw texture.
                        lz77 = Lz77()
                        compressed_texture = lz77.compress(raw_texture)

                    # Construct the mini-header and the texture itself.
                    name_to_length[texture.name] = len(compressed_texture) + 8
                    texture_to_update_offset[texture.name] = (
                        0xDEADBEEF,
                        struct.pack(
                            ">II",
                            len(raw_texture),
                            len(compressed_texture),
                        ) + compressed_texture,
                    )
                else:
                    # We just need to place the raw texture down.
                    name_to_length[texture.name] = len(raw_texture) + 8
                    texture_to_update_offset[texture.name] = (
                        0xDEADBEEF,
                        struct.pack(
                            ">II",
                            len(raw_texture),
                            len(raw_texture),
                        ) + raw_texture,
                    )

            # Now, make sure the texture block is padded to 4 bytes, so we can figure out
            # where strings go.
            string_offset = AFPFile.align(len(body) + (len(self.textures) * 12))

            # Now, write out texture pointers and strings.
            for texture in self.textures:
                if texture.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[texture.name] = string_offset
                    string_offsets[texture.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(texture.name) + 1

                # Write out the chunk itself, remember where we need to fix up later.
                texture_to_update_offset[texture.name] = (
                    len(body) + 8,
                    texture_to_update_offset[texture.name][1],
                )
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[texture.name],
                    name_to_length[texture.name],  # Structure length
                    0xDEADBEEF,  # Structure offset (we will fix this later)
                )

            # Now, put down the texture chunk itself and then strings that were new in this chunk.
            body = self.write_strings(body, pending_strings)
            pending_strings = {}

        if self.features & 0x08:
            # Mapping between individual graphics and their respective textures.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[3] = struct.pack(f"{self.endian}II", len(self.texture_to_region), offset)

            for bounds in self.texture_to_region:
                body += struct.pack(
                    f"{self.endian}HHHHH",
                    bounds.textureno,
                    bounds.left,
                    bounds.top,
                    bounds.right,
                    bounds.bottom,
                )

        if self.features & 0x40:
            # Unknown file chunk.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[6] = struct.pack(f"{self.endian}II", len(self.unknown1), offset)

            # Now, calculate where we can put strings.
            string_offset = AFPFile.align(len(body) + (len(self.unknown1) * 16))

            # Now, write out chunks and strings.
            for entry1 in self.unknown1:
                if entry1.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[entry1.name] = string_offset
                    string_offsets[entry1.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(entry1.name) + 1

                # Write out the chunk itself.
                body += struct.pack(f"{self.endian}I", string_offsets[entry1.name]) + entry1.data

            # Now, put down the strings that were new in this chunk.
            body = self.write_strings(body, pending_strings)
            pending_strings = {}

        if self.features & 0x100:
            # Two unknown bytes, first is a length or a count. Secound is
            # an optional offset to grab another set of bytes from.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # First, lay down pointers and length, regardless of number of entries.
            bitchunks[8] = struct.pack(f"{self.endian}II", len(self.unknown2), offset)

            # Now, write out chunks and strings.
            for entry2 in self.unknown2:
                # Write out the chunk itself.
                body += entry2.data

        if self.features & 0x800:
            # This is the names and locations of the SWF data as far as I can tell.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            bitchunks[11] = struct.pack(f"{self.endian}II", len(self.swfdata), offset)

            # Now, calculate where we can put SWF data and their names.
            swfdata_offset = AFPFile.align(len(body) + (len(self.swfdata) * 12))
            string_offset = AFPFile.align(swfdata_offset + sum(AFPFile.align(len(a.data)) for a in self.swfdata))
            swfdata = b""

            # Now, lay them out.
            for data in self.swfdata:
                if data.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[data.name] = string_offset
                    string_offsets[data.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(data.name) + 1

                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[data.name],
                    len(data.data),
                    swfdata_offset + len(swfdata),
                )
                swfdata += AFPFile.pad(data.data, AFPFile.align(len(data.data)))

            # Now, lay out the data itself and finally string names.
            body = self.write_strings(body + swfdata, pending_strings)
            pending_strings = {}

        if self.features & 0x2000:
            # This is the names and data for shapes as far as I can tell.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            bitchunks[13] = struct.pack(f"{self.endian}II", len(self.shapes), offset)

            # Now, calculate where we can put shapes and their names.
            shape_offset = AFPFile.align(len(body) + (len(self.shapes) * 12))
            string_offset = AFPFile.align(shape_offset + sum(AFPFile.align(len(s.data)) for s in self.shapes))
            shapedata = b""

            # Now, lay them out.
            for shape in self.shapes:
                if shape.name not in string_offsets:
                    # We haven't written this string out yet, so put it on our pending list.
                    pending_strings[shape.name] = string_offset
                    string_offsets[shape.name] = string_offset

                    # Room for the null byte!
                    string_offset += len(shape.name) + 1

                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    string_offsets[shape.name],
                    len(shape.data),
                    shape_offset + len(shapedata),
                )
                shapedata += AFPFile.pad(shape.data, AFPFile.align(len(shape.data)))

            # Now, lay out the data itself and finally string names.
            body = self.write_strings(body + shapedata, pending_strings)
            pending_strings = {}

        if self.features & 0x02:
            # Mapping between texture index and the name of the texture.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[1] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.texturemap, string_offsets)

        if self.features & 0x10:
            # Names of the graphics regions, so we can look into the texture_to_region
            # mapping above.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[4] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.regionmap, string_offsets)

        if self.features & 0x80:
            # One unknown byte, treated as an offset. This is clearly the mapping for the parsed
            # structures from 0x40, but I don't know what those are.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[7] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.unk_pman1, string_offsets)

        if self.features & 0x200:
            # I am pretty sure this is a mapping for the structures parsed at 0x100.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[9] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.unk_pman2, string_offsets)

        if self.features & 0x1000:
            # Mapping of SWF data to their ID.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[12] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.swfmap, string_offsets)

        if self.features & 0x4000:
            # Mapping of shapes to their ID.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Lay down PMAN pointer and PMAN structure itself.
            bitchunks[14] = struct.pack(f"{self.endian}I", offset)
            body = self.write_pman(body, offset, self.shapemap, string_offsets)

        if self.features & 0x10000:
            # Font information.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            bitchunks[16] = struct.pack(f"{self.endian}I", offset)

            # Now, encode the font information.
            fontbytes = self.benc.encode(self.fontdata)
            body += struct.pack(
                f"{self.endian}III",
                0,
                len(fontbytes),
                offset + 12,
            )
            body += fontbytes

        if self.features & 0x400:
            # I haven't seen any files with any meaningful information for this, but
            # it gets included anyway since games seem to parse it.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            # Point to current data location (seems to be what original files do too).
            bitchunks[10] = struct.pack(f"{self.endian}I", offset)

        if self.features & 0x8000:
            # Unknown, never seen bit. We shouldn't be here, we set ourselves
            # to read-only.
            raise Exception("This should not be possible!")

        if self.features & 0x20000:
            # SWF header information.
            offset = AFPFile.align(len(body))
            body = AFPFile.pad(body, offset)

            bitchunks[17] = struct.pack(f"{self.endian}I", offset)

            # Now, calculate where we can put SWF headers.
            swfdata_offset = AFPFile.align(len(body) + (len(self.swfdata) * 12))
            swfheader = b""

            # Now, lay them out.
            for data in self.swfdata:
                # Write out the chunk itself.
                body += struct.pack(
                    f"{self.endian}III",
                    0,
                    len(data.descramble_info),
                    swfdata_offset + len(swfheader),
                )
                swfheader += AFPFile.pad(data.descramble_info, AFPFile.align(len(data.descramble_info)))

            # Now, lay out the header itself
            body += swfheader

        if self.features & 0x01:
            # Now, go back and add texture data to the end of the file, fixing up the
            # pointer to said data we wrote down earlier.
            for texture in self.textures:
                # Grab the offset we need to fix, our current offset and place
                # the texture data itself down.
                fix_offset, texture_data = texture_to_update_offset[texture.name]
                offset = AFPFile.align(len(body))
                body = AFPFile.pad(body, offset) + texture_data

                # Now, update the patch location to make sure we point at the texture data.
                body = body[:fix_offset] + struct.pack(f"{self.endian}I", offset) + body[(fix_offset + 4):]

        # Bit 0x40000 is for lz options.

        # Now, no matter what happened above, make sure file is aligned to 4 bytes.
        offset = AFPFile.align(len(body))
        body = AFPFile.pad(body, offset)

        # Record the bitfield options into the bitfield structure, and we can
        # get started writing the file out.
        bitfields = struct.pack(f"{self.endian}I", self.features) + b"".join(bitchunks)

        # Finally, now that we know the full file length, we can finish
        # writing the header.
        header += struct.pack(f"{self.endian}II", len(body), header_length + 24)
        if len(header) != 20:
            raise Exception("Logic error, incorrect header length!")

        # Skip over padding to the body that we inserted specifically to track offsets
        # against the headers.
        return header + bitfields + body[(header_length + 24):]

    def update_texture(self, name: str, png_data: bytes) -> None:
        for texture in self.textures:
            if texture.name == name:
                # First, let's get the dimensions of this new picture and
                # ensure that it is identical to the existing one.
                img = Image.open(io.BytesIO(png_data))
                if img.width != texture.width or img.height != texture.height:
                    raise Exception("Cannot update texture with different size!")

                # Now, get the raw image data.
                img = img.convert('RGBA')
                texture.img = img

                # Now, refresh the raw texture data for when we write it out.
                self._refresh_texture(texture)

                return
        else:
            raise Exception(f"There is no texture named {name}!")

    def update_sprite(self, texture: str, sprite: str, png_data: bytes) -> None:
        # First, identify the bounds where the texture lives.
        for no, name in enumerate(self.texturemap.entries):
            if name == texture:
                textureno = no
                break
        else:
            raise Exception(f"There is no texture named {texture}!")

        for no, name in enumerate(self.regionmap.entries):
            if name == sprite:
                region = self.texture_to_region[no]
                if region.textureno == textureno:
                    # We found the region associated with the sprite we want to update.
                    break
        else:
            raise Exception(f"There is no sprite named {sprite} on texture {texture}!")

        # Now, figure out if the PNG data we got is valid.
        sprite_img = Image.open(io.BytesIO(png_data))
        if sprite_img.width != ((region.right // 2) - (region.left // 2)) or sprite_img.height != ((region.bottom // 2) - (region.top // 2)):
            raise Exception("Cannot update sprite with different size!")

        # Now, copy the data over and update the raw texture.
        for tex in self.textures:
            if tex.name == texture:
                tex.img.paste(sprite_img, (region.left // 2, region.top // 2))

                # Now, refresh the texture so when we save the file its updated.
                self._refresh_texture(tex)

    def _refresh_texture(self, texture: Texture) -> None:
        if texture.fmt == 0x0B:
            # 16-bit 565 color RGB format.
            texture.raw = b"".join(
                struct.pack(
                    f"{self.endian}H",
                    (
                        (((pixel[0] >> 3) & 0x1F) << 11) |
                        (((pixel[1] >> 2) & 0x3F) << 5) |
                        ((pixel[2] >> 3) & 0x1F)
                    )
                ) for pixel in texture.img.getdata()
            )
        elif texture.fmt == 0x13:
            # 16-bit A1R5G55 texture format.
            texture.raw = b"".join(
                struct.pack(
                    f"{self.endian}H",
                    (
                        (0x8000 if pixel[3] >= 128 else 0x0000) |
                        (((pixel[0] >> 3) & 0x1F) << 10) |
                        (((pixel[1] >> 3) & 0x1F) << 5) |
                        ((pixel[2] >> 3) & 0x1F)
                    )
                ) for pixel in texture.img.getdata()
            )
        elif texture.fmt == 0x1F:
            # 16-bit 4-4-4-4 RGBA format.
            texture.raw = b"".join(
                struct.pack(
                    f"{self.endian}H",
                    (
                        ((pixel[2] >> 4) & 0xF) |
                        (((pixel[1] >> 4) & 0xF) << 4) |
                        (((pixel[0] >> 4) & 0xF) << 8) |
                        (((pixel[3] >> 4) & 0xF) << 12)
                    )
                ) for pixel in texture.img.getdata()
            )
        elif texture.fmt == 0x20:
            # 32-bit RGBA format
            texture.raw = b"".join(
                struct.pack(
                    f"{self.endian}BBBB",
                    pixel[2],
                    pixel[1],
                    pixel[0],
                    pixel[3],
                ) for pixel in texture.img.getdata()
            )
        else:
            raise Exception(f"Unsupported format {hex(texture.fmt)} for texture {texture.name}")

        # Make sure we don't use the old compressed data.
        texture.compressed = None
