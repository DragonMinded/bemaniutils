import os
from typing import TYPE_CHECKING, Any, Dict, List, Set, Tuple, Optional

if TYPE_CHECKING:
    # This is a circular dependency otherwise.
    from ..decompile import ByteCode


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
    AP2_PLACE_CAMERA = 0x88
    AP2_SCALING_GRID = 0x89

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
            cls.AP2_PLACE_CAMERA: 'AP2_PLACE_CAMERA',
            cls.AP2_SCALING_GRID: 'AP2_SCALING_GRID',
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

    # Init an array from the stack. Pops the array's number of items, and then an item each
    # to add to the array. Then it adds the array to the stack.
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

    # Swaps the position of the two two objects on the stack. If there isn't enough to swap, does
    # nothing.
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

    # Takes at least 3 objects on the stack, the third being the number of parameters, the second being
    # the object to add a method to and the first being the member name.
    NEW_METHOD = 51

    # Takes two objects, pops them off the stack and adds a boolean object to the stack set to true
    # if one is an instance of the other or false otherwise.
    INSTANCEOF = 52

    # Enumerates some sort of object into a variable on the top of the stack.
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

    # Pops two objects off the stack and does some sort of OOP with them, the first being the superclass
    # and the second being the subclass.
    EXTENDS = 62

    # Pop a value from the stack and store it in a register specified by the opcode param. Also push
    # it back onto the stack.
    STORE_REGISTER = 63

    # Define a function based on parameters on the stack. This reads the next 9 bytes of the bytecode
    # as parameters, and uses that to read the next N bytes of bytecode as the function definition.
    DEFINE_FUNCTION2 = 64

    # Grabs a 16 bit offset pointer as the opcode param, then skips bytecode processing forward
    # that many bytes, passing the skipped bytes as pointer data to a function that adds it to the
    # stack as a pointer type, and then adds a copy of the top of the stack before the pointer as a
    # second new stack entry. Strangely enough, if the object on the top of the stack doesn't meet
    # some criteria, the skipped bytes are processed as bytecode. I am not sure what the hell is going
    # on here.
    WITH = 66

    # Push an object onto the stack. Creates objects based on the bytecode parameters and pushes
    # them onto the stack.
    PUSH = 67

    # Unconditional jump based on bytecode value.
    JUMP = 68

    # Gets a single 8-bit integer as an opcode param, take the top two bits of that param as the
    # action to take. Looks like it is similar to SWF GET_URL2 action. Supported actions are 0,
    # 2 and 3. It pops two objects from the stack to perform against.
    GET_URL2 = 69

    # Pops a value from the stack, jumps to offset from opcode params if value is truthy.
    IF = 70

    # Go to frame specified by top of stack, popping that value from the stack. Also specifies
    # flags for whether to play or stop when going to that frame, and additional frames to advance
    # in opcode params.
    GOTO_FRAME2 = 71

    # Pops the top of the stack, uses that to get a target, pushes a pointer to that target on
    # the stack.
    GET_TARGET = 72

    # Given a subtype of check and a positive offset to jump to on true, perform a conditional check.
    # Pops two values from the stack for all equality checks except for undefined checks, which pop
    # one value.
    IF2 = 73

    # Similar to STORE_REGISTER but does not preserve the value on the stack afterwards.
    STORE_REGISTER2 = 74

    # Take one opcode parameter for the number of registers to init, and then one opcode parameter
    # per the number of registers param as the register number to init, initializing that register
    # as an "Undefined" object.
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
            cls.INSTANCEOF,
            cls.TARGET_PATH,
            cls.ENUMERATE2,
            cls.THROW,
            cls.CAST_OP,
            cls.IMPLEMENTS_OP,
            cls.STACK_SWAP,
            cls.GET_TIME,
            cls.RETURN,
            cls.POP,
            cls.PUSH_DUPLICATE,
            cls.DELETE,
            cls.DELETE2,
            cls.NEW_OBJECT,
            cls.EXTENDS,
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
            cls.NEW_METHOD,
            cls.CALL_METHOD,
            cls.CALL_FUNCTION,
            cls.TO_NUMBER,
            cls.TO_STRING,
            cls.GET_TARGET,
        }

    def __init__(self, offset: int, opcode: int) -> None:
        self.offset = offset
        self.opcode = opcode

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            'offset': self.offset,
            'action': AP2Action.action_to_name(self.opcode),
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}"


class DefineFunction2Action(AP2Action):
    def __init__(self, offset: int, name: Optional[str], flags: int, body: "ByteCode") -> None:
        super().__init__(offset, AP2Action.DEFINE_FUNCTION2)
        self.name = name
        self.flags = flags
        self.body = body

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'name': self.name,
            'flags': self.flags,
            'body': self.body.as_dict(*args, **kwargs),
        }

    def __repr__(self) -> str:
        bytecode = [f"  {line}" for line in str(self.body).split(os.linesep)]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join([
            f"{self.offset}: {action_name}, Name: {self.name or '<anonymous function>'}, Flags: {hex(self.flags)}",
            *bytecode,
            f"END_{action_name}",
        ])


class Expression:
    # Any thing that can be evaluated for a result, such as a variable
    # reference, function call, or mathematical operation.
    def render(self, parent_prefix: str, nested: bool = False) -> str:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement render()!")


# A bunch of stuff for implementing PushAction
class GenericObject(Expression):
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name

    def render(self, parent_prefix: str, nested: bool = False) -> str:
        return self.name


NULL = GenericObject('NULL')
UNDEFINED = GenericObject('UNDEFINED')
THIS = GenericObject('THIS')
ROOT = GenericObject('ROOT')
PARENT = GenericObject('PARENT')
CLIP = GenericObject('CLIP')
GLOBAL = GenericObject('GLOBAL')


class Register(Expression):
    def __init__(self, no: int) -> None:
        self.no = no

    def __repr__(self) -> str:
        return f"Register({self.no})"

    def render(self, parent_prefix: str, nested: bool = False) -> str:
        return f"registers[{self.no}]"


class StringConstant(Expression):
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

    def __init__(self, const: int, alias: Optional[str] = None) -> None:
        self.const = const
        self.alias = alias

    def __repr__(self) -> str:
        if self.alias:
            return f"StringConstant({hex(self.const)}: {self.alias})"
        else:
            return f"StringConstant({hex(self.const)}: {StringConstant.property_to_name(self.const)})"

    def render(self, parent_prefix: str, nested: bool = False) -> str:
        if self.alias:
            return self.alias
        else:
            return StringConstant.property_to_name(self.const)


class PushAction(AP2Action):
    def __init__(self, offset: int, objects: List[Any]) -> None:
        super().__init__(offset, AP2Action.PUSH)
        self.objects = objects

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            # TODO: We need to do better than this when exporting objects,
            # we should preserve their type.
            'objects': [repr(o) for o in self.objects],
        }

    def __repr__(self) -> str:
        objects = [f"  {repr(obj)}" for obj in self.objects]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join([
            f"{self.offset}: {action_name}",
            *objects,
            f"END_{action_name}",
        ])


class InitRegisterAction(AP2Action):
    def __init__(self, offset: int, registers: List[Register]) -> None:
        super().__init__(offset, AP2Action.INIT_REGISTER)
        self.registers = registers

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'registers': [r.no for r in self.registers],
        }

    def __repr__(self) -> str:
        registers = [f"  {reg}" for reg in self.registers]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join([
            f"{self.offset}: {action_name}",
            *registers,
            f"END_{action_name}",
        ])


class StoreRegisterAction(AP2Action):
    def __init__(self, offset: int, registers: List[Register], preserve_stack: bool) -> None:
        super().__init__(offset, AP2Action.STORE_REGISTER)
        self.registers = registers
        self.preserve_stack = preserve_stack

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'registers': [r.no for r in self.registers],
        }

    def __repr__(self) -> str:
        registers = [f"  {reg}" for reg in self.registers]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join([
            f"{self.offset}: {action_name}, Preserve Stack: {self.preserve_stack}",
            *registers,
            f"END_{action_name}",
        ])


class IfAction(AP2Action):
    EQUALS = 0
    NOT_EQUALS = 1
    LT = 2
    GT = 3
    LT_EQUALS = 4
    GT_EQUALS = 5
    IS_FALSE = 6
    BITAND = 7
    NOT_BITAND = 8
    STRICT_EQUALS = 9
    STRICT_NOT_EQUALS = 10
    IS_UNDEFINED = 11
    IS_NOT_UNDEFINED = 12
    IS_TRUE = 1000

    def __init__(self, offset: int, comparison: int, jump_if_true_offset: int) -> None:
        super().__init__(offset, AP2Action.IF)
        self.comparison = comparison
        self.jump_if_true_offset = jump_if_true_offset

    @classmethod
    def comparison_to_str(cls, comparison: int) -> str:
        return {
            cls.EQUALS: "==",
            cls.NOT_EQUALS: "!=",
            cls.LT: "<",
            cls.GT: ">",
            cls.LT_EQUALS: "<=",
            cls.GT_EQUALS: ">=",
            cls.IS_FALSE: "IS FALSE",
            cls.BITAND: "BITAND",
            cls.NOT_BITAND: "BITNOTAND",
            cls.STRICT_EQUALS: "STRICT ==",
            cls.STRICT_NOT_EQUALS: "STRICT !=",
            cls.IS_UNDEFINED: "IS UNDEFINED",
            cls.IS_NOT_UNDEFINED: "IS NOT UNDEFINED",
            cls.IS_TRUE: "IS TRUE",
        }[comparison]

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'comparison': IfAction.comparison_to_str(self.comparison),
            'jump_if_true_offset': self.jump_if_true_offset,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Comparison: {IfAction.comparison_to_str(self.comparison)}, Offset To Jump To If True: {self.jump_if_true_offset}"


class JumpAction(AP2Action):
    def __init__(self, offset: int, jump_offset: int) -> None:
        super().__init__(offset, AP2Action.JUMP)
        self.jump_offset = jump_offset

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'jump_offset': self.jump_offset,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Offset To Jump To: {self.jump_offset}"


class WithAction(AP2Action):
    def __init__(self, offset: int, unknown: bytes) -> None:
        super().__init__(offset, AP2Action.WITH)
        self.unknown = unknown

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            # TODO: We need to do better than this, so I guess it comes down to having
            # a better idea how WITH works.
            'unknown': str(self.unknown),
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Unknown: {self.unknown!r}"


class GotoFrame2Action(AP2Action):
    def __init__(self, offset: int, additional_frames: int, stop: bool) -> None:
        super().__init__(offset, AP2Action.GOTO_FRAME2)
        self.additional_frames = additional_frames
        self.stop = stop

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'additiona_frames': self.additional_frames,
            'stop': self.stop,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Additional Frames: {self.additional_frames}, Stop On Arrival: {'yes' if self.stop else 'no'}"


class AddNumVariableAction(AP2Action):
    def __init__(self, offset: int, amount_to_add: int) -> None:
        super().__init__(offset, AP2Action.ADD_NUM_VARIABLE)
        self.amount_to_add = amount_to_add

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'amount_to_add': self.amount_to_add,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Amount To Add: {self.amount_to_add}"


class AddNumRegisterAction(AP2Action):
    def __init__(self, offset: int, register: Register, amount_to_add: int) -> None:
        super().__init__(offset, AP2Action.ADD_NUM_REGISTER)
        self.register = register
        self.amount_to_add = amount_to_add

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'register': self.register.no,
            'amount_to_add': self.amount_to_add,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Register: {self.register}, Amount To Add: {self.amount_to_add}"


class GetURL2Action(AP2Action):
    def __init__(self, offset: int, action: int) -> None:
        super().__init__(offset, AP2Action.GET_URL2)
        self.action = action

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'action': self.action,
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Action: {self.action}"


class StartDragAction(AP2Action):
    def __init__(self, offset: int, constrain: Optional[bool]) -> None:
        super().__init__(offset, AP2Action.START_DRAG)
        self.constrain = constrain

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            'constrain': self.constrain,
        }

    def __repr__(self) -> str:
        if self.constrain is None:
            cstr = "check stack"
        else:
            cstr = "yes" if self.constrain else "no"
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Constrain Mouse: {cstr}"


class AP2Object:
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


class AP2Pointer:
    # The type of the object if it is an AP2Object.POINTER or AP2Object.OBJECT
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
