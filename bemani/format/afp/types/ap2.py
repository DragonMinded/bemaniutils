import os
from typing import TYPE_CHECKING, Any, Dict, List, Set, Optional
from typing_extensions import Final

from .expression import Register

if TYPE_CHECKING:
    # This is a circular dependency otherwise.
    from ..decompile import ByteCode


class AP2Object:
    # These are internal object types, useful to have them for understanding
    # what the original games are doing with data types.
    UNDEFINED: Final[int] = 0x0
    NAN: Final[int] = 0x1
    BOOLEAN: Final[int] = 0x2
    INTEGER: Final[int] = 0x3
    S64: Final[int] = 0x4
    FLOAT: Final[int] = 0x5
    DOUBLE: Final[int] = 0x6
    STRING: Final[int] = 0x7
    POINTER: Final[int] = 0x8
    OBJECT: Final[int] = 0x9
    INFINITY: Final[int] = 0xA
    CONST_STRING: Final[int] = 0xB
    BUILT_IN_FUNCTION: Final[int] = 0xC


class AP2Pointer:
    # The type of the object if it is an AP2Object.POINTER or AP2Object.OBJECT.
    # These are internal object types as well, and are only useful to have these
    # around for understanding what games are doing with data types.
    UNDEFINED: Final[int] = 0x0
    AFP_TEXT: Final[int] = 0x1
    AFP_RECT: Final[int] = 0x2
    AFP_SHAPE: Final[int] = 0x3
    DRAG: Final[int] = 0x4
    MATRIX: Final[int] = 0x5
    POINT: Final[int] = 0x6
    GETTER_SETTER_PROPERTY: Final[int] = 0x7
    FUNCTION_WITH_PROTOTYPE: Final[int] = 0x8
    ROW_DATA: Final[int] = 0x20

    object_W: Final[int] = 0x50
    movieClip_W: Final[int] = 0x51
    sound_W: Final[int] = 0x52
    color_W: Final[int] = 0x53
    date_W: Final[int] = 0x54
    array_W: Final[int] = 0x55
    xml_W: Final[int] = 0x56
    xmlNode_W: Final[int] = 0x57
    textFormat_W: Final[int] = 0x58
    sharedObject_W: Final[int] = 0x59
    sharedObjectData_W: Final[int] = 0x5A
    textField_W: Final[int] = 0x5B
    xmlAttrib_W: Final[int] = 0x5C
    bitmapdata_W: Final[int] = 0x5D
    matrix_W: Final[int] = 0x5E
    point_W: Final[int] = 0x5F
    ColorMatrixFilter_W: Final[int] = 0x60
    String_W: Final[int] = 0x61
    Boolean_W: Final[int] = 0x62
    Number_W: Final[int] = 0x63
    function_W: Final[int] = 0x64
    prototype_W: Final[int] = 0x65
    super_W: Final[int] = 0x66
    transform_W: Final[int] = 0x68
    colorTransform_W: Final[int] = 0x69
    rectangle_W: Final[int] = 0x6A

    # All of these can have prototypes, not sure what the "C" stands for.
    Object_C: Final[int] = 0x78
    MovieClip_C: Final[int] = 0x79
    Sound_C: Final[int] = 0x7A
    Color_C: Final[int] = 0x7B
    Date_C: Final[int] = 0x7C
    Array_C: Final[int] = 0x7D
    XML_C: Final[int] = 0x7E
    XMLNode_C: Final[int] = 0x7F
    TextFormat_C: Final[int] = 0x80
    TextField_C: Final[int] = 0x83
    BitmapData_C: Final[int] = 0x85
    matrix_C: Final[int] = 0x86
    point_C: Final[int] = 0x87
    String_C: Final[int] = 0x89
    Boolean_C: Final[int] = 0x8A
    Number_C: Final[int] = 0x8B
    Function_C: Final[int] = 0x8C
    aplib_C: Final[int] = 0x8F
    transform_C: Final[int] = 0x90
    colorTransform_C: Final[int] = 0x91
    rectangle_C: Final[int] = 0x92
    asdlib_C: Final[int] = 0x93
    XMLController_C: Final[int] = 0x94
    eManager_C: Final[int] = 0x95

    stage_O: Final[int] = 0xA0
    math_O: Final[int] = 0xA1
    key_O: Final[int] = 0xA2
    mouse_O: Final[int] = 0xA3
    system_O: Final[int] = 0xA4
    sharedObject_O: Final[int] = 0xA5
    flash_O: Final[int] = 0xA6
    global_O: Final[int] = 0xA7

    display_P: Final[int] = 0xB4
    geom_P: Final[int] = 0xB5
    filtesr_P: Final[int] = 0xB6


class AP2Trigger:
    # Possible triggers for ByteCode to be attached to on object place tags.
    ON_LOAD: Final[int] = 0x1
    ON_ENTER_FRAME: Final[int] = 0x2
    ON_UNLOAD: Final[int] = 0x4
    ON_MOUSE_MOVE: Final[int] = 0x8
    ON_MOUSE_DOWN: Final[int] = 0x10
    ON_MOUSE_UP: Final[int] = 0x20
    ON_KEY_DOWN: Final[int] = 0x40
    ON_KEY_UP: Final[int] = 0x80
    ON_DATA: Final[int] = 0x100
    ON_PRESS: Final[int] = 0x400
    ON_RELEASE: Final[int] = 0x800
    ON_RELEASE_OUTSIDE: Final[int] = 0x1000
    ON_ROLL_OVER: Final[int] = 0x2000
    ON_ROLL_OUT: Final[int] = 0x4000


class AP2Tag:
    # Every tag found in an AFP file. The majority of these are identical to tags
    # in the SWF file specification but are not seen in practice.
    END: Final[int] = 0x0
    SHOW_FRAME: Final[int] = 0x1
    DEFINE_SHAPE: Final[int] = 0x2
    PLACE_OBJECT: Final[int] = 0x4
    REMOVE_OBJECT: Final[int] = 0x5
    DEFINE_BITS: Final[int] = 0x6
    DEFINE_BUTTON: Final[int] = 0x7
    JPEG_TABLES: Final[int] = 0x8
    BACKGROUND_COLOR: Final[int] = 0x9
    DEFINE_FONT: Final[int] = 0xA
    DEFINE_TEXT: Final[int] = 0xB
    DO_ACTION: Final[int] = 0xC
    DEFINE_FONT_INFO: Final[int] = 0xD
    DEFINE_SOUND: Final[int] = 0xE
    START_SOUND: Final[int] = 0xF
    DEFINE_BUTTON_SOUND: Final[int] = 0x11
    SOUND_STREAM_HEAD: Final[int] = 0x12
    SOUND_STREAM_BLOCK: Final[int] = 0x13
    DEFINE_BITS_LOSSLESS: Final[int] = 0x14
    DEFINE_BITS_JPEG2: Final[int] = 0x15
    DEFINE_SHAPE2: Final[int] = 0x16
    DEFINE_BUTTON_CXFORM: Final[int] = 0x17
    PROTECT: Final[int] = 0x18
    PLACE_OBJECT2: Final[int] = 0x1A
    REMOVE_OBJECT2: Final[int] = 0x1C
    DEFINE_SHAPE3: Final[int] = 0x20
    DEFINE_TEXT2: Final[int] = 0x21
    DEFINE_BUTTON2: Final[int] = 0x22
    DEFINE_BITS_JPEG3: Final[int] = 0x23
    DEFINE_BITS_LOSSLESS2: Final[int] = 0x24
    DEFINE_EDIT_TEXT: Final[int] = 0x25
    DEFINE_SPRITE: Final[int] = 0x27
    FRAME_LABEL: Final[int] = 0x2B
    SOUND_STREAM_HEAD2: Final[int] = 0x2D
    DEFINE_MORPH_SHAPE: Final[int] = 0x2E
    DEFINE_FONT2: Final[int] = 0x30
    EXPORT_ASSETS: Final[int] = 0x38
    IMPORT_ASSETS: Final[int] = 0x39
    DO_INIT_ACTION: Final[int] = 0x3B
    DEFINE_VIDEO_STREAM: Final[int] = 0x3C
    VIDEO_FRAME: Final[int] = 0x3D
    DEFINE_FONT_INFO2: Final[int] = 0x3E
    ENABLE_DEBUGGER2: Final[int] = 0x40
    SCRIPT_LIMITS: Final[int] = 0x41
    SET_TAB_INDEX: Final[int] = 0x42
    PLACE_OBJECT3: Final[int] = 0x46
    IMPORT_ASSETS2: Final[int] = 0x47
    DEFINE_FONT3: Final[int] = 0x4B
    METADATA: Final[int] = 0x4D
    DEFINE_SCALING_GRID: Final[int] = 0x4E
    DEFINE_SHAPE4: Final[int] = 0x53
    DEFINE_MORPH_SHAPE2: Final[int] = 0x54
    SCENE_LABEL: Final[int] = 0x56
    AFP_IMAGE: Final[int] = 0x64
    AFP_DEFINE_SOUND: Final[int] = 0x65
    AFP_SOUND_STREAM_BLOCK: Final[int] = 0x66
    AFP_DEFINE_FONT: Final[int] = 0x67
    AFP_DEFINE_SHAPE: Final[int] = 0x68
    AEP_PLACE_OBJECT: Final[int] = 0x6E
    AP2_DEFINE_FONT: Final[int] = 0x78
    AP2_DEFINE_SPRITE: Final[int] = 0x79
    AP2_DO_ACTION: Final[int] = 0x7A
    AP2_DEFINE_BUTTON: Final[int] = 0x7B
    AP2_DEFINE_BUTTON_SOUND: Final[int] = 0x7C
    AP2_DEFINE_TEXT: Final[int] = 0x7D
    AP2_DEFINE_EDIT_TEXT: Final[int] = 0x7E
    AP2_PLACE_OBJECT: Final[int] = 0x7F
    AP2_REMOVE_OBJECT: Final[int] = 0x80
    AP2_START_SOUND: Final[int] = 0x81
    AP2_DEFINE_MORPH_SHAPE: Final[int] = 0x82
    AP2_IMAGE: Final[int] = 0x83
    AP2_SHAPE: Final[int] = 0x84
    AP2_SOUND: Final[int] = 0x85
    AP2_VIDEO: Final[int] = 0x86
    AP2_PLACE_CAMERA: Final[int] = 0x88
    AP2_SCALING_GRID: Final[int] = 0x89

    @classmethod
    def tag_to_name(cls, tagid: int) -> str:
        resources: Dict[int, str] = {
            cls.END: "END",
            cls.SHOW_FRAME: "SHOW_FRAME",
            cls.DEFINE_SHAPE: "DEFINE_SHAPE",
            cls.PLACE_OBJECT: "PLACE_OBJECT",
            cls.REMOVE_OBJECT: "REMOVE_OBJECT",
            cls.DEFINE_BITS: "DEFINE_BITS",
            cls.DEFINE_BUTTON: "DEFINE_BUTTON",
            cls.JPEG_TABLES: "JPEG_TABLES",
            cls.BACKGROUND_COLOR: "BACKGROUND_COLOR",
            cls.DEFINE_FONT: "DEFINE_FONT",
            cls.DEFINE_TEXT: "DEFINE_TEXT",
            cls.DO_ACTION: "DO_ACTION",
            cls.DEFINE_FONT_INFO: "DEFINE_FONT_INFO",
            cls.DEFINE_SOUND: "DEFINE_SOUND",
            cls.START_SOUND: "START_SOUND",
            cls.DEFINE_BUTTON_SOUND: "DEFINE_BUTTON_SOUND",
            cls.SOUND_STREAM_HEAD: "SOUND_STREAM_HEAD",
            cls.SOUND_STREAM_BLOCK: "SOUND_STREAM_BLOCK",
            cls.DEFINE_BITS_LOSSLESS: "DEFINE_BITS_LOSSLESS",
            cls.DEFINE_BITS_JPEG2: "DEFINE_BITS_JPEG2",
            cls.DEFINE_SHAPE2: "DEFINE_SHAPE2",
            cls.DEFINE_BUTTON_CXFORM: "DEFINE_BUTTON_CXFORM",
            cls.PROTECT: "PROTECT",
            cls.PLACE_OBJECT2: "PLACE_OBJECT2",
            cls.REMOVE_OBJECT2: "REMOVE_OBJECT2",
            cls.DEFINE_SHAPE3: "DEFINE_SHAPE3",
            cls.DEFINE_TEXT2: "DEFINE_TEXT2",
            cls.DEFINE_BUTTON2: "DEFINE_BUTTON2",
            cls.DEFINE_BITS_JPEG3: "DEFINE_BITS_JPEG3",
            cls.DEFINE_BITS_LOSSLESS2: "DEFINE_BITS_LOSSLESS2",
            cls.DEFINE_EDIT_TEXT: "DEFINE_EDIT_TEXT",
            cls.DEFINE_SPRITE: "DEFINE_SPRITE",
            cls.FRAME_LABEL: "FRAME_LABEL",
            cls.SOUND_STREAM_HEAD2: "SOUND_STREAM_HEAD2",
            cls.DEFINE_MORPH_SHAPE: "DEFINE_MORPH_SHAPE",
            cls.DEFINE_FONT2: "DEFINE_FONT2",
            cls.EXPORT_ASSETS: "EXPORT_ASSETS",
            cls.IMPORT_ASSETS: "IMPORT_ASSETS",
            cls.DO_INIT_ACTION: "DO_INIT_ACTION",
            cls.DEFINE_VIDEO_STREAM: "DEFINE_VIDEO_STREAM",
            cls.VIDEO_FRAME: "VIDEO_FRAME",
            cls.DEFINE_FONT_INFO2: "DEFINE_FONT_INFO2",
            cls.ENABLE_DEBUGGER2: "ENABLE_DEBUGGER2",
            cls.SCRIPT_LIMITS: "SCRIPT_LIMITS",
            cls.SET_TAB_INDEX: "SET_TAB_INDEX",
            cls.PLACE_OBJECT3: "PLACE_OBJECT3",
            cls.IMPORT_ASSETS2: "IMPORT_ASSETS2",
            cls.DEFINE_FONT3: "DEFINE_FONT3",
            cls.DEFINE_SCALING_GRID: "DEFINE_SCALING_GRID",
            cls.METADATA: "METADATA",
            cls.DEFINE_SHAPE4: "DEFINE_SHAPE4",
            cls.DEFINE_MORPH_SHAPE2: "DEFINE_MORPH_SHAPE2",
            cls.SCENE_LABEL: "SCENE_LABEL",
            cls.AFP_IMAGE: "AFP_IMAGE",
            cls.AFP_DEFINE_SOUND: "AFP_DEFINE_SOUND",
            cls.AFP_SOUND_STREAM_BLOCK: "AFP_SOUND_STREAM_BLOCK",
            cls.AFP_DEFINE_FONT: "AFP_DEFINE_FONT",
            cls.AFP_DEFINE_SHAPE: "AFP_DEFINE_SHAPE",
            cls.AEP_PLACE_OBJECT: "AEP_PLACE_OBJECT",
            cls.AP2_DEFINE_FONT: "AP2_DEFINE_FONT",
            cls.AP2_DEFINE_SPRITE: "AP2_DEFINE_SPRITE",
            cls.AP2_DO_ACTION: "AP2_DO_ACTION",
            cls.AP2_DEFINE_BUTTON: "AP2_DEFINE_BUTTON",
            cls.AP2_DEFINE_BUTTON_SOUND: "AP2_DEFINE_BUTTON_SOUND",
            cls.AP2_DEFINE_TEXT: "AP2_DEFINE_TEXT",
            cls.AP2_DEFINE_EDIT_TEXT: "AP2_DEFINE_EDIT_TEXT",
            cls.AP2_PLACE_OBJECT: "AP2_PLACE_OBJECT",
            cls.AP2_REMOVE_OBJECT: "AP2_REMOVE_OBJECT",
            cls.AP2_START_SOUND: "AP2_START_SOUND",
            cls.AP2_DEFINE_MORPH_SHAPE: "AP2_DEFINE_MORPH_SHAPE",
            cls.AP2_IMAGE: "AP2_IMAGE",
            cls.AP2_SHAPE: "AP2_SHAPE",
            cls.AP2_SOUND: "AP2_SOUND",
            cls.AP2_VIDEO: "AP2_VIDEO",
            cls.AP2_PLACE_CAMERA: "AP2_PLACE_CAMERA",
            cls.AP2_SCALING_GRID: "AP2_SCALING_GRID",
        }

        return resources.get(tagid, f"<UNKNOWN {hex(tagid)}>")


class AP2Action:
    # End bytecode processing
    END: Final[int] = 0

    # Advance movieclip to next frame.
    NEXT_FRAME: Final[int] = 1

    # Rewind movieclip to previous frame.
    PREVIOUS_FRAME: Final[int] = 2

    # Play the movieclip.
    PLAY: Final[int] = 3

    # Stop the movieclip.
    STOP: Final[int] = 4

    # Stop all sound from the movie clip.
    STOP_SOUND: Final[int] = 5

    # Pop two objects from the stack, subtract them, push the result to the stack.
    SUBTRACT: Final[int] = 7

    # Pop two objects from the stack, multiply them, push the result to the stack.
    MULTIPLY: Final[int] = 8

    # Pop two objects from the stack, divide them, push the result to the stack.
    DIVIDE: Final[int] = 9

    # Pop an object from the stack, boolean negate it, push the result to the stack.
    NOT: Final[int] = 12

    # Pop an object from the stack, discard it.
    POP: Final[int] = 13

    # Pop an object off the stack, use that as a string to look up a variable, push
    # that variable's value onto the stack.
    GET_VARIABLE: Final[int] = 14

    # Pop two objects from the stack, if the second object is a string or const, define a
    # variable with that name equal to the first object.
    SET_VARIABLE: Final[int] = 15

    # Similar to GET_MEMBER, but the member value is an integer in the range 0x0-0x15 which
    # gets added to 0x100 and looked up in StringConstants.
    GET_PROPERTY: Final[int] = 16

    # Similar to SET_MEMBER in exactly the same way GET_PROPERTY is similar to GET_MEMBER.
    SET_PROPERTY: Final[int] = 17

    # Clone a sprite that's specified on the stack.
    CLONE_SPRITE: Final[int] = 18

    # Remove a sprite as specified on the stack.
    REMOVE_SPRITE: Final[int] = 19

    # Print a trace of the current object on the stack, and pop it.
    TRACE: Final[int] = 20

    # Start dragging an object. It pops a value from the stack to set as the drag target.
    # It pops a second boolean value from the stack to specify if the drag target should be
    # locked to the mouse. One opcode specifies that we pop 4 more values from the stack
    # as a rectangle to constrain the mouse if the opcode is > 0, that we don't constrain
    # at all if the opcode is 0, or that we pop another boolean from the stack and constrain
    # if that value is true.
    START_DRAG: Final[int] = 21

    # End dragging the current drag target that was started with START_DRAG.
    END_DRAG: Final[int] = 22

    # Pop an object from the stack and throw it as an exception.
    THROW: Final[int] = 23

    # Pop an object from the stack, and an object representing a class. If the first
    # object is an instance of the class, push it back. Otherwise, push back a null.
    CAST_OP: Final[int] = 24

    # Unclear exactly what this does on the stack, the implementation seems wrong.
    IMPLEMENTS_OP: Final[int] = 25

    # Get the current playback position as an integer number of milliseconds, pushed to the stack.
    GET_TIME: Final[int] = 26

    # Pops two values from the stack to look up what to delete.
    DELETE: Final[int] = 27

    # Delete a variable as defined on the stack. Pops that variable name.
    DELETE2: Final[int] = 28

    # Pop two objects from the stack, and then define a local variable just like "SET_VARIABLE"
    # but in the scope of the current movieclip or function.
    DEFINE_LOCAL: Final[int] = 29

    # Call a function. Similar to CALL_METHOD but with only one pop for the function name.
    CALL_FUNCTION: Final[int] = 30

    # Return the top of the stack as the return value of the function.
    RETURN: Final[int] = 31

    # Pop two numbers, modulo them, push them back to the stack.
    MODULO: Final[int] = 32

    # Create a new object, I haven't figured out what it pushes and pops from the stack yet.
    NEW_OBJECT: Final[int] = 33

    # Define a variable in the local movieclip or function, without a value.
    DEFINE_LOCAL2: Final[int] = 34

    # Init an array from the stack. Pops the array's number of items, and then an item each
    # to add to the array. Then it adds the array to the stack.
    INIT_ARRAY: Final[int] = 35

    # Init an object from the stack.
    INIT_OBJECT: Final[int] = 36

    # Pop an object off the stack, push the type of the object as a string.
    TYPEOF: Final[int] = 37

    # Pop an item off the stack, and if it is a movieclip, push the string path. If it isn't
    # a movieclip, push an undefined object onto the stack.
    TARGET_PATH: Final[int] = 38

    # Add two values on the stack, popping them and pushing the result.
    ADD2: Final[int] = 39

    # Pops two values from the stack, and pushes a boolean representing whether one is less than
    # the other. If they cannot be compared, pushes an "Undefined" object onto the stack instead.
    LESS2: Final[int] = 40

    # Pop two objects from the stack, get their string equivalent, and push a boolean onto the
    # stack if those strings match.
    EQUALS2: Final[int] = 41

    # Pops the top of the stack, converts it to an integer object, and pushes it. If it can't
    # convert, instead pushes a "NaN" object.
    TO_NUMBER: Final[int] = 42

    # Pops the top of the stack, converts the object to its string equivalent, and pushes it.
    TO_STRING: Final[int] = 43

    # Takes the top of the stack and duplicates the object before pushing that object to the stack.
    PUSH_DUPLICATE: Final[int] = 44

    # Swaps the position of the two two objects on the stack. If there isn't enough to swap, does
    # nothing.
    STACK_SWAP: Final[int] = 45

    # Get a member value and place it on the stack.
    GET_MEMBER: Final[int] = 46

    # Set member, popping three values from the stack.
    SET_MEMBER: Final[int] = 47

    # Increment value on stack.
    INCREMENT: Final[int] = 48

    # Decrement value on stack.
    DECREMENT: Final[int] = 49

    # Call method. Pops two values from the stack to lookup an object method, another value from the
    # stack for the number of params, and then that many values from the stack as function parameters.
    CALL_METHOD: Final[int] = 50

    # Takes at least 3 objects on the stack, the third being the number of parameters, the second being
    # the object to add a method to and the first being the member name.
    NEW_METHOD: Final[int] = 51

    # Takes two objects, pops them off the stack and adds a boolean object to the stack set to true
    # if one is an instance of the other or false otherwise.
    INSTANCEOF: Final[int] = 52

    # Enumerates some sort of object into a variable on the top of the stack.
    ENUMERATE2: Final[int] = 53

    # Pop two values from the stack, bitwise and them, push the result.
    BIT_AND: Final[int] = 54

    # Pop two values from the stack, bitwise or them, push the result.
    BIT_OR: Final[int] = 55

    # Pop two values from the stack, bitwise xor them, push the result.
    BIT_XOR: Final[int] = 56

    # Pop the amount to left shift, and an integer from the stack, push the result.
    BIT_L_SHIFT: Final[int] = 57

    # Pop the amount to right shift, and an integer from the stack, push the result.
    BIT_R_SHIFT: Final[int] = 58

    # Same as above but unsigned. It appears that games implement this identically to BIT_U_R_SHIFT.
    BIT_U_R_SHIFT: Final[int] = 59

    # Pop two values from the stack, push a boolean set to true if the values are strictly equal.
    STRICT_EQUALS: Final[int] = 60

    # Pop two objects off the stack, push a boolean object for whether the first object is greater tha
    # the second or not.
    GREATER: Final[int] = 61

    # Pops two objects off the stack and does some sort of OOP with them, the first being the superclass
    # and the second being the subclass.
    EXTENDS: Final[int] = 62

    # Pop a value from the stack and store it in a register specified by the opcode param. Also push
    # it back onto the stack.
    STORE_REGISTER: Final[int] = 63

    # Define a function based on parameters on the stack. This reads the next 9 bytes of the bytecode
    # as parameters, and uses that to read the next N bytes of bytecode as the function definition.
    DEFINE_FUNCTION2: Final[int] = 64

    # Grabs a 16 bit offset pointer as the opcode param, then skips bytecode processing forward
    # that many bytes, passing the skipped bytes as pointer data to a function that adds it to the
    # stack as a pointer type, and then adds a copy of the top of the stack before the pointer as a
    # second new stack entry. Strangely enough, if the object on the top of the stack doesn't meet
    # some criteria, the skipped bytes are processed as bytecode. I am not sure what the hell is going
    # on here.
    WITH: Final[int] = 66

    # Push an object onto the stack. Creates objects based on the bytecode parameters and pushes
    # them onto the stack.
    PUSH: Final[int] = 67

    # Unconditional jump based on bytecode value.
    JUMP: Final[int] = 68

    # Gets a single 8-bit integer as an opcode param, take the top two bits of that param as the
    # action to take. Looks like it is similar to SWF GET_URL2 action. Supported actions are 0,
    # 1 and 3. It pops two objects from the stack to perform against.
    GET_URL2: Final[int] = 69

    # Pops a value from the stack, jumps to offset from opcode params if value is truthy.
    IF: Final[int] = 70

    # Go to frame specified by top of stack, popping that value from the stack. Also specifies
    # flags for whether to play or stop when going to that frame, and additional frames to advance
    # in opcode params.
    GOTO_FRAME2: Final[int] = 71

    # Pops the top of the stack, uses that to get a target, pushes a pointer to that target on
    # the stack.
    GET_TARGET: Final[int] = 72

    # Given a subtype of check and a positive offset to jump to on true, perform a conditional check.
    # Pops two values from the stack for all equality checks except for undefined checks, which pop
    # one value.
    IF2: Final[int] = 73

    # Similar to STORE_REGISTER but does not preserve the value on the stack afterwards.
    STORE_REGISTER2: Final[int] = 74

    # Take one opcode parameter for the number of registers to init, and then one opcode parameter
    # per the number of registers param as the register number to init, initializing that register
    # as an "Undefined" object.
    INIT_REGISTER: Final[int] = 75

    # Similar to ADD_NUM_VARIABLE, but operating on a register number instead of the stack. Takes
    # two params from opcodes, one for the register number and one for the addition value.
    ADD_NUM_REGISTER: Final[int] = 76

    # Add a number dictated by an opcode param to the variable on the stack, popping the variable
    # name.
    ADD_NUM_VARIABLE: Final[int] = 77

    @classmethod
    def action_to_name(cls, actionid: int) -> str:
        resources: Dict[int, str] = {
            cls.END: "END",
            cls.NEXT_FRAME: "NEXT_FRAME",
            cls.PREVIOUS_FRAME: "PREVIOUS_FRAME",
            cls.PLAY: "PLAY",
            cls.STOP: "STOP",
            cls.STOP_SOUND: "STOP_SOUND",
            cls.SUBTRACT: "SUBTRACT",
            cls.MULTIPLY: "MULTIPLY",
            cls.DIVIDE: "DIVIDE",
            cls.NOT: "NOT",
            cls.POP: "POP",
            cls.GET_VARIABLE: "GET_VARIABLE",
            cls.SET_VARIABLE: "SET_VARIABLE",
            cls.GET_PROPERTY: "GET_PROPERTY",
            cls.SET_PROPERTY: "SET_PROPERTY",
            cls.CLONE_SPRITE: "CLONE_SPRITE",
            cls.REMOVE_SPRITE: "REMOVE_SPRITE",
            cls.TRACE: "TRACE",
            cls.START_DRAG: "START_DRAG",
            cls.END_DRAG: "END_DRAG",
            cls.THROW: "THROW",
            cls.CAST_OP: "CAST_OP",
            cls.IMPLEMENTS_OP: "IMPLEMENTS_OP",
            cls.GET_TIME: "GET_TIME",
            cls.DELETE: "DELETE",
            cls.DELETE2: "DELETE2",
            cls.DEFINE_LOCAL: "DEFINE_LOCAL",
            cls.CALL_FUNCTION: "CALL_FUNCTION",
            cls.RETURN: "RETURN",
            cls.MODULO: "MODULO",
            cls.NEW_OBJECT: "NEW_OBJECT",
            cls.DEFINE_LOCAL2: "DEFINE_LOCAL2",
            cls.INIT_ARRAY: "INIT_ARRAY",
            cls.INIT_OBJECT: "INIT_OBJECT",
            cls.TYPEOF: "TYPEOF",
            cls.TARGET_PATH: "TARGET_PATH",
            cls.ADD2: "ADD2",
            cls.LESS2: "LESS2",
            cls.EQUALS2: "EQUALS2",
            cls.TO_NUMBER: "TO_NUMBER",
            cls.TO_STRING: "TO_STRING",
            cls.PUSH_DUPLICATE: "PUSH_DUPLICATE",
            cls.STACK_SWAP: "STACK_SWAP",
            cls.GET_MEMBER: "GET_MEMBER",
            cls.SET_MEMBER: "SET_MEMBER",
            cls.INCREMENT: "INCREMENT",
            cls.DECREMENT: "DECREMENT",
            cls.CALL_METHOD: "CALL_METHOD",
            cls.NEW_METHOD: "NEW_METHOD",
            cls.INSTANCEOF: "INSTANCEOF",
            cls.ENUMERATE2: "ENUMERATE2",
            cls.BIT_AND: "BIT_AND",
            cls.BIT_OR: "BIT_OR",
            cls.BIT_XOR: "BIT_XOR",
            cls.BIT_L_SHIFT: "BIT_L_SHIFT",
            cls.BIT_R_SHIFT: "BIT_R_SHIFT",
            cls.BIT_U_R_SHIFT: "BIT_U_R_SHIFT",
            cls.STRICT_EQUALS: "STRICT_EQUALS",
            cls.GREATER: "GREATER",
            cls.EXTENDS: "EXTENDS",
            cls.STORE_REGISTER: "STORE_REGISTER",
            cls.DEFINE_FUNCTION2: "DEFINE_FUNCTION2",
            cls.WITH: "WITH",
            cls.PUSH: "PUSH",
            cls.JUMP: "JUMP",
            cls.GET_URL2: "GET_URL2",
            cls.IF: "IF",
            cls.GOTO_FRAME2: "GOTO_FRAME2",
            cls.GET_TARGET: "GET_TARGET",
            cls.IF2: "IF2",
            cls.STORE_REGISTER2: "STORE_REGISTER2",
            cls.INIT_REGISTER: "INIT_REGISTER",
            cls.ADD_NUM_REGISTER: "ADD_NUM_REGISTER",
            cls.ADD_NUM_VARIABLE: "ADD_NUM_VARIABLE",
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
            "offset": self.offset,
            "action": AP2Action.action_to_name(self.opcode),
        }

    def __repr__(self) -> str:
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}"


class DefineFunction2Action(AP2Action):
    def __init__(
        self, offset: int, name: Optional[str], flags: int, body: "ByteCode"
    ) -> None:
        super().__init__(offset, AP2Action.DEFINE_FUNCTION2)
        self.name = name
        self.flags = flags
        self.body = body

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "name": self.name,
            "flags": self.flags,
            "body": self.body.as_dict(*args, **kwargs),
        }

    def __repr__(self) -> str:
        bytecode = [f"  {line}" for line in str(self.body).split(os.linesep)]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join(
            [
                f"{self.offset}: {action_name}, Name: {self.name or '<anonymous function>'}, Flags: {hex(self.flags)}",
                *bytecode,
                f"END_{action_name}",
            ]
        )


class PushAction(AP2Action):
    def __init__(self, offset: int, objects: List[Any]) -> None:
        super().__init__(offset, AP2Action.PUSH)
        self.objects = objects

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            # TODO: We need to do better than this when exporting objects,
            # we should preserve their type.
            "objects": [repr(o) for o in self.objects],
        }

    def __repr__(self) -> str:
        objects = [f"  {repr(obj)}" for obj in self.objects]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join(
            [
                f"{self.offset}: {action_name}",
                *objects,
                f"END_{action_name}",
            ]
        )


class InitRegisterAction(AP2Action):
    def __init__(self, offset: int, registers: List[Register]) -> None:
        super().__init__(offset, AP2Action.INIT_REGISTER)
        self.registers = registers

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "registers": [r.no for r in self.registers],
        }

    def __repr__(self) -> str:
        registers = [f"  {reg}" for reg in self.registers]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join(
            [
                f"{self.offset}: {action_name}",
                *registers,
                f"END_{action_name}",
            ]
        )


class StoreRegisterAction(AP2Action):
    def __init__(
        self, offset: int, registers: List[Register], preserve_stack: bool
    ) -> None:
        super().__init__(offset, AP2Action.STORE_REGISTER)
        self.registers = registers
        self.preserve_stack = preserve_stack

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "registers": [r.no for r in self.registers],
        }

    def __repr__(self) -> str:
        registers = [f"  {reg}" for reg in self.registers]
        action_name = AP2Action.action_to_name(self.opcode)
        return os.linesep.join(
            [
                f"{self.offset}: {action_name}, Preserve Stack: {self.preserve_stack}",
                *registers,
                f"END_{action_name}",
            ]
        )


class IfAction(AP2Action):
    COMP_EQUALS: Final[int] = 0
    COMP_NOT_EQUALS: Final[int] = 1
    COMP_LT: Final[int] = 2
    COMP_GT: Final[int] = 3
    COMP_LT_EQUALS: Final[int] = 4
    COMP_GT_EQUALS: Final[int] = 5
    COMP_IS_FALSE: Final[int] = 6
    COMP_BITAND: Final[int] = 7
    COMP_NOT_BITAND: Final[int] = 8
    COMP_STRICT_EQUALS: Final[int] = 9
    COMP_STRICT_NOT_EQUALS: Final[int] = 10
    COMP_IS_UNDEFINED: Final[int] = 11
    COMP_IS_NOT_UNDEFINED: Final[int] = 12
    COMP_IS_TRUE: Final[int] = 1000

    def __init__(self, offset: int, comparison: int, jump_if_true_offset: int) -> None:
        super().__init__(offset, AP2Action.IF)
        self.comparison = comparison
        self.jump_if_true_offset = jump_if_true_offset

    @classmethod
    def comparison_to_str(cls, comparison: int) -> str:
        return {
            cls.COMP_EQUALS: "==",
            cls.COMP_NOT_EQUALS: "!=",
            cls.COMP_LT: "<",
            cls.COMP_GT: ">",
            cls.COMP_LT_EQUALS: "<=",
            cls.COMP_GT_EQUALS: ">=",
            cls.COMP_IS_FALSE: "IS FALSE",
            cls.COMP_BITAND: "BITAND",
            cls.COMP_NOT_BITAND: "BITNOTAND",
            cls.COMP_STRICT_EQUALS: "STRICT ==",
            cls.COMP_STRICT_NOT_EQUALS: "STRICT !=",
            cls.COMP_IS_UNDEFINED: "IS UNDEFINED",
            cls.COMP_IS_NOT_UNDEFINED: "IS NOT UNDEFINED",
            cls.COMP_IS_TRUE: "IS TRUE",
        }[comparison]

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            **super().as_dict(*args, **kwargs),
            "comparison": IfAction.comparison_to_str(self.comparison),
            "jump_if_true_offset": self.jump_if_true_offset,
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
            "jump_offset": self.jump_offset,
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
            "unknown": str(self.unknown),
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
            "additiona_frames": self.additional_frames,
            "stop": self.stop,
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
            "amount_to_add": self.amount_to_add,
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
            "register": self.register.no,
            "amount_to_add": self.amount_to_add,
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
            "action": self.action,
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
            "constrain": self.constrain,
        }

    def __repr__(self) -> str:
        if self.constrain is None:
            cstr = "check stack"
        else:
            cstr = "yes" if self.constrain else "no"
        return f"{self.offset}: {AP2Action.action_to_name(self.opcode)}, Constrain Mouse: {cstr}"
