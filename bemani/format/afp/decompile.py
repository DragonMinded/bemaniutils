import os
from typing import Any, Dict, List, Sequence, Tuple, Set, Union, Optional, Callable, cast

from .types import (
    AP2Action,
    JumpAction,
    IfAction,
    PushAction,
    AddNumVariableAction,
    AddNumRegisterAction,
    Expression,
    Register,
    GenericObject,
    StringConstant,
    InitRegisterAction,
    StoreRegisterAction,
    DefineFunction2Action,
    GotoFrame2Action,
    WithAction,
    GetURL2Action,
    StartDragAction,
    UNDEFINED,
    GLOBAL,
)
from .util import VerboseOutput


class ByteCode:
    # A list of bytecodes to execute.
    def __init__(self, name: Optional[str], actions: Sequence[AP2Action], end_offset: int) -> None:
        self.name = name
        self.actions = list(actions)
        self.start_offset = self.actions[0].offset if actions else None
        self.end_offset = end_offset

    def decompile(self, verbose: bool = False) -> str:
        decompiler = ByteCodeDecompiler(self)
        decompiler.decompile(verbose=verbose)
        code = decompiler.as_string(prefix="    " if self.name else "", verbose=verbose)
        if self.name:
            opar = '{'
            cpar = '}'
            code = f"{self.name}(){os.linesep}{opar}{os.linesep}{code}{os.linesep}{cpar}"
        return code

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if kwargs.get('decompile_bytecode', False):
            return {
                'code': self.decompile(verbose=kwargs.get('verbose', False)),
            }
        else:
            return {
                'actions': [a.as_dict(*args, **kwargs) for a in self.actions],
                'end_offset': self.end_offset,
            }

    def __repr__(self) -> str:
        entries: List[str] = []
        for action in self.actions:
            entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        return f"ByteCode({os.linesep}{os.linesep.join(entries)}{os.linesep}  {self.end_offset}: END{os.linesep})"


class ControlFlow:
    def __init__(self, beginning: int, end: int, next_flow: List[int]) -> None:
        self.beginning = beginning
        self.end = end
        self.next_flow = next_flow

    def contains(self, offset: int) -> bool:
        return (self.beginning <= offset) and (offset < self.end)

    def is_first(self, offset: int) -> bool:
        return self.beginning == offset

    def is_last(self, offset: int) -> bool:
        return self.end == (offset + 1)

    def split(self, offset: int, link: bool = False) -> Tuple["ControlFlow", "ControlFlow"]:
        if not self.contains(offset):
            raise Exception(f"Logic error, this ControlFlow does not contain offset {offset}")

        # First, make the second half that the first half will point to.
        second = ControlFlow(
            offset,
            self.end,
            self.next_flow,
        )

        # Now, make the first half that we can point to.
        first = ControlFlow(
            self.beginning,
            offset,
            [second.beginning] if link else [],
        )

        return (first, second)

    def __repr__(self) -> str:
        return f"ControlFlow(beginning={self.beginning}, end={self.end}, next={(', '.join(str(n) for n in self.next_flow)) or 'N/A'}"


class IfResult:
    def __init__(self, stmt_id: int, path: bool) -> None:
        self.stmt_id = stmt_id
        self.path = path

    def makes_tautology(self, other: "IfResult") -> bool:
        return self.stmt_id == other.stmt_id and self.path != other.path

    def __repr__(self) -> str:
        return f"IfResult(stmt_id={self.stmt_id}, path={self.path})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IfResult):
            return NotImplemented
        return self.stmt_id == other.stmt_id and self.path == other.path

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, IfResult):
            return NotImplemented
        return not (self.stmt_id == other.stmt_id and self.path == other.path)

    def __hash__(self) -> int:
        # Lower bit will be for true/false, upper bits for statement ID.
        return (self.stmt_id * 2) + (1 if self.path else 0)


class ConvertedAction:
    # An action that has been analyzed and converted to an intermediate representation.
    pass


class MultiAction(ConvertedAction):
    # An action that allows us to expand the number of lines we have to work with, for
    # opcodes that perform more than one statement's worth of actions.
    def __init__(self, actions: Sequence[ConvertedAction]) -> None:
        self.actions = actions

    def __repr__(self) -> str:
        # We should never emit one of these in printing.
        return f"MultiAction({self.actions})"


class Statement(ConvertedAction):
    # This is just a type class for finished statements.
    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement render()!")


def object_ref(obj: Any, parent_prefix: str, verbose: bool=False) -> str:
    if isinstance(obj, (GenericObject, Variable, TempVariable, Member, MethodCall, FunctionCall, Register)):
        return obj.render(parent_prefix, verbose=verbose, nested=True)
    else:
        raise Exception(f"Unsupported objectref {obj} ({type(obj)})")


def value_ref(param: Any, parent_prefix: str, verbose: bool=False, parens: bool = False) -> str:
    if isinstance(param, StringConstant):
        # Treat this as a string constant.
        return repr(param.render(parent_prefix, verbose=verbose))
    elif isinstance(param, Expression):
        return param.render(parent_prefix, verbose=verbose, nested=parens)
    elif isinstance(param, (str, int, float)):
        return repr(param)
    else:
        raise Exception(f"Unsupported valueref {param} ({type(param)})")


def name_ref(param: Any, parent_prefix: str, verbose: bool=False) -> str:
    # Reference a name, so strings should not be quoted.
    if isinstance(param, str):
        return param
    elif isinstance(param, StringConstant):
        return param.render(parent_prefix, verbose=verbose)
    else:
        raise Exception(f"Unsupported nameref {param} ({type(param)})")


ArbitraryOpcode = Union[AP2Action, ConvertedAction]


class DefineLabelStatement(Statement):
    def __init__(self, location: int) -> None:
        self.location = location

    def __repr__(self) -> str:
        return f"label_{self.location}:"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"label_{self.location}:"]


class BreakStatement(Statement):
    # A break from a loop (forces execution to the next line after the loop).
    def __repr__(self) -> str:
        return "break"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}break;"]


class ContinueStatement(Statement):
    # A continue in a loop (forces execution to the top of the loop).
    def __repr__(self) -> str:
        return "continue"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}continue;"]


class GotoStatement(Statement):
    # A goto, including the ID of the chunk we want to jump to.
    def __init__(self, location: int) -> None:
        if location < 0:
            raise Exception(f"Logic error, attempting to go to artificially inserted location {location}!")

        self.location = location

    def __repr__(self) -> str:
        return f"goto label_{self.location}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}goto label_{self.location};"]


class NullReturnStatement(Statement):
    # A statement which directs the control flow to the end of the code, but
    # does not pop the stack to return
    def __repr__(self) -> str:
        return "return"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}return;"]


class ReturnStatement(Statement):
    # A statement which directs the control flow to the end of the code,
    # returning the top of the stack.
    def __init__(self, ret: Any) -> None:
        self.ret = ret

    def __repr__(self) -> str:
        ret = value_ref(self.ret, "")
        return f"return {ret}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        ret = value_ref(self.ret, prefix, verbose=verbose)
        return [f"{prefix}return {ret};"]


class ThrowStatement(Statement):
    # A statement which raises an exception. It appears that there is no
    # 'catch' in this version of bytecode so it must be used only as an
    # assert.
    def __init__(self, exc: Any) -> None:
        self.exc = exc

    def __repr__(self) -> str:
        exc = value_ref(self.exc, "")
        return f"throw {exc}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        exc = value_ref(self.exc, prefix, verbose=verbose)
        return [f"{prefix}throw {exc};"]


class NopStatement(Statement):
    # A literal no-op. We will get rid of these in an optimizing pass.
    def __repr__(self) -> str:
        return "nop"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        # We should never render this!
        raise Exception("Logic error, a NopStatement should never make it to the render stage!")


class ExpressionStatement(Statement):
    # A statement which is an expression that discards its return.
    def __init__(self, expr: Expression) -> None:
        self.expr = expr

    def __repr__(self) -> str:
        return f"{self.expr.render('')}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}{self.expr.render(prefix, verbose=verbose)};"]


class StopSoundStatement(Statement):
    # Stop all sounds, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StopAllSounds()"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}builtin_StopAllSounds();"]


class StopMovieStatement(Statement):
    # Stop the movie, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StopPlaying()"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}builtin_StopPlaying();"]


class PlayMovieStatement(Statement):
    # Play the movie, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StartPlaying()"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}builtin_StartPlaying();"]


class NextFrameStatement(Statement):
    # Advance to the next frame, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_GotoNextFrame()"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}builtin_GotoNextFrame();"]


class PreviousFrameStatement(Statement):
    # Advance to the previous frame, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_GotoPreviousFrame()"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        return [f"{prefix}builtin_GotoPreviousFrame();"]


class DebugTraceStatement(Statement):
    # Print a debug trace if supported.
    def __init__(self, trace: Any) -> None:
        self.trace = trace

    def __repr__(self) -> str:
        trace = value_ref(self.trace, "")
        return f"builtin_DebugTrace({trace})"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        trace = value_ref(self.trace, prefix, verbose=verbose)
        return [f"{prefix}builtin_DebugTrace({trace});"]


class GotoFrameStatement(Statement):
    # Go to a specified frame in the animation.
    def __init__(self, frame: Any) -> None:
        self.frame = frame

    def __repr__(self) -> str:
        frame = value_ref(self.frame, "")
        return f"builtin_GotoFrame({frame})"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        frame = value_ref(self.frame, prefix, verbose=verbose)
        return [f"{prefix}builtin_GotoFrame({frame});"]


class CloneSpriteStatement(Statement):
    # Clone a sprite.
    def __init__(self, obj_to_clone: Any, name: Union[str, Expression], depth: Union[int, Expression]) -> None:
        self.obj_to_clone = obj_to_clone
        self.name = name
        self.depth = depth

    def __repr__(self) -> str:
        obj = object_ref(self.obj_to_clone, "")
        name = value_ref(self.name, "")
        depth = value_ref(self.depth, "")
        return f"builtin_CloneSprite({obj}, {name}, {depth})"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        obj = object_ref(self.obj_to_clone, prefix, verbose=verbose)
        name = value_ref(self.name, prefix, verbose=verbose)
        depth = value_ref(self.depth, prefix, verbose=verbose)
        return [f"{prefix}builtin_CloneSprite({obj}, {name}, {depth});"]


class RemoveSpriteStatement(Statement):
    # Clone a sprite.
    def __init__(self, obj_to_remove: Any) -> None:
        self.obj_to_remove = obj_to_remove

    def __repr__(self) -> str:
        obj = object_ref(self.obj_to_remove, "")
        return f"builtin_RemoveSprite({obj})"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        obj = object_ref(self.obj_to_remove, prefix, verbose=verbose)
        return [f"{prefix}builtin_RemoveSprite({obj});"]


class GetURL2Statement(Statement):
    # Load the URL given in the parameters, with any possible target.
    def __init__(self, action: int, url: Any, target: Any) -> None:
        self.action = action
        self.url = url
        self.target = target

    def __repr__(self) -> str:
        url = value_ref(self.url, "")
        target = value_ref(self.target, "")
        return f"builtin_GetURL2({self.action}, {url}, {target})"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        url = value_ref(self.url, prefix, verbose=verbose)
        target = value_ref(self.target, prefix, verbose=verbose)
        return [f"{prefix}builtin_GetURL2({self.action}, {url}, {target});"]


class MaybeStackEntry(Expression):
    def __init__(self, parent_stack_id: int) -> None:
        self.parent_stack_id = parent_stack_id

    def __repr__(self) -> str:
        return f"MaybeStackEntry({self.parent_stack_id})"

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        raise Exception("Logic error, a MaybeStackEntry should never make it to the render stage!")


class ArithmeticExpression(Expression):
    def __init__(self, left: Any, op: str, right: Any) -> None:
        self.left = left
        self.op = op
        self.right = right

    def __repr__(self) -> str:
        left = value_ref(self.left, "", parens=True)
        right = value_ref(self.right, "", parens=True)
        return f"{left} {self.op} {right}"

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        left = value_ref(self.left, parent_prefix, parens=True, verbose=verbose)
        right = value_ref(self.right, parent_prefix, parens=True, verbose=verbose)

        if nested and self.op == '-':
            return f"({left} {self.op} {right})"
        else:
            return f"{left} {self.op} {right}"


class NotExpression(Expression):
    def __init__(self, obj: Any) -> None:
        self.obj = obj

    def __repr__(self) -> str:
        obj = value_ref(self.obj, "", parens=True)
        return f"not {obj}"

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        obj = value_ref(self.obj, parent_prefix, parens=True, verbose=verbose)
        return f"not {obj}"


class Array(Expression):
    # Call a method on an object.
    def __init__(self, params: List[Any]) -> None:
        self.params = params

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        params = [value_ref(param, parent_prefix, verbose=verbose) for param in self.params]
        return f"[{', '.join(params)}]"


class Object(Expression):
    # Call a method on an object.
    def __init__(self, params: Dict[Any, Any]) -> None:
        self.params = params

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        params = [f"{value_ref(key, parent_prefix, verbose=verbose)}: {value_ref(val, parent_prefix, verbose=verbose)}" for (key, val) in self.params.items()]
        lpar = "{"
        rpar = "}"

        return f"{lpar}{', '.join(params)}{rpar}"


class FunctionCall(Expression):
    # Call a method on an object.
    def __init__(self, insertion_ref: int, name: Union[str, StringConstant], params: List[Any]) -> None:
        self.insertion_ref = insertion_ref
        self.name = name
        self.params = params

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        name = name_ref(self.name, parent_prefix, verbose=verbose)
        params = [value_ref(param, parent_prefix, verbose=verbose) for param in self.params]
        return f"{name}({', '.join(params)})"


class GetTimeFunctionCall(FunctionCall):
    # Call the built-in 'get time' method which returns the current playback position.
    def __init__(self, insertion_ref: int) -> None:
        super().__init__(insertion_ref, "builtin_GetCurrentPlaybackPosition", [])


class GetPathFunctionCall(FunctionCall):
    # Call the built-in 'get time' method which returns the current playback position.
    def __init__(self, insertion_ref: int, movieclip: Any) -> None:
        super().__init__(insertion_ref, "builtin_GetPathOfMovie", [movieclip])


class MethodCall(Expression):
    # Call a method on an object.
    def __init__(self, insertion_ref: int, objectref: Any, name: Union[str, int, Expression], params: List[Any]) -> None:
        self.insertion_ref = insertion_ref
        self.objectref = objectref
        self.name = name
        self.params = params

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        try:
            obj = object_ref(self.objectref, parent_prefix, verbose=verbose)
            name = name_ref(self.name, parent_prefix, verbose=verbose)
            params = [value_ref(param, parent_prefix, verbose=verbose) for param in self.params]
            return f"{obj}.{name}({', '.join(params)})"
        except Exception:
            obj = object_ref(self.objectref, parent_prefix, verbose=verbose)
            name = value_ref(self.name, parent_prefix, verbose=verbose)
            params = [value_ref(param, parent_prefix, verbose=verbose) for param in self.params]
            return f"{obj}[{name}]({', '.join(params)})"


class NewFunction(Expression):
    # Create a new function.
    def __init__(self, flags: int, body: ByteCode) -> None:
        self.flags = flags
        self.body = body

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        # This feels somewhat like a hack, but the bytecode inside the function definition
        # *is* independent of the bytecode in this function, except for the shared string table.
        decompiler = ByteCodeDecompiler(self.body)
        decompiler.decompile(verbose=verbose)
        code = decompiler.as_string(prefix=parent_prefix + "    ", verbose=verbose)

        opar = '{'
        cpar = '}'
        val = f"new Function({hex(self.flags)}, {opar}{os.linesep}{code}{os.linesep}{parent_prefix}{cpar})"
        if nested:
            return f"({val})"
        else:
            return val


class NewObject(Expression):
    # Create a new object of type.
    def __init__(self, objname: Union[str, StringConstant], params: List[Any]) -> None:
        self.objname = objname
        self.params = params

    def __repr__(self) -> str:
        return self.render('')

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        objname = name_ref(self.objname, parent_prefix, verbose=verbose)
        params = [value_ref(param, parent_prefix, verbose=verbose) for param in self.params]
        val = f"new {objname}({', '.join(params)})"
        if nested:
            return f"({val})"
        else:
            return val


class SetMemberStatement(Statement):
    # Call a method on an object.
    def __init__(self, objectref: Any, name: Union[str, int, Expression], valueref: Any) -> None:
        self.objectref = objectref
        self.name = name
        self.valueref = valueref

    def code_equiv(self) -> str:
        try:
            ref = object_ref(self.objectref, "")
            name = name_ref(self.name, "")
            return f"{ref}.{name}"
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, "")
            name = value_ref(self.name, "")
            return f"{ref}[{name}]"

    def __repr__(self) -> str:
        try:
            ref = object_ref(self.objectref, "")
            name = name_ref(self.name, "")
            val = value_ref(self.valueref, "")
            return f"{ref}.{name} = {val}"
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, "")
            name = value_ref(self.name, "")
            val = value_ref(self.valueref, "")
            return f"{ref}[{name}] = {val}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        try:
            ref = object_ref(self.objectref, prefix, verbose=verbose)
            name = name_ref(self.name, prefix, verbose=verbose)
            val = value_ref(self.valueref, prefix, verbose=verbose)
            return [f"{prefix}{ref}.{name} = {val};"]
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, prefix, verbose=verbose)
            name = value_ref(self.name, prefix, verbose=verbose)
            val = value_ref(self.valueref, prefix, verbose=verbose)
            return [f"{prefix}{ref}[{name}] = {val};"]


class DeleteVariableStatement(Statement):
    # Call a method on an object.
    def __init__(self, name: Union[str, StringConstant]) -> None:
        self.name = name

    def __repr__(self) -> str:
        name = name_ref(self.name, "")
        return f"del {name}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        name = name_ref(self.name, prefix, verbose=verbose)
        return [f"{prefix}del {name};"]


class DeleteMemberStatement(Statement):
    # Call a method on an object.
    def __init__(self, objectref: Any, name: Union[str, int, Expression]) -> None:
        self.objectref = objectref
        self.name = name

    def __repr__(self) -> str:
        try:
            ref = object_ref(self.objectref, "")
            name = name_ref(self.name, "")
            return f"del {ref}.{name}"
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, "")
            name = value_ref(self.name, "")
            return f"del {ref}[{name}]"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        try:
            ref = object_ref(self.objectref, prefix, verbose=verbose)
            name = name_ref(self.name, prefix, verbose=verbose)
            return [f"{prefix}del {ref}.{name};"]
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, prefix, verbose=verbose)
            name = value_ref(self.name, prefix, verbose=verbose)
            return [f"{prefix}del {ref}[{name}];"]


class StoreRegisterStatement(Statement):
    # Set a variable to a value.
    def __init__(self, register: Register, valueref: Any) -> None:
        self.register = register
        self.valueref = valueref

    def code_equiv(self) -> str:
        return self.register.render('')

    def __repr__(self) -> str:
        val = value_ref(self.valueref, "")
        return f"{self.register.render('')} = {val}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        val = value_ref(self.valueref, prefix, verbose=verbose)
        return [f"{prefix}{self.register.render(prefix, verbose=verbose)} = {val};"]


class SetVariableStatement(Statement):
    # Set a variable to a value.
    def __init__(self, name: Union[str, StringConstant], valueref: Any) -> None:
        self.name = name
        self.valueref = valueref

    def code_equiv(self) -> str:
        return name_ref(self.name, "")

    def __repr__(self) -> str:
        name = name_ref(self.name, "")
        val = value_ref(self.valueref, "")
        return f"{name} = {val}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        name = name_ref(self.name, prefix, verbose=verbose)
        val = value_ref(self.valueref, prefix, verbose=verbose)
        return [f"{prefix}{name} = {val};"]


class SetLocalStatement(Statement):
    # Define a local variable with a value.
    def __init__(self, name: Union[str, StringConstant], valueref: Any) -> None:
        self.name = name
        self.valueref = valueref

    def code_equiv(self) -> str:
        return name_ref(self.name, "")

    def __repr__(self) -> str:
        name = name_ref(self.name, "")
        val = value_ref(self.valueref, "")
        return f"local {name} = {val}"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        name = name_ref(self.name, prefix, verbose=verbose)
        val = value_ref(self.valueref, prefix, verbose=verbose)
        return [f"{prefix}local {name} = {val};"]


class IfExpr(ConvertedAction):
    # This is just for typing.
    def invert(self) -> "IfExpr":
        raise NotImplementedError("Not implemented!")

    def swap(self) -> "IfExpr":
        raise NotImplementedError("Not implemented!")


class IsUndefinedIf(IfExpr):
    def __init__(self, conditional: Any, negate: bool) -> None:
        self.conditional = conditional
        self.negate = negate

    def invert(self) -> "IsUndefinedIf":
        return IsUndefinedIf(self.conditional, not self.negate)

    def swap(self) -> "IsUndefinedIf":
        return IsUndefinedIf(self.conditional, self.negate)

    def __repr__(self) -> str:
        val = value_ref(self.conditional, "", parens=True)
        if self.negate:
            return f"{val} is not UNDEFINED"
        else:
            return f"{val} is UNDEFINED"


class IsBooleanIf(IfExpr):
    def __init__(self, conditional: Any, negate: bool) -> None:
        self.conditional = conditional
        self.negate = negate

    def invert(self) -> "IsBooleanIf":
        return IsBooleanIf(self.conditional, not self.negate)

    def swap(self) -> "IsBooleanIf":
        return IsBooleanIf(self.conditional, self.negate)

    def __repr__(self) -> str:
        val = value_ref(self.conditional, "", parens=True)
        if self.negate:
            return f"not {val}"
        else:
            return f"{val}"


class TwoParameterIf(IfExpr):
    EQUALS = "=="
    NOT_EQUALS = "!="
    LT = "<"
    GT = ">"
    LT_EQUALS = "<="
    GT_EQUALS = ">="
    STRICT_EQUALS = "==="
    STRICT_NOT_EQUALS = "!=="

    def __init__(self, conditional1: Any, comp: str, conditional2: Any) -> None:
        if comp not in {
            self.EQUALS,
            self.NOT_EQUALS,
            self.LT,
            self.GT,
            self.LT_EQUALS,
            self.GT_EQUALS,
            self.STRICT_EQUALS,
            self.STRICT_NOT_EQUALS,
        }:
            raise Exception(f"Invalid comparision {comp}!")

        self.conditional1 = conditional1
        self.comp = comp
        self.conditional2 = conditional2

    def invert(self) -> "TwoParameterIf":
        if self.comp == self.EQUALS:
            return TwoParameterIf(self.conditional1, self.NOT_EQUALS, self.conditional2)
        if self.comp == self.NOT_EQUALS:
            return TwoParameterIf(self.conditional1, self.EQUALS, self.conditional2)
        if self.comp == self.LT:
            return TwoParameterIf(self.conditional1, self.GT_EQUALS, self.conditional2)
        if self.comp == self.GT:
            return TwoParameterIf(self.conditional1, self.LT_EQUALS, self.conditional2)
        if self.comp == self.LT_EQUALS:
            return TwoParameterIf(self.conditional1, self.GT, self.conditional2)
        if self.comp == self.GT_EQUALS:
            return TwoParameterIf(self.conditional1, self.LT, self.conditional2)
        if self.comp == self.STRICT_EQUALS:
            return TwoParameterIf(self.conditional1, self.STRICT_NOT_EQUALS, self.conditional2)
        if self.comp == self.STRICT_NOT_EQUALS:
            return TwoParameterIf(self.conditional1, self.STRICT_EQUALS, self.conditional2)
        raise Exception(f"Cannot invert {self.comp}!")

    def swap(self) -> "TwoParameterIf":
        if self.comp == self.EQUALS:
            return TwoParameterIf(self.conditional2, self.EQUALS, self.conditional1)
        if self.comp == self.NOT_EQUALS:
            return TwoParameterIf(self.conditional2, self.NOT_EQUALS, self.conditional1)
        if self.comp == self.LT:
            return TwoParameterIf(self.conditional2, self.GT, self.conditional1)
        if self.comp == self.GT:
            return TwoParameterIf(self.conditional2, self.LT, self.conditional1)
        if self.comp == self.LT_EQUALS:
            return TwoParameterIf(self.conditional2, self.GT_EQUALS, self.conditional1)
        if self.comp == self.GT_EQUALS:
            return TwoParameterIf(self.conditional2, self.LT_EQUALS, self.conditional1)
        if self.comp == self.STRICT_EQUALS:
            return TwoParameterIf(self.conditional2, self.STRICT_EQUALS, self.conditional1)
        if self.comp == self.STRICT_NOT_EQUALS:
            return TwoParameterIf(self.conditional2, self.STRICT_NOT_EQUALS, self.conditional1)
        raise Exception(f"Cannot swap {self.comp}!")

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, "", parens=True)
        val2 = value_ref(self.conditional2, "", parens=True)
        return f"{val1} {self.comp} {val2}"


class IfStatement(Statement):
    def __init__(self, cond: IfExpr, true_statements: Sequence[Statement], false_statements: Sequence[Statement]) -> None:
        self.cond = cond
        self.true_statements = list(true_statements)
        self.false_statements = list(false_statements)

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for statement in self.true_statements:
            true_entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        false_entries: List[str] = []
        for statement in self.false_statements:
            false_entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        if false_entries:
            return os.linesep.join([
                f"if ({self.cond}) {{",
                os.linesep.join(true_entries),
                "} else {",
                os.linesep.join(false_entries),
                "}"
            ])
        else:
            return os.linesep.join([
                f"if ({self.cond}) {{",
                os.linesep.join(true_entries),
                "}"
            ])

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        true_entries: List[str] = []
        for statement in self.true_statements:
            true_entries.extend(statement.render(prefix=prefix + "    ", verbose=verbose))

        false_entries: List[str] = []
        for statement in self.false_statements:
            false_entries.extend(statement.render(prefix=prefix + "    ", verbose=verbose))

        if false_entries:
            return [
                f"{prefix}if ({self.cond})",
                f"{prefix}{{",
                *true_entries,
                f"{prefix}}}",
                f"{prefix}else",
                f"{prefix}{{",
                *false_entries,
                f"{prefix}}}"
            ]
        else:
            return [
                f"{prefix}if ({self.cond})",
                f"{prefix}{{",
                *true_entries,
                f"{prefix}}}"
            ]


class DoWhileStatement(Statement):
    def __init__(self, body: Sequence[Statement]) -> None:
        self.body = list(body)

    def __repr__(self) -> str:
        entries: List[str] = []
        for statement in self.body:
            entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        return os.linesep.join([
            "do {",
            os.linesep.join(entries),
            "} while (True)"
        ])

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    ", verbose=verbose))

        return [
            f"{prefix}do",
            f"{prefix}{{",
            *entries,
            f"{prefix}}}",
            f"{prefix}while (True);",
        ]


class ForStatement(DoWhileStatement):
    # Special case of a DoWhileStatement that tracks its own exit condition and increment.
    def __init__(self, inc_variable: str, inc_init: Any, cond: IfExpr, inc_assign: Any, body: Sequence[Statement], local: bool = False) -> None:
        super().__init__(body)
        self.inc_variable = inc_variable
        self.inc_init = inc_init
        self.cond = cond
        self.inc_assign = inc_assign
        self.local = local

    def __repr__(self) -> str:
        entries: List[str] = []
        for statement in self.body:
            entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        inc_init = value_ref(self.inc_init, "")
        inc_assign = value_ref(self.inc_assign, "")
        if self.local:
            local = "local "
        else:
            local = ""

        return os.linesep.join([
            f"for ({local}{self.inc_variable} = {inc_init}; {self.cond}; {self.inc_variable} = {inc_assign}) {{",
            os.linesep.join(entries),
            "}"
        ])

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    ", verbose=verbose))

        inc_init = value_ref(self.inc_init, prefix, verbose=verbose)
        inc_assign = value_ref(self.inc_assign, prefix, verbose=verbose)
        if self.local:
            local = "local "
        else:
            local = ""

        return [
            f"{prefix}for ({local}{self.inc_variable} = {inc_init}; {self.cond}; {self.inc_variable} = {inc_assign}) {{",
            f"{prefix}{{",
            *entries,
            f"{prefix}}}",
        ]


class WhileStatement(DoWhileStatement):
    # Special case of a DoWhileStatement that tracks its own exit condition.
    def __init__(self, cond: IfExpr, body: Sequence[Statement]) -> None:
        super().__init__(body)
        self.cond = cond

    def __repr__(self) -> str:
        entries: List[str] = []
        for statement in self.body:
            entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        return os.linesep.join([
            f"while ({self.cond}) {{",
            os.linesep.join(entries),
            "}"
        ])

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    ", verbose=verbose))

        return [
            f"{prefix}while ({self.cond}) {{",
            f"{prefix}{{",
            *entries,
            f"{prefix}}}",
        ]


class IntermediateIf(ConvertedAction):
    def __init__(self, parent_action: Union[IfAction, IfExpr], true_statements: Sequence[Statement], false_statements: Sequence[Statement]) -> None:
        self.parent_action = parent_action
        self.true_statements = list(true_statements)
        self.false_statements = list(false_statements)

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for action in self.true_statements:
            true_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        false_entries: List[str] = []
        for action in self.false_statements:
            false_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        if self.false_statements:
            return os.linesep.join([
                f"if <{self.parent_action}> {{",
                os.linesep.join(true_entries),
                "} else {",
                os.linesep.join(false_entries),
                "}"
            ])
        else:
            return os.linesep.join([
                f"if <{self.parent_action}> {{",
                os.linesep.join(true_entries),
                "}"
            ])


class ByteCodeChunk:
    def __init__(self, id: int, actions: Sequence[ArbitraryOpcode], next_chunks: List[int] = [], previous_chunks: List[int] = []) -> None:
        self.id = id
        self.actions = list(actions)
        self.next_chunks = next_chunks or []
        self.previous_chunks = previous_chunks or []

    def __repr__(self) -> str:
        entries: List[str] = []
        for action in self.actions:
            if isinstance(action, DefineFunction2Action):
                # Special case, since we will decompile this later, we don't want to print it now.
                entries.append(f"  {action.offset}: {AP2Action.action_to_name(action.opcode)}, Name: {action.name or '<anonymous function>'}, Flags: {hex(action.flags)}")
            else:
                entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        return (
            f"ByteCodeChunk({os.linesep}" +
            f"  ID: {self.id}{os.linesep}" +
            (f"  Previous Chunks: {', '.join(str(n) for n in self.previous_chunks)}{os.linesep}" if self.previous_chunks else f"  Start Chunk{os.linesep}") +
            f"{os.linesep.join(entries)}{os.linesep}" +
            (f"  Next Chunks: {', '.join(str(n) for n in self.next_chunks)}{os.linesep}" if self.next_chunks else f"  End Chunk{os.linesep}") +
            ")"
        )


ArbitraryCodeChunk = Union[ByteCodeChunk, "Loop", "IfBody"]


class Loop:
    def __init__(self, id: int, chunks: Sequence[ArbitraryCodeChunk]) -> None:
        # The ID is the chunk that other chunks point into, aka the loop header.
        self.id = id

        # Calculate predecessors (who points into it) and successors (who we point out of).
        ided_chunks: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}

        self.previous_chunks: List[int] = []
        self.next_chunks: List[int] = []
        self.chunks = list(chunks)
        self.post_statements: List[Statement] = []

        for chunk in chunks:
            for nextid in chunk.next_chunks:
                if nextid not in ided_chunks:
                    self.next_chunks.append(nextid)
            for previd in chunk.previous_chunks:
                if previd not in ided_chunks:
                    self.previous_chunks.append(previd)

    def __repr__(self) -> str:
        entries: List[str] = []
        for chunk in self.chunks:
            entries.extend([f"  {s}" for s in str(chunk).split(os.linesep)])

        return (
            f"Loop({os.linesep}" +
            f"  ID: {self.id}{os.linesep}" +
            (f"  Previous Chunks: {', '.join(str(n) for n in self.previous_chunks)}{os.linesep}" if self.previous_chunks else f"  Start Chunk{os.linesep}") +
            f"{os.linesep.join(entries)}{os.linesep}" +
            (f"  Next Chunks: {', '.join(str(n) for n in self.next_chunks)}{os.linesep}" if self.next_chunks else f"  End Chunk{os.linesep}") +
            ")"
        )


class IfBody:
    def __init__(self, id: int, true_chunks: Sequence[ArbitraryCodeChunk], false_chunks: Sequence[ArbitraryCodeChunk], next_chunk: Optional[int], previous_chunk: int) -> None:
        # The ID in this case is what the previous block points at. It does not
        # have any bearing on the ID of the true and false chunks.
        self.id = id

        # If bodies are a bit special compared to Loops, we know the previous and next chunks
        # for all of them.
        self.previous_chunks: List[int] = [previous_chunk]
        self.next_chunks: List[int] = [next_chunk] if next_chunk is not None else []
        self.true_chunks = list(true_chunks)
        self.false_chunks = list(false_chunks)

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for chunk in self.true_chunks:
            true_entries.extend([f"    {s}" for s in str(chunk).split(os.linesep)])

        false_entries: List[str] = []
        for chunk in self.false_chunks:
            false_entries.extend([f"    {s}" for s in str(chunk).split(os.linesep)])

        return (
            f"IfBody({os.linesep}" +
            f"  ID: {self.id}{os.linesep}" +
            (f"  Previous Chunks: {', '.join(str(n) for n in self.previous_chunks)}{os.linesep}" if self.previous_chunks else f"  Start Chunk{os.linesep}") +
            f"  True Chunks:{os.linesep}" +
            f"{os.linesep.join(true_entries)}{os.linesep}" +
            f"  False Chunks:{os.linesep}" +
            f"{os.linesep.join(false_entries)}{os.linesep}" +
            (f"  Next Chunks: {', '.join(str(n) for n in self.next_chunks)}{os.linesep}" if self.next_chunks else f"  End Chunk{os.linesep}") +
            ")"
        )


class Variable(Expression):
    def __init__(self, name: Union[str, StringConstant]) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"Variable({name_ref(self.name, '')})"

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        return name_ref(self.name, parent_prefix, verbose=verbose)


class TempVariable(Expression):
    # This is solely for recognizing when a stack which is being reconciled already has
    # a variable.
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"TempVariable({self.name})"

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        return self.name


class InsertionLocation(Statement):
    def __init__(self, location: int) -> None:
        self.location = location

    def __repr__(self) -> str:
        return f"<INSERTION POINT FOR {self.location}>"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        raise Exception("Logic error, an InsertionLocation should never make it to the render stage!")


class OriginalCallLocation(Statement):
    def __init__(self, insertion_id: int) -> None:
        self.insertion_id = insertion_id

    def __repr__(self) -> str:
        return f"<INSERTION POINT FOR {self.insertion_id}>"

    def render(self, prefix: str, verbose: bool = False) -> List[str]:
        raise Exception("Logic error, an InsertionLocation should never make it to the render stage!")


class Member(Expression):
    # A member can be an array entry in an array, or an object member as accessed
    # in array lookup syntax or dot notation.
    def __init__(self, objectref: Any, member: Union[str, int, Expression]) -> None:
        self.objectref = objectref
        self.member = member

    def __repr__(self) -> str:
        return self.render("")

    def render(self, parent_prefix: str, verbose: bool = False, nested: bool = False) -> str:
        try:
            member = name_ref(self.member, parent_prefix, verbose=verbose)
            ref = object_ref(self.objectref, parent_prefix, verbose=verbose)
            return f"{ref}.{member}"
        except Exception:
            # This is not a simple string object reference.
            member = value_ref(self.member, parent_prefix, verbose=verbose)
            ref = object_ref(self.objectref, parent_prefix, verbose=verbose)
            return f"{ref}[{member}]"


class BitVector:
    def __init__(self, length: int, init: bool = False) -> None:
        self.__bits: Dict[int, bool] = {i: init for i in range(length)}

    def clone(self) -> "BitVector":
        new = BitVector(len(self.__bits))
        new.__bits = {i: self.__bits[i] for i in self.__bits}
        return new

    def setAllBitsTo(self, val: bool) -> "BitVector":
        self.__bits = {i: val for i in self.__bits}
        return self

    def setBit(self, bit: int) -> "BitVector":
        if bit < 0 or bit >= len(self.__bits):
            raise Exception(f"Logic error, trying to set bit {bit} of a bitvector length {len(self.__bits)}!")
        self.__bits[bit] = True
        return self

    def clearBit(self, bit: int) -> "BitVector":
        if bit < 0 or bit >= len(self.__bits):
            raise Exception(f"Logic error, trying to set bit {bit} of a bitvector length {len(self.__bits)}!")
        self.__bits[bit] = False
        return self

    def orVector(self, other: "BitVector") -> "BitVector":
        if len(self.__bits) != len(other.__bits):
            raise Exception(f"Logic error, trying to combine bitvector of size {len(self.__bits)} with another of size {len(other.__bits)}!")
        self.__bits = {i: (self.__bits[i] or other.__bits[i]) for i in self.__bits}
        return self

    def andVector(self, other: "BitVector") -> "BitVector":
        if len(self.__bits) != len(other.__bits):
            raise Exception(f"Logic error, trying to combine bitvector of size {len(self.__bits)} with another of size {len(other.__bits)}!")
        self.__bits = {i: (self.__bits[i] and other.__bits[i]) for i in self.__bits}
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BitVector):
            return NotImplemented
        if len(self.__bits) != len(other.__bits):
            raise Exception(f"Logic error, trying to compare bitvector of size {len(self.__bits)} with another of size {len(other.__bits)}!")

        for i in self.__bits:
            if self.__bits[i] != other.__bits[i]:
                return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __len__(self) -> int:
        return len(self.__bits)

    @property
    def bitsSet(self) -> Set[int]:
        return {i for i in self.__bits if self.__bits[i]}


class ByteCodeDecompiler(VerboseOutput):
    def __init__(self, bytecode: ByteCode, optimize: bool = True) -> None:
        super().__init__()

        self.bytecode = bytecode
        self.optimize = optimize
        self.__statements: Optional[List[Statement]] = None
        self.__tmpvar_id: int = 0
        self.__goto_body_id: int = -1
        self.__insertion_id: int = 0

    @property
    def statements(self) -> List[Statement]:
        if self.__statements is None:
            raise Exception("Call decompile() first before retrieving statements!")
        return self.__statements

    def __graph_control_flow(self, bytecode: ByteCode) -> Tuple[List[ByteCodeChunk], Dict[int, int]]:
        # Start by assuming that the whole bytecode never directs flow. This is, confusingly,
        # indexed by AP2Action offset, not by actual bytecode offset, so we can avoid the
        # prickly problem of opcodes that take more than one byte in the data.
        flows: Dict[int, ControlFlow] = {}
        end = len(bytecode.actions)
        beginning = 0

        # The end of the program.
        flows[end] = ControlFlow(end, end + 1, [])

        # The rest of the program.
        flows[beginning] = ControlFlow(beginning, end, [end])

        # Function that helps us find a flow by position.
        def find(opcodeno: int) -> int:
            for start, cf in flows.items():
                if cf.contains(opcodeno):
                    return start

            raise Exception(f"Logic error, offset {opcodeno} somehow not in our control flow graph!")

        # Now, walk the entire bytecode, and every control flow point split the graph at that point.
        for i, action in enumerate(bytecode.actions):
            current_action = i
            next_action = i + 1

            if action.opcode in [AP2Action.THROW, AP2Action.RETURN, AP2Action.END]:
                # This should end execution, so we should cap off the current execution
                # and send it to the end.
                current_action_flow = find(current_action)
                next_action_flow = find(next_action)

                if current_action_flow == next_action_flow:
                    # We need to split this on the next_action boundary.
                    first, second = flows[current_action_flow].split(next_action)
                    first.next_flow = [end]

                    self.vprint(f"{action} action split {flows[current_action_flow]} into {first}, {second}")

                    flows[current_action_flow] = first
                    flows[next_action] = second

                else:
                    # This already was split in two, presumably by something
                    # earlier in the chain jumping to the opcode after this.
                    # We need to unlink the current flow from the second and
                    # link it to the end.
                    flows[current_action_flow].next_flow = [end]

                    self.vprint(f"{action} action repointed {flows[current_action_flow]} to end")
            elif action.opcode == AP2Action.JUMP:
                # Unconditional control flow redirection after this, we should split the
                # section if necessary and point this section at the new offset.
                # First, we need to find the jump point and make sure that its the start
                # of a section.
                action = cast(JumpAction, action)
                for j, dest in enumerate(bytecode.actions):
                    if dest.offset == action.jump_offset:
                        dest_action = j
                        break
                else:
                    if action.jump_offset == bytecode.end_offset:
                        dest_action = end
                    else:
                        raise Exception(f"{action} jumps to an opcode that doesn't exist!")

                # If the destination action flow already starts with the jump offset,
                # then we're good, we just need to point our current split at this new
                # offset. If it doesn't start with the jump offset, then we need to split
                # that flow so we can point to the opcode directly.
                dest_action_flow = find(dest_action)
                if not flows[dest_action_flow].is_first(dest_action):
                    first, second = flows[dest_action_flow].split(dest_action, link=True)

                    self.vprint(f"{action} action required split of {flows[dest_action_flow]} into {first, second}")

                    flows[dest_action_flow] = first
                    flows[dest_action] = second

                    # Now, the second is what we want to point at in the next section.
                    dest_action_flow = dest_action

                # Now, we must split the current flow at the point of this jump.
                current_action_flow = find(current_action)
                next_action_flow = find(next_action)

                if current_action_flow == next_action_flow:
                    # We need to split this on the next_action boundary.
                    first, second = flows[current_action_flow].split(next_action)
                    first.next_flow = [dest_action_flow]

                    self.vprint(f"{action} action split {flows[current_action_flow]} into {first}, {second}")

                    flows[current_action_flow] = first
                    flows[next_action] = second
                else:
                    # This already was split in two, presumably by something
                    # earlier in the chain jumping to the opcode after this.
                    # We need to unlink the current flow from the second and
                    # link it to the end.
                    flows[current_action_flow].next_flow = [dest_action_flow]

                    self.vprint(f"{action} action repointed {flows[current_action_flow]} to new chunk")
            elif action.opcode == AP2Action.IF:
                # Conditional control flow redirection after this, we should split the
                # section if necessary and point this section at the new offset as well
                # as the second half of the split section.
                # First, we need to find the jump point and make sure that its the start
                # of a section.
                action = cast(IfAction, action)
                for j, dest in enumerate(bytecode.actions):
                    if dest.offset == action.jump_if_true_offset:
                        dest_action = j
                        break
                else:
                    if action.jump_if_true_offset == bytecode.end_offset:
                        dest_action = end
                    else:
                        raise Exception(f"{action} conditionally jumps to an opcode that doesn't exist!")

                # If the destination action flow already starts with the jump offset,
                # then we're good, we just need to point our current split at this new
                # offset. If it doesn't start with the jump offset, then we need to split
                # that flow so we can point to the opcode directly.
                dest_action_flow = find(dest_action)
                if not flows[dest_action_flow].is_first(dest_action):
                    first, second = flows[dest_action_flow].split(dest_action, link=True)

                    self.vprint(f"{action} action required split of {flows[dest_action_flow]} into {first, second}")

                    flows[dest_action_flow] = first
                    flows[dest_action] = second

                    # Now, the second is what we want to point at in the next section.
                    dest_action_flow = dest_action

                # Now, we must split the current flow at the point of this jump.
                current_action_flow = find(current_action)
                next_action_flow = find(next_action)

                if current_action_flow == next_action_flow:
                    # We need to split this on the next_action boundary.
                    first, second = flows[current_action_flow].split(next_action)
                    first.next_flow = [next_action, dest_action_flow]

                    self.vprint(f"{action} action split {flows[current_action_flow]} into {first}, {second}")

                    flows[current_action_flow] = first
                    flows[next_action] = second
                else:
                    # This already was split in two, presumably by something
                    # earlier in the chain jumping to the opcode after this.
                    # We need to unlink the current flow from the second and
                    # link it to the end.
                    flows[current_action_flow].next_flow = [next_action, dest_action_flow]

                    self.vprint(f"{action} action repointed {flows[current_action_flow]} to new chunk")
            elif action.opcode == AP2Action.IF2:
                # We don't emit this anymore, so this is a problem.
                raise Exception("Logic error, unexpected AP2Action.IF2 opcode which we should not emit in parsing stage!")

        # Finally, return chunks of contiguous execution.
        chunks: List[ByteCodeChunk] = []
        for start, flow in flows.items():
            if start == end:
                # We don't want to render out the end of the graph, it was only there to make
                # the above algorithm easier. We'll add it back later after we fix up the
                # chunks based on start_offset, which the end chunk would not have on account
                # of containing zero instructions.
                continue

            next_chunks: List[int] = []
            for ano in flow.next_flow:
                if ano == end:
                    next_chunks.append(bytecode.end_offset)
                else:
                    next_chunks.append(bytecode.actions[ano].offset)
            chunks.append(ByteCodeChunk(bytecode.actions[flow.beginning].offset, bytecode.actions[flow.beginning:flow.end], next_chunks))

        # Calculate who points to us as well, for posterity. We can still use chunk.id as
        # the offset of the chunk since we haven't converted yet.
        entries: Dict[int, List[int]] = {}
        for chunk in chunks:
            # We haven't emitted any non-AP2Actions yet, so we are safe in casting here.
            for next_chunk in chunk.next_chunks:
                entries[next_chunk] = entries.get(next_chunk, []) + [chunk.id]

        for chunk in chunks:
            # We haven't emitted any non-AP2Actions yet, so we are safe in casting here.
            chunk.previous_chunks = entries.get(chunk.id, [])

        # Now, eliminate any dead code since it will trip us up later. Chunk ID is still the
        # offset of the first entry in the chunk since we haven't assigned IDs yet.
        while True:
            dead_chunk_ids = {c.id for c in chunks if not c.previous_chunks and c.id != bytecode.start_offset}
            if dead_chunk_ids:
                self.vprint(f"Elimitating dead code chunks {', '.join(str(d) for d in dead_chunk_ids)}")
                chunks = [c for c in chunks if c.id not in dead_chunk_ids]

                for chunk in chunks:
                    for c in chunk.next_chunks:
                        if c in dead_chunk_ids:
                            # Hoo this shouldn't be possible!
                            raise Exception(f"Logic error, chunk ID {chunk.id} points at a dead code chunk we're eliminating!")
                    chunk.previous_chunks = [c for c in chunk.previous_chunks if c not in dead_chunk_ids]
            else:
                break

        # Sort by start, so IDs make more sense.
        chunks = sorted(chunks, key=lambda c: c.id)

        # Now, calculate contiguous IDs for each remaining chunk.
        offset_to_id: Dict[int, int] = {}
        chunk_id: int = 0
        for chunk in chunks:
            # We haven't emitted any non-AP2Actions yet, so we are safe in casting here.
            offset_to_id[chunk.id] = chunk_id
            chunk.id = chunk_id

            chunk_id += 1

        end_chunk_id = chunk_id
        offset_to_id[bytecode.end_offset] = end_chunk_id

        # Now, convert the offsets to chunk ID pointers.
        end_previous_chunks: List[int] = []
        for chunk in chunks:
            if chunk.next_chunks:
                # Normal chunk.
                chunk.next_chunks = [offset_to_id[c] for c in chunk.next_chunks]
                if end_chunk_id in chunk.next_chunks:
                    end_previous_chunks.append(chunk.id)
            else:
                # Point this chunk at the end of bytecode sentinel.
                chunk.next_chunks = [end_chunk_id]
                end_previous_chunks.append(chunk.id)
            chunk.previous_chunks = [offset_to_id[c] for c in chunk.previous_chunks]

        # Add the "return" chunk now that we've converted everything.
        chunks.append(ByteCodeChunk(end_chunk_id, [], [], previous_chunks=end_previous_chunks))

        # Verify a few invariants about the tree we just created.
        num_start_chunks = 0
        num_end_chunks = 0
        for chunk in chunks:
            if not chunk.next_chunks:
                num_end_chunks += 1
            if not chunk.previous_chunks:
                if chunk.id != offset_to_id[bytecode.start_offset]:
                    raise Exception(f"Start of graph found at ID {chunk.id} but expected to be {offset_to_id[bytecode.start_offset]}!")
                num_start_chunks += 1

            if chunk.actions:
                # We haven't done any fixing up, we're guaranteed this is an AP2Action.
                last_action = cast(AP2Action, chunk.actions[-1])

                if last_action.opcode in [AP2Action.THROW, AP2Action.RETURN, AP2Action.JUMP, AP2Action.END] and len(chunk.next_chunks) != 1:
                    raise Exception(f"Chunk ID {chunk.id} has control flow action expecting one next chunk but has {len(chunk.next_chunks)}!")
                if len(chunk.next_chunks) == 2 and last_action.opcode != AP2Action.IF:
                    raise Exception(f"Chunk ID {chunk.id} has two next chunks but control flow action is not an if statement!")
                if len(chunk.next_chunks) > 2:
                    raise Exception(f"Chunk ID {chunk.id} has more than two next chunks!")

        # Num start chunks can be 0 (if the start chunk is a loop beginning) or 1 (if its a normal chunk).
        if num_start_chunks > 1:
            raise Exception(f"Found {num_start_chunks} start chunks but expecting at most 1!")
        # Num end chunks can only be 1 as we created an artificial end chunk.
        if num_end_chunks != 1:
            raise Exception(f"Found {num_end_chunks} end chunks but expecting exactly 1!")

        # Now that we're satisfied with the tree we created, return it.
        return (chunks, offset_to_id)

    def __get_entry_block(self, chunks: Sequence[ArbitraryCodeChunk]) -> int:
        start_id: Optional[int] = None
        for chunk in chunks:
            if not chunk.previous_chunks:
                if start_id is not None:
                    # This should never happen, we have one entrypoint. If we run into
                    # this we might need to do dead code analysis and discarding.
                    raise Exception("Logic error, more than one start block found!")
                start_id = chunk.id

        if start_id is None:
            # We should never get to this as we always have at least one entrypoint.
            raise Exception("Logic error, no start block found!")
        return start_id

    def __compute_dominators(self, start_id: int, chunks: Sequence[ByteCodeChunk]) -> Dict[int, Set[int]]:
        # Compute dominators recursively
        chunklen = len(chunks)
        dominators: Dict[int, BitVector] = {chunk.id: BitVector(chunklen, init=True) for chunk in chunks}
        dominators[start_id].setAllBitsTo(False).setBit(start_id)

        # Verify that the chunk IDs are contiguous. Otherwise this algorithm fails, since it
        # assigns an integer ID to each bit in a bitfield contiguously.
        for chunk in chunks:
            if chunk.id < 0 or chunk.id >= len(chunks):
                raise Exception("Chunk ID {chunk.id} is outside of our created BitVector, the ID space of chunks is non-contiguous!")

        changed = True
        while changed:
            changed = False

            for chunk in chunks:
                if chunk.id == start_id:
                    continue

                for previd in chunk.previous_chunks:
                    comparison = dominators[chunk.id].clone()
                    dominators[chunk.id].andVector(dominators[previd]).setBit(chunk.id)
                    if dominators[chunk.id] != comparison:
                        changed = True

        return {chunk.id: dominators[chunk.id].bitsSet for chunk in chunks}

    def __analyze_loop_jumps(self, loop: Loop, offset_map: Dict[int, int]) -> Loop:
        # Go through and try to determine which jumps are "break" and "continue" statements based on
        # where they point (to the header or to the exit point). First, let's try to identify all
        # exits, and which one is the break point and which ones are possibly goto statements
        # (break out of multiple loop depths).
        internal_jump_points = {c.id for c in loop.chunks}

        header_chunks = [c for c in loop.chunks if c.id == loop.id]
        if len(header_chunks) != 1:
            # Should never happen, only one should match ID.
            raise Exception("Logic error, didn't find the header chunk based on Loop ID!")
        header_chunk = header_chunks[0]

        # Identify external jumps from the header.
        break_points = [i for i in header_chunk.next_chunks if i not in internal_jump_points]
        if len(break_points) > 1:
            # We should not have two exits here, if so this isn't a loop!
            raise Exception("Logic error, loop has more than one next chunk to jump to on break!")
        if not break_points:
            # This might be possible, but I don't know how to deal with it.
            raise Exception("Logic error, loop has no chunk to jump to on break!")

        # Identify the break and continue jump points.
        break_point = break_points[0]
        continue_point = header_chunk.id

        self.vprint(f"Loop ID {loop.id} breaks to {break_point} and continues to {continue_point}")

        # Now, go through each chunk, identify whether it has an if, and fix up the
        # if statements.
        for chunk in loop.chunks:
            if not chunk.next_chunks:
                # All chunks need a next chunk of some type, the only one that doesn't
                # is the end chunk which should never be part of a loop.
                raise Exception(f"Logic error, chunk ID {chunk.id} has no successor and we haven't broken the graph yet!")
            if not isinstance(chunk, ByteCodeChunk):
                # We don't need to fix up loops, we already did this in a previous
                # fixup.
                continue

            last_action = chunk.actions[-1]
            if isinstance(last_action, AP2Action):
                if last_action.opcode == AP2Action.JUMP:
                    # This is either an unconditional break/continue or an
                    # internal jump.
                    if len(chunk.next_chunks) != 1:
                        raise Exception(f"Logic error, chunk ID {chunk.id} has jump control action but {len(chunk.next_chunks)} next chunks!")
                    next_chunk = chunk.next_chunks[0]

                    if next_chunk == break_point:
                        self.vprint("Converting jump to loop break into break statement.")
                        chunk.actions[-1] = BreakStatement()
                        chunk.next_chunks = []
                    elif next_chunk == continue_point:
                        self.vprint("Converting jump to loop continue into continue statement.")
                        chunk.actions[-1] = ContinueStatement()
                        chunk.next_chunks = []
                    elif next_chunk not in internal_jump_points:
                        if next_chunk == offset_map[self.bytecode.end_offset]:
                            self.vprint("Converting jump to external point into return statement.")
                            chunk.actions[-1] = NullReturnStatement()
                        else:
                            self.vprint("Converting jump to external point into goto statement.")
                            chunk.actions[-1] = GotoStatement(next_chunk)
                        chunk.next_chunks = []
                    continue

                if last_action.opcode == AP2Action.IF:
                    # Calculate true and false jump points.
                    true_jump_point, false_jump_point = self.__get_jump_points(chunk, offset_map)
                    end_offset = offset_map[self.bytecode.end_offset]

                    # Calculate true and false jump points, see if they are break/continue/goto.
                    # Its possible for the true and false jump points to be equal if this is an
                    # if statement which jumps to the next line of code in the true case. The below
                    # code will still work (it will change both the true and false points to a break,
                    # continue or return statement).
                    true_action: Optional[Statement] = None
                    if true_jump_point == break_point:
                        self.vprint("Converting jump if true to loop break into break statement.")
                        true_action = BreakStatement()
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != true_jump_point]
                    elif true_jump_point == continue_point:
                        self.vprint("Converting jump if true to loop continue into continue statement.")
                        true_action = ContinueStatement()
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != true_jump_point]
                    elif true_jump_point not in internal_jump_points:
                        if true_jump_point == end_offset:
                            self.vprint("Converting jump if true to external point into return statement.")
                            true_action = NullReturnStatement()
                        else:
                            self.vprint("Converting jump if true to external point into goto statement.")
                            true_action = GotoStatement(true_jump_point)
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != true_jump_point]

                    false_action: Optional[Statement] = None
                    if false_jump_point == break_point:
                        self.vprint("Converting jump if false to loop break into break statement.")
                        false_action = BreakStatement()
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != false_jump_point]
                    elif false_jump_point == continue_point:
                        self.vprint("Converting jump if false to loop continue into continue statement.")
                        false_action = ContinueStatement()
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != false_jump_point]
                    elif false_jump_point not in internal_jump_points:
                        if false_jump_point == end_offset:
                            self.vprint("Converting jump if false to external point into return statement.")
                            false_action = NullReturnStatement()
                        else:
                            self.vprint("Converting jump if false to external point into goto statement.")
                            false_action = GotoStatement(false_jump_point)
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != false_jump_point]

                    if true_action is None and false_action is None:
                        # This is an internal-only if statement, we don't care. We will handle it in
                        # a later if logic step.
                        continue

                    chunk.actions[-1] = IntermediateIf(
                        cast(IfAction, last_action),
                        [true_action],
                        [false_action] if false_action else [],
                    )

                if last_action.opcode in [AP2Action.RETURN, AP2Action.THROW, AP2Action.END]:
                    if len(chunk.next_chunks) != 1:
                        raise Exception(f"Logic error, chunkd ID {chunk.id} returns, throws or end to multiple blocks!")
                    if chunk.next_chunks[0] != offset_map[self.bytecode.end_offset]:
                        raise Exception(f"Expected chunk ID {chunk.id} to jump to return block but jumped elsewhere!")
                    # We will convert this later.
                    self.vprint("Severing link to return address.")
                    chunk.next_chunks = []

        # At this point, all chunks in our list should point only to other chunks in our list.
        for chunk in loop.chunks:
            for n in chunk.next_chunks:
                if n not in internal_jump_points:
                    raise Exception(f"Found unconverted next chunk {n} in chunk ID {chunk.id}, for loop ID {loop.id} with break point {break_point}!")
            if isinstance(chunk, ByteCodeChunk):
                last_action = chunk.actions[-1]
                if isinstance(last_action, AP2Action):
                    if last_action.opcode == AP2Action.IF and len(chunk.next_chunks) != 2:
                        raise Exception(f"Somehow messed up the next pointers on if statement in chunk ID {chunk.id}!")
                    if last_action.opcode == AP2Action.JUMP and len(chunk.next_chunks) != 1:
                        raise Exception(f"Somehow messed up the next pointers on control flow statement in chunk ID {chunk.id}!")
                    if last_action.opcode in [AP2Action.RETURN, AP2Action.THROW, AP2Action.END] and len(chunk.next_chunks) != 0:
                        raise Exception(f"Somehow messed up the next pointers on control flow statement in chunk ID {chunk.id}!")
                else:
                    if len(chunk.next_chunks) > 1:
                        raise Exception(f"Somehow messed up the next pointers on converted statement in chunk ID {chunk.id}!")

        # Now, we have converted all external jumps to either break or goto, so we don't
        # need to keep track of the next chunk aside from the break location. We know this
        # is the correct location to break form in normal circumstances because we verified
        # it above.
        loop.next_chunks = [break_point]

        return loop

    def __separate_loops(
        self,
        start_id: int,
        chunks: Sequence[ByteCodeChunk],
        dominators: Dict[int, Set[int]],
        offset_map: Dict[int, int],
    ) -> List[Union[ByteCodeChunk, Loop]]:
        chunks_by_id: Dict[int, Union[ByteCodeChunk, Loop]] = {chunk.id: chunk for chunk in chunks}

        # Go through and gather up all loops in the chunks.
        loops: Dict[int, Set[int]] = {}
        for chunk in chunks:
            for nextid in chunk.next_chunks:
                # If this next chunk dominates us, then that means we found a loop.
                if nextid in dominators[chunk.id]:
                    # Calculate the blocks that are in this loop.
                    header = nextid
                    tail = chunk.id
                    blocks = {header}

                    # If we don't already have a loop of one block,
                    # we need to walk backwards to find all blocks in this
                    # loop.
                    if header != tail:
                        blocks.add(tail)
                        blocks_to_examine = [tail]

                        while blocks_to_examine:
                            block = blocks_to_examine.pop()
                            for predecessor in chunks_by_id[block].previous_chunks:
                                if predecessor not in blocks:
                                    blocks.add(predecessor)
                                    blocks_to_examine.append(predecessor)

                    self.vprint(f"Found loop with header {header} and blocks {', '.join(str(b) for b in blocks)}.")

                    # Now, make sure we scoop up any remaining if/else bodies not found in the backwards walk.
                    changed: bool = True
                    while changed:
                        changed = False

                        for b in blocks:
                            # Explicitly exclude the header here, as it will only point at the break
                            # location which will usually pass the following dominator test.
                            if b == header:
                                continue
                            add_id: Optional[int] = None
                            for cid, doms in dominators.items():
                                if dominators[b] == doms - {cid} and cid not in blocks and cid != header:
                                    add_id = cid
                                    break
                            if add_id is not None:
                                self.vprint(f"Chunk {cid} should be included in loop list!")
                                blocks.add(add_id)
                                changed = True
                                break

                    # We found a loop!
                    if header in loops:
                        raise Exception(f"Logic error, loop with header {header} was already found!")
                    loops[header] = blocks

        # Now, we need to reduce our list of chunks down to non-loops only. We do this
        # by recursively trying to find inner loops until we find a loop that has no
        # inner loops, and converting that. Once we do that, we remove the chunks from
        # our list, add it to that new loop, and convert all other loops that might
        # reference it to point at the loop instead.
        deleted_chunks: Set[int] = set()
        while loops:
            delete_header: Optional[int] = None
            delete_blocks: Set[int] = set()
            for header, blocks in loops.items():
                # See if any of the blocks in this loop are the header of any other loop.
                for block in blocks:
                    if block in loops and loops[block] is not blocks:
                        # This particular block of code is the header of another loop,
                        # so we shouldn't convert this loop until we handle the inner
                        # loop.
                        self.vprint(f"Skipping loop with header {header} for now because it contains another unconverted loop with header {block}.")
                        break
                else:
                    # This loop does not contain any loops of its own. It is safe to
                    # convert.
                    self.vprint(f"Converting loop with header {header} and blocks {', '.join(str(b) for b in blocks)}.")
                    new_loop = Loop(header, [chunks_by_id[i] for i in blocks])

                    # Eliminate jumps that are to the beginning/end of the loop to
                    # make if statement detection later on easier. This also breaks
                    # the graph at any spot where we successfully converted a jump
                    # to a break/continue/goto.
                    new_loop = self.__analyze_loop_jumps(new_loop, offset_map)
                    if len(new_loop.next_chunks) != 1:
                        raise Exception(f"Newly created loop ID {new_loop.id} has more than one exit point!")
                    chunks_by_id[header] = new_loop

                    # These blocks are now part of the loop, so we need to remove them
                    # from the IDed chunks as well as from existing loops.
                    delete_blocks = {block for block in blocks if block != header}
                    delete_header = header
                    break

            if delete_header is None:
                # We must find at LEAST one loop that has no inner loops of its own.
                raise Exception("Logic error, we found no fixable loops, yet have at least one loop to fix up!")

            # Remove this loop from the processing list
            del loops[delete_header]

            # Go through and remove the rest of the chunks from the rest of the loops
            loops = {header: {block for block in blocks if block not in delete_blocks} for (header, blocks) in loops.items()}

            # Also remove the rest of the chunks from our IDed chunks as they are part of this loop now.
            for block in delete_blocks:
                del chunks_by_id[block]

            # Verify that we don't have any existing chunks that point at the non-header portion of the loop.
            for chunk_id, chunk_or_loop in chunks_by_id.items():
                for nextid in chunk_or_loop.next_chunks:
                    if nextid in delete_blocks:
                        # Woah, we point at a chunk inside this loop that isn't the header!
                        raise Exception(f"Logic error, chunkd ID {chunk_id} points into loop ID {delete_header} body!")

            # Update our master list of chunks we deleted.
            deleted_chunks.update(delete_blocks)

        # Finally, construct our new list of chunks and verify that we didn't accidentally keep any that we shouldn't have.
        updated_chunks = [chunks_by_id[i] for i in chunks_by_id]
        for new_chunk in updated_chunks:
            if new_chunk.id in deleted_chunks:
                raise Exception(f"Chunk ID {new_chunk.id} in list of chunks we converted but we expected it to be deleted!")
        return updated_chunks

    def __get_jump_points(self, chunk: ByteCodeChunk, offset_map: Dict[int, int]) -> Tuple[int, int]:
        action = chunk.actions[-1]

        if isinstance(action, IfAction):
            true_jump_point = offset_map[action.jump_if_true_offset]
            false_jump_points = [n for n in chunk.next_chunks if n != true_jump_point]
            if len(false_jump_points) != 1:
                if chunk.next_chunks[0] != chunk.next_chunks[1]:
                    raise Exception(f"Logic error, got more than one false jump point for if statement in chunk {chunk.id}")
                else:
                    false_jump_point = true_jump_point
            else:
                false_jump_point = false_jump_points[0]

            return true_jump_point, false_jump_point
        else:
            raise Exception(f"Logic error, expecting JumpAction but got {action} in chunk {chunk.id}!")

    def __break_graph(self, chunks: Sequence[Union[ByteCodeChunk, Loop]], offset_map: Dict[int, int]) -> None:
        for chunk in chunks:
            if chunk.id == offset_map[self.bytecode.end_offset]:
                # Don't examine the sentinel we keep around as a jump point for returns.
                continue

            if isinstance(chunk, Loop):
                self.vprint(f"Entering into loop {chunk.id} to break graph...")

                # At this point, we know chunk.chunks is a Union[ByteCodeChunk, Loop] because we haven't run
                # any if detection yet.
                self.__break_graph(cast(List[Union[ByteCodeChunk, Loop]], chunk.chunks), offset_map)
            else:
                # Examine the last instruction.
                last_action = chunk.actions[-1]
                if isinstance(last_action, AP2Action):
                    if last_action.opcode in [AP2Action.THROW, AP2Action.RETURN, AP2Action.END]:
                        # The last action already dictates what we should do here. Break
                        # the chain at this point.
                        self.vprint(f"Breaking chain on {chunk.id} because it is a {last_action}.")
                        chunk.next_chunks = []
                    elif len(chunk.next_chunks) == 1 and chunk.next_chunks[0] == offset_map[self.bytecode.end_offset]:
                        # The jump point for this is the end of the function. If it is a jump,
                        # then we should replace it with a return. If it is not a jump, we should
                        # add a return.
                        if last_action.opcode == AP2Action.JUMP:
                            self.vprint(f"Converting jump to end of code in {chunk.id} into a null return.")
                            chunk.actions[-1] = NullReturnStatement()
                        else:
                            if last_action.opcode == AP2Action.IF:
                                raise Exception(f"Logic error, unexpected if statement with only one successor in {chunk.id}!")
                            self.vprint(f"Converting fall-through to end of code in {chunk.id} into a null return.")
                            chunk.actions.append(NullReturnStatement())
                        chunk.next_chunks = []
                    elif len(chunk.next_chunks) == 2:
                        if last_action.opcode != AP2Action.IF:
                            raise Exception(f"Logic error, expected if statement with two successors in {chunk.id}!")

                        # This is an if statement, let's see if any of the arms point to a return.
                        true_jump_point, false_jump_point = self.__get_jump_points(chunk, offset_map)
                        end_offset = offset_map[self.bytecode.end_offset]

                        # It's possible for the true and false jump point to be equal, if the code being
                        # decompiled has not been optimized. The below code will produce the correct
                        # result for this case (true and false cases both containing the same return).
                        true_action: Optional[Statement] = None
                        if true_jump_point == end_offset:
                            self.vprint(f"Converting jump if true to external point into return statement in {chunk.id}.")
                            true_action = NullReturnStatement()
                            chunk.next_chunks = [c for c in chunk.next_chunks if c != true_jump_point]

                        false_action: Optional[Statement] = None
                        if false_jump_point == end_offset:
                            self.vprint(f"Converting jump if false to external point into return statement in {chunk.id}.")
                            false_action = NullReturnStatement()
                            chunk.next_chunks = [c for c in chunk.next_chunks if c != false_jump_point]

                        if true_action or false_action:
                            chunk.actions[-1] = IntermediateIf(
                                cast(IfAction, last_action),
                                [true_action],
                                [false_action] if false_action else [],
                            )

    def __find_shallowest_successor(self, start_chunk: int, chunks_by_id: Dict[int, ArbitraryCodeChunk]) -> Optional[int]:
        if len(chunks_by_id[start_chunk].next_chunks) != 2:
            # We don't care about this, the successor is the next chunk!
            raise Exception("Logic error!")

        left, right = chunks_by_id[start_chunk].next_chunks
        visited: Set[int] = set()

        # First, let's find all the successors to the left side.
        candidates: List[int] = [left] if left in chunks_by_id else []
        while candidates:
            for candidate in candidates:
                visited.add(candidate)

            new_candidates = []
            for candidate in candidates:
                # We can avoid re-traversing what we've already traversed, as we only want to color
                # in the part of the tree that we're interested in. We are also not interested in
                # goto/return/throw statements as they should be treated the same as not finding an
                # end.
                new_candidates.extend([c for c in chunks_by_id[candidate].next_chunks if c not in visited and c in chunks_by_id])
            candidates = new_candidates

        # Now, lets do the same with the right, and the first one we encounter that's visited is our guy.
        candidates = [right] if right in chunks_by_id else []
        while candidates:
            possible_candidates = {c for c in candidates if c in visited}
            if len(possible_candidates) == 1:
                return possible_candidates.pop()
            if len(possible_candidates) > 1:
                # This shouldn't be possible, I don't think? Let's enforce it as an invariant because I don't know what it means if this happens.
                raise Exception(f"Logic error, found too many candidates {possible_candidates} as shallowest successor to {start_chunk}!")

            new_candidates = []
            for candidate in candidates:
                # We can't take the same shortcut here as above, as we are trying to ask the question
                # of what's the shallowest successor, not color them in.
                new_candidates.extend([c for c in chunks_by_id[candidate].next_chunks if c in chunks_by_id])
            candidates = new_candidates

        # If we didn't find a successor, that means one of the control paths leads to end of execution.
        return None

    def __gather_chunks(self, start_chunk: int, end_chunk: Optional[int], chunks_by_id: Dict[int, ArbitraryCodeChunk]) -> List[ArbitraryCodeChunk]:
        # Gather all chunks starting with the start_chunk, walking the tree until we hit
        # end_chunk. Return all chunks in that walk up to but not including the end_chunk.
        # If end_chunk is None, then just walk the tree until we hit the end, including all
        # of those nodes. Note that if some chunks point at ndes we don't have in our
        # chunks_by_id map, we assume they are goto/return/throw statements and ignore them.

        visited: Set[int] = set()
        chunks: List[ArbitraryCodeChunk] = []
        candidates: List[int] = [start_chunk]

        while candidates:
            first_candidate = candidates.pop()
            if first_candidate in visited or first_candidate not in chunks_by_id:
                # We already visited this node, no need to include it or its children
                # twice, or the node isn't in our list of nodes to gather (its a goto/
                # return/throw) and we don't care to try to grab it.
                continue

            if end_chunk is None or first_candidate != end_chunk:
                chunks.append(chunks_by_id[first_candidate])
                visited.add(first_candidate)
                candidates.extend(chunks_by_id[first_candidate].next_chunks)

        # The chunk list is all chunks that belong in this sequence. Now, kill any pointers to the end chunk.
        for chunk in chunks:
            if chunk.id == start_chunk:
                # This is safe to do because we've already encapsulated loops into Loop structures and broken
                # their chains. So we break this in order to find it again as the start chunk later.
                chunk.previous_chunks = []

        # Make sure we have one and only one start chunk.
        num_start_chunks: int = 0
        for chunk in chunks:
            if not chunk.previous_chunks:
                num_start_chunks += 1
        if chunks and num_start_chunks != 1:
            # We're allowed to gather zero chunks (say an if with no else), but if we gather at least one
            # chunk, we should better have one and only one start to the flow.
            raise Exception(f"Logic error, splitting chunks by start chunk {start_chunk} should leave us with one start, but we got {num_start_chunks}!")

        return chunks

    def __separate_ifs(self, start_id: int, end_id: Optional[int], chunks: Sequence[ArbitraryCodeChunk], offset_map: Dict[int, int]) -> List[ArbitraryCodeChunk]:
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        cur_id = start_id

        self.vprint(f"Separating if statements out of graph starting at {start_id}")

        while True:
            cur_chunk = chunks_by_id[cur_id]
            if isinstance(cur_chunk, Loop):
                self.vprint(f"Examining loop {cur_chunk.id} body for if statements...")
                cur_chunk.chunks = self.__separate_ifs(cur_chunk.id, None, cur_chunk.chunks, offset_map)
                self.vprint(f"Finished examining loop {cur_chunk.id} body for if statements...")

            # Filter out anything pointing at the end chunk, since we know that's where we will end up
            # when we leave this if statement anyway. Don't do this for if statements as we need to
            # preserve the jump point in that case.
            if len(chunks_by_id[cur_id].next_chunks) == 1:
                chunks_by_id[cur_id].next_chunks = [c for c in chunks_by_id[cur_id].next_chunks if c != end_id]

            if not chunks_by_id[cur_id].next_chunks:
                # We're done!
                break

            if len(chunks_by_id[cur_id].next_chunks) == 1:
                if not isinstance(cur_chunk, ByteCodeChunk):
                    # This is an already-handled loop or if, don't bother checking for
                    # if-goto patterns.
                    next_id = chunks_by_id[cur_id].next_chunks[0]
                    if next_id not in chunks_by_id:
                        # We need to go to the next chunk, but we don't own it. Convert it to a goto.
                        if isinstance(cur_chunk, Loop):
                            self.vprint(f"Loop ID {cur_id} needs a goto outside of this if.")
                            cur_chunk.post_statements.append(GotoStatement(next_id))
                            chunks_by_id[cur_id].next_chunks = []
                            break
                        else:
                            raise Exception(f"Logic error, we can't jump to chunk {next_id} for if {cur_id} as it is outside of our scope!")

                    cur_id = next_id
                    continue

                last_action = cur_chunk.actions[-1]
                if isinstance(last_action, IfAction):
                    raise Exception(f"Logic error, IfAction with only one child in chunk {cur_chunk}!")

                next_id = chunks_by_id[cur_id].next_chunks[0]
                if isinstance(last_action, AP2Action) and last_action.opcode in [AP2Action.THROW, AP2Action.RETURN, AP2Action.END, AP2Action.JUMP]:
                    if next_id not in chunks_by_id:
                        # This is just a goto/chunk, move on to the next one.
                        self.vprint(f"Chunk ID {cur_id} is a goto outside of this if.")
                        chunks_by_id[cur_id].next_chunks = []
                        break

                else:
                    if next_id not in chunks_by_id:
                        # We need to go to the next chunk, but we don't own it. Convert it to a goto.
                        self.vprint(f"Chunk ID {cur_id} needs a goto outside of this if.")
                        cur_chunk.actions.append(GotoStatement(next_id))
                        chunks_by_id[cur_id].next_chunks = []
                        break

                cur_id = next_id
                continue

            if not isinstance(cur_chunk, ByteCodeChunk):
                # We should only be looking at bytecode chunks at this point, all other
                # types should have a single next chunk.
                raise Exception(f"Logic error, found converted Loop or If chunk {cur_chunk.id} with multiple successors!")

            if len(chunks_by_id[cur_id].next_chunks) != 2:
                # This needs to be an if statement.
                raise Exception(f"Logic error, expected 2 successors but got {len(chunks_by_id[cur_id].next_chunks)} in chunk {cur_chunk.id}!")
            last_action = cur_chunk.actions[-1]
            if not isinstance(last_action, IfAction):
                # This needs, again, to be an if statement.
                raise Exception("Logic error, only IfActions can have multiple successors in chunk {cur_chunk.id}!")

            # This should be an if statement. Figure out if it is an if-else or an
            # if, and if both branches return.
            if_end = self.__find_shallowest_successor(cur_id, chunks_by_id)
            true_jump_point, false_jump_point = self.__get_jump_points(cur_chunk, offset_map)
            if true_jump_point == false_jump_point:
                # This is an optimized-away if statement, render it out as an empty intermediate If
                # and set the jump point to the next location.
                self.vprint(f"Chunk ID {cur_id} is an empty if statement")
                chunks_by_id[cur_id].next_chunks = [true_jump_point]
                cur_chunk.actions[-1] = IntermediateIf(
                    last_action,
                    [],
                    [],
                )

                next_id = chunks_by_id[cur_id].next_chunks[0]
                if next_id not in chunks_by_id:
                    # We need to go to the next chunk, but we don't own it. Convert it to a goto.
                    self.vprint(f"Chunk ID {cur_id} needs a goto after empty if.")
                    cur_chunk.actions.append(GotoStatement(next_id))
                    chunks_by_id[cur_id].next_chunks = []
                    break

                cur_id = next_id
                continue

            self.vprint(f"Chunk ID {cur_id} is an if statement with true node {true_jump_point} and false node {false_jump_point} and ending at {if_end}")

            true_chunks: List[ArbitraryCodeChunk] = []
            if true_jump_point not in chunks_by_id and true_jump_point != if_end:
                self.vprint(f"If statement true jump point {true_jump_point} is a goto!")
                true_chunks.append(ByteCodeChunk(self.__goto_body_id, [GotoStatement(true_jump_point)]))
                self.__goto_body_id -= 1
            elif true_jump_point not in {if_end, end_id}:
                self.vprint(f"Gathering true path starting with {true_jump_point} and ending with {if_end} and detecting if statements within it as well.")

                # First, grab all the chunks in this if statement body.
                true_chunks = self.__gather_chunks(true_jump_point, if_end, chunks_by_id)
                self.vprint(f"True chunks are {', '.join(str(c.id) for c in true_chunks)}")

                # Delete these chunks from our chunk mapping since we're putting them in an if body.
                for chunk in true_chunks:
                    del chunks_by_id[chunk.id]

                # Now, recursively attempt to detect if statements within this chunk as well.
                true_chunks = self.__separate_ifs(true_jump_point, if_end if if_end is not None else end_id, true_chunks, offset_map)

            false_chunks: List[ArbitraryCodeChunk] = []
            if false_jump_point not in chunks_by_id and false_jump_point != if_end:
                self.vprint(f"If statement false jump point {false_jump_point} is a goto!")
                false_chunks.append(ByteCodeChunk(self.__goto_body_id, [GotoStatement(false_jump_point)]))
                self.__goto_body_id -= 1
            elif false_jump_point not in {if_end, end_id}:
                self.vprint(f"Gathering false path starting with {false_jump_point} and ending with {if_end} and detecting if statements within it as well.")

                # First, grab all the chunks in this if statement body.
                false_chunks = self.__gather_chunks(false_jump_point, if_end, chunks_by_id)
                self.vprint(f"False chunks are {', '.join(str(c.id) for c in false_chunks)}")

                # Delete these chunks from our chunk mapping since we're putting them in an if body.
                for chunk in false_chunks:
                    del chunks_by_id[chunk.id]

                # Now, recursively attempt to detect if statements within this chunk as well.
                false_chunks = self.__separate_ifs(false_jump_point, if_end if if_end is not None else end_id, false_chunks, offset_map)

            if (not true_chunks) and (not false_chunks):
                # We should have at least one!
                raise Exception("Logic error, if statement has no code for if or else!")

            # Lets use a brand new ID here for easier traversal and so we don't accidentally
            # reuse the ID of one of our parents if a jump point is a goto.
            if_id = self.__goto_body_id
            self.__goto_body_id -= 1

            # Add a new if body that this current chunk points to. At this point, chunks_by_id contains
            # none of the chunks in the true or false bodies of the if, so we add it back to the graph
            # in the form of an IfBody.
            self.vprint(f"Created new IfBody for chunk {cur_id} to point at, ending at {if_id}")
            chunks_by_id[if_id] = IfBody(if_id, true_chunks, false_chunks, if_end, cur_id)
            chunks_by_id[cur_id].next_chunks = [if_id]

            if if_end is not None:
                # Skip over the if, we already analyzed it.
                cur_id = if_end
            else:
                # This if statement encompases all the rest of the statements, we're done.
                break

        self.vprint(f"Finished separating if statements out of graph starting at {start_id}")
        return [c for _, c in chunks_by_id.items()]

    def __new_separate_ifs(self, start_id: int, end_id: Optional[int], chunks: Sequence[ArbitraryCodeChunk], offset_map: Dict[int, int]) -> List[ArbitraryCodeChunk]:
        # TODO: This algorithm can possibly do better than the original at identifying cases.
        # In particular, it handles compound if statements (if x or y) where the previous one
        # ends up sticking gotos in. The problem is that it needs to know what if statements
        # exist before combining them, and we can't do that until we walk the stack, and the
        # stack walking algorithm both a) comes later and b) relies on all ifs being processed.
        # So, this stays as a beta for now, and will possibly be integrated at a later time.
        # If we want to use this, we should probably reformat it to work on the finished
        # statement list we get after fully rendering the stack, and use it in the optimization
        # pass phase to rewrite code with fewer (possibly sometimes no) gotos.
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        chunks_examined: Set[int] = set()

        self.vprint(f"BETA: Separating if statements out of graph starting at {start_id}")

        def walk_children(cur_chunk: ArbitraryCodeChunk, apply_logic: Sequence[IfResult]) -> Dict[int, Set[IfResult]]:
            # First, if we have any previous if statements to apply to this chunk, do that now.
            self.vprint(f"BETA: Applying {apply_logic} to {cur_chunk.id}")
            chunks_to_logic: Dict[int, Set[IfResult]] = {cur_chunk.id: {x for x in apply_logic}}

            # Now, if it is a loop and we haven't already passed over this chunk, recursively
            # find if statements inside it as well.
            if isinstance(cur_chunk, Loop):
                if cur_chunk.id not in chunks_examined:
                    chunks_examined.add(cur_chunk.id)

                    self.vprint(f"BETA: Examining loop {cur_chunk.id} body for if statements...")
                    cur_chunk.chunks = self.__new_separate_ifs(cur_chunk.id, None, cur_chunk.chunks, offset_map)
                    self.vprint(f"BETA: Finished examining loop {cur_chunk.id} body for if statements...")

            # Now, see if we need to split logic up or not.
            if not cur_chunk.next_chunks:
                # We are at the end of our walk.
                return chunks_to_logic

            if len(cur_chunk.next_chunks) == 1:
                # We only have one child, so follow that link.
                next_chunk = cur_chunk.next_chunks[0]
                if next_chunk in chunks_by_id:
                    for cid, logic in walk_children(chunks_by_id[next_chunk], apply_logic).items():
                        chunks_to_logic[cid] = {*chunks_to_logic.get(cid, set()), *logic}
                return chunks_to_logic

            if not isinstance(cur_chunk, ByteCodeChunk):
                # We should only be looking at bytecode chunks at this point, all other
                # types should have a single next chunk.
                raise Exception(f"Logic error, found converted Loop or If chunk {cur_chunk.id} with multiple successors!")

            if len(cur_chunk.next_chunks) != 2:
                # This needs to be an if statement.
                raise Exception(f"Logic error, expected 2 successors but got {len(cur_chunk.next_chunks)} in chunk {cur_chunk.id}!")
            last_action = cur_chunk.actions[-1]
            if not isinstance(last_action, IfAction):
                # This needs, again, to be an if statement.
                raise Exception("Logic error, only IfActions can have multiple successors in chunk {cur_chunk.id}!")

            # Find the true and false jump points, walk those graphs and assign logical predecessors
            # to each of them.
            true_jump_point, false_jump_point = self.__get_jump_points(cur_chunk, offset_map)
            if true_jump_point == false_jump_point:
                # This should never happen.
                raise Exception("Logic error, both true and false jumps are to the same location!")

            self.vprint(f"BETA: Chunk ID {cur_chunk.id} is an if statement with true node {true_jump_point} and false node {false_jump_point}")

            # Walk both halves, assigning the if statement that has to exist to get to each half.
            if true_jump_point in chunks_by_id:
                for cid, logic in walk_children(chunks_by_id[true_jump_point], [*apply_logic, IfResult(cur_chunk.id, True)]).items():
                    chunks_to_logic[cid] = {*chunks_to_logic.get(cid, set()), *logic}
            if false_jump_point in chunks_by_id:
                for cid, logic in walk_children(chunks_by_id[false_jump_point], [*apply_logic, IfResult(cur_chunk.id, False)]).items():
                    chunks_to_logic[cid] = {*chunks_to_logic.get(cid, set()), *logic}
            return chunks_to_logic

        # First, walk through and identify how we get to each chunk.
        chunks_by_logic = walk_children(chunks_by_id[start_id], [])
        self.vprint(f"BETA: List of logics: {chunks_by_logic}")

        # Now, go through each chunk and remove tautologies (where we get to it through a previous
        # if statement from both true and false paths, meaning this isn't owned by an if statement).
        for cid in chunks_by_logic:
            changed: bool = True
            while changed:
                # Assume we didn't change anything.
                changed = False

                # Figure out if there is a tautology existing in this logic.
                for path in chunks_by_logic[cid]:
                    remove: Optional[IfResult] = None
                    for other in chunks_by_logic[cid]:
                        if path.makes_tautology(other):
                            remove = other
                            break

                    if remove:
                        # We found a tautology, remove both halves.
                        self.vprint(f"BETA: {path} makes a tautology with {remove}, removing both of them!")
                        chunks_by_logic[cid].remove(path)
                        chunks_by_logic[cid].remove(remove)
                        changed = True
                        break

        self.vprint(f"BETA: Cleaned up logics: {chunks_by_logic}")

        self.vprint(f"BETA: Finished separating if statements out of graph starting at {start_id}")
        return [c for _, c in chunks_by_id.items()]

    def __check_graph(self, start_id: int, chunks: Sequence[ArbitraryCodeChunk]) -> List[ArbitraryCodeChunk]:
        # Recursively go through and verify that all entries to the graph have only one link.
        # Also, clean up the graph.
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        new_chunks: List[ArbitraryCodeChunk] = []

        while True:
            cur_chunk = chunks_by_id[start_id]

            # First, clean up any code in chunks that contain other chunks.
            if isinstance(cur_chunk, Loop):
                # Clean up the loop's chunks
                self.vprint(f"Cleaning up graph of Loop {cur_chunk.id}")
                cur_chunk.chunks = self.__check_graph(cur_chunk.id, cur_chunk.chunks)
            elif isinstance(cur_chunk, IfBody):
                # Clean up the if's chunks
                if cur_chunk.true_chunks:
                    self.vprint(f"Cleaning up graph of IfBody {cur_chunk.id} true case")
                    true_start = self.__get_entry_block(cur_chunk.true_chunks)
                    cur_chunk.true_chunks = self.__check_graph(true_start, cur_chunk.true_chunks)
                if cur_chunk.false_chunks:
                    self.vprint(f"Cleaning up graph of IfBody {cur_chunk.id} false case")
                    false_start = self.__get_entry_block(cur_chunk.false_chunks)
                    cur_chunk.false_chunks = self.__check_graph(false_start, cur_chunk.false_chunks)

            # Now, check to make sure that we have only one exit pointer.
            num_exits = len(cur_chunk.next_chunks)
            if num_exits > 1:
                raise Exception("Logic error!")

            # Now, we know this chunk is visited, so we can keep it.
            new_chunks.append(cur_chunk)

            # Finally, bail if we've hit the end of the list.
            if num_exits == 0:
                break

            # Go to the next one!
            start_id = cur_chunk.next_chunks[0]

        # Return the tree, stripped of all dead code (most likely just the return sentinel).
        return new_chunks

    def __eval_stack(self, chunk: ByteCodeChunk, stack: List[Any], offset_map: Dict[int, int]) -> Tuple[List[ConvertedAction], List[Any]]:
        # Make a copy of the stack so we can safely modify it ourselves.
        stack = [s for s in stack]

        # TODO: Its possible for there to be a function/method call with no subsequent use of the return
        # value and no POP to clear the stack. If this is the case, technically the function WAS called,
        # just the result was completely ignored. This shows up in a few Pop'n animations. What should
        # happen is that we check the stack for any leftover function/method calls and re-insert them
        # into the spot where they were called since we know that they aren't used.

        def make_if_expr(action: IfAction) -> IfExpr:
            if action.comparison in [IfAction.IS_UNDEFINED, IfAction.IS_NOT_UNDEFINED]:
                conditional = stack.pop()
                return IsUndefinedIf(conditional, negate=(action.comparison != IfAction.IS_UNDEFINED))
            elif action.comparison in [IfAction.IS_TRUE, IfAction.IS_FALSE]:
                conditional = stack.pop()
                return IsBooleanIf(conditional, negate=(action.comparison != IfAction.IS_TRUE))
            elif action.comparison in [
                IfAction.EQUALS,
                IfAction.NOT_EQUALS,
                IfAction.STRICT_EQUALS,
                IfAction.STRICT_NOT_EQUALS,
                IfAction.LT,
                IfAction.GT,
                IfAction.LT_EQUALS,
                IfAction.GT_EQUALS
            ]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                comp = {
                    IfAction.EQUALS: TwoParameterIf.EQUALS,
                    IfAction.NOT_EQUALS: TwoParameterIf.NOT_EQUALS,
                    IfAction.STRICT_EQUALS: TwoParameterIf.STRICT_EQUALS,
                    IfAction.STRICT_NOT_EQUALS: TwoParameterIf.STRICT_NOT_EQUALS,
                    IfAction.LT: TwoParameterIf.LT,
                    IfAction.GT: TwoParameterIf.GT,
                    IfAction.LT_EQUALS: TwoParameterIf.LT_EQUALS,
                    IfAction.GT_EQUALS: TwoParameterIf.GT_EQUALS,
                }[action.comparison]

                return TwoParameterIf(conditional1, comp, conditional2)
            elif action.comparison in [IfAction.BITAND, IfAction.NOT_BITAND]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                comp = TwoParameterIf.NOT_EQUALS if action.comparison == IfAction.BITAND else TwoParameterIf.EQUALS

                return TwoParameterIf(
                    ArithmeticExpression(conditional1, "&", conditional2),
                    comp,
                    0,
                )
            else:
                raise Exception(f"Logic error, unknown if action {action}!")

        for i in range(len(chunk.actions)):
            action = chunk.actions[i]

            if isinstance(action, PushAction):
                for obj in action.objects:
                    stack.append(obj)

                chunk.actions[i] = NopStatement()
                continue

            if isinstance(action, DefineFunction2Action):
                if action.name:
                    # This defines a global function, so it won't go on the stack.
                    chunk.actions[i] = SetVariableStatement(action.name, NewFunction(action.flags, action.body))
                else:
                    # This defines a function object, most likely for attaching to a member of an object.
                    stack.append(NewFunction(action.flags, action.body))
                    chunk.actions[i] = NopStatement()

                continue

            if isinstance(action, GotoFrame2Action):
                after: Statement

                if action.stop:
                    after = StopMovieStatement()
                else:
                    after = PlayMovieStatement()

                frame = stack.pop()
                if action.additional_frames:
                    frame = ArithmeticExpression(frame, '+', action.additional_frames)

                chunk.actions[i] = MultiAction([
                    GotoFrameStatement(frame),
                    after,
                ])
                continue

            if isinstance(action, StoreRegisterAction):
                # This one's fun, because a store register can generate zero or more statements.
                # So we need to expand the stack. But we can't mid-iteration without a lot of
                # shenanigans, so we instead invent a new type of ConvertedAction that can contain
                # multiple statements.
                set_value = stack.pop()
                if action.preserve_stack:
                    # If we are only initializing one register, put the register back
                    # on the stack instead of the value, to make decompiled output
                    # better. This helps a lot when we initialize to a function call return.
                    if len(action.registers) == 1:
                        stack.append(action.registers[0])
                    else:
                        stack.append(set_value)

                store_actions: List[StoreRegisterStatement] = []

                for reg in action.registers:
                    store_actions.append(StoreRegisterStatement(reg, set_value))

                chunk.actions[i] = MultiAction(store_actions)
                continue

            if isinstance(action, InitRegisterAction):
                # Same as the above statement, but we are initializing to UNDEFINED.
                init_actions: List[StoreRegisterStatement] = []

                for reg in action.registers:
                    init_actions.append(StoreRegisterStatement(reg, UNDEFINED))

                chunk.actions[i] = MultiAction(init_actions)
                continue

            if isinstance(action, JumpAction):
                # This could possibly be a jump to the very next line, but we will wait for the
                # optimization pass to figure that out.
                chunk.actions[i] = GotoStatement(offset_map[action.jump_offset])
                continue

            if isinstance(action, IfAction):
                chunk.actions[i] = make_if_expr(action)
                continue

            if isinstance(action, WithAction):
                # TODO: I have to figure out what "with" actually even does.
                # It sets some context and local variables, but to what?
                raise Exception(f"TODO: {action}")

            if isinstance(action, GetURL2Action):
                # TODO: I have to figure out what "geturl2" actually even does.
                # It is something to do with getting the "URL" of the current
                # movie clip.
                url = stack.pop()
                target = stack.pop()
                chunk.actions[i] = GetURL2Statement(action.action, url, target)
                continue

            if isinstance(action, StartDragAction):
                # TODO: I have to implement this, if I ever come across it.
                raise Exception(f"TODO: {action}")

            if isinstance(action, AddNumVariableAction):
                variable_name = stack.pop()
                if not isinstance(variable_name, (str, StringConstant)):
                    raise Exception("Logic error!")

                chunk.actions[i] = SetVariableStatement(
                    variable_name,
                    ArithmeticExpression(
                        Variable(variable_name),
                        "+" if action.amount_to_add >= 0 else '-',
                        abs(action.amount_to_add),
                    )
                )
                continue

            if isinstance(action, AddNumRegisterAction):
                chunk.actions[i] = StoreRegisterStatement(
                    action.register,
                    ArithmeticExpression(
                        action.register,
                        "+" if action.amount_to_add >= 0 else '-',
                        abs(action.amount_to_add),
                    )
                )
                continue

            if isinstance(action, AP2Action):
                if action.opcode == AP2Action.STOP:
                    chunk.actions[i] = StopMovieStatement()
                    continue

                if action.opcode == AP2Action.PLAY:
                    chunk.actions[i] = PlayMovieStatement()
                    continue

                if action.opcode == AP2Action.END:
                    chunk.actions[i] = NullReturnStatement()
                    continue

                if action.opcode == AP2Action.NEXT_FRAME:
                    chunk.actions[i] = NextFrameStatement()
                    continue

                if action.opcode == AP2Action.PREVIOUS_FRAME:
                    chunk.actions[i] = PreviousFrameStatement()
                    continue

                if action.opcode == AP2Action.STOP_SOUND:
                    chunk.actions[i] = StopSoundStatement()
                    continue

                if action.opcode == AP2Action.CLONE_SPRITE:
                    depth = stack.pop()
                    if not isinstance(depth, (int, Expression)):
                        raise Exception("Logic error!")
                    name = stack.pop()
                    if not isinstance(name, (str, Expression)):
                        raise Exception("Logic error!")
                    obj = stack.pop()
                    chunk.actions[i] = CloneSpriteStatement(obj, name, depth)
                    continue

                if action.opcode == AP2Action.REMOVE_SPRITE:
                    obj = stack.pop()
                    chunk.actions[i] = RemoveSpriteStatement(obj)
                    continue

                if action.opcode == AP2Action.TO_NUMBER:
                    obj_ref = stack.pop()
                    stack.append(FunctionCall(self.__insertion_id, 'int', [obj_ref]))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.TO_STRING:
                    obj_ref = stack.pop()
                    stack.append(FunctionCall(self.__insertion_id, 'str', [obj_ref]))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.INCREMENT:
                    obj_ref = stack.pop()
                    stack.append(ArithmeticExpression(obj_ref, '+', 1))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.DECREMENT:
                    obj_ref = stack.pop()
                    stack.append(ArithmeticExpression(obj_ref, '-', 1))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.NOT:
                    obj_ref = stack.pop()
                    stack.append(NotExpression(obj_ref))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.INSTANCEOF:
                    name_ref = stack.pop()
                    obj_to_check = stack.pop()
                    stack.append(FunctionCall(self.__insertion_id, 'isinstance', [obj_to_check, name_ref]))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.TYPEOF:
                    obj_to_check = stack.pop()
                    stack.append(FunctionCall(self.__insertion_id, 'typeof', [obj_to_check]))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.CALL_METHOD:
                    method_name = stack.pop()
                    if not isinstance(method_name, (str, int, Expression)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()
                    num_params = stack.pop()
                    if not isinstance(num_params, int):
                        raise Exception("Logic error!")
                    params = []
                    for _ in range(num_params):
                        params.append(stack.pop())
                    stack.append(MethodCall(self.__insertion_id, object_reference, method_name, params))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.CALL_FUNCTION:
                    function_name = stack.pop()
                    if not isinstance(function_name, (str, StringConstant)):
                        raise Exception("Logic error!")
                    num_params = stack.pop()
                    if not isinstance(num_params, int):
                        raise Exception("Logic error!")
                    params = []
                    for _ in range(num_params):
                        params.append(stack.pop())
                    stack.append(FunctionCall(self.__insertion_id, function_name, params))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.RETURN:
                    retval = stack.pop()
                    chunk.actions[i] = ReturnStatement(retval)
                    continue

                if action.opcode == AP2Action.THROW:
                    retval = stack.pop()
                    chunk.actions[i] = ThrowStatement(retval)
                    continue

                if action.opcode == AP2Action.POP:
                    # This is a discard. Let's see if its discarding a function or method
                    # call. If so, that means the return doesn't matter.
                    discard = stack.pop()
                    if isinstance(discard, (FunctionCall, MethodCall)):
                        # It is! Let's act on the statement.
                        chunk.actions[i] = ExpressionStatement(discard)
                    else:
                        chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.GET_VARIABLE:
                    variable_name = stack.pop()
                    if isinstance(variable_name, (str, StringConstant)):
                        stack.append(Variable(variable_name))
                    else:
                        # This is probably a reference to a variable by
                        # string concatenation.
                        stack.append(Member(GLOBAL, variable_name))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.SET_VARIABLE:
                    set_value = stack.pop()
                    local_name = stack.pop()
                    if isinstance(local_name, (str, StringConstant)):
                        chunk.actions[i] = SetVariableStatement(local_name, set_value)
                    else:
                        # This is probably a reference to a variable by
                        # string concatenation.
                        chunk.actions[i] = SetMemberStatement(GLOBAL, local_name, set_value)

                    continue

                if action.opcode == AP2Action.DELETE:
                    member_name = stack.pop()
                    if not isinstance(member_name, (str, int, Expression)):
                        raise Exception("Logic error!")
                    obj_name = stack.pop()

                    chunk.actions[i] = DeleteMemberStatement(obj_name, member_name)
                    continue

                if action.opcode == AP2Action.DELETE2:
                    variable_name = stack.pop()
                    if not isinstance(variable_name, (str, StringConstant)):
                        raise Exception("Logic error!")

                    chunk.actions[i] = DeleteVariableStatement(variable_name)
                    continue

                if action.opcode == AP2Action.GET_MEMBER:
                    member_name = stack.pop()
                    if not isinstance(member_name, (str, int, Expression)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()
                    stack.append(Member(object_reference, member_name))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.SET_MEMBER:
                    set_value = stack.pop()
                    member_name = stack.pop()
                    if not isinstance(member_name, (str, int, Expression)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()

                    chunk.actions[i] = SetMemberStatement(object_reference, member_name, set_value)
                    continue

                if action.opcode == AP2Action.GET_PROPERTY:
                    property_int = stack.pop()
                    if not isinstance(property_int, int):
                        # Its possible that code which uses this outdated SWF GET_PROPERTY call
                        # might dynamically calculate the integer which it wants to use to get
                        # a property on. But, probably not. I haven't seen any code use this or
                        # SET_PROPERTY so this is just here for documentation.
                        raise Exception("Logic error!")
                    object_reference = stack.pop()
                    stack.append(Member(object_reference, StringConstant(property_int + 0x100)))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.SET_PROPERTY:
                    set_value = stack.pop()
                    property_int = stack.pop()
                    if not isinstance(property_int, int):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()

                    chunk.actions[i] = SetMemberStatement(object_reference, StringConstant(property_int + 0x100), set_value)
                    continue

                if action.opcode == AP2Action.DEFINE_LOCAL:
                    set_value = stack.pop()
                    local_name = stack.pop()
                    if not isinstance(local_name, (str, StringConstant)):
                        raise Exception(f"Logic error, local name {local_name} is not a string!")

                    chunk.actions[i] = SetLocalStatement(local_name, set_value)
                    continue

                if action.opcode == AP2Action.DEFINE_LOCAL2:
                    local_name = stack.pop()
                    if not isinstance(local_name, (str, StringConstant)):
                        raise Exception(f"Logic error, local name {local_name} is not a string!")

                    chunk.actions[i] = SetLocalStatement(local_name, UNDEFINED)
                    continue

                if action.opcode == AP2Action.NEW_OBJECT:
                    object_name = stack.pop()
                    if not isinstance(object_name, (str, StringConstant)):
                        raise Exception("Logic error!")
                    num_params = stack.pop()
                    if not isinstance(num_params, int):
                        raise Exception("Logic error!")
                    params = []
                    for _ in range(num_params):
                        params.append(stack.pop())
                    stack.append(NewObject(object_name, params))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.INIT_ARRAY:
                    num_entries = stack.pop()
                    if not isinstance(num_entries, int):
                        raise Exception("Logic error!")
                    arrparams = []
                    for _ in range(num_entries):
                        arrparams.append(stack.pop())
                    stack.append(Array(arrparams))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.INIT_OBJECT:
                    num_entries = stack.pop()
                    if not isinstance(num_entries, int):
                        raise Exception("Logic error!")
                    objparams: Dict[Any, Any] = {}
                    for _ in range(num_entries):
                        val = stack.pop()
                        key = stack.pop()
                        objparams[key] = val
                    stack.append(Object(objparams))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.TRACE:
                    trace_obj = stack.pop()
                    chunk.actions[i] = DebugTraceStatement(trace_obj)
                    continue

                if action.opcode == AP2Action.ADD2:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "+", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.SUBTRACT:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "-", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.MULTIPLY:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "*", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.DIVIDE:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "/", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.MODULO:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "%", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.BIT_OR:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "|", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.BIT_AND:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "&", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.BIT_XOR:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "^", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.BIT_L_SHIFT:
                    shift_amt = stack.pop()
                    shift_val = stack.pop()
                    stack.append(ArithmeticExpression(shift_val, "<<", shift_amt))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode in {AP2Action.BIT_R_SHIFT, AP2Action.BIT_U_R_SHIFT}:
                    shift_amt = stack.pop()
                    shift_val = stack.pop()
                    stack.append(ArithmeticExpression(shift_val, ">>", shift_amt))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.EQUALS2:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "==", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.STRICT_EQUALS:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "===", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.GREATER:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, ">", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.LESS2:
                    expr2 = stack.pop()
                    expr1 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "<", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.PUSH_DUPLICATE:
                    dup = stack.pop()
                    stack.append(dup)
                    stack.append(dup)

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.GET_TIME:
                    stack.append(GetTimeFunctionCall(self.__insertion_id))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.TARGET_PATH:
                    clip = stack.pop()
                    stack.append(GetPathFunctionCall(self.__insertion_id, clip))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.CAST_OP:
                    obj_ref = stack.pop()
                    class_ref = stack.pop()
                    stack.append(FunctionCall(self.__insertion_id, 'cast', [obj_ref, class_ref]))

                    chunk.actions[i] = OriginalCallLocation(self.__insertion_id)
                    self.__insertion_id += 1
                    continue

                if action.opcode == AP2Action.IMPLEMENTS_OP:
                    # This appears to be completely unimplemented/broken in
                    # Bishi so I have no idea what it intends to do. Probably
                    # I could look at the SWF spec and infer the functionality
                    # but there aren't any files that I've found in any games
                    # that use this opcode, so meh.
                    raise Exception(f"TODO: {action}")

                if action.opcode == AP2Action.STACK_SWAP:
                    first = stack.pop()
                    second = stack.pop()
                    stack.append(first)
                    stack.append(second)

                    chunk.actions[i] = NopStatement()
                    continue

                # None of the below actions are understood outside of the fact
                # that they operate entirely on the stack. They do not appear to
                # be used in any game code I've come across and might be remnants
                # of when the code was for playing SWF directly.
                if action.opcode == AP2Action.ENUMERATE2:
                    raise Exception(f"TODO: {action}")

                if action.opcode == AP2Action.EXTENDS:
                    raise Exception(f"TODO: {action}")

                if action.opcode == AP2Action.END_DRAG:
                    raise Exception(f"TODO: {action}")

                if action.opcode == AP2Action.NEW_METHOD:
                    raise Exception(f"TODO: {action}")

                if action.opcode == AP2Action.GET_TARGET:
                    raise Exception(f"TODO: {action}")

            if isinstance(action, NullReturnStatement):
                # We already handled this
                continue

            if isinstance(action, ContinueStatement):
                # We already handled this
                continue

            if isinstance(action, BreakStatement):
                # We already handled this
                continue

            if isinstance(action, GotoStatement):
                # We already handled this
                continue

            if isinstance(action, IntermediateIf):
                # A partially-converted if from loop detection. Leave as-is, this
                # is the job of our caller since it needs to follow the stack to
                # the next jump given the statements in this intermediate if. The
                # only thing we convert is the expression, since we need the current
                # stack to do that.
                chunk.actions[i] = IntermediateIf(
                    make_if_expr(cast(IfAction, action.parent_action)),
                    action.true_statements,
                    action.false_statements,
                )
                continue

            raise Exception(f"Unexpected action {action}, the cases above should be exhaustive!")

        # Now, clean up code generation.
        new_actions: List[ConvertedAction] = []
        for action in chunk.actions:
            if not isinstance(action, ConvertedAction):
                # We should have handled all AP2Actions at this point!
                raise Exception("Logic error!")
            if isinstance(action, NopStatement):
                # Filter out noops.
                continue
            if isinstance(action, NullReturnStatement):
                if new_actions and isinstance(new_actions[-1], NullReturnStatement):
                    # Filter out redundant return statements.
                    continue
            if isinstance(action, MultiAction):
                for new_action in action.actions:
                    new_actions.append(new_action)
                continue

            new_actions.append(action)

        # Finally, return everything we did.
        return new_actions, stack

    def __eval_chunks(self, start_id: int, chunks: Sequence[ArbitraryCodeChunk], offset_map: Dict[int, int]) -> List[Statement]:
        stack: Dict[int, List[Any]] = {start_id: []}
        insertables: Dict[int, List[Statement]] = {}
        orphaned_functions: Dict[int, Union[FunctionCall, MethodCall]] = {}
        other_locs: Dict[int, int] = {}

        # Convert all chunks to a list of statements.
        statements = self.__eval_chunks_impl(start_id, chunks, None, stack, insertables, orphaned_functions, other_locs, offset_map)

        # Now, go through and fix up any insertables.
        def fixup(statements: Sequence[Statement]) -> List[Statement]:
            new_statements: List[Statement] = []

            for statement in statements:
                if isinstance(statement, DoWhileStatement):
                    statement.body = fixup(statement.body)
                    new_statements.append(statement)
                elif isinstance(statement, IfStatement):
                    statement.true_statements = fixup(statement.true_statements)
                    statement.false_statements = fixup(statement.false_statements)
                    new_statements.append(statement)
                else:
                    if isinstance(statement, InsertionLocation):
                        # Convert to any statements we need to insert.
                        if statement.location in insertables:
                            self.vprint(f"Inserting temp variable assignments into insertion location {statement.location}")
                            for stmt in insertables[statement.location]:
                                new_statements.append(stmt)
                    elif isinstance(statement, OriginalCallLocation):
                        # Convert any orphaned function calls to calls without an assignment.
                        if statement.insertion_id in orphaned_functions:
                            self.vprint(f"Inserting orphaned function into insertion location {statement.insertion_id}")
                            new_statements.append(ExpressionStatement(orphaned_functions[statement.insertion_id]))
                            del orphaned_functions[statement.insertion_id]
                    else:
                        new_statements.append(statement)
            return new_statements

        statements = fixup(statements)

        if orphaned_functions:
            raise Exception(f"Unexpected leftover orphan functions {orphaned_functions}!")

        # Make sure we consumed the stack.
        for cid, leftovers in stack.items():
            if leftovers:
                raise Exception(f"Stack not empty, chunk {cid} contains {stack}!")

        # Finally, return the statements!
        return statements

    def __eval_chunks_impl(
        self,
        start_id: int,
        chunks: Sequence[ArbitraryCodeChunk],
        next_id: Optional[int],
        stacks: Dict[int, List[Any]],
        insertables: Dict[int, List[Statement]],
        orphaned_functions: Dict[int, Union[FunctionCall, MethodCall]],
        other_stack_locs: Dict[int, int],
        offset_map: Dict[int, int],
    ) -> List[Statement]:
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        statements: List[Statement] = []

        def reconcile_stacks(cur_chunk: int, new_stack_id: int, new_stack: List[Any]) -> List[Statement]:
            if new_stack_id in stacks:
                if cur_chunk == other_stack_locs[new_stack_id]:
                    raise Exception("Logic error, cannot reconcile variable names with self!")
                other_chunk = other_stack_locs[new_stack_id]
                if len(stacks[new_stack_id]) != len(new_stack):
                    min_len = min(len(stacks[new_stack_id]), len(new_stack))
                    max_len = max(len(stacks[new_stack_id]), len(new_stack))
                    borrows = max_len - min_len
                    if borrows <= 0:
                        raise Exception("Logic error!")

                    # It doesn't matter what it is, just mark the stack entry as being poisoned since
                    # we couldn't reconcile it. We want to throw an exception down the line if we
                    # run into this value, as we needed it but only sometimes got it.
                    borrow_vals = [MaybeStackEntry(new_stack_id) for _ in range(borrows)]

                    if min_len > 0:
                        stacks[new_stack_id] = [*borrow_vals, *stacks[new_stack_id][-min_len:]]
                        new_stack = [*borrow_vals, new_stack[-min_len:]]
                    else:
                        stacks[new_stack_id] = [*borrow_vals]
                        new_stack = [*borrow_vals]
                    self.vprint(f"Chopped off {borrows} values from longest stack and replaced with MaybeStackEntry for {new_stack_id}")

                    if len(new_stack) != len(stacks[new_stack_id]):
                        raise Exception(f"Logic error, expected {new_stack} and {stacks[new_stack_id]} to be equal length!")

                self.vprint(
                    f"Merging stack {stacks[new_stack_id]} for chunk ID {new_stack_id} with {new_stack}, " +
                    f"and scheduling chunks {cur_chunk} and {other_chunk} for variable definitions."
                )

                stack: List[Any] = []
                definitions: List[Statement] = []
                for j in range(len(new_stack)):
                    # Walk the stack backwards to mimic the order in which a stack entry would be pulled.
                    i = (len(new_stack) - (j + 1))
                    new_entry = new_stack[i]
                    old_entry = stacks[new_stack_id][i]

                    if new_entry != old_entry:
                        if isinstance(old_entry, TempVariable):
                            # This is already converted in another stack, so we just need to use the same.
                            tmpname = old_entry.name

                            insertables[cur_chunk] = insertables.get(cur_chunk, []) + [SetVariableStatement(tmpname, new_entry)]

                            stack.append(TempVariable(tmpname))
                            self.vprint(f"Reusing temporary variable {tmpname} to hold stack value {new_stack[i]}")
                        else:
                            tmpname = f"tempvar_{self.__tmpvar_id}"
                            self.__tmpvar_id += 1

                            insertables[cur_chunk] = insertables.get(cur_chunk, []) + [SetVariableStatement(tmpname, new_entry)]
                            insertables[other_chunk] = insertables.get(other_chunk, []) + [SetVariableStatement(tmpname, old_entry)]

                            stack.append(TempVariable(tmpname))
                            self.vprint(f"Creating temporary variable {tmpname} to hold stack values {new_stack[i]} and {stacks[new_stack_id][i]}")
                    else:
                        stack.append(new_entry)

                self.vprint(f"Redefining stack for chunk ID {new_stack_id} to be {stack} after merging multiple paths")
                stacks[new_stack_id] = stack[::-1]
                return definitions
            else:
                self.vprint(f"Defining stack for chunk ID {new_stack_id} to be {new_stack} based on evaluation of {cur_chunk}")
                other_stack_locs[new_stack_id] = cur_chunk
                stacks[new_stack_id] = new_stack
                return []

        while True:
            # Grab the chunk to operate on.
            chunk = chunks_by_id[start_id]
            if len(chunk.next_chunks) > 1:
                # We've checked so this should be impossible.
                raise Exception("Logic error!")
            if chunk.next_chunks:
                next_chunk_id = chunk.next_chunks[0]
            else:
                next_chunk_id = next_id

            if isinstance(chunk, Loop):
                # Evaluate the loop. No need to update per-chunk stacks here since we will do it in a child eval.
                self.vprint(f"Evaluating graph in Loop {chunk.id}")
                loop_statements = self.__eval_chunks_impl(chunk.id, chunk.chunks, next_chunk_id, stacks, insertables, orphaned_functions, other_stack_locs, offset_map)
                statements.append(DoWhileStatement(loop_statements))
                statements.extend(chunk.post_statements)
            elif isinstance(chunk, IfBody):
                # We should have evaluated this earlier!
                raise Exception("Logic error!")
            else:
                if start_id >= 0:
                    # Make sure when we collapse chunks, we don't lose labels.
                    statements.append(DefineLabelStatement(start_id))

                # Grab the computed start stack for this ID
                if chunk.id not in stacks:
                    # We somehow failed to assign a stack to this chunk but got here anyway?
                    raise Exception(f"Logic error, stack for {chunk.id} does not exist!")

                stack = stacks[chunk.id]
                del stacks[chunk.id]

                # Calculate the statements for this chunk, as well as the leftover stack entries.
                self.vprint(f"Evaluating graph of ByteCodeChunk {chunk.id} with stack {stack}")
                new_statements, stack_leftovers = self.__eval_stack(chunk, stack, offset_map)

                # We need to check and see if the last entry is an IfExpr, and hoist it
                # into a statement here.
                if new_statements and isinstance(new_statements[-1], IfExpr):
                    if_body = chunk.next_chunks[0]
                    if_body_chunk = chunks_by_id[if_body]

                    if not isinstance(if_body_chunk, IfBody):
                        # IfBody should always follow a chunk that ends with an if.
                        raise Exception(f"Logic error, expecting an IfBody chunk but got {if_body_chunk}!")

                    if if_body in stacks:
                        # Nothing should ever create a stack pointing at an IfBody except this code here.
                        raise Exception(f"Logic error, IfBody ID {if_body} already has a stack {stacks[if_body]}!")

                    # Recalculate next chunk ID since we're calculating two chunks here.
                    if len(if_body_chunk.next_chunks) > 1:
                        # We've checked so this should be impossible.
                        raise Exception("Logic error!")
                    if if_body_chunk.next_chunks:
                        next_chunk_id = if_body_chunk.next_chunks[0]
                    else:
                        next_chunk_id = next_id
                    self.vprint(f"Recalculated next ID for IfBody {if_body} to be {next_chunk_id}")

                    # Make sure if its an if with only one body (true/false) that we track
                    # the stack in this case as well.
                    if_sentinels: List[ConvertedAction] = [InsertionLocation(chunk.id)]
                    if_sentinels.append(new_statements[-1])
                    new_statements = new_statements[:-1]
                    new_statements.extend(if_sentinels)

                    # Evaluate the if body
                    true_statements: List[Statement] = []
                    if if_body_chunk.true_chunks:
                        self.vprint(f"Evaluating graph of IfBody {if_body_chunk.id} true case")
                        true_start = self.__get_entry_block(if_body_chunk.true_chunks)
                        if true_start in stacks:
                            raise Exception("Logic error, unexpected stack for if!")
                        else:
                            # The stack for both of these is the leftovers from the previous evaluation as they
                            # rollover.
                            stacks[true_start] = [s for s in stack_leftovers]
                        self.vprint(f"True start {true_start} of IfBody has stack {stacks[true_start]}")
                        true_statements = self.__eval_chunks_impl(
                            true_start,
                            if_body_chunk.true_chunks,
                            next_chunk_id,
                            stacks,
                            insertables,
                            orphaned_functions,
                            other_stack_locs,
                            offset_map,
                        )
                    else:
                        reconcile_stacks(chunk.id, next_chunk_id, stack_leftovers)

                    false_statements: List[Statement] = []
                    if if_body_chunk.false_chunks:
                        self.vprint(f"Evaluating graph of IfBody {if_body_chunk.id} false case")
                        false_start = self.__get_entry_block(if_body_chunk.false_chunks)
                        if false_start in stacks:
                            raise Exception("Logic error, unexpected stack for if!")
                        else:
                            # The stack for both of these is the leftovers from the previous evaluation as they
                            # rollover.
                            stacks[false_start] = [s for s in stack_leftovers]
                        self.vprint(f"False start {false_start} of IfBody has stack {stacks[false_start]}")
                        false_statements = self.__eval_chunks_impl(
                            false_start,
                            if_body_chunk.false_chunks,
                            next_chunk_id,
                            stacks,
                            insertables,
                            orphaned_functions,
                            other_stack_locs,
                            offset_map,
                        )
                    else:
                        reconcile_stacks(chunk.id, next_chunk_id, stack_leftovers)

                    # Convert this IfExpr to a full-blown IfStatement.
                    new_statements[-1] = IfStatement(
                        cast(IfExpr, new_statements[-1]),
                        true_statements,
                        false_statements,
                    )

                    # Skip evaluating the IfBody next iteration.
                    chunk = if_body_chunk
                else:
                    # We must propagate the stack to the next entry. If it already exists we must merge it.
                    new_next_ids: Set[int] = {next_chunk_id}
                    if new_statements:
                        last_new_statement = new_statements[-1]
                        if isinstance(last_new_statement, GotoStatement):
                            # Replace the next IDs with just the goto.
                            new_next_ids = {last_new_statement.location}
                        elif isinstance(last_new_statement, (ThrowStatement, NullReturnStatement, ReturnStatement)):
                            # We don't have a next ID, we're returning.
                            new_next_ids = set()
                        elif isinstance(last_new_statement, IntermediateIf):
                            # We have potentially more than one next ID, given what statements exist
                            # inside the true/false chunks.
                            intermediates: List[Statement] = []
                            if len(last_new_statement.true_statements) > 1:
                                raise Exception(f"Logic error, expected only one true statement in intermediate if {last_new_statement}!")
                            else:
                                intermediates.extend(last_new_statement.true_statements)
                            if len(last_new_statement.false_statements) > 1:
                                raise Exception(f"Logic error, expected only one false statement in intermediate if {last_new_statement}!")
                            else:
                                intermediates.extend(last_new_statement.false_statements)

                            for stmt in intermediates:
                                if isinstance(stmt, GotoStatement):
                                    new_next_ids.add(stmt.location)
                                elif isinstance(stmt, (ThrowStatement, NullReturnStatement, ReturnStatement, ContinueStatement)):
                                    # Do nothing. Three of these cases point at the end of the program, one
                                    # points back at the top of the loop which we've already covered. Maybe
                                    # we should assert here like we do below? Not sure.
                                    pass
                                elif isinstance(stmt, BreakStatement):
                                    # This points at the next chunk ID after the loop.
                                    if next_id is not None:
                                        new_next_ids.add(next_id)
                                else:
                                    raise Exception(f"Logic error, unexpected statement {stmt}!")

                    if new_next_ids:
                        for new_next_id in new_next_ids:
                            reconcile_stacks(chunk.id, new_next_id, [s for s in stack_leftovers])

                        # Insert a sentinel for where temporary variables can be added if we
                        # need to in the future.
                        sentinels: List[Union[Statement, IntermediateIf]] = [InsertionLocation(chunk.id)]

                        # If we have a goto or intermediate if, we need to insert the tempvar assignment before it.
                        # This is because in both cases we will redirect control flow, so we need to make sure
                        # tempvar assignment happens before that redirection for the code to make sense.
                        if new_statements and isinstance(new_statements[-1], (GotoStatement, IntermediateIf)):
                            sentinels.append(new_statements[-1])
                            new_statements = new_statements[:-1]

                        # Add our new statements to the end of the statement list.
                        new_statements.extend(sentinels)
                    else:
                        # We have nowhere else to go, verify that we have an empty stack.
                        orphans = [s for s in stack_leftovers if isinstance(s, (FunctionCall, MethodCall))]
                        stack_leftovers = [s for s in stack_leftovers if not isinstance(s, (MaybeStackEntry, FunctionCall, MethodCall))]
                        for func in orphans:
                            if func.insertion_ref in orphaned_functions:
                                raise Exception(f"Logic error, already have an insertion ID {func.insertion_ref}!")
                            orphaned_functions[func.insertion_ref] = func
                        if stack_leftovers:
                            raise Exception(f"Logic error, reached execution end and have stack entries {stack_leftovers} still!")

                # Verify that we converted all the statements properly.
                for statement in new_statements:
                    if isinstance(statement, IntermediateIf):
                        # Intermediate if conditional (such as a break/return/goto inside
                        # a loop.
                        if not isinstance(statement.parent_action, IfExpr):
                            raise Exception(f"Logic error, found unconverted IntermediateIf {statement}!")

                        if not statement.true_statements and not statement.false_statements:
                            self.vprint(f"Skipping adding if statement {statement} because it is an empty sentinel!")
                        else:
                            statements.append(
                                IfStatement(
                                    statement.parent_action,
                                    statement.true_statements,
                                    statement.false_statements,
                                )
                            )
                    elif isinstance(statement, Statement):
                        # Regular statement.
                        statements.append(statement)
                    else:
                        # We didn't convert a statement properly.
                        raise Exception(f"Logic error, {statement} is not converted!")

            # Go to the next chunk
            if not chunk.next_chunks:
                break
            start_id = chunk.next_chunks[0]

        return statements

    def __walk(self, statements: Sequence[Statement], do: Callable[[Statement], Optional[Statement]]) -> List[Statement]:
        new_statements: List[Statement] = []

        for statement in statements:
            new_statement = do(statement)
            if isinstance(new_statement, DoWhileStatement):
                new_statement.body = self.__walk(new_statement.body, do)
                new_statements.append(new_statement)
            elif isinstance(new_statement, IfStatement):
                new_statement.true_statements = self.__walk(new_statement.true_statements, do)
                new_statement.false_statements = self.__walk(new_statement.false_statements, do)
                new_statements.append(new_statement)
            elif new_statement:
                new_statements.append(new_statement)

        return new_statements

    def __collapse_identical_labels(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find labels that point at gotos, remove them and point the
        # gotos to those labels at the second gotos.
        statements = list(statements)

        def find_labels_and_gotos(statements: Sequence[Statement]) -> Dict[int, int]:
            label_and_goto: Dict[int, int] = {}

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else None
                if (
                    isinstance(cur_statement, DefineLabelStatement) and
                    isinstance(next_statement, GotoStatement)
                ):
                    label_and_goto[cur_statement.location] = next_statement.location

                elif isinstance(cur_statement, DoWhileStatement):
                    label_and_goto.update(find_labels_and_gotos(cur_statement.body))

                elif isinstance(cur_statement, IfStatement):
                    label_and_goto.update(find_labels_and_gotos(cur_statement.true_statements))
                    label_and_goto.update(find_labels_and_gotos(cur_statement.false_statements))

            return label_and_goto

        def reduce_labels_and_gotos(pairs: Dict[int, int]) -> Dict[int, int]:
            changed = True
            while changed:
                changed = False

                for label, goto in pairs.items():
                    if goto in pairs:
                        pairs[label] = pairs[goto]
                        changed = True

            return pairs

        changed: bool = False
        while True:
            redundant_pairs = reduce_labels_and_gotos(find_labels_and_gotos(statements))
            if not redundant_pairs:
                break

            # Whether we change the tree this pass. If not, we should bail.
            updated: bool = False

            def update_gotos(statement: Statement) -> Statement:
                nonlocal updated

                if isinstance(statement, GotoStatement):
                    if statement.location in redundant_pairs:
                        statement.location = redundant_pairs[statement.location]
                        updated = True
                return statement

            statements = self.__walk(statements, update_gotos)
            changed = changed or updated
            if not updated:
                break

        return statements, changed

    def __remove_goto_return(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find labels that point at returns, convert any gotos pointing
        # at them to returns.
        def find_labels(statements: Sequence[Statement], parent_next_statement: Optional[Statement]) -> Set[int]:
            labels: Set[int] = set()

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else parent_next_statement
                if (
                    isinstance(cur_statement, DefineLabelStatement) and
                    isinstance(next_statement, NullReturnStatement)
                ):
                    labels.add(cur_statement.location)

                elif isinstance(cur_statement, DoWhileStatement):
                    labels.update(find_labels(cur_statement.body, next_statement))

                elif isinstance(cur_statement, IfStatement):
                    labels.update(find_labels(cur_statement.true_statements, next_statement))
                    labels.update(find_labels(cur_statement.false_statements, next_statement))

            return labels

        labels = find_labels(statements, None)

        updated: bool = False

        def update_gotos(statement: Statement) -> Statement:
            nonlocal updated

            if isinstance(statement, GotoStatement):
                if statement.location in labels:
                    return NullReturnStatement()
                    updated = True
            return statement

        statements = self.__walk(statements, update_gotos)
        return statements, updated

    def __eliminate_useless_returns(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find returns that are on the "last" line. Basically, any
        # return statement where the next statement is another return statement
        # or the end of a function.
        def find_returns(statements: Sequence[Statement], parent_next_statement: Statement) -> Set[NullReturnStatement]:
            returns: Set[NullReturnStatement] = set()

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else parent_next_statement
                if (
                    isinstance(cur_statement, NullReturnStatement) and
                    isinstance(next_statement, NullReturnStatement)
                ):
                    returns.add(cur_statement)

                elif isinstance(cur_statement, DoWhileStatement):
                    returns.update(find_returns(cur_statement.body, next_statement))

                elif isinstance(cur_statement, IfStatement):
                    returns.update(find_returns(cur_statement.true_statements, next_statement))
                    returns.update(find_returns(cur_statement.false_statements, next_statement))

            return returns

        # Instead of an empty next statement, make up a return so we catch anything
        # without needing multiple conditionals above.
        returns = find_returns(statements, NullReturnStatement())

        updated: bool = False

        def remove_returns(statement: Statement) -> Statement:
            nonlocal updated

            for removable in returns:
                if removable is statement:
                    updated = True
                    return None
            return statement

        statements = self.__walk(statements, remove_returns)
        return statements, updated

    def __remove_useless_gotos(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find gotos that point at the very next line and remove them.
        # This can happen due to the way we analyze if statements.
        statements = list(statements)

        def find_goto_next_line(statements: Sequence[Statement], next_instruction: Statement) -> List[Statement]:
            gotos: List[Statement] = []

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else next_instruction

                if (
                    isinstance(cur_statement, GotoStatement) and
                    isinstance(next_statement, DefineLabelStatement)
                ):
                    if cur_statement.location == next_statement.location:
                        gotos.append(cur_statement)

                elif isinstance(cur_statement, DoWhileStatement):
                    # Loops do not "flow" into the next line, they can only "break" to the next
                    # line. Goto of the next line has already been converted to a "break" statement.
                    gotos.extend(find_goto_next_line(cur_statement.body, NopStatement()))

                elif isinstance(cur_statement, IfStatement):
                    # The next statement for both the if and else body is the next statement we have
                    # looked up, either the next statement in this group of statements, or the next
                    # statement in the parent.
                    gotos.extend(find_goto_next_line(cur_statement.true_statements, next_statement))
                    gotos.extend(find_goto_next_line(cur_statement.false_statements, next_statement))

            return gotos

        # Whether we made at least one substitution.
        changed: bool = False

        while True:
            gotos = find_goto_next_line(statements, NopStatement())
            if not gotos:
                break

            def remove_goto(statement: Statement) -> Optional[Statement]:
                nonlocal changed

                for goto in gotos:
                    if statement is goto:
                        changed = True
                        return None
                return statement

            statements = self.__walk(statements, remove_goto)

        return statements, changed

    def __eliminate_unused_labels(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find labels that nothing is pointing at, and remove them.
        locations: Set[int] = set()

        def find_goto(statement: Statement) -> Statement:
            if isinstance(statement, GotoStatement):
                locations.add(statement.location)
            return statement

        self.__walk(statements, find_goto)
        changed: bool = False

        def remove_label(statement: Statement) -> Optional[Statement]:
            nonlocal changed

            if isinstance(statement, DefineLabelStatement):
                if statement.location not in locations:
                    changed = True
                    return None
            return statement

        return self.__walk(statements, remove_label), changed

    def __eliminate_useless_continues(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Go through and find continues that are on the "last" line of a while. Basically, any
        # continue statement where the next statement is another continue statement or the end
        # of a loop.
        def find_continues(statements: Sequence[Statement], parent_next_statement: Statement) -> Set[ContinueStatement]:
            continues: Set[ContinueStatement] = set()

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else parent_next_statement
                if (
                    isinstance(cur_statement, ContinueStatement) and
                    isinstance(next_statement, ContinueStatement)
                ):
                    continues.add(cur_statement)

                elif isinstance(cur_statement, DoWhileStatement):
                    # Clever hack, where we pretend the next value after the loop is a continue,
                    # because hitting the bottom of a loop is actually a continue.
                    continues.update(find_continues(cur_statement.body, ContinueStatement()))

                elif isinstance(cur_statement, IfStatement):
                    continues.update(find_continues(cur_statement.true_statements, next_statement))
                    continues.update(find_continues(cur_statement.false_statements, next_statement))

            return continues

        # Instead of an empty next statement, make up a return because that's what
        # falling off the end of execution means.
        continues = find_continues(statements, NullReturnStatement())

        updated: bool = False

        def remove_continues(statement: Statement) -> Statement:
            nonlocal updated

            for removable in continues:
                if removable is statement:
                    updated = True
                    return None
            return statement

        statements = self.__walk(statements, remove_continues)
        return statements, updated

    def __is_math(self, expression: Expression, variable: str) -> bool:
        if isinstance(expression, ArithmeticExpression):
            # Okay, let's see if it is any sort of math.
            if expression.op in {"+", "-", "*", "/"}:
                # It is, let's see if one of the two sides contains the
                # variable we care about.
                try:
                    left = object_ref(expression.left, "")
                except Exception:
                    left = None
                try:
                    right = object_ref(expression.right, "")
                except Exception:
                    right = None

                return left == variable or right == variable
        return False

    def __get_increment_variable(self, statement: Statement) -> Optional[str]:
        if isinstance(statement, SetMemberStatement):
            if isinstance(statement.valueref, Expression):
                if self.__is_math(statement.valueref, statement.code_equiv()):
                    return statement.code_equiv()
        if isinstance(statement, StoreRegisterStatement):
            if isinstance(statement.valueref, Expression):
                if self.__is_math(statement.valueref, statement.code_equiv()):
                    return statement.code_equiv()
        if isinstance(statement, SetVariableStatement):
            if isinstance(statement.valueref, Expression):
                if self.__is_math(statement.valueref, statement.code_equiv()):
                    return statement.code_equiv()
        if isinstance(statement, SetLocalStatement):
            if isinstance(statement.valueref, Expression):
                if self.__is_math(statement.valueref, statement.code_equiv()):
                    return statement.code_equiv()
        return None

    def __get_assignment(self, statement: Statement) -> Any:
        if isinstance(statement, SetMemberStatement):
            return statement.valueref
        if isinstance(statement, StoreRegisterStatement):
            return statement.valueref
        if isinstance(statement, SetVariableStatement):
            return statement.valueref
        if isinstance(statement, SetLocalStatement):
            return statement.valueref
        return None

    def __extract_condition(self, possible_if: Statement, required_variable: Optional[str]) -> Tuple[Optional[IfExpr], List[Statement]]:
        if isinstance(possible_if, IfStatement):
            if len(possible_if.true_statements) == 1 and isinstance(possible_if.true_statements[0], BreakStatement):
                # This is possibly a candidate, check the condition's variable usage.
                if isinstance(possible_if.cond, IsUndefinedIf):
                    if required_variable is not None:
                        try:
                            if_variable = object_ref(possible_if.cond.conditional, "")
                        except Exception:
                            if_variable = None
                        if required_variable != if_variable:
                            return None
                    return possible_if.cond, possible_if.false_statements
                elif isinstance(possible_if.cond, IsBooleanIf):
                    if required_variable is not None:
                        try:
                            if_variable = object_ref(possible_if.cond.conditional, "")
                        except Exception:
                            if_variable = None
                        if required_variable != if_variable:
                            return None
                    return possible_if.cond, possible_if.false_statements
                elif isinstance(possible_if.cond, TwoParameterIf):
                    if required_variable is not None:
                        try:
                            if_variable1 = object_ref(possible_if.cond.conditional1, "")
                        except Exception:
                            if_variable1 = None
                        if if_variable1 == required_variable:
                            return possible_if.cond, possible_if.false_statements

                        try:
                            if_variable2 = object_ref(possible_if.cond.conditional2, "")
                        except Exception:
                            if_variable2 = None
                        if if_variable2 == required_variable:
                            return possible_if.cond.swap(), possible_if.false_statements
                    return possible_if.cond, possible_if.false_statements
        return None, []

    def __convert_loops(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Convert any do {} while loops that resemble for statements into actual for statements.
        # First, we need to hoist any increment to the actual end of the loop in case its in the
        # last statement of some if/else condition. This isn't going to be perfectly accurate because
        # there can be all sorts of bizarre for statements, but it should be good enough for most
        # cases to make better code.
        def convert_loops(statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
            new_statements: List[Statement] = []
            updated_statements: Dict[DoWhileStatement, DoWhileStatement] = {}
            changed: bool = False

            for i in range(len(statements)):
                cur_statement = statements[i]
                next_statement = statements[i + 1] if (i < len(statements) - 1) else None

                if isinstance(cur_statement, IfStatement):
                    # Don't care about this, but we need to recursively walk its children.
                    cur_statement.true_statements, new_changed = convert_loops(cur_statement.true_statements)
                    changed = changed or new_changed

                    cur_statement.false_statements, new_changed = convert_loops(cur_statement.false_statements)
                    changed = changed or new_changed

                    new_statements.append(cur_statement)
                elif isinstance(cur_statement, DoWhileStatement):
                    # If we addressed this statement, we should use the new statement instead.
                    for old, new in updated_statements.items():
                        if old is cur_statement:
                            cur_statement = new
                            break

                    if not isinstance(cur_statement, (ForStatement, WhileStatement)):
                        # This might be a candidate for white statement hoisting.
                        if len(cur_statement.body) > 0:
                            # Let's see if the first statement is an if statement with a break.
                            possible_cond, false_body = self.__extract_condition(cur_statement.body[0], None)
                        else:
                            possible_cond = None

                        if possible_cond is not None:
                            # This is a for statement. Let's convert it.
                            cur_statement = WhileStatement(
                                possible_cond.invert(),
                                # Drop the if statement, since we are incorporating it.
                                false_body + cur_statement.body[1:],
                            )
                            changed = True

                    # Need to recursively walk through and perform stuff on the body of this.
                    cur_statement.body, new_changed = convert_loops(cur_statement.body)
                    changed = changed or new_changed

                    new_statements.append(cur_statement)
                elif (
                    isinstance(cur_statement, (SetMemberStatement, StoreRegisterStatement, SetVariableStatement, SetLocalStatement)) and
                    isinstance(next_statement, DoWhileStatement) and
                    not isinstance(next_statement, ForStatement)
                ):
                    # This is a possible conversion that hasn't been converted yet. Let's try to grab
                    # the increment variable.
                    if next_statement.body:
                        inc_variable = self.__get_increment_variable(next_statement.body[-1])
                    else:
                        inc_variable = None

                    # Now that we know what's being incremented, let's see if it matches our
                    # initializer.
                    inc_assignment = None
                    if inc_variable is not None and inc_variable != cur_statement.code_equiv():
                        # This doesn't match, so let's kill our reference.
                        inc_variable = None
                    else:
                        inc_assignment = self.__get_assignment(next_statement.body[-1])

                    if inc_variable is not None:
                        # This is a while statement previously converted, possibly due to
                        # an incomplete increment variable hoisting. We can further convert
                        # it to a for statement, but we need the conditional.
                        if isinstance(next_statement, WhileStatement):
                            possible_cond = next_statement.cond.invert()
                            if isinstance(possible_cond, TwoParameterIf):
                                try:
                                    if_variable = object_ref(possible_cond.conditional2, "")
                                    if inc_variable == if_variable:
                                        possible_cond = possible_cond.swap()
                                except Exception:
                                    pass
                            false_body = []
                        else:
                            # Let's see if the first statement is an if statement with a break.
                            possible_cond, false_body = self.__extract_condition(next_statement.body[0], inc_variable)
                    else:
                        possible_cond = None

                    if inc_variable is not None and possible_cond is not None:
                        # This is a for statement. Let's convert it.
                        updated_statements[next_statement] = ForStatement(
                            inc_variable,
                            self.__get_assignment(cur_statement),
                            possible_cond.invert(),
                            inc_assignment,
                            # Drop the increment and the if statement, since we are incorporating them.
                            false_body + (next_statement.body[:-1] if isinstance(next_statement, WhileStatement) else next_statement.body[1:-1]),
                            local=isinstance(cur_statement, SetLocalStatement),
                        )
                        changed = True
                    else:
                        new_statements.append(cur_statement)
                else:
                    # Don't care about this one, just append it.
                    new_statements.append(cur_statement)

            return new_statements, changed

        return convert_loops(statements)

    def __swap_empty_ifs(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # Get rid of empty if statements. If statements with empty if bodies and nonempty
        # else bodies will also be swapped.
        changed: bool = False
        updated: bool = False

        def swap_empty_ifs(statement: Statement) -> Optional[Statement]:
            nonlocal changed
            nonlocal updated

            if isinstance(statement, IfStatement):
                if statement.false_statements and (not statement.true_statements):
                    # Swap this, invert the conditional
                    changed = True
                    updated = True
                    return IfStatement(
                        statement.cond.invert(),
                        statement.false_statements,
                        statement.true_statements,
                    )
                elif (not statement.true_statements) and (not statement.false_statements):
                    # Drop the if, it has no body.
                    changed = True
                    updated = True
                    return None
            return statement

        while True:
            changed = False
            statements = self.__walk(statements, swap_empty_ifs)
            if not changed:
                return statements, updated

    def __drop_unneeded_else(self, statements: Sequence[Statement]) -> Tuple[List[Statement], bool]:
        # If an if has an else, but the last line of the if is a break/continue/return/throw/goto
        # then the else body doesn't need to exist, so hoist it up into the parent. If the false
        # statement also has an exit condition, don't drop it for asthetics.
        def update_ifs(statements: Sequence[Statement], in_loop: bool) -> Tuple[List[Statement], bool]:
            new_statements: List[Statement] = []
            changed: bool = False

            for statement in statements:
                if isinstance(statement, IfStatement):
                    if (
                        statement.true_statements and
                        statement.false_statements and
                        isinstance(
                            statement.true_statements[-1],
                            (BreakStatement, ContinueStatement, ReturnStatement, NullReturnStatement, ThrowStatement, GotoStatement),
                        ) and
                        not isinstance(
                            statement.false_statements[-1],
                            (BreakStatement, ContinueStatement, ReturnStatement, NullReturnStatement, ThrowStatement, GotoStatement),
                        )
                    ):
                        # We need to walk both halves still, but once we're done, hoist the false
                        # statements up to our level.
                        statement.true_statements, new_changed = update_ifs(statement.true_statements, in_loop)
                        changed = changed or new_changed

                        new_false_statements, new_changed = update_ifs(statement.false_statements, in_loop)
                        changed = changed or new_changed
                        statement.false_statements = []

                        # Now, append the if statement, and follow up with the body.
                        new_statements.append(statement)
                        new_statements.extend(new_false_statements)
                    else:
                        statement.true_statements, new_changed = update_ifs(statement.true_statements, in_loop)
                        changed = changed or new_changed

                        statement.false_statements, new_changed = update_ifs(statement.false_statements, in_loop)
                        changed = changed or new_changed

                        new_statements.append(statement)
                elif isinstance(statement, DoWhileStatement):
                    # Need to recursively walk through and perform stuff on the body of this.
                    statement.body, new_changed = update_ifs(statement.body, in_loop=True)
                    changed = changed or new_changed

                    new_statements.append(statement)
                else:
                    # Don't care about this one, just append it.
                    new_statements.append(statement)

            return new_statements, changed

        return update_ifs(statements, in_loop=False)

    def __verify_balanced_labels(self, statements: Sequence[Statement]) -> None:
        gotos: Set[int] = set()
        labels: Set[int] = set()

        # Gather gotos and labels and make sure they're balanced.
        def gather_gotos_and_labels(statement: Statement) -> Optional[Statement]:
            nonlocal gotos
            nonlocal labels

            if isinstance(statement, GotoStatement):
                gotos.add(statement.location)
            elif isinstance(statement, DefineLabelStatement):
                labels.add(statement.location)
            return statement

        self.__walk(statements, gather_gotos_and_labels)

        unmatched_gotos = gotos - labels
        unmatched_labels = labels - gotos

        if unmatched_gotos:
            formatted_labels = ", ".join(f"label_{x}" for x in unmatched_gotos)
            raise Exception(f"Logic error, gotos found jumping to the following labels which don't exist: {formatted_labels}")
        if unmatched_labels and self.optimize:
            formatted_labels = ", ".join(f"label_{x}" for x in unmatched_labels)
            raise Exception(f"Logic error, labels found with no gotos pointing at them: {formatted_labels}")

    def __verify_no_empty_ifs(self, statements: Sequence[Statement]) -> None:
        def check_ifs(statement: Statement) -> Optional[Statement]:
            if isinstance(statement, IfStatement):
                if (not statement.true_statements) and (not statement.false_statements):
                    raise Exception(f"If statement {statement} has no true or false statements inside it!")
            return statement

        self.__walk(statements, check_ifs)

    def __pretty_print(self, statements: Sequence[Statement], prefix: str = "") -> str:
        output: List[str] = []

        for statement in statements:
            output.extend(statement.render(prefix, verbose=self.verbose))

        return os.linesep.join(output)

    def __decompile(self) -> None:
        # First, we need to construct a control flow graph.
        self.vprint("Generating control flow graph...")
        chunks, offset_map = self.__graph_control_flow(self.bytecode)
        start_id = offset_map[self.bytecode.start_offset]

        # Now, compute dominators so we can locate back-refs.
        self.vprint("Generating dominator list...")
        dominators = self.__compute_dominators(start_id, chunks)

        # Now, separate chunks out into chunks and loops.
        self.vprint("Identifying and separating loops...")
        chunks_and_loops = self.__separate_loops(start_id, chunks, dominators, offset_map)

        # Now, break the graph anywhere where we have control
        # flow that ends the execution (return, throw, goto end).
        self.vprint("Breaking control flow graph on non-returnable statements...")
        self.__break_graph(chunks_and_loops, offset_map)

        # Now, identify any remaining control flow logic.
        self.vprint("Identifying and separating ifs...")
        chunks_loops_and_ifs = self.__separate_ifs(start_id, None, chunks_and_loops, offset_map)

        # At this point, we *should* have a directed graph where there are no
        # backwards refs and every fork has been identified as an if. This means
        # we can now walk and recursively generate pseudocode in one pass.
        self.vprint("Cleaning up and checking graph...")
        chunks_loops_and_ifs = self.__check_graph(start_id, chunks_loops_and_ifs)

        # Now, its safe to start actually evaluating the stack.
        statements = self.__eval_chunks(start_id, chunks_loops_and_ifs, offset_map)

        # Now, let's do some clean-up passes.
        if self.optimize:
            while True:
                any_changed = False
                for func in [
                    self.__collapse_identical_labels,
                    self.__eliminate_useless_continues,
                    self.__eliminate_unused_labels,
                    self.__remove_useless_gotos,
                    self.__remove_goto_return,
                    self.__eliminate_useless_returns,
                    self.__convert_loops,
                    self.__swap_empty_ifs,
                    self.__drop_unneeded_else,
                ]:
                    statements, changed = func(statements)
                    any_changed = any_changed or changed

                if not any_changed:
                    break

        # TODO: There's definitely a lot missing from this decompilation process.
        # For one, function definitions do not include any mention of number of
        # arguments. It appears that functions take arguments in the registers
        # and when you call a function/method, the values that are popped from
        # the stack for the function/method call are placed into registers for the
        # function itself to access. However, there's some implicit parameters such
        # as "_this" which is even checked for in some Bishi code. Ideally the code
        # can be cross-referenced with function calls to determine the number of
        # arguments and the decompilation can be improved in that regard, but we
        # would need to nail down function call semantics better. The TRACE opcode
        # is still active in Bishi and its output can be coaxed to appear in stdout
        # so it would be possible to craft some bytecode and print out the register
        # contents in a function call to nail this down, but it is left as a future
        # enhancement.

        # TODO: If statements still don't support compound or properly, and resort
        # to using nasty gotos. We have a prototype of an algorithm above with its
        # own TODO section that can possibly fix this, but I haven't taken the time
        # to try to fix it up and integrate it. It would produde far more readable
        # code in some instances. We also would probably want to collapse some really
        # long if chains to swithc statements or if/elif/else blocks for readability
        # but that is also left as a future enhancement.

        # Let's sanity check the code for a few things that might trip us up.
        self.__verify_balanced_labels(statements)
        self.__verify_no_empty_ifs(statements)

        # Finally, let's save the code!
        self.__statements = statements

    def as_string(self, prefix: str = "", verbose: bool = False) -> str:
        with self.debugging(verbose):
            code = self.__pretty_print(self.statements, prefix=prefix)
            self.vprint(f"Final code:{os.linesep}{code}")
            return code

    def decompile(self, verbose: bool = False) -> None:
        with self.debugging(verbose):
            if self.bytecode.start_offset is None:
                self.vprint("ByteCode is empty, decompiling to nothing!")
                self.__statements = []
            else:
                self.__decompile()
