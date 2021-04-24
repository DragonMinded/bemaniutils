import os
from typing import Any, Dict, List, Sequence, Tuple, Set, Union, Optional, Callable, cast

from .types import (
    AP2Action,
    JumpAction,
    IfAction,
    PushAction,
    AddNumVariableAction,
    Expression,
    Register,
    GenericObject,
    StringConstant,
    StoreRegisterAction,
    DefineFunction2Action,
)
from .util import VerboseOutput


class ByteCode:
    # A list of bytecodes to execute.
    def __init__(self, actions: Sequence[AP2Action], end_offset: int) -> None:
        self.actions = list(actions)
        self.end_offset = end_offset

    def as_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if kwargs.get('decompile_bytecode', False):
            decompiler = ByteCodeDecompiler(self)
            code = decompiler.decompile(verbose=True)

            return {
                'code': code,
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
            raise Exception(f"This ControlFlow does not contain offset {offset}")

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
    def render(self, prefix: str) -> List[str]:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement render()!")


def object_ref(obj: Any) -> str:
    if isinstance(obj, (GenericObject, Variable, Member)):
        return obj.render(nested=True)
    else:
        raise Exception(f"Unsupported objectref {obj} ({type(obj)})")


def value_ref(param: Any, parens: bool = False) -> str:
    if isinstance(param, Expression):
        return param.render(nested=parens)
    elif isinstance(param, (str, int, float)):
        return repr(param)
    else:
        raise Exception(f"Unsupported valueref {param} ({type(param)})")


def name_ref(param: Any) -> str:
    if isinstance(param, str):
        return param
    elif isinstance(param, StringConstant):
        return param.render()
    else:
        raise Exception(f"Unsupported nameref {param} ({type(param)})")


ArbitraryOpcode = Union[AP2Action, ConvertedAction]


class DefineLabelStatement(Statement):
    def __init__(self, location: int) -> None:
        self.location = location

    def render(self, prefix: str) -> List[str]:
        return [f"label_{self.location}:"]


class BreakStatement(Statement):
    # A break from a loop (forces execution to the next line after the loop).
    def __repr__(self) -> str:
        return "break"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}break;"]


class ContinueStatement(Statement):
    # A continue in a loop (forces execution to the top of the loop).
    def __repr__(self) -> str:
        return "continue"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}continue;"]


class GotoStatement(Statement):
    # A goto, including the ID of the chunk we want to jump to.
    def __init__(self, location: int) -> None:
        self.location = location

    def __repr__(self) -> str:
        return f"goto label_{self.location}"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}goto label_{self.location};"]


class NullReturnStatement(Statement):
    # A statement which directs the control flow to the end of the code, but
    # does not pop the stack to return
    def __repr__(self) -> str:
        return "return"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}return;"]


class NopStatement(Statement):
    # A literal no-op. We will get rid of these in an optimizing pass.
    def __repr__(self) -> str:
        return "nop"

    def render(self, prefix: str) -> List[str]:
        # We should never render this!
        raise Exception("Logic error!")


class ExpressionStatement(Statement):
    # A statement which is an expression that discards its return.
    def __init__(self, expr: Expression) -> None:
        self.expr = expr

    def __repr__(self) -> str:
        return f"{self.expr.render()}"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}{self.expr.render()};"]


class StopMovieStatement(Statement):
    # Stop the movie, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StopPlaying()"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}builtin_StopPlaying();"]


class PlayMovieStatement(Statement):
    # Play the movie, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StartPlaying()"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}builtin_StartPlaying();"]


class ArithmeticExpression(Expression):
    def __init__(self, left: Any, op: str, right: Any) -> None:
        self.left = left
        self.op = op
        self.right = right

    def __repr__(self) -> str:
        left = value_ref(self.left, parens=True)
        right = value_ref(self.right, parens=True)
        return f"{left} {self.op} {right}"

    def render(self, nested: bool = False) -> str:
        left = value_ref(self.left, parens=True)
        right = value_ref(self.right, parens=True)
        return f"{left} {self.op} {right}"


class FunctionCall(Expression):
    # Call a method on an object.
    def __init__(self, name: Union[str, StringConstant], params: List[Any]) -> None:
        self.name = name
        self.params = params

    def __repr__(self) -> str:
        return self.render()

    def render(self, nested: bool = False) -> str:
        name = name_ref(self.name)
        params = [value_ref(param) for param in self.params]
        return f"{name}({', '.join(params)})"


class MethodCall(Expression):
    # Call a method on an object.
    def __init__(self, objectref: Any, name: Union[str, StringConstant], params: List[Any]) -> None:
        self.objectref = objectref
        self.name = name
        self.params = params

    def __repr__(self) -> str:
        return self.render()

    def render(self, nested: bool = False) -> str:
        obj = object_ref(self.objectref)
        name = name_ref(self.name)
        params = [value_ref(param) for param in self.params]
        return f"{obj}.{name}({', '.join(params)})"


class NewFunction(Expression):
    # Create a new function.
    def __init__(self, funcname: Optional[str], flags: int, body: ByteCode) -> None:
        self.funcname = funcname
        self.flags = flags
        self.body = body

    def __repr__(self) -> str:
        return self.render()

    def render(self, nested: bool = False) -> str:
        val = f"new function({repr(self.funcname) or '<anonymous function>'}, {hex(self.flags)}, 'TODO: ByteCode')"
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
        return self.render()

    def render(self, nested: bool = False) -> str:
        objname = name_ref(self.objname)
        params = [value_ref(param) for param in self.params]
        val = f"new {objname}({', '.join(params)})"
        if nested:
            return f"({val})"
        else:
            return val


class SetMemberStatement(Statement):
    # Call a method on an object.
    def __init__(self, objectref: Any, name: Union[str, Expression], valueref: Any) -> None:
        self.objectref = objectref
        self.name = name
        self.valueref = valueref

    def __repr__(self) -> str:
        try:
            ref = object_ref(self.objectref)
            name = name_ref(self.name)
            val = value_ref(self.valueref)
            return f"{ref}.{name} = {val}"
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref)
            name = value_ref(self.name)
            val = value_ref(self.valueref)
            return f"{ref}[{name}] = {val}"

    def render(self, prefix: str) -> List[str]:
        try:
            ref = object_ref(self.objectref)
            name = name_ref(self.name)
            val = value_ref(self.valueref)
            return [f"{prefix}{ref}.{name} = {val};"]
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref)
            name = value_ref(self.name)
            val = value_ref(self.valueref)
            return [f"{prefix}{ref}[{name}] = {val};"]


class DeleteVariableStatement(Statement):
    # Call a method on an object.
    def __init__(self, name: Union[str, StringConstant]) -> None:
        self.name = name

    def __repr__(self) -> str:
        name = name_ref(self.name)
        return f"del {name}"

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name)
        return [f"{prefix}delete {name};"]


class StoreRegisterStatement(Statement):
    # Set a variable to a value.
    def __init__(self, register: Register, valueref: Any) -> None:
        self.register = register
        self.valueref = valueref

    def __repr__(self) -> str:
        val = value_ref(self.valueref)
        return f"{self.register.render()} = {val}"

    def render(self, prefix: str) -> List[str]:
        val = value_ref(self.valueref)
        return [f"{prefix}{self.register.render()} = {val};"]


class SetVariableStatement(Statement):
    # Set a variable to a value.
    def __init__(self, name: Union[str, StringConstant], valueref: Any) -> None:
        self.name = name
        self.valueref = valueref

    def __repr__(self) -> str:
        name = name_ref(self.name)
        val = value_ref(self.valueref)
        return f"{name} = {val}"

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name)
        val = value_ref(self.valueref)
        return [f"{prefix}{name} = {val};"]


class SetLocalStatement(Statement):
    # Define a local variable with a value.
    def __init__(self, name: Union[str, StringConstant], valueref: Any) -> None:
        self.name = name
        self.valueref = valueref

    def __repr__(self) -> str:
        name = name_ref(self.name)
        val = value_ref(self.valueref)
        return f"local {name} = {val}"

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name)
        val = value_ref(self.valueref)
        return [f"{prefix}local {name} = {val};"]


class IfExpr(ConvertedAction):
    # This is just for typing.
    pass


class IsUndefinedIf(IfExpr):
    def __init__(self, conditional: Any, negate: bool) -> None:
        self.conditional = conditional
        self.negate = negate

    def __repr__(self) -> str:
        val = value_ref(self.conditional, parens=True)
        if self.negate:
            return f"if ({val} is not UNDEFINED)"
        else:
            return f"if ({val} is UNDEFINED)"


class IsBooleanIf(IfExpr):
    def __init__(self, conditional: Any, negate: bool) -> None:
        self.conditional = conditional
        self.negate = negate

    def __repr__(self) -> str:
        val = value_ref(self.conditional, parens=True)
        if self.negate:
            return f"if ({val} is False)"
        else:
            return f"if ({val} is True)"


class IsEqualIf(IfExpr):
    def __init__(self, conditional1: Any, conditional2: Any, negate: bool) -> None:
        self.conditional1 = conditional1
        self.conditional2 = conditional2
        self.negate = negate

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, parens=True)
        val2 = value_ref(self.conditional2, parens=True)
        return f"if ({val1} {'!=' if self.negate else '=='} {val2})"


class IsStrictEqualIf(IfExpr):
    def __init__(self, conditional1: Any, conditional2: Any, negate: bool) -> None:
        self.conditional1 = conditional1
        self.conditional2 = conditional2
        self.negate = negate

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, parens=True)
        val2 = value_ref(self.conditional2, parens=True)
        return f"if ({val1} {'!==' if self.negate else '==='} {val2})"


class MagnitudeIf(IfExpr):
    def __init__(self, conditional1: Any, conditional2: Any, negate: bool) -> None:
        self.conditional1 = conditional1
        self.conditional2 = conditional2
        self.negate = negate

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, parens=True)
        val2 = value_ref(self.conditional2, parens=True)
        return f"if ({val1} {'<' if self.negate else '>'} {val2})"


class MagnitudeEqualIf(IfExpr):
    def __init__(self, conditional1: Any, conditional2: Any, negate: bool) -> None:
        self.conditional1 = conditional1
        self.conditional2 = conditional2
        self.negate = negate

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, parens=True)
        val2 = value_ref(self.conditional2, parens=True)
        return f"if ({val1} {'<=' if self.negate else '>='} {val2})"


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
                f"{self.cond} {{",
                os.linesep.join(true_entries),
                "} else {",
                os.linesep.join(false_entries),
                "}"
            ])
        else:
            return os.linesep.join([
                f"{self.cond} {{",
                os.linesep.join(true_entries),
                "}"
            ])

    def render(self, prefix: str) -> List[str]:
        true_entries: List[str] = []
        for statement in self.true_statements:
            true_entries.extend(statement.render(prefix=prefix + "    "))

        false_entries: List[str] = []
        for statement in self.false_statements:
            false_entries.extend(statement.render(prefix=prefix + "    "))

        if false_entries:
            return [
                f"{prefix}{self.cond}",
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
                f"{prefix}{self.cond}",
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
            "} while(True);"
        ])

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    "))

        return [
            f"{prefix}do",
            f"{prefix}{{",
            *entries,
            f"{prefix}}} while(True);",
        ]


class IntermediateIf(ConvertedAction):
    def __init__(self, parent_action: IfAction, true_statements: Sequence[Statement], false_statements: Sequence[Statement], negate: bool) -> None:
        self.parent_action = parent_action
        self.true_statements = list(true_statements)
        self.false_statements = list(false_statements)
        self.negate = negate

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for action in self.true_statements:
            true_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        false_entries: List[str] = []
        for action in self.false_statements:
            false_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        if self.false_statements:
            return os.linesep.join([
                f"if <{'!' if self.negate else ''}{self.parent_action}> {{",
                os.linesep.join(true_entries),
                "} else {",
                os.linesep.join(false_entries),
                "}"
            ])
        else:
            return os.linesep.join([
                f"if <{'!' if self.negate else ''}{self.parent_action}> {{",
                os.linesep.join(true_entries),
                "}"
            ])


class ByteCodeChunk:
    def __init__(self, id: int, actions: Sequence[ArbitraryOpcode], next_chunks: List[int], previous_chunks: List[int] = []) -> None:
        self.id = id
        self.actions = list(actions)
        self.next_chunks = next_chunks
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
    def __init__(self, id: int, true_chunks: Sequence[ArbitraryCodeChunk], false_chunks: Sequence[ArbitraryCodeChunk], next_chunk: Optional[int], previous_chunk: int, negate: bool) -> None:
        # The ID in this case is what the previous block points at. It does not
        # have any bearing on the ID of the true and false chunks.
        self.id = id

        # If bodies are a bit special compared to Loops, we know the previous and next chunks
        # for all of them.
        self.previous_chunks: List[int] = [previous_chunk]
        self.next_chunks: List[int] = [next_chunk] if next_chunk is not None else []
        self.true_chunks = list(true_chunks)
        self.false_chunks = list(false_chunks)
        self.negate = negate

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for chunk in self.true_chunks:
            true_entries.extend([f"    {s}" for s in str(chunk).split(os.linesep)])

        false_entries: List[str] = []
        for chunk in self.false_chunks:
            false_entries.extend([f"    {s}" for s in str(chunk).split(os.linesep)])

        return (
            f"IfBody({os.linesep}" +
            f"  Negated: {self.negate}{os.linesep}" +
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
        return f"Variable({name_ref(self.name)})"

    def render(self, nested: bool = False) -> str:
        return name_ref(self.name)


class Member(Expression):
    def __init__(self, objectref: Any, member: Union[str, Expression]) -> None:
        self.objectref = objectref
        self.member = member

    def __repr__(self) -> str:
        return self.render()

    def render(self, nested: bool = False) -> str:
        try:
            member = name_ref(self.member)
            ref = object_ref(self.objectref)
            return f"{ref}.{member}"
        except Exception:
            # This is not a simple string object reference.
            member = value_ref(self.member)
            ref = object_ref(self.objectref)
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
        self.__bits[bit] = True
        return self

    def clearBit(self, bit: int) -> "BitVector":
        self.__bits[bit] = False
        return self

    def orVector(self, other: "BitVector") -> "BitVector":
        if len(self.__bits) != len(other.__bits):
            raise Exception("Cannot or different-sized bitvectors!")
        self.__bits = {i: (self.__bits[i] or other.__bits[i]) for i in self.__bits}
        return self

    def andVector(self, other: "BitVector") -> "BitVector":
        if len(self.__bits) != len(other.__bits):
            raise Exception("Cannot and different-sized bitvectors!")
        self.__bits = {i: (self.__bits[i] and other.__bits[i]) for i in self.__bits}
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BitVector):
            return NotImplemented
        if len(self.__bits) != len(other.__bits):
            raise Exception("Cannot compare different-sized bitvectors!")

        for i in self.__bits:
            if self.__bits[i] != other.__bits[i]:
                return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    @property
    def bitsSet(self) -> Set[int]:
        return {i for i in self.__bits if self.__bits[i]}


class ByteCodeDecompiler(VerboseOutput):
    def __init__(self, bytecode: ByteCode, main: bool = True) -> None:
        super().__init__()

        self.bytecode = bytecode
        self.main = main

    def __graph_control_flow(self) -> Tuple[List[ByteCodeChunk], Dict[int, int]]:
        # Start by assuming that the whole bytecode never directs flow. This is, confusingly,
        # indexed by AP2Action offset, not by actual bytecode offset, so we can avoid the
        # prickly problem of opcodes that take more than one byte in the data.
        flows: Dict[int, ControlFlow] = {}
        end = len(self.bytecode.actions)
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

            raise Exception(f"Offset {opcodeno} somehow not in our control flow graph!")

        # Now, walk the entire bytecode, and every control flow point split the graph at that point.
        for i, action in enumerate(self.bytecode.actions):
            current_action = i
            next_action = i + 1

            if action.opcode in [AP2Action.THROW, AP2Action.RETURN]:
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
                for j, dest in enumerate(self.bytecode.actions):
                    if dest.offset == action.jump_offset:
                        dest_action = j
                        break
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
                for j, dest in enumerate(self.bytecode.actions):
                    if dest.offset == action.jump_if_true_offset:
                        dest_action = j
                        break
                else:
                    raise Exception(f"{action} conditional jumps to an opcode that doesn't exist!")

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
                raise Exception("Logic error!")

        # Finally, return chunks of contiguous execution.
        chunks: List[ByteCodeChunk] = []
        chunkid: int = 0
        for start, flow in flows.items():
            if start == end:
                # We don't want to render out the end of the graph, it was only there to make
                # the above algorithm easier.
                continue

            if len(flow.next_flow) == 1 and flow.next_flow[0] == end:
                # This flow is a termination state.
                chunks.append(ByteCodeChunk(chunkid, self.bytecode.actions[flow.beginning:flow.end], []))
                chunkid += 1
            else:
                next_chunks: List[int] = []
                for ano in flow.next_flow:
                    if ano == end:
                        raise Exception("Logic error!")
                    next_chunks.append(self.bytecode.actions[ano].offset)
                chunks.append(ByteCodeChunk(chunkid, self.bytecode.actions[flow.beginning:flow.end], next_chunks))
                chunkid += 1

        # Calculate who points to us as well, for posterity.
        entries: Dict[int, List[int]] = {}
        offset_to_id: Dict[int, int] = {}
        for chunk in chunks:
            # We haven't emitted any non-AP2Actions yet, so we are safe in casting here.
            chunk_offset = cast(AP2Action, chunk.actions[0]).offset
            offset_to_id[chunk_offset] = chunk.id
            for next_chunk in chunk.next_chunks:
                entries[next_chunk] = entries.get(next_chunk, []) + [chunk_offset]

        for chunk in chunks:
            # We haven't emitted any non-AP2Actions yet, so we are safe in casting here.
            chunk_offset = cast(AP2Action, chunk.actions[0]).offset
            chunk.previous_chunks = entries.get(chunk_offset, [])

        # Now, convert the offsets to chunk ID pointers.
        end_previous_chunks: List[int] = []
        for chunk in chunks:
            if chunk.next_chunks:
                # Normal chunk.
                chunk.next_chunks = [offset_to_id[c] for c in chunk.next_chunks]
            else:
                # Point this chunk at the end of bytecode sentinel.
                chunk.next_chunks = [chunkid]
                end_previous_chunks.append(chunk.id)
            chunk.previous_chunks = [offset_to_id[c] for c in chunk.previous_chunks]

        # Add the "return" chunk now that we've converted everything.
        chunks.append(ByteCodeChunk(chunkid, [], [], previous_chunks=end_previous_chunks))
        offset_to_id[self.bytecode.end_offset] = chunkid

        return (sorted(chunks, key=lambda c: c.id), offset_to_id)

    def __get_entry_block(self, chunks: Sequence[ArbitraryCodeChunk]) -> int:
        start_id: int = -1
        for chunk in chunks:
            if not chunk.previous_chunks:
                if start_id != -1:
                    # This should never happen, we have one entrypoint. If we run into
                    # this we might need to do dead code analysis and discarding.
                    raise Exception("Logic error!")
                start_id = chunk.id

        if start_id == -1:
            # We should never get to this as we always have at least one entrypoint.
            raise Exception("Logic error!")
        return start_id

    def __compute_dominators(self, chunks: Sequence[ByteCodeChunk]) -> Dict[int, Set[int]]:
        # Find the start of the graph (the node with no previous entries).
        start_id = self.__get_entry_block(chunks)

        # Compute dominators recursively
        chunklen = len(chunks)
        dominators: Dict[int, BitVector] = {chunk.id: BitVector(chunklen, init=True) for chunk in chunks}
        dominators[start_id].setAllBitsTo(False).setBit(start_id)

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
            raise Exception("Logic error!")
        header_chunk = header_chunks[0]

        # Identify external jumps from the header.
        break_points = [i for i in header_chunk.next_chunks if i not in internal_jump_points]
        if len(break_points) > 1:
            # We should not have two exits here, if so this isn't a loop!
            raise Exception("Logic error!")

        # Identify the break and continue jump points.
        if not break_points:
            # This might be possible, but I don't know how to deal with it.
            raise Exception("Logic error!")
        break_point = break_points[0]
        continue_point = header_chunk.id

        self.vprint(f"Loop breaks to {break_point} and continues to {continue_point}")

        # Now, go through each chunk, identify whether it has an if, and fix up the
        # if statements.
        for chunk in loop.chunks:
            if not chunk.next_chunks:
                # All chunks need a next chunk of some type, the only one that doesn't
                # is the end chunk which should never be part of a loop.
                raise Exception("Logic error!")
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
                        raise Exception("Logic error!")
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
                    true_jump_point = offset_map[cast(IfAction, last_action).jump_if_true_offset]
                    false_jump_points = [n for n in chunk.next_chunks if n != true_jump_point]
                    if len(false_jump_points) != 1:
                        raise Exception("Logic error!")
                    false_jump_point = false_jump_points[0]

                    # Calculate true and false jump points, see if they are break/continue/goto.
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
                        if true_jump_point == offset_map[self.bytecode.end_offset]:
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
                        if false_jump_point == offset_map[self.bytecode.end_offset]:
                            self.vprint("Converting jump if false to external point into return statement.")
                            false_action = NullReturnStatement()
                        else:
                            self.vprint("Converting jump if false to external point into goto statement.")
                            false_action = GotoStatement(false_jump_point)
                        chunk.next_chunks = [n for n in chunk.next_chunks if n != false_jump_point]

                    if true_action is None and false_action is not None:
                        true_action = false_action
                        false_action = None
                        negate = True
                    else:
                        negate = False

                    if true_action is None and false_action is None:
                        # This is an internal-only if statement, we don't care.
                        continue

                    chunk.actions[-1] = IntermediateIf(
                        cast(IfAction, last_action),
                        [true_action],
                        [false_action] if false_action else [],
                        negate=negate,
                    )
                    continue

        # Now, we have converted all external jumps to either break or goto, so we don't
        # need to keep track of the next chunk aside from the break location.
        loop.next_chunks = [break_point]

        return loop

    def __separate_loops(self, chunks: Sequence[ByteCodeChunk], dominators: Dict[int, Set[int]], offset_map: Dict[int, int]) -> List[Union[ByteCodeChunk, Loop]]:
        # Find the start of the graph (the node with no previous entries).
        start_id = self.__get_entry_block(chunks)
        chunks_by_id: Dict[int, Union[ByteCodeChunk, Loop]] = {chunk.id: chunk for chunk in chunks}

        # Go through and gather up all loops in the chunks.
        loops: Dict[int, Set[int]] = {}
        for chunk in chunks:
            if chunk.id == start_id:
                continue

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

                    # We found a loop!
                    if header in loops:
                        raise Exception("Logic error!")
                    loops[header] = blocks

        # Now, we need to reduce our list of chunks down to non-loops only. We do this
        # by recursively trying to find inner loops until we find a loop that has no
        # inner loops, and converting that. Once we do that, we remove the chunks from
        # our list, add it to that new loop, and convert all other loops that might
        # reference it to point at the loop instead.
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
                    chunks_by_id[header] = new_loop

                    # These blocks are now part of the loop, so we need to remove them
                    # from the IDed chunks as well as from existing loops.
                    delete_blocks = {block for block in blocks if block != header}
                    delete_header = header
                    break

            if delete_header is None:
                # We must find at LEAST one loop that has no inner loops of its own.
                raise Exception("Logic error!")

            # Remove this loop from the processing list
            del loops[delete_header]

            # Go through and remove the rest of the chunks from the rest of the loops
            loops = {header: {block for block in blocks if block not in delete_blocks} for (header, blocks) in loops.items()}

            # Also remove the rest of the chunks from our IDed chunks as they are part of this loop now.
            for block in delete_blocks:
                del chunks_by_id[block]

            # Verify that we don't have any existing chunks that point at the non-header portion of the loop.
            for _, chunk_or_loop in chunks_by_id.items():
                for nextid in chunk_or_loop.next_chunks:
                    if nextid in delete_blocks:
                        # Woah, we point at a chunk inside this loop that isn't the header!
                        raise Exception("Logic error!")

        return [chunks_by_id[i] for i in chunks_by_id]

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
                    if last_action.opcode in [AP2Action.THROW, AP2Action.RETURN]:
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
                            self.vprint(f"Converting fall-through to end of code in {chunk.id} into a null return.")
                            chunk.actions.append(NullReturnStatement())
                        chunk.next_chunks = []

    def __find_shallowest_successor(self, start_chunk: int, chunks_by_id: Dict[int, ArbitraryCodeChunk]) -> Optional[int]:
        if len(chunks_by_id[start_chunk].next_chunks) != 2:
            # We don't care about this, the successor is the next chunk!
            raise Exception("Logic error!")

        left, right = chunks_by_id[start_chunk].next_chunks
        visited: Set[int] = set()

        # First, let's find all the successors to the left side.
        candidates: List[int] = [left]
        while candidates:
            for candidate in candidates:
                visited.add(candidate)

            new_candidates = []
            for candidate in candidates:
                # We can avoid re-traversing what we've already traversed, as we only want to color
                # in the part of the tree that we're interested in.
                new_candidates.extend([c for c in chunks_by_id[candidate].next_chunks if c not in visited])
            candidates = new_candidates

        # Now, lets do the same with the right, and the first one we encounter that's visited is our guy.
        candidates = [right]
        while candidates:
            for candidate in candidates:
                if candidate in visited:
                    return candidate

            new_candidates = []
            for candidate in candidates:
                # We can't take the same shortcut here as above, as we are trying to ask the question
                # of what's the shallowest successor, not color them in.
                new_candidates.extend(chunks_by_id[candidate].next_chunks)
            candidates = new_candidates

        # If we didn't find a successor, that means one of the control paths leads to end of execution.
        return None

    def __gather_chunks(self, start_chunk: int, end_chunk: Optional[int], chunks_by_id: Dict[int, ArbitraryCodeChunk]) -> List[ArbitraryCodeChunk]:
        visited: Set[int] = set()
        chunks: List[ArbitraryCodeChunk] = []
        candidates: List[int] = [start_chunk]

        while candidates:
            first_candidate = candidates.pop()
            if first_candidate in visited:
                # We already visited this node.
                continue

            if end_chunk is None or first_candidate != end_chunk:
                chunks.append(chunks_by_id[first_candidate])
                visited.add(first_candidate)
                candidates.extend(chunks_by_id[first_candidate].next_chunks)

        # The chunk list is all chunks that belong in this sequence. Now, kill any pointers to the end chunk.
        for chunk in chunks:
            if end_chunk is not None:
                chunk.next_chunks = [n for n in chunk.next_chunks if n != end_chunk]
            if chunk.id == start_chunk:
                chunk.previous_chunks = []

        return chunks

    def __separate_ifs(self, start_id: int, chunks: Sequence[ArbitraryCodeChunk], offset_map: Dict[int, int]) -> List[ArbitraryCodeChunk]:
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        cur_id = start_id

        self.vprint(f"Separating if statements out of graph starting at {start_id}")

        while True:
            cur_chunk = chunks_by_id[cur_id]
            if isinstance(cur_chunk, Loop):
                self.vprint(f"Examining loop {cur_chunk.id} body for if statements...")
                cur_chunk.chunks = self.__separate_ifs(cur_chunk.id, cur_chunk.chunks, offset_map)
                self.vprint(f"Finished examining loop {cur_chunk.id} body for if statements...")

            if not chunks_by_id[cur_id].next_chunks:
                # We're done!
                break

            if len(chunks_by_id[cur_id].next_chunks) == 1:
                if not isinstance(cur_chunk, ByteCodeChunk):
                    # This is an already-handled loop or if, don't bother checking for
                    # if-goto patterns.
                    cur_id = chunks_by_id[cur_id].next_chunks[0]
                    continue

                last_action = cur_chunk.actions[-1]
                if not isinstance(last_action, IfAction):
                    # This is just a goto/chunk, move on to the next one.
                    cur_id = chunks_by_id[cur_id].next_chunks[0]
                    continue

                # This is an if with a goto in the true clause. Verify that and
                # then convert it.
                jump_offset = offset_map[last_action.jump_if_true_offset]
                if jump_offset == chunks_by_id[cur_id].next_chunks[0]:
                    # We have an if that goes to the next chunk on true, so we've
                    # lost the false path. This is a problem.
                    raise Exception("Logic error!")

                # Conver this to an if-goto statement, much like we do in loops.
                cur_chunk.actions[-1] = IntermediateIf(
                    last_action,
                    [GotoStatement(jump_offset)],
                    [],
                    negate=False,
                )

                self.vprint("Converted if-goto pattern in chuk ID {cur_id} to intermediate if")
                cur_id = chunks_by_id[cur_id].next_chunks[0]
                continue

            if not isinstance(cur_chunk, ByteCodeChunk):
                # We should only be looking at bytecode chunks at this point, all other
                # types should have a single next chunk.
                raise Exception("Logic error!")

            last_action = cur_chunk.actions[-1]
            if not isinstance(last_action, IfAction):
                # This needs, again, to be an if statement.
                raise Exception("Logic error!")
            if len(chunks_by_id[cur_id].next_chunks) != 2:
                # This needs to be an if statement.
                raise Exception("Logic error!")

            # This should be an if statement. Figure out if it is an if-else or an
            # if, and if both branches return.
            if_end = self.__find_shallowest_successor(cur_id, chunks_by_id)

            # This is a normal if or if-else, let's compile the true and false
            # statements.
            true_jump_point = offset_map[last_action.jump_if_true_offset]
            false_jump_points = [n for n in cur_chunk.next_chunks if n != true_jump_point]
            if len(false_jump_points) != 1:
                raise Exception("Logic error!")
            false_jump_point = false_jump_points[0]

            if true_jump_point == false_jump_point:
                # This should never happen.
                raise Exception("Logic error!")

            self.vprint(f"Chunk ID {cur_id} is an if statement with true node {true_jump_point} and false node {false_jump_point} and ending at {if_end}")

            true_chunks: List[ArbitraryCodeChunk] = []
            if true_jump_point != if_end:
                self.vprint(f"Gathering true path starting with {true_jump_point} and ending with {if_end} and detecting if statements within it as well.")

                # First, grab all the chunks in this if statement body.
                true_chunks = self.__gather_chunks(true_jump_point, if_end, chunks_by_id)

                # Delete these chunks from our chunk mapping since we're putting them in an if body.
                for chunk in true_chunks:
                    del chunks_by_id[chunk.id]

                # Now, recursively attempt to detect if statements within this chunk as well.
                true_chunks = self.__separate_ifs(true_jump_point, true_chunks, offset_map)

            false_chunks: List[ArbitraryCodeChunk] = []
            if false_jump_point != if_end:
                self.vprint(f"Gathering false path starting with {false_jump_point} and ending with {if_end} and detecting if statements within it as well.")

                # First, grab all the chunks in this if statement body.
                false_chunks = self.__gather_chunks(false_jump_point, if_end, chunks_by_id)

                # Delete these chunks from our chunk mapping since we're putting them in an if body.
                for chunk in false_chunks:
                    del chunks_by_id[chunk.id]

                # Now, recursively attempt to detect if statements within this chunk as well.
                false_chunks = self.__separate_ifs(false_jump_point, false_chunks, offset_map)

            if false_chunks and (not true_chunks):
                negate = True
                true_chunks = false_chunks
                false_chunks = []
                if_id = false_jump_point
            else:
                negate = False
                if_id = true_jump_point

            if (not true_chunks) and (not false_chunks):
                # We should have at least one!
                raise Exception("Logic error!")

            # Add a new if body that this current chunk points to. At this point, chunks_by_id contains
            # none of the chunks in the true or false bodies of the if, so we add it back to the graph
            # in the form of an IfBody.
            self.vprint(f"Created new IfBody for chunk {cur_id} to point at, ending at {if_id}")
            chunks_by_id[if_id] = IfBody(if_id, true_chunks, false_chunks, if_end, cur_id, negate)
            chunks_by_id[cur_id].next_chunks = [if_id]

            if if_end is not None:
                # Skip over the if, we already analyzed it.
                cur_id = if_end
            else:
                # This if statement encompases all the rest of the statements, we're done.
                break

        self.vprint(f"Finished separating if statements out of graph starting at {start_id}")
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

    def __eval_stack(self, chunk: ByteCodeChunk, offset_map: Dict[int, int]) -> List[ConvertedAction]:
        stack: List[Any] = []

        def make_if_expr(action: IfAction, negate: bool) -> IfExpr:
            if action.comparison in ["IS DEFINED", "IS NOT UNDEFINED"]:
                conditional = stack.pop()
                return IsUndefinedIf(conditional, negate=negate != (action.comparison == "IS DEFINED"))
            if action.comparison in ["IS TRUE", "IS FALSE"]:
                conditional = stack.pop()
                return IsBooleanIf(conditional, negate=negate != (action.comparison == "IS FALSE"))
            if action.comparison in ["==", "!="]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                return IsEqualIf(conditional1, conditional2, negate=negate != (action.comparison == "!="))
            if action.comparison in ["STRICT ==", "STRICT !="]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                return IsStrictEqualIf(conditional1, conditional2, negate=negate != (action.comparison == "STRICT !="))
            if action.comparison in ["<", ">"]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                return MagnitudeIf(conditional1, conditional2, negate=negate != (action.comparison == "<"))
            if action.comparison in ["<=", ">="]:
                conditional2 = stack.pop()
                conditional1 = stack.pop()
                return MagnitudeEqualIf(conditional1, conditional2, negate=negate != (action.comparison == "<="))

            raise Exception("TODO: {action}")

        for i in range(len(chunk.actions)):
            action = chunk.actions[i]

            if isinstance(action, PushAction):
                for obj in action.objects:
                    stack.append(obj)

                chunk.actions[i] = NopStatement()
                continue

            if isinstance(action, DefineFunction2Action):
                # TODO: We need to recursively decompile this function and add its contents here.
                stack.append(NewFunction(action.name, action.flags, action.body))

                chunk.actions[i] = NopStatement()
                continue

            if isinstance(action, StoreRegisterAction):
                # This one's fun, because a store register can generate zero or more statements.
                # So we need to expand the stack. But we can't mid-iteration without a lot of
                # shenanigans, so we instead invent a new type of ConvertedAction that can contain
                # multiple statements.
                set_value = stack.pop()
                if action.preserve_stack:
                    stack.append(set_value)

                store_actions: List[StoreRegisterStatement] = []

                for reg in action.registers:
                    store_actions.append(StoreRegisterStatement(reg, set_value))

                chunk.actions[i] = MultiAction(store_actions)
                continue

            if isinstance(action, JumpAction):
                # This could possibly be a jump to the very next line, but we will wait for the
                # optimization pass to figure that out.
                chunk.actions[i] = GotoStatement(offset_map[action.jump_offset])
                continue

            if isinstance(action, IfAction):
                chunk.actions[i] = make_if_expr(action, False)
                continue

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

                if action.opcode == AP2Action.GET_VARIABLE:
                    variable_name = stack.pop()
                    if not isinstance(variable_name, (str, StringConstant)):
                        raise Exception("Logic error!")
                    stack.append(Variable(variable_name))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.DELETE2:
                    variable_name = stack.pop()
                    if not isinstance(variable_name, (str, StringConstant)):
                        raise Exception("Logic error!")

                    chunk.actions[i] = DeleteVariableStatement(variable_name)
                    continue

                if action.opcode == AP2Action.CALL_METHOD:
                    method_name = stack.pop()
                    if not isinstance(method_name, (str, StringConstant)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()
                    num_params = stack.pop()
                    if not isinstance(num_params, int):
                        raise Exception("Logic error!")
                    params = []
                    for _ in range(num_params):
                        params.append(stack.pop())
                    stack.append(MethodCall(object_reference, method_name, params))

                    chunk.actions[i] = NopStatement()
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
                    stack.append(FunctionCall(function_name, params))

                    chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.POP:
                    # This is a discard. Let's see if its discarding a function or method
                    # call. If so, that means the return doesn't matter.
                    discard = stack.pop()
                    if isinstance(discard, MethodCall):
                        # It is! Let's act on the statement.
                        chunk.actions[i] = ExpressionStatement(discard)
                    else:
                        chunk.actions[i] = NopStatement()
                    continue

                if action.opcode == AP2Action.SET_VARIABLE:
                    set_value = stack.pop()
                    local_name = stack.pop()
                    if not isinstance(local_name, (str, StringConstant)):
                        raise Exception("Logic error!")

                    chunk.actions[i] = SetVariableStatement(local_name, set_value)
                    continue

                if action.opcode == AP2Action.SET_MEMBER:
                    set_value = stack.pop()
                    member_name = stack.pop()
                    if not isinstance(member_name, (str, Expression)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()

                    chunk.actions[i] = SetMemberStatement(object_reference, member_name, set_value)
                    continue

                if action.opcode == AP2Action.DEFINE_LOCAL:
                    set_value = stack.pop()
                    local_name = stack.pop()
                    if not isinstance(local_name, (str, StringConstant)):
                        raise Exception("Logic error!")

                    chunk.actions[i] = SetLocalStatement(local_name, set_value)
                    continue

                if action.opcode == AP2Action.GET_MEMBER:
                    member_name = stack.pop()
                    if not isinstance(member_name, (str, Expression)):
                        raise Exception("Logic error!")
                    object_reference = stack.pop()
                    stack.append(Member(object_reference, member_name))

                    chunk.actions[i] = NopStatement()
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

                if action.opcode == AP2Action.ADD2:
                    expr1 = stack.pop()
                    expr2 = stack.pop()
                    stack.append(ArithmeticExpression(expr1, "+", expr2))

                    chunk.actions[i] = NopStatement()
                    continue

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
                # A partially-converted if from loop detection. Let's hoist it out properly.
                chunk.actions[i] = IfStatement(
                    make_if_expr(action.parent_action, action.negate),
                    action.true_statements,
                    action.false_statements,
                )
                continue

            self.vprint(chunk.actions)
            self.vprint(stack)
            raise Exception(f"TODO: {action}")

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
        return new_actions

    def __eval_chunks(self, start_id: int, chunks: Sequence[ArbitraryCodeChunk], offset_map: Dict[int, int]) -> List[Statement]:
        chunks_by_id: Dict[int, ArbitraryCodeChunk] = {chunk.id: chunk for chunk in chunks}
        statements: List[Statement] = []

        while True:
            # Grab the chunk to operate on.
            chunk = chunks_by_id[start_id]

            # Make sure when we collapse chunks, we don't lose labels.
            statements.append(DefineLabelStatement(start_id))

            if isinstance(chunk, Loop):
                # Evaluate the loop
                self.vprint(f"Evaluating graph in Loop {chunk.id}")
                statements.append(
                    DoWhileStatement(self.__eval_chunks(chunk.id, chunk.chunks, offset_map))
                )
            elif isinstance(chunk, IfBody):
                # We should have evaluated this earlier!
                raise Exception("Logic error!")
            else:
                new_statements = self.__eval_stack(chunk, offset_map)

                # We need to check and see if the last entry is an IfExpr, and hoist it
                # into a statement here.
                if isinstance(new_statements[-1], IfExpr):
                    if_body = chunk.next_chunks[0]
                    if_body_chunk = chunks_by_id[if_body]

                    if not isinstance(if_body_chunk, IfBody):
                        # IfBody should always follow a chunk that ends with an if.
                        raise Exception("Logic error!")

                    # Evaluate the if body
                    true_statements: List[Statement] = []
                    if if_body_chunk.true_chunks:
                        self.vprint(f"Evaluating graph of IfBody {if_body_chunk.id} true case")
                        true_start = self.__get_entry_block(if_body_chunk.true_chunks)
                        true_statements = self.__eval_chunks(true_start, if_body_chunk.true_chunks, offset_map)
                    false_statements: List[Statement] = []
                    if if_body_chunk.false_chunks:
                        self.vprint(f"Evaluating graph of IfBody {if_body_chunk.id} false case")
                        false_start = self.__get_entry_block(if_body_chunk.false_chunks)
                        false_statements = self.__eval_chunks(false_start, if_body_chunk.false_chunks, offset_map)

                    # Convert this IfExpr to a full-blown IfStatement.
                    new_statements[-1] = IfStatement(
                        new_statements[-1],
                        true_statements,
                        false_statements,
                    )

                    # Skip evaluating the IfBody next iteration.
                    chunk = if_body_chunk

                # Verify that we converted all the statements properly.
                for statement in new_statements:
                    if not isinstance(statement, Statement):
                        # We didn't convert a statement properly.
                        self.vprint(statement)
                        raise Exception("Logic error!")
                    statements.append(statement)

            # Go to the next chunk
            if not chunk.next_chunks:
                break
            if len(chunk.next_chunks) != 1:
                # We've checked so this should be impossible.
                raise Exception("Logic error!")
            start_id = chunk.next_chunks[0]

        return statements

    def __walk(self, statements: Sequence[Statement], do: Callable[[Statement], Optional[Statement]]) -> List[Statement]:
        new_statements: List[Statement] = []

        for statement in statements:
            if isinstance(statement, DoWhileStatement):
                new_statement = do(statement)
                if new_statement and isinstance(new_statement, DoWhileStatement):
                    new_statement.body = self.__walk(new_statement.body, do)
                    new_statements.append(new_statement)
                elif new_statement is not None:
                    # Cannot currently handle changing a statement with children to a new
                    # type of statement.
                    raise Exception("Logic error!")
            elif isinstance(statement, IfStatement):
                new_statement = do(statement)
                if new_statement and isinstance(new_statement, IfStatement):
                    statement.true_statements = self.__walk(statement.true_statements, do)
                    statement.false_statements = self.__walk(statement.false_statements, do)
                    new_statements.append(new_statement)
                elif new_statement is not None:
                    # Cannot currently handle changing a statement with children to a new
                    # type of statement.
                    raise Exception("Logic error!")
            else:
                new_statement = do(statement)
                if new_statement:
                    new_statements.append(new_statement)

        return new_statements

    def __eliminate_unused_labels(self, statements: Sequence[Statement]) -> List[Statement]:
        # Go through and find labels that nothing is pointing at, and remove them.
        locations: Set[int] = set()

        def find_goto(statement: Statement) -> Statement:
            if isinstance(statement, GotoStatement):
                locations.add(statement.location)
            return statement

        self.__walk(statements, find_goto)

        def remove_label(statement: Statement) -> Optional[Statement]:
            if isinstance(statement, DefineLabelStatement):
                if statement.location not in locations:
                    return None
            return statement

        return self.__walk(statements, remove_label)

    def __eliminate_useless_continues(self, statements: Sequence[Statement]) -> List[Statement]:
        # Go through and find continue statements on the last line of a do-while.
        def remove_continue(statement: Statement) -> Optional[Statement]:
            if isinstance(statement, DoWhileStatement):
                if statement.body and isinstance(statement.body[-1], ContinueStatement):
                    statement.body.pop()
            return statement

        return self.__walk(statements, remove_continue)

    def __pretty_print(self, start_id: int, statements: Sequence[Statement], prefix: str = "") -> str:
        output: List[str] = []

        for statement in statements:
            output.extend(statement.render(prefix))

        return os.linesep.join(output)

    def __decompile(self) -> str:
        # First, we need to construct a control flow graph.
        self.vprint("Generating control flow graph...")
        chunks, offset_map = self.__graph_control_flow()

        # Now, compute dominators so we can locate back-refs.
        self.vprint("Generating dominator list...")
        dominators = self.__compute_dominators(chunks)

        # Now, separate chunks out into chunks and loops.
        self.vprint("Identifying and separating loops...")
        chunks_and_loops = self.__separate_loops(chunks, dominators, offset_map)

        # Now, break the graph anywhere where we have control
        # flow that ends the execution (return, throw, goto end).
        self.vprint("Breaking control flow graph on non-returnable statements...")
        self.__break_graph(chunks_and_loops, offset_map)

        # Now, identify any remaining control flow logic.
        self.vprint("Identifying and separating ifs...")
        start_id = self.__get_entry_block(chunks_and_loops)
        chunks_loops_and_ifs = self.__separate_ifs(start_id, chunks_and_loops, offset_map)

        # At this point, we *should* have a directed graph where there are no
        # backwards refs and every fork has been identified as an if. This means
        # we can now walk and recursively generate pseudocode in one pass.
        self.vprint("Cleaning up and checking graph...")
        chunks_loops_and_ifs = self.__check_graph(start_id, chunks_loops_and_ifs)

        # Now, its safe to start actually evaluating the stack.
        statements = self.__eval_chunks(start_id, chunks_loops_and_ifs, offset_map)

        # Now, let's do some clean-up passes.
        statements = self.__eliminate_unused_labels(statements)
        statements = self.__eliminate_useless_continues(statements)

        # Finally, let's print the code!
        code = self.__pretty_print(start_id, statements, prefix="    " if self.main else "")

        if self.main:
            code = f"void main(){os.linesep}{{{os.linesep}{code}{os.linesep}}}"
        self.vprint(f"Final code:{os.linesep}{code}")

        return code

    def decompile(self, verbose: bool = False) -> str:
        with self.debugging(verbose):
            return self.__decompile()
