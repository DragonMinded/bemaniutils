import os
from typing import Any, Final, List, Sequence, Union

from .expression import (
    Expression,
    StringConstant,
    Register,
    value_ref,
    name_ref,
    object_ref,
)


class ConvertedAction:
    # An action that has been analyzed and converted to an intermediate representation.
    # This is only here because a Statement is a ConvertedAction and I don't want to
    # introduce a circular dependency.
    pass


class Statement(ConvertedAction):
    # This is just a type class for finished statements.
    def render(self, prefix: str) -> List[str]:
        raise NotImplementedError(f"{self.__class__.__name__} does not implement render()!")


class DefineLabelStatement(Statement):
    def __init__(self, location: int) -> None:
        self.location = location

    def __repr__(self) -> str:
        return f"label_{self.location}:"

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
        if location < 0:
            raise Exception(f"Logic error, attempting to go to artificially inserted location {location}!")

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


class ReturnStatement(Statement):
    # A statement which directs the control flow to the end of the code,
    # returning the top of the stack.
    def __init__(self, ret: Any) -> None:
        self.ret = ret

    def __repr__(self) -> str:
        ret = value_ref(self.ret, "")
        return f"return {ret}"

    def render(self, prefix: str) -> List[str]:
        ret = value_ref(self.ret, prefix)
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

    def render(self, prefix: str) -> List[str]:
        exc = value_ref(self.exc, prefix)
        return [f"{prefix}throw {exc};"]


class NopStatement(Statement):
    # A literal no-op. We will get rid of these in an optimizing pass.
    def __repr__(self) -> str:
        return "nop"

    def render(self, prefix: str) -> List[str]:
        # We should never render this!
        raise Exception("Logic error, a NopStatement should never make it to the render stage!")


class ExpressionStatement(Statement):
    # A statement which is an expression that discards its return.
    def __init__(self, expr: Expression) -> None:
        self.expr = expr

    def __repr__(self) -> str:
        return f"{self.expr.render('')}"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}{self.expr.render(prefix)};"]


class StopSoundStatement(Statement):
    # Stop all sounds, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_StopAllSounds()"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}builtin_StopAllSounds();"]


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


class NextFrameStatement(Statement):
    # Advance to the next frame, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_GotoNextFrame()"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}builtin_GotoNextFrame();"]


class PreviousFrameStatement(Statement):
    # Advance to the previous frame, this is an actionscript-specific opcode.
    def __repr__(self) -> str:
        return "builtin_GotoPreviousFrame()"

    def render(self, prefix: str) -> List[str]:
        return [f"{prefix}builtin_GotoPreviousFrame();"]


class DebugTraceStatement(Statement):
    # Print a debug trace if supported.
    def __init__(self, trace: Any) -> None:
        self.trace = trace

    def __repr__(self) -> str:
        trace = value_ref(self.trace, "")
        return f"builtin_DebugTrace({trace})"

    def render(self, prefix: str) -> List[str]:
        trace = value_ref(self.trace, prefix)
        return [f"{prefix}builtin_DebugTrace({trace});"]


class GotoFrameStatement(Statement):
    # Go to a specified frame in the animation.
    def __init__(self, frame: Any) -> None:
        self.frame = frame

    def __repr__(self) -> str:
        frame = value_ref(self.frame, "")
        return f"builtin_GotoFrame({frame})"

    def render(self, prefix: str) -> List[str]:
        frame = value_ref(self.frame, prefix)
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

    def render(self, prefix: str) -> List[str]:
        obj = object_ref(self.obj_to_clone, prefix)
        name = value_ref(self.name, prefix)
        depth = value_ref(self.depth, prefix)
        return [f"{prefix}builtin_CloneSprite({obj}, {name}, {depth});"]


class RemoveSpriteStatement(Statement):
    # Clone a sprite.
    def __init__(self, obj_to_remove: Any) -> None:
        self.obj_to_remove = obj_to_remove

    def __repr__(self) -> str:
        obj = object_ref(self.obj_to_remove, "")
        return f"builtin_RemoveSprite({obj})"

    def render(self, prefix: str) -> List[str]:
        obj = object_ref(self.obj_to_remove, prefix)
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

    def render(self, prefix: str) -> List[str]:
        url = value_ref(self.url, prefix)
        target = value_ref(self.target, prefix)
        return [f"{prefix}builtin_GetURL2({self.action}, {url}, {target});"]


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

    def render(self, prefix: str) -> List[str]:
        try:
            ref = object_ref(self.objectref, prefix)
            name = name_ref(self.name, prefix)
            val = value_ref(self.valueref, prefix)
            return [f"{prefix}{ref}.{name} = {val};"]
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, prefix)
            name = value_ref(self.name, prefix)
            val = value_ref(self.valueref, prefix)
            return [f"{prefix}{ref}[{name}] = {val};"]


class DeleteVariableStatement(Statement):
    # Call a method on an object.
    def __init__(self, name: Union[str, StringConstant]) -> None:
        self.name = name

    def __repr__(self) -> str:
        name = name_ref(self.name, "")
        return f"del {name}"

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name, prefix)
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

    def render(self, prefix: str) -> List[str]:
        try:
            ref = object_ref(self.objectref, prefix)
            name = name_ref(self.name, prefix)
            return [f"{prefix}del {ref}.{name};"]
        except Exception:
            # This is not a simple string object reference.
            ref = object_ref(self.objectref, prefix)
            name = value_ref(self.name, prefix)
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

    def render(self, prefix: str) -> List[str]:
        val = value_ref(self.valueref, prefix)
        return [f"{prefix}{self.register.render(prefix)} = {val};"]


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

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name, prefix)
        val = value_ref(self.valueref, prefix)
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

    def render(self, prefix: str) -> List[str]:
        name = name_ref(self.name, prefix)
        val = value_ref(self.valueref, prefix)
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
    EQUALS: Final[str] = "=="
    NOT_EQUALS: Final[str] = "!="
    LT: Final[str] = "<"
    GT: Final[str] = ">"
    LT_EQUALS: Final[str] = "<="
    GT_EQUALS: Final[str] = ">="
    STRICT_EQUALS: Final[str] = "==="
    STRICT_NOT_EQUALS: Final[str] = "!=="

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

    def render(self, prefix: str) -> List[str]:
        true_entries: List[str] = []
        for statement in self.true_statements:
            true_entries.extend(statement.render(prefix=prefix + "    "))

        false_entries: List[str] = []
        for statement in self.false_statements:
            false_entries.extend(statement.render(prefix=prefix + "    "))

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

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    "))

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

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    "))

        inc_init = value_ref(self.inc_init, prefix)
        inc_assign = value_ref(self.inc_assign, prefix)
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

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    "))

        return [
            f"{prefix}while ({self.cond}) {{",
            f"{prefix}{{",
            *entries,
            f"{prefix}}}",
        ]
