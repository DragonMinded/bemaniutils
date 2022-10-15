import os
from typing import Any, List, Optional, Sequence, Union
from typing_extensions import Final

from .expression import (
    Expression,
    StringConstant,
    Register,
    value_ref,
    name_ref,
    object_ref,
    UNDEFINED,
)


class ConvertedAction:
    # An action that has been analyzed and converted to an intermediate representation.
    # This is only here because a Statement is a ConvertedAction and I don't want to
    # introduce a circular dependency.
    pass


class Statement(ConvertedAction):
    # This is just a type class for finished statements.
    def render(self, prefix: str) -> List[str]:
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement render()!"
        )


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
            raise Exception(
                f"Logic error, attempting to go to artificially inserted location {location}!"
            )

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
        raise Exception(
            "Logic error, a NopStatement should never make it to the render stage!"
        )


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
    def __init__(
        self,
        obj_to_clone: Any,
        name: Union[str, Expression],
        depth: Union[int, Expression],
    ) -> None:
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
    def __init__(
        self, objectref: Any, name: Union[str, int, Expression], valueref: Any
    ) -> None:
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
        return self.register.render("")

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

    def is_always_true(self) -> bool:
        return False

    def is_always_false(self) -> bool:
        return False

    def simplify(self) -> "IfExpr":
        if self.is_always_true():
            return IsBooleanIf(True)
        if self.is_always_false():
            return IsBooleanIf(False)
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IfExpr):
            return False
        return repr(self) == repr(other)

    def __hash__(self) -> int:
        return hash(repr(self))


class AndIf(IfExpr):
    def __init__(self, left: IfExpr, right: IfExpr) -> None:
        self.left: Final[IfExpr] = left.simplify()
        self.right: Final[IfExpr] = right.simplify()
        self.__true: Optional[bool] = None
        self.__false: Optional[bool] = None
        self._simplified = False
        self.__inverted: Optional[OrIf] = None
        self._gathered: Optional[List[IfExpr]] = None
        self.__hash: Optional[int] = None

    def invert(self) -> "OrIf":
        if self.__inverted is None:
            self.__inverted = OrIf(self.left.invert(), self.right.invert())
            self.__inverted._simplified = self._simplified
        return self.__inverted

    def swap(self) -> "AndIf":
        new_and = AndIf(self.right, self.left)
        new_and.__true = self.__true
        new_and.__false = self.__false
        new_and._simplified = self._simplified
        new_and._gathered = self._gathered
        new_and.__hash = self.__hash
        return new_and

    def is_always_true(self) -> bool:
        if self.__true is None:
            self.__true = self.left.is_always_true() and self.right.is_always_true()
        return self.__true

    def is_always_false(self) -> bool:
        if self.__false is None:
            if self.left.invert() == self.right:
                # If the left and right side are inverses of each other, we know
                # for a fact that this if can never be true.
                self.__false = True
            else:
                self.__false = (
                    self.left.is_always_false() or self.right.is_always_false()
                )
        return self.__false

    def simplify(self) -> "IfExpr":
        # If we already know that we're as simple as we can get, just return ourselves.
        if self._simplified:
            return self

        # Basic superclass stuff.
        if self.is_always_true():
            return IsBooleanIf(True)
        if self.is_always_false():
            return IsBooleanIf(False)

        # Tautology simplifications.
        if self.left.is_always_true() and not self.right.is_always_true():
            return self.right
        if not self.left.is_always_true() and self.right.is_always_true():
            return self.left

        # Equivalent folding (this can get complicated because "x && y && x"
        # should be folded to "x && y". We use set membership to fold.
        # Gather up each piece in order, dropping duplicates.
        ifexprs: List[IfExpr] = _gather_and(self)
        final: List[IfExpr] = []

        for expr in ifexprs:
            if expr.is_always_true():
                # Don't bother adding this, it should always be discarded.
                continue
            if expr in final:
                # Don't bother adding this, we already saw it.
                continue

            # Now, make sure that this isn't a negation of a previous term.
            for fexpr in final:
                if fexpr == expr.invert():
                    return IsBooleanIf(False)

            # Now, try to factor this expression out with an existing one to simplify.
            for i, fexpr in enumerate(final):
                factor = _factor_and(fexpr, expr)
                if factor:
                    final[i] = factor
                    break
            else:
                # We did not find a factor. See if there's a negative absorption available.
                for i, fexpr in enumerate(final):
                    absorb = _negative_absorb_and(fexpr, expr)
                    if absorb:
                        final[i] = absorb
                        break
                else:
                    # Nothing simplifies, just add this
                    final.append(expr)

        # Now, grab the last entry, adding it to the right side of and expressions
        # over and over until we have nothing to add.
        if len(final) == 1:
            return final[0]
        new_and = _accum_and(final, simplified=True)
        if not isinstance(new_and, AndIf):
            raise Exception("Logic error!")
        new_and.__true = self.__true
        new_and.__false = self.__false
        new_and._simplified = True
        return new_and

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AndIf):
            return False
        return set(_gather_and(self)) == set(_gather_and(other))

    def __hash__(self) -> int:
        if self.__hash is None:
            self.__hash = hash(
                "AND:" + ",".join(sorted(str(hash(s)) for s in set(_gather_and(self))))
            )
        return self.__hash

    def __repr__(self) -> str:
        return " && ".join(
            (f"({c!r})" if isinstance(c, (AndIf, OrIf)) else repr(c))
            for c in _gather_and(self)
        )


class OrIf(IfExpr):
    def __init__(self, left: IfExpr, right: IfExpr) -> None:
        self.left: Final[IfExpr] = left.simplify()
        self.right: Final[IfExpr] = right.simplify()
        self.__true: Optional[bool] = None
        self.__false: Optional[bool] = None
        self._simplified = False
        self.__inverted: Optional[AndIf] = None
        self._gathered: Optional[List[IfExpr]] = None
        self.__hash: Optional[int] = None

    def invert(self) -> "AndIf":
        if not self.__inverted:
            self.__inverted = AndIf(self.left.invert(), self.right.invert())
            self.__inverted._simplified = self._simplified
        return self.__inverted

    def swap(self) -> "OrIf":
        new_or = OrIf(self.right, self.left)
        new_or.__true = self.__true
        new_or.__false = self.__false
        new_or._simplified = self._simplified
        new_or._gathered = self._gathered
        new_or.__hash = self.__hash
        return new_or

    def is_always_true(self) -> bool:
        if self.__true is None:
            if self.left.invert() == self.right:
                # If the left and right side are inverses of each other, we know
                # for a fact that this if can never be false.
                self.__true = True
            else:
                self.__true = self.left.is_always_true() or self.right.is_always_true()
        return self.__true

    def is_always_false(self) -> bool:
        if self.__false is None:
            self.__false = self.left.is_always_false() and self.right.is_always_false()
        return self.__false

    def simplify(self) -> "IfExpr":
        # If we already know that we're as simple as we can get, just return ourselves.
        if self._simplified:
            return self

        # Basic superclass stuff.
        if self.is_always_true():
            return IsBooleanIf(True)
        if self.is_always_false():
            return IsBooleanIf(False)

        # Tautology simplifications.
        if self.left.is_always_false() and not self.right.is_always_false():
            return self.right
        if not self.left.is_always_false() and self.right.is_always_false():
            return self.left

        # Equivalent folding (this can get complicated because "x && y && x"
        # should be folded to "x && y". We use set membership to fold.
        # Gather up each piece in order, dropping duplicates.
        ifexprs: List[IfExpr] = _gather_or(self)
        final: List[IfExpr] = []

        for expr in ifexprs:
            if expr.is_always_false():
                # Don't bother adding this, it should always be discarded.
                continue
            if expr in final:
                # Don't bother adding this, we already saw it.
                continue

            # Now, make sure that this isn't a negation of a previous term.
            for fexpr in final:
                if fexpr == expr.invert():
                    return IsBooleanIf(True)

            # Now, try to factor this expression out with an existing one to simplify.
            for i, fexpr in enumerate(final):
                factor = _factor_or(fexpr, expr)
                if factor:
                    final[i] = factor
                    break
            else:
                # We did not find a factor. See if there's a negative absorption available.
                for i, fexpr in enumerate(final):
                    absorb = _negative_absorb_or(fexpr, expr)
                    if absorb:
                        final[i] = absorb
                        break
                else:
                    # Nothing simplifies, just add this
                    final.append(expr)

        # Now, grab the last entry, adding it to the right side of and expressions
        # over and over until we have nothing to add.
        if len(final) == 1:
            return final[0]
        new_or = _accum_or(final, simplified=True)
        if not isinstance(new_or, OrIf):
            raise Exception("Logic error!")
        new_or.__true = self.__true
        new_or.__false = self.__false
        new_or._simplified = True
        return new_or

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OrIf):
            return False
        return set(_gather_or(self)) == set(_gather_or(other))

    def __hash__(self) -> int:
        if self.__hash is None:
            self.__hash = hash(
                "OR:" + ",".join(sorted(str(hash(s)) for s in set(_gather_or(self))))
            )
        return self.__hash

    def __repr__(self) -> str:
        return " || ".join(
            (f"({c!r})" if isinstance(c, (AndIf, OrIf)) else repr(c))
            for c in _gather_or(self)
        )


def _gather_and(obj: IfExpr) -> List[IfExpr]:
    if isinstance(obj, AndIf):
        if obj._gathered is None:
            obj._gathered = [*_gather_and(obj.left), *_gather_and(obj.right)]
        return obj._gathered
    else:
        return [obj]


def _accum_and(objs: List[IfExpr], simplified: bool = False) -> IfExpr:
    accum = objs[-1]
    for i, obj in enumerate(reversed(objs)):
        if i == 0:
            continue
        accum = AndIf(obj, accum)
        accum._simplified = simplified
    return accum


def _factor_and(left: IfExpr, right: IfExpr) -> Optional[IfExpr]:
    left_ors = _gather_or(left)
    right_ors = _gather_or(right)
    commons: List[IfExpr] = []

    for exp in left_ors:
        if exp in right_ors:
            commons.append(exp)

    if commons:
        left_ors = [exp for exp in left_ors if exp not in commons]
        right_ors = [exp for exp in right_ors if exp not in commons]
        if not left_ors or not right_ors:
            return _accum_or(commons).simplify()

        return OrIf(
            _accum_or(commons), AndIf(_accum_or(left_ors), _accum_or(right_ors))
        ).simplify()
    else:
        return None


def _negative_absorb_and(left: IfExpr, right: IfExpr) -> Optional[IfExpr]:
    left_ors = _gather_or(left)
    right_ors = _gather_or(right)
    neg_left = left.invert()
    neg_right = right.invert()

    for val in right_ors:
        if neg_left == val:
            return AndIf(
                left,
                _accum_or([o for o in right_ors if o is not val]),
            ).simplify()
    for val in left_ors:
        if neg_right == val:
            return AndIf(
                _accum_or([o for o in left_ors if o is not val]),
                right,
            ).simplify()

    return None


def _gather_or(obj: IfExpr) -> List[IfExpr]:
    if isinstance(obj, OrIf):
        if obj._gathered is None:
            obj._gathered = [*_gather_or(obj.left), *_gather_or(obj.right)]
        return obj._gathered
    else:
        return [obj]


def _accum_or(objs: List[IfExpr], simplified: bool = False) -> IfExpr:
    accum = objs[-1]
    for i, obj in enumerate(reversed(objs)):
        if i == 0:
            continue
        accum = OrIf(obj, accum)
        accum._simplified = simplified
    return accum


def _factor_or(left: IfExpr, right: IfExpr) -> Optional[IfExpr]:
    left_ands = _gather_and(left)
    right_ands = _gather_and(right)
    commons: List[IfExpr] = []

    for exp in left_ands:
        if exp in right_ands:
            commons.append(exp)

    if commons:
        left_ands = [exp for exp in left_ands if exp not in commons]
        right_ands = [exp for exp in right_ands if exp not in commons]
        if not left_ands or not right_ands:
            return _accum_and(commons).simplify()

        return AndIf(
            _accum_and(commons), OrIf(_accum_and(left_ands), _accum_and(right_ands))
        ).simplify()
    else:
        return None


def _negative_absorb_or(left: IfExpr, right: IfExpr) -> Optional[IfExpr]:
    left_ands = _gather_and(left)
    right_ands = _gather_and(right)
    neg_left = left.invert()
    neg_right = right.invert()

    for val in right_ands:
        if neg_left == val:
            return OrIf(
                left,
                _accum_and([o for o in right_ands if o is not val]),
            ).simplify()
    for val in left_ands:
        if neg_right == val:
            return OrIf(
                _accum_and([o for o in left_ands if o is not val]),
                right,
            ).simplify()

    return None


class IsUndefinedIf(IfExpr):
    def __init__(self, conditional: Any) -> None:
        self.conditional: Final[Any] = conditional
        self.__negated = False

    def invert(self) -> "IsUndefinedIf":
        new = IsUndefinedIf(self.conditional)
        new.__negated = not self.__negated
        return new

    def swap(self) -> "IsUndefinedIf":
        return IsUndefinedIf(self.conditional)

    def is_always_true(self) -> bool:
        if self.conditional is UNDEFINED:
            return not self.__negated
        return False

    def is_always_false(self) -> bool:
        if self.conditional is UNDEFINED:
            return self.__negated
        return False

    def __repr__(self) -> str:
        val = value_ref(self.conditional, "", parens=True)
        if self.__negated:
            return f"{val} is not UNDEFINED"
        else:
            return f"{val} is UNDEFINED"


class IsBooleanIf(IfExpr):
    def __init__(self, conditional: Any) -> None:
        self.conditional: Final[Any] = conditional
        self.__negated = False

    def invert(self) -> "IsBooleanIf":
        new = IsBooleanIf(self.conditional)
        new.__negated = not self.__negated
        return new

    def swap(self) -> "IsBooleanIf":
        return IsBooleanIf(self.conditional)

    def is_always_true(self) -> bool:
        if self.conditional is True:
            return not self.__negated
        elif self.conditional is False:
            return self.__negated
        return False

    def is_always_false(self) -> bool:
        if self.conditional is True:
            return self.__negated
        elif self.conditional is False:
            return not self.__negated
        return False

    def __repr__(self) -> str:
        val = value_ref(self.conditional, "", parens=True)
        if self.__negated:
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

        self.conditional1: Final[Any] = conditional1
        self.comp: Final[str] = comp
        self.conditional2: Final[Any] = conditional2

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
            return TwoParameterIf(
                self.conditional1, self.STRICT_NOT_EQUALS, self.conditional2
            )
        if self.comp == self.STRICT_NOT_EQUALS:
            return TwoParameterIf(
                self.conditional1, self.STRICT_EQUALS, self.conditional2
            )
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
            return TwoParameterIf(
                self.conditional2, self.STRICT_EQUALS, self.conditional1
            )
        if self.comp == self.STRICT_NOT_EQUALS:
            return TwoParameterIf(
                self.conditional2, self.STRICT_NOT_EQUALS, self.conditional1
            )
        raise Exception(f"Cannot swap {self.comp}!")

    def __repr__(self) -> str:
        val1 = value_ref(self.conditional1, "", parens=True)
        val2 = value_ref(self.conditional2, "", parens=True)
        return f"{val1} {self.comp} {val2}"


class IfStatement(Statement):
    def __init__(
        self,
        cond: IfExpr,
        true_statements: Sequence[Statement],
        false_statements: Sequence[Statement],
    ) -> None:
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
            return os.linesep.join(
                [
                    f"if ({self.cond}) {{",
                    os.linesep.join(true_entries),
                    "} else {",
                    os.linesep.join(false_entries),
                    "}",
                ]
            )
        else:
            return os.linesep.join(
                [f"if ({self.cond}) {{", os.linesep.join(true_entries), "}"]
            )

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
                f"{prefix}}}",
            ]
        else:
            return [
                f"{prefix}if ({self.cond})",
                f"{prefix}{{",
                *true_entries,
                f"{prefix}}}",
            ]


class DoWhileStatement(Statement):
    def __init__(self, body: Sequence[Statement]) -> None:
        self.body = list(body)

    def __repr__(self) -> str:
        entries: List[str] = []
        for statement in self.body:
            entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        return os.linesep.join(["do {", os.linesep.join(entries), "} while (True)"])

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
    def __init__(
        self,
        inc_variable: str,
        inc_init: Any,
        cond: IfExpr,
        inc_assign: Any,
        body: Sequence[Statement],
        local: bool = False,
    ) -> None:
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

        return os.linesep.join(
            [
                f"for ({local}{self.inc_variable} = {inc_init}; {self.cond}; {self.inc_variable} = {inc_assign}) {{",
                os.linesep.join(entries),
                "}",
            ]
        )

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
            f"{prefix}for ({local}{self.inc_variable} = {inc_init}; {self.cond}; {self.inc_variable} = {inc_assign})",
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

        return os.linesep.join(
            [f"while ({self.cond}) {{", os.linesep.join(entries), "}"]
        )

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.body:
            entries.extend(statement.render(prefix=prefix + "    "))

        return [
            f"{prefix}while ({self.cond})",
            f"{prefix}{{",
            *entries,
            f"{prefix}}}",
        ]


class SwitchCase:
    def __init__(self, const: Any, statements: Sequence[Statement]) -> None:
        self.const = const
        self.statements = list(statements)

    def __repr__(self) -> str:
        entries: List[str] = []
        for statement in self.statements:
            entries.extend([f"  {s}" for s in str(statement).split(os.linesep)])

        if self.const is not None:
            const = value_ref(self.const, "")
            return os.linesep.join(
                [
                    f"case {const}:",
                    os.linesep.join(entries),
                ]
            )
        else:
            return os.linesep.join(
                [
                    "default:",
                    os.linesep.join(entries),
                ]
            )

    def render(self, prefix: str) -> List[str]:
        entries: List[str] = []
        for statement in self.statements:
            entries.extend(statement.render(prefix=prefix + "    "))

        if self.const is not None:
            const = value_ref(self.const, prefix)
            return [
                f"{prefix}case {const}:",
                *entries,
            ]
        else:
            return [
                f"{prefix}default:",
                *entries,
            ]


class SwitchStatement(Statement):
    def __init__(self, check_variable: Any, cases: Sequence[SwitchCase]) -> None:
        self.check_variable = check_variable
        self.cases = list(cases)

    def __repr__(self) -> str:
        cases: List[str] = []
        for case in self.cases:
            cases.extend([f"  {s}" for s in str(case).split(os.linesep)])

        check = object_ref(self.check_variable, "")
        return os.linesep.join([f"switch ({check}) {{", os.linesep.join(cases), "}"])

    def render(self, prefix: str) -> List[str]:
        cases: List[str] = []
        for case in self.cases:
            cases.extend(case.render(prefix=prefix + "    "))

        check = object_ref(self.check_variable, prefix)
        return [f"{prefix}switch ({check})", f"{prefix}{{", *cases, f"{prefix}}}"]
