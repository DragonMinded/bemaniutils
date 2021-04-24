import os
from typing import Any, Dict, List, Sequence, Tuple, Set, Union, Optional, cast

from .types import AP2Action, JumpAction, IfAction, DefineFunction2Action
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


ArbitraryOpcode = Union[AP2Action, ConvertedAction]


class BreakStatement(ConvertedAction):
    # A break from a loop (forces execution to the next line after the loop).
    def __repr__(self) -> str:
        return "break;"


class ContinueStatement(ConvertedAction):
    # A continue in a loop (forces execution to the top of the loop).
    def __repr__(self) -> str:
        return "continue;"


class GotoStatement(ConvertedAction):
    # A goto, including the ID of the chunk we want to jump to.
    def __init__(self, location: int) -> None:
        self.location = location

    def __repr__(self) -> str:
        return f"goto label_{self.location};"


class NullReturnStatement(ConvertedAction):
    # A statement which directs the control flow to the end of the code, but
    # does not pop the stack to return
    def __repr__(self) -> str:
        return "return;"


class IntermediateIfStatement(ConvertedAction):
    def __init__(self, parent_action: IfAction, true_actions: Sequence[ArbitraryOpcode], false_actions: Sequence[ArbitraryOpcode], negate: bool) -> None:
        self.parent_action = parent_action
        self.true_actions = list(true_actions)
        self.false_actions = list(false_actions)
        self.negate = negate

    def __repr__(self) -> str:
        true_entries: List[str] = []
        for action in self.true_actions:
            true_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        false_entries: List[str] = []
        for action in self.false_actions:
            false_entries.extend([f"  {s}" for s in str(action).split(os.linesep)])

        if self.false_actions:
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
    def __init__(self, bytecode: ByteCode) -> None:
        super().__init__()

        self.bytecode = bytecode

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
                    true_action: Optional[ConvertedAction] = None
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

                    false_action: Optional[ConvertedAction] = None
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

                    chunk.actions[-1] = IntermediateIfStatement(
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
                # This is just a goto/chunk, move on to the next one.
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
                self.vprint(chunks)
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

        # TODO: Need to go through and start actually converting statements now.
        self.vprint(chunks_loops_and_ifs)

        return "TODO"

    def decompile(self, verbose: bool = False) -> str:
        with self.debugging(verbose):
            return self.__decompile()
