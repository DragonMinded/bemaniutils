# vim: set fileencoding=utf-8
import os
import unittest
from typing import Dict, List, Sequence, Tuple, Union

from bemani.tests.helpers import ExtendedTestCase
from bemani.format.afp.decompile import (
    ByteCodeDecompiler,
    ByteCode,
    BitVector,
    ByteCodeChunk,
    ControlFlow,
)
from bemani.format.afp.types import (
    AP2Action,
    IfAction,
    JumpAction,
    PushAction,
    AddNumVariableAction,
    Register,
    Variable,
    ArithmeticExpression,
    UNDEFINED,
    Statement,
    DefineLabelStatement,
    GotoStatement,
    ReturnStatement,
    PlayMovieStatement,
    StopMovieStatement,
    NextFrameStatement,
    PreviousFrameStatement,
    IfStatement,
    ForStatement,
    IsUndefinedIf,
    IsBooleanIf,
    TwoParameterIf,
    AndIf,
    OrIf,
)


OPEN_BRACKET = "{"
CLOSE_BRACKET = "}"


class TestAFPBitVector(unittest.TestCase):
    def test_simple(self) -> None:
        bv = BitVector(5)

        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, set())

        bv.setBit(2)
        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, {2})

        bv.setBit(2)
        bv.setBit(3)
        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, {2, 3})

        bv.clearBit(2)
        bv.clearBit(1)
        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, {3})

        bv.setAllBitsTo(True)
        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, {0, 1, 2, 3, 4})

        bv.setAllBitsTo(False)
        self.assertEqual(len(bv), 5)
        self.assertEqual(bv.bitsSet, set())

    def test_equality(self) -> None:
        bv1 = BitVector(5, init=True)
        bv2 = BitVector(5, init=False)

        self.assertFalse(bv1 == bv2)
        self.assertTrue(bv1 != bv2)

        bv2.setAllBitsTo(True)

        self.assertTrue(bv1 == bv2)
        self.assertFalse(bv1 != bv2)

    def test_clone(self) -> None:
        bv = BitVector(5)
        bv.setBit(2)
        bvclone = bv.clone()

        self.assertTrue(bv == bvclone)

        bv.setBit(3)
        bvclone.setBit(4)
        self.assertEqual(bv.bitsSet, {2, 3})
        self.assertEqual(bvclone.bitsSet, {2, 4})

    def test_boolean_logic(self) -> None:
        bv1 = BitVector(5).setBit(2).setBit(3)
        bv2 = BitVector(5).setBit(1).setBit(2)

        clone = bv1.clone().orVector(bv2)
        self.assertEqual(clone.bitsSet, {1, 2, 3})

        clone = bv1.clone().andVector(bv2)
        self.assertEqual(clone.bitsSet, {2})


class TestAFPControlGraph(ExtendedTestCase):
    # Note that the offsets made up in these test functions are not realistic. Jump/If instructions
    # take up more than one opcode, and the end offset might be more than one byte past the last
    # action if that action takes up more than one byte. However, from the perspective of the
    # decompiler, it doesn't care about accurate sizes, only that the offsets are correct.

    def test_control_flow(self) -> None:
        cf = ControlFlow(1, 10, [20])

        self.assertTrue(cf.contains(1))
        self.assertFalse(cf.contains(10))
        self.assertTrue(cf.contains(5))
        self.assertFalse(cf.contains(20))

        self.assertTrue(cf.is_first(1))
        self.assertFalse(cf.is_first(10))
        self.assertFalse(cf.is_first(5))
        self.assertFalse(cf.is_first(20))

        self.assertFalse(cf.is_last(1))
        self.assertFalse(cf.is_last(10))
        self.assertFalse(cf.is_last(5))
        self.assertFalse(cf.is_last(20))
        self.assertTrue(cf.is_last(9))

        cf1, cf2 = cf.split(5, link=False)
        self.assertEqual(cf1.beginning, 1)
        self.assertEqual(cf1.end, 5)
        self.assertEqual(cf1.next_flow, [])
        self.assertEqual(cf2.beginning, 5)
        self.assertEqual(cf2.end, 10)
        self.assertEqual(cf2.next_flow, [20])

        cf3, cf4 = cf.split(5, link=True)
        self.assertEqual(cf3.beginning, 1)
        self.assertEqual(cf3.end, 5)
        self.assertEqual(cf3.next_flow, [5])
        self.assertEqual(cf4.beginning, 5)
        self.assertEqual(cf4.end, 10)
        self.assertEqual(cf4.next_flow, [20])

    def __make_bytecode(self, actions: Sequence[AP2Action]) -> ByteCode:
        return ByteCode(
            None,
            actions,
            actions[-1].offset + 1,
        )

    def __call_graph(
        self, bytecode: ByteCode
    ) -> Tuple[Dict[int, ByteCodeChunk], Dict[int, int]]:
        # Just create a dummy compiler so we can access the internal method for testing.
        bcd = ByteCodeDecompiler(bytecode, optimize=True)

        # Call it, return the data in an easier to test fashion.
        chunks, offset_map = bcd._graph_control_flow(bytecode)
        return {chunk.id: chunk for chunk in chunks}, offset_map

    def __equiv(
        self, bytecode: Union[ByteCode, ByteCodeChunk, List[AP2Action]]
    ) -> List[str]:
        if isinstance(bytecode, (ByteCode, ByteCodeChunk)):
            return [str(x) for x in bytecode.actions]
        else:
            return [str(x) for x in bytecode]

    def test_simple_bytecode(self) -> None:
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 101: 1})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [])

        # Also verify the code
        self.assertEqual(self.__equiv(chunks_by_id[0]), ["100: STOP"])
        self.assertEqual(self.__equiv(chunks_by_id[1]), [])

    def test_jump_handling(self) -> None:
        bytecode = self.__make_bytecode(
            [
                JumpAction(100, 102),
                JumpAction(101, 104),
                JumpAction(102, 101),
                JumpAction(103, 106),
                JumpAction(104, 103),
                JumpAction(105, 107),
                JumpAction(106, 105),
                AP2Action(107, AP2Action.STOP),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(
            offset_map,
            {100: 0, 101: 1, 102: 2, 103: 3, 104: 4, 105: 5, 106: 6, 107: 7, 108: 8},
        )
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3, 4, 5, 6, 7, 8})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [2])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [4])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [4])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [6])
        self.assertItemsEqual(chunks_by_id[4].previous_chunks, [1])
        self.assertItemsEqual(chunks_by_id[4].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[5].previous_chunks, [6])
        self.assertItemsEqual(chunks_by_id[5].next_chunks, [7])
        self.assertItemsEqual(chunks_by_id[6].previous_chunks, [3])
        self.assertItemsEqual(chunks_by_id[6].next_chunks, [5])
        self.assertItemsEqual(chunks_by_id[7].previous_chunks, [5])
        self.assertItemsEqual(chunks_by_id[7].next_chunks, [8])
        self.assertItemsEqual(chunks_by_id[8].previous_chunks, [7])
        self.assertItemsEqual(chunks_by_id[8].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]), ["100: JUMP, Offset To Jump To: 102"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]), ["101: JUMP, Offset To Jump To: 104"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[2]), ["102: JUMP, Offset To Jump To: 101"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[3]), ["103: JUMP, Offset To Jump To: 106"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[4]), ["104: JUMP, Offset To Jump To: 103"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[5]), ["105: JUMP, Offset To Jump To: 107"]
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[6]), ["106: JUMP, Offset To Jump To: 105"]
        )
        self.assertEqual(self.__equiv(chunks_by_id[7]), ["107: STOP"])
        self.assertEqual(self.__equiv(chunks_by_id[8]), [])

    def test_dead_code_elimination_jump(self) -> None:
        # Jump case
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
                JumpAction(101, 103),
                AP2Action(102, AP2Action.PLAY),
                AP2Action(103, AP2Action.STOP),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 103: 1, 104: 2})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [2])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [1])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            ["100: STOP", "101: JUMP, Offset To Jump To: 103"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[1]), ["103: STOP"])
        self.assertEqual(self.__equiv(chunks_by_id[2]), [])

    def test_dead_code_elimination_return(self) -> None:
        # Return case
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
                AP2Action(101, AP2Action.RETURN),
                AP2Action(102, AP2Action.STOP),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 103: 1})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [])

        # Also verify the code
        self.assertEqual(self.__equiv(chunks_by_id[0]), ["100: STOP", "101: RETURN"])
        self.assertEqual(self.__equiv(chunks_by_id[1]), [])

    def test_dead_code_elimination_end(self) -> None:
        # Return case
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
                AP2Action(101, AP2Action.END),
                AP2Action(102, AP2Action.END),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 103: 1})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [])

        # Also verify the code
        self.assertEqual(self.__equiv(chunks_by_id[0]), ["100: STOP", "101: END"])
        self.assertEqual(self.__equiv(chunks_by_id[1]), [])

    def test_dead_code_elimination_throw(self) -> None:
        # Throw case
        bytecode = self.__make_bytecode(
            [
                PushAction(100, ["exception"]),
                AP2Action(101, AP2Action.THROW),
                AP2Action(102, AP2Action.STOP),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 103: 1})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [f"100: PUSH{os.linesep}  'exception'{os.linesep}END_PUSH", "101: THROW"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[1]), [])

    def test_if_handling_basic(self) -> None:
        # If by itself case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_FALSE, 103),
                # False case (fall through from if).
                AP2Action(102, AP2Action.PLAY),
                # Line after the if statement.
                AP2Action(103, AP2Action.END),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 103: 2, 104: 3})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [2])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0, 1])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS FALSE, Offset To Jump To If True: 103",
            ],
        )
        self.assertEqual(self.__equiv(chunks_by_id[1]), ["102: PLAY"])
        self.assertEqual(self.__equiv(chunks_by_id[2]), ["103: END"])
        self.assertEqual(self.__equiv(chunks_by_id[3]), [])

    def test_if_handling_basic_jump_to_end(self) -> None:
        # If by itself case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_FALSE, 103),
                # False case (fall through from if).
                AP2Action(102, AP2Action.PLAY),
                # Some code will jump to the end offset as a way of
                # "returning" early from a function.
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 103: 2})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [2])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0, 1])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS FALSE, Offset To Jump To If True: 103",
            ],
        )
        self.assertEqual(self.__equiv(chunks_by_id[1]), ["102: PLAY"])
        self.assertEqual(self.__equiv(chunks_by_id[2]), [])

    def test_if_handling_diamond(self) -> None:
        # If true-false diamond case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                AP2Action(102, AP2Action.STOP),
                JumpAction(103, 105),
                # True case.
                AP2Action(104, AP2Action.PLAY),
                # Line after the if statement.
                AP2Action(105, AP2Action.END),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 104: 2, 105: 3, 106: 4})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3, 4})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [4])
        self.assertItemsEqual(chunks_by_id[4].previous_chunks, [3])
        self.assertItemsEqual(chunks_by_id[4].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS TRUE, Offset To Jump To If True: 104",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]),
            ["102: STOP", "103: JUMP, Offset To Jump To: 105"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[2]), ["104: PLAY"])
        self.assertEqual(self.__equiv(chunks_by_id[3]), ["105: END"])
        self.assertEqual(self.__equiv(chunks_by_id[4]), [])

    def test_if_handling_diamond_jump_to_end(self) -> None:
        # If true-false diamond case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                AP2Action(102, AP2Action.STOP),
                JumpAction(103, 105),
                # True case.
                AP2Action(104, AP2Action.PLAY),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 104: 2, 105: 3})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS TRUE, Offset To Jump To If True: 104",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]),
            ["102: STOP", "103: JUMP, Offset To Jump To: 105"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[2]), ["104: PLAY"])
        self.assertEqual(self.__equiv(chunks_by_id[3]), [])

    def test_if_handling_diamond_return_to_end(self) -> None:
        # If true-false diamond case but the cases never converge.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                PushAction(102, ["b"]),
                AP2Action(103, AP2Action.RETURN),
                # True case.
                PushAction(104, ["a"]),
                AP2Action(105, AP2Action.RETURN),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 104: 2, 106: 3})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS TRUE, Offset To Jump To If True: 104",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]),
            [f"102: PUSH{os.linesep}  'b'{os.linesep}END_PUSH", "103: RETURN"],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[2]),
            [f"104: PUSH{os.linesep}  'a'{os.linesep}END_PUSH", "105: RETURN"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[3]), [])

    def test_if_handling_switch(self) -> None:
        # Series of ifs (basically a switch statement).
        bytecode = self.__make_bytecode(
            [
                # Beginning of the first if statement.
                PushAction(100, [Register(0), 1]),
                IfAction(101, IfAction.COMP_NOT_EQUALS, 104),
                # False case (fall through from if).
                PushAction(102, ["a"]),
                JumpAction(103, 113),
                # Beginning of the second if statement.
                PushAction(104, [Register(0), 2]),
                IfAction(105, IfAction.COMP_NOT_EQUALS, 108),
                # False case (fall through from if).
                PushAction(106, ["b"]),
                JumpAction(107, 113),
                # Beginning of the third if statement.
                PushAction(108, [Register(0), 3]),
                IfAction(109, IfAction.COMP_NOT_EQUALS, 112),
                # False case (fall through from if).
                PushAction(110, ["c"]),
                JumpAction(111, 113),
                # Beginning of default case.
                PushAction(112, ["d"]),
                # Line after the switch statement.
                AP2Action(113, AP2Action.END),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(
            offset_map,
            {100: 0, 102: 1, 104: 2, 106: 3, 108: 4, 110: 5, 112: 6, 113: 7, 114: 8},
        )
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3, 4, 5, 6, 7, 8})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [7])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3, 4])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [7])
        self.assertItemsEqual(chunks_by_id[4].previous_chunks, [2])
        self.assertItemsEqual(chunks_by_id[4].next_chunks, [5, 6])
        self.assertItemsEqual(chunks_by_id[5].previous_chunks, [4])
        self.assertItemsEqual(chunks_by_id[5].next_chunks, [7])
        self.assertItemsEqual(chunks_by_id[6].previous_chunks, [4])
        self.assertItemsEqual(chunks_by_id[6].next_chunks, [7])
        self.assertItemsEqual(chunks_by_id[7].previous_chunks, [1, 3, 5, 6])
        self.assertItemsEqual(chunks_by_id[7].next_chunks, [8])
        self.assertItemsEqual(chunks_by_id[8].previous_chunks, [7])
        self.assertItemsEqual(chunks_by_id[8].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  Register(0){os.linesep}  1{os.linesep}END_PUSH",
                "101: IF, Comparison: !=, Offset To Jump To If True: 104",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]),
            [
                f"102: PUSH{os.linesep}  'a'{os.linesep}END_PUSH",
                "103: JUMP, Offset To Jump To: 113",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[2]),
            [
                f"104: PUSH{os.linesep}  Register(0){os.linesep}  2{os.linesep}END_PUSH",
                "105: IF, Comparison: !=, Offset To Jump To If True: 108",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[3]),
            [
                f"106: PUSH{os.linesep}  'b'{os.linesep}END_PUSH",
                "107: JUMP, Offset To Jump To: 113",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[4]),
            [
                f"108: PUSH{os.linesep}  Register(0){os.linesep}  3{os.linesep}END_PUSH",
                "109: IF, Comparison: !=, Offset To Jump To If True: 112",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[5]),
            [
                f"110: PUSH{os.linesep}  'c'{os.linesep}END_PUSH",
                "111: JUMP, Offset To Jump To: 113",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[6]),
            [f"112: PUSH{os.linesep}  'd'{os.linesep}END_PUSH"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[7]), ["113: END"])
        self.assertEqual(self.__equiv(chunks_by_id[8]), [])

    def test_if_handling_diamond_end_both_sides(self) -> None:
        # If true-false diamond case but the cases never converge.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                PushAction(102, ["b"]),
                AP2Action(103, AP2Action.END),
                # True case.
                PushAction(104, ["a"]),
                AP2Action(105, AP2Action.END),
            ]
        )
        chunks_by_id, offset_map = self.__call_graph(bytecode)
        self.assertEqual(offset_map, {100: 0, 102: 1, 104: 2, 106: 3})
        self.assertItemsEqual(chunks_by_id.keys(), {0, 1, 2, 3})
        self.assertItemsEqual(chunks_by_id[0].previous_chunks, [])
        self.assertItemsEqual(chunks_by_id[0].next_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[1].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[1].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[2].previous_chunks, [0])
        self.assertItemsEqual(chunks_by_id[2].next_chunks, [3])
        self.assertItemsEqual(chunks_by_id[3].previous_chunks, [1, 2])
        self.assertItemsEqual(chunks_by_id[3].next_chunks, [])

        # Also verify the code
        self.assertEqual(
            self.__equiv(chunks_by_id[0]),
            [
                f"100: PUSH{os.linesep}  True{os.linesep}END_PUSH",
                "101: IF, Comparison: IS TRUE, Offset To Jump To If True: 104",
            ],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[1]),
            [f"102: PUSH{os.linesep}  'b'{os.linesep}END_PUSH", "103: END"],
        )
        self.assertEqual(
            self.__equiv(chunks_by_id[2]),
            [f"104: PUSH{os.linesep}  'a'{os.linesep}END_PUSH", "105: END"],
        )
        self.assertEqual(self.__equiv(chunks_by_id[3]), [])


class TestAFPDecompile(ExtendedTestCase):
    # Note that the offsets made up in these test functions are not realistic. Jump/If instructions
    # take up more than one opcode, and the end offset might be more than one byte past the last
    # action if that action takes up more than one byte. However, from the perspective of the
    # decompiler, it doesn't care about accurate sizes, only that the offsets are correct.

    def __make_bytecode(self, actions: Sequence[AP2Action]) -> ByteCode:
        return ByteCode(
            None,
            actions,
            actions[-1].offset + 1,
        )

    def __call_decompile(self, bytecode: ByteCode) -> List[Statement]:
        # Just create a dummy compiler so we can access the internal method for testing.
        bcd = ByteCodeDecompiler(bytecode, optimize=True)
        bcd.decompile(verbose=self.verbose)
        return bcd.statements

    def __equiv(self, statements: List[Statement]) -> List[str]:
        return [str(x) for x in statements]

    def test_simple_bytecode(self) -> None:
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(self.__equiv(statements), ["builtin_StopPlaying()"])

    def test_jump_handling(self) -> None:
        bytecode = self.__make_bytecode(
            [
                JumpAction(100, 102),
                JumpAction(101, 104),
                JumpAction(102, 101),
                JumpAction(103, 106),
                JumpAction(104, 103),
                JumpAction(105, 107),
                JumpAction(106, 105),
                AP2Action(107, AP2Action.STOP),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(self.__equiv(statements), ["builtin_StopPlaying()"])

    def test_dead_code_elimination_jump(self) -> None:
        # Jump case
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
                JumpAction(101, 103),
                AP2Action(102, AP2Action.PLAY),
                AP2Action(103, AP2Action.STOP),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements), ["builtin_StopPlaying()", "builtin_StopPlaying()"]
        )

    def test_dead_code_elimination_return(self) -> None:
        # Return case
        bytecode = self.__make_bytecode(
            [
                PushAction(100, ["strval"]),
                AP2Action(101, AP2Action.RETURN),
                AP2Action(102, AP2Action.STOP),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(self.__equiv(statements), ["return 'strval'"])

    def test_dead_code_elimination_end(self) -> None:
        # Return case
        bytecode = self.__make_bytecode(
            [
                AP2Action(100, AP2Action.STOP),
                AP2Action(101, AP2Action.END),
                AP2Action(102, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(self.__equiv(statements), ["builtin_StopPlaying()"])

    def test_dead_code_elimination_throw(self) -> None:
        # Throw case
        bytecode = self.__make_bytecode(
            [
                PushAction(100, ["exception"]),
                AP2Action(101, AP2Action.THROW),
                AP2Action(102, AP2Action.STOP),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(self.__equiv(statements), ["throw 'exception'"])

    def test_if_handling_basic_flow_to_end(self) -> None:
        # If by itself case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_FALSE, 103),
                # False case (fall through from if).
                AP2Action(102, AP2Action.PLAY),
                # Line after the if statement.
                AP2Action(103, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  builtin_StartPlaying(){os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_basic_jump_to_end(self) -> None:
        # If by itself case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_FALSE, 103),
                # False case (fall through from if).
                AP2Action(102, AP2Action.PLAY),
                # Some code will jump to the end offset as a way of
                # "returning" early from a function.
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  builtin_StartPlaying(){os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_diamond(self) -> None:
        # If true-false diamond case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                AP2Action(102, AP2Action.STOP),
                JumpAction(103, 105),
                # True case.
                AP2Action(104, AP2Action.PLAY),
                # Line after the if statement.
                AP2Action(105, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  builtin_StartPlaying(){os.linesep}{CLOSE_BRACKET} else {OPEN_BRACKET}{os.linesep}  builtin_StopPlaying(){os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_diamond_jump_to_end(self) -> None:
        # If true-false diamond case.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                AP2Action(102, AP2Action.STOP),
                JumpAction(103, 105),
                # True case.
                AP2Action(104, AP2Action.PLAY),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  builtin_StartPlaying(){os.linesep}{CLOSE_BRACKET} else {OPEN_BRACKET}{os.linesep}  builtin_StopPlaying(){os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_diamond_return_to_end(self) -> None:
        # If true-false diamond case but the cases never converge.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                PushAction(102, ["b"]),
                AP2Action(103, AP2Action.RETURN),
                # True case.
                PushAction(104, ["a"]),
                AP2Action(105, AP2Action.RETURN),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  return 'a'{os.linesep}{CLOSE_BRACKET} else {OPEN_BRACKET}{os.linesep}  return 'b'{os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_switch(self) -> None:
        # Series of ifs (basically a switch statement).
        bytecode = self.__make_bytecode(
            [
                # Beginning of the first if statement.
                PushAction(100, [Register(0), 1]),
                IfAction(101, IfAction.COMP_NOT_EQUALS, 104),
                # False case (fall through from if).
                PushAction(102, ["a"]),
                JumpAction(103, 113),
                # Beginning of the second if statement.
                PushAction(104, [Register(0), 2]),
                IfAction(105, IfAction.COMP_NOT_EQUALS, 108),
                # False case (fall through from if).
                PushAction(106, ["b"]),
                JumpAction(107, 113),
                # Beginning of the third if statement.
                PushAction(108, [Register(0), 3]),
                IfAction(109, IfAction.COMP_NOT_EQUALS, 112),
                # False case (fall through from if).
                PushAction(110, ["c"]),
                JumpAction(111, 113),
                # Beginning of default case.
                PushAction(112, ["d"]),
                # Line after the switch statement.
                AP2Action(113, AP2Action.RETURN),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"switch (registers[0]) {OPEN_BRACKET}{os.linesep}"
                f"  case 1:{os.linesep}"
                f"    tempvar_0 = 'a'{os.linesep}"
                f"    break{os.linesep}"
                f"  case 2:{os.linesep}"
                f"    tempvar_0 = 'b'{os.linesep}"
                f"    break{os.linesep}"
                f"  case 3:{os.linesep}"
                f"    tempvar_0 = 'c'{os.linesep}"
                f"    break{os.linesep}"
                f"  default:{os.linesep}"
                f"    tempvar_0 = 'd'{os.linesep}"
                f"    break{os.linesep}"
                "}",
                "return tempvar_0",
            ],
        )

    def test_if_handling_diamond_end_both_sides(self) -> None:
        # If true-false diamond case but the cases never converge.
        bytecode = self.__make_bytecode(
            [
                # Beginning of the if statement.
                PushAction(100, [True]),
                IfAction(101, IfAction.COMP_IS_TRUE, 104),
                # False case (fall through from if).
                AP2Action(102, AP2Action.STOP),
                AP2Action(103, AP2Action.END),
                # True case.
                AP2Action(104, AP2Action.PLAY),
                AP2Action(105, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (True) {OPEN_BRACKET}{os.linesep}  builtin_StartPlaying(){os.linesep}{CLOSE_BRACKET} else {OPEN_BRACKET}{os.linesep}  builtin_StopPlaying(){os.linesep}{CLOSE_BRACKET}"
            ],
        )

    def test_if_handling_or(self) -> None:
        # Two ifs that together make an or (if register == 1 or register == 3)
        bytecode = self.__make_bytecode(
            [
                # Beginning of the first if statement.
                PushAction(100, [Register(0), 1]),
                IfAction(101, IfAction.COMP_EQUALS, 104),
                # False case (circuit not broken, register is not equal to 1)
                PushAction(102, [Register(0), 2]),
                IfAction(103, IfAction.COMP_NOT_EQUALS, 106),
                # This is the true case
                AP2Action(104, AP2Action.PLAY),
                JumpAction(105, 107),
                # This is the false case
                AP2Action(106, AP2Action.STOP),
                # This is the fall-through after the if.
                PushAction(107, ["strval"]),
                AP2Action(108, AP2Action.RETURN),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"if (registers[0] == 1 || registers[0] == 2) {OPEN_BRACKET}{os.linesep}"
                f"  builtin_StartPlaying(){os.linesep}"
                f"{CLOSE_BRACKET} else {OPEN_BRACKET}{os.linesep}"
                f"  builtin_StopPlaying(){os.linesep}"
                f"{CLOSE_BRACKET}",
                "return 'strval'",
            ],
        )

    def test_basic_while(self) -> None:
        # A basic while statement.
        bytecode = self.__make_bytecode(
            [
                # Define exit condition variable.
                PushAction(100, ["finished", False]),
                AP2Action(101, AP2Action.DEFINE_LOCAL),
                # Check exit condition.
                PushAction(102, ["finished"]),
                AP2Action(103, AP2Action.GET_VARIABLE),
                IfAction(104, IfAction.COMP_IS_TRUE, 107),
                # Loop code.
                AP2Action(105, AP2Action.NEXT_FRAME),
                # Loop finished jump back to beginning.
                JumpAction(106, 102),
                # End of loop.
                AP2Action(107, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                "local finished = False",
                f"while (not finished) {OPEN_BRACKET}{os.linesep}"
                f"  builtin_GotoNextFrame(){os.linesep}"
                "}",
            ],
        )

    def test_advanced_while(self) -> None:
        # A basic while statement.
        bytecode = self.__make_bytecode(
            [
                # Define exit condition variable.
                PushAction(100, ["finished", False]),
                AP2Action(101, AP2Action.DEFINE_LOCAL),
                # Check exit condition.
                PushAction(102, ["finished"]),
                AP2Action(103, AP2Action.GET_VARIABLE),
                IfAction(104, IfAction.COMP_IS_TRUE, 112),
                # Loop code with a continue statement.
                PushAction(105, ["some_condition"]),
                AP2Action(106, AP2Action.GET_VARIABLE),
                IfAction(107, IfAction.COMP_IS_FALSE, 110),
                AP2Action(108, AP2Action.NEXT_FRAME),
                # Continue statement.
                JumpAction(109, 102),
                # Exit early.
                AP2Action(110, AP2Action.STOP),
                # Break statement.
                JumpAction(111, 112),
                # End of loop.
                AP2Action(112, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                "local finished = False",
                f"while (not finished) {OPEN_BRACKET}{os.linesep}"
                f"  if (not some_condition) {OPEN_BRACKET}{os.linesep}"
                f"    builtin_StopPlaying(){os.linesep}"
                f"    break{os.linesep}"
                f"  {CLOSE_BRACKET}{os.linesep}"
                f"  builtin_GotoNextFrame(){os.linesep}"
                "}",
            ],
        )

    def test_basic_for(self) -> None:
        # A basic for statement.
        bytecode = self.__make_bytecode(
            [
                # Define exit condition variable.
                PushAction(100, ["i", 0]),
                AP2Action(101, AP2Action.DEFINE_LOCAL),
                # Check exit condition.
                PushAction(102, [10, "i"]),
                AP2Action(103, AP2Action.GET_VARIABLE),
                IfAction(104, IfAction.COMP_LT_EQUALS, 109),
                # Loop code.
                AP2Action(105, AP2Action.NEXT_FRAME),
                # Increment, also the continue point.
                PushAction(106, ["i"]),
                AddNumVariableAction(107, 1),
                # Loop finished jump back to beginning.
                JumpAction(108, 102),
                # End of loop.
                AP2Action(109, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"for (local i = 0; i < 10; i = i + 1) {OPEN_BRACKET}{os.linesep}"
                f"  builtin_GotoNextFrame(){os.linesep}"
                "}"
            ],
        )

    def test_advanced_for(self) -> None:
        # A basic for statement.
        bytecode = self.__make_bytecode(
            [
                # Define exit condition variable.
                PushAction(100, ["i", 0]),
                AP2Action(101, AP2Action.DEFINE_LOCAL),
                # Check exit condition.
                PushAction(102, [10, "i"]),
                AP2Action(103, AP2Action.GET_VARIABLE),
                IfAction(104, IfAction.COMP_LT_EQUALS, 115),
                # Loop code with a continue statement.
                PushAction(105, ["some_condition"]),
                AP2Action(106, AP2Action.GET_VARIABLE),
                IfAction(107, IfAction.COMP_IS_FALSE, 110),
                AP2Action(108, AP2Action.NEXT_FRAME),
                # Continue statement.
                JumpAction(109, 112),
                # Exit early.
                AP2Action(110, AP2Action.STOP),
                # Break statement.
                JumpAction(111, 115),
                # Increment, also the continue point.
                PushAction(112, ["i"]),
                AddNumVariableAction(113, 1),
                # Loop finished jump back to beginning.
                JumpAction(114, 102),
                # End of loop.
                AP2Action(115, AP2Action.END),
            ]
        )
        statements = self.__call_decompile(bytecode)
        self.assertEqual(
            self.__equiv(statements),
            [
                f"for (local i = 0; i < 10; i = i + 1) {OPEN_BRACKET}{os.linesep}"
                f"  if (not some_condition) {OPEN_BRACKET}{os.linesep}"
                f"    builtin_StopPlaying(){os.linesep}"
                f"    break{os.linesep}"
                f"  {CLOSE_BRACKET}{os.linesep}"
                f"  builtin_GotoNextFrame(){os.linesep}"
                "}"
            ],
        )


class TestIfExprs(ExtendedTestCase):
    def test_simple(self) -> None:
        self.assertEqual(str(IsUndefinedIf(Variable("a"))), "a is UNDEFINED")
        self.assertEqual(str(IsBooleanIf(Variable("a"))), "a")
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.EQUALS, Variable("b"))),
            "a == b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.NOT_EQUALS, Variable("b"))
            ),
            "a != b",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b"))),
            "a < b",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b"))),
            "a > b",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.LT_EQUALS, Variable("b"))),
            "a <= b",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b"))),
            "a >= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_EQUALS, Variable("b")
                )
            ),
            "a === b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_NOT_EQUALS, Variable("b")
                )
            ),
            "a !== b",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
            ),
            "a < b && c > d",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
            ),
            "a < b || c > d",
        )

    def test_invert_simple(self) -> None:
        self.assertEqual(
            str(IsUndefinedIf(Variable("a")).invert()), "a is not UNDEFINED"
        )
        self.assertEqual(str(IsBooleanIf(Variable("a")).invert()), "not a")
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.EQUALS, Variable("b")
                ).invert()
            ),
            "a != b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.NOT_EQUALS, Variable("b")
                ).invert()
            ),
            "a == b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")).invert()
            ),
            "a >= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b")).invert()
            ),
            "a <= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.LT_EQUALS, Variable("b")
                ).invert()
            ),
            "a > b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b")
                ).invert()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_EQUALS, Variable("b")
                ).invert()
            ),
            "a !== b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_NOT_EQUALS, Variable("b")
                ).invert()
            ),
            "a === b",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).invert()
            ),
            "a >= b || c <= d",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).invert(),
            ),
            "a >= b && c <= d",
        )

    def test_invert_double(self) -> None:
        self.assertEqual(
            str(IsUndefinedIf(Variable("a")).invert().invert()), "a is UNDEFINED"
        )
        self.assertEqual(str(IsBooleanIf(Variable("a")).invert().invert()), "a")
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.EQUALS, Variable("b"))
                .invert()
                .invert()
            ),
            "a == b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.NOT_EQUALS, Variable("b"))
                .invert()
                .invert()
            ),
            "a != b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b"))
                .invert()
                .invert()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b"))
                .invert()
                .invert()
            ),
            "a > b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.LT_EQUALS, Variable("b"))
                .invert()
                .invert()
            ),
            "a <= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b"))
                .invert()
                .invert()
            ),
            "a >= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_EQUALS, Variable("b")
                )
                .invert()
                .invert()
            ),
            "a === b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_NOT_EQUALS, Variable("b")
                )
                .invert()
                .invert()
            ),
            "a !== b",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
                .invert()
                .invert()
            ),
            "a < b && c > d",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
                .invert()
                .invert()
            ),
            "a < b || c > d",
        )

    def test_swap_simple(self) -> None:
        self.assertEqual(str(IsUndefinedIf(Variable("a")).swap()), "a is UNDEFINED")
        self.assertEqual(str(IsBooleanIf(Variable("a")).swap()), "a")
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.EQUALS, Variable("b")
                ).swap()
            ),
            "b == a",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.NOT_EQUALS, Variable("b")
                ).swap()
            ),
            "b != a",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")).swap()),
            "b > a",
        )
        self.assertEqual(
            str(TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b")).swap()),
            "b < a",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.LT_EQUALS, Variable("b")
                ).swap()
            ),
            "b >= a",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b")
                ).swap()
            ),
            "b <= a",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_EQUALS, Variable("b")
                ).swap()
            ),
            "b === a",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_NOT_EQUALS, Variable("b")
                ).swap()
            ),
            "b !== a",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).swap()
            ),
            "c > d && a < b",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).swap(),
            ),
            "c > d || a < b",
        )

    def test_swap_double(self) -> None:
        self.assertEqual(
            str(IsUndefinedIf(Variable("a")).swap().swap()), "a is UNDEFINED"
        )
        self.assertEqual(str(IsBooleanIf(Variable("a")).swap().swap()), "a")
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.EQUALS, Variable("b"))
                .swap()
                .swap()
            ),
            "a == b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.NOT_EQUALS, Variable("b"))
                .swap()
                .swap()
            ),
            "a != b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b"))
                .swap()
                .swap()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b"))
                .swap()
                .swap()
            ),
            "a > b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.LT_EQUALS, Variable("b"))
                .swap()
                .swap()
            ),
            "a <= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b"))
                .swap()
                .swap()
            ),
            "a >= b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_EQUALS, Variable("b")
                )
                .swap()
                .swap()
            ),
            "a === b",
        )
        self.assertEqual(
            str(
                TwoParameterIf(
                    Variable("a"), TwoParameterIf.STRICT_NOT_EQUALS, Variable("b")
                )
                .swap()
                .swap()
            ),
            "a !== b",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
                .swap()
                .swap()
            ),
            "a < b && c > d",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                )
                .swap()
                .swap()
            ),
            "a < b || c > d",
        )

    def test_simplify_noop(self) -> None:
        self.assertEqual(str(IsUndefinedIf(Variable("a")).simplify()), "a is UNDEFINED")
        self.assertEqual(
            str(IsUndefinedIf(Variable("a")).invert().simplify()), "a is not UNDEFINED"
        )
        self.assertEqual(str(IsBooleanIf(Variable("a")).simplify()), "a")
        self.assertEqual(str(IsBooleanIf(Variable("a")).invert().simplify()), "not a")
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).simplify()
            ),
            "a < b && c > d",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("c"), TwoParameterIf.GT, Variable("d")),
                ).simplify()
            ),
            "a < b || c > d",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(
                        Variable("a"), TwoParameterIf.GT_EQUALS, Variable("c")
                    ),
                ).simplify()
            ),
            "a < b && a >= c",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(Variable("a"), TwoParameterIf.GT, Variable("b")),
                ).simplify()
            ),
            "a < b || a > b",
        )

    def test_simplify_basic(self) -> None:
        self.assertEqual(str(IsUndefinedIf(UNDEFINED).simplify()), "True")
        self.assertEqual(str(IsUndefinedIf(UNDEFINED).invert().simplify()), "False")
        self.assertEqual(str(IsBooleanIf(True).simplify()), "True")
        self.assertEqual(str(IsBooleanIf(True).invert().simplify()), "False")
        self.assertEqual(str(IsBooleanIf(False).simplify()), "False")
        self.assertEqual(str(IsBooleanIf(False).invert().simplify()), "True")

    def test_simplify_compound(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    IsBooleanIf(True),
                ).simplify()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    IsBooleanIf(False),
                ).simplify()
            ),
            "False",
        )
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(True),
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                ).simplify()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(False),
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                ).simplify()
            ),
            "False",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    IsBooleanIf(True),
                ).simplify()
            ),
            "True",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    IsBooleanIf(False),
                ).simplify()
            ),
            "a < b",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(True),
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                ).simplify()
            ),
            "True",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(False),
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                ).simplify()
            ),
            "a < b",
        )

    def test_simplify_equivalent(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(
                        Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b")
                    ),
                ).simplify()
            ),
            "False",
        )
        self.assertEqual(
            str(
                OrIf(
                    TwoParameterIf(Variable("a"), TwoParameterIf.LT, Variable("b")),
                    TwoParameterIf(
                        Variable("a"), TwoParameterIf.GT_EQUALS, Variable("b")
                    ),
                ).simplify()
            ),
            "True",
        )

    def test_equals_associativity(self) -> None:
        self.assertEqual(
            AndIf(
                IsBooleanIf(Variable("a")),
                AndIf(
                    IsBooleanIf(Variable("b")),
                    IsBooleanIf(Variable("c")),
                ),
            ),
            AndIf(
                AndIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("b")),
                ),
                IsBooleanIf(Variable("c")),
            ),
        )
        self.assertEqual(
            OrIf(
                IsBooleanIf(Variable("a")),
                OrIf(
                    IsBooleanIf(Variable("b")),
                    IsBooleanIf(Variable("c")),
                ),
            ),
            OrIf(
                OrIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("b")),
                ),
                IsBooleanIf(Variable("c")),
            ),
        )

    def test_equals_commutativity(self) -> None:
        self.assertEqual(
            AndIf(
                IsBooleanIf(Variable("a")),
                IsBooleanIf(Variable("b")),
            ),
            AndIf(
                IsBooleanIf(Variable("b")),
                IsBooleanIf(Variable("a")),
            ),
        )
        self.assertEqual(
            OrIf(
                IsBooleanIf(Variable("a")),
                IsBooleanIf(Variable("b")),
            ),
            OrIf(
                IsBooleanIf(Variable("b")),
                IsBooleanIf(Variable("a")),
            ),
        )

    def test_simplify_identity(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(True),
                ).simplify(),
            ),
            "a",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(False),
                ).simplify(),
            ),
            "a",
        )

    def test_simplify_annihilation(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(False),
                ).simplify(),
            ),
            "False",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(True),
                ).simplify(),
            ),
            "True",
        )

    def test_simplify_idempotence(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("a")),
                ).simplify(),
            ),
            "a",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("a")),
                ).simplify(),
            ),
            "a",
        )

    def test_simplify_complementation(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("a")).invert(),
                ).simplify(),
            ),
            "False",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("a")),
                    IsBooleanIf(Variable("a")).invert(),
                ).simplify(),
            ),
            "True",
        )

    def test_simplify_elimination(self) -> None:
        self.assertEqual(
            str(
                OrIf(
                    AndIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")),
                    ),
                    AndIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")).invert(),
                    ),
                ).simplify(),
            ),
            "x",
        )
        self.assertEqual(
            str(
                AndIf(
                    OrIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")),
                    ),
                    OrIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")).invert(),
                    ),
                ).simplify(),
            ),
            "x",
        )

    def test_simplify_absorption(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("x")),
                    OrIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")),
                    ),
                ).simplify(),
            ),
            "x",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("x")),
                    AndIf(
                        IsBooleanIf(Variable("x")),
                        IsBooleanIf(Variable("y")),
                    ),
                ).simplify(),
            ),
            "x",
        )

    def test_simplify_negative_absorption(self) -> None:
        self.assertEqual(
            str(
                AndIf(
                    IsBooleanIf(Variable("x")),
                    OrIf(
                        IsBooleanIf(Variable("x")).invert(),
                        IsBooleanIf(Variable("y")),
                    ),
                ).simplify(),
            ),
            "x && y",
        )
        self.assertEqual(
            str(
                OrIf(
                    IsBooleanIf(Variable("x")),
                    AndIf(
                        IsBooleanIf(Variable("x")).invert(),
                        IsBooleanIf(Variable("y")),
                    ),
                ).simplify(),
            ),
            "x || y",
        )


class TestAFPOptimize(ExtendedTestCase):
    def __optimize_code(self, statements: Sequence[Statement]) -> List[str]:
        bcd = ByteCodeDecompiler(
            ByteCode(
                None,
                [],
                -1,
            ),
            optimize=True,
        )
        with bcd.debugging(verbose=self.verbose):
            return bcd._pretty_print(bcd._optimize_code(statements), prefix="").split(
                os.linesep
            )

    def test_no_flow(self) -> None:
        statements: List[Statement] = [
            PlayMovieStatement(),
            StopMovieStatement(),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "builtin_StartPlaying();",
                "builtin_StopPlaying();",
            ],
        )

    def test_basic_flow(self) -> None:
        statements: List[Statement] = [
            PlayMovieStatement(),
            IfStatement(
                IsBooleanIf(
                    Variable("a"),
                ),
                [
                    NextFrameStatement(),
                ],
                [
                    PreviousFrameStatement(),
                ],
            ),
            StopMovieStatement(),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "builtin_StartPlaying();",
                "if (a)",
                "{",
                "    builtin_GotoNextFrame();",
                "}",
                "else",
                "{",
                "    builtin_GotoPreviousFrame();",
                "}",
                "builtin_StopPlaying();",
            ],
        )

    def test_compound_or_basic(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            StopMovieStatement(),
                            DefineLabelStatement(1000),
                            ReturnStatement("strval"),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            PlayMovieStatement(),
            GotoStatement(1000),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2)",
                "{",
                "    builtin_StartPlaying();",
                "}",
                "else",
                "{",
                "    builtin_StopPlaying();",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_alternate(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            StopMovieStatement(),
                            GotoStatement(1000),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            PlayMovieStatement(),
            DefineLabelStatement(1000),
            ReturnStatement("strval"),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2)",
                "{",
                "    builtin_StartPlaying();",
                "}",
                "else",
                "{",
                "    builtin_StopPlaying();",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_inside_if(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                IsBooleanIf(
                    Variable("debug"),
                ).invert(),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            1,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("a"),
                                    TwoParameterIf.NOT_EQUALS,
                                    2,
                                ),
                                [
                                    StopMovieStatement(),
                                    DefineLabelStatement(1000),
                                    ReturnStatement("strval"),
                                ],
                                [],
                            ),
                        ],
                        [],
                    ),
                    PlayMovieStatement(),
                    GotoStatement(1000),
                ],
                [],
            ),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (not debug)",
                "{",
                "    if (a == 1 || a == 2)",
                "    {",
                "        builtin_StartPlaying();",
                "    }",
                "    else",
                "    {",
                "        builtin_StopPlaying();",
                "    }",
                "    return 'strval';",
                "}",
            ],
        )

    def test_compound_or_inside_while(self) -> None:
        statements: List[Statement] = [
            ForStatement(
                "x",
                0,
                TwoParameterIf(
                    Variable("x"),
                    TwoParameterIf.LT,
                    10,
                ),
                ArithmeticExpression(
                    Variable("x"),
                    "+",
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            1,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("a"),
                                    TwoParameterIf.NOT_EQUALS,
                                    2,
                                ),
                                [
                                    StopMovieStatement(),
                                    DefineLabelStatement(1000),
                                    ReturnStatement("strval"),
                                ],
                                [],
                            ),
                        ],
                        [],
                    ),
                    PlayMovieStatement(),
                    GotoStatement(1000),
                ],
                local=True,
            ),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "for (local x = 0; x < 10; x = x + 1)",
                "{",
                "    if (a == 1 || a == 2)",
                "    {",
                "        builtin_StartPlaying();",
                "    }",
                "    else",
                "    {",
                "        builtin_StopPlaying();",
                "    }",
                "    return 'strval';",
                "}",
            ],
        )

    def test_compound_or_with_inner_if(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("x"),
                                    TwoParameterIf.EQUALS,
                                    5,
                                ),
                                [
                                    StopMovieStatement(),
                                ],
                                [],
                            ),
                            DefineLabelStatement(1000),
                            ReturnStatement("strval"),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            IfStatement(
                TwoParameterIf(
                    Variable("x"),
                    TwoParameterIf.EQUALS,
                    10,
                ),
                [
                    PlayMovieStatement(),
                ],
                [],
            ),
            GotoStatement(1000),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2)",
                "{",
                "    if (x == 10)",
                "    {",
                "        builtin_StartPlaying();",
                "    }",
                "}",
                "else",
                "{",
                "    if (x == 5)",
                "    {",
                "        builtin_StopPlaying();",
                "    }",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_with_inner_compound_or(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("x"),
                                    TwoParameterIf.NOT_EQUALS,
                                    10,
                                ),
                                [
                                    IfStatement(
                                        TwoParameterIf(
                                            Variable("x"),
                                            TwoParameterIf.NOT_EQUALS,
                                            20,
                                        ),
                                        [
                                            StopMovieStatement(),
                                            GotoStatement(1000),
                                        ],
                                        [],
                                    ),
                                ],
                                [],
                            ),
                            PlayMovieStatement(),
                            GotoStatement(1000),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            NextFrameStatement(),
            PreviousFrameStatement(),
            DefineLabelStatement(1000),
            ReturnStatement("strval"),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2)",
                "{",
                "    builtin_GotoNextFrame();",
                "    builtin_GotoPreviousFrame();",
                "}",
                "else",
                "{",
                "    if (x == 10 || x == 20)",
                "    {",
                "        builtin_StartPlaying();",
                "    }",
                "    else",
                "    {",
                "        builtin_StopPlaying();",
                "    }",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_triple(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("a"),
                                    TwoParameterIf.NOT_EQUALS,
                                    3,
                                ),
                                [
                                    StopMovieStatement(),
                                    DefineLabelStatement(1000),
                                    ReturnStatement("strval"),
                                ],
                                [],
                            ),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            PlayMovieStatement(),
            GotoStatement(1000),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2 || a == 3)",
                "{",
                "    builtin_StartPlaying();",
                "}",
                "else",
                "{",
                "    builtin_StopPlaying();",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_quad(self) -> None:
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("a"),
                                    TwoParameterIf.NOT_EQUALS,
                                    3,
                                ),
                                [
                                    IfStatement(
                                        TwoParameterIf(
                                            Variable("a"),
                                            TwoParameterIf.NOT_EQUALS,
                                            4,
                                        ),
                                        [
                                            StopMovieStatement(),
                                            DefineLabelStatement(1000),
                                            ReturnStatement("strval"),
                                        ],
                                        [],
                                    ),
                                ],
                                [],
                            ),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            PlayMovieStatement(),
            GotoStatement(1000),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2 || a == 3 || a == 4)",
                "{",
                "    builtin_StartPlaying();",
                "}",
                "else",
                "{",
                "    builtin_StopPlaying();",
                "}",
                "return 'strval';",
            ],
        )

    def test_compound_or_quint(self) -> None:
        # Okay, at this point I believe that the algorithm works...
        statements: List[Statement] = [
            IfStatement(
                TwoParameterIf(
                    Variable("a"),
                    TwoParameterIf.NOT_EQUALS,
                    1,
                ),
                [
                    IfStatement(
                        TwoParameterIf(
                            Variable("a"),
                            TwoParameterIf.NOT_EQUALS,
                            2,
                        ),
                        [
                            IfStatement(
                                TwoParameterIf(
                                    Variable("a"),
                                    TwoParameterIf.NOT_EQUALS,
                                    3,
                                ),
                                [
                                    IfStatement(
                                        TwoParameterIf(
                                            Variable("a"),
                                            TwoParameterIf.NOT_EQUALS,
                                            4,
                                        ),
                                        [
                                            IfStatement(
                                                TwoParameterIf(
                                                    Variable("a"),
                                                    TwoParameterIf.NOT_EQUALS,
                                                    5,
                                                ),
                                                [
                                                    StopMovieStatement(),
                                                    DefineLabelStatement(1000),
                                                    ReturnStatement("strval"),
                                                ],
                                                [],
                                            ),
                                        ],
                                        [],
                                    ),
                                ],
                                [],
                            ),
                        ],
                        [],
                    ),
                ],
                [],
            ),
            PlayMovieStatement(),
            GotoStatement(1000),
        ]

        self.assertEqual(
            self.__optimize_code(statements),
            [
                "if (a == 1 || a == 2 || a == 3 || a == 4 || a == 5)",
                "{",
                "    builtin_StartPlaying();",
                "}",
                "else",
                "{",
                "    builtin_StopPlaying();",
                "}",
                "return 'strval';",
            ],
        )
