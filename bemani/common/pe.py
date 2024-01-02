import pefile  # type: ignore
import struct
import sys
from iced_x86 import (
    Decoder,
    Instruction,
    Formatter,
    FormatterSyntax,
    FormatMnemonicOptions,
)
from typing import Any, List, Dict, Optional


class Memory:
    def __init__(self) -> None:
        self.values: Dict[int, int] = {}
        self.defaults: Dict[int, bytes] = {}

    def init(self, min_offset: int, max_offset: int) -> None:
        for i in range(min_offset + 1, max_offset + 1):
            self.store(i, self.load(i, 1))

    def store(self, offset: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.values[i + offset] = b

    def load(self, offset: int, length: int) -> bytes:
        data: List[int] = []

        for i in range(offset, offset + length):
            if i in self.values:
                # Return modified value.
                data.append(self.values[i])
            else:
                # Attempt to return the default.
                for virtual_start in self.defaults:
                    if i >= virtual_start and i < (virtual_start + len(self.defaults[virtual_start])):
                        data.append(self.defaults[virtual_start][i - virtual_start])
                        break
                else:
                    # Nothing here, return initialized RAM.
                    data.append(0)

        return bytes(data)


class Registers:
    def __init__(self, stack: int) -> None:
        self.rax = 0
        self.rbx = 0
        self.rcx = 0
        self.rdx = 0
        self.rsi = 0
        self.rdi = 0
        self.rbp = 0
        self.rsp = stack

        self.zf = False
        self.sf = False


class JumpException(Exception):
    def __init__(self, address: int, message: str) -> None:
        super().__init__(message)
        self.address = address


class RetException(Exception):
    pass


class InvalidOffsetException(Exception):
    pass


class InvalidVirtualOffsetException(InvalidOffsetException):
    pass


class InvalidPhysicalOffsetException(InvalidOffsetException):
    pass


class PEFile:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.__pe = pefile.PE(data=data, fast_load=True)
        self.__adhoc_mapping: Dict[int, int] = {}

    def virtual_to_physical(self, offset: int) -> int:
        for section in self.__pe.sections:
            start = section.VirtualAddress + self.__pe.OPTIONAL_HEADER.ImageBase
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.PointerToRawData

        for virtual, physical in self.__adhoc_mapping.items():
            if offset == virtual:
                return physical

        raise InvalidVirtualOffsetException(f"Couldn't find physical offset for virtual offset 0x{offset:08x}")

    def physical_to_virtual(self, offset: int) -> int:
        for section in self.__pe.sections:
            start = section.PointerToRawData
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.VirtualAddress + self.__pe.OPTIONAL_HEADER.ImageBase

        for virtual, physical in self.__adhoc_mapping.items():
            if offset == physical:
                return virtual

        raise InvalidPhysicalOffsetException(f"Couldn't find virtual offset for physical offset 0x{offset:08x}")

    def is_virtual(self, offset: int) -> bool:
        return offset >= self.__pe.OPTIONAL_HEADER.ImageBase

    def is_64bit(self) -> bool:
        return hex(self.__pe.FILE_HEADER.Machine) == "0x8664"

    def emulate_code(self, start: int, end: int, verbose: bool = False) -> None:
        if self.is_virtual(start):
            # Assume this is virtual
            start = self.virtual_to_physical(start)
        if self.is_virtual(end):
            # Assume this is virtual
            end = self.virtual_to_physical(end)

        registers = Registers(0xFFFFFFFFFFFFFFFF if self.is_64bit() else 0xFFFFFFFF)
        memory = self.__to_memory()

        decoder = Decoder(
            64 if self.is_64bit() else 32,
            self.data[start:end],
            ip=self.physical_to_virtual(start),
        )
        self.__emulate_chunk(registers, memory, [i for i in decoder], verbose)

        # Replace memory that we care about.
        self.__update(memory)

    def emulate_function(self, start: int, verbose: bool = False) -> None:
        if self.is_virtual(start):
            # Assume this is virtual
            start = self.virtual_to_physical(start)

        registers = Registers(0xFFFFFFFFFFFFFFFF if self.is_64bit() else 0xFFFFFFFF)
        memory = self.__to_memory()

        # Need to fetch one at a time, emulating until we get a ret.
        loc = start
        end = len(self.data)
        while True:
            decoder = Decoder(
                64 if self.is_64bit() else 32,
                self.data[loc:end],
                ip=self.physical_to_virtual(loc),
            )
            chunk = [decoder.decode()]

            try:
                # First attempt to just run the instruction as normal.
                self.__emulate_chunk(registers, memory, chunk, verbose)
                loc = self.virtual_to_physical(chunk[0].next_ip)
            except JumpException as jmp:
                # We need to jump elsewhere.
                loc = self.virtual_to_physical(jmp.address)
            except RetException:
                # We're done!
                break

        # Replace memory that we care about.
        self.__update(memory)

    def __to_memory(self) -> Memory:
        memory = Memory()

        for section in self.__pe.sections:
            virtual = section.VirtualAddress + self.__pe.OPTIONAL_HEADER.ImageBase
            length = section.SizeOfRawData
            physical = self.virtual_to_physical(virtual)
            memory.defaults[virtual] = self.data[physical : (physical + length)]

        for virtual, physical in self.__adhoc_mapping.items():
            memory.values[virtual] = self.data[physical]

        return memory

    def __update(self, memory: Memory) -> None:
        newdata = [x for x in self.data]
        for virtual in sorted(memory.values):
            try:
                physical = self.virtual_to_physical(virtual)
                newdata[physical] = memory.values[virtual]
            except Exception:
                # This is outside of the data we are tracking. Its really not ideal
                # that we are just shoving this at the end of the data, but it should
                # work for what we care about.
                physical = len(newdata)
                self.__adhoc_mapping[virtual] = physical
                newdata.append(memory.values[virtual])

        self.data = bytes(newdata)
        self.__pe = pefile.PE(data=self.data, fast_load=True)

    def __emulate_chunk(
        self,
        registers: Registers,
        memory: Memory,
        chunk: List[Instruction],
        verbose: bool,
    ) -> None:
        if verbose:

            def vprint(*args: Any, **kwargs: Any) -> None:
                print(*args, **kwargs, file=sys.stderr)

        else:

            def vprint(*args: Any, **kwargs: Any) -> None:
                pass

        # Stuck here so that jump can bind to it.
        loc: int = 0

        def jump(destination: int) -> None:
            nonlocal loc

            for i in range(len(chunk)):
                if chunk[i].ip == destination:
                    # Jump to this instruction.
                    loc = i
                    break
            else:
                if destination == chunk[-1].next_ip:
                    # Jump to the end, we're done.
                    loc = len(chunk)
                else:
                    raise JumpException(
                        destination,
                        f"Jumping to {hex(destination)} which is outside of our evaluation range!",
                    )

        formatter = Formatter(FormatterSyntax.NASM)

        while loc < len(chunk):
            inst = chunk[loc]
            loc = loc + 1
            mnemonic = formatter.format_mnemonic(inst, FormatMnemonicOptions.NO_PREFIXES)

            if mnemonic == "mov":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"mov {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, src)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "movzx":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"movzx {dest}, {src}")

                srcsize = get_size(src)
                dstsize = get_size(dest)
                if srcsize is None or dstsize is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, srcsize, src)
                assign(registers, memory, dstsize, dest, result)

            elif mnemonic == "add":
                dest = formatter.format_operand(inst, 0)
                amt = formatter.format_operand(inst, 1)

                vprint(f"add {dest}, {amt}")

                size = get_size(amt) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")

                # Special case for adjusting ESP, to make sure our memory contains zeros for reading
                # out the stack later.
                if dest == "esp":
                    before = fetch(registers, memory, size, dest)
                    after = before + fetch(registers, memory, size, amt)
                    memory.init(min(before, after), max(before, after))
                    assign(registers, memory, size, dest, after)
                else:
                    result = fetch(registers, memory, size, dest) + fetch(registers, memory, size, amt)
                    assign(registers, memory, size, dest, result)

            elif mnemonic == "sub":
                dest = formatter.format_operand(inst, 0)
                amt = formatter.format_operand(inst, 1)

                vprint(f"sub {dest}, {amt}")

                size = get_size(amt) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")

                # Special case for adjusting ESP, to make sure our memory contains zeros for reading
                # out the stack later.
                if dest == "esp":
                    before = fetch(registers, memory, size, dest)
                    after = before - fetch(registers, memory, size, amt)
                    memory.init(min(before, after), max(before, after))
                    assign(registers, memory, size, dest, after)
                else:
                    result = fetch(registers, memory, size, dest) - fetch(registers, memory, size, amt)
                    assign(registers, memory, size, dest, result)

            elif mnemonic == "imul":
                dest = formatter.format_operand(inst, 0)
                mult = formatter.format_operand(inst, 1)
                try:
                    const = formatter.format_operand(inst, 2)
                    vprint(f"imul {dest}, {mult}, {const}")
                except Exception:
                    const = None
                    vprint(f"imul {dest}, {mult}")

                size = get_size(mult) or get_size(dest) or (get_size(const) if const is not None else None)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                if const is None:
                    result = fetch(registers, memory, size, dest) * fetch(registers, memory, size, mult)
                else:
                    result = fetch(registers, memory, size, mult) * get_value(const)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "push":
                src = formatter.format_operand(inst, 0)

                vprint(f"push {src}")

                size = get_size(src)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, src)
                registers.rsp -= size
                assign(
                    registers,
                    memory,
                    size,
                    "[rsp]" if self.is_64bit() else "[esp]",
                    result,
                )

            elif mnemonic == "pop":
                dest = formatter.format_operand(inst, 0)

                vprint(f"pop {dest}")

                size = get_size(src)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, "[rsp]" if self.is_64bit() else "[esp]")
                assign(registers, memory, size, dest, result)
                registers.rsp += size

            elif mnemonic == "test":
                op1 = formatter.format_operand(inst, 0)
                op2 = formatter.format_operand(inst, 1)

                vprint(f"test {op1}, {op2}")

                size = get_size(op1) or get_size(op2)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, op1) & fetch(registers, memory, size, op2)

                registers.zf = result == 0
                if size == 1:
                    registers.sf = (result & 0x80) != 0
                if size == 2:
                    registers.sf = (result & 0x8000) != 0
                if size == 4:
                    registers.sf = (result & 0x80000000) != 0
                if size == 8:
                    registers.sf = (result & 0x8000000000000000) != 0

            elif mnemonic == "jne":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jnz {dest}")

                if not registers.zf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")
                    jump(destination)

            elif mnemonic == "je":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jz {dest}")

                if registers.zf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")
                    jump(destination)

            elif mnemonic == "jns":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jns {dest}")

                if not registers.sf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")
                    jump(destination)

            elif mnemonic == "js":
                dest = formatter.format_operand(inst, 0)

                vprint(f"js {dest}")

                if registers.sf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")
                    jump(destination)

            elif mnemonic == "jmp":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jmp {dest}")

                destination = get_value(dest)
                if destination is None:
                    raise Exception(f"Jumping to unsupported destination {dest}")
                jump(destination)

            elif mnemonic == "and":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"and {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, dest) & fetch(registers, memory, size, src)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "or":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"or {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, dest) | fetch(registers, memory, size, src)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "xor":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"xor {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, dest) ^ fetch(registers, memory, size, src)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "lea":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"lea {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = get_address(registers, src)
                if result is None:
                    raise Exception(f"Could not compute effective address for {mnemonic} operation!")
                assign(registers, memory, size, dest, result)

            elif mnemonic == "ret":
                vprint("ret")

                raise RetException("Encountered {mnemonic} instruction but we aren't in function context!")

            else:
                raise Exception(f"Unsupported mnemonic {mnemonic}!")


def sanitize(indirect: str) -> str:
    """
    Given an indirect address or a value from iced-x86 as formatted by the
    operand formatter, sanitize it by getting rid of size specifiers.
    """

    if indirect[:5] == "near ":
        indirect = indirect[5:]

    if indirect[:4] == "rel ":
        indirect = indirect[4:]

    if indirect[:6] == "short ":
        indirect = indirect[6:]

    if indirect[:5] == "byte ":
        indirect = indirect[5:]

    if indirect[:5] == "word ":
        indirect = indirect[5:]

    if indirect[:6] == "dword ":
        indirect = indirect[6:]

    if indirect[:6] == "qword ":
        indirect = indirect[6:]

    return indirect


def get_address(registers: Registers, indirect: str) -> Optional[int]:
    """
    Given an indirect reference as formatted by the iced-x86 operand formatter,
    resolve it to an actual 32-bit address that we should load from or store to.
    This optionally supports indirect register address format so that we can
    conveniently specify fetches and stores from the stack. If the value we
    receive is not actually an indirect reference, return None.
    """

    indirect = sanitize(indirect)

    if indirect[0] == "[" and indirect[-1] == "]":
        indirect = sanitize(indirect[1:-1])

        adjust = 0
        if "+" in indirect:
            indirect, const = indirect.split("+", 1)
            indirect = sanitize(indirect)
            const = sanitize(const)

            if const[-1] == "h":
                adjust = int(const[:-1], 16)
            else:
                adjust = int(const, 10)
        elif "-" in indirect:
            indirect, const = indirect.split("-", 1)
            indirect = sanitize(indirect)
            const = sanitize(const)

            if const[-1] == "h":
                adjust = -int(const[:-1], 16)
            else:
                adjust = -int(const, 10)

        if indirect[-1] == "h":
            return int(indirect[:-1], 16) + adjust

        # Register-based indirect modes.
        if indirect == "rsp":
            return registers.rsp + adjust
        if indirect == "esp":
            return (registers.rsp & 0xFFFFFFFF) + adjust
        if indirect == "sp":
            return (registers.rsp & 0xFFFF) + adjust
        if indirect == "spl":
            return (registers.rsp & 0xFF) + adjust
        if indirect == "rbp":
            return registers.rbp + adjust
        if indirect == "ebp":
            return (registers.rbp & 0xFFFFFFFF) + adjust
        if indirect == "bp":
            return (registers.rbp & 0xFFFF) + adjust
        if indirect == "bp":
            return (registers.rbp & 0xFF) + adjust
        if indirect == "rsi":
            return registers.rsi + adjust
        if indirect == "esi":
            return (registers.rsi & 0xFFFFFFFF) + adjust
        if indirect == "si":
            return (registers.rsi & 0xFFFF) + adjust
        if indirect == "si":
            return (registers.rsi & 0xFF) + adjust
        if indirect == "rdi":
            return registers.rdi + adjust
        if indirect == "edi":
            return (registers.rdi & 0xFFFFFFFF) + adjust
        if indirect == "di":
            return (registers.rdi & 0xFFFF) + adjust
        if indirect == "di":
            return (registers.rdi & 0xFF) + adjust

        raise Exception(f"Unsupported indirect address {indirect}!")
    return None


def get_value(immediate: str) -> Optional[int]:
    """
    Given an immediate value as formatted by the iced-x86 operand formatter,
    resolve it to an immediate integer. If the value we receive is not
    actually an immediate value, return None.
    """

    immediate = sanitize(immediate)

    if immediate[-1] == "h":
        try:
            return int(immediate[:-1], 16)
        except Exception:
            return None

    try:
        return int(immediate, 10)
    except Exception:
        return None


def get_size(operand: str) -> Optional[int]:
    """
    Given an operand as formatted by the iced-x86 operand formatter, return
    the size in bytes that that operand represents in a load or store.
    Supports both registers and byte/word/dword/qword specifiers in front of
    immediate values and indirect memory references.
    """

    if operand in {"rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi"}:
        return 8
    if operand in {"eax", "ebx", "ecx", "edx", "esp", "ebp", "esi", "edi"}:
        return 4
    if operand in {"ax", "bx", "cx", "dx", "sp", "bp", "si", "di"}:
        return 2
    if operand in {
        "ah",
        "al",
        "bh",
        "bl",
        "ch",
        "cl",
        "dh",
        "dl",
        "spl",
        "bpl",
        "sil",
        "dil",
    }:
        return 1

    if operand[:5] == "byte ":
        return 1

    if operand[:5] == "word ":
        return 2

    if operand[:6] == "dword ":
        return 4

    if operand[:6] == "qword ":
        return 8

    return None


def assign(registers: Registers, memory: Memory, size: int, loc: str, value: int) -> None:
    """
    Given the registers and memory of our emulator, the size of the operation
    performed, the location to assign to and the value we should assign,
    compute where the assignment should happen and then execute it.
    """

    address = get_address(registers, loc)
    if address is not None:
        if size == 1:
            data = struct.pack("<B", value)
        elif size == 2:
            data = struct.pack("<H", value)
        elif size == 4:
            data = struct.pack("<I", value)
        elif size == 8:
            data = struct.pack("<Q", value)
        else:
            raise Exception(f"Unsupported size {size} for memory assign!")
        memory.store(address, data)
        return

    if loc == "rax":
        registers.rax = value
        return

    if loc == "rbx":
        registers.rbx = value
        return

    if loc == "rcx":
        registers.rcx = value
        return

    if loc == "rdx":
        registers.rdx = value
        return

    if loc == "rsp":
        registers.rsp = value
        return

    if loc == "rbp":
        registers.rbp = value
        return

    if loc == "rsi":
        registers.rsi = value
        return

    if loc == "rdi":
        registers.rdi = value
        return

    if loc == "eax":
        registers.rax = (registers.rax & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "ebx":
        registers.rbx = (registers.rbx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "ecx":
        registers.rcx = (registers.rcx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "edx":
        registers.rdx = (registers.rdx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "esp":
        registers.rsp = (registers.rsp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "ebp":
        registers.rbp = (registers.rbp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "esi":
        registers.rsi = (registers.rsi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "edi":
        registers.rdi = (registers.rdi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
        return

    if loc == "ax":
        registers.rax = (registers.rax & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "bx":
        registers.rbx = (registers.rbx & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "cx":
        registers.rcx = (registers.rcx & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "dx":
        registers.rdx = (registers.rdx & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "sp":
        registers.rsp = (registers.rsp & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "bp":
        registers.rbp = (registers.rbp & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "si":
        registers.rsi = (registers.rsi & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "di":
        registers.rdi = (registers.rdi & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
        return

    if loc == "ah":
        registers.rax = (registers.rax & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
        return

    if loc == "al":
        registers.rax = (registers.rax & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "bh":
        registers.rbx = (registers.rbx & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
        return

    if loc == "bl":
        registers.rbx = (registers.rbx & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "ch":
        registers.rcx = (registers.rcx & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
        return

    if loc == "cl":
        registers.rcx = (registers.rcx & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "dh":
        registers.rdx = (registers.rdx & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
        return

    if loc == "dl":
        registers.rdx = (registers.rdx & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "spl":
        registers.rsp = (registers.rsp & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "bpl":
        registers.rbp = (registers.rbp & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "sil":
        registers.rsi = (registers.rsi & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    if loc == "dil":
        registers.rdi = (registers.rdi & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
        return

    raise Exception(f"Unsupported destination {loc} for assign!")


def fetch(registers: Registers, memory: Memory, size: int, loc: str) -> int:
    """
    Given the registers and memory of our emulator, the size of the operation
    performed and the location to fetch from, compute where the fetch should
    happen and then execute it, returning the results of the fetch.
    """

    address = get_address(registers, loc)
    if address is not None:
        if size == 1:
            return struct.unpack("<B", memory.load(address, size))[0]
        elif size == 2:
            return struct.unpack("<H", memory.load(address, size))[0]
        elif size == 4:
            return struct.unpack("<I", memory.load(address, size))[0]
        elif size == 8:
            return struct.unpack("<Q", memory.load(address, size))[0]
        else:
            raise Exception(f"Unsupported size {size} for memory fetch!")

    immediate = get_value(loc)
    if immediate is not None:
        if size == 1:
            return immediate & 0xFF
        if size == 2:
            return immediate & 0xFFFF
        if size == 4:
            return immediate & 0xFFFFFFFF
        if size == 8:
            return immediate
        raise Exception(f"Unsupported size {size} for immediate fetch!")

    if loc == "rax":
        return registers.rax

    if loc == "rbx":
        return registers.rbx

    if loc == "rcx":
        return registers.rcx

    if loc == "rdx":
        return registers.rdx

    if loc == "rsi":
        return registers.rsi

    if loc == "rdi":
        return registers.rdi

    if loc == "rsp":
        return registers.rsp

    if loc == "rbp":
        return registers.rbp

    if loc == "eax":
        return registers.rax & 0xFFFFFFFF

    if loc == "ebx":
        return registers.rbx & 0xFFFFFFFF

    if loc == "ecx":
        return registers.rcx & 0xFFFFFFFF

    if loc == "edx":
        return registers.rdx & 0xFFFFFFFF

    if loc == "esi":
        return registers.rsi & 0xFFFFFFFF

    if loc == "edi":
        return registers.rdi & 0xFFFFFFFF

    if loc == "ebp":
        return registers.rbp & 0xFFFFFFFF

    if loc == "esp":
        return registers.rsp & 0xFFFFFFFF

    if loc == "ax":
        return registers.rax & 0xFFFF

    if loc == "bx":
        return registers.rbx & 0xFFFF

    if loc == "cx":
        return registers.rcx & 0xFFFF

    if loc == "dx":
        return registers.rdx & 0xFFFF

    if loc == "si":
        return registers.rsi & 0xFFFF

    if loc == "di":
        return registers.rdi & 0xFFFF

    if loc == "bp":
        return registers.rbp & 0xFFFF

    if loc == "sp":
        return registers.rsp & 0xFFFF

    if loc == "ah":
        return (registers.rax & 0xFF00) >> 8

    if loc == "al":
        return registers.rax & 0xFF

    if loc == "bh":
        return (registers.rbx & 0xFF00) >> 8

    if loc == "bl":
        return registers.rbx & 0xFF

    if loc == "ch":
        return (registers.rcx & 0xFF00) >> 8

    if loc == "cl":
        return registers.rcx & 0xFF

    if loc == "dh":
        return (registers.rdx & 0xFF00) >> 8

    if loc == "dl":
        return registers.rdx & 0xFF

    if loc == "spl":
        return registers.rsp & 0xFF

    if loc == "bpl":
        return registers.rbp & 0xFF

    if loc == "sil":
        return registers.rsi & 0xFF

    if loc == "dil":
        return registers.rdi & 0xFF

    raise Exception(f"Unsupported source {loc} for fetch!")
