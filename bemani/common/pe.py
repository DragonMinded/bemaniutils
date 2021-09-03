import pefile  # type: ignore
import struct
import sys
from iced_x86 import Decoder, Formatter, FormatterSyntax, FormatMnemonicOptions
from typing import Any, List, Dict, Optional


class Memory:
    def __init__(self) -> None:
        self.values: Dict[int, int] = {}

    def store(self, offset: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.values[i + offset] = b

    def load(self, offset: int, length: int) -> bytes:
        data: List[int] = []

        for i in range(offset, offset + length):
            if i in self.values:
                data.append(self.values[i])
            else:
                data.append(0)

        return bytes(data)


class Registers:
    def __init__(self) -> None:
        self.rax = 0
        self.rbx = 0
        self.rcx = 0
        self.rdx = 0
        self.rsi = 0
        self.rdi = 0
        self.rbp = 0
        self.rsp = 0xFFFFFFFF

        self.zf = False
        self.sf = False


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

        raise Exception(f"Couldn't find physical offset for virtual offset 0x{offset:08x}")

    def physical_to_virtual(self, offset: int) -> int:
        for section in self.__pe.sections:
            start = section.PointerToRawData
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.VirtualAddress + self.__pe.OPTIONAL_HEADER.ImageBase

        for virtual, physical in self.__adhoc_mapping.items():
            if offset == physical:
                return virtual

        raise Exception(f"Couldn't find virtual offset for physical offset 0x{offset:08x}")

    def is_virtual(self, offset: int) -> bool:
        return offset >= self.__pe.OPTIONAL_HEADER.ImageBase

    def is_64bit(self) -> bool:
        return hex(self.__pe.FILE_HEADER.Machine) == '0x8664'

    def emulate_code(self, start: int, end: int, verbose: bool = False) -> None:
        if self.is_virtual(start):
            # Assume this is virtual
            start = self.virtual_to_physical(start)
        if self.is_virtual(end):
            # Assume this is virtual
            end = self.virtual_to_physical(end)

        if verbose:
            def vprint(*args: Any, **kwargs: Any) -> None:
                print(*args, **kwargs, file=sys.stderr)
        else:
            def vprint(*args: Any, **kwargs: Any) -> None:
                pass

        registers = Registers()
        memory = Memory()
        formatter = Formatter(FormatterSyntax.NASM)  # type: ignore

        decoder = Decoder(64 if self.is_64bit() else 32, self.data[start:end], ip=self.physical_to_virtual(start))
        insts = [i for i in decoder]
        loc = 0

        while loc < len(insts):
            inst = insts[loc]
            loc = loc + 1
            mnemonic = formatter.format_mnemonic(inst, FormatMnemonicOptions.NO_PREFIXES)  # type: ignore

            if mnemonic == "mov":
                dest = formatter.format_operand(inst, 0)
                src = formatter.format_operand(inst, 1)

                vprint(f"mov {dest}, {src}")

                size = get_size(src) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, src)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "sub":
                dest = formatter.format_operand(inst, 0)
                amt = formatter.format_operand(inst, 1)

                vprint(f"sub {dest}, {amt}")

                size = get_size(amt) or get_size(dest)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, dest) - fetch(registers, memory, size, amt)
                assign(registers, memory, size, dest, result)

            elif mnemonic == "push":
                src = formatter.format_operand(inst, 0)

                vprint(f"push {src}")

                size = get_size(src)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, src)
                registers.rsp -= size
                assign(registers, memory, size, "[rsp]" if self.is_64bit() else "[esp]", result)

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

                    dest_off = self.virtual_to_physical(destination)
                    if dest_off == end:
                        loc = len(insts)
                    elif dest_off < start or dest_off > end:
                        raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")
                    else:
                        decoder = Decoder(64 if self.is_64bit() else 32, self.data[dest_off:end], ip=self.physical_to_virtual(dest_off))
                        insts = [i for i in decoder]
                        loc = 0

            elif mnemonic == "je":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jz {dest}")

                if registers.zf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")

                    dest_off = self.virtual_to_physical(destination)
                    if dest_off == end:
                        loc = len(insts)
                    elif dest_off < start or dest_off > end:
                        raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")
                    else:
                        decoder = Decoder(64 if self.is_64bit() else 32, self.data[dest_off:end], ip=self.physical_to_virtual(dest_off))
                        insts = [i for i in decoder]
                        loc = 0

            elif mnemonic == "jns":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jns {dest}")

                if not registers.sf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")

                    dest_off = self.virtual_to_physical(destination)
                    if dest_off == end:
                        loc = len(insts)
                    elif dest_off < start or dest_off > end:
                        raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")
                    else:
                        decoder = Decoder(64 if self.is_64bit() else 32, self.data[dest_off:end], ip=self.physical_to_virtual(dest_off))
                        insts = [i for i in decoder]
                        loc = 0

            elif mnemonic == "js":
                dest = formatter.format_operand(inst, 0)

                vprint(f"js {dest}")

                if registers.sf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")

                    dest_off = self.virtual_to_physical(destination)
                    if dest_off == end:
                        loc = len(insts)
                    elif dest_off < start or dest_off > end:
                        raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")
                    else:
                        decoder = Decoder(64 if self.is_64bit() else 32, self.data[dest_off:end], ip=self.physical_to_virtual(dest_off))
                        insts = [i for i in decoder]
                        loc = 0

            elif mnemonic == "jmp":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jmp {dest}")

                destination = get_value(dest)
                if destination is None:
                    raise Exception(f"Jumping to unsupported destination {dest}")

                dest_off = self.virtual_to_physical(destination)
                if dest_off == end:
                    loc = len(insts)
                elif dest_off < start or dest_off > end:
                    raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")
                else:
                    decoder = Decoder(64 if self.is_64bit() else 32, self.data[dest_off:end], ip=self.physical_to_virtual(dest_off))
                    insts = [i for i in decoder]
                    loc = 0

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

            else:
                raise Exception(f"Unsupported mnemonic {mnemonic}!")

        # Replace memory that we care about.
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


def sanitize(indirect: str) -> str:
    """
    Given an indirect address or a value from iced-x86 as formatted by the
    operand formatter, sanitize it by getting rid of size specifiers.
    """

    if indirect[:5] == "near ":
        indirect = indirect[5:]

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
        indirect = indirect[1:-1]

        adjust = 0
        if '+' in indirect:
            indirect, const = indirect.split('+', 1)

            if const[-1] == 'h':
                adjust = int(const[:-1], 16)
            else:
                raise Exception(f"Unsupported constant adjustment to indirect address {indirect}")
        elif '-' in indirect:
            indirect, const = indirect.split('-', 1)

            if const[-1] == 'h':
                adjust = -int(const[:-1], 16)
            else:
                raise Exception(f"Unsupported constant adjustment to indirect address {indirect}")

        if indirect[-1] == 'h':
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

    if operand in {'rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rsi', 'rdi'}:
        return 8
    if operand in {'eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi'}:
        return 4
    if operand in {'ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di'}:
        return 2
    if operand in {'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl', 'spl', 'bpl', 'sil', 'dil'}:
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
