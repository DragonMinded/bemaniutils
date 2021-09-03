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
        self.eax = 0
        self.ebx = 0
        self.ecx = 0
        self.edx = 0
        self.esi = 0
        self.edi = 0
        self.ebp = 0
        self.esp = 0xFFFFFFFF

        self.zf = False
        self.of = False
        self.cf = False


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
                registers.esp -= 4
                assign(registers, memory, size, "[esp]", result)

            elif mnemonic == "test":
                op1 = formatter.format_operand(inst, 0)
                op2 = formatter.format_operand(inst, 1)

                vprint(f"test {op1}, {op2}")

                size = get_size(op1) or get_size(op2)
                if size is None:
                    raise Exception(f"Could not determine size of {mnemonic} operation!")
                result = fetch(registers, memory, size, op1) & fetch(registers, memory, size, op2)
                registers.zf = result == 0
                registers.of = False
                registers.cf = False

            elif mnemonic == "jne":
                dest = formatter.format_operand(inst, 0)

                vprint(f"jne {dest}")

                if not registers.zf:
                    destination = get_value(dest)
                    if destination is None:
                        raise Exception(f"Jumping to unsupported destination {dest}")

                    dest_off = self.virtual_to_physical(destination)
                    if dest_off < start or dest_off >= end:
                        raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")

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
                if dest_off < start or dest_off >= end:
                    raise Exception(f"Jumping to {hex(destination)} which is outside of our evaluation range!")

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

    return indirect


def get_address(registers: Registers, indirect: str) -> Optional[int]:
    indirect = sanitize(indirect)

    if indirect[0] == "[" and indirect[-1] == "]":
        val = indirect[1:-1]

        if val[-1] == 'h':
            return int(val[:-1], 16)

        if val == "esp":
            return registers.esp

        raise Exception(f"Unsupported indirect address {indirect}!")
    return None


def get_value(immediate: str) -> Optional[int]:
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


def get_size(reg: str) -> Optional[int]:
    if reg in {'eax', 'ebx', 'ecx', 'edx', 'esp', 'ebp', 'esi', 'edi'}:
        return 4
    if reg in {'ax', 'bx', 'cx', 'dx', 'sp', 'bp', 'si', 'di'}:
        return 2
    if reg in {'ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl'}:
        return 1

    if reg[:5] == "byte ":
        return 1

    if reg[:5] == "word ":
        return 2

    if reg[:6] == "dword ":
        return 4

    return None


def assign(registers: Registers, memory: Memory, size: int, loc: str, value: int) -> None:
    address = get_address(registers, loc)
    if address is not None:
        if size == 1:
            data = struct.pack("<B", value)
        elif size == 2:
            data = struct.pack("<H", value)
        elif size == 4:
            data = struct.pack("<I", value)
        else:
            raise Exception(f"Unsupported size {size} for memory assign!")
        memory.store(address, data)
        return

    if loc == "eax":
        registers.eax = value
        return

    if loc == "ebx":
        registers.ebx = value
        return

    if loc == "ecx":
        registers.ecx = value
        return

    if loc == "edx":
        registers.edx = value
        return

    if loc == "esp":
        registers.esp = value
        return

    if loc == "ebp":
        registers.esp = value
        return

    if loc == "esi":
        registers.esi = value
        return

    if loc == "edi":
        registers.edi = value
        return

    if loc == "al":
        registers.eax = (registers.eax & 0xFFFFFF00) | (value & 0xFF)
        return

    if loc == "bl":
        registers.ebx = (registers.ebx & 0xFFFFFF00) | (value & 0xFF)
        return

    if loc == "cl":
        registers.ecx = (registers.ecx & 0xFFFFFF00) | (value & 0xFF)
        return

    if loc == "dl":
        registers.edx = (registers.edx & 0xFFFFFF00) | (value & 0xFF)
        return

    raise Exception(f"Unsupported destination {loc} for assign!")


def fetch(registers: Registers, memory: Memory, size: int, loc: str) -> int:
    address = get_address(registers, loc)
    if address is not None:
        if size == 1:
            return struct.unpack("<B", memory.load(address, size))[0]
        elif size == 2:
            return struct.unpack("<H", memory.load(address, size))[0]
        elif size == 4:
            return struct.unpack("<I", memory.load(address, size))[0]
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
        raise Exception(f"Unsupported size {size} for immediate fetch!")

    if loc == "eax":
        return registers.eax

    if loc == "ebx":
        return registers.ebx

    if loc == "ecx":
        return registers.ecx

    if loc == "edx":
        return registers.edx

    if loc == "esi":
        return registers.esi

    if loc == "edi":
        return registers.edi

    if loc == "esp":
        return registers.esp

    if loc == "ebp":
        return registers.esp

    if loc == "ax":
        return registers.eax & 0xFFFF

    if loc == "bx":
        return registers.ebx & 0xFFFF

    if loc == "cx":
        return registers.ecx & 0xFFFF

    if loc == "dx":
        return registers.edx & 0xFFFF

    if loc == "si":
        return registers.esi & 0xFFFF

    if loc == "di":
        return registers.edi & 0xFFFF

    if loc == "al":
        return registers.eax & 0xFF

    if loc == "bl":
        return registers.ebx & 0xFF

    if loc == "cl":
        return registers.ecx & 0xFF

    if loc == "dl":
        return registers.edx & 0xFF

    raise Exception(f"Unsupported source {loc} for fetch!")
