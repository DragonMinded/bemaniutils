import pefile  # type: ignore


class PEFile:
    def __init__(self, data: bytes) -> None:
        self.__pe = pefile.PE(data=data, fast_load=True)

    def virtual_to_physical(self, offset: int) -> int:
        for section in self.__pe.sections:
            start = section.VirtualAddress + self.__pe.OPTIONAL_HEADER.ImageBase
            end = start + section.SizeOfRawData

            if offset >= start and offset < end:
                return (offset - start) + section.PointerToRawData

        raise Exception(f"Couldn't find physical offset for virtual offset 0x{offset:08x}")

    def is_virtual(self, offset: int) -> bool:
        return offset >= self.__pe.OPTIONAL_HEADER.ImageBase

    def is_64bit(self) -> bool:
        return hex(self.__pe.FILE_HEADER.Machine) == '0x8664'
