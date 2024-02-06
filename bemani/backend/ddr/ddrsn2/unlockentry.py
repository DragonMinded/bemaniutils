from ctypes import *


class UnlockEntryStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("id", c_uint8),
        ("enabled", c_uint8),
        # Set to 1 to enable. This is only read if the other flags check out. Set all other flags to 0 to force unlock.
        ("flag1", c_uint8),  # Must be less than some value passed to check function (always 0x3d6???)
        ("flag2", c_uint8),  # Some kind of "unlock type" flag? If 0 then other flags aren't checked.
        ("flag3", c_uint8),  # Unused??
        ("flag4", c_uint8),
        # If 0, flag2 (if flag2 is non-0) must match the type of unlock looked for by the checker function. If non-0, flag4 * 10 must be <= param4 of checker function (when is this used?)
    ]


class UnlockEntry:
    @staticmethod
    def create(id: int, enabled: int, flag1: int, flag2: int, flag3: int, flag4: int) -> UnlockEntryStruct:
        return UnlockEntryStruct(id, enabled, flag1, flag2, flag3, flag4)
