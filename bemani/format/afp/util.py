import sys

from typing import Any, List


def _hex(data: int) -> str:
    hexval = hex(data)[2:]
    if len(hexval) == 1:
        return "0" + hexval
    return hexval


def align(val: int) -> int:
    return (val + 3) & 0xFFFFFFFFC


def pad(data: bytes, length: int) -> bytes:
    if len(data) == length:
        return data
    elif len(data) > length:
        raise Exception("Logic error, padding request in data already written!")
    return data + (b"\0" * (length - len(data)))


def descramble_text(text: bytes, obfuscated: bool) -> str:
    if len(text):
        if obfuscated and (text[0] - 0x20) > 0x7F:
            # Gotta do a weird demangling where we swap the
            # top bit.
            return bytes(((x + 0x80) & 0xFF) for x in text).decode('ascii')
        else:
            return text.decode('ascii')
    else:
        return ""


def scramble_text(text: str, obfuscated: bool) -> bytes:
    if obfuscated:
        return bytes(((x + 0x80) & 0xFF) for x in text.encode('ascii')) + b'\0'
    else:
        return text.encode('ascii') + b'\0'


class TrackedCoverageManager:
    def __init__(self, covered_class: "TrackedCoverage", verbose: bool) -> None:
        self.covered_class = covered_class
        self.verbose = verbose

    def __enter__(self) -> "TrackedCoverageManager":
        if self.verbose:
            self.covered_class._tracking = True
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.covered_class._tracking = False


class TrackedCoverage:
    def __init__(self) -> None:
        self.coverage: List[bool] = []
        self._tracking: bool = False

    def covered(self, size: int, verbose: bool) -> TrackedCoverageManager:
        if verbose:
            self.coverage = [False] * size
        return TrackedCoverageManager(self, verbose)

    def add_coverage(self, offset: int, length: int, unique: bool = True) -> None:
        if not self._tracking:
            # Save some CPU cycles if we aren't verbose.
            return
        for i in range(offset, offset + length):
            if self.coverage[i] and unique:
                raise Exception(f"Already covered {hex(offset)}!")
            self.coverage[i] = True

    def print_coverage(self) -> None:
        # First offset that is not coverd in a run.
        start = None

        for offset, covered in enumerate(self.coverage):
            if covered:
                if start is not None:
                    print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)
                    start = None
            else:
                if start is None:
                    start = offset
        if start is not None:
            # Print final range
            offset = len(self.coverage)
            print(f"Uncovered: {hex(start)} - {hex(offset)} ({offset-start} bytes)", file=sys.stderr)


class VerboseOutputManager:
    def __init__(self, covered_class: "VerboseOutput", verbose: bool) -> None:
        self.covered_class = covered_class
        self.verbose = verbose

    def __enter__(self) -> "VerboseOutputManager":
        if self.verbose:
            self.covered_class._verbose = True
        else:
            self.covered_class._verbose = False
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.covered_class._verbose = False


class VerboseOutput:
    def __init__(self) -> None:
        self._verbose: bool = False

    def debugging(self, verbose: bool) -> VerboseOutputManager:
        return VerboseOutputManager(self, verbose)

    def vprint(self, *args: Any, **kwargs: Any) -> None:
        if self._verbose:
            print(*args, **kwargs, file=sys.stderr)
