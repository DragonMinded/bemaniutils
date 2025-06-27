import sys

from typing import Any, List, Optional, Tuple


def align(val: int) -> int:
    return (val + 3) & 0xFFFFFFFFC


def pad(data: bytes, length: int) -> bytes:
    if len(data) == length:
        return data
    elif len(data) > length:
        raise Exception("Logic error, padding request in data already written!")
    return data + (b"\0" * (length - len(data)))


def descramble_text(text: bytes, obfuscated: bool) -> str:
    if text:
        if obfuscated and (text[0] - 0x20) > 0x7F:
            # Gotta do a weird demangling where we swap the
            # top bit.
            return bytes(((x + 0x80) & 0xFF) for x in text).decode("ascii")
        else:
            return text.decode("ascii")
    else:
        return ""


def scramble_text(text: str, obfuscated: bool) -> bytes:
    if obfuscated:
        return bytes(((x + 0x80) & 0xFF) for x in text.encode("ascii")) + b"\0"
    else:
        return text.encode("ascii") + b"\0"


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
        super().__init__()

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

    def print_coverage(self, req_start: Optional[int] = None, req_end: Optional[int] = None) -> None:
        for start, offset in self.get_uncovered_chunks(req_start, req_end):
            print(
                f"Uncovered: {hex(start)} - {hex(offset)} ({offset - start} bytes)",
                file=sys.stderr,
            )

    def get_uncovered_chunks(
        self,
        req_start: Optional[int] = None,
        req_end: Optional[int] = None,
        adjust_offsets: bool = False,
    ) -> List[Tuple[int, int]]:
        # First offset that is not coverd in a run.
        start: Optional[int] = None
        chunks: List[Tuple[int, int]] = []

        for offset, covered in enumerate(self.coverage):
            if covered:
                if start is not None:
                    chunks.append((start, offset))
                    start = None
            else:
                if start is None:
                    start = offset
        if start is not None:
            # Print final range
            offset = len(self.coverage)
            chunks.append((start, offset))

        if req_start is None and req_end is None:
            return chunks

        filtered_chunks: List[Tuple[int, int]] = []
        for start, end in chunks:
            if start >= end:
                raise Exception("Logic error!")

            if req_start is not None:
                if end <= req_start:
                    # Don't care this is wholly before our start filter.
                    continue
                if start < req_start and end > req_start:
                    # This overlaps our start filter, so update the start to be
                    # our start filter.
                    start = req_start
            if req_end is not None:
                if start >= req_end:
                    # Don't care, this is wholly after our end filter.
                    continue
                if start < req_end and end > req_end:
                    # This overlaps our end filter, so update the end to be
                    # our end filter.
                    end = req_end

            if adjust_offsets:
                filtered_chunks.append(
                    (
                        start - req_start if req_start else 0,
                        end - req_start if req_start else 0,
                    )
                )
            else:
                filtered_chunks.append((start, end))
        return filtered_chunks


class VerboseOutputManager:
    def __init__(self, covered_class: "VerboseOutput", verbose: bool) -> None:
        self.covered_class = covered_class
        self.verbose = verbose

    def __enter__(self) -> "VerboseOutputManager":
        if self.verbose:
            self.covered_class.verbose = True
        else:
            self.covered_class.verbose = False
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.covered_class.verbose = False


class VerboseOutput:
    def __init__(self, components: List[str] = []) -> None:
        super().__init__()

        self.verbose: bool = False
        self.components: List[str] = components or []

    def debugging(self, verbose: bool) -> VerboseOutputManager:
        return VerboseOutputManager(self, verbose)

    def vprint(self, *args: Any, **kwargs: Any) -> None:
        should_print = self.verbose or (kwargs.get("component", None) in self.components)
        kwargs = {k: v for k, v in kwargs.items() if k != "component"}
        if should_print:
            print(*args, **kwargs, file=sys.stderr)
