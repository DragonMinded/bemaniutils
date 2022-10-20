import struct
from typing import List, Optional, Tuple
from typing_extensions import Final


class IIDXChart:
    """
    Class representing a IIDX chart. This is known to be iffy with charge notes
    and hell charge notes, but I never investigated enough to fix it. If somebody
    wants to dig in and make a patch that would be excellent. This currently only
    allows fetching notecounts and bpm since this is necessary for calculating
    clear ranks for IIDX.
    """

    CHART_POSITIONS: Final[List[int]] = [1, 0, 2, 7, 6, 8]

    def __init__(self, data: bytes) -> None:
        self.__bpm_min: Optional[int] = None
        self.__bpm_max: Optional[int] = None
        self.__note_counts = [0, 0, 0, 0, 0, 0]
        self.__parse_charts(data)

    def __parse_header(self, data: bytes) -> List[Tuple[int, int]]:
        header: List[Tuple[int, int]] = []
        for i in range(12):
            offset, length = struct.unpack("<II", data[(i * 8) : ((i + 1) * 8)])
            header.append((offset, length))
        return header

    def __parse_charts(self, data: bytes) -> None:
        header = self.__parse_header(data)

        for chart in [0, 1, 2, 3, 4, 5]:
            offset, length = header[self.CHART_POSITIONS[chart]]
            chartdata = data[offset : (offset + length)]
            position = 0

            if length == 0:
                # Some songs don't have all charts :(
                continue

            while True:
                time, event, side, value = struct.unpack(
                    "<iBBH", chartdata[(position * 8) : ((position + 1) * 8)]
                )
                position += 1

                if time == 0x7FFFFFFF:
                    break

                if event == 0 or event == 1:
                    # Note!
                    self.__note_counts[chart] += 1
                    if value != 0:
                        # Add one more for charge note lift
                        self.__note_counts[chart] += 1

                if event == 4:
                    # BPM change
                    if value > 1000:
                        value = int(value / 100)

                    if self.__bpm_min is None:
                        self.__bpm_min = value
                    else:
                        self.__bpm_min = min(self.__bpm_min, value)
                    if self.__bpm_max is None:
                        self.__bpm_max = value
                    else:
                        self.__bpm_max = max(self.__bpm_max, value)

    @property
    def bpm(self) -> Tuple[int, int]:
        if self.__bpm_min is None or self.__bpm_max is None:
            raise Exception("BPM change was not found in the chart!")
        return (self.__bpm_min, self.__bpm_max)

    @property
    def notecounts(self) -> List[int]:
        return self.__note_counts
