from abc import ABC, abstractmethod
from typing import List

from bemani.data.types import Server


class APIProviderInterface(ABC):

    @abstractmethod
    def get_all_servers(self) -> List[Server]:
        """
        Grab all authorized servers in the system.

        Returns:
            A list of Server objects sorted by add time.
        """
