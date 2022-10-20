from typing import List, Optional

from bemani.data.api.client import APIClient
from bemani.data.interfaces import APIProviderInterface


class BaseGlobalData:
    def __init__(self, api: APIProviderInterface) -> None:
        self.__localapi = api
        self.__apiclients: Optional[List[APIClient]] = None

    @property
    def clients(self) -> List[APIClient]:
        if self.__apiclients is None:
            servers = self.__localapi.get_all_servers()
            self.__apiclients = [
                APIClient(
                    server.uri, server.token, server.allow_stats, server.allow_scores
                )
                for server in servers
            ]

        return self.__apiclients
