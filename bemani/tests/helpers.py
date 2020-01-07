# vim: set fileencoding=utf-8
from typing import List, Dict, Any


class FakeCursor():

    def __init__(self, rows: List[Dict[str, Any]]) -> None:
        self.__rows = rows
        self.rowcount = len(rows)

    def fetchone(self) -> Dict[str, Any]:
        if len(self.__rows) != 1:
            raise Exception(f'Tried to fetch one row and there are {len(self.__rows)} rows!')
        return self.__rows[0]

    def fetchall(self) -> List[Dict[str, Any]]:
        return self.__rows
