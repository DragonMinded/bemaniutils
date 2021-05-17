from typing import List, Optional, Dict, Any, Set

from bemani.common import GameConstants, ValidatedDict, Parallel
from bemani.data.api.base import BaseGlobalData
from bemani.data.types import Item


class GlobalGameData(BaseGlobalData):

    def __translate_sdvx_song_unlock(self, entry: Dict[str, Any]) -> Item:
        return Item(
            "song_unlock",
            int(entry["catalogid"]),
            {
                "musicid": int(entry["song"]),
                "chart": int(entry["chart"]),
                "blocks": int(entry["price"]),
            },
        )

    def __translate_sdvx_appealcard(self, entry: Dict[str, Any]) -> Item:
        return Item(
            "appealcard",
            int(entry["appealid"]),
            {},
        )

    def __translate_jubeat_emblems(self, entry: Dict[str, Any]) -> Item:
        return Item(
            "emblem",
            int(entry["index"]),
            {
                "music_id": int(entry["song"]),
                "layer": int(entry["layer"]),
                "evolved": int(entry["evolved"]),
                "rarity": int(entry["rarity"]),
                "name": entry["name"],
            },
        )

    def __translate_iidx_qpros(self, entry: Dict[str, Any]) -> Item:
        return Item(
            f'qp_{entry["type"]}',
            int(entry["id"]),
            {
                "identifier": entry["identifier"],
                "name": entry["name"],
                "type": entry["type"],
            }
        )

    def get_items(self, game: str, version: int) -> List[Item]:
        """
        Given a game/userid, find all items in the catalog.

        Parameters:
            game - String identifier of the game looking up the catalog.
            version - Integer identifier of the version looking up this catalog.

        Returns:
            A list of item objects.
        """
        catalogs: List[Dict[str, List[Dict[str, Any]]]] = Parallel.call(
            [client.get_catalog for client in self.clients],
            game,
            version
        )
        retval: List[Item] = []
        seen: Set[str] = set()
        for catalog in catalogs:
            for catalogtype in catalog:
                # Simple LUT for now, might need to be complicated later
                if game == GameConstants.SDVX:
                    translation = {
                        "purchases": self.__translate_sdvx_song_unlock,
                        "appealcards": self.__translate_sdvx_appealcard,
                    }.get(catalogtype, None)
                elif game == GameConstants.JUBEAT:
                    translation = {
                        "emblems": self.__translate_jubeat_emblems,
                    }.get(catalogtype, None)
                elif game == GameConstants.IIDX:
                    translation = {
                        "qpros": self.__translate_iidx_qpros,
                    }.get(catalogtype, None)
                else:
                    translation = None

                # If we don't have a mapping for this, ignore it
                if translation is None:
                    continue

                for entry in catalog[catalogtype]:
                    # Translate the entry
                    item = translation(entry)

                    # Now, see if it is unique, and if so, remember it
                    key = f"{item.type}_{item.id}"
                    if key in seen:
                        continue

                    retval.append(item)
                    seen.add(key)
        return retval

    def get_item(self, game: str, version: int, catid: int, cattype: str) -> Optional[ValidatedDict]:
        """
        Given a game/userid and catalog id/type, find that catalog entry.

        Note that there can be more than one catalog entry with the same ID and game/userid
        as long as each one is a different type. Essentially, cattype namespaces catalog entry.

        Parameters:
            game - String identifier of the game looking up this entry.
            version - Integer identifier of the version looking up this entry.
            catid - Integer ID, as provided by a game.
            cattype - The type of catalog entry.

        Returns:
            A dictionary as stored by a game class previously, or None if not found.
        """
        all_items = self.get_items(game, version)
        for item in all_items:
            if item.id == catid and item.type == cattype:
                return item.data
        return None
