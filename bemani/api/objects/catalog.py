from typing import Any, Dict, List

from bemani.api.exceptions import APIException
from bemani.api.objects.base import BaseObject
from bemani.common import GameConstants, APIConstants, DBConstants, VersionConstants
from bemani.data import Song


class CatalogObject(BaseObject):

    def __format_ddr_song(self, song: Song) -> Dict[str, Any]:
        groove = song.data.get_dict('groove')
        return {
            'editid': str(song.data.get_int('edit_id')),
            'difficulty': song.data.get_int('difficulty'),
            'bpm_min': song.data.get_int('bpm_min'),
            'bpm_max': song.data.get_int('bpm_max'),
            'category': str(song.data.get_int('category')),
            'groove': {
                'air': groove.get_int('air'),
                'chaos': groove.get_int('chaos'),
                'freeze': groove.get_int('freeze'),
                'stream': groove.get_int('stream'),
                'voltage': groove.get_int('voltage'),
            },
        }

    def __format_iidx_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'bpm_min': song.data.get_int('bpm_min'),
            'bpm_max': song.data.get_int('bpm_max'),
            'notecount': song.data.get_int('notecount'),
            'category': str(int(song.id / 1000)),
        }

    def __format_jubeat_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'bpm_min': song.data.get_int('bpm_min'),
            'bpm_max': song.data.get_int('bpm_max'),
        }

    def __format_museca_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'bpm_min': song.data.get_int('bpm_min'),
            'bpm_max': song.data.get_int('bpm_max'),
            'limited': song.data.get_int('limited'),
        }

    def __format_popn_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'category': song.data.get_str('category'),
        }

    def __format_reflec_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'category': str(song.data.get_int('folder')),
            'musicid': song.data.get_str('chart_id'),
        }

    def __format_sdvx_song(self, song: Song) -> Dict[str, Any]:
        return {
            'difficulty': song.data.get_int('difficulty'),
            'bpm_min': song.data.get_int('bpm_min'),
            'bpm_max': song.data.get_int('bpm_max'),
            'limited': song.data.get_int('limited'),
        }

    def __format_song(self, song: Song) -> Dict[str, Any]:
        base = {
            'song': str(song.id),
            'chart': str(song.chart),
            'title': song.name or "",
            'artist': song.artist or "",
            'genre': song.genre or "",
        }

        if self.game == GameConstants.DDR:
            base.update(self.__format_ddr_song(song))
        if self.game == GameConstants.IIDX:
            base.update(self.__format_iidx_song(song))
        if self.game == GameConstants.JUBEAT:
            base.update(self.__format_jubeat_song(song))
        if self.game == GameConstants.MUSECA:
            base.update(self.__format_museca_song(song))
        if self.game == GameConstants.POPN_MUSIC:
            base.update(self.__format_popn_song(song))
        if self.game == GameConstants.REFLEC_BEAT:
            base.update(self.__format_reflec_song(song))
        if self.game == GameConstants.SDVX:
            base.update(self.__format_sdvx_song(song))

        return base

    def __format_sdvx_extras(self) -> Dict[str, List[Dict[str, Any]]]:
        # Gotta look up the unlock catalog
        items = self.data.local.game.get_items(self.game, self.version)

        # Format it depending on the version
        if self.version == 1:
            return {
                "purchases": [
                    {
                        "catalogid": str(item.id),
                        "song": str(item.data.get_int("musicid")),
                        "chart": str(item.data.get_int("chart")),
                        "price": item.data.get_int("blocks"),
                    }
                    for item in items
                    if item.type == "song_unlock"
                ],
                "appealcards": [],
            }
        else:
            return {
                "purchases": [],
                "appealcards": [
                    {
                        "appealid": str(item.id),
                        "description": item.data.get_str("description"),
                    }
                    for item in items
                    if item.type == "appealcard"
                ],
            }

    def __format_jubeat_extras(self) -> Dict[str, List[Dict[str, Any]]]:
        # Gotta look up the unlock catalog
        items = self.data.local.game.get_items(self.game, self.version)

        # Format it depending on the version
        if self.version in {
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
        }:
            return {
                "emblems": [
                    {
                        "index": str(item.id),
                        "song": item.data.get_int("music_id"),
                        "layer": item.data.get_int("layer"),
                        "evolved": item.data.get_int("evolved"),
                        "rarity": item.data.get_int("rarity"),
                        "name": item.data.get_str("name"),
                    }
                    for item in items
                    if item.type == "emblem"
                ],
            }
        else:
            return {"emblems": []}

    def __format_extras(self) -> Dict[str, List[Dict[str, Any]]]:
        if self.game == GameConstants.SDVX:
            return self.__format_sdvx_extras()
        elif self.game == GameConstants.JUBEAT:
            return self.__format_jubeat_extras()
        else:
            return {}

    @property
    def music_version(self) -> int:
        if self.game in [GameConstants.IIDX, GameConstants.MUSECA]:
            if self.omnimix:
                return self.version + DBConstants.OMNIMIX_VERSION_BUMP
            else:
                return self.version
        else:
            return self.version

    def fetch_v1(self, idtype: str, ids: List[str], params: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        # Verify IDs
        if idtype != APIConstants.ID_TYPE_SERVER:
            raise APIException(
                'Unsupported ID for lookup!',
                405,
            )

        # Fetch the songs
        songs = self.data.local.music.get_all_songs(self.game, self.music_version)
        if self.game == GameConstants.JUBEAT and self.version == VersionConstants.JUBEAT_CLAN:
            # There's always a special case. We don't store all music IDs since those in
            # the range of 80000301-80000347 are actually the same song, but copy-pasted
            # for different prefectures and slightly different charts. So, we need to copy
            # that song data so that remote clients can resolve scores for those ID ranges.
            additions: List[Song] = []
            for song in songs:
                if song.id == 80000301:
                    for idrange in range(80000302, 80000348):
                        additions.append(
                            Song(
                                song.game,
                                song.version,
                                idrange,
                                song.chart,
                                song.name,
                                song.artist,
                                song.genre,
                                song.data,
                            )
                        )
            songs.extend(additions)
        retval = {
            'songs': [self.__format_song(song) for song in songs],
        }

        # Fetch any optional extras per-game, return
        retval.update(self.__format_extras())
        return retval
