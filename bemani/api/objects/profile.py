from typing import Any, Dict, List, Set, Tuple

from bemani.api.exceptions import APIException
from bemani.api.objects.base import BaseObject
from bemani.common import Profile, ValidatedDict, GameConstants, APIConstants
from bemani.data import UserID


class ProfileObject(BaseObject):
    def __format_danevo_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {
            "area": profile.get_str("area", "") if exact else "",
        }

    def __format_ddr_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {
            "area": profile.get_int("area", -1) if exact else -1,
        }

    def __format_iidx_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        qpro = profile.get_dict("qpro")

        return {
            "area": profile.get_int("pid", -1),
            "qpro": {
                "head": qpro.get_int("head", -1) if exact else -1,
                "hair": qpro.get_int("hair", -1) if exact else -1,
                "face": qpro.get_int("face", -1) if exact else -1,
                "body": qpro.get_int("body", -1) if exact else -1,
                "hand": qpro.get_int("hand", -1) if exact else -1,
            },
        }

    def __format_jubeat_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {}

    def __format_museca_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {}

    def __format_popn_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {
            "character": profile.get_int("chara", -1) if exact else -1,
        }

    def __format_reflec_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {
            "icon": profile.get_dict("config").get_int("icon_id", -1) if exact else -1,
        }

    def __format_sdvx_profile(self, profile: Profile, exact: bool) -> Dict[str, Any]:
        return {}

    def __format_profile(
        self, cardids: List[str], profile: Profile, settings: ValidatedDict, exact: bool
    ) -> Dict[str, Any]:
        base = {
            "name": profile.get_str("name"),
            "cards": cardids,
            "registered": settings.get_int("first_play_timestamp", -1),
            "updated": settings.get_int("last_play_timestamp", -1),
            "plays": settings.get_int("total_plays", -1),
            "match": "exact" if exact else "partial",
        }

        if self.game == GameConstants.DDR:
            base.update(self.__format_ddr_profile(profile, exact))
        if self.game == GameConstants.IIDX:
            base.update(self.__format_iidx_profile(profile, exact))
        if self.game == GameConstants.JUBEAT:
            base.update(self.__format_jubeat_profile(profile, exact))
        if self.game == GameConstants.MUSECA:
            base.update(self.__format_museca_profile(profile, exact))
        if self.game == GameConstants.POPN_MUSIC:
            base.update(self.__format_popn_profile(profile, exact))
        if self.game == GameConstants.REFLEC_BEAT:
            base.update(self.__format_reflec_profile(profile, exact))
        if self.game == GameConstants.SDVX:
            base.update(self.__format_sdvx_profile(profile, exact))
        if self.game == GameConstants.DANCE_EVOLUTION:
            base.update(self.__format_danevo_profile(profile, exact))

        return base

    def fetch_v1(self, idtype: APIConstants, ids: List[str], params: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Fetch the profiles
        profiles: List[Tuple[UserID, Profile]] = []
        if idtype == APIConstants.ID_TYPE_SERVER:
            profiles.extend(self.data.local.user.get_all_profiles(self.game, self.version))
        elif idtype == APIConstants.ID_TYPE_SONG:
            raise APIException(
                "Unsupported ID for lookup!",
                405,
            )
        elif idtype == APIConstants.ID_TYPE_INSTANCE:
            raise APIException(
                "Unsupported ID for lookup!",
                405,
            )
        elif idtype == APIConstants.ID_TYPE_CARD:
            users: Set[UserID] = set()
            for cardid in ids:
                userid = self.data.local.user.from_cardid(cardid)
                if userid is not None:
                    # Don't duplicate loads for users with multiple card IDs if multiples
                    # of those IDs are requested.
                    if userid in users:
                        continue
                    users.add(userid)

                    # We can possibly find another profile for this user. This is important
                    # in the case that we returned scores for a user that doesn't have a
                    # profile on a particular version. We allow that on this network, so in
                    # order to not break remote networks, try our best to return any profile.
                    profile = self.data.local.user.get_any_profile(self.game, self.version, userid)
                    if profile is not None:
                        profiles.append((userid, profile))
        else:
            raise APIException("Invalid ID type!")

        # Now, fetch the users, and filter out profiles belonging to orphaned users
        retval: List[Dict[str, Any]] = []
        id_to_cards: Dict[UserID, List[str]] = {}
        for userid, profile in profiles:
            if userid not in id_to_cards:
                cards = self.data.local.user.get_cards(userid)
                if len(cards) == 0:
                    # Can't add this user, skip the profile
                    continue

                id_to_cards[userid] = cards

            # Format the profile and add it
            settings = self.data.local.game.get_settings(self.game, userid)
            if settings is None:
                settings = ValidatedDict({})

            retval.append(
                self.__format_profile(
                    id_to_cards[userid],
                    profile,
                    settings,
                    profile.version == self.version,
                )
            )

        return retval
