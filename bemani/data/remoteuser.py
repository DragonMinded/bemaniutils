from bemani.data.types import UserID


class RemoteUser:
    """
    We use a nasty trick to tell the difference between a local and remote user.
    Local users are assumed to be in the range of 1 to 2^32-1. Remote users therefore
    are anything above that range. We cast card IDs to user IDs by treating them as
    raw integers and then wrapping them in the UserID type. This is how we can
    store local information in our DB for remote users, such as rival settings/etc.
    """

    @staticmethod
    def card_to_userid(cardid: str) -> UserID:
        return UserID(int(cardid, 16))

    @staticmethod
    def userid_to_card(userid: UserID) -> str:
        cardid = hex(abs(userid))[2:].upper()
        if len(cardid) <= 8:
            raise Exception("Got invalid card back when converting from UserID!")
        if len(cardid) < 16:
            cardid = ("0" * (16 - len(cardid))) + cardid
        return cardid

    @staticmethod
    def is_remote(userid: UserID) -> bool:
        return userid > (2**32 - 1)
