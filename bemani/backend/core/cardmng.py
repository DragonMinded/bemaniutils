from bemani.backend.base import Base, Status
from bemani.protocol import Node
from bemani.common import Model


class CardManagerHandler(Base):
    """
    The class that handles card management. This assumes it is attached as a mixin to a game
    class so that it can understand if there's a profile for a game or not.

    Handle a request for card management. This is independent of a game's profile handling,
    but still gives the game information as to whether or not a profile exists for a game.
    These methods handle looking up a card, handling binding a profile to a game version,
    returning whether a game profile exists or should be migrated, and creating a new account
    when no account is associated with a card.
    """

    def handle_cardmng_inquire_request(self, request: Node) -> Node:
        # Given a cardid, look up the dataid/refid (same thing in this system).
        # If the card doesn't exist or isn't allowed, return a status specifying this
        # instead of the results of the dataid/refid lookup.
        cardid = request.attribute("cardid")
        modelstring = request.attribute("model")
        userid = self.data.local.user.from_cardid(cardid)

        if userid is None:
            # This user doesn't exist, force system to create new account
            root = Node.void("cardmng")
            root.set_attribute("status", str(Status.NOT_REGISTERED))
            return root

        # Special handling for looking up whether the previous game's profile existed. If we
        # don't do this then some games won't present the user with a migration.
        bound = self.has_profile(userid)
        expired = False
        if bound is False:
            if modelstring is not None:
                model = Model.from_modelstring(modelstring)
                oldgame = Base.create(self.data, self.config, model, self.model)
                if oldgame is not None:
                    bound = oldgame.has_profile(userid)
                    expired = self.supports_expired_profiles

        refid = self.data.local.user.get_refid(self.game, self.version, userid)
        paseli_enabled = self.supports_paseli and self.config.paseli.enabled
        newflag = (
            self.data.remote.user.get_any_profile(self.game, self.version, userid)
            is None
        )

        root = Node.void("cardmng")
        root.set_attribute("refid", refid)
        root.set_attribute("dataid", refid)

        # Unsure what this does, but it appears not to matter so we set it to my best guess.
        root.set_attribute("newflag", "1" if newflag else "0")

        # Whether we've bound a profile to this refid/dataid or not. This includes current profiles and any
        # older game profiles that might exist that we should do a conversion from.
        root.set_attribute("binded", "1" if bound else "0")

        # Whether this version of the profile is expired (was converted to newer version). We support forwards
        # and backwards compatibility so some games will always set this to 0.
        root.set_attribute("expired", "1" if expired else "0")

        # Whether to allow paseli, as enabled by the operator and arcade owner.
        root.set_attribute("ecflag", "1" if paseli_enabled else "0")

        # I have absolutely no idea what these do.
        root.set_attribute("useridflag", "1")
        root.set_attribute("extidflag", "1")
        return root

    def handle_cardmng_authpass_request(self, request: Node) -> Node:
        # Given a dataid/refid previously found via inquire, verify the pin
        refid = request.attribute("refid")
        pin = request.attribute("pass")
        userid = self.data.local.user.from_refid(self.game, self.version, refid)
        if userid is not None:
            valid = self.data.local.user.validate_pin(userid, pin)
        else:
            valid = False
        root = Node.void("cardmng")
        root.set_attribute(
            "status", str(Status.SUCCESS if valid else Status.INVALID_PIN)
        )
        return root

    def handle_cardmng_getrefid_request(self, request: Node) -> Node:
        # Given a cardid and a pin, register the card with the system and generate a new dataid/refid + extid
        cardid = request.attribute("cardid")
        pin = request.attribute("passwd")
        userid = self.data.local.user.create_account(cardid, pin)
        if userid is None:
            # This user can't be created
            root = Node.void("cardmng")
            root.set_attribute("status", str(Status.NOT_ALLOWED))
            return root

        refid = self.data.local.user.create_refid(self.game, self.version, userid)
        root = Node.void("cardmng")
        root.set_attribute("dataid", refid)
        root.set_attribute("refid", refid)
        return root

    def handle_cardmng_bindmodel_request(self, request: Node) -> Node:
        # Given a refid, bind the user's card to the current version of the game
        refid = request.attribute("refid")
        userid = self.data.local.user.from_refid(self.game, self.version, refid)
        self.bind_profile(userid)
        root = Node.void("cardmng")
        root.set_attribute("dataid", refid)
        return root

    def handle_cardmng_getkeepspan_request(self, request: Node) -> Node:
        # Unclear what this method does, return an arbitrary span
        root = Node.void("cardmng")
        root.set_attribute("keepspan", "30")
        return root

    def handle_cardmng_getdatalist_request(self, request: Node) -> Node:
        # Unclear what this method does, return a dummy response
        root = Node.void("cardmng")
        return root
