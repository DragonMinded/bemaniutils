from typing import Optional, TYPE_CHECKING


if TYPE_CHECKING:
    from flask.ctx import _AppCtxGlobals
    from flask_caching import Cache

    from bemani.data import Config, Data, UserID

    class RequestGlobals(_AppCtxGlobals):
        config: Config
        cache: Cache
        data: Data
        sessionID: Optional[str]
        userID: Optional[UserID]

    g = RequestGlobals()
else:
    from flask import g


__all__ = ["g"]
