from typing import Any, Dict, Optional, TYPE_CHECKING


if TYPE_CHECKING:
    from flask.ctx import _AppCtxGlobals
    from flask_caching import Cache  # type: ignore

    from bemani.data import Data, UserID

    class RequestGlobals(_AppCtxGlobals):
        config: Dict[str, Any]
        cache: Cache
        data: Data
        sessionID: Optional[str]
        userID: Optional[UserID]

    g = RequestGlobals()
else:
    from flask import g


__all__ = ["g"]
