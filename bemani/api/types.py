from typing import Any, Dict, TYPE_CHECKING


if TYPE_CHECKING:
    from flask.ctx import _AppCtxGlobals

    from bemani.data import Data

    class RequestGlobals(_AppCtxGlobals):
        config: Dict[str, Any]
        data: Data
        authorized: bool

    g = RequestGlobals()
else:
    from flask import g


__all__ = ["g"]
