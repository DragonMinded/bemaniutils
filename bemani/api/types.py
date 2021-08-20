from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from flask.ctx import _AppCtxGlobals

    from bemani.data import Config, Data

    class RequestGlobals(_AppCtxGlobals):
        config: Config
        data: Data
        authorized: bool

    g = RequestGlobals()
else:
    from flask import g


__all__ = ["g"]
