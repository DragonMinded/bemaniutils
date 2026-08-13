from typing import TypeVar

T = TypeVar("T")


def debugonly(func: T) -> T:
    """
    A decorator that can be added to any handler function in a game backend
    which will make it not possible to call in production mode, which is
    when running this through uWSGI or another WSGI application.
    """

    setattr(func, "__debug_only__", True)
    return func
