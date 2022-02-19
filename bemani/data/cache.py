from typing import Any, Callable
from functools import wraps
import hashlib
import pickle
# Make memcache optional
try:
    import pylibmc  # type: ignore
    has_mc = True
except ModuleNotFoundError:
    has_mc = False


def cached(lifetime: int=10, extra_key: Any=None) -> Callable:
    def _cached(func: Callable) -> Callable:
        if has_mc:
            memcache = pylibmc.Client(["127.0.0.1"], binary=True)
            memcache.behaviors = {"tcp_nodelay": True, "ketama": True}
        else:
            memcache = None

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if memcache is None:
                return func(*args, **kwargs)

            if lifetime is not None:

                # Hash function args
                items = kwargs.items()
                hashable_args = (args[1:], sorted(list(items)))

                args_key = hashlib.md5(pickle.dumps(hashable_args)).hexdigest()

                # Generate unique cache key
                cache_key = f'{func.__module__}-{func.__name__}-{args_key}-{extra_key() if hasattr(extra_key, "__call__") else extra_key}'

                # Return cached version if allowed and available
                result = memcache.get(cache_key)
                if result is not None:
                    return result

            # Generate output
            result = func(*args, **kwargs)

            # Cache output if allowed
            if lifetime is not None and result is not None:
                memcache.set(cache_key, result, lifetime)

            return result

        return wrapper

    return _cached
