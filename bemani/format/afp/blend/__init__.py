try:
    # If we compiled the faster cython/c++ code, we can use it instead!
    from .blendcpp import affine_composite
    from .blendcpp import perspective_composite
except ImportError:
    # If we didn't, then fall back to the pure python implementation.
    from .blend import affine_composite
    from .blend import perspective_composite


__all__ = ["affine_composite", "perspective_composite"]
