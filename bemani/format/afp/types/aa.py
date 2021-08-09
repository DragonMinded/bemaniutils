from typing_extensions import Final


class AAMode:
    NONE: Final[int] = 0
    UNSCALED_SSAA_ONLY: Final[int] = 1
    SSAA_ONLY: Final[int] = 2
    SSAA_OR_BILINEAR: Final[int] = 3
