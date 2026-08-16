"""Seven public witness axes for atomic evidence gaps."""

from enum import Enum


class Witness(str, Enum):  # noqa: UP042 - exact public inheritance contract
    """Witness identity with stable serialized values."""

    WHAT = "WHAT"
    WHERE = "WHERE"
    WHICH = "WHICH"
    WHEN = "WHEN"
    FOR_WHAT = "FOR-WHAT"
    HOW = "HOW"
    WHENCE = "WHENCE"
