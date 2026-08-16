"""Immutable public verdict and risk identities."""

from enum import Enum, IntEnum


class Verdict(IntEnum):
    """Four-valued public verdict identity."""

    NO = 0
    YES = 1
    MAYBE = 2
    IFF = 3


class Risk(str, Enum):  # noqa: UP042 - exact public inheritance contract
    """Public risk classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
