"""The ten active sparse-trace operator families."""

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType


class OperatorFamily(str, Enum):  # noqa: UP042 - exact public inheritance contract
    """Active runtime operator-family identity."""

    THIS = "THIS"
    SAME_NOT_SAME = "SAME/NOT-SAME"
    IF_THEN = "IF/THEN"
    BECAUSE = "BECAUSE"
    INSIDE_OUTSIDE = "INSIDE/OUTSIDE"
    NEAR_FAR = "NEAR/FAR"
    CAN_CANNOT = "CAN/CANNOT"
    TOGETHER_ALONE = "TOGETHER/ALONE"
    MORE_LESS = "MORE/LESS"
    EVERY_SOME = "EVERY/SOME"


ALLOWED_POLES: Mapping[OperatorFamily, tuple[str, ...]] = MappingProxyType(
    {
        OperatorFamily.THIS: ("THIS",),
        OperatorFamily.SAME_NOT_SAME: ("SAME", "NOT-SAME"),
        OperatorFamily.IF_THEN: ("IF", "THEN"),
        OperatorFamily.BECAUSE: ("BECAUSE",),
        OperatorFamily.INSIDE_OUTSIDE: ("INSIDE", "OUTSIDE"),
        OperatorFamily.NEAR_FAR: ("NEAR", "FAR"),
        OperatorFamily.CAN_CANNOT: ("CAN", "CANNOT"),
        OperatorFamily.TOGETHER_ALONE: ("TOGETHER", "ALONE"),
        OperatorFamily.MORE_LESS: ("MORE", "LESS"),
        OperatorFamily.EVERY_SOME: ("EVERY", "SOME"),
    }
)
