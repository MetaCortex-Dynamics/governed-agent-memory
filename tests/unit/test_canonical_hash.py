"""Stable canonical serialization and SHA-256 tests."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal

import pytest

from src.traces import ContractViolation, canonical_json_bytes, canonical_sha256
from src.verdict import Verdict


@dataclass(frozen=True, slots=True)
class Fixture:
    label: str
    verdict: Verdict
    score: Decimal
    vector: tuple[float, ...]


def test_explicit_enum_decimal_float_and_nfc_encoding() -> None:
    value = Fixture("e\u0301", Verdict.IFF, Decimal("1.2300"), (0.1,))
    encoded = canonical_json_bytes(value).decode()
    assert '"$enum":"gam.public.v1/Verdict"' in encoded
    assert '"member":"IFF"' in encoded
    assert '"$decimal":"1.23"' in encoded
    assert '"$float":"0.10000000000000001"' in encoded
    assert "é" in encoded
    assert "__module__" not in encoded


def test_digest_is_stable_across_fresh_processes() -> None:
    expression = (
        "from src.traces import canonical_sha256;"
        "from src.verdict import Verdict;"
        "print(canonical_sha256((Verdict.YES, 'stable', 7)))"
    )
    first = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, "-c", expression],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    second = subprocess.run(  # noqa: S603  # nosec B603
        [sys.executable, "-c", expression],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert first == second
    assert len(first.strip()) == 64


def test_every_authoritative_change_changes_digest() -> None:
    base = Fixture("stable", Verdict.YES, Decimal("0.5"), (1.0,))
    changed = Fixture("stable", Verdict.NO, Decimal("0.5"), (1.0,))
    assert canonical_sha256(base) != canonical_sha256(changed)


def test_mutable_and_unknown_values_fail_closed() -> None:
    with pytest.raises(ContractViolation, match="unsupported canonical type"):
        canonical_json_bytes(["mutable"])
    with pytest.raises(ContractViolation, match="non-finite"):
        canonical_json_bytes(float("nan"))
    with pytest.raises(ContractViolation, match="collision"):
        canonical_json_bytes({"é": 1, "e\u0301": 2})
