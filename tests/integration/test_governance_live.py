"""Separately authorized CockroachDB governance round-trip contract."""

from __future__ import annotations

import os

import pytest

pytestmark = [pytest.mark.live_crdb, pytest.mark.phase_implementation]


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL_APP"),
    reason="live CockroachDB identity is not configured",
)
def test_live_snapshot_evaluation_is_separately_authorized() -> None:
    """Reserve the live read/evaluate/append/readback boundary for credentials."""
    pytest.skip("live persistence adapter is implemented by the memory packet")
