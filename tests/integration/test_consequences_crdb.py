"""Credential-gated QG-005 CockroachDB contract checks."""

from __future__ import annotations

import os

import pytest

from src.config import AppDbConfig
from src.memory import AppMemory

pytestmark = [pytest.mark.live_crdb, pytest.mark.phase_implementation]


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL is not configured for the live consequence check",
)
async def test_live_consequence_schema_is_append_only_ready() -> None:
    """Verify the authorized database has every immutable consequence binding."""
    memory = AppMemory(AppDbConfig(os.environ["DATABASE_URL"]))
    expected = {
        "id",
        "proposal_id",
        "receipt_id",
        "receipt_digest",
        "observation_number",
        "predicted_snapshot_digest",
        "actual_snapshot_digest",
        "comparison_version",
        "leaf_report",
        "divergence_score",
        "report_digest",
        "idempotency_key",
    }
    try:
        async with memory.transaction() as connection:
            rows = await connection.fetch(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' "
                "AND table_name = 'consequence_reports'"
            )
            assert expected <= {str(row["column_name"]) for row in rows}
    finally:
        await memory.close()
