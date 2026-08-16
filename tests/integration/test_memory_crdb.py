"""Credential-gated CockroachDB memory transaction checks."""

from __future__ import annotations

import os

import pytest

from src.config import AppDbConfig
from src.memory import AppMemory

pytestmark = [pytest.mark.live_crdb, pytest.mark.phase_implementation]


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL is not configured for the live memory check",
)
async def test_live_app_memory_serializable_connection() -> None:
    """Prove the configured database exposes the frozen append-only tables."""
    memory = AppMemory(AppDbConfig(os.environ["DATABASE_URL"]))
    try:
        async with memory.transaction() as connection:
            row = await connection.fetchrow(
                "SELECT count(*) AS table_count FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = ANY($1::STRING[])",
                ("proposals", "gate_evaluations", "consequence_reports"),
            )
            assert row is not None
            assert int(row["table_count"]) == 3
    finally:
        await memory.close()
