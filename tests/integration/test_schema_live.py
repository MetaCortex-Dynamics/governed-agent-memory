"""Schema contract and opt-in CockroachDB integration tests."""

from __future__ import annotations

import os
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest

ROOT = Path(__file__).parents[2]
EXPECTED_TABLES = {
    "consequence_reports",
    "decisions",
    "demo_kv",
    "dependency_facts",
    "exclusions",
    "execution_attempts",
    "execution_receipts",
    "gate_evaluations",
    "proposals",
    "tool_evidence",
}


def test_schema_declares_exact_tables_and_vector_index() -> None:
    """The checked-in DDL carries the complete required table surface."""
    sql = (ROOT / "schema/init.sql").read_text(encoding="utf-8")
    declared = {
        line.split()[2] for line in sql.splitlines() if line.startswith("CREATE TABLE ")
    }
    assert declared == EXPECTED_TABLES
    assert "CREATE VECTOR INDEX idx_proposals_embedding" in sql
    assert "profile_version STRING NULL UNIQUE" not in sql
    assert "profile_version STRING NULL," in sql
    assert (
        "CREATE INDEX idx_gate_eval_profile_created\n"
        "    ON gate_evaluations (profile_version, created_at DESC);"
    ) in sql
    assert "profile_version IS NULL OR status = 'FINALIZED'" in sql
    for preserved_constraint in (
        "gate_eval_profile_state_ck",
        "gate_eval_digest_ck",
        "gate_eval_prior_fk",
        "gate_eval_bound_uq",
    ):
        assert preserved_constraint in sql
    assert "VECTOR(1536)" in sql
    assert "CREATE EXTENSION" not in sql
    assert "HNSW" not in sql.upper()


def test_role_matrix_is_append_only() -> None:
    """No runtime group role receives mutable or administrative privileges."""
    sql = (ROOT / "schema/roles.sql").read_text(encoding="utf-8")
    assert " NOLOGIN;" in sql
    assert "GRANT UPDATE" not in sql
    assert "GRANT DELETE" not in sql
    assert "GRANT CREATE" not in sql
    assert "REVOKE CREATE ON SCHEMA public FROM public;" in sql
    assert (
        "GRANT INSERT ON TABLE demo_kv, execution_attempts, execution_receipts" in sql
    )


def _live_url(name: str) -> str:
    if os.environ.get("RUN_LIVE_CRDB") != "1":
        pytest.skip("live CockroachDB test is opt-in")
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"missing live binding: {name}")
    assert "sslmode=verify-full" in value
    return value


@pytest.mark.asyncio
@pytest.mark.live_crdb
async def test_schema_inventory_live() -> None:
    """The deployed namespace matches the exact table set."""
    connection = await asyncpg.connect(dsn=_live_url("DATABASE_URL_SCHEMA_ADMIN"))
    try:
        rows = await connection.fetch(
            """
            SELECT table_name
              FROM information_schema.tables
             WHERE table_schema='public' AND table_type='BASE TABLE'
            """
        )
        assert {row["table_name"] for row in rows} == EXPECTED_TABLES
        assert await connection.fetchval("SELECT current_database()") == (
            "governed_agent_memory"
        )
    finally:
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.live_crdb
async def test_profile_version_is_non_unique_and_indexed_live() -> None:
    """The deployed evaluation profile is reusable and has its lookup index."""
    connection = await asyncpg.connect(dsn=_live_url("DATABASE_URL_SCHEMA_ADMIN"))
    try:
        constraints = await connection.fetch(
            """
            SELECT tc.constraint_type, kcu.column_name
              FROM information_schema.table_constraints AS tc
              JOIN information_schema.key_column_usage AS kcu
                ON kcu.constraint_catalog = tc.constraint_catalog
               AND kcu.constraint_schema = tc.constraint_schema
               AND kcu.constraint_name = tc.constraint_name
             WHERE tc.table_schema = 'public'
               AND tc.table_name = 'gate_evaluations'
            """
        )
        assert not any(
            row["constraint_type"] == "UNIQUE"
            and row["column_name"] == "profile_version"
            for row in constraints
        )
        indexes = await connection.fetch("SHOW INDEX FROM gate_evaluations")
        profile_index = sorted(
            (
                int(row["seq_in_index"]),
                row["column_name"],
                row["direction"],
            )
            for row in indexes
            if row["index_name"] == "idx_gate_eval_profile_created"
            and not row["storing"]
            and not row["implicit"]
        )
        assert profile_index == [
            (1, "profile_version", "ASC"),
            (2, "created_at", "DESC"),
        ]
        assert all(
            row["non_unique"]
            for row in indexes
            if row["index_name"] == "idx_gate_eval_profile_created"
        )
    finally:
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.live_crdb
@pytest.mark.parametrize(
    ("environment_name", "forbidden_table"),
    [
        ("DATABASE_URL_APP", "decisions"),
        ("DATABASE_URL_DECIDER", "proposals"),
        ("DATABASE_URL_EXECUTOR", "proposals"),
    ],
)
async def test_runtime_roles_cannot_mutate_history(
    environment_name: str, forbidden_table: str
) -> None:
    """Actual login bindings cannot update append-only governance history."""
    connection = await asyncpg.connect(dsn=_live_url(environment_name))
    try:
        statements = {
            "decisions": "DELETE FROM decisions WHERE false",
            "proposals": "DELETE FROM proposals WHERE false",
        }
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await connection.execute(statements[forbidden_table])
    finally:
        await connection.close()
