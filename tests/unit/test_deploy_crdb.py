"""Tests for the idempotent profile-version schema migration."""

from __future__ import annotations

import runpy
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from types import TracebackType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_URL = "postgresql://unit.invalid/governed_agent_memory?sslmode=verify-full"


class Transaction(AbstractAsyncContextManager[None]):
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


class Connection:
    def __init__(self, constraints: list[dict[str, object]]) -> None:
        self.constraints = constraints
        self.executed: list[str] = []
        self.closed = False

    async def fetchval(self, statement: str) -> str:
        assert statement == "SELECT current_database()"
        return "governed_agent_memory"

    async def fetch(self, statement: str) -> list[dict[str, object]]:
        assert "information_schema.table_constraints" in statement
        return list(self.constraints)

    def transaction(self) -> Transaction:
        return Transaction()

    async def execute(self, statement: str) -> None:
        self.executed.append(statement)

    async def close(self) -> None:
        self.closed = True


def migration() -> dict[str, Any]:
    return runpy.run_path(str(ROOT / "scripts/deploy_crdb.py"))


async def run_migration(
    monkeypatch: pytest.MonkeyPatch, constraints: list[dict[str, object]]
) -> tuple[dict[str, Any], Connection]:
    namespace = migration()
    connection = Connection(constraints)

    async def connect(*, dsn: str) -> Connection:
        assert dsn == SCHEMA_URL
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    await namespace["migrate"]()
    return namespace, connection


@pytest.mark.asyncio
@pytest.mark.parametrize("already_migrated", (False, True))
async def test_profile_version_migration_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, already_migrated: bool
) -> None:
    rows = (
        []
        if already_migrated
        else [
            {
                "constraint_name": "gate_evaluations_profile_version_key",
                "column_name": "profile_version",
                "ordinal_position": 1,
            }
        ]
    )
    namespace, connection = await run_migration(monkeypatch, rows)

    assert connection.executed == [
        namespace["DROP_LEGACY_CONSTRAINT"],
        namespace["CREATE_PROFILE_INDEX"],
    ]
    assert "IF EXISTS" in connection.executed[0]
    assert "IF NOT EXISTS" in connection.executed[1]
    assert connection.closed


@pytest.mark.asyncio
async def test_profile_version_migration_rejects_unexpected_uniqueness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = migration()
    connection = Connection(
        [
            {
                "constraint_name": "unexpected_profile_unique",
                "column_name": "profile_version",
                "ordinal_position": 1,
            }
        ]
    )

    async def connect(*, dsn: str) -> Connection:
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    with pytest.raises(namespace["MigrationBlocked"], match="unexpected"):
        await namespace["migrate"]()

    assert connection.executed == []
    assert connection.closed
