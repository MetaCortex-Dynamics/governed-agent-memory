"""Credential-free tests for the CockroachDB verification boundary."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETTING_STATEMENT = "SHOW CLUSTER SETTING feature.vector_index.enabled"
INTERNAL_SETTINGS_TABLE = "crdb_internal.cluster_settings"


class DatabaseFailure(RuntimeError):
    """Synthetic database error used to prove fail-closed propagation."""


class FakeConnection:
    """Record preflight statements without opening a database connection."""

    def __init__(self, setting: object, *, setting_error: Exception | None = None):
        self.setting = setting
        self.setting_error = setting_error
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.closed = False

    async def fetchval(self, statement: str, *args: object) -> object:
        self.calls.append((statement, args))
        if INTERNAL_SETTINGS_TABLE in statement:
            raise AssertionError("the internal settings table must never be queried")
        if statement == "SELECT version()":
            return "CockroachDB CCL v26.2.5"
        if statement == SETTING_STATEMENT:
            if self.setting_error is not None:
                raise self.setting_error
            return self.setting
        if statement == "SELECT count(*) FROM [SHOW DATABASES] WHERE database_name=$1":
            return 0
        raise AssertionError(f"unexpected statement: {statement!r}")

    async def close(self) -> None:
        self.closed = True


def verifier() -> dict[str, Any]:
    """Load the verification script without invoking its command-line entry point."""
    return runpy.run_path(str(ROOT / "scripts/verify_crdb.py"))


async def run_server_preflight(
    monkeypatch: pytest.MonkeyPatch,
    setting: object,
    *,
    setting_error: Exception | None = None,
) -> tuple[dict[str, Any], FakeConnection]:
    """Run server_preflight against a connection that never reaches the network."""
    namespace = verifier()
    connection = FakeConnection(setting, setting_error=setting_error)

    async def connect(*, dsn: str) -> FakeConnection:
        assert dsn == "postgresql://unit.invalid/database"
        return connection

    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    result = await namespace["server_preflight"]("postgresql://unit.invalid/database")
    return result, connection


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", ("true", " TRUE "))
async def test_server_preflight_uses_only_supported_setting_statement(
    monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    result, connection = await run_server_preflight(monkeypatch, setting)

    assert result["feature_vector_index_enabled"] is True
    assert [call[0] for call in connection.calls] == [
        "SELECT version()",
        SETTING_STATEMENT,
        "SELECT count(*) FROM [SHOW DATABASES] WHERE database_name=$1",
    ]
    assert all(INTERNAL_SETTINGS_TABLE not in call[0] for call in connection.calls)
    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", ("false", None, "enabled", "", True, 1))
async def test_server_preflight_blocks_non_true_setting_values(
    monkeypatch: pytest.MonkeyPatch, setting: object
) -> None:
    namespace = verifier()
    connection = FakeConnection(setting)

    async def connect(*, dsn: str) -> FakeConnection:
        return connection

    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    with pytest.raises(namespace["EvidenceBlocked"], match="vector indexing"):
        await namespace["server_preflight"]("postgresql://unit.invalid/database")

    assert all(INTERNAL_SETTINGS_TABLE not in call[0] for call in connection.calls)
    assert connection.closed


@pytest.mark.asyncio
async def test_server_preflight_propagates_database_setting_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = DatabaseFailure("synthetic database failure")
    namespace = verifier()
    connection = FakeConnection("true", setting_error=failure)

    async def connect(*, dsn: str) -> FakeConnection:
        return connection

    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    with pytest.raises(DatabaseFailure, match="synthetic database failure"):
        await namespace["server_preflight"]("postgresql://unit.invalid/database")

    assert [call[0] for call in connection.calls] == [
        "SELECT version()",
        SETTING_STATEMENT,
    ]
    assert all(INTERNAL_SETTINGS_TABLE not in call[0] for call in connection.calls)
    assert connection.closed
