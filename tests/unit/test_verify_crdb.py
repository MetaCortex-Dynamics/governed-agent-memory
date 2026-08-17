"""Credential-free tests for the CockroachDB verification boundary."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETTING_STATEMENT = "SHOW CLUSTER SETTING feature.vector_index.enabled"
INTERNAL_SETTINGS_TABLE = "crdb_internal.cluster_settings"
SCHEMA_DATABASE_URL = (
    "postgresql://unit.invalid/governed_agent_memory?sslmode=verify-full"
)
TABLE_INVENTORY_STATEMENT = """
            SELECT table_name
              FROM information_schema.tables
             WHERE table_schema='public' AND table_type='BASE TABLE'
             ORDER BY table_name
            """
INDEX_STATEMENT = "SHOW INDEX FROM proposals"
TARGETLESS_INDEX_STATEMENT = "SHOW INDEXES"
GRANTS_STATEMENT = """
            SELECT grantee, table_name, privilege_type
              FROM information_schema.table_privileges
             WHERE table_schema='public'
             ORDER BY grantee, table_name, privilege_type
            """
ROLE_OPTIONS_STATEMENT = """
            SELECT username, options
              FROM [SHOW ROLES]
             WHERE username = ANY($1::STRING[])
             ORDER BY username
            """
LEGACY_ROLE_COLUMNS = ('"isRole"', '"canLogin"', '"createDB"', '"createRole"')


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


class FakeSchemaConnection:
    """Record schema verification without opening a database connection."""

    def __init__(
        self,
        table_names: tuple[str, ...],
        *,
        current_database: str = "governed_agent_memory",
        index_name: str | None = "idx_proposals_embedding",
    ) -> None:
        self.table_names = table_names
        self.current_database = current_database
        self.index_name = index_name
        self.calls: list[tuple[str, str]] = []
        self.closed = False

    async def fetchval(self, statement: str) -> str:
        self.calls.append(("fetchval", statement))
        if statement != "SELECT current_database()":
            raise AssertionError(f"unexpected fetchval statement: {statement!r}")
        return self.current_database

    async def fetch(self, statement: str) -> list[dict[str, str]]:
        self.calls.append(("fetch", statement))
        if TARGETLESS_INDEX_STATEMENT in statement:
            raise AssertionError("targetless index discovery must never be queried")
        if statement == TABLE_INVENTORY_STATEMENT:
            return [{"table_name": name} for name in self.table_names]
        if statement == INDEX_STATEMENT:
            if self.index_name is None:
                return []
            return [
                {"table_name": "proposals", "index_name": self.index_name},
            ]
        raise AssertionError(f"unexpected fetch statement: {statement!r}")

    async def close(self) -> None:
        self.closed = True


class FakeGrantsConnection:
    """Record grant verification without opening a database connection."""

    def __init__(
        self,
        grants: list[dict[str, Any]],
        role_options: list[dict[str, object]],
    ) -> None:
        self.grants = grants
        self.role_options = role_options
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.closed = False

    async def fetch(self, statement: str, *args: object) -> list[dict[str, Any]]:
        self.calls.append((statement, args))
        if statement == GRANTS_STATEMENT:
            return list(self.grants)
        if statement == ROLE_OPTIONS_STATEMENT:
            return list(self.role_options)
        raise AssertionError(f"unexpected fetch statement: {statement!r}")

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


async def run_schema_check(
    monkeypatch: pytest.MonkeyPatch,
    *,
    current_database: str = "governed_agent_memory",
    table_names: tuple[str, ...] | None = None,
    index_name: str | None = "idx_proposals_embedding",
) -> tuple[dict[str, Any], FakeSchemaConnection]:
    """Run schema_check against an isolated in-memory connection."""
    namespace = verifier()
    expected_tables = namespace["TABLES"] if table_names is None else table_names
    connection = FakeSchemaConnection(
        expected_tables,
        current_database=current_database,
        index_name=index_name,
    )

    async def connect(*, dsn: str) -> FakeSchemaConnection:
        assert dsn == SCHEMA_DATABASE_URL
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_DATABASE_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    await namespace["schema_check"]()
    return namespace, connection


def canonical_grants(namespace: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the exact INSERT matrix consumed by grants_check."""
    return [
        {"grantee": role, "table_name": table, "privilege_type": "INSERT"}
        for role in namespace["ROLES"]
        for table in sorted(namespace["EXPECTED_INSERTS"][role])
    ]


def canonical_role_options(namespace: dict[str, Any]) -> list[dict[str, object]]:
    """Build the exact four-role NOLOGIN result."""
    return [
        {"username": role, "options": ["NOLOGIN"]}
        for role in sorted(namespace["ROLES"])
    ]


async def configured_grants_check(
    monkeypatch: pytest.MonkeyPatch,
    namespace: dict[str, Any],
    connection: FakeGrantsConnection,
) -> None:
    """Run grants_check against one isolated fake connection."""

    async def connect(*, dsn: str) -> FakeGrantsConnection:
        assert dsn == SCHEMA_DATABASE_URL
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_DATABASE_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    await namespace["grants_check"]()


@pytest.mark.asyncio
async def test_server_preflight_uses_only_supported_setting_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, connection = await run_server_preflight(monkeypatch, True)

    assert result["feature_vector_index_enabled"] is True
    assert [call[0] for call in connection.calls] == [
        "SELECT version()",
        SETTING_STATEMENT,
        "SELECT count(*) FROM [SHOW DATABASES] WHERE database_name=$1",
    ]
    assert all(INTERNAL_SETTINGS_TABLE not in call[0] for call in connection.calls)
    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("setting", (False, "true", "TRUE", 1, None))
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
    connection = FakeConnection(True, setting_error=failure)

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


@pytest.mark.asyncio
async def test_schema_check_uses_qualified_index_and_preserves_inventory_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace, connection = await run_schema_check(monkeypatch)

    assert tuple(connection.table_names) == namespace["TABLES"]
    assert connection.current_database == namespace["DATABASE_NAME"]
    assert connection.calls == [
        ("fetchval", "SELECT current_database()"),
        ("fetch", TABLE_INVENTORY_STATEMENT),
        ("fetch", INDEX_STATEMENT),
    ]
    assert all(TARGETLESS_INDEX_STATEMENT not in call[1] for call in connection.calls)
    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("index_name", (None, "idx_proposals_embedding_renamed"))
async def test_schema_check_blocks_missing_or_renamed_vector_index(
    monkeypatch: pytest.MonkeyPatch, index_name: str | None
) -> None:
    namespace = verifier()
    connection = FakeSchemaConnection(namespace["TABLES"], index_name=index_name)

    async def connect(*, dsn: str) -> FakeSchemaConnection:
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_DATABASE_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    with pytest.raises(namespace["EvidenceBlocked"], match="vector index is absent"):
        await namespace["schema_check"]()

    assert ("fetch", INDEX_STATEMENT) in connection.calls
    assert all(TARGETLESS_INDEX_STATEMENT not in call[1] for call in connection.calls)
    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("current_database", "table_names", "message"),
    (
        ("defaultdb", None, "current database mismatch"),
        ("governed_agent_memory", ("proposals",), "table inventory mismatch"),
    ),
)
async def test_schema_check_preserves_database_and_table_inventory_failures(
    monkeypatch: pytest.MonkeyPatch,
    current_database: str,
    table_names: tuple[str, ...] | None,
    message: str,
) -> None:
    namespace = verifier()
    observed_tables = namespace["TABLES"] if table_names is None else table_names
    connection = FakeSchemaConnection(
        observed_tables,
        current_database=current_database,
    )

    async def connect(*, dsn: str) -> FakeSchemaConnection:
        return connection

    monkeypatch.setenv("DATABASE_URL_SCHEMA_ADMIN", SCHEMA_DATABASE_URL)
    monkeypatch.setattr(namespace["asyncpg"], "connect", connect)
    with pytest.raises(namespace["EvidenceBlocked"], match=message):
        await namespace["schema_check"]()

    assert connection.calls[:2] == [
        ("fetchval", "SELECT current_database()"),
        ("fetch", TABLE_INVENTORY_STATEMENT),
    ]
    assert connection.closed


@pytest.mark.asyncio
async def test_grants_check_accepts_exact_four_nologin_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = verifier()
    connection = FakeGrantsConnection(
        canonical_grants(namespace),
        canonical_role_options(namespace),
    )

    await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.calls == [
        (GRANTS_STATEMENT, ()),
        (ROLE_OPTIONS_STATEMENT, (list(namespace["ROLES"]),)),
    ]
    assert all(column not in ROLE_OPTIONS_STATEMENT for column in LEGACY_ROLE_COLUMNS)
    assert connection.closed


@pytest.mark.asyncio
async def test_grants_check_blocks_missing_runtime_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = verifier()
    options = canonical_role_options(namespace)[:-1]
    connection = FakeGrantsConnection(canonical_grants(namespace), options)

    with pytest.raises(namespace["EvidenceBlocked"], match="role inventory"):
        await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("elevated", ("LOGIN", "CREATEDB", "CREATEROLE", "CREATELOGIN"))
async def test_grants_check_blocks_authority_enhancing_role_options(
    monkeypatch: pytest.MonkeyPatch, elevated: str
) -> None:
    namespace = verifier()
    options = canonical_role_options(namespace)
    options[0] = {"username": options[0]["username"], "options": ["NOLOGIN", elevated]}
    connection = FakeGrantsConnection(canonical_grants(namespace), options)

    with pytest.raises(namespace["EvidenceBlocked"], match="authority exceeds"):
        await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "malformed",
    (
        ["NOLOGIN", "FUTURE_AUTHORITY"],
        "NOLOGIN",
        None,
        [],
        [1],
        ["nologin"],
    ),
)
async def test_grants_check_blocks_unknown_or_malformed_options(
    monkeypatch: pytest.MonkeyPatch, malformed: object
) -> None:
    namespace = verifier()
    options = canonical_role_options(namespace)
    options[0] = {"username": options[0]["username"], "options": malformed}
    connection = FakeGrantsConnection(canonical_grants(namespace), options)

    with pytest.raises(namespace["EvidenceBlocked"], match="authority exceeds"):
        await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ("missing", "extra"))
async def test_grants_check_preserves_exact_insert_matrix(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    namespace = verifier()
    grants = canonical_grants(namespace)
    if mutation == "missing":
        grants.pop()
    else:
        grants.append(
            {
                "grantee": "gam_reader_role",
                "table_name": "proposals",
                "privilege_type": "INSERT",
            }
        )
    connection = FakeGrantsConnection(grants, canonical_role_options(namespace))

    with pytest.raises(namespace["EvidenceBlocked"], match="INSERT grant mismatch"):
        await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forbidden_grant",
    (
        {"grantee": "public", "table_name": "proposals", "privilege_type": "SELECT"},
        {
            "grantee": "gam_app_role",
            "table_name": "proposals",
            "privilege_type": "UPDATE",
        },
        {
            "grantee": "gam_executor_role",
            "table_name": "proposals",
            "privilege_type": "DELETE",
        },
    ),
)
async def test_grants_check_preserves_public_and_mutable_privilege_rejection(
    monkeypatch: pytest.MonkeyPatch,
    forbidden_grant: dict[str, Any],
) -> None:
    namespace = verifier()
    grants = [*canonical_grants(namespace), forbidden_grant]
    connection = FakeGrantsConnection(grants, canonical_role_options(namespace))

    with pytest.raises(namespace["EvidenceBlocked"]):
        await configured_grants_check(monkeypatch, namespace, connection)

    assert connection.closed
