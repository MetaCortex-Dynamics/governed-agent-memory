#!/usr/bin/env python3
"""Apply the bounded, idempotent CockroachDB profile-version migration."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from typing import NoReturn

import asyncpg  # type: ignore[import-untyped]

DATABASE_NAME = "governed_agent_memory"
LEGACY_CONSTRAINT = "gate_evaluations_profile_version_key"
CONSTRAINT_QUERY = """
SELECT tc.constraint_name, kcu.column_name, kcu.ordinal_position
  FROM information_schema.table_constraints AS tc
  JOIN information_schema.key_column_usage AS kcu
    ON kcu.constraint_catalog = tc.constraint_catalog
   AND kcu.constraint_schema = tc.constraint_schema
   AND kcu.constraint_name = tc.constraint_name
 WHERE tc.table_schema = 'public'
   AND tc.table_name = 'gate_evaluations'
   AND tc.constraint_type = 'UNIQUE'
 ORDER BY tc.constraint_name, kcu.ordinal_position
"""
DROP_LEGACY_CONSTRAINT = (
    "ALTER TABLE gate_evaluations DROP CONSTRAINT IF EXISTS " + LEGACY_CONSTRAINT
)
CREATE_PROFILE_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_gate_eval_profile_created "
    "ON gate_evaluations (profile_version, created_at DESC)"
)


class MigrationBlocked(RuntimeError):
    """Safe migration-boundary failure."""


def blocked(message: str) -> NoReturn:
    raise MigrationBlocked(message)


def database_url() -> str:
    value = os.environ.get("DATABASE_URL_SCHEMA_ADMIN")
    if not value or value != value.strip():
        blocked("schema-admin binding is absent")
    if "sslmode=verify-full" not in value or any(
        item in value for item in ("sslmode=disable", "sslmode=require")
    ):
        blocked("schema-admin TLS binding is invalid")
    return value


def _unique_columns(rows: Sequence[object]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for row in rows:
        name = row["constraint_name"]  # type: ignore[index]
        column = row["column_name"]  # type: ignore[index]
        ordinal = row["ordinal_position"]  # type: ignore[index]
        if (
            not isinstance(name, str)
            or not isinstance(column, str)
            or isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal != len(grouped.setdefault(name, [])) + 1
        ):
            blocked("unique-constraint metadata is malformed")
        grouped[name].append(column)
    return {name: tuple(columns) for name, columns in grouped.items()}


async def migrate() -> None:
    connection = await asyncpg.connect(dsn=database_url())
    try:
        if await connection.fetchval("SELECT current_database()") != DATABASE_NAME:
            blocked("current database mismatch")
        async with connection.transaction():
            constraints = _unique_columns(await connection.fetch(CONSTRAINT_QUERY))
            profile_constraints = {
                name: columns
                for name, columns in constraints.items()
                if "profile_version" in columns
            }
            if profile_constraints not in (
                {},
                {LEGACY_CONSTRAINT: ("profile_version",)},
            ):
                blocked("unexpected profile-version uniqueness remains")
            await connection.execute(DROP_LEGACY_CONSTRAINT)
            await connection.execute(CREATE_PROFILE_INDEX)
    finally:
        await connection.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("profile-version",))
    arguments = parser.parse_args(argv)
    try:
        if arguments.command != "profile-version":
            raise AssertionError(arguments.command)
        asyncio.run(migrate())
    except (MigrationBlocked, OSError, asyncpg.PostgresError):
        print("crdb-profile-version-migration: BLOCKED")
        return 1
    print("crdb-profile-version-migration: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
