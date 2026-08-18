#!/usr/bin/env python3
"""Fail-closed CockroachDB preflight and live verification."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

import asyncpg  # type: ignore[import-untyped]

from src.ccloud_tool import (
    CCAPI_COMPAT_VERSION,
    CLUSTER_NAME,
    EXPECTED_REGION,
    REQUIRED_VERSION_FAMILY,
    EvidenceBlocked,
    canonical_bytes,
    canonical_digest,
    discover_preflight,
    normalize_legacy_plan,
    sha256_bytes,
    strict_json,
)

VERSION_ARTIFACT = Path("schema/crdb-version.json")
DATABASE_NAME = "governed_agent_memory"
VECTOR_DOCS_URL = "https://www.cockroachlabs.com/docs/v26.2/vector-indexes"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
RELEASE = re.compile(r"(?<![0-9])v?(26\.2\.(?:0|[1-9][0-9]*))(?![0-9])")
TABLES = (
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
)
PROFILE_CONSTRAINTS_STATEMENT = """
            SELECT tc.constraint_name, tc.constraint_type, kcu.column_name
              FROM information_schema.table_constraints AS tc
              JOIN information_schema.key_column_usage AS kcu
                ON kcu.constraint_catalog = tc.constraint_catalog
               AND kcu.constraint_schema = tc.constraint_schema
               AND kcu.constraint_name = tc.constraint_name
             WHERE tc.table_schema = 'public'
               AND tc.table_name = 'gate_evaluations'
             ORDER BY tc.constraint_name, kcu.ordinal_position
            """
GATE_INDEX_STATEMENT = "SHOW INDEX FROM gate_evaluations"
ROLES = (
    "gam_reader_role",
    "gam_app_role",
    "gam_decider_role",
    "gam_executor_role",
)
EXPECTED_INSERTS = {
    "gam_reader_role": set(),
    "gam_app_role": {
        "proposals",
        "gate_evaluations",
        "dependency_facts",
        "consequence_reports",
        "tool_evidence",
    },
    "gam_decider_role": {"decisions", "exclusions"},
    "gam_executor_role": {
        "demo_kv",
        "execution_attempts",
        "execution_receipts",
    },
}


def blocked(message: str) -> NoReturn:
    """Raise a safe fail-closed diagnostic."""
    raise EvidenceBlocked(message)


def required(name: str) -> str:
    """Read one nonempty environment binding."""
    value = os.environ.get(name)
    if value is None or value == "":
        blocked(f"required environment binding absent: {name}")
    return value


def require_digest(value: str, label: str) -> str:
    """Validate one SHA-256 text binding."""
    if not HEX_64.fullmatch(value):
        blocked(f"invalid digest binding: {label}")
    return value


def database_url(name: str) -> str:
    """Load one role URL and enforce verified TLS."""
    value = required(name)
    if "sslmode=verify-full" not in value:
        blocked(f"{name} must use sslmode=verify-full")
    if "sslmode=disable" in value or "sslmode=require" in value:
        blocked(f"{name} has insufficient TLS verification")
    return value


def canonical_timestamp(value: Any) -> datetime:
    """Parse exact canonical UTC RFC3339 seconds."""
    if not isinstance(value, str):
        blocked("preprovision timestamp type is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise EvidenceBlocked("preprovision timestamp is not canonical") from error
    if parsed > datetime.now(UTC):
        blocked("preprovision timestamp is in the future")
    return parsed


def load_preprovision() -> tuple[dict[str, Any], bytes]:
    """Load and bind the external canonical preprovision record."""
    path = Path(required("CRDB_PREPROVISION_EVIDENCE_FILE")).resolve(strict=True)
    raw = path.read_bytes()
    expected_raw = require_digest(
        required("CRDB_PREPROVISION_EVIDENCE_SHA256"), "preprovision record"
    )
    if sha256_bytes(raw) != expected_raw:
        blocked("preprovision record-byte digest mismatch")
    value = strict_json(raw)
    if not isinstance(value, dict):
        blocked("preprovision record is not an object")
    expected_keys = {
        "schema",
        "admin_handle_digest",
        "captured_at",
        "cloud",
        "cluster_id_digest",
        "cluster_name",
        "cluster_name_digest",
        "cockroach_version",
        "plan",
        "promotion_digest",
        "provisioning_receipt_digest",
        "regions",
        "spend_limit_usd",
        "state",
        "evidence_digest",
    }
    if set(value) != expected_keys:
        blocked("preprovision fields differ")
    if canonical_bytes(value) != raw:
        blocked("preprovision record bytes are not canonical")
    evidence_digest = require_digest(str(value["evidence_digest"]), "evidence")
    payload = dict(value)
    del payload["evidence_digest"]
    if canonical_digest(payload) != evidence_digest:
        blocked("preprovision evidence digest mismatch")
    canonical_timestamp(value["captured_at"])
    literal_expected: dict[str, Any] = {
        "schema": "gam.cluster-preprovision.v1",
        "cloud": "AWS",
        "cluster_name": CLUSTER_NAME,
        "cluster_name_digest": sha256_bytes(CLUSTER_NAME.encode()),
        "plan": "SERVERLESS",
        "regions": [EXPECTED_REGION],
        "spend_limit_usd": "0",
        "state": "CREATED",
    }
    for key, expected in literal_expected.items():
        if value[key] != expected:
            blocked(f"preprovision target mismatch: {key}")
    observed_version = str(value["cockroach_version"])
    if not observed_version.startswith(f"{REQUIRED_VERSION_FAMILY}."):
        blocked("preprovision target mismatch: cockroach_version")
    for key in (
        "admin_handle_digest",
        "cluster_id_digest",
        "promotion_digest",
        "provisioning_receipt_digest",
    ):
        require_digest(str(value[key]), key)
    if value["promotion_digest"] != required("CRDB_SETUP_PROMOTION_DIGEST"):
        blocked("setup promotion binding mismatch")
    if value["cluster_id_digest"] != required("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST"):
        blocked("expected cluster ID binding mismatch")
    if value["provisioning_receipt_digest"] != required(
        "CCLOUD_PROVISIONING_RECEIPT_DIGEST"
    ):
        blocked("provisioning receipt binding mismatch")
    handle = required("CRDB_SCHEMA_ADMIN_HANDLE")
    if sha256_bytes(handle.encode()) != value["admin_handle_digest"]:
        blocked("schema-admin handle binding mismatch")
    if required("CCLOUD_CLUSTER_NAME") != CLUSTER_NAME:
        blocked("cluster-name environment binding mismatch")
    return value, raw


def normalize_release(raw: str) -> str:
    """Normalize exactly the bound CockroachDB release."""
    matches = RELEASE.findall(raw)
    if len(matches) != 1:
        blocked("CockroachDB release is absent or ambiguous")
    return f"v{matches[0]}"


async def server_preflight(url: str) -> dict[str, Any]:
    """Read only server version, vector setting, and database absence."""
    connection = await asyncpg.connect(dsn=url)
    try:
        version_raw = str(await connection.fetchval("SELECT version()"))
        setting = await connection.fetchval(
            "SHOW CLUSTER SETTING feature.vector_index.enabled"
        )
        collision = await connection.fetchval(
            "SELECT count(*) FROM [SHOW DATABASES] WHERE database_name=$1",
            DATABASE_NAME,
        )
    finally:
        await connection.close()
    observed_version = normalize_release(version_raw)
    if not observed_version.startswith(f"{REQUIRED_VERSION_FAMILY}."):
        blocked("server release family mismatch")
    if setting is not True:
        blocked("vector indexing is disabled")
    if collision != 0:
        blocked("target database already exists")
    return {
        "required_version_family": REQUIRED_VERSION_FAMILY,
        "observed_cockroach_version": observed_version,
        "cockroach_version_raw_digest": sha256_bytes(version_raw.encode()),
        "feature_vector_index_enabled": True,
    }


def preflight_config(
    record: Mapping[str, Any],
    raw_digest: str,
    tool: Mapping[str, str],
) -> dict[str, Any]:
    """Build the tagged ccloud preflight configuration."""
    profile = required("CCLOUD_AUTH_PROFILE")
    return {
        "schema": "gam.ccloud-preflight-config.v1",
        "ccloud_executable_sha256": tool["ccloud_executable_sha256"],
        "ccloud_version": tool["ccloud_version"],
        "ccloud_version_raw_digest": tool["ccloud_version_raw_digest"],
        "ccloud_help_digest": tool["ccloud_help_digest"],
        "ccloud_json_flag": tool["ccloud_json_flag"],
        "ccloud_auth_profile_digest": sha256_bytes(profile.encode()),
        "cluster_name_digest": record["cluster_name_digest"],
        "expected_cluster_id_digest": record["cluster_id_digest"],
        "preprovision_record_sha256": raw_digest,
        "preprovision_evidence_digest": record["evidence_digest"],
        "provisioning_receipt_digest": record["provisioning_receipt_digest"],
        "setup_promotion_digest": record["promotion_digest"],
        "schema_admin_handle_digest": record["admin_handle_digest"],
        "preprovision_observed_at": record["captured_at"],
        "target_state": record["state"],
        "target_wire_plan": record["plan"],
        "target_plan": normalize_legacy_plan(
            str(record["plan"]),
            ccloud_version=tool["ccloud_version"],
            ccapi_version=CCAPI_COMPAT_VERSION,
        ),
        "target_cloud": record["cloud"],
        "target_regions": record["regions"],
        "required_version_family": REQUIRED_VERSION_FAMILY,
        "observed_cockroach_version": record["cockroach_version"],
        "ccapi_version": CCAPI_COMPAT_VERSION,
        "target_spend_limit_usd": record["spend_limit_usd"],
    }


def atomic_artifact(value: Mapping[str, Any]) -> None:
    """Write the complete version artifact atomically."""
    VERSION_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    content = canonical_bytes(value)
    with tempfile.NamedTemporaryFile(
        dir=VERSION_ARTIFACT.parent, prefix=".crdb-version.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temporary.replace(VERSION_ARTIFACT)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def build_preflight_artifact(
    record: Mapping[str, Any],
    raw: bytes,
    tool: Mapping[str, str],
    server: Mapping[str, Any],
) -> dict[str, Any]:
    """Construct the canonical credential-free preflight artifact."""
    if server["observed_cockroach_version"] != record["cockroach_version"]:
        blocked("observed CockroachDB release differs from preprovision evidence")
    raw_digest = sha256_bytes(raw)
    config = preflight_config(record, raw_digest, tool)
    artifact: dict[str, Any] = {
        "artifact_version": "gam.crdb-version.v1",
        **server,
        "database_name": DATABASE_NAME,
        "cluster_name_digest": record["cluster_name_digest"],
        "expected_cluster_id_digest": record["cluster_id_digest"],
        "provisioning_receipt_digest": record["provisioning_receipt_digest"],
        "preprovision_record_sha256": raw_digest,
        "preprovision_evidence_digest": record["evidence_digest"],
        "preprovision_observed_at": record["captured_at"],
        "setup_promotion_digest": record["promotion_digest"],
        "schema_admin_handle_digest": record["admin_handle_digest"],
        "target_state": record["state"],
        "target_wire_plan": record["plan"],
        "target_plan": normalize_legacy_plan(
            str(record["plan"]),
            ccloud_version=tool["ccloud_version"],
            ccapi_version=CCAPI_COMPAT_VERSION,
        ),
        "target_cloud": record["cloud"],
        "target_regions": record["regions"],
        "target_spend_limit_usd": record["spend_limit_usd"],
        "vector_docs_url": VECTOR_DOCS_URL,
        "ccloud_executable": tool["ccloud_executable"],
        "ccloud_executable_sha256": tool["ccloud_executable_sha256"],
        "ccloud_version": tool["ccloud_version"],
        "ccapi_version": CCAPI_COMPAT_VERSION,
        "ccloud_version_raw_digest": tool["ccloud_version_raw_digest"],
        "ccloud_help_digest": tool["ccloud_help_digest"],
        "ccloud_config_digest": canonical_digest(config),
        "ccloud_auth_profile_digest": config["ccloud_auth_profile_digest"],
        "ccloud_json_flag": tool["ccloud_json_flag"],
    }
    artifact["capture_digest"] = canonical_digest(artifact)
    return artifact


async def preflight() -> None:
    """Run the complete authorized read-only preflight."""
    record, raw = load_preprovision()
    tool = discover_preflight()
    server = await server_preflight(database_url("DATABASE_URL_SCHEMA_ADMIN"))
    atomic_artifact(build_preflight_artifact(record, raw, tool, server))


async def schema_check() -> None:
    """Verify the exact deployed table and index set."""
    connection = await asyncpg.connect(dsn=database_url("DATABASE_URL_SCHEMA_ADMIN"))
    try:
        current = await connection.fetchval("SELECT current_database()")
        rows = await connection.fetch(
            """
            SELECT table_name
              FROM information_schema.tables
             WHERE table_schema='public' AND table_type='BASE TABLE'
             ORDER BY table_name
            """
        )
        indexes = await connection.fetch("SHOW INDEX FROM proposals")
        gate_constraints = await connection.fetch(PROFILE_CONSTRAINTS_STATEMENT)
        gate_indexes = await connection.fetch(GATE_INDEX_STATEMENT)
    finally:
        await connection.close()
    if current != DATABASE_NAME:
        blocked("current database mismatch")
    if tuple(row["table_name"] for row in rows) != TABLES:
        blocked("deployed table inventory mismatch")
    names = {(row["table_name"], row["index_name"]) for row in indexes}
    if ("proposals", "idx_proposals_embedding") not in names:
        blocked("distributed vector index is absent")
    if any(
        row["constraint_type"] == "UNIQUE" and row["column_name"] == "profile_version"
        for row in gate_constraints
    ):
        blocked("profile version remains unique")
    profile_index = sorted(
        (
            int(row["seq_in_index"]),
            str(row["column_name"]),
            str(row["direction"]),
        )
        for row in gate_indexes
        if row["index_name"] == "idx_gate_eval_profile_created"
        and not bool(row.get("storing", False))
        and not bool(row.get("implicit", False))
    )
    if profile_index != [
        (1, "profile_version", "ASC"),
        (2, "created_at", "DESC"),
    ] or any(
        row["index_name"] == "idx_gate_eval_profile_created"
        and not bool(row["non_unique"])
        for row in gate_indexes
    ):
        blocked("profile-version lookup index mismatch")


async def grants_check() -> None:
    """Verify the finite runtime-role grant matrix."""
    connection = await asyncpg.connect(dsn=database_url("DATABASE_URL_SCHEMA_ADMIN"))
    try:
        grants = await connection.fetch(
            """
            SELECT grantee, table_name, privilege_type
              FROM information_schema.table_privileges
             WHERE table_schema='public'
             ORDER BY grantee, table_name, privilege_type
            """
        )
        options = await connection.fetch(
            """
            SELECT username, options
              FROM [SHOW ROLES]
             WHERE username = ANY($1::STRING[])
             ORDER BY username
            """,
            list(ROLES),
        )
    finally:
        await connection.close()
    role_rows = [row for row in grants if row["grantee"] in ROLES]
    if any(
        row["privilege_type"] in {"UPDATE", "DELETE"}
        for row in grants
        if row["grantee"] in {*ROLES, "public"}
    ):
        blocked("mutable runtime grant detected")
    if any(row["grantee"] == "public" for row in grants):
        blocked("public table privilege detected")
    for role in ROLES:
        observed = {
            row["table_name"]
            for row in role_rows
            if row["grantee"] == role and row["privilege_type"] == "INSERT"
        }
        if observed != EXPECTED_INSERTS[role]:
            blocked(f"INSERT grant mismatch: {role}")
    usernames = [row["username"] for row in options]
    if len(usernames) != len(ROLES) or set(usernames) != set(ROLES):
        blocked("runtime role inventory mismatch")
    for row in options:
        value = row["options"]
        if not isinstance(value, list) or value != ["NOLOGIN"]:
            blocked("runtime role authority exceeds matrix")


def probe_vector(axis: int) -> str:
    """Create one canonical 1536-dimensional VECTOR text probe."""
    if type(axis) is not int or not 0 <= axis < 1536:
        blocked("vector probe axis is out of range")
    components = ["0.0"] * 1536
    components[axis] = "1.0"
    return "[" + ",".join(components) + "]"


async def vector_check() -> None:
    """Prove the distributed vector index and query plan."""
    connection = await asyncpg.connect(dsn=database_url("DATABASE_URL_SCHEMA_ADMIN"))
    try:
        show_create = str(await connection.fetchval("SHOW CREATE TABLE proposals"))
        show_index = "\n".join(
            str(dict(row))
            for row in await connection.fetch("SHOW INDEX FROM proposals")
        )
        query = (
            "SELECT id, embedding <=> $1::VECTOR AS distance "
            "FROM proposals ORDER BY embedding <=> $1::VECTOR LIMIT 5"
        )
        parameter = probe_vector(0)
        plan = "\n".join(
            str(row[0]) for row in await connection.fetch("EXPLAIN " + query, parameter)
        )
    finally:
        await connection.close()
    lowered = (show_create + show_index).lower()
    if "idx_proposals_embedding" not in lowered:
        blocked("vector index metadata mismatch")
    if "vector search" not in plan.lower() or "idx_proposals_embedding" not in plan:
        blocked("query plan did not use the distributed vector index")


async def run(command: str) -> None:
    """Dispatch one exact verifier mode."""
    if command == "preflight":
        await preflight()
    elif command == "schema":
        await schema_check()
    elif command == "grants":
        await grants_check()
    elif command == "vector":
        await vector_check()
    else:
        raise AssertionError(command)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint with redacted diagnostics."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("preflight", "schema", "grants", "vector"))
    arguments = parser.parse_args(argv)
    try:
        asyncio.run(run(arguments.command))
    except (
        EvidenceBlocked,
        OSError,
        asyncpg.PostgresError,
        KeyError,
        TypeError,
        ValueError,
    ):
        print(f"crdb-{arguments.command}: BLOCKED")
        return 1
    print(f"crdb-{arguments.command}: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
