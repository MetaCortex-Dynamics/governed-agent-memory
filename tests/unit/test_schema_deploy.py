"""Tests for schema deployment behavior."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "schema/deploy.sh"


def resolve_bash() -> str:
    """Resolve Bash once so subprocess execution uses an absolute path."""
    executable = shutil.which("bash")
    if executable is None:
        raise RuntimeError("bash executable unavailable")
    return executable


BASH = resolve_bash()
ADMIN_USER = "schema_" + "admin"
ADMIN_PASSWORD = "unit-" + "credential"


def database_url(database: str, query: str | None) -> str:
    """Build a synthetic URL without embedding one in tracked source."""
    value = (
        "postgresql://"
        + ADMIN_USER
        + ":"
        + ADMIN_PASSWORD
        + "@db.invalid:26257/"
        + database
    )
    return value if query is None else f"{value}?{query}"


ADMIN_URL = database_url("ignored", "application_name=unit&sslmode=verify-full")
DEFAULTDB_URL = database_url("defaultdb", "application_name=unit&sslmode=verify-full")
COLLISION_QUERY = (
    "SELECT count(*) AS database_count FROM [SHOW DATABASES] "
    "WHERE database_name = 'governed_agent_memory'"
)


def install_fake_cockroach(tmp_path: Path) -> tuple[Path, Path]:
    """Install a fake client that records only non-secret invocation data."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    executable = fake_bin / "cockroach"
    log = tmp_path / "calls.log"
    count = tmp_path / "count"
    executable.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
[[ "${COCKROACH_URL-}" == "${EXPECTED_COCKROACH_URL-}" ]] || exit 90
call=0
if [[ -f "$FAKE_COUNT" ]]; then
    read -r call < "$FAKE_COUNT"
fi
call=$((call + 1))
printf '%s\n' "$call" > "$FAKE_COUNT"
{
    printf 'CALL=%s\n' "$call"
    url_without_query="${COCKROACH_URL%%\?*}"
    printf 'URL_DATABASE=%s\n' "${url_without_query##*/}"
    for argument in "$@"; do
        printf 'ARG=%s\n' "$argument"
    done
    printf 'END\n'
} >> "$FAKE_LOG"
if [[ "$call" -eq "${FAKE_FAIL_CALL:-0}" ]]; then
    exit 42
fi
if [[ "$call" -eq 1 ]]; then
    printf 'database_count\n%s\n' "${FAKE_COLLISION:-0}"
fi
"""
    )
    executable.chmod(0o755)
    count.write_text("0\n")
    return fake_bin, log


def run_deploy(
    tmp_path: Path,
    *,
    admin_url: str | None = ADMIN_URL,
    collision: int = 0,
    fail_call: int = 0,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run deploy.sh with an isolated fake client and environment."""
    fake_bin, log = install_fake_cockroach(tmp_path)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    environment["EXPECTED_COCKROACH_URL"] = DEFAULTDB_URL
    environment["FAKE_LOG"] = str(log)
    environment["FAKE_COUNT"] = str(tmp_path / "count")
    environment["FAKE_COLLISION"] = str(collision)
    environment["FAKE_FAIL_CALL"] = str(fail_call)
    environment["COCKROACH_URL"] = "postgresql://must-be-overwritten.invalid/unsafe"
    if admin_url is None:
        environment.pop("DATABASE_URL_SCHEMA_ADMIN", None)
    else:
        environment["DATABASE_URL_SCHEMA_ADMIN"] = admin_url
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [BASH, str(DEPLOY)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, log


def read_calls(log: Path) -> list[list[str]]:
    """Decode the fake client's non-secret argument log."""
    if not log.exists():
        return []
    calls: list[list[str]] = []
    current: list[str] = []
    for line in log.read_text().splitlines():
        if line.startswith("CALL="):
            current = []
        elif line.startswith("ARG="):
            current.append(line.removeprefix("ARG="))
        elif line == "END":
            calls.append(current)
    return calls


def expected_calls() -> list[list[str]]:
    """Return the exact authorized client command sequence."""
    return [
        ["sql", "--format=tsv", "--execute", COLLISION_QUERY],
        ["sql", "--execute", "CREATE DATABASE governed_agent_memory"],
        [
            "sql",
            "--database",
            "governed_agent_memory",
            "--file",
            str(ROOT / "schema/init.sql"),
        ],
        [
            "sql",
            "--database",
            "governed_agent_memory",
            "--file",
            str(ROOT / "schema/roles.sql"),
        ],
    ]


def test_deploy_uses_exact_order_and_discloses_no_credentials(tmp_path: Path) -> None:
    completed, log = run_deploy(tmp_path)

    assert completed.returncode == 0
    assert completed.stdout == "crdb-deploy: ok\n"
    assert completed.stderr == ""
    assert read_calls(log) == expected_calls()
    observed = completed.stdout + completed.stderr + log.read_text()
    assert ADMIN_PASSWORD not in observed
    assert ADMIN_USER not in observed
    safe_blocks = log.read_text().split("END")[:-1]
    assert all("URL_DATABASE=defaultdb" in block for block in safe_blocks)


def test_deploy_refuses_existing_target_before_creation(tmp_path: Path) -> None:
    completed, log = run_deploy(tmp_path, collision=1)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert read_calls(log) == expected_calls()[:1]


@pytest.mark.parametrize("fail_call", (1, 2, 3, 4))
def test_deploy_stops_at_first_client_failure(tmp_path: Path, fail_call: int) -> None:
    completed, log = run_deploy(tmp_path, fail_call=fail_call)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert read_calls(log) == expected_calls()[:fail_call]


@pytest.mark.parametrize(
    "admin_url",
    (
        None,
        "",
        database_url("defaultdb", None),
        database_url("defaultdb", "sslmode=require"),
        database_url("defaultdb", "sslmode=verify-full&sslmode=verify-full"),
    ),
)
def test_deploy_rejects_missing_or_noncanonical_tls_binding(
    tmp_path: Path, admin_url: str | None
) -> None:
    completed, log = run_deploy(tmp_path, admin_url=admin_url)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert not log.exists()
