"""Scaffold contract tests."""

from __future__ import annotations

import hashlib
import importlib
import json
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
main = cast(Callable[[], int], importlib.import_module("src.__main__").main)
BOUNDARY_NAMESPACE = runpy.run_path(str(ROOT / "scripts/check_boundary.py"))
EXPECTED_BOUNDARY_CONFIG = cast(
    dict[str, object], BOUNDARY_NAMESPACE["EXPECTED_BOUNDARY"]
)
EXPECTED_SOURCE_CONFIG = cast(dict[str, object], BOUNDARY_NAMESPACE["EXPECTED_SOURCES"])
PARSE_DENYLIST = cast(
    Callable[[str], tuple[tuple[int, str], ...]],
    BOUNDARY_NAMESPACE["parse_denylist"],
)
MATCHING_DIGEST = cast(
    Callable[[str, tuple[tuple[int, str], ...]], str | None],
    BOUNDARY_NAMESPACE["matching_digest"],
)
EXPECTED_PATHS = {
    ".env.example",
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".gitignore",
    ".python-version",
    "LICENSE",
    "NOTICE",
    "README.md",
    "config/public-boundary.json",
    "config/theory-sources.json",
    "docs/architecture.md",
    "docs/devpost-draft.md",
    "docs/judge-runbook.md",
    "docs/theory-sources.md",
    "examples/.gitkeep",
    "lambda/deploy.sh",
    "lambda/handler.py",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
    "schema/init.sql",
    "scripts/check_boundary.py",
    "scripts/check_license_boundary.py",
    "scripts/check_secrets.py",
    "scripts/clean_clone_smoke.sh",
    "scripts/verify_release.py",
    "security/forbidden-public-terms.txt",
    "src/__init__.py",
    "src/__main__.py",
    "src/agent.py",
    "src/ccloud_tool.py",
    "src/cli.py",
    "src/config.py",
    "src/consequences.py",
    "src/embeddings.py",
    "src/executor.py",
    "src/governance.py",
    "src/memory.py",
    "src/models.py",
    "src/operators.py",
    "src/traces.py",
    "src/verdict.py",
    "src/witnesses.py",
    "tests/integration/.gitkeep",
    "tests/live/.gitkeep",
    "tests/test_skeleton.py",
    "tests/unit/.gitkeep",
}


def test_entry_point(capsys: pytest.CaptureFixture[str]) -> None:
    """The scaffold command reports only scaffold state."""
    assert main() == 0
    assert capsys.readouterr().out == "governed-agent-memory: scaffold only\n"


def test_lambda_refuses() -> None:
    """The scaffold Lambda cannot claim an implementation."""
    handler = importlib.import_module("lambda.handler")
    with pytest.raises(
        RuntimeError, match="^AWS Lambda is not implemented in this scaffold$"
    ):
        handler.lambda_handler({}, None)


def test_configuration_contracts() -> None:
    """Public configuration has exact cardinality and identities."""
    boundary = json.loads((ROOT / "config/public-boundary.json").read_text())
    sources = json.loads((ROOT / "config/theory-sources.json").read_text())
    assert boundary == EXPECTED_BOUNDARY_CONFIG
    assert sources == EXPECTED_SOURCE_CONFIG
    assert [item["role"] for item in sources["sources"]] == [
        "verdict tokens and ordering",
        "fifteen public operator-family names",
        "pre-numeric thesis",
        "seven witness names",
    ]


def test_placeholder_modules_import() -> None:
    """Public modules import without environment or network access in every phase."""
    names = [
        "agent",
        "ccloud_tool",
        "cli",
        "config",
        "consequences",
        "embeddings",
        "executor",
        "governance",
        "memory",
        "models",
        "operators",
        "traces",
        "verdict",
        "witnesses",
    ]
    for name in names:
        importlib.import_module(f"src.{name}")


def test_environment_example_is_blank_at_sensitive_fields() -> None:
    """Examples contain no credentials or credential-bearing URL."""
    text = (ROOT / ".env.example").read_text()
    values = dict(line.split("=", 1) for line in text.splitlines())
    database_names = {
        "DATABASE_URL",
        "DATABASE_URL_APP",
        "DATABASE_URL_DECIDER",
        "DATABASE_URL_EXECUTOR",
        "DATABASE_URL_SCHEMA_ADMIN",
    }
    present = database_names.intersection(values)
    assert present
    assert all(values[name] == "" for name in present)
    assert values["OPENAI_API_KEY"] == ""
    assert "://" not in text


def test_expected_paths_exist() -> None:
    """Every terminal path exists before the initial commit."""
    assert all((ROOT / path).is_file() for path in EXPECTED_PATHS)


@pytest.mark.parametrize(
    "text",
    [
        "0 " + "0" * 64,
        "1 " + "G" * 64,
        "1 " + "0" * 63,
        "1 " + "0" * 64 + " extra",
        "1 " + "0" * 64 + "\n1 " + "0" * 64,
        "",
    ],
)
def test_denylist_parser_fails_closed(text: str) -> None:
    """Malformed records are never accepted."""
    with pytest.raises(ValueError):
        PARSE_DENYLIST(text)


def test_synthetic_boundary_match() -> None:
    """A synthetic digest matches only its exact normalized source."""
    term = "synthetic-boundary-sentinel"
    digest = hashlib.sha256(term.encode()).hexdigest()
    records = ((len(term), digest),)
    assert MATCHING_DIGEST(term, records) == digest
    assert MATCHING_DIGEST(term + "-adjacent", records) == digest
    assert MATCHING_DIGEST("different-safe-text", records) is None


def test_boundary_checker_success() -> None:
    """The tracked scaffold passes its own boundary check."""
    completed = subprocess.run(
        [sys.executable, "scripts/check_boundary.py", "."],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    assert completed.stdout == "boundary: ok\n"
    assert completed.stderr == ""
