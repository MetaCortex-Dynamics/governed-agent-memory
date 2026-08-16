#!/usr/bin/env python3
"""Verify release inventory and scaffold content contracts."""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

INITIAL_INVENTORY = (
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
)
EXECUTABLES = {"lambda/deploy.sh", "scripts/clean_clone_smoke.sh"}


def resolve_git() -> str:
    """Resolve Git once and fail closed when it is unavailable."""
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable unavailable")
    return executable


GIT_EXECUTABLE = resolve_git()
REQUIRED_REQUIREMENTS = (
    "asyncpg==0.31.0\nopenai==3.1.0\npydantic==2.13.4\nrich==15.0.0\n"
)
REQUIRED_DEV_REQUIREMENTS = (
    "-r requirements.txt\n"
    "bandit==1.9.4\n"
    "mypy==2.3.0\n"
    "pip-audit==2.10.1\n"
    "pytest==9.1.1\n"
    "pytest-asyncio==1.4.0\n"
    "ruff==0.16.0\n"
)
PLACEHOLDERS = {
    "src/__init__.py": '"""Governed Agent Memory scaffold package."""\n',
    "src/agent.py": (
        '"""Agent-loop implementation is unavailable in this scaffold."""\n'
    ),
    "src/ccloud_tool.py": (
        '"""Read-only ccloud adapter is unavailable in this scaffold."""\n'
    ),
    "src/cli.py": '"""Human CLI is unavailable in this scaffold."""\n',
    "src/config.py": '"""Runtime configuration is unavailable in this scaffold."""\n',
    "src/consequences.py": (
        '"""Consequence reporting is unavailable in this scaffold."""\n'
    ),
    "src/embeddings.py": (
        '"""Embedding integration is unavailable in this scaffold."""\n'
    ),
    "src/executor.py": (
        '"""Typed effect execution is unavailable in this scaffold."""\n'
    ),
    "src/governance.py": (
        '"""Governance evaluation is unavailable in this scaffold."""\n'
    ),
    "src/memory.py": '"""Persistent memory is unavailable in this scaffold."""\n',
    "src/models.py": '"""Persisted models are unavailable in this scaffold."""\n',
    "src/operators.py": (
        '"""Sparse operator traces are unavailable in this scaffold."""\n'
    ),
    "src/traces.py": '"""Typed traces are unavailable in this scaffold."""\n',
    "src/verdict.py": '"""Verdict types are unavailable in this scaffold."""\n',
    "src/witnesses.py": '"""Witness gaps are unavailable in this scaffold."""\n',
}

DATABASE_PHASE_PATHS = {
    "schema/roles.sql",
    "scripts/verify_crdb.py",
    "tests/integration/test_schema_live.py",
}
PUBLIC_CONTRACT_PHASE_PATHS = {
    "src/verdict.py",
    "src/operators.py",
    "src/witnesses.py",
    "src/models.py",
    "src/traces.py",
}


def git_inventory(root: Path) -> tuple[str, ...]:
    """Read a strict NUL-delimited tracked inventory."""
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [GIT_EXECUTABLE, "ls-files", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    return tuple(
        sorted(
            raw.decode("utf-8", "strict")
            for raw in completed.stdout.split(b"\0")
            if raw
        )
    )


def git_modes(root: Path) -> dict[str, str]:
    """Read the index mode for each path."""
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [GIT_EXECUTABLE, "ls-files", "--stage", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    modes: dict[str, str] = {}
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        metadata, path_raw = raw.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        path = path_raw.decode("utf-8", "strict")
        modes[path] = mode
    return modes


def verify_inventory(root: Path, initial_exact: bool) -> None:
    """Verify paths, modes, sizes, and regular-file status."""
    inventory = git_inventory(root)
    if initial_exact:
        if inventory != INITIAL_INVENTORY:
            raise ValueError("initial inventory mismatch")
    elif not set(INITIAL_INVENTORY).issubset(inventory):
        raise ValueError("persistent base file missing")
    modes = git_modes(root)
    if set(modes) != set(inventory):
        raise ValueError("mode inventory mismatch")
    safe_path = re.compile(r"^[A-Za-z0-9._/-]+$")
    for relative in inventory:
        path = root / relative
        if (
            not safe_path.fullmatch(relative)
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            raise ValueError("unsafe path")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 1_048_576:
            raise ValueError("invalid tracked file")
        expected_mode = "100755" if relative in EXECUTABLES else "100644"
        if modes[relative] != expected_mode:
            raise ValueError("file mode mismatch")


def _verify_phase(root: Path, *, initial_exact: bool) -> None:
    """Require complete packet phases and reject partial placeholder transitions."""
    if initial_exact:
        for relative, expected in PLACEHOLDERS.items():
            if (root / relative).read_text(encoding="utf-8") != expected:
                raise ValueError("initial placeholder ownership")
        return
    database_phase_present = {
        path for path in DATABASE_PHASE_PATHS if (root / path).is_file()
    }
    if database_phase_present and database_phase_present != DATABASE_PHASE_PATHS:
        raise ValueError("partial database implementation phase")
    if database_phase_present:
        if (root / "src/ccloud_tool.py").read_text(encoding="utf-8") == PLACEHOLDERS[
            "src/ccloud_tool.py"
        ]:
            raise ValueError("ccloud implementation missing")
        if (
            (root / "schema/init.sql")
            .read_text(encoding="utf-8")
            .startswith("-- This scaffold")
        ):
            raise ValueError("schema implementation missing")
    public_contracts_implemented = {
        path
        for path in PUBLIC_CONTRACT_PHASE_PATHS
        if (root / path).read_text(encoding="utf-8") != PLACEHOLDERS[path]
    }
    if (
        public_contracts_implemented
        and public_contracts_implemented != PUBLIC_CONTRACT_PHASE_PATHS
    ):
        raise ValueError("partial public-contract implementation phase")


def verify_content(root: Path, *, initial_exact: bool) -> None:
    """Verify the persistent scaffold contracts."""
    if (root / ".python-version").read_text(encoding="utf-8") != "3.12\n":
        raise ValueError("python version")
    if (root / "requirements.txt").read_text(encoding="utf-8") != REQUIRED_REQUIREMENTS:
        raise ValueError("requirements")
    if (root / "requirements-dev.txt").read_text(
        encoding="utf-8"
    ) != REQUIRED_DEV_REQUIREMENTS:
        raise ValueError("development requirements")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    for dependency in REQUIRED_REQUIREMENTS.splitlines():
        if project.count(f'"{dependency}"') != 1:
            raise ValueError("dependency duplication")
    env_lines = (root / ".env.example").read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in env_lines)
    database_names = {
        "DATABASE_URL",
        "DATABASE_URL_APP",
        "DATABASE_URL_DECIDER",
        "DATABASE_URL_EXECUTOR",
        "DATABASE_URL_SCHEMA_ADMIN",
    }
    present_database_names = database_names.intersection(values)
    if (
        not present_database_names
        or any(values[name] != "" for name in present_database_names)
        or values.get("OPENAI_API_KEY") != ""
    ):
        raise ValueError("sensitive example value")
    boundary = json.loads(
        (root / "config/public-boundary.json").read_text(encoding="utf-8")
    )
    if boundary["trace_mode"] != "sparse" or boundary["verdict_identity"] != {
        "NO": 0,
        "YES": 1,
        "MAYBE": 2,
        "IFF": 3,
    }:
        raise ValueError("boundary configuration")
    if len(boundary["active_operator_families"]) != 10:
        raise ValueError("active family list")
    if len(boundary["inactive_operator_families"]) != 5:
        raise ValueError("inactive family list")
    if len(boundary["witness_gap_types"]) != 7:
        raise ValueError("witness list")
    if "NOT YET AVAILABLE — demonstration not implemented" not in (
        root / "docs/judge-runbook.md"
    ).read_text(encoding="utf-8"):
        raise ValueError("runbook marker")
    if "NOT YET AVAILABLE — submission draft not prepared" not in (
        root / "docs/devpost-draft.md"
    ).read_text(encoding="utf-8"):
        raise ValueError("draft marker")
    _verify_phase(root, initial_exact=initial_exact)


def main(argv: list[str] | None = None) -> int:
    """Run exact-initial or evolving-tree verification."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--initial-exact"]):
        return 2
    try:
        root = Path.cwd().resolve(strict=True)
        verify_inventory(root, arguments == ["--initial-exact"])
        verify_content(root, initial_exact=arguments == ["--initial-exact"])
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"release-inventory failure: {type(error).__name__}", file=sys.stderr)
        return 1
    print("release-inventory: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
