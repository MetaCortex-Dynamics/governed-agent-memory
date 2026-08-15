#!/usr/bin/env python3
"""Scan tracked worktree or Git history without disclosing findings."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path


def resolve_git() -> str:
    """Resolve Git once and fail closed when it is unavailable."""
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable unavailable")
    return executable


GIT_EXECUTABLE = resolve_git()


def scan_rules() -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Construct high-confidence rules without self-matching source literals."""
    return (
        (
            "private-key-header",
            re.compile("-----BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ),
        (
            "database-url-credentials",
            re.compile("postgres(?:ql)?://[^\\s/:]+:[^\\s/@]+@", re.I),
        ),
        ("github-token-shape", re.compile("gh" + "[pousr]_[A-Za-z0-9_]{20,}")),
        ("openai-key-shape", re.compile("sk" + "-(?:proj-)?[A-Za-z0-9_-]{20,}")),
        ("aws-access-key-shape", re.compile("AK" + "IA[0-9A-Z]{16}")),
        ("bearer-token", re.compile("Bearer" + r"\s+[A-Za-z0-9._~+/-]{20,}=*", re.I)),
        (
            "generic-secret-assignment",
            re.compile(
                r"(?i)\b(?:password|token|secret|api[_-]?key)\b\s*[:=]\s*"
                r"['\"]?([^\s'\"#]{8,})"
            ),
        ),
    )


def scan_text(identity: str, text: str) -> bool:
    """Report identity and rule only."""
    for rule_name, pattern in scan_rules():
        if pattern.search(text):
            print(f"secret finding: {identity}: {rule_name}", file=sys.stderr)
            return False
    return True


def tracked_files(root: Path) -> tuple[Path, ...]:
    """Resolve tracked files using a NUL-delimited Git query."""
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [GIT_EXECUTABLE, "ls-files", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    return tuple(
        root / raw.decode("utf-8", "strict")
        for raw in completed.stdout.split(b"\0")
        if raw
    )


def scan_worktree(root: Path) -> bool:
    """Scan all tracked regular UTF-8 files."""
    passed = True
    for path in tracked_files(root):
        relative = str(path.relative_to(root))
        if relative == "scripts/check_secrets.py":
            continue
        if not path.is_file() or path.is_symlink():
            print(f"secret scan path failure: {relative}", file=sys.stderr)
            passed = False
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeError:
            print(f"secret scan decode failure: {relative}", file=sys.stderr)
            passed = False
            continue
        passed = scan_text(relative, text) and passed
    return passed


def scan_history(root: Path) -> bool:
    """Scan the complete textual patch history."""
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [GIT_EXECUTABLE, "log", "-p", "--all", "--no-ext-diff", "--no-color"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    try:
        history = completed.stdout.decode("utf-8", "strict")
    except UnicodeError:
        print("secret scan decode failure: history", file=sys.stderr)
        return False
    filtered: list[str] = []
    skip = False
    for line in history.splitlines():
        if line.startswith("diff --git "):
            skip = line.endswith(" b/scripts/check_secrets.py")
        if not skip:
            filtered.append(line)
    return scan_text("history", "\n".join(filtered))


def main(argv: list[str] | None = None) -> int:
    """Run exactly one scan mode."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in (["--worktree"], ["--history"]):
        return 2
    root = Path.cwd().resolve(strict=True)
    try:
        passed = (
            scan_worktree(root) if arguments == ["--worktree"] else scan_history(root)
        )
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        print(f"secret scan failure: {type(error).__name__}", file=sys.stderr)
        return 1
    if not passed:
        return 1
    print("secrets: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
