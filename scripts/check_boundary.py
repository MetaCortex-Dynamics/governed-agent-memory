#!/usr/bin/env python3
"""Validate the repository's bounded public vocabulary."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess  # nosec B404
import sys
import unicodedata
from pathlib import Path

DIGEST_FILE = Path("security/forbidden-public-terms.txt")
BOUNDARY_FILE = Path("config/public-boundary.json")
SOURCES_FILE = Path("config/theory-sources.json")
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}


def resolve_git() -> str:
    """Resolve Git once and fail closed when it is unavailable."""
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable unavailable")
    return executable


GIT_EXECUTABLE = resolve_git()

EXPECTED_BOUNDARY: dict[str, object] = {
    "schema_version": 1,
    "trace_mode": "sparse",
    "active_operator_families": [
        "THIS",
        "SAME/NOT-SAME",
        "IF/THEN",
        "BECAUSE",
        "INSIDE/OUTSIDE",
        "NEAR/FAR",
        "CAN/CANNOT",
        "TOGETHER/ALONE",
        "MORE/LESS",
        "EVERY/SOME",
    ],
    "inactive_operator_families": [
        "GOES-WITH",
        "MANY/ONE",
        "NO",
        "MAYBE",
        "MUST/LET",
    ],
    "witness_gap_types": [
        "WHAT",
        "WHERE",
        "WHICH",
        "WHEN",
        "FOR-WHAT",
        "HOW",
        "WHENCE",
    ],
    "verdict_identity": {"NO": 0, "YES": 1, "MAYBE": 2, "IFF": 3},
}

EXPECTED_SOURCES: dict[str, object] = {
    "schema_version": 1,
    "use": "citation-and-independent-implementation-only",
    "sources": [
        {
            "role": "verdict tokens and ordering",
            "title": "Your Loop Has Two States. It Needs Four.",
            "author": "Devon Generally / MetaCortex Dynamics",
            "date": "2026-07-09",
            "url": (
                "https://metacortexdynamics.substack.com/p/"
                "your-loop-has-two-states-it-needs"
            ),
            "license": "citation-only unless separately granted",
        },
        {
            "role": "fifteen public operator-family names",
            "title": (
                "The Operator Completeness Theorem: The 15 Invariant Operators "
                "as Constitutive Conditions of Projection"
            ),
            "author": "Devon A. Generally",
            "date": "2026-05-25",
            "doi": "10.5281/zenodo.20370848",
            "license": "CC BY-NC-ND 4.0",
        },
        {
            "role": "pre-numeric thesis",
            "title": "Operators, Not Numbers: 0 and 1 as Pre-Numeric Structure",
            "author": "Devon A. Generally",
            "date": "2026-07-22",
            "doi": "10.5281/zenodo.21499659",
            "license": "CC BY 4.0",
        },
        {
            "role": "seven witness names",
            "title": (
                "The Universal Interrogative Theorem: The Constitutive Grammar "
                "of Appearing-Being"
            ),
            "author": "Devon A. Generally",
            "date": "2026-07-21",
            "doi": "10.5281/zenodo.21465420",
            "license": "CC BY-ND 4.0",
        },
    ],
}


def parse_denylist(text: str) -> tuple[tuple[int, str], ...]:
    """Parse strict length/digest records."""
    records: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) != 2 or not fields[0].isdigit():
            raise ValueError("malformed denylist record")
        length = int(fields[0])
        digest = fields[1]
        if (
            length <= 0
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("malformed denylist record")
        record = (length, digest)
        if record in seen:
            raise ValueError("duplicate denylist record")
        seen.add(record)
        records.append(record)
    if not records:
        raise ValueError("empty denylist")
    return tuple(records)


def normalize_text(text: str) -> str:
    """Apply the canonical scan normalization."""
    return " ".join(unicodedata.normalize("NFC", text).casefold().split())


def matching_digest(text: str, records: tuple[tuple[int, str], ...]) -> str | None:
    """Return only a matched digest, never matched source text."""
    normalized = normalize_text(text)
    by_length: dict[int, set[str]] = {}
    for length, digest in records:
        by_length.setdefault(length, set()).add(digest)
    for length, digests in by_length.items():
        if length > len(normalized):
            continue
        for offset in range(len(normalized) - length + 1):
            candidate = normalized[offset : offset + length].encode()
            observed = hashlib.sha256(candidate).hexdigest()
            if observed in digests:
                return observed
    return None


def tracked_paths(root: Path) -> tuple[Path, ...]:
    """Return tracked paths, or safe regular candidates before Git exists."""
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [GIT_EXECUTABLE, "ls-files", "-z"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode == 0:
        names = [name for name in completed.stdout.split(b"\0") if name]
        return tuple(root / name.decode("utf-8", "strict") for name in names)
    return tuple(path for path in root.rglob("*") if path.is_file())


def validate_configuration(root: Path) -> None:
    """Validate the exact public configurations."""
    boundary = json.loads((root / BOUNDARY_FILE).read_text(encoding="utf-8"))
    sources = json.loads((root / SOURCES_FILE).read_text(encoding="utf-8"))
    if boundary != EXPECTED_BOUNDARY or sources != EXPECTED_SOURCES:
        raise ValueError("public configuration mismatch")
    unrelated = "10.5281/zenodo." + "20318684"
    for path in tracked_paths(root):
        if path == root / DIGEST_FILE or any(
            part in EXCLUDED_PARTS for part in path.parts
        ):
            continue
        if unrelated in path.read_text(encoding="utf-8", errors="strict"):
            raise ValueError("unrelated source identifier")


def check_root(root: Path) -> None:
    """Fail closed on any public-boundary violation."""
    root = root.resolve(strict=True)
    records = parse_denylist((root / DIGEST_FILE).read_text(encoding="utf-8"))
    validate_configuration(root)
    for path in tracked_paths(root):
        relative = path.relative_to(root)
        if relative == DIGEST_FILE or any(
            part in EXCLUDED_PARTS for part in relative.parts
        ):
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError("non-regular tracked path")
        text = path.read_text(encoding="utf-8", errors="strict")
        if matching_digest(text, records) is not None:
            raise ValueError(f"public boundary digest match: {relative}")


def main(argv: list[str] | None = None) -> int:
    """Run the boundary validation."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) > 1:
        return 2
    root = Path(arguments[0]) if arguments else Path.cwd()
    try:
        check_root(root)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"boundary failure: {type(error).__name__}", file=sys.stderr)
        return 1
    print("boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
