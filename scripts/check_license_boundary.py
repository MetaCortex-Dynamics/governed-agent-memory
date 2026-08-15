#!/usr/bin/env python3
"""Validate the source-license boundary."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess  # nosec B404
from pathlib import Path

LICENSE_DIGEST = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
FORBIDDEN_SUFFIXES = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".zip", ".tar", ".gz"}


def resolve_git() -> str:
    """Resolve Git once and fail closed when it is unavailable."""
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable unavailable")
    return executable


GIT_EXECUTABLE = resolve_git()


def tracked_paths(root: Path) -> tuple[Path, ...]:
    """Return every tracked path."""
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


def check(root: Path) -> None:
    """Fail unless licensing and attribution are exact."""
    if hashlib.sha256((root / "LICENSE").read_bytes()).hexdigest() != LICENSE_DIGEST:
        raise ValueError("license digest")
    notice = (root / "NOTICE").read_text(encoding="utf-8", errors="strict")
    readme = (root / "README.md").read_text(encoding="utf-8", errors="strict")
    sources = json.loads(
        (root / "config/theory-sources.json").read_text(encoding="utf-8")
    )
    if "Cited external publications retain their stated licenses" not in notice:
        raise ValueError("notice boundary")
    disclosure = (
        "All submitted source code was written during the submission period. The\n"
        "> project applies concepts from the cited prior publications. No pre-"
        "existing\n"
        "> source code or protected implementation was incorporated."
    )
    if disclosure not in readme:
        raise ValueError("original-work disclosure")
    expected_roles = [
        ("verdict tokens and ordering", "citation-only unless separately granted"),
        ("fifteen public operator-family names", "CC BY-NC-ND 4.0"),
        ("pre-numeric thesis", "CC BY 4.0"),
        ("seven witness names", "CC BY-ND 4.0"),
    ]
    observed = [(item["role"], item["license"]) for item in sources["sources"]]
    if observed != expected_roles:
        raise ValueError("source matrix")
    unrelated = "10.5281/zenodo." + "20318684"
    for path in tracked_paths(root):
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            raise ValueError("deposited or archive file")
        text = path.read_text(encoding="utf-8", errors="strict")
        if unrelated in text:
            raise ValueError("unrelated source")
        lowered = text.casefold()
        prohibited_claim = "external publications are licensed under " + "apache-2.0"
        if prohibited_claim in lowered:
            raise ValueError("relicensing claim")


def main() -> int:
    """Run the license-boundary validation."""
    try:
        check(Path.cwd().resolve(strict=True))
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        print(f"license-boundary failure: {type(error).__name__}")
        return 1
    print("license-boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
