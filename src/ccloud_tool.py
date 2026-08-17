"""Bounded, read-only ccloud evidence adapter."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess  # nosec B404
import time
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn
from uuid import uuid4

import asyncpg  # type: ignore[import-untyped]

from src.models import ToolEvidence

MAX_OUTPUT_BYTES = 65_536
COMMAND_TIMEOUT_SECONDS = 10.0
CLUSTER_NAME = "kingly-dreamer"
REQUIRED_VERSION_FAMILY = "v26.2"
EXPECTED_REGION = "us-east-1"
CCLOUD_COMPAT_VERSION = "v0.6.12"
CCAPI_COMPAT_VERSION = "2023-04-10"
LEGACY_WIRE_PLAN = "SERVERLESS"
SEMANTIC_PLAN = "BASIC"
VERSION_ARTIFACT = Path("schema/crdb-version.json")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REGION = re.compile(r"^[a-z]{2}-[a-z]+-[0-9]$")
EMAIL = re.compile(r"[^\s@]+@[^\s@]+")
NETWORK_ADDRESS = re.compile(
    r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?::[0-9]{1,5})?"
)
CONNECTION_STRING = re.compile(r"(?i)postgres(?:ql)?://[^\s]+")
CREDENTIAL_FIELD = re.compile(
    r"(?i)^(?:access[_-]?key|authorization|credential|password|"
    r"private[_-]?key|secret|session[_-]?key|token)$"
)
CLUSTER_DOCUMENT_FIELDS = frozenset(
    {
        "account_id",
        "cloud_provider",
        "cockroach_version",
        "config",
        "created_at",
        "creator_id",
        "egress_traffic_policy",
        "id",
        "name",
        "network_visibility",
        "operation_status",
        "parent_id",
        "plan",
        "regions",
        "sql_dns",
        "state",
        "updated_at",
        "upgrade_status",
    }
)


class EvidenceBlocked(RuntimeError):
    """Fail-closed, non-sensitive evidence error."""


@dataclass(frozen=True, slots=True)
class ProcessReceipt:
    """Bounded raw process receipt."""

    argv: tuple[str, ...]
    stdout: bytes
    stderr: bytes
    exit_status: int
    raw_output_digest: str


def _blocked(message: str) -> NoReturn:
    raise EvidenceBlocked(message)


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _blocked("duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes) -> Any:
    """Decode strict UTF-8 JSON while rejecting duplicate keys and constants."""

    def reject_constant(_: str) -> NoReturn:
        _blocked("non-finite JSON number")

    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceBlocked("invalid JSON document") from error


def normalize_json(value: Any) -> Any:
    """Normalize the permitted plain-JSON subset."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            _blocked("non-finite JSON number")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                _blocked("non-string JSON key")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                _blocked("normalized JSON key collision")
            normalized[key] = normalize_json(item)
        return normalized
    _blocked("unsupported JSON value")


def canonical_bytes(value: Any) -> bytes:
    """Serialize normalized JSON deterministically."""
    return json.dumps(
        normalize_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    """Hash canonical JSON bytes."""
    return sha256_bytes(canonical_bytes(value))


def _regular_executable(name: str = "ccloud") -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        _blocked("ccloud executable unavailable")
    path = Path(resolved).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        _blocked("ccloud executable is not a canonical regular file")
    return path


def _read_ready(
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    total: int,
) -> int:
    for key, _ in selector.select(timeout=0.05):
        stream = key.fileobj
        chunk = os.read(key.fd, min(8192, MAX_OUTPUT_BYTES + 1 - total))
        if not chunk:
            selector.unregister(stream)
            continue
        buffers[str(key.data)].extend(chunk)
        total += len(chunk)
        if total > MAX_OUTPUT_BYTES:
            _blocked("ccloud output limit exceeded")
    return total


def bounded_process(executable: Path, arguments: Sequence[str]) -> ProcessReceipt:
    """Execute one bounded no-shell ccloud argument vector."""
    argv = (str(executable), *arguments)
    process = subprocess.Popen(  # noqa: S603  # nosec B603
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        shell=False,
        close_fds=True,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        _blocked("ccloud pipe allocation failed")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        total = 0
        while selector.get_map():
            if time.monotonic() >= deadline:
                process.kill()
                process.wait()
                _blocked("ccloud command timed out")
            total = _read_ready(selector, buffers, total)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.wait()
            _blocked("ccloud command timed out")
        status = process.wait(timeout=remaining)
    except EvidenceBlocked:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
    stdout = bytes(buffers["stdout"])
    stderr = bytes(buffers["stderr"])
    framed = b"stdout\0" + stdout + b"\0stderr\0" + stderr
    receipt = ProcessReceipt(argv, stdout, stderr, status, sha256_bytes(framed))
    if status != 0:
        _blocked("ccloud command returned nonzero")
    return receipt


def _complete_text(receipt: ProcessReceipt) -> str:
    try:
        return (receipt.stdout + receipt.stderr).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise EvidenceBlocked("ccloud output is not UTF-8") from error


def _version(text: str) -> str:
    match = re.search(r"(?<![0-9])v?(\d+\.\d+\.\d+)(?![0-9])", text)
    if match is None:
        _blocked("ccloud version is ambiguous")
    return f"v{match.group(1)}"


CCLOUD_OUTPUT_HELP = re.compile(
    r"^[ \t]*(?:-o,[ \t]+)?--output[ \t]+string[ \t]+"
    r"output format[ \t]+\[standard\|json\]"
    r'(?:[ \t]+\(default "standard"\))?[ \t]*$'
)
CCLOUD_OUTPUT_OPTION = re.compile(r"(?<![A-Za-z0-9_-])--output(?:[= \t]|$)")
CCLOUD_COMPETING_JSON_OPTION = re.compile(
    r"(?<![A-Za-z0-9_-])(?:--format(?:[= \t]|$)|--json(?![A-Za-z0-9_-]))"
)


def _canonical_json_flag(help_text: str) -> str:
    """Bind the one approved ccloud JSON mechanism from canonical help."""
    output_lines = [
        line for line in help_text.splitlines() if CCLOUD_OUTPUT_OPTION.search(line)
    ]
    competing = [
        line
        for line in help_text.splitlines()
        if CCLOUD_COMPETING_JSON_OPTION.search(line)
    ]
    if (
        len(output_lines) != 1
        or CCLOUD_OUTPUT_HELP.fullmatch(output_lines[0]) is None
        or competing
    ):
        _blocked("exactly one canonical ccloud JSON output option is required")
    return "--output=json"


def discover_preflight() -> dict[str, str]:
    """Bind the installed ccloud executable, version, help, and JSON flag."""
    executable = _regular_executable()
    executable_digest = sha256_bytes(executable.read_bytes())
    version_receipt = bounded_process(executable, ("version",))
    help_receipt = bounded_process(executable, ("cluster", "info", "--help"))
    version_text = _complete_text(version_receipt)
    help_text = _complete_text(help_receipt)
    json_flag = _canonical_json_flag(help_text)
    return {
        "ccloud_executable": str(executable),
        "ccloud_executable_sha256": executable_digest,
        "ccloud_version": _version(version_text),
        "ccloud_version_raw_digest": sha256_bytes(
            version_receipt.stdout + version_receipt.stderr
        ),
        "ccloud_help_digest": sha256_bytes(help_receipt.stdout + help_receipt.stderr),
        "ccloud_json_flag": json_flag,
    }


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        _blocked(f"required environment binding absent: {name}")
    return value


def load_version_artifact(path: Path = VERSION_ARTIFACT) -> dict[str, Any]:
    """Load and verify the complete preflight artifact."""
    value = strict_json(path.read_bytes())
    if not isinstance(value, dict):
        _blocked("version artifact is not an object")
    capture = value.get("capture_digest")
    if not isinstance(capture, str) or not HEX_64.fullmatch(capture):
        _blocked("version artifact capture digest is invalid")
    payload = dict(value)
    del payload["capture_digest"]
    if canonical_digest(payload) != capture:
        _blocked("version artifact capture digest mismatch")
    return value


def _region_names(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        _blocked("cluster regions are invalid")
    names: list[str] = []
    for item in value:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            name = item["name"]
        else:
            _blocked("cluster region entry is invalid")
        if not isinstance(name, str) or not REGION.fullmatch(name):
            _blocked("cluster region name is invalid")
        names.append(name)
    if names != sorted(set(names)):
        _blocked("cluster regions are not sorted and unique")
    return names


def _field(document: Mapping[str, Any], *names: str) -> Any:
    present = [name for name in names if name in document]
    if len(present) != 1:
        _blocked("cluster document field is missing or ambiguous")
    return document[present[0]]


def normalize_cluster_document(
    raw: bytes,
    *,
    ccloud_version: str,
    ccapi_version: str,
) -> tuple[dict[str, Any], list[str]]:
    """Reduce ccloud output to the exact non-sensitive closure document."""
    value = strict_json(raw)
    if isinstance(value, list):
        if len(value) != 1 or not isinstance(value[0], dict):
            _blocked("cluster output array is not exactly one object")
        document = value[0]
    elif isinstance(value, dict):
        document = value
    else:
        _blocked("cluster output envelope is invalid")
    if set(document) != CLUSTER_DOCUMENT_FIELDS:
        _blocked("cluster output fields differ from the bound ccloud shape")
    raw_id = _field(document, "id")
    name = _field(document, "name")
    version = _field(document, "cockroach_version")
    state = _field(document, "state")
    wire_plan = _field(document, "plan")
    cloud = _field(document, "cloud_provider")
    regions = _region_names(_field(document, "regions"))
    scalar_values = (raw_id, name, version, state, wire_plan, cloud)
    if not all(isinstance(item, str) for item in scalar_values):
        _blocked("cluster output field type is invalid")
    version_normalized = _version(str(version))
    semantic_plan = normalize_legacy_plan(
        str(wire_plan),
        ccloud_version=ccloud_version,
        ccapi_version=ccapi_version,
    )
    normalized = {
        "name": name,
        "cluster_id_digest": sha256_bytes(str(raw_id).encode()),
        "cockroach_version": version_normalized,
        "state": state,
        "wire_plan": wire_plan,
        "plan": semantic_plan,
        "cloud": cloud,
        "regions": regions,
    }
    manifest = ["cluster_id"]
    return normalized, manifest


def normalize_legacy_plan(
    wire_plan: str,
    *,
    ccloud_version: str,
    ccapi_version: str,
) -> str:
    """Normalize only the explicitly bound legacy Serverless wire value."""
    if wire_plan == SEMANTIC_PLAN:
        return SEMANTIC_PLAN
    if (
        wire_plan == LEGACY_WIRE_PLAN
        and ccloud_version == CCLOUD_COMPAT_VERSION
        and ccapi_version == CCAPI_COMPAT_VERSION
    ):
        return SEMANTIC_PLAN
    _blocked("ccloud plan compatibility binding mismatch")


def _validate_target(document: Mapping[str, Any], artifact: Mapping[str, Any]) -> None:
    expected = {
        "name": CLUSTER_NAME,
        "cluster_id_digest": artifact["expected_cluster_id_digest"],
        "cockroach_version": artifact["observed_cockroach_version"],
        "state": "CREATED",
        "wire_plan": artifact["target_wire_plan"],
        "plan": artifact["target_plan"],
        "cloud": "AWS",
        "regions": [EXPECTED_REGION],
    }
    if document != expected:
        _blocked("ccloud target binding mismatch")
    version = str(document["cockroach_version"])
    if not version.startswith(f"{artifact['required_version_family']}."):
        _blocked("ccloud target version family mismatch")
    semantic_plan = normalize_legacy_plan(
        str(document["wire_plan"]),
        ccloud_version=str(artifact["ccloud_version"]),
        ccapi_version=str(artifact["ccapi_version"]),
    )
    if semantic_plan != artifact["target_plan"]:
        _blocked("ccloud target semantic plan mismatch")


def _redaction_guard(value: Any) -> None:
    text = canonical_bytes(value).decode("utf-8")
    if (
        CONNECTION_STRING.search(text)
        or EMAIL.search(text)
        or NETWORK_ADDRESS.search(text)
    ):
        _blocked("sensitive ccloud output survived normalization")
    if isinstance(value, dict):
        for key, item in value.items():
            if CREDENTIAL_FIELD.fullmatch(key):
                _blocked("credential field survived normalization")
            _redaction_guard(item)
    elif isinstance(value, list):
        for item in value:
            _redaction_guard(item)


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def _persist(evidence: Mapping[str, Any]) -> None:
    url = _required_environment("DATABASE_URL_APP")
    if "sslmode=verify-full" not in url:
        _blocked("application database URL must use sslmode=verify-full")
    connection = await asyncpg.connect(dsn=url)
    try:
        row = await connection.fetchrow(
            """
            INSERT INTO tool_evidence (
                id, tool_name, tool_version, redacted_command_argv,
                command_digest, help_digest, config_digest, cluster_name,
                cluster_name_digest, observed_cluster_id_digest,
                observed_version, observed_state, observed_plan, observed_cloud,
                normalized_redacted_output, redaction_manifest,
                raw_output_digest, normalized_output_digest, exit_status,
                captured_at, expires_at, captured_by, evidence_digest,
                idempotency_key
            ) VALUES (
                $1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15::jsonb, $16::jsonb, $17, $18, $19, $20, $21,
                $22, $23, $24
            )
            ON CONFLICT (idempotency_key) DO NOTHING
            RETURNING evidence_digest
            """,
            *evidence.values(),
        )
        if row is None:
            row = await connection.fetchrow(
                "SELECT evidence_digest FROM tool_evidence WHERE idempotency_key=$1",
                evidence["idempotency_key"],
            )
        if row is None or row["evidence_digest"] != evidence["evidence_digest"]:
            _blocked("tool evidence read-back mismatch")
    finally:
        await connection.close()


def build_capture(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Capture, normalize, bind, and prepare one closure evidence row."""
    if _required_environment("CCLOUD_CLUSTER_NAME") != CLUSTER_NAME:
        _blocked("cluster name binding mismatch")
    profile = _required_environment("CCLOUD_AUTH_PROFILE")
    expected_id = _required_environment("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST")
    receipt_digest = _required_environment("CCLOUD_PROVISIONING_RECEIPT_DIGEST")
    if sha256_bytes(profile.encode()) != artifact["ccloud_auth_profile_digest"]:
        _blocked("ccloud profile binding mismatch")
    if expected_id != artifact["expected_cluster_id_digest"]:
        _blocked("cluster ID binding mismatch")
    if receipt_digest != artifact["provisioning_receipt_digest"]:
        _blocked("provisioning receipt binding mismatch")
    executable = Path(str(artifact["ccloud_executable"])).resolve(strict=True)
    if sha256_bytes(executable.read_bytes()) != artifact["ccloud_executable_sha256"]:
        _blocked("ccloud executable changed after preflight")
    flag = artifact["ccloud_json_flag"]
    if flag not in ("--output=json", "--format=json", "--json"):
        _blocked("unbound ccloud JSON flag")
    arguments = ("cluster", "info", CLUSTER_NAME, str(flag))
    receipt = bounded_process(executable, arguments)
    normalized, redactions = normalize_cluster_document(
        receipt.stdout,
        ccloud_version=str(artifact["ccloud_version"]),
        ccapi_version=str(artifact["ccapi_version"]),
    )
    _validate_target(normalized, artifact)
    _redaction_guard(normalized)
    captured = datetime.now(UTC)
    expires = captured + timedelta(minutes=15)
    argv = ["ccloud", *arguments]
    evidence_payload = {
        "schema": "gam.tool-evidence.v1",
        "tool_name": "ccloud",
        "tool_version": artifact["ccloud_version"],
        "redacted_command_argv": argv,
        "command_digest": canonical_digest(argv),
        "help_digest": artifact["ccloud_help_digest"],
        "config_digest": artifact["ccloud_config_digest"],
        "cluster_name": CLUSTER_NAME,
        "cluster_name_digest": sha256_bytes(CLUSTER_NAME.encode()),
        "observed_cluster_id_digest": normalized["cluster_id_digest"],
        "observed_version": normalized["cockroach_version"],
        "observed_state": normalized["state"],
        "observed_plan": normalized["plan"],
        "observed_cloud": normalized["cloud"],
        "normalized_redacted_output": normalized,
        "redaction_manifest": redactions,
        "raw_output_digest": receipt.raw_output_digest,
        "normalized_output_digest": canonical_digest(normalized),
        "exit_status": receipt.exit_status,
        "captured_at": _utc(captured),
        "expires_at": _utc(expires),
        "captured_by": "ccloud-evidence-adapter",
        "idempotency_key": f"ccloud-{uuid4()}",
    }
    digest_payload = dict(evidence_payload)
    digest_payload.pop("schema")
    evidence_payload["evidence_digest"] = canonical_digest(
        {"schema": "gam.tool-evidence.v1", **digest_payload}
    )
    return evidence_payload


def _tool_evidence(payload: Mapping[str, Any], evidence_id: str) -> ToolEvidence:
    """Convert one already-redacted capture into the frozen memory contract."""
    return ToolEvidence(
        evidence_id=evidence_id,
        tool_name=str(payload["tool_name"]),
        tool_version=str(payload["tool_version"]),
        redacted_command_argv_json=canonical_bytes(
            payload["redacted_command_argv"]
        ).decode(),
        command_digest=str(payload["command_digest"]),
        help_digest=str(payload["help_digest"]),
        config_digest=str(payload["config_digest"]),
        cluster_name=str(payload["cluster_name"]),
        cluster_name_digest=str(payload["cluster_name_digest"]),
        observed_cluster_id_digest=str(payload["observed_cluster_id_digest"]),
        observed_version=str(payload["observed_version"]),
        observed_state=str(payload["observed_state"]),
        observed_plan=str(payload["observed_plan"]),
        observed_cloud=str(payload["observed_cloud"]),
        normalized_redacted_output_json=canonical_bytes(
            payload["normalized_redacted_output"]
        ).decode(),
        redaction_manifest_json=canonical_bytes(payload["redaction_manifest"]).decode(),
        raw_output_digest=str(payload["raw_output_digest"]),
        normalized_output_digest=str(payload["normalized_output_digest"]),
        exit_status=int(payload["exit_status"]),
        captured_at=str(payload["captured_at"]),
        expires_at=str(payload["expires_at"]),
        captured_by=str(payload["captured_by"]),
        evidence_digest=str(payload["evidence_digest"]),
        idempotency_key=str(payload["idempotency_key"]),
    )


async def capture(*, purpose: str) -> ToolEvidence:
    """Run exactly one closure-bound read-only capture for the runtime agent."""
    if purpose != "runtime":
        _blocked("ccloud capture purpose is not permitted")
    artifact = load_version_artifact()
    payload = await asyncio.to_thread(build_capture, artifact)
    return _tool_evidence(payload, str(uuid4()))


async def capture_closure() -> dict[str, Any]:
    """Run and persist the exact closure-purpose capture."""
    artifact = load_version_artifact()
    payload = build_capture(artifact)
    ordered = {
        "id": uuid4(),
        "tool_name": payload["tool_name"],
        "tool_version": payload["tool_version"],
        "redacted_command_argv": canonical_bytes(
            payload["redacted_command_argv"]
        ).decode(),
        "command_digest": payload["command_digest"],
        "help_digest": payload["help_digest"],
        "config_digest": payload["config_digest"],
        "cluster_name": payload["cluster_name"],
        "cluster_name_digest": payload["cluster_name_digest"],
        "observed_cluster_id_digest": payload["observed_cluster_id_digest"],
        "observed_version": payload["observed_version"],
        "observed_state": payload["observed_state"],
        "observed_plan": payload["observed_plan"],
        "observed_cloud": payload["observed_cloud"],
        "normalized_redacted_output": canonical_bytes(
            payload["normalized_redacted_output"]
        ).decode(),
        "redaction_manifest": canonical_bytes(payload["redaction_manifest"]).decode(),
        "raw_output_digest": payload["raw_output_digest"],
        "normalized_output_digest": payload["normalized_output_digest"],
        "exit_status": payload["exit_status"],
        "captured_at": datetime.strptime(
            payload["captured_at"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC),
        "expires_at": datetime.strptime(
            payload["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC),
        "captured_by": payload["captured_by"],
        "evidence_digest": payload["evidence_digest"],
        "idempotency_key": payload["idempotency_key"],
    }
    await _persist(ordered)
    return payload


def main(argv: list[str] | None = None) -> int:
    """Run the closure-purpose command-line adapter."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--purpose", choices=("closure",), required=True)
    arguments = parser.parse_args(argv)
    if arguments.command != "capture" or arguments.purpose != "closure":
        return 2
    try:
        payload = asyncio.run(capture_closure())
    except (EvidenceBlocked, OSError, asyncpg.PostgresError):
        print("ccloud evidence: BLOCKED")
        return 1
    print(
        json.dumps(
            {
                "evidence_digest": payload["evidence_digest"],
                "result": "ok",
                "schema": "gam.ccloud-closure.v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
