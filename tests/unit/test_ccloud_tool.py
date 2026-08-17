"""Unit tests for deterministic ccloud discovery and target normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src import ccloud_tool
from src.ccloud_tool import EvidenceBlocked, ProcessReceipt

OFFICIAL_HELP = (
    "Usage: ccloud cluster info [name]\n\n"
    "Flags:\n"
    '  -o, --output string   output format [standard|json] (default "standard")\n'
)
SYNTHETIC_CLUSTER_ID = "synthetic-cluster-identifier"
SYNTHETIC_CLUSTER_DIGEST = ccloud_tool.sha256_bytes(SYNTHETIC_CLUSTER_ID.encode())


def observed_record(**changes: Any) -> dict[str, Any]:
    """Return a wholly synthetic fixture with the observed official key shape."""
    value: dict[str, Any] = {
        "account_id": "synthetic-account",
        "cloud_provider": "AWS",
        "cockroach_version": "v26.2.5",
        "config": {},
        "created_at": "2000-01-01T00:00:00Z",
        "creator_id": "synthetic-creator",
        "egress_traffic_policy": "ALLOW_ALL",
        "id": SYNTHETIC_CLUSTER_ID,
        "name": "kingly-dreamer",
        "network_visibility": "PUBLIC",
        "operation_status": "COMPLETED",
        "parent_id": "synthetic-parent",
        "plan": "SERVERLESS",
        "regions": [{"name": "us-east-1", "synthetic_extra": "ignored"}],
        "sql_dns": "synthetic.invalid",
        "state": "CREATED",
        "updated_at": "2000-01-01T00:00:00Z",
        "upgrade_status": "FINALIZED",
    }
    value.update(changes)
    return value


def normalize(value: object) -> dict[str, Any]:
    normalized, _ = ccloud_tool.normalize_cluster_document(
        ccloud_tool.canonical_bytes(value),
        ccloud_version=ccloud_tool.CCLOUD_COMPAT_VERSION,
        ccapi_version=ccloud_tool.CCAPI_COMPAT_VERSION,
    )
    return normalized


def target_artifact(executable: Path, profile: str) -> dict[str, Any]:
    return {
        "ccloud_executable": str(executable),
        "ccloud_executable_sha256": ccloud_tool.sha256_bytes(executable.read_bytes()),
        "ccloud_version": ccloud_tool.CCLOUD_COMPAT_VERSION,
        "ccapi_version": ccloud_tool.CCAPI_COMPAT_VERSION,
        "ccloud_help_digest": "3" * 64,
        "ccloud_config_digest": "4" * 64,
        "ccloud_auth_profile_digest": ccloud_tool.sha256_bytes(profile.encode()),
        "ccloud_json_flag": "--output=json",
        "required_version_family": ccloud_tool.REQUIRED_VERSION_FAMILY,
        "observed_cockroach_version": "v26.2.5",
        "expected_cluster_id_digest": SYNTHETIC_CLUSTER_DIGEST,
        "provisioning_receipt_digest": "2" * 64,
        "target_wire_plan": "SERVERLESS",
        "target_plan": "BASIC",
    }


def _receipt(argv: tuple[str, ...], stdout: str) -> ProcessReceipt:
    return ProcessReceipt(
        argv=argv,
        stdout=stdout.encode(),
        stderr=b"",
        exit_status=0,
        raw_output_digest=ccloud_tool.sha256_bytes(stdout.encode()),
    )


def _discover(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    help_text: str,
) -> dict[str, str]:
    executable = tmp_path / "ccloud"
    executable.write_bytes(b"official-ccloud-0.6.12")
    calls: list[tuple[str, ...]] = []

    def fake_process(path: Path, arguments: tuple[str, ...]) -> ProcessReceipt:
        assert path == executable
        calls.append(arguments)
        if arguments == ("version",):
            return _receipt((str(path), *arguments), "ccloud version v0.6.12\n")
        assert arguments == ("cluster", "info", "--help")
        return _receipt((str(path), *arguments), help_text)

    monkeypatch.setattr(ccloud_tool, "_regular_executable", lambda: executable)
    monkeypatch.setattr(ccloud_tool, "bounded_process", fake_process)
    result = ccloud_tool.discover_preflight()
    assert calls == [("version",), ("cluster", "info", "--help")]
    return result


def test_discover_preflight_binds_official_output_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _discover(monkeypatch, tmp_path, OFFICIAL_HELP)
    assert result["ccloud_version"] == "v0.6.12"
    assert result["ccloud_json_flag"] == "--output=json"


@pytest.mark.parametrize(
    "help_text",
    [
        "  -o, --output string   output format [standard]\n",
        "  -o, --output string   output format [standard|yaml]\n",
    ],
)
def test_discover_preflight_rejects_missing_json_support(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    help_text: str,
) -> None:
    with pytest.raises(EvidenceBlocked, match="canonical ccloud JSON output option"):
        _discover(monkeypatch, tmp_path, help_text)


@pytest.mark.parametrize(
    "competing",
    [
        "  --json   emit JSON\n",
        "  --format string   output format [standard|json]\n",
        "  --format=json   emit JSON\n",
    ],
)
def test_discover_preflight_rejects_competing_json_mechanisms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    competing: str,
) -> None:
    with pytest.raises(EvidenceBlocked, match="canonical ccloud JSON output option"):
        _discover(monkeypatch, tmp_path, OFFICIAL_HELP + competing)


@pytest.mark.parametrize(
    "help_text",
    [
        '  -o, --output string output format [json|standard] (default "standard")\n',
        "  -o, --output string output format "
        '[standard|json|yaml] (default "standard")\n',
        '  -o, --output=json output format [standard|json] (default "standard")\n',
        OFFICIAL_HELP + OFFICIAL_HELP,
    ],
)
def test_discover_preflight_rejects_ambiguous_or_malformed_output_help(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    help_text: str,
) -> None:
    with pytest.raises(EvidenceBlocked, match="canonical ccloud JSON output option"):
        _discover(monkeypatch, tmp_path, help_text)


@pytest.mark.parametrize("envelope", ["object", "one-element-array"])
def test_observed_document_shape_and_exact_digest_are_normalized(envelope: str) -> None:
    record = observed_record()
    payload: object = record if envelope == "object" else [record]
    result = normalize(payload)
    assert result == {
        "name": "kingly-dreamer",
        "cluster_id_digest": SYNTHETIC_CLUSTER_DIGEST,
        "cockroach_version": "v26.2.5",
        "state": "CREATED",
        "wire_plan": "SERVERLESS",
        "plan": "BASIC",
        "cloud": "AWS",
        "regions": ["us-east-1"],
    }


@pytest.mark.parametrize(
    "regions",
    [
        ["us-east-1"],
        [{"name": "us-east-1"}],
        [{"name": "us-east-1", "synthetic_extra": "ignored"}],
    ],
)
def test_region_shapes_are_normalized(regions: object) -> None:
    assert normalize(observed_record(regions=regions))["regions"] == ["us-east-1"]


@pytest.mark.parametrize(
    "value",
    [
        [],
        [observed_record(), observed_record()],
        {**observed_record(), "unknown_field": "rejected"},
        observed_record(regions=[]),
        observed_record(regions=[{"region": "us-east-1"}]),
    ],
)
def test_unknown_ambiguous_or_malformed_shapes_are_rejected(value: object) -> None:
    with pytest.raises(EvidenceBlocked):
        normalize(value)


def test_serverless_normalizes_only_in_bound_compatibility_domain() -> None:
    assert (
        ccloud_tool.normalize_legacy_plan(
            "SERVERLESS",
            ccloud_version="v0.6.12",
            ccapi_version="2023-04-10",
        )
        == "BASIC"
    )
    for versions in (("v0.6.13", "2023-04-10"), ("v0.6.12", "2024-01-01")):
        with pytest.raises(EvidenceBlocked, match="compatibility binding"):
            ccloud_tool.normalize_legacy_plan(
                "SERVERLESS",
                ccloud_version=versions[0],
                ccapi_version=versions[1],
            )


def base_target_artifact() -> dict[str, object]:
    return {
        "expected_cluster_id_digest": SYNTHETIC_CLUSTER_DIGEST,
        "required_version_family": "v26.2",
        "observed_cockroach_version": "v26.2.5",
        "target_wire_plan": "SERVERLESS",
        "target_plan": "BASIC",
        "ccloud_version": "v0.6.12",
        "ccapi_version": "2023-04-10",
    }


def test_v26_2_patch_is_preserved_and_outside_family_is_rejected() -> None:
    document = normalize(observed_record(cockroach_version="v26.2.5"))
    artifact = base_target_artifact()
    ccloud_tool._validate_target(document, artifact)
    assert document["cockroach_version"] == "v26.2.5"
    outside = normalize(observed_record(cockroach_version="v26.3.0"))
    artifact["observed_cockroach_version"] = "v26.3.0"
    with pytest.raises(EvidenceBlocked, match="version family"):
        ccloud_tool._validate_target(outside, artifact)


@pytest.mark.parametrize(
    "record_change,artifact_change",
    [
        ({"name": "wrong-name"}, {}),
        ({"id": "wrong-id"}, {}),
        ({"cloud_provider": "GCP"}, {}),
        ({"regions": ["us-west-2"]}, {}),
        ({"state": "UPDATING"}, {}),
    ],
)
def test_every_mismatched_target_field_is_rejected(
    record_change: dict[str, object], artifact_change: dict[str, object]
) -> None:
    document = normalize(observed_record(**record_change))
    artifact = base_target_artifact()
    artifact.update(artifact_change)
    with pytest.raises(EvidenceBlocked):
        ccloud_tool._validate_target(document, artifact)


def test_capture_uses_bound_canonical_argv_and_preserves_both_plans(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "ccloud"
    executable.write_bytes(b"official-ccloud-0.6.12")
    profile = "local-test-profile"
    artifact = target_artifact(executable, profile)
    monkeypatch.setenv("CCLOUD_CLUSTER_NAME", ccloud_tool.CLUSTER_NAME)
    monkeypatch.setenv("CCLOUD_AUTH_PROFILE", profile)
    monkeypatch.setenv("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST", SYNTHETIC_CLUSTER_DIGEST)
    monkeypatch.setenv("CCLOUD_PROVISIONING_RECEIPT_DIGEST", "2" * 64)
    observed_arguments: list[tuple[str, ...]] = []

    def fake_process(path: Path, arguments: tuple[str, ...]) -> ProcessReceipt:
        observed_arguments.append(arguments)
        raw = ccloud_tool.canonical_bytes([observed_record()])
        return ProcessReceipt(
            argv=(str(path), *arguments),
            stdout=raw,
            stderr=b"",
            exit_status=0,
            raw_output_digest=ccloud_tool.sha256_bytes(raw),
        )

    monkeypatch.setattr(ccloud_tool, "bounded_process", fake_process)
    result = ccloud_tool.build_capture(artifact)
    assert observed_arguments == [
        ("cluster", "info", "kingly-dreamer", "--output=json")
    ]
    assert result["redacted_command_argv"][-1] == "--output=json"
    assert result["normalized_redacted_output"]["wire_plan"] == "SERVERLESS"
    assert result["normalized_redacted_output"]["plan"] == "BASIC"


@pytest.mark.asyncio
async def test_runtime_capture_returns_frozen_tool_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "ccloud"
    executable.write_bytes(b"official-ccloud-0.6.12")
    profile = "local-test-profile"
    artifact = target_artifact(executable, profile)
    monkeypatch.setenv("CCLOUD_CLUSTER_NAME", ccloud_tool.CLUSTER_NAME)
    monkeypatch.setenv("CCLOUD_AUTH_PROFILE", profile)
    monkeypatch.setenv("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST", SYNTHETIC_CLUSTER_DIGEST)
    monkeypatch.setenv("CCLOUD_PROVISIONING_RECEIPT_DIGEST", "2" * 64)
    monkeypatch.setattr(ccloud_tool, "load_version_artifact", lambda: artifact)

    def fake_process(path: Path, arguments: tuple[str, ...]) -> ProcessReceipt:
        raw = ccloud_tool.canonical_bytes(observed_record())
        return ProcessReceipt(
            (str(path), *arguments),
            raw,
            b"",
            0,
            ccloud_tool.sha256_bytes(b"stdout\0" + raw + b"\0stderr\0"),
        )

    monkeypatch.setattr(ccloud_tool, "bounded_process", fake_process)
    result = await ccloud_tool.capture(purpose="runtime")
    assert result.tool_name == "ccloud"
    assert result.cluster_name == "kingly-dreamer"
    assert result.observed_state == "CREATED"
    assert result.observed_plan == "BASIC"
    assert result.evidence_digest


@pytest.mark.asyncio
async def test_runtime_capture_rejects_every_other_purpose() -> None:
    with pytest.raises(EvidenceBlocked, match="purpose"):
        await ccloud_tool.capture(purpose="closure")
