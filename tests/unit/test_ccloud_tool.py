"""Unit tests for deterministic ccloud help discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from src import ccloud_tool
from src.ccloud_tool import EvidenceBlocked, ProcessReceipt

OFFICIAL_HELP = (
    "Usage: ccloud cluster info [name]\n\n"
    "Flags:\n"
    '  -o, --output string   output format [standard|json] (default "standard")\n'
)


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


def test_capture_uses_bound_canonical_one_token_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "ccloud"
    executable.write_bytes(b"official-ccloud-0.6.12")
    profile = "local-test-profile"
    expected_id = ccloud_tool.sha256_bytes(b"cluster-id")
    receipt_digest = "2" * 64
    artifact = {
        "ccloud_executable": str(executable),
        "ccloud_executable_sha256": ccloud_tool.sha256_bytes(executable.read_bytes()),
        "ccloud_version": "v0.6.12",
        "ccloud_help_digest": "3" * 64,
        "ccloud_config_digest": "4" * 64,
        "ccloud_auth_profile_digest": ccloud_tool.sha256_bytes(profile.encode()),
        "ccloud_json_flag": "--output=json",
        "expected_cluster_id_digest": expected_id,
        "provisioning_receipt_digest": receipt_digest,
    }
    monkeypatch.setenv("CCLOUD_CLUSTER_NAME", ccloud_tool.CLUSTER_NAME)
    monkeypatch.setenv("CCLOUD_AUTH_PROFILE", profile)
    monkeypatch.setenv("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST", expected_id)
    monkeypatch.setenv("CCLOUD_PROVISIONING_RECEIPT_DIGEST", receipt_digest)
    observed_arguments: list[tuple[str, ...]] = []

    def fake_process(path: Path, arguments: tuple[str, ...]) -> ProcessReceipt:
        assert path == executable
        observed_arguments.append(arguments)
        payload = {
            "id": "cluster-id",
            "name": ccloud_tool.CLUSTER_NAME,
            "version": ccloud_tool.EXPECTED_VERSION,
            "state": "CREATED",
            "plan": "Basic",
            "cloud": "AWS",
            "regions": [{"name": ccloud_tool.EXPECTED_REGION}],
        }
        raw = ccloud_tool.canonical_bytes(payload)
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
        ("cluster", "info", ccloud_tool.CLUSTER_NAME, "--output=json")
    ]
    assert result["redacted_command_argv"][-1] == "--output=json"
