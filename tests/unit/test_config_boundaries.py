"""Application database configuration authority boundaries."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path
from typing import Any

import pytest

from src.config import (
    AppDbConfig,
    BoundCrdbVersion,
    CcloudToolConfig,
    ConfigError,
    EmbeddingConfig,
)

ROOT = Path(__file__).resolve().parents[2]


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def artifact_fixture(tmp_path: Path) -> tuple[Path, str]:
    executable = tmp_path / "ccloud"
    executable.write_bytes(b"unit executable")
    profile = "unit-profile-label"
    value: dict[str, object] = {
        "artifact_version": "gam.crdb-version.v1",
        "cockroach_version": "v26.2.1",
        "cockroach_version_raw_digest": "1" * 64,
        "feature_vector_index_enabled": True,
        "database_name": "governed_agent_memory",
        "cluster_name_digest": digest(b"governed-agent-memory"),
        "expected_cluster_id_digest": "2" * 64,
        "provisioning_receipt_digest": "3" * 64,
        "preprovision_record_sha256": "4" * 64,
        "preprovision_evidence_digest": "5" * 64,
        "preprovision_observed_at": "2026-08-16T12:00:00.000000Z",
        "setup_promotion_digest": "6" * 64,
        "schema_admin_handle_digest": "7" * 64,
        "target_state": "READY",
        "target_plan": "Basic",
        "target_cloud": "AWS",
        "target_regions": ["us-east-1"],
        "target_spend_limit_usd": "0",
        "vector_docs_url": "https://www.cockroachlabs.com/docs/v26.2/vector-indexes",
        "ccloud_executable": str(executable.resolve()),
        "ccloud_executable_sha256": digest(executable.read_bytes()),
        "ccloud_version": "v0.6.12",
        "ccloud_version_raw_digest": "8" * 64,
        "ccloud_help_digest": "9" * 64,
        "ccloud_config_digest": "a" * 64,
        "ccloud_auth_profile_digest": digest(profile.encode()),
        "ccloud_json_flag": "--json",
    }
    value["capture_digest"] = digest(canonical(value))
    path = tmp_path / "crdb-version.json"
    path.write_bytes(canonical(value))
    return path, profile


def test_app_config_reads_only_its_declared_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL_APP",
        "postgresql://gam_app@db.example/app?sslmode=verify-full",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://ignored@db.example/app?sslmode=verify-full",
    )
    assert AppDbConfig.from_env().database_url.startswith("postgresql://gam_app@")


@pytest.mark.parametrize(
    "url",
    (
        "",
        "postgresql://gam_app@db.example/app",
        "postgresql://gam_app@db.example/app?sslmode=require",
        "postgresql://root@db.example/app?sslmode=verify-full",
        "postgresql://gam_decider_role@db.example/app?sslmode=verify-full",
        "https://gam_app@db.example/app?sslmode=verify-full",
    ),
)
def test_app_config_rejects_unsafe_or_higher_authority_urls(url: str) -> None:
    with pytest.raises(ConfigError):
        AppDbConfig(url)


def test_app_config_requires_declared_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL_APP", raising=False)
    with pytest.raises(ConfigError, match="DATABASE_URL_APP"):
        AppDbConfig.from_env()


def test_embedding_config_is_pinned_and_does_not_represent_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "unit-only-value")
    monkeypatch.setenv("DATABASE_URL_APP", "ignored")
    config = EmbeddingConfig.from_env()
    assert config.model == "text-embedding-3-small"
    assert config.dimensions == 1536
    assert "unit-only-value" not in repr(config)
    assert "unit-only-value" not in config.config_digest
    assert config == EmbeddingConfig("different-unit-value")


@pytest.mark.parametrize("value", (None, "", " padded "))
def test_embedding_config_rejects_missing_or_malformed_key(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    else:
        monkeypatch.setenv("OPENAI_API_KEY", value)
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        EmbeddingConfig.from_env()


def test_bound_crdb_artifact_and_ccloud_environment_are_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path, profile = artifact_fixture(tmp_path)
    monkeypatch.setenv(
        "DATABASE_URL_APP",
        "postgresql://gam_app@db.example/app?sslmode=verify-full",
    )
    monkeypatch.setenv("CCLOUD_CLUSTER_NAME", "governed-agent-memory")
    monkeypatch.setenv("CCLOUD_AUTH_PROFILE", profile)
    monkeypatch.setenv("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST", "2" * 64)
    monkeypatch.setenv("CCLOUD_PROVISIONING_RECEIPT_DIGEST", "3" * 64)
    config = CcloudToolConfig.from_env(path)
    assert isinstance(config.bound_version, BoundCrdbVersion)
    assert profile not in repr(config)
    assert "postgresql://" not in repr(config)
    assert config.bound_version.cockroach_version == "v26.2.1"
    assert config.bound_version.ccloud_version == "v0.6.12"
    assert config.bound_version.ccloud_version != config.bound_version.cockroach_version


def test_preflight_writer_round_trips_exactly_through_bound_loader(
    tmp_path: Path,
) -> None:
    source, _ = artifact_fixture(tmp_path)
    value = json.loads(source.read_bytes())
    output = tmp_path / "writer" / "crdb-version.json"
    namespace: dict[str, Any] = runpy.run_path(str(ROOT / "scripts/verify_crdb.py"))
    writer = namespace["atomic_artifact"]
    writer.__globals__["VERSION_ARTIFACT"] = output
    writer(value)
    assert output.read_bytes() == canonical(value)
    assert not output.read_bytes().endswith(b"\n")
    loaded = BoundCrdbVersion.load(output)
    assert loaded.cockroach_version == "v26.2.1"
    assert loaded.ccloud_version == "v0.6.12"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"target_cloud": "GCP"}, "target_cloud"),
        ({"ccloud_version": "v26.2.1"}, "version domain"),
        ({"ccloud_version": "0.6.12"}, "version domain"),
        ({"expected_cluster_id_digest": "f" * 64}, "capture digest"),
        ({"capture_digest": "f" * 64}, "capture digest"),
        ({"extra": "value"}, "fields differ"),
    ],
)
def test_bound_crdb_artifact_rejects_schema_and_binding_changes(
    tmp_path: Path, mutation: dict[str, object], message: str
) -> None:
    path, _ = artifact_fixture(tmp_path)
    value = json.loads(path.read_bytes())
    value.update(mutation)
    path.write_bytes(canonical(value))
    with pytest.raises(ConfigError, match=message):
        BoundCrdbVersion.load(path)


def test_bound_crdb_artifact_rejects_missing_noncanonical_and_changed_binary(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigError, match="unavailable"):
        BoundCrdbVersion.load(tmp_path / "absent.json")
    path, _ = artifact_fixture(tmp_path)
    value = json.loads(path.read_bytes())
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(ConfigError, match="not canonical"):
        BoundCrdbVersion.load(path)
    path, _ = artifact_fixture(tmp_path)
    executable = Path(str(json.loads(path.read_bytes())["ccloud_executable"]))
    executable.write_bytes(b"changed")
    with pytest.raises(ConfigError, match="executable identity"):
        BoundCrdbVersion.load(path)


def test_ccloud_rejects_raw_identity_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path, _ = artifact_fixture(tmp_path)
    monkeypatch.setenv("CCLOUD_CLUSTER_ID", "unit-only-raw-id")
    with pytest.raises(ConfigError, match="unpermitted"):
        CcloudToolConfig.from_env(path)
