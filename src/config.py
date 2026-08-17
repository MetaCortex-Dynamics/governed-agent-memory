"""Authority-bounded runtime configuration loaders."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit


class ConfigError(ValueError):
    """A configuration value crossed an authority or transport boundary."""


_FORBIDDEN_APP_USERS = frozenset(
    {
        "root",
        "admin",
        "gam_decider",
        "gam_decider_role",
        "gam_executor",
        "gam_executor_role",
        "gam_schema_admin",
        "gam_schema_admin_role",
    }
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_CLUSTER_NAME = "kingly-dreamer"
_DATABASE_NAME = "governed_agent_memory"
_REQUIRED_VERSION_FAMILY = "v26.2"
_CCLOUD_VERSION = "v0.6.12"
_CCAPI_VERSION = "2023-04-10"
_VECTOR_DOCS_URL = "https://www.cockroachlabs.com/docs/v26.2/vector-indexes"
_EMBEDDING_MODEL = "text-embedding-3-small"
_EMBEDDING_DIMENSIONS = 1536
_BOUND_VERSION_PATH = Path("schema/crdb-version.json")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_text(value: str | None, name: str) -> str:
    if value is None or value == "" or value != value.strip():
        raise ConfigError(f"{name} is not configured correctly")
    return value


def _require_digest(value: str | None, name: str) -> str:
    text = _require_text(value, name)
    if _HEX_64.fullmatch(text) is None:
        raise ConfigError(f"{name} digest is invalid")
    return text


def _validate_database_url(value: str) -> str:
    if not value or value != value.strip():
        raise ConfigError("database URL is blank or padded")
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ConfigError("database URL scheme is not PostgreSQL")
    if not parsed.hostname or not parsed.path.strip("/") or not parsed.username:
        raise ConfigError("database URL identity is incomplete")
    if parsed.username.casefold() in _FORBIDDEN_APP_USERS:
        raise ConfigError("database URL uses a higher-authority identity")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if query.get("sslmode") != ["verify-full"]:
        raise ConfigError("database URL must use sslmode=verify-full")
    return value


@dataclass(frozen=True, slots=True)
class AppDbConfig:
    """Application-memory connection configuration only."""

    database_url: str
    max_serialization_retries: int = 4

    def __post_init__(self) -> None:
        _validate_database_url(self.database_url)
        if not 1 <= self.max_serialization_retries <= 8:
            raise ConfigError("serialization retry bound is invalid")

    @classmethod
    def from_env(cls) -> AppDbConfig:
        """Read only the application database variable."""
        value = os.environ.get("DATABASE_URL_APP")
        if value is None:
            raise ConfigError("DATABASE_URL_APP is not configured")
        return cls(database_url=value)


@dataclass(frozen=True, slots=True)
class EmbeddingConfig:
    """Pinned embedding configuration with non-represented credential state."""

    api_key: str = field(repr=False, compare=False)
    model: str = _EMBEDDING_MODEL
    dimensions: int = _EMBEDDING_DIMENSIONS

    def __post_init__(self) -> None:
        _require_text(self.api_key, "OPENAI_API_KEY")
        if self.model != _EMBEDDING_MODEL or self.dimensions != _EMBEDDING_DIMENSIONS:
            raise ConfigError("embedding model binding is invalid")

    @property
    def config_digest(self) -> str:
        """Bind only non-secret embedding configuration."""
        return _digest(
            _canonical_bytes({"model": self.model, "dimensions": self.dimensions})
        )

    @classmethod
    def from_env(cls) -> EmbeddingConfig:
        return cls(_require_text(os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY"))


@dataclass(frozen=True, slots=True)
class BoundCrdbVersion:
    artifact_version: str
    required_version_family: str
    observed_cockroach_version: str
    cockroach_version_raw_digest: str
    feature_vector_index_enabled: bool
    database_name: str
    cluster_name_digest: str
    expected_cluster_id_digest: str
    provisioning_receipt_digest: str
    preprovision_record_sha256: str
    preprovision_evidence_digest: str
    preprovision_observed_at: str
    setup_promotion_digest: str
    schema_admin_handle_digest: str
    target_state: str
    target_wire_plan: str
    target_plan: str
    target_cloud: str
    target_regions: tuple[str, ...]
    target_spend_limit_usd: str
    vector_docs_url: str
    ccloud_executable: str
    ccloud_executable_sha256: str
    ccloud_version: str
    ccapi_version: str
    ccloud_version_raw_digest: str
    ccloud_help_digest: str
    ccloud_config_digest: str
    ccloud_auth_profile_digest: str
    ccloud_json_flag: str
    capture_digest: str

    def payload(self) -> dict[str, object]:
        return {
            item.name: (list(value) if item.name == "target_regions" else value)
            for item in fields(self)
            if item.name != "capture_digest"
            for value in (getattr(self, item.name),)
        }

    def __post_init__(self) -> None:
        literal = {
            "artifact_version": "gam.crdb-version.v1",
            "required_version_family": _REQUIRED_VERSION_FAMILY,
            "feature_vector_index_enabled": True,
            "database_name": _DATABASE_NAME,
            "target_state": "CREATED",
            "target_wire_plan": "SERVERLESS",
            "target_plan": "BASIC",
            "target_cloud": "AWS",
            "target_regions": ("us-east-1",),
            "target_spend_limit_usd": "0",
            "vector_docs_url": _VECTOR_DOCS_URL,
            "ccloud_version": _CCLOUD_VERSION,
            "ccapi_version": _CCAPI_VERSION,
        }
        for name, expected in literal.items():
            if getattr(self, name) != expected:
                raise ConfigError(f"bound CockroachDB field mismatch: {name}")
        for name in (
            "cockroach_version_raw_digest",
            "cluster_name_digest",
            "expected_cluster_id_digest",
            "provisioning_receipt_digest",
            "preprovision_record_sha256",
            "preprovision_evidence_digest",
            "setup_promotion_digest",
            "schema_admin_handle_digest",
            "ccloud_executable_sha256",
            "ccloud_version_raw_digest",
            "ccloud_help_digest",
            "ccloud_config_digest",
            "ccloud_auth_profile_digest",
        ):
            _require_digest(cast(str, getattr(self, name)), name)
        if self.cluster_name_digest != _digest(_CLUSTER_NAME.encode("utf-8")):
            raise ConfigError("bound cluster-name digest mismatch")
        if _VERSION.fullmatch(self.observed_cockroach_version) is None or not (
            self.observed_cockroach_version.startswith(
                f"{self.required_version_family}."
            )
        ):
            raise ConfigError("bound CockroachDB version family is invalid")
        if _VERSION.fullmatch(self.ccloud_version) is None:
            raise ConfigError("bound ccloud version domain is invalid")
        if self.ccloud_json_flag != "--output=json":
            raise ConfigError("bound ccloud JSON flag is invalid")
        executable = Path(self.ccloud_executable)
        try:
            resolved = executable.resolve(strict=True)
        except OSError as error:
            raise ConfigError("bound ccloud executable is unavailable") from error
        if (
            not executable.is_absolute()
            or not resolved.is_file()
            or executable.is_symlink()
            or _digest(resolved.read_bytes()) != self.ccloud_executable_sha256
        ):
            raise ConfigError("bound ccloud executable identity mismatch")
        try:
            observed_at = self.preprovision_observed_at
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", observed_at
            ):
                raise ValueError
        except (TypeError, ValueError) as error:
            raise ConfigError("preprovision timestamp is invalid") from error
        if self.capture_digest != _digest(_canonical_bytes(self.payload())):
            raise ConfigError("bound CockroachDB capture digest mismatch")

    @classmethod
    def load(cls, path: Path = _BOUND_VERSION_PATH) -> BoundCrdbVersion:
        try:
            raw = path.read_bytes()
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ConfigError("bound CockroachDB artifact is unavailable") from error
        if not isinstance(parsed, dict) or set(parsed) != {
            item.name for item in fields(cls)
        }:
            raise ConfigError("bound CockroachDB artifact fields differ")
        if _canonical_bytes(parsed) != raw:
            raise ConfigError("bound CockroachDB artifact is not canonical")
        values = dict(parsed)
        regions = values.get("target_regions")
        if not isinstance(regions, list) or not all(
            isinstance(item, str) for item in regions
        ):
            raise ConfigError("bound CockroachDB regions are invalid")
        values["target_regions"] = tuple(regions)
        try:
            return cls(**cast(dict[str, Any], values))
        except TypeError as error:
            raise ConfigError("bound CockroachDB artifact types differ") from error


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("bound CockroachDB artifact has duplicate keys")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class CcloudToolConfig:
    """Application DB and opaque ccloud identity bindings."""

    database_url: str = field(repr=False)
    cluster_name: str
    auth_profile: str = field(repr=False, compare=False)
    expected_cluster_id_digest: str
    provisioning_receipt_digest: str
    bound_version: BoundCrdbVersion

    def __post_init__(self) -> None:
        _validate_database_url(self.database_url)
        _require_text(self.auth_profile, "CCLOUD_AUTH_PROFILE")
        if self.cluster_name != _CLUSTER_NAME:
            raise ConfigError("ccloud cluster-name binding mismatch")
        expected = _require_digest(
            self.expected_cluster_id_digest, "CCLOUD_EXPECTED_CLUSTER_ID_DIGEST"
        )
        receipt = _require_digest(
            self.provisioning_receipt_digest,
            "CCLOUD_PROVISIONING_RECEIPT_DIGEST",
        )
        if (
            expected != self.bound_version.expected_cluster_id_digest
            or receipt != self.bound_version.provisioning_receipt_digest
            or _digest(self.auth_profile.encode("utf-8"))
            != self.bound_version.ccloud_auth_profile_digest
        ):
            raise ConfigError("ccloud environment and artifact bindings differ")

    @classmethod
    def from_env(cls, path: Path = _BOUND_VERSION_PATH) -> CcloudToolConfig:
        if "CCLOUD_CLUSTER_ID" in os.environ or "CCLOUD_API_KEY" in os.environ:
            raise ConfigError("unpermitted ccloud environment input is present")
        return cls(
            database_url=_require_text(
                os.environ.get("DATABASE_URL_APP"), "DATABASE_URL_APP"
            ),
            cluster_name=_require_text(
                os.environ.get("CCLOUD_CLUSTER_NAME"), "CCLOUD_CLUSTER_NAME"
            ),
            auth_profile=_require_text(
                os.environ.get("CCLOUD_AUTH_PROFILE"), "CCLOUD_AUTH_PROFILE"
            ),
            expected_cluster_id_digest=_require_digest(
                os.environ.get("CCLOUD_EXPECTED_CLUSTER_ID_DIGEST"),
                "CCLOUD_EXPECTED_CLUSTER_ID_DIGEST",
            ),
            provisioning_receipt_digest=_require_digest(
                os.environ.get("CCLOUD_PROVISIONING_RECEIPT_DIGEST"),
                "CCLOUD_PROVISIONING_RECEIPT_DIGEST",
            ),
            bound_version=BoundCrdbVersion.load(path),
        )


__all__ = [
    "AppDbConfig",
    "BoundCrdbVersion",
    "CcloudToolConfig",
    "ConfigError",
    "EmbeddingConfig",
]
