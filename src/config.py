"""Authority-bounded runtime configuration loaders."""

from __future__ import annotations

import os
from dataclasses import dataclass
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


__all__ = ["AppDbConfig", "ConfigError"]
