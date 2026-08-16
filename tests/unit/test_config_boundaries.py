"""Application database configuration authority boundaries."""

from __future__ import annotations

import pytest

from src.config import AppDbConfig, ConfigError


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
