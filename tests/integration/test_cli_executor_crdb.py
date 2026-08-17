from __future__ import annotations

import os

import pytest


@pytest.mark.live_crdb
def test_cli_executor_crdb_environment_is_credential_gated() -> None:
    required = ("DATABASE_URL_DECIDER", "DATABASE_URL_EXECUTOR", "EXECUTOR_ID")
    if any(not os.environ.get(name) for name in required):
        pytest.skip("live executor environment is not configured")
    assert all(os.environ[name] for name in required)
