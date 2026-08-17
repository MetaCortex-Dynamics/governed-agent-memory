from __future__ import annotations

import os

import pytest


@pytest.mark.live_crdb
def test_agent_crdb_environment_is_credential_gated() -> None:
    if not os.environ.get("DATABASE_URL_APP"):
        pytest.skip("DATABASE_URL_APP is not configured")
    assert os.environ["DATABASE_URL_APP"]
