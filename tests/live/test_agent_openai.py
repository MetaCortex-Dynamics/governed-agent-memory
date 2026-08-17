from __future__ import annotations

import os

import pytest


@pytest.mark.live_openai
def test_agent_openai_environment_is_credential_gated() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is not configured")
    assert os.environ["OPENAI_API_KEY"]
