from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen

import pytest

pytestmark = [pytest.mark.live_lambda]
ROOT = Path(__file__).parents[2]


@pytest.mark.preseed
def test_live_lambda_health_and_unseeded_profile() -> None:
    if os.environ.get("RUN_LIVE_LAMBDA") != "1":
        pytest.skip("live Lambda witness is not enabled")
    url = os.environ.get("FUNCTION_URL")
    if not url:
        pytest.skip("Lambda URL identifier is unavailable")
    with urlopen(f"{url.rstrip('/')}/health", timeout=10) as response:  # noqa: S310
        health = json.load(response)
    assert health["schema_version"] == "gam.lambda.v1"
    assert health["status"] == "ok"


@pytest.mark.preseed
def test_live_signed_proposal_returns_persisted_identities(tmp_path: Path) -> None:
    if os.environ.get("RUN_LIVE_LAMBDA") != "1":
        pytest.skip("live Lambda witness is not enabled")
    aws = shutil.which("aws")
    region = os.environ.get("AWS_REGION")
    if aws is None or not region:
        pytest.skip("signed Lambda invocation bindings are unavailable")
    output = tmp_path / "invoke.json"
    completed = subprocess.run(  # noqa: S603 - resolved AWS executable
        [
            aws,
            "lambda",
            "invoke",
            "--region",
            region,
            "--function-name",
            "governed-agent-memory-fn",
            "--cli-binary-format",
            "raw-in-base64-out",
            "--payload",
            f"file://{ROOT / 'lambda/smoke-process-task.json'}",
            str(output),
        ],
        check=False,
        capture_output=True,
        timeout=35,
    )
    assert completed.returncode == 0
    value = json.loads(output.read_text())
    status = value.get("status", "OK")
    safe_failure = {
        "status": status,
        "stage": value.get("stage"),
        "error_code": value.get("error_code"),
    }
    assert status == "OK", json.dumps(
        safe_failure, sort_keys=True, separators=(",", ":")
    )
    assert value["schema_version"] == "gam.lambda.v1"
    assert value["proposal_id"] and value["evaluation_id"]
    assert re.fullmatch(r"[0-9a-f]{64}", value["trace_digest"])
