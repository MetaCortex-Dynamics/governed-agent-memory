from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_lockfiles_are_byte_identical_pinned_and_hashed() -> None:
    root = (ROOT / "requirements.lock").read_bytes()
    deployed = (ROOT / "lambda/requirements.txt").read_bytes()
    assert root == deployed
    text = root.decode()
    logical = re.sub(r"\\\n\s*", " ", text)
    requirements = [
        line.strip()
        for line in logical.splitlines()
        if line.strip() and not line.strip().startswith(("#", "--"))
    ]
    assert requirements
    assert all("==" in line and "--hash=sha256:" in line for line in requirements)
    assert "--only-binary :all:" in text


def test_hash_enforced_linux_python_312_install_is_declared() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    required = (
        "python3.12 -m pip install",
        "--require-hashes",
        "--only-binary=:all:",
        "--platform manylinux2014_x86_64",
        "--implementation cp",
        "--python-version 3.12",
        "--abi cp312",
        "cmp -s requirements.lock lambda/requirements.txt",
    )
    assert all(item in script for item in required)


def test_clean_hash_install_resolves(tmp_path: Path) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter argv
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--dry-run",
            "--require-hashes",
            "--only-binary=:all:",
            "--target",
            str(tmp_path / "install"),
            "-r",
            str(ROOT / "requirements.lock"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr[-1000:]


def test_iam_template_is_exact_secret_read() -> None:
    value = json.loads((ROOT / "lambda/iam-secrets-policy.template.json").read_text())
    assert value == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "__APP_SECRET_ARN__",
            }
        ],
    }


def test_deploy_inventory_and_boundaries_are_exact() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    for item in (
        "governed-agent-memory-fn",
        "--runtime python3.12",
        "--architectures x86_64",
        "--handler handler.lambda_handler",
        "--timeout 30",
        "--memory-size 512",
        "--ephemeral-storage Size=512",
        "--reserved-concurrent-executions 2",
        "UrlPolicyInvokeURL",
        "UrlPolicyInvokeFunction",
        "AWSLambdaBasicExecutionRole",
        "MAX_ACCEPTED_AWS_ESTIMATE_USD",
    ):
        assert item in script
    assert "set -euo pipefail" in script
    assert "DATABASE_URL_APP" not in script
    assert "OPENAI_API_KEY" not in script
    assert "ListSecrets" not in script
    assert "PutSecretValue" not in script


def test_pricing_input_is_concrete_canonical_and_current_contract() -> None:
    path = ROOT / "lambda/pricing-input.json"
    raw = path.read_bytes()
    value = json.loads(raw)
    assert raw == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert value["schema_version"] == "gam.aws-pricing.v1"
    assert value["architecture"] == "x86_64"
    assert value["aws_region"] == "us-east-1"
    assert value["source_url"] == "https://aws.amazon.com/lambda/pricing/"
    assert re.fullmatch(r"[0-9a-f]{64}", value["source_page_sha256"])


def test_smoke_and_teardown_have_narrow_command_surfaces() -> None:
    smoke = (ROOT / "lambda/smoke.sh").read_text()
    teardown = (ROOT / "lambda/teardown.sh").read_text()
    fixture = (ROOT / "lambda/smoke-process-task.json").read_text()
    assert fixture == (
        '{"agent_id":"lambda-smoke-agent","operation":"process_task",'
        '"request_id":"6b71eae4-6f07-55a7-a691-ec0a40267790",'
        '"requester_ref":"lambda-smoke-operator",'
        '"schema_version":"gam.lambda.v1","session_id":"lambda-smoke-session",'
        '"task_description":"Propose setting demo key lambda_smoke to the scalar '
        'string ready. Do not decide or execute it."}\n'
    )
    assert "POLL_COUNT < 6" in smoke and "PROFILE_NOT_READY" in smoke
    assert "delete-function-url-config" in teardown
    assert "delete-function --function-name governed-agent-memory-fn" in teardown
    assert "delete-secret" not in teardown and "delete-role " not in teardown


def test_obsolete_cluster_target_is_absent_from_executable_lambda_surface() -> None:
    handler = (ROOT / "lambda/handler.py").read_text()
    assert "kingly-dreamer" not in handler  # imported from the closed binding
    assert "from src.ccloud_tool import CLUSTER_NAME" in handler
