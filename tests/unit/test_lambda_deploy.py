from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _embedded_python_containing(needle: str) -> str:
    lines = (ROOT / "lambda/deploy.sh").read_text().splitlines()
    needle_index = next(index for index, line in enumerate(lines) if needle in line)
    start = max(
        index for index in range(needle_index + 1) if lines[index].endswith("<<'PY'")
    )
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == "PY")
    return "\n".join(lines[start + 1 : end])


def _account_settings(
    concurrent: object = 10, unreserved: object = 10
) -> dict[str, object]:
    return {
        "AccountLimit": {
            "TotalCodeSize": 1,
            "CodeSizeUnzipped": 1,
            "CodeSizeZipped": 1,
            "ConcurrentExecutions": concurrent,
            "UnreservedConcurrentExecutions": unreserved,
        },
        "AccountUsage": {},
    }


def _run_concurrency_validator(
    tmp_path: Path,
    account: object,
    concurrency: bytes = b"",
) -> subprocess.CompletedProcess[str]:
    account_path = tmp_path / "account.json"
    concurrency_path = tmp_path / "concurrency.json"
    account_path.write_text(json.dumps(account))
    concurrency_path.write_bytes(concurrency)
    return subprocess.run(  # noqa: S603 - fixed interpreter and embedded code
        [
            sys.executable,
            "-c",
            _embedded_python_containing("malformed account settings"),
            str(account_path),
            str(concurrency_path),
            "yes",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_runtime_lock_is_distinct_pinned_hashed_and_runtime_only() -> None:
    root = (ROOT / "requirements.lock").read_bytes()
    deployed = (ROOT / "lambda/requirements.txt").read_bytes()
    assert hashlib.sha256(root).hexdigest() == (
        "e9413bf0a6069a1f4939c1cd3ad17ee935728671d117be62a1937da4e46e8f57"
    )
    assert root != deployed
    text = deployed.decode()
    logical = re.sub(r"\\\n\s*", " ", text)
    requirements = [
        line.strip()
        for line in logical.splitlines()
        if line.strip() and not line.strip().startswith(("#", "--"))
    ]
    assert requirements
    assert all("==" in line and "--hash=sha256:" in line for line in requirements)
    assert "--only-binary :all:" in text
    assert "--strip-extras requirements.txt" in text
    assert "requirements-dev.txt" not in text
    names = set(re.findall(r"(?m)^([A-Za-z0-9_.-]+)==", text))
    assert names == {
        "annotated-types",
        "anyio",
        "asyncpg",
        "distro",
        "h11",
        "httpcore2",
        "httpx2",
        "idna",
        "jiter",
        "markdown-it-py",
        "mdurl",
        "openai",
        "pydantic",
        "pydantic-core",
        "pygments",
        "rich",
        "sniffio",
        "tqdm",
        "truststore",
        "typing-extensions",
        "typing-inspection",
    }
    assert not names & {
        "bandit",
        "mypy",
        "pip-audit",
        "pytest",
        "pytest-asyncio",
        "ruff",
    }


def test_hash_enforced_linux_python_312_install_is_declared() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    required = (
        "python3.12 -m pip install",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-compile",
        "--platform manylinux_2_28_x86_64",
        "--platform manylinux2014_x86_64",
        "--implementation cp",
        "--python-version 3.12",
        "--abi cp312",
    )
    assert all(item in script for item in required)
    assert "cmp -s requirements.lock lambda/requirements.txt" not in script


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
            "--platform",
            "manylinux_2_28_x86_64",
            "--platform",
            "manylinux2014_x86_64",
            "--implementation",
            "cp",
            "--python-version",
            "3.12",
            "--abi",
            "cp312",
            "--target",
            str(tmp_path / "install"),
            "-r",
            str(ROOT / "lambda/requirements.txt"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr[-1000:]


def test_deploy_requires_exact_asyncpg_lambda_wheel_tag() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    assert 'root / "asyncpg-0.31.0.dist-info"' in script
    assert 'tags != {"cp312-cp312-manylinux_2_28_x86_64"}' in script
    assert "asyncpg wheel metadata missing" in script
    assert "asyncpg wheel tag mismatch" in script


def test_deploy_copies_only_tracked_python_application_sources() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    assert '["git", "ls-files", "-z", "--", "src"]' in script
    assert 'source.suffix != ".py"' in script
    assert "source.is_symlink() or not source.is_file()" in script
    assert "shutil.copyfile(source, destination)" in script
    assert "destination.chmod(0o644)" in script
    assert "--no-build-isolation" not in script
    assert '--target "$TMP_DIR/package" .' not in script


def test_deploy_gates_runtime_inventory_imports_and_package_sizes_before_aws() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    gate = script.index(
        'for module_name in ("asyncpg", "openai", "pydantic", "handler")'
    )
    compressed = script.index("compressed_limit = 50 * 1024 * 1024")
    uncompressed = script.index("uncompressed_limit = 250 * 1024 * 1024")
    first_aws = script.index("aws sts get-caller-identity")
    assert gate < compressed < first_aws
    assert uncompressed < first_aws
    for forbidden in (
        '"bandit"',
        '"mypy"',
        '"pip-audit"',
        '"pytest"',
        '"pytest-asyncio"',
        '"ruff"',
        '"__pycache__"',
        '".pytest_cache"',
        '"tests"',
        '"_tests"',
        '"_testbase"',
        '".env"',
        '"credentials"',
        '".pyc"',
        '".o"',
        '".whl"',
    ):
        assert forbidden in script
    assert 'test_directories = {"test", "tests", "_tests", "_testbase"}' in script
    assert "shutil.rmtree(path)" in script
    assert 'python3.12 -B - "$TMP_DIR/package"' in script


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
        "aws lambda get-account-settings",
        "aws lambda get-function-concurrency",
        "UNRESERVED_ON_DEMAND",
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
    assert "put-function-concurrency" not in script


def test_concurrency_evidence_accepts_positive_unreserved_account(
    tmp_path: Path,
) -> None:
    completed = _run_concurrency_validator(tmp_path, _account_settings())
    assert completed.returncode == 0, completed.stderr
    records = completed.stdout.splitlines()
    assert records[0] == "10"
    assert re.fullmatch(r"[0-9a-f]{64}", records[1])


def test_concurrency_evidence_rejects_function_reservation(tmp_path: Path) -> None:
    completed = _run_concurrency_validator(
        tmp_path,
        _account_settings(),
        json.dumps({"ReservedConcurrentExecutions": 1}).encode(),
    )
    assert completed.returncode != 0
    assert "unexpected reserved concurrency" in completed.stderr


def test_concurrency_evidence_rejects_malformed_account_settings(
    tmp_path: Path,
) -> None:
    completed = _run_concurrency_validator(tmp_path, {"AccountLimit": {}})
    assert completed.returncode != 0
    assert "malformed account settings" in completed.stderr


def test_concurrency_evidence_rejects_zero_and_missing_quota(tmp_path: Path) -> None:
    zero = _run_concurrency_validator(tmp_path, _account_settings(0, 0))
    assert zero.returncode != 0
    assert "invalid account concurrency" in zero.stderr
    missing = _account_settings()
    assert isinstance(missing["AccountLimit"], dict)
    missing["AccountLimit"].pop("UnreservedConcurrentExecutions")
    absent = _run_concurrency_validator(tmp_path, missing)
    assert absent.returncode != 0
    assert "malformed account settings" in absent.stderr


def test_observed_concurrency_cost_cap_exceedance_blocks(tmp_path: Path) -> None:
    output = tmp_path / "pricing.json"
    until = (datetime.now(UTC) + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and embedded code
        [
            sys.executable,
            "-c",
            _embedded_python_containing("estimate exceeds cap"),
            "us-east-2",
            until,
            "0",
            "1",
            "0" * 64,
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "estimate exceeds cap" in completed.stderr
    assert not output.exists()


def test_concurrency_cost_gate_precedes_every_deployment_mutation() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    gate = script.index(
        'write_pricing_evidence "$UNRESERVED_CONCURRENCY" "$ACCOUNT_CONCURRENCY_DIGEST"'
    )
    mutations = (
        "aws iam put-role-policy",
        "aws lambda update-function-code",
        "aws lambda update-function-configuration",
        "aws lambda create-function ",
        "aws lambda create-function-url-config",
        "aws lambda add-permission",
    )
    assert all(gate < script.index(mutation) for mutation in mutations)


def test_pricing_input_is_concrete_canonical_and_current_contract() -> None:
    path = ROOT / "lambda/pricing-input.json"
    raw = path.read_bytes()
    value = json.loads(raw)
    assert raw == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert value["schema_version"] == "gam.aws-pricing.v1"
    assert value["architecture"] == "x86_64"
    assert value["aws_region"] == "us-east-2"
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
    assert "[[ \"$AWS_REGION\" == 'us-east-2' ]]" in smoke
    assert "[[ \"$AWS_REGION\" == 'us-east-2' ]]" in teardown


def test_deploy_region_is_exact_and_does_not_bind_database_region() -> None:
    script = (ROOT / "lambda/deploy.sh").read_text()
    assert "[[ \"$AWS_REGION\" == 'us-east-2' ]]" in script
    assert "us-east-1" not in script
    assert "DATABASE_URL" not in script


def test_obsolete_cluster_target_is_absent_from_executable_lambda_surface() -> None:
    handler = (ROOT / "lambda/handler.py").read_text()
    assert "kingly-dreamer" not in handler  # imported from the closed binding
    assert "from src.ccloud_tool import CLUSTER_NAME" in handler
