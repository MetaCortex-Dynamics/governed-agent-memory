#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  printf '%s\n' 'lambda-deploy: positional arguments are forbidden' >&2
  exit 2
fi

required=(
  AWS_REGION LAMBDA_ROLE_NAME LAMBDA_ROLE_ARN APP_SECRET_ARN OPENAI_MODEL
  EXPECTED_AWS_ACCOUNT_ID DEPLOYED_UNTIL_UTC MAX_ACCEPTED_AWS_ESTIMATE_USD
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    printf '%s\n' "lambda-deploy: missing ${name}" >&2
    exit 2
  fi
done
[[ "$OPENAI_MODEL" == 'gpt-4.1-mini-2025-04-14' ]]
[[ "$AWS_REGION" == 'us-east-2' ]]
[[ "$EXPECTED_AWS_ACCOUNT_ID" =~ ^[0-9]{12}$ ]]
[[ "$LAMBDA_ROLE_NAME" =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]]
[[ "$LAMBDA_ROLE_ARN" == "arn:aws:iam::${EXPECTED_AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE_NAME}" ]]
[[ "$APP_SECRET_ARN" == "arn:aws:secretsmanager:${AWS_REGION}:${EXPECTED_AWS_ACCOUNT_ID}:secret:"* ]]

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
chmod 0700 "$TMP_DIR"
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_PAGER=''

python3.12 - "$AWS_REGION" "$DEPLOYED_UNTIL_UTC" \
  "$MAX_ACCEPTED_AWS_ESTIMATE_USD" "$TMP_DIR/pricing-evidence.json" <<'PY'
import hashlib, json, sys
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path

region, deployed_until, cap_text, output = sys.argv[1:]
path = Path("lambda/pricing-input.json")
raw = path.read_bytes()
value = json.loads(raw)
keys = {
    "schema_version", "aws_region", "architecture",
    "request_price_usd_per_million", "duration_price_usd_per_gb_second",
    "captured_at_utc", "effective_date", "source_url", "source_page_sha256",
}
if set(value) != keys or raw != json.dumps(value, sort_keys=True, separators=(",", ":")).encode():
    raise SystemExit("lambda-deploy: noncanonical pricing input")
if value["schema_version"] != "gam.aws-pricing.v1" or value["aws_region"] != region:
    raise SystemExit("lambda-deploy: pricing identity mismatch")
if value["architecture"] != "x86_64" or value["source_url"] != "https://aws.amazon.com/lambda/pricing/":
    raise SystemExit("lambda-deploy: pricing source mismatch")
if len(value["source_page_sha256"]) != 64:
    raise SystemExit("lambda-deploy: pricing source digest invalid")
parse = lambda item: datetime.strptime(item, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
captured, until, now = parse(value["captured_at_utc"]), parse(deployed_until), datetime.now(UTC)
if abs((now - captured).total_seconds()) > 86400:
    raise SystemExit("lambda-deploy: pricing input expired")
seconds = (until - now).total_seconds()
if not 0 < seconds <= 168 * 3600:
    raise SystemExit("lambda-deploy: deployment window invalid")
hours = int((seconds + 3599) // 3600)
try:
    request_price = Decimal(value["request_price_usd_per_million"])
    duration_price = Decimal(value["duration_price_usd_per_gb_second"])
    cap = Decimal(cap_text)
except (InvalidOperation, TypeError):
    raise SystemExit("lambda-deploy: invalid decimal") from None
if min(request_price, duration_price, cap) < 0:
    raise SystemExit("lambda-deploy: negative price")
request_rate = request_price / Decimal(1_000_000)
smoke = Decimal(100) * request_rate + Decimal(1500) * duration_price
window_seconds = Decimal(hours * 3600)
continuous_requests = Decimal(2) * (window_seconds / Decimal(30))
continuous = continuous_requests * request_rate + Decimal(2) * window_seconds * Decimal("0.5") * duration_price
round_up = lambda item: item.quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
if round_up(smoke) > cap or round_up(continuous) > cap:
    raise SystemExit("lambda-deploy: estimate exceeds cap")
digest_value = {"schema": "gam.aws-pricing.v1", **value}
evidence = {
    "architecture": "x86_64", "memory_gb": "0.5", "timeout_seconds": 30,
    "reserved_concurrency": 2, "planned_smoke_invocations": 100,
    "deployment_window_hours": hours,
    "regional_request_price": str(request_price),
    "regional_gb_second_price": str(duration_price),
    "planned_smoke_upper_bound_usd_unrounded": str(smoke),
    "planned_smoke_upper_bound_usd": str(round_up(smoke)),
    "continuous_timeout_upper_bound_usd_unrounded": str(continuous),
    "continuous_timeout_upper_bound_usd": str(round_up(continuous)),
    "estimate_timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "pricing_source_url": value["source_url"],
    "pricing_input_file_sha256": hashlib.sha256(raw).hexdigest(),
    "pricing_input_digest": hashlib.sha256(json.dumps(digest_value, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
}
Path(output).write_bytes(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode())
PY

python3.12 - "$APP_SECRET_ARN" "$TMP_DIR/iam-policy.json" \
  "$OPENAI_MODEL" "$DEPLOYED_UNTIL_UTC" "$TMP_DIR/environment.json" <<'PY'
import json, sys
from pathlib import Path

secret, policy_path, model, until, environment_path = sys.argv[1:]
template = json.loads(Path("lambda/iam-secrets-policy.template.json").read_text())
if template != {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"__APP_SECRET_ARN__"}]}:
    raise SystemExit("lambda-deploy: IAM template mismatch")
template["Statement"][0]["Resource"] = secret
Path(policy_path).write_bytes(json.dumps(template, sort_keys=True, separators=(",", ":")).encode())
environment = {"Variables": {
    "APP_SCHEMA_VERSION": "gam.lambda.v1", "APP_SECRET_ARN": secret,
    "DEPLOYED_UNTIL_UTC": until, "LOG_LEVEL": "INFO", "OPENAI_MODEL": model,
}}
Path(environment_path).write_bytes(json.dumps(environment, sort_keys=True, separators=(",", ":")).encode())
PY

mkdir --mode=0700 "$TMP_DIR/package"
cmp -s requirements.lock lambda/requirements.txt
python3.12 -m pip install --disable-pip-version-check --no-input \
  --only-binary=:all: --platform manylinux_2_28_x86_64 \
  --platform manylinux2014_x86_64 \
  --implementation cp --python-version 3.12 --abi cp312 --require-hashes \
  --requirement lambda/requirements.txt --target "$TMP_DIR/package"
python3.12 - "$TMP_DIR/package" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
dist_info = root / "asyncpg-0.31.0.dist-info"
wheel = dist_info / "WHEEL"
if not dist_info.is_dir() or not wheel.is_file():
    raise SystemExit("lambda-deploy: asyncpg wheel metadata missing")
tags = {
    line.removeprefix("Tag: ")
    for line in wheel.read_text(encoding="utf-8").splitlines()
    if line.startswith("Tag: ")
}
if tags != {"cp312-cp312-manylinux_2_28_x86_64"}:
    raise SystemExit("lambda-deploy: asyncpg wheel tag mismatch")
PY
python3.12 -m pip install --disable-pip-version-check --no-input \
  --no-build-isolation --no-deps --target "$TMP_DIR/package" .
install -m 0644 lambda/handler.py "$TMP_DIR/package/handler.py"
python3.12 - "$TMP_DIR/package" <<'PY'
import os, sys
from pathlib import Path
root = Path(sys.argv[1])
for path in root.rglob("*"):
    if path.is_symlink(): raise SystemExit("lambda-deploy: package symlink")
    if path.name in {".env", "preflight.env", "crdb-version.json"}:
        raise SystemExit("lambda-deploy: forbidden package path")
PY
(cd "$TMP_DIR/package" && python3.12 -m zipfile -c "$TMP_DIR/package.zip" .)
PACKAGE_SHA256="$(sha256sum "$TMP_DIR/package.zip" | cut -d' ' -f1)"

aws sts get-caller-identity --output json > "$TMP_DIR/identity.json"
aws iam get-role --role-name "$LAMBDA_ROLE_NAME" --output json > "$TMP_DIR/role.json"
aws iam list-attached-role-policies --role-name "$LAMBDA_ROLE_NAME" \
  --max-items 100 --no-paginate --output json > "$TMP_DIR/attached.json"
aws iam list-role-policies --role-name "$LAMBDA_ROLE_NAME" \
  --max-items 100 --no-paginate --output json > "$TMP_DIR/inline.json"

INLINE_PRESENT="$(python3.12 - "$EXPECTED_AWS_ACCOUNT_ID" "$LAMBDA_ROLE_ARN" \
  "$TMP_DIR/identity.json" "$TMP_DIR/role.json" "$TMP_DIR/attached.json" \
  "$TMP_DIR/inline.json" <<'PY'
import json, sys
account, arn, identity, role, attached, inline = sys.argv[1:]
load=lambda path: json.load(open(path, encoding="utf-8"))
if load(identity).get("Account") != account: raise SystemExit("lambda-deploy: account mismatch")
r=load(role).get("Role", {})
if r.get("Arn") != arn: raise SystemExit("lambda-deploy: role mismatch")
trust=r.get("AssumeRolePolicyDocument")
expected={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
if trust != expected: raise SystemExit("lambda-deploy: trust mismatch")
a=load(attached)
if a.get("IsTruncated") or sorted(x.get("PolicyArn") for x in a.get("AttachedPolicies",[])) != ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]:
    raise SystemExit("lambda-deploy: attached policies mismatch")
i=load(inline)
names=sorted(i.get("PolicyNames",[]))
if i.get("IsTruncated") or names not in ([], ["governed-agent-memory-secrets"]):
    raise SystemExit("lambda-deploy: inline policies mismatch")
print("yes" if names else "no")
PY
)"

if [[ "$INLINE_PRESENT" == yes ]]; then
  aws iam get-role-policy --role-name "$LAMBDA_ROLE_NAME" \
    --policy-name governed-agent-memory-secrets > "$TMP_DIR/current-policy.json"
  python3.12 - "$TMP_DIR/current-policy.json" "$TMP_DIR/iam-policy.json" <<'PY'
import json, sys, urllib.parse
current=json.load(open(sys.argv[1], encoding="utf-8")).get("PolicyDocument")
if isinstance(current,str): current=json.loads(urllib.parse.unquote(current))
desired=json.load(open(sys.argv[2], encoding="utf-8"))
if current != desired: raise SystemExit("lambda-deploy: existing inline policy mismatch")
PY
else
  aws iam put-role-policy --role-name "$LAMBDA_ROLE_NAME" \
    --policy-name governed-agent-memory-secrets \
    --policy-document "file://$TMP_DIR/iam-policy.json"
fi
aws iam get-role-policy --role-name "$LAMBDA_ROLE_NAME" \
  --policy-name governed-agent-memory-secrets > "$TMP_DIR/final-policy.json"
aws secretsmanager describe-secret --secret-id "$APP_SECRET_ARN" \
  --output json > "$TMP_DIR/secret-description.json"
python3.12 - "$TMP_DIR/final-policy.json" "$TMP_DIR/iam-policy.json" \
  "$TMP_DIR/secret-description.json" "$APP_SECRET_ARN" <<'PY'
import json,sys,urllib.parse
final,desired,description,arn=sys.argv[1:]
document=json.load(open(final,encoding="utf-8")).get("PolicyDocument")
if isinstance(document,str): document=json.loads(urllib.parse.unquote(document))
if document != json.load(open(desired,encoding="utf-8")):
    raise SystemExit("lambda-deploy: final inline policy mismatch")
if json.load(open(description,encoding="utf-8")).get("ARN") != arn:
    raise SystemExit("lambda-deploy: secret identity mismatch")
PY

if aws lambda get-function --function-name governed-agent-memory-fn \
  > "$TMP_DIR/function-before.json" 2> "$TMP_DIR/function-before.err"; then
  python3.12 - "$TMP_DIR/function-before.json" "$LAMBDA_ROLE_ARN" <<'PY'
import json,sys
configuration=json.load(open(sys.argv[1],encoding="utf-8")).get("Configuration",{})
if configuration.get("FunctionName") != "governed-agent-memory-fn" or configuration.get("Role") != sys.argv[2]:
    raise SystemExit("lambda-deploy: existing function identity mismatch")
PY
  aws lambda update-function-code --function-name governed-agent-memory-fn \
    --zip-file "fileb://$TMP_DIR/package.zip" --architectures x86_64
  aws lambda wait function-updated-v2 --function-name governed-agent-memory-fn
  aws lambda update-function-configuration --function-name governed-agent-memory-fn \
    --runtime python3.12 --role "$LAMBDA_ROLE_ARN" --handler handler.lambda_handler \
    --timeout 30 --memory-size 512 --ephemeral-storage Size=512 \
    --environment "file://$TMP_DIR/environment.json" --logging-config LogFormat=JSON
  aws lambda wait function-updated-v2 --function-name governed-agent-memory-fn
else
  grep -q 'ResourceNotFoundException' "$TMP_DIR/function-before.err" || {
    printf '%s\n' 'lambda-deploy: function lookup failed' >&2
    exit 1
  }
  aws lambda create-function --function-name governed-agent-memory-fn \
    --package-type Zip --runtime python3.12 --architectures x86_64 \
    --role "$LAMBDA_ROLE_ARN" --handler handler.lambda_handler \
    --zip-file "fileb://$TMP_DIR/package.zip" --timeout 30 --memory-size 512 \
    --ephemeral-storage Size=512 --environment "file://$TMP_DIR/environment.json" \
    --logging-config LogFormat=JSON
  aws lambda wait function-active-v2 --function-name governed-agent-memory-fn
fi

if ! aws lambda get-function-url-config --function-name governed-agent-memory-fn \
  > "$TMP_DIR/url.json" 2> "$TMP_DIR/url.err"; then
  grep -q 'ResourceNotFoundException' "$TMP_DIR/url.err" || {
    printf '%s\n' 'lambda-deploy: URL lookup failed' >&2
    exit 1
  }
  aws lambda create-function-url-config --function-name governed-agent-memory-fn \
    --auth-type NONE --invoke-mode BUFFERED > "$TMP_DIR/url.json"
  aws lambda add-permission --function-name governed-agent-memory-fn \
    --statement-id UrlPolicyInvokeURL --action lambda:InvokeFunctionUrl \
    --principal '*' --function-url-auth-type NONE
  aws lambda add-permission --function-name governed-agent-memory-fn \
    --statement-id UrlPolicyInvokeFunction --action lambda:InvokeFunction \
    --principal '*' --invoked-via-function-url
else
  python3.12 - "$TMP_DIR/url.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
if value.get("AuthType") != "NONE" or value.get("InvokeMode") != "BUFFERED":
    raise SystemExit("lambda-deploy: existing URL mismatch")
PY
fi
aws lambda get-policy --function-name governed-agent-memory-fn > "$TMP_DIR/function-policy.json"
aws lambda get-function-configuration --function-name governed-agent-memory-fn \
  > "$TMP_DIR/function-configuration.json"
aws lambda put-function-concurrency --function-name governed-agent-memory-fn \
  --reserved-concurrent-executions 2
aws lambda get-function-concurrency --function-name governed-agent-memory-fn \
  > "$TMP_DIR/concurrency.json"

python3.12 - "$TMP_DIR/function-configuration.json" "$TMP_DIR/url.json" \
  "$TMP_DIR/function-policy.json" "$TMP_DIR/concurrency.json" <<'PY'
import json, sys
configuration,url,policy,concurrency=(json.load(open(p,encoding="utf-8")) for p in sys.argv[1:])
if configuration.get("Runtime") != "python3.12" or configuration.get("Architectures") != ["x86_64"]:
    raise SystemExit("lambda-deploy: runtime readback mismatch")
if url.get("AuthType") != "NONE" or url.get("InvokeMode") != "BUFFERED":
    raise SystemExit("lambda-deploy: URL readback mismatch")
statements=json.loads(policy.get("Policy","{}")).get("Statement",[])
if {item.get("Sid") for item in statements} != {"UrlPolicyInvokeURL","UrlPolicyInvokeFunction"}:
    raise SystemExit("lambda-deploy: function policy mismatch")
if concurrency.get("ReservedConcurrentExecutions") != 2:
    raise SystemExit("lambda-deploy: concurrency mismatch")
PY

printf '%s\n' "lambda-deploy: ok package_sha256=${PACKAGE_SHA256}"
