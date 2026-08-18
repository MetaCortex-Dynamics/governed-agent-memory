#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  printf '%s\n' 'lambda-teardown: positional arguments are forbidden' >&2
  exit 2
fi
: "${AWS_REGION:?AWS_REGION is required}"
: "${EXPECTED_AWS_ACCOUNT_ID:?EXPECTED_AWS_ACCOUNT_ID is required}"
: "${LAMBDA_ROLE_NAME:?LAMBDA_ROLE_NAME is required}"
: "${EXPECTED_LAMBDA_FUNCTION_ARN:?EXPECTED_LAMBDA_FUNCTION_ARN is required}"
: "${EXPECTED_FUNCTION_URL:?EXPECTED_FUNCTION_URL is required}"
: "${TEARDOWN_PROMOTION_DIGEST:?TEARDOWN_PROMOTION_DIGEST is required}"
[[ "$AWS_REGION" == 'us-east-2' ]]
[[ "$TEARDOWN_PROMOTION_DIGEST" =~ ^[0-9a-f]{64}$ ]]
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_PAGER=''
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
chmod 0700 "$TMP_DIR"
aws sts get-caller-identity --output json > "$TMP_DIR/identity.json"
aws lambda get-function --function-name governed-agent-memory-fn \
  > "$TMP_DIR/function.json"
aws lambda get-function-url-config --function-name governed-agent-memory-fn \
  > "$TMP_DIR/url.json"
python3.12 - "$EXPECTED_AWS_ACCOUNT_ID" "$EXPECTED_LAMBDA_FUNCTION_ARN" \
  "$EXPECTED_FUNCTION_URL" "$TMP_DIR/identity.json" "$TMP_DIR/function.json" \
  "$TMP_DIR/url.json" <<'PY'
import json,sys
account,arn,url,*paths=sys.argv[1:]
identity,function,url_value=(json.load(open(p,encoding="utf-8")) for p in paths)
if identity.get("Account") != account: raise SystemExit("lambda-teardown: account mismatch")
if function.get("Configuration",{}).get("FunctionArn") != arn: raise SystemExit("lambda-teardown: function mismatch")
if url_value.get("FunctionUrl") != url: raise SystemExit("lambda-teardown: URL mismatch")
PY
aws lambda delete-function-url-config --function-name governed-agent-memory-fn
aws lambda delete-function --function-name governed-agent-memory-fn
aws iam delete-role-policy --role-name "$LAMBDA_ROLE_NAME" \
  --policy-name governed-agent-memory-secrets
printf '%s\n' 'lambda-teardown: ok'
