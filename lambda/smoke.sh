#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  printf '%s\n' 'lambda-smoke: positional arguments are forbidden' >&2
  exit 2
fi
: "${FUNCTION_URL:?FUNCTION_URL is required}"
: "${AWS_REGION:?AWS_REGION is required}"
[[ "$FUNCTION_URL" == https://*\.lambda-url.*.on.aws/ ]]
[[ "$AWS_REGION" =~ ^[a-z]{2}-[a-z]+-[0-9]$ ]]
BASE_URL="${FUNCTION_URL%/}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
chmod 0700 "$TMP_DIR"
umask 077
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_PAGER=''
SMOKE_START_MS="$(python3.12 -c 'import time; print(time.time_ns() // 1000000)')"

curl --fail --silent --show-error "$BASE_URL/health" \
  --output "$TMP_DIR/health.json"
PRESEED_STATUS="$(curl --silent --show-error \
  "$BASE_URL/v1/demo/maybe-novel" --output "$TMP_DIR/preseed.json" \
  --write-out '%{http_code}')"
[[ "$PRESEED_STATUS" == 404 ]]
aws lambda invoke --function-name governed-agent-memory-fn \
  --cli-binary-format raw-in-base64-out --log-type Tail \
  --payload file://lambda/smoke-process-task.json "$TMP_DIR/invoke.json" \
  > "$TMP_DIR/invoke-metadata.json"
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/governed-agent-memory-fn \
  --max-items 10 --no-paginate --output json > "$TMP_DIR/log-groups.json"

POLL_COUNT=0
while ((POLL_COUNT < 6)); do
  POLL_COUNT=$((POLL_COUNT + 1))
  SMOKE_END_MS="$(python3.12 -c 'import time; print(time.time_ns() // 1000000)')"
  aws logs filter-log-events \
    --log-group-name /aws/lambda/governed-agent-memory-fn \
    --start-time "$SMOKE_START_MS" --end-time "$SMOKE_END_MS" \
    --limit 100 --max-items 100 --no-paginate --output json \
    > "$TMP_DIR/log-events.json"
  if python3.12 - "$TMP_DIR/invoke.json" "$TMP_DIR/log-events.json" <<'PY'
import json,sys
invoke=json.load(open(sys.argv[1],encoding="utf-8"))
events=json.load(open(sys.argv[2],encoding="utf-8")).get("events",[])
application=invoke.get("request_id")
raise SystemExit(0 if application and any(application in str(item.get("message","")) for item in events) else 1)
PY
  then break; fi
  ((POLL_COUNT < 6)) && sleep 5
done

python3.12 - "$AWS_REGION" "$SMOKE_START_MS" "$SMOKE_END_MS" "$POLL_COUNT" \
  "$TMP_DIR/health.json" "$TMP_DIR/preseed.json" "$TMP_DIR/invoke.json" \
  "$TMP_DIR/invoke-metadata.json" "$TMP_DIR/log-groups.json" \
  "$TMP_DIR/log-events.json" <<'PY'
import base64,hashlib,json,re,sys
region,start,end,polls,*paths=sys.argv[1:]
health,preseed,invoke,metadata,groups,logs=(json.load(open(p,encoding="utf-8")) for p in paths)
if health != {"schema_version":"gam.lambda.v1","status":"ok","database":"reachable","request_id":health.get("request_id")}:
    raise SystemExit("lambda-smoke: health mismatch")
if preseed.get("error") != "PROFILE_NOT_READY": raise SystemExit("lambda-smoke: preseed mismatch")
required={"schema_version","operation","request_id","proposal_id","proposal_digest","evaluation_id","verdict","risk","operator_trace","evidence_gaps","dependencies","because_step_id","trace_digest"}
if set(invoke) != required: raise SystemExit("lambda-smoke: invocation mismatch")
if groups.get("nextToken") or [x.get("logGroupName") for x in groups.get("logGroups",[])] != ["/aws/lambda/governed-agent-memory-fn"]:
    raise SystemExit("lambda-smoke: log group mismatch")
tail=base64.b64decode(metadata.get("LogResult", ""), validate=True)
events=logs.get("events",[])
safe={"event_name","schema_version","aws_request_id","application_request_id_if_any","route_or_operation","status","duration_ms","proposal_id_if_any","evaluation_id_if_any","trace_digest_if_any","error_code_if_any"}
messages=[]
for item in events:
    message=item.get("message","")
    try: value=json.loads(message)
    except (TypeError,json.JSONDecodeError): continue
    if not isinstance(value,dict) or set(value)-safe: raise SystemExit("lambda-smoke: unsafe log shape")
    messages.append(value)
matched=[x for x in messages if x.get("application_request_id_if_any")==invoke["request_id"] and x.get("aws_request_id")]
if not matched: raise SystemExit("lambda-smoke: matching log absent")
scan=json.dumps([health,preseed,invoke,messages],sort_keys=True,separators=(",",":"))
if re.search(r"(?i)(postgres(?:ql)?://|api[_-]?key|authorization|bearer |select |insert |exception)",scan):
    raise SystemExit("lambda-smoke: secret detector blocked")
digest=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
evidence={"aws_region":region,"log_group_name":"/aws/lambda/governed-agent-memory-fn","log_group_response_digest":digest(groups),"smoke_start_ms":start,"smoke_end_ms":end,"poll_count":int(polls),"aws_request_id":matched[0]["aws_request_id"],"application_request_id":invoke["request_id"],"invoke_tail_decoded_digest":hashlib.sha256(tail).hexdigest(),"filtered_events_canonical_digest":digest(events),"matched_event_count":len(matched),"cloudwatch_secret_scan_result":"PASS"}
print("lambda-smoke: ok health_digest="+digest(health)+" invocation_digest="+digest(invoke)+" cloudwatch_log_evidence_digest="+digest({"schema":"gam.lambda-cloudwatch-evidence.v1",**evidence}))
PY
