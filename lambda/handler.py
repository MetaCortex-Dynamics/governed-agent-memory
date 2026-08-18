"""Fail-closed AWS Lambda boundary for public reads and signed proposals."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import asdict, is_dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Literal, NoReturn, cast
from urllib.parse import parse_qsl, quote, urlsplit
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import openai

import src.agent as agent
from src.agent import (
    MODEL_SNAPSHOT,
    AgentBlockedResult,
    AgentConfig,
    AgentGateBlockedResult,
    AgentResult,
)
from src.ccloud_tool import CLUSTER_NAME
from src.config import ConfigError
from src.governance import default_rule_config
from src.memory import AppMemory, _snapshot_from_json  # noqa: PLC2701
from src.models import CheckResult, ToolEvidence
from src.operators import OperatorFamily
from src.traces import validate_check_result, validate_snapshot
from src.witnesses import Witness

SCHEMA_VERSION = "gam.lambda.v1"
MAX_EVENT_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 6 * 1024 * 1024
DEMO_PROFILES = {
    "/v1/demo/maybe-novel": "gam-demo-maybe-v1",
    "/v1/demo/no-exclusion": "gam-demo-no-v1",
    "/v1/demo/iff-dependency": "gam-demo-iff-v1",
    "/v1/demo/consequence-warning": "gam-demo-consequence-v1",
}
_DIRECT_KEYS = frozenset(
    {
        "schema_version",
        "operation",
        "request_id",
        "task_description",
        "agent_id",
        "session_id",
        "requester_ref",
    }
)
_SECRET_KEYS = frozenset({"DATABASE_URL_APP", "OPENAI_API_KEY"})
_SAFE_LOG_KEYS = frozenset(
    {
        "event_name",
        "schema_version",
        "aws_request_id",
        "application_request_id_if_any",
        "route_or_operation",
        "status",
        "duration_ms",
        "proposal_id_if_any",
        "evaluation_id_if_any",
        "trace_digest_if_any",
        "error_code_if_any",
    }
)
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_HEADERS = {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
}
_SECRET_CACHE: dict[str, str] | None = None
_SECRET_LOCK = threading.Lock()
_AGENT_LOCK = threading.Lock()
_SQLSTATE = re.compile(r"^[0-9A-Z]{5}$")
_COCKROACH_ROOT_SHA256 = (
    "04cc3f18076b845976384175c7ea45b127de9b66c756ac8fdb148617b9c57a43"
)
_CERTIFICATE_BUNDLE = re.compile(
    rb"(?:-----BEGIN CERTIFICATE-----\n"
    rb"(?:[A-Za-z0-9+/=]{1,76}\n)+"
    rb"-----END CERTIFICATE-----(?:\n|\Z))+\Z"
)


class _SecretAccessFailure(RuntimeError):
    """Secrets Manager access failed without retaining provider context."""


class _SecretContentFailure(RuntimeError):
    """Secret content failed its exact local contract."""


class _HealthSqlFailure(RuntimeError):
    """The health query returned no canonical success witness."""


class _DatabaseTlsRootFailure(RuntimeError):
    """The packaged TLS trust root failed its exact runtime binding."""


class BoundaryError(ValueError):
    """Stable public-boundary failure without sensitive context."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _fail(code: str, status: int = 400) -> NoReturn:
    raise BoundaryError(code, status)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.name if isinstance(value.value, int) else value.value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _response(status: int, body: dict[str, object]) -> dict[str, object]:
    encoded = _canonical(body)
    if len(encoded.encode("utf-8")) > MAX_RESPONSE_BYTES:
        status = 503
        encoded = _canonical(
            {"schema_version": SCHEMA_VERSION, "error": "INTERNAL_BLOCKED"}
        )
    return {
        "statusCode": status,
        "headers": dict(_HEADERS),
        "isBase64Encoded": False,
        "body": encoded,
    }


def _error_response(error: BoundaryError) -> dict[str, object]:
    return _response(
        error.status, {"schema_version": SCHEMA_VERSION, "error": error.code}
    )


def _request_id(context: object, event: dict[str, object]) -> str:
    aws_id = getattr(context, "aws_request_id", None)
    if isinstance(aws_id, str) and aws_id:
        return aws_id
    request = event.get("requestContext")
    if isinstance(request, dict) and isinstance(request.get("requestId"), str):
        return cast(str, request["requestId"])
    return "unavailable"


def _safe_log(**values: object) -> None:
    record = {key: values[key] for key in _SAFE_LOG_KEYS if key in values}
    logging.getLogger("gam.lambda").info(_canonical(record))


def _load_secret() -> dict[str, str]:
    global _SECRET_CACHE
    with _SECRET_LOCK:
        if _SECRET_CACHE is not None:
            return dict(_SECRET_CACHE)
        arn = os.environ.get("APP_SECRET_ARN")
        if not arn or arn != arn.strip():
            raise _SecretAccessFailure("secret identifier unavailable")
        try:
            import boto3  # type: ignore[import-not-found]  # AWS runtime SDK

            response = boto3.client("secretsmanager").get_secret_value(SecretId=arn)
        except Exception:
            raise _SecretAccessFailure("secret access unavailable") from None
        if not isinstance(response, dict):
            raise _SecretContentFailure("secret shape invalid")
        raw = response.get("SecretString")
        if not isinstance(raw, str):
            raise _SecretContentFailure("secret value unavailable")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raise _SecretContentFailure("secret shape invalid") from None
        if (
            not isinstance(parsed, dict)
            or frozenset(parsed) != _SECRET_KEYS
            or any(
                not isinstance(parsed[key], str) or not parsed[key] for key in parsed
            )
        ):
            raise _SecretContentFailure("secret shape invalid")
        _SECRET_CACHE = cast(dict[str, str], parsed)
        return dict(_SECRET_CACHE)


def _agent_config() -> AgentConfig:
    if os.environ.get("OPENAI_MODEL") != MODEL_SNAPSHOT:
        raise RuntimeError("model identity unavailable")
    return AgentConfig(
        cast(Literal["gpt-4.1-mini-2025-04-14"], MODEL_SNAPSHOT),
        openai.__version__,
        "proposal-draft/1.1",
        Decimal("20"),
        2,
        4096,
        5,
        Decimal("0.85000000"),
        default_rule_config().rule_config_digest,
    )


def _validated_cockroach_root(
    path: Path | None = None,
    expected_digest: str = _COCKROACH_ROOT_SHA256,
) -> Path:
    candidate = Path(__file__).with_name("cockroach-root.crt") if path is None else path
    if candidate.is_symlink() or not candidate.is_file():
        raise _DatabaseTlsRootFailure("database TLS root unavailable")
    try:
        raw = candidate.read_bytes()
    except OSError:
        raise _DatabaseTlsRootFailure("database TLS root unavailable") from None
    if (
        b"\r" in raw
        or b"PRIVATE KEY" in raw
        or _CERTIFICATE_BUNDLE.fullmatch(raw) is None
    ):
        raise _DatabaseTlsRootFailure("database TLS root invalid")
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise _DatabaseTlsRootFailure("database TLS root mismatch")
    try:
        ssl.create_default_context(cadata=raw.decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError, ValueError):
        raise _DatabaseTlsRootFailure("database TLS root invalid") from None
    return candidate.resolve(strict=True)


def _database_url_with_root(value: str) -> str:
    try:
        parsed = urlsplit(value)
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except (TypeError, ValueError):
        raise _DatabaseTlsRootFailure("database TLS URL invalid") from None
    ssl_modes = [item for name, item in pairs if name == "sslmode"]
    if ssl_modes != ["verify-full"] or any(name == "sslrootcert" for name, _ in pairs):
        raise _DatabaseTlsRootFailure("database TLS URL conflict")
    certificate = quote(str(_validated_cockroach_root()), safe="")
    prefix, marker, fragment = value.partition("#")
    suffix = marker + fragment if marker else ""
    return f"{prefix}&sslrootcert={certificate}{suffix}"


async def _with_secret_environment(operation: Any) -> object:
    bindings = _load_secret()
    runtime_bindings = dict(bindings)
    runtime_bindings["DATABASE_URL_APP"] = _database_url_with_root(
        bindings["DATABASE_URL_APP"]
    )
    previous = {key: os.environ.get(key) for key in _SECRET_KEYS}
    try:
        os.environ.update(runtime_bindings)
        return await operation()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run(coro: Any) -> object:
    return asyncio.run(coro)


async def _health() -> None:
    async def operation() -> None:
        memory = AppMemory()
        try:
            async with memory.transaction() as connection:
                if await connection.fetchrow("SELECT 1 AS reachable") is None:
                    raise _HealthSqlFailure("database unavailable")
        finally:
            await memory.close()

    await _with_secret_environment(operation)


def _health_failure_code(error: BaseException) -> str:
    if isinstance(error, _SecretAccessFailure):
        return "SECRET_ACCESS_FAILED"
    if isinstance(error, _SecretContentFailure):
        return "SECRET_CONTENT_FAILED"
    if isinstance(error, ConfigError):
        return "DB_CONFIG_FAILED"
    if isinstance(error, _DatabaseTlsRootFailure):
        return "DB_TLS_FAILED"
    if isinstance(error, socket.gaierror):
        return "DB_DNS_FAILED"
    if isinstance(error, (ssl.CertificateError, ssl.SSLError)):
        return "DB_TLS_FAILED"
    if isinstance(error, (ConnectionError, TimeoutError, OSError)):
        return "DB_NETWORK_FAILED"
    if isinstance(error, _HealthSqlFailure):
        return "DB_SQL_FAILED"
    if isinstance(error, asyncpg.PostgresError):
        sqlstate = getattr(error, "sqlstate", None)
        if not isinstance(sqlstate, str) or _SQLSTATE.fullmatch(sqlstate) is None:
            return "DB_CONNECT_FAILED"
        if sqlstate.startswith("28"):
            return "DB_AUTH_FAILED"
        if sqlstate.startswith("08"):
            return "DB_CONNECT_FAILED"
        return "DB_SQL_FAILED"
    return "DB_CONNECT_FAILED"


async def _demo(profile: str) -> tuple[object, CheckResult]:
    async def operation() -> tuple[object, CheckResult]:
        memory = AppMemory()
        try:
            async with memory.transaction() as connection:
                rows = await connection.fetch(
                    "SELECT id, proposal_id, trace_digest, input_snapshot "
                    "FROM gate_evaluations WHERE profile_version = $1 "
                    "AND status = 'FINALIZED' ORDER BY id LIMIT 2",
                    profile,
                )
            if not rows:
                raise BoundaryError("PROFILE_NOT_READY", 404)
            if len(rows) != 1:
                raise BoundaryError("DIGEST_MISMATCH", 409)
            row = rows[0]
            result = await memory.get_evaluation(str(row["id"]))
            proposal = await memory.get_proposal(str(row["proposal_id"]))
            snapshot = validate_snapshot(_snapshot_from_json(row["input_snapshot"]))
            if (
                not isinstance(result, CheckResult)
                or validate_check_result(result).trace_digest
                != str(row["trace_digest"])
                or result.profile_version != profile
                or snapshot.profile_version != profile
                or snapshot.evaluation_id != result.evaluation_id
                or snapshot.proposal.proposal_id != proposal.proposal_id
                or snapshot.proposal.proposal_digest != proposal.proposal_digest
            ):
                raise BoundaryError("DIGEST_MISMATCH", 409)
            return proposal, result
        finally:
            await memory.close()

    return cast(tuple[object, CheckResult], await _with_secret_environment(operation))


def _filters(raw: str) -> tuple[OperatorFamily | None, Witness | None]:
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        _fail("INVALID_FILTER")
    if len(pairs) > 2 or len({key for key, _ in pairs}) != len(pairs):
        _fail("INVALID_FILTER")
    if any(key not in {"operator", "witness"} or not value for key, value in pairs):
        _fail("INVALID_FILTER")
    values = dict(pairs)
    try:
        family = OperatorFamily(values["operator"]) if "operator" in values else None
        witness = Witness(values["witness"]) if "witness" in values else None
    except ValueError:
        _fail("INVALID_FILTER")
    return family, witness


def _demo_body(
    proposal: object,
    result: CheckResult,
    family: OperatorFamily | None,
    witness: Witness | None,
    request_id: str,
) -> dict[str, object]:
    matching_steps = [
        step.step_id
        for step in result.operator_trace
        if family is None or step.family is family
    ]
    matching_gaps = [
        gap.gap_id
        for gap in result.evidence_gaps
        if witness is None or gap.witness is witness
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "profile_version": result.profile_version,
        "proposal_id": cast(Any, proposal).proposal_id,
        "evaluation_id": result.evaluation_id,
        "verdict": result.verdict.name,
        "risk": result.risk.value,
        "operator_trace": _jsonable(result.operator_trace),
        "evidence_gaps": _jsonable(result.evidence_gaps),
        "dependencies": _jsonable(result.dependencies),
        "because_step_id": result.because_step_id,
        "trace_digest": result.trace_digest,
        "canonical_digest_verified": True,
        "matching_step_ids": matching_steps,
        "matching_gap_ids": matching_gaps,
        "request_id": request_id,
    }


def _public(event: dict[str, object], context: object) -> dict[str, object]:
    request_context = event.get("requestContext")
    http = request_context.get("http") if isinstance(request_context, dict) else None
    path = event.get("rawPath")
    method = http.get("method") if isinstance(http, dict) else None
    if method != "GET":
        _fail("METHOD_NOT_ALLOWED", 405)
    if event.get("body") not in (None, "") or event.get("isBase64Encoded") is not False:
        _fail("INVALID_ENVELOPE")
    if not isinstance(path, str):
        _fail("INVALID_ENVELOPE")
    request_id = _request_id(context, event)
    if path == "/health":
        if event.get("rawQueryString") not in (None, ""):
            _fail("INVALID_FILTER")
        try:
            _run(_health())
        except Exception as error:
            if isinstance(error, BoundaryError):
                raise
            _safe_log(
                event_name="health_dependency",
                schema_version=SCHEMA_VERSION,
                route_or_operation="/health",
                status="BLOCKED",
                error_code_if_any=_health_failure_code(error),
            )
            _fail("DATABASE_UNAVAILABLE", 503)
        return _response(
            200,
            {
                "schema_version": SCHEMA_VERSION,
                "status": "ok",
                "database": "reachable",
                "request_id": request_id,
            },
        )
    profile = DEMO_PROFILES.get(path)
    if profile is None:
        _fail("NOT_FOUND", 404)
    raw_query = event.get("rawQueryString", "")
    if not isinstance(raw_query, str):
        _fail("INVALID_FILTER")
    family, witness = _filters(raw_query)
    try:
        proposal, result = cast(tuple[object, CheckResult], _run(_demo(profile)))
    except BoundaryError:
        raise
    except Exception:
        _fail("DATABASE_UNAVAILABLE", 503)
    return _response(200, _demo_body(proposal, result, family, witness, request_id))


def _direct_input(event: dict[str, object]) -> dict[str, str]:
    if frozenset(event) != _DIRECT_KEYS or event.get("operation") != "process_task":
        _fail("INVALID_ENVELOPE")
    result: dict[str, str] = {}
    for key in _DIRECT_KEYS:
        value = event.get(key)
        if not isinstance(value, str) or not value or value != value.strip():
            _fail("INVALID_ENVELOPE")
        result[key] = value
    try:
        if str(UUID(result["request_id"])) != result["request_id"]:
            _fail("INVALID_ENVELOPE")
    except ValueError:
        _fail("INVALID_ENVELOPE")
    if len(result["task_description"].encode("utf-8")) > 4096 or any(
        _REF.fullmatch(result[key]) is None
        for key in ("agent_id", "session_id", "requester_ref")
    ):
        _fail("INVALID_ENVELOPE")
    return result


async def _agent_call(values: dict[str, str]) -> object:
    memory = AppMemory()
    try:
        evidence = await memory.get_latest_unexpired_tool_evidence(CLUSTER_NAME)

        async def provider(**_: object) -> ToolEvidence:
            return evidence

        old_memory, old_capture = agent._MEMORY, agent._CAPTURE  # noqa: SLF001
        agent._MEMORY, agent._CAPTURE = memory, provider  # noqa: SLF001
        try:
            return await agent.process_task(
                values["task_description"],
                request_id=values["request_id"],
                agent_id=values["agent_id"],
                session_id=values["session_id"],
                requester_ref=values["requester_ref"],
                config=_agent_config(),
            )
        finally:
            agent._MEMORY, agent._CAPTURE = old_memory, old_capture  # noqa: SLF001
    finally:
        await memory.close()


def _direct(event: dict[str, object]) -> dict[str, object]:
    values = _direct_input(event)
    try:
        with _AGENT_LOCK:
            result = _run(_with_secret_environment(lambda: _agent_call(values)))
    except Exception:
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": "process_task",
            "request_id": values["request_id"],
            "status": "BLOCKED",
            "stage": "PERSISTENCE",
            "error_code": "RUNTIME_UNAVAILABLE",
            "safe_message": "proposal processing is unavailable",
            "attempt_digest": "0" * 64,
        }
    if isinstance(result, AgentBlockedResult):
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": "process_task",
            "request_id": result.request_id,
            "status": "BLOCKED",
            "stage": result.stage,
            "error_code": result.error_code,
            "safe_message": result.safe_message,
            "attempt_digest": result.attempt_digest,
        }
    if isinstance(result, AgentGateBlockedResult):
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": "process_task",
            "request_id": values["request_id"],
            "status": "BLOCKED",
            "stage": "GATE",
            "proposal_id": result.proposal_id,
            "proposal_digest": result.proposal_digest,
            "evaluation_id": result.evaluation_id,
            **cast(dict[str, object], _jsonable(result.blocked_result)),
        }
    accepted = cast(AgentResult, result)
    checked = accepted.check_result
    return {
        "schema_version": SCHEMA_VERSION,
        "operation": "process_task",
        "request_id": values["request_id"],
        "proposal_id": accepted.proposal_id,
        "proposal_digest": accepted.proposal_digest,
        "evaluation_id": accepted.evaluation_id,
        "verdict": checked.verdict.name,
        "risk": checked.risk.value,
        "operator_trace": _jsonable(checked.operator_trace),
        "evidence_gaps": _jsonable(checked.evidence_gaps),
        "dependencies": _jsonable(checked.dependencies),
        "because_step_id": checked.because_step_id,
        "trace_digest": accepted.trace_digest,
    }


def lambda_handler(event: dict[str, object], context: object) -> dict[str, object]:
    """Handle one payload-v2 public read or one IAM-signed proposal request."""
    started = time.monotonic_ns()
    aws_id = _request_id(context, event) if isinstance(event, dict) else "unavailable"
    route = "invalid"
    status = "BLOCKED"
    error_code: str | None = None
    response: dict[str, object]
    try:
        if not isinstance(event, dict):
            _fail("INVALID_ENVELOPE")
        try:
            encoded_size = len(_canonical(event).encode("utf-8"))
        except (TypeError, ValueError):
            _fail("INVALID_ENVELOPE")
        if encoded_size > MAX_EVENT_BYTES:
            _fail("PAYLOAD_TOO_LARGE", 413)
        public = event.get("version") == "2.0"
        direct = event.get("schema_version") == SCHEMA_VERSION
        if public == direct:
            _fail("INVALID_ENVELOPE")
        if public:
            route = str(event.get("rawPath", "invalid"))
            response = _public(event, context)
            status = str(response["statusCode"])
        else:
            route = str(event.get("operation", "invalid"))
            response = _direct(event)
            status = str(response.get("status", "OK"))
            error_code = cast(str | None, response.get("error_code"))
    except BoundaryError as error:
        error_code = error.code
        response = _error_response(error)
        status = str(error.status)
    except Exception:
        error_code = "INTERNAL_BLOCKED"
        response = _error_response(BoundaryError(error_code, 503))
        status = "503"
    duration_ms = (time.monotonic_ns() - started) // 1_000_000
    _safe_log(
        event_name="lambda_request",
        schema_version=SCHEMA_VERSION,
        aws_request_id=aws_id,
        application_request_id_if_any=(
            event.get("request_id") if isinstance(event, dict) else None
        ),
        route_or_operation=route,
        status=status,
        duration_ms=duration_ms,
        proposal_id_if_any=response.get("proposal_id"),
        evaluation_id_if_any=response.get("evaluation_id"),
        trace_digest_if_any=response.get("trace_digest"),
        error_code_if_any=error_code,
    )
    return response


__all__ = ["lambda_handler"]
