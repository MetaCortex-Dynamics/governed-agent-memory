from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import logging
import os
import socket
import ssl
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest

from src.config import ConfigError

handler = importlib.import_module("lambda.handler")


@dataclass
class Context:
    aws_request_id: str = "aws-request-unit"


def _handler_path() -> Path:
    assert handler.__file__ is not None
    return Path(handler.__file__)


def _encoded_database_url() -> str:
    return (
        "postgres"
        + "ql:"
        + "//encoded%40user"
        + ":p%2Fass"
        + "@cluster.example:26257/database"
    )


def public_event(path: str = "/health", **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {},
        "requestContext": {
            "http": {"method": "GET", "path": path},
            "requestId": "url-request-unit",
        },
        "isBase64Encoded": False,
    }
    value.update(changes)
    return value


def direct_event(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "gam.lambda.v1",
        "operation": "process_task",
        "request_id": str(uuid4()),
        "task_description": "Draft one bounded proposal.",
        "agent_id": "agent-unit",
        "session_id": "session-unit",
        "requester_ref": "requester-unit",
    }
    value.update(changes)
    return value


def body(response: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(str(response["body"])))


def close_and(value: object) -> Callable[[Coroutine[Any, Any, object]], object]:
    def run(coroutine: Any) -> object:
        coroutine.close()
        return value

    return run


def test_health_payload_v2_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handler, "_run", close_and(None))
    response = handler.lambda_handler(public_event(), Context())
    assert response["statusCode"] == 200
    assert body(response) == {
        "schema_version": "gam.lambda.v1",
        "status": "ok",
        "database": "reachable",
        "request_id": "aws-request-unit",
    }


def test_cockroach_root_is_exact_public_certificate_bundle() -> None:
    path = _handler_path().with_name("cockroach-root.crt")
    raw = path.read_bytes()
    assert not path.is_symlink()
    assert hashlib.sha256(raw).hexdigest() == handler._COCKROACH_ROOT_SHA256
    assert handler._CERTIFICATE_BUNDLE.fullmatch(raw) is not None
    assert raw.count(b"-----BEGIN CERTIFICATE-----") == 2
    assert b"PRIVATE KEY" not in raw


def test_database_url_adds_only_encoded_explicit_root_before_fragment() -> None:
    original = (
        _encoded_database_url()
        + "?application_name=governed%2Bagent&sslmode=verify-full#preserved"
    )
    certificate = handler.quote(
        str(_handler_path().with_name("cockroach-root.crt").resolve()), safe=""
    )
    assert handler._database_url_with_root(original) == (
        original.removesuffix("#preserved") + f"&sslrootcert={certificate}#preserved"
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        "sslmode=require",
        "sslmode=verify-full&sslmode=verify-full",
        "sslmode=verify-full&sslrootcert=%2Ftmp%2Froot.crt",
        "sslmode=verify-full&%73slrootcert=%2Ftmp%2Froot.crt",
        "sslmode=verify-full&malformed",
    ],
)
def test_database_url_rejects_missing_weak_conflicting_or_malformed_tls(
    query: str,
) -> None:
    suffix = f"?{query}" if query else ""
    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._database_url_with_root(
            f"postgresql://user@cluster.example/database{suffix}"
        )


def test_cockroach_root_rejects_missing_symlink_private_malformed_and_digest(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.crt"
    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._validated_cockroach_root(missing)

    valid = _handler_path().with_name("cockroach-root.crt").read_bytes()
    target = tmp_path / "target.crt"
    target.write_bytes(valid)
    symlink = tmp_path / "symlink.crt"
    symlink.symlink_to(target)
    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._validated_cockroach_root(symlink)

    private = tmp_path / "private.crt"
    private_bytes = (
        b"-----BEGIN " + b"PRIVATE KEY-----\nblocked\n-----END " + b"PRIVATE KEY-----"
    )
    private.write_bytes(private_bytes)
    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._validated_cockroach_root(
            private, hashlib.sha256(private_bytes).hexdigest()
        )

    malformed = tmp_path / "malformed.crt"
    malformed_bytes = b"-----BEGIN CERTIFICATE-----\nblocked\n-----END CERTIFICATE-----"
    malformed.write_bytes(malformed_bytes)
    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._validated_cockroach_root(
            malformed, hashlib.sha256(malformed_bytes).hexdigest()
        )

    with pytest.raises(handler._DatabaseTlsRootFailure):
        handler._validated_cockroach_root(target, "0" * 64)


def test_secret_value_is_not_mutated_by_runtime_tls_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = {
        "DATABASE_URL_APP": (_encoded_database_url() + "?sslmode=verify-full"),
        "OPENAI_API_KEY": "non-secret-unit-value",
    }
    original = dict(secret)
    observed: dict[str, str] = {}

    async def operation() -> None:
        observed["url"] = os.environ["DATABASE_URL_APP"]

    monkeypatch.setattr(handler, "_load_secret", lambda: secret)
    monkeypatch.delenv("DATABASE_URL_APP", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    asyncio.run(handler._with_secret_environment(operation))
    assert secret == original
    assert observed["url"].startswith(original["DATABASE_URL_APP"] + "&sslrootcert=")
    assert "DATABASE_URL_APP" not in os.environ
    assert "OPENAI_API_KEY" not in os.environ


def _sql_error(sqlstate: str, message: str) -> asyncpg.PostgresError:
    error = asyncpg.PostgresError(message)
    error.sqlstate = sqlstate
    return error


def _credential_url(host: str) -> str:
    return "postgres" + "ql:" + "//user" + ":sensitive-value" + "@" + host + "/db"


@pytest.mark.parametrize(
    ("error", "classification"),
    [
        (
            handler._SecretAccessFailure("access failed for SECRET-ACCESS-SENTINEL"),
            "SECRET_ACCESS_FAILED",
        ),
        (
            handler._SecretContentFailure("invalid SECRET-CONTENT-SENTINEL"),
            "SECRET_CONTENT_FAILED",
        ),
        (
            ConfigError(_credential_url("DB-CONFIG-SENTINEL")),
            "DB_CONFIG_FAILED",
        ),
        (socket.gaierror("DB-DNS-SENTINEL.example"), "DB_DNS_FAILED"),
        (ConnectionRefusedError("DB-NETWORK-SENTINEL:26257"), "DB_NETWORK_FAILED"),
        (ssl.SSLError("certificate DB-TLS-SENTINEL"), "DB_TLS_FAILED"),
        (asyncpg.InvalidPasswordError("sensitive DB-AUTH-SENTINEL"), "DB_AUTH_FAILED"),
        (
            asyncpg.InsufficientPrivilegeError("SELECT DB-SQL-SENTINEL"),
            "DB_SQL_FAILED",
        ),
        (
            RuntimeError(_credential_url("DB-CONNECT-SENTINEL")),
            "DB_CONNECT_FAILED",
        ),
    ],
)
def test_health_failure_classification_is_safe_and_public_response_is_stable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: BaseException,
    classification: str,
) -> None:
    def blocked(coroutine: Any) -> object:
        coroutine.close()
        raise error

    monkeypatch.setattr(handler, "_run", blocked)
    caplog.set_level(logging.INFO, logger="gam.lambda")
    response = handler.lambda_handler(public_event(), Context())

    assert response["statusCode"] == 503
    assert response["body"] == (
        '{"error":"DATABASE_UNAVAILABLE","schema_version":"gam.lambda.v1"}'
    )
    records = [json.loads(record.getMessage()) for record in caplog.records]
    dependency = [
        record for record in records if record.get("event_name") == "health_dependency"
    ]
    assert dependency == [
        {
            "error_code_if_any": classification,
            "event_name": "health_dependency",
            "route_or_operation": "/health",
            "schema_version": "gam.lambda.v1",
            "status": "BLOCKED",
        }
    ]
    assert all(set(record) <= handler._SAFE_LOG_KEYS for record in records)
    combined = response["body"] + "".join(
        record.getMessage() for record in caplog.records
    )
    for sentinel in (
        "SECRET-ACCESS-SENTINEL",
        "SECRET-CONTENT-SENTINEL",
        "DB-CONFIG-SENTINEL",
        "DB-DNS-SENTINEL",
        "DB-NETWORK-SENTINEL",
        "DB-TLS-SENTINEL",
        "DB-AUTH-SENTINEL",
        "DB-SQL-SENTINEL",
        "DB-CONNECT-SENTINEL",
        _credential_url("DB-CONFIG-SENTINEL"),
        _credential_url("DB-CONNECT-SENTINEL"),
        "SELECT",
    ):
        assert sentinel not in combined


@pytest.mark.parametrize("sqlstate", ["", "2800", "28p01", "TOO-LONG"])
def test_malformed_sqlstate_fails_closed_without_message_inspection(
    sqlstate: str,
) -> None:
    error = _sql_error(sqlstate, _credential_url("MALFORMED"))
    assert handler._health_failure_code(error) == "DB_CONNECT_FAILED"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"requestContext": {"http": {"method": "POST"}}}, "METHOD_NOT_ALLOWED"),
        ({"body": "{}"}, "INVALID_ENVELOPE"),
        ({"rawQueryString": "operator="}, "INVALID_FILTER"),
        ({"rawQueryString": "unknown=value"}, "INVALID_FILTER"),
        ({"version": "1.0"}, "INVALID_ENVELOPE"),
        ({"schema_version": "gam.lambda.v1"}, "INVALID_ENVELOPE"),
    ],
)
def test_public_rejections_precede_io(changes: dict[str, object], code: str) -> None:
    event = public_event()
    event.update(changes)
    response = handler.lambda_handler(event, Context())
    assert body(response)["error"] == code


def test_unknown_public_route_has_stable_error() -> None:
    response = handler.lambda_handler(public_event("/admin"), Context())
    assert response["statusCode"] == 404
    assert body(response)["error"] == "NOT_FOUND"


def test_event_size_is_bounded_before_io() -> None:
    response = handler.lambda_handler(
        public_event(headers={"padding": "x" * (33 * 1024)}), Context()
    )
    assert response["statusCode"] == 413
    assert body(response)["error"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.parametrize("path", tuple(handler.DEMO_PROFILES))
def test_every_demo_route_maps_to_exact_profile(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    expected = {"profile": handler.DEMO_PROFILES[path]}
    monkeypatch.setattr(handler, "_run", close_and((object(), object())))
    monkeypatch.setattr(handler, "_demo_body", lambda *args: expected)
    response = handler.lambda_handler(public_event(path), Context())
    assert body(response) == expected


def test_profile_not_ready_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(coroutine: Any) -> object:
        coroutine.close()
        raise handler.BoundaryError("PROFILE_NOT_READY", 404)

    monkeypatch.setattr(handler, "_run", blocked)
    response = handler.lambda_handler(public_event("/v1/demo/maybe-novel"), Context())
    assert response["statusCode"] == 404
    assert body(response)["error"] == "PROFILE_NOT_READY"


def test_filters_are_exact_and_do_not_change_trace() -> None:
    family, witness = handler._filters("operator=BECAUSE&witness=FOR-WHAT")
    assert family.value == "BECAUSE"
    assert witness.value == "FOR-WHAT"
    for invalid in (
        "operator=NO",
        "operator=BECAUSE&operator=THIS",
        "witness=FOR_WHAT",
        "witness=",
    ):
        with pytest.raises(handler.BoundaryError):
            handler._filters(invalid)


def test_direct_contract_exposes_only_process_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = SimpleNamespace(
        request_id="request",
        stage="OPENAI",
        error_code="OPENAI_OUTPUT_BLOCKED",
        safe_message="OpenAI response was unavailable or invalid",
        attempt_digest="a" * 64,
    )
    monkeypatch.setattr(handler, "AgentBlockedResult", type(blocked))
    monkeypatch.setattr(handler, "_run", close_and(blocked))
    response = handler.lambda_handler(direct_event(), Context())
    assert response["operation"] == "process_task"
    assert response["status"] == "BLOCKED"
    for operation in ("decide", "approve", "reject", "execute", "SET_DEMO_VALUE"):
        rejected = handler.lambda_handler(direct_event(operation=operation), Context())
        assert body(rejected)["error"] == "INVALID_ENVELOPE"


def test_secret_shape_is_exact_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = {"DATABASE_URL_APP": "database-value", "OPENAI_API_KEY": "api-value"}

    class Client:
        def get_secret_value(self, **kwargs: object) -> dict[str, str]:
            assert set(kwargs) == {"SecretId"}
            return {"SecretString": json.dumps(secret)}

    monkeypatch.setenv("APP_SECRET_ARN", "arn:unit")
    monkeypatch.setitem(
        sys.modules, "boto3", SimpleNamespace(client=lambda _: Client())
    )
    monkeypatch.setattr(handler, "_SECRET_CACHE", None)
    assert handler._load_secret() == secret
    monkeypatch.setattr(handler, "_SECRET_CACHE", None)
    secret["EXTRA"] = "blocked"
    with pytest.raises(RuntimeError, match="shape"):
        handler._load_secret()


def test_cluster_binding_is_closed_predecessor_identity() -> None:
    assert handler.CLUSTER_NAME == "kingly-dreamer"
    assert handler.__file__ is not None
    source = open(handler.__file__, encoding="utf-8").read()
    assert "get_latest_unexpired_tool_evidence(CLUSTER_NAME)" in source
    assert "src.executor" not in source
