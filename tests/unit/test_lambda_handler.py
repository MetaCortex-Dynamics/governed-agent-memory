from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

handler = importlib.import_module("lambda.handler")


@dataclass
class Context:
    aws_request_id: str = "aws-request-unit"


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
