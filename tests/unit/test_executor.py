from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from src.executor import (
    ExecutionBlocked,
    ExecutorConfig,
    _append_error_chain,
    _FailedEffect,
    _validate_effect,
    attempt_digest,
    derive_executor_id,
    receipt_digest,
)
from src.governance import proposal_action_digest, proposal_record_digest
from src.models import (
    DecisionRecord,
    DecisionValue,
    DemoExecutionCommand,
    ExecutionAttempt,
    ExecutionReceipt,
    ExecutionStatus,
    Proposal,
)

DIGEST = "a" * 64


def proposal(**changes: object) -> Proposal:
    value = Proposal(
        str(uuid4()),
        None,
        None,
        None,
        "agent",
        "session",
        "SET_DEMO_VALUE",
        "set_demo_value",
        "demo_kv:alpha",
        "demo_kv:alpha",
        "bounded",
        "demo",
        '{"value":1}',
        "{}",
        '{"value":1}',
        (),
        (),
        (0.0,) * 1536,
        "text-embedding-3-small",
        DIGEST,
        DIGEST,
        DIGEST,
    )
    value = replace(value, **cast(Any, changes))
    value = replace(value, action_digest=proposal_action_digest(value))
    return replace(value, proposal_digest=proposal_record_digest(value))


def attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        DIGEST,
        str(uuid4()),
        DecisionValue.APPROVE,
        DIGEST,
        "set_demo_value",
        DIGEST,
        "demo_kv:alpha",
        "alpha",
        "1",
        "2026-08-17T12:00:00.000000Z",
        "2026-08-17T12:00:00.000001Z",
        ExecutionStatus.OBSERVED,
        str(uuid4()),
        DIGEST,
        "b" * 64,
        1,
        '{"status":"OBSERVED"}',
        "c" * 64,
        "0" * 64,
        "d" * 64,
        str(uuid4()),
        None,
        None,
    )


def receipt() -> ExecutionReceipt:
    return ExecutionReceipt(
        str(uuid4()),
        str(uuid4()),
        DIGEST,
        str(uuid4()),
        str(uuid4()),
        DIGEST,
        str(uuid4()),
        DecisionValue.APPROVE,
        DIGEST,
        DIGEST,
        "demo_kv:alpha",
        ExecutionStatus.OBSERVED,
        DIGEST,
        DIGEST,
        "b" * 64,
        1,
        "d" * 64,
        str(uuid4()),
        True,
        "0" * 64,
    )


def test_only_exact_allowlisted_scalar_effect_is_accepted() -> None:
    assert _validate_effect(proposal()) == ("alpha", "1")
    assert _validate_effect(proposal(parameters_json='{"value":null}')) == (
        "alpha",
        "null",
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"action_type": "RUN_SQL"},
        {"target": "demo_kv:../bad", "target_key": "demo_kv:../bad"},
        {"parameters_json": '{"value":[]}'},
        {"parameters_json": '{"value":{}}'},
        {"parameters_json": '{"value":"' + "x" * 257 + '"}'},
        {"parameters_json": '{"value":NaN}'},
        {"parameters_json": '{"value":1,"other":2}'},
    ),
)
def test_every_non_allowlisted_action_key_or_value_blocks(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ExecutionBlocked):
        _validate_effect(proposal(**changes))


def test_executor_identity_is_derived_and_accepts_digit_leading_sha256() -> None:
    identity = derive_executor_id("synthetic_executor_principal")
    assert len(identity) == 64
    assert identity == derive_executor_id("synthetic_executor_principal")
    ExecutorConfig(
        "postgresql://runtime_user@localhost/db?sslmode=verify-full",
        "0" * 64,
    )
    with pytest.raises(ExecutionBlocked):
        ExecutorConfig(
            "postgresql://runtime_user@localhost/db?sslmode=verify-full",
            "not-a-digest",
        )


def test_attempt_digest_binds_timestamps_terminal_and_safe_error_fields() -> None:
    value = attempt()
    base = attempt_digest(value)
    assert (
        attempt_digest(replace(value, finished_at="2026-08-17T12:00:00.000002Z"))
        != base
    )
    assert attempt_digest(replace(value, terminal_status=ExecutionStatus.ERROR)) != base
    assert attempt_digest(replace(value, error_code="PROVEN_ROLLBACK")) != base
    assert attempt_digest(replace(value, safe_message="effect did not commit")) != base


def test_receipt_digest_binds_attempt_action_target_and_observation() -> None:
    value = receipt()
    base = receipt_digest(value)
    assert receipt_digest(replace(value, attempt_digest="e" * 64)) != base
    assert receipt_digest(replace(value, action_digest="f" * 64)) != base
    assert receipt_digest(replace(value, target_key="demo_kv:beta")) != base
    assert receipt_digest(replace(value, observed_effect_version=2)) != base


@pytest.mark.asyncio
async def test_proven_rollback_appends_error_attempt_and_receipt_without_effect() -> (
    None
):
    class Connection:
        def __init__(self) -> None:
            self.queries: list[str] = []

        async def execute(self, query: str, *args: object) -> str:
            self.queries.append(query)
            return "INSERT 0 1"

    item = proposal()
    decision = DecisionRecord(
        str(uuid4()),
        item.proposal_id,
        str(uuid4()),
        DIGEST,
        DecisionValue.APPROVE,
        "human:unit",
        "approved",
        "{}",
        DIGEST,
        str(uuid4()),
    )
    failed = _FailedEffect(
        DemoExecutionCommand(decision.decision_id, "d" * 64, str(uuid4())),
        item,
        cast(
            Any,
            SimpleNamespace(evaluation_id=decision.evaluation_id, trace_digest=DIGEST),
        ),
        decision,
        "alpha",
        "1",
        "0" * 64,
    )
    connection = Connection()
    result = await _append_error_chain(cast(Any, connection), failed)
    assert result.attempt_terminal_status is ExecutionStatus.ERROR
    assert result.after_effect_digest is None
    assert result.observed_effect_version is None
    assert len(connection.queries) == 2
    assert "execution_attempts" in connection.queries[0]
    assert "execution_receipts" in connection.queries[1]
    assert all("INSERT INTO demo_kv" not in query for query in connection.queries)
