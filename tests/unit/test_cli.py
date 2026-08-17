from __future__ import annotations

import importlib
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Any, cast
from uuid import uuid4

import pytest

from src.cli import (
    ADVISORY,
    EXPLICIT_EXECUTE,
    CliBlocked,
    DeciderMemory,
    parser,
    render_review,
)
from src.governance import (
    default_rule_config,
    evaluate_proposal,
    proposal_action_digest,
    proposal_record_digest,
)
from src.models import DecisionValue
from src.traces import finalize_snapshot

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")


def bound_pair() -> tuple[Any, Any]:
    proposal_id = str(uuid4())
    evaluation_id = str(uuid4())
    base = fixtures.make_proposal()
    proposal = replace(base, proposal_id=proposal_id)
    proposal = replace(proposal, action_digest=proposal_action_digest(proposal))
    proposal = replace(proposal, proposal_digest=proposal_record_digest(proposal))
    snapshot = fixtures.make_snapshot(
        proposal=proposal,
        evaluation_id=evaluation_id,
    )
    snapshot = finalize_snapshot(snapshot)
    return proposal, evaluate_proposal(snapshot, default_rule_config())


class Connection:
    def __init__(self, proposal: Any, result: Any) -> None:
        self.proposal = proposal
        self.result = result
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fail_exclusion = False

    async def fetchrow(self, query: str, *args: object) -> dict[str, object] | None:
        if "FROM gate_evaluations" in query:
            return {
                "id": self.result.evaluation_id,
                "trace_digest": self.result.trace_digest,
            }
        if "FROM decisions WHERE idempotency_key" in query:
            return None
        if "FROM decisions WHERE proposal_id" in query:
            return None
        if "FROM exclusions" in query:
            return None
        raise AssertionError(query)

    async def execute(self, query: str, *args: object) -> str:
        if "INSERT INTO exclusions" in query and self.fail_exclusion:
            raise RuntimeError("synthetic exclusion failure")
        self.executed.append((query, args))
        return "INSERT 0 1"


class Memory:
    def __init__(self, proposal: Any, result: Any) -> None:
        self.proposal = proposal
        self.result = result
        self.connection = Connection(proposal, result)

    async def get_proposal(self, proposal_id: str) -> Any:
        assert proposal_id == self.proposal.proposal_id
        return self.proposal

    async def get_evaluation(self, evaluation_id: str) -> Any:
        assert evaluation_id == self.result.evaluation_id
        return self.result

    @asynccontextmanager
    async def transaction(self) -> Any:
        yield self.connection

    async def _retry(self, operation: Any) -> Any:
        before = list(self.connection.executed)
        try:
            return await operation(self.connection)
        except Exception:
            self.connection.executed = before
            raise


def test_cli_exposes_only_six_separate_commands() -> None:
    command = parser()
    choices = next(
        action.choices
        for action in command._actions
        if getattr(action, "choices", None)
    )
    assert set(cast(Any, choices)) == {
        "show",
        "decide",
        "execute",
        "consequence",
        "reevaluate",
        "history",
    }


def test_review_preserves_trace_order_and_advisory_text() -> None:
    proposal, result = bound_pair()
    rendered = render_review(proposal, result)
    positions = [rendered.index(step.step_id) for step in result.operator_trace]
    assert positions == sorted(positions)
    assert result.trace_digest in rendered
    assert ADVISORY in rendered
    assert EXPLICIT_EXECUTE in rendered


@pytest.mark.asyncio
async def test_reject_exclude_appends_decision_and_exclusion_atomically() -> None:
    proposal, result = bound_pair()
    memory = Memory(proposal, result)
    record, exclusion = await DeciderMemory(cast(Any, memory)).append_decision(
        proposal_id=proposal.proposal_id,
        evaluation_id=result.evaluation_id,
        trace_digest=result.trace_digest,
        decision=DecisionValue.REJECT,
        decided_by="human:unit",
        rationale="exact target is excluded",
        idempotency_key=str(uuid4()),
        exclusion_requested=True,
    )
    assert record.decision is DecisionValue.REJECT
    assert exclusion is not None
    assert exclusion.target_key == proposal.target_key
    assert len(memory.connection.executed) == 2
    assert all(
        "execution_receipts" not in query for query, _ in memory.connection.executed
    )


@pytest.mark.asyncio
async def test_exclusion_failure_rolls_back_decision_in_same_retry_unit() -> None:
    proposal, result = bound_pair()
    memory = Memory(proposal, result)
    memory.connection.fail_exclusion = True
    with pytest.raises(RuntimeError):
        await DeciderMemory(cast(Any, memory)).append_decision(
            proposal_id=proposal.proposal_id,
            evaluation_id=result.evaluation_id,
            trace_digest=result.trace_digest,
            decision=DecisionValue.REJECT,
            decided_by="human:unit",
            rationale="exact target is excluded",
            idempotency_key=str(uuid4()),
            exclusion_requested=True,
        )
    assert memory.connection.executed == []


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", (DecisionValue.APPROVE, DecisionValue.MODIFY))
async def test_approve_and_modify_never_create_receipt_or_exclusion(
    decision: DecisionValue,
) -> None:
    proposal, result = bound_pair()
    memory = Memory(proposal, result)
    _, exclusion = await DeciderMemory(cast(Any, memory)).append_decision(
        proposal_id=proposal.proposal_id,
        evaluation_id=result.evaluation_id,
        trace_digest=result.trace_digest,
        decision=decision,
        decided_by="human:unit",
        rationale="terminal human decision",
        idempotency_key=str(uuid4()),
        exclusion_requested=False,
    )
    assert exclusion is None
    assert len(memory.connection.executed) == 1
    assert "INSERT INTO decisions" in memory.connection.executed[0][0]


@pytest.mark.asyncio
async def test_stale_trace_and_invalid_exclusion_request_block() -> None:
    proposal, result = bound_pair()
    memory = Memory(proposal, result)
    with pytest.raises(CliBlocked):
        await DeciderMemory(cast(Any, memory)).exact_evaluation(
            proposal.proposal_id, result.evaluation_id, "0" * 64
        )
    with pytest.raises(CliBlocked):
        await DeciderMemory(cast(Any, memory)).append_decision(
            proposal_id=proposal.proposal_id,
            evaluation_id=result.evaluation_id,
            trace_digest=result.trace_digest,
            decision=DecisionValue.APPROVE,
            decided_by="human:unit",
            rationale="approve",
            idempotency_key=str(uuid4()),
            exclusion_requested=True,
        )
