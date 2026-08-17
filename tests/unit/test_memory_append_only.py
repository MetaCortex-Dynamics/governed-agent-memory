"""Atomic, retryable, append-only AppMemory behavior."""

from __future__ import annotations

import copy
import hashlib
import importlib
from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from src.memory import (
    CCLOUD_CLUSTER_NAME,
    AppMemory,
    MemoryConflictError,
    MemoryIntegrityError,
    _tool_evidence_digest,
    _validate_tool_evidence,
)
from src.models import (
    CheckResult,
    ConsequenceReport,
    ExecutionStatus,
    PriorEvaluationTrace,
    ToolEvidence,
)
from src.traces import canonical_sha256, snapshot_digest

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")
ROOT = Path(__file__).resolve().parents[2]


class SerializationFailure(RuntimeError):
    sqlstate = "40001"


class FakeTransaction(AbstractAsyncContextManager[object]):
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.before: dict[str, Any] = {}

    async def __aenter__(self) -> object:
        self.before = copy.deepcopy(self.connection.state)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        if exc_type is not None:
            self.connection.state.clear()
            self.connection.state.update(self.before)
            self.connection.rollbacks += 1
        else:
            self.connection.commits += 1
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.state: dict[str, dict[str, dict[str, Any]]] = {
            "proposals": {},
            "evaluations": {},
            "consequences": {},
        }
        self.commits = 0
        self.rollbacks = 0
        self.fail_evaluation_once = False
        self.serialize_once = False

    def transaction(self, *, isolation: str) -> FakeTransaction:
        assert isolation == "serializable"
        return FakeTransaction(self)

    async def execute(self, query: str, *args: object) -> str:
        if "INSERT INTO proposals" in query:
            if self.serialize_once:
                self.serialize_once = False
                raise SerializationFailure("restart transaction")
            self.state["proposals"][str(args[0])] = {
                "id": str(args[0]),
                "proposal_digest": str(args[21]),
            }
        elif "INSERT INTO gate_evaluations" in query:
            if self.fail_evaluation_once:
                self.fail_evaluation_once = False
                raise RuntimeError("evaluation insert failed")
            self.state["evaluations"][str(args[0])] = {
                "id": str(args[0]),
                "proposal_id": str(args[1]),
                "prior_evaluation_id": args[2],
                "trace_digest": str(args[19]),
                "ordinal": len(self.state["evaluations"]),
            }
        elif "INSERT INTO consequence_reports" in query:
            self.state["consequences"][str(args[0])] = {
                "id": str(args[0]),
                "report_digest": str(args[16]),
                "idempotency_key": str(args[17]),
            }
        return "INSERT 0 1"

    async def fetchrow(self, query: str, *args: object) -> dict[str, Any] | None:
        if "FROM proposals WHERE id" in query:
            return self.state["proposals"].get(str(args[0]))
        if "WHERE idempotency_key" in query and "consequence_reports" in query:
            return next(
                (
                    row
                    for row in self.state["consequences"].values()
                    if row["idempotency_key"] == str(args[0])
                ),
                None,
            )
        if "WHERE id = $1::UUID AND proposal_id" in query:
            row = self.state["evaluations"].get(str(args[0]))
            return row if row and row["proposal_id"] == str(args[1]) else None
        if "WHERE id = $1::UUID" in query and "gate_evaluations" in query:
            return self.state["evaluations"].get(str(args[0]))
        if "ORDER BY created_at DESC" in query:
            rows = [
                row
                for row in self.state["evaluations"].values()
                if row["proposal_id"] == str(args[0])
            ]
            return max(rows, key=lambda row: int(row["ordinal"])) if rows else None
        return None

    async def fetch(self, query: str, *args: object) -> Sequence[dict[str, Any]]:
        return ()


class FakeAcquire(AbstractAsyncContextManager[FakeConnection]):
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    async def __aenter__(self) -> FakeConnection:
        return self.connection

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None


class FakePool:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def acquire(self) -> FakeAcquire:
        return FakeAcquire(self.connection)

    async def close(self) -> None:
        return None


def memory_fixture() -> tuple[AppMemory, FakeConnection, Any, CheckResult]:
    connection = FakeConnection()
    memory = AppMemory(pool=FakePool(connection))
    snapshot = fixtures.make_snapshot()
    result = fixtures.evaluate(snapshot)
    return memory, connection, snapshot, result


def prior_from(snapshot: Any, result: CheckResult) -> PriorEvaluationTrace:
    return PriorEvaluationTrace(
        evaluation_id=result.evaluation_id,
        proposal_id=snapshot.proposal.proposal_id,
        verdict=result.verdict,
        risk=result.risk,
        operator_trace=result.operator_trace,
        evidence_gaps=result.evidence_gaps,
        dependencies=result.dependencies,
        precedent_refs=result.precedent_refs,
        consequence_warning_refs=result.consequence_warning_refs,
        because_step_id=result.because_step_id,
        profile_version=result.profile_version,
        prior_evaluation_id=result.prior_evaluation_id,
        changed_fact_rule_ids=result.changed_fact_rule_ids,
        evaluator_version=result.evaluator_version,
        rule_config_digest=result.rule_config_digest,
        input_snapshot_digest=result.input_snapshot_digest,
        policy_digest=result.policy_digest,
        trace_digest=result.trace_digest,
    )


@pytest.mark.asyncio
async def test_atomic_first_append_rolls_back_both_rows() -> None:
    memory, connection, snapshot, result = memory_fixture()
    connection.fail_evaluation_once = True
    with pytest.raises(RuntimeError, match="evaluation insert"):
        await memory.append_proposal_and_evaluation(snapshot.proposal, snapshot, result)
    assert connection.state["proposals"] == {}
    assert connection.state["evaluations"] == {}
    assert connection.rollbacks == 1


@pytest.mark.asyncio
async def test_serialization_retry_commits_once_without_duplicate() -> None:
    memory, connection, snapshot, result = memory_fixture()
    connection.serialize_once = True
    observed = await memory.append_proposal_and_evaluation(
        snapshot.proposal, snapshot, result
    )
    assert observed == (snapshot.proposal.proposal_id, result.evaluation_id)
    assert len(connection.state["proposals"]) == 1
    assert len(connection.state["evaluations"]) == 1
    assert connection.rollbacks == 1
    assert connection.commits == 1


@pytest.mark.asyncio
async def test_exact_replay_is_idempotent_and_conflict_fails_closed() -> None:
    memory, connection, snapshot, result = memory_fixture()
    expected = await memory.append_proposal_and_evaluation(
        snapshot.proposal, snapshot, result
    )
    assert (
        await memory.append_proposal_and_evaluation(snapshot.proposal, snapshot, result)
        == expected
    )
    assert len(connection.state["evaluations"]) == 1
    with pytest.raises(MemoryIntegrityError):
        await memory.append_proposal_and_evaluation(
            snapshot.proposal,
            snapshot,
            replace(result, trace_digest="b" * 64),
        )


def consequence_report() -> ConsequenceReport:
    provisional = ConsequenceReport(
        consequence_id="consequence-1",
        proposal_id="proposal-current",
        receipt_id="receipt-1",
        receipt_terminal_status=ExecutionStatus.OBSERVED,
        receipt_digest="a" * 64,
        observation_number=1,
        predicted_snapshot_digest="a" * 64,
        actual_snapshot_digest="b" * 64,
        comparison_version="json-divergence-v1",
        predicted_outcome_json='{"value":1}',
        actual_outcome_json='{"value":2}',
        leaf_report_json="[]",
        divergence_score=Decimal("0.500000"),
        divergence_threshold=Decimal("0.500000"),
        divergence_summary="MORE",
        reported_by="human",
        report_digest="a" * 64,
        idempotency_key="consequence-key",
    )
    digest = canonical_sha256(
        {
            "schema": "gam.consequence-report.v1",
            **{
                field: getattr(provisional, field)
                for field in provisional.__dataclass_fields__
                if field != "report_digest"
            },
        }
    )
    return replace(provisional, report_digest=digest)


def redigest_report(report: ConsequenceReport) -> ConsequenceReport:
    digest = canonical_sha256(
        {
            "schema": "gam.consequence-report.v1",
            **{
                field: getattr(report, field)
                for field in report.__dataclass_fields__
                if field != "report_digest"
            },
        }
    )
    return replace(report, report_digest=digest)


def tool_evidence(
    *,
    cluster_name: str = "kingly-dreamer",
    cluster_name_digest: str | None = None,
) -> ToolEvidence:
    name_digest = (
        cluster_name_digest or hashlib.sha256(cluster_name.encode()).hexdigest()
    )
    provisional = ToolEvidence(
        evidence_id="00000000-0000-0000-0000-000000000001",
        tool_name="ccloud",
        tool_version="v0.6.12",
        redacted_command_argv_json='["ccloud","cluster","info"]',
        command_digest="1" * 64,
        help_digest="2" * 64,
        config_digest="3" * 64,
        cluster_name=cluster_name,
        cluster_name_digest=name_digest,
        observed_cluster_id_digest="4" * 64,
        observed_version="v26.2.5",
        observed_state="CREATED",
        observed_plan="BASIC",
        observed_cloud="AWS",
        normalized_redacted_output_json='{"name":"kingly-dreamer"}',
        redaction_manifest_json='["cluster_id"]',
        raw_output_digest="5" * 64,
        normalized_output_digest="6" * 64,
        exit_status=0,
        captured_at="2026-08-17T00:00:00.000000Z",
        expires_at="2026-08-17T00:15:00.000000Z",
        captured_by="ccloud-evidence-adapter",
        evidence_digest="0" * 64,
        idempotency_key="tool-evidence-key",
    )
    return replace(
        provisional,
        evidence_digest=_tool_evidence_digest(provisional),
    )


def test_tool_evidence_schema_binds_observed_cluster_name() -> None:
    schema = (ROOT / "schema/init.sql").read_text(encoding="utf-8")
    assert "cluster_name STRING NOT NULL DEFAULT 'kingly-dreamer'" in schema
    assert "CHECK (cluster_name = 'kingly-dreamer')" in schema
    assert "CHECK (cluster_name = 'governed-agent-memory')" not in schema


def test_tool_evidence_accepts_exact_name_and_digest() -> None:
    _validate_tool_evidence(tool_evidence())


@pytest.mark.parametrize("cluster_name", ["governed-agent-memory", "other-cluster"])
def test_tool_evidence_rejects_obsolete_or_arbitrary_cluster_name(
    cluster_name: str,
) -> None:
    name_digest = hashlib.sha256(cluster_name.encode()).hexdigest()
    with pytest.raises(MemoryIntegrityError, match="tool evidence binding"):
        _validate_tool_evidence(
            tool_evidence(
                cluster_name=cluster_name,
                cluster_name_digest=name_digest,
            )
        )


def test_tool_evidence_rejects_correct_name_with_wrong_name_digest() -> None:
    evidence = tool_evidence(cluster_name_digest="f" * 64)
    with pytest.raises(MemoryIntegrityError, match="tool evidence binding"):
        _validate_tool_evidence(evidence)


@pytest.mark.asyncio
@pytest.mark.parametrize("cluster_name", ["governed-agent-memory", "other-cluster"])
async def test_latest_tool_evidence_lookup_rejects_incorrect_name(
    cluster_name: str,
) -> None:
    memory, _, _, _ = memory_fixture()
    with pytest.raises(MemoryIntegrityError, match="not permitted"):
        await memory.get_latest_unexpired_tool_evidence(cluster_name)
    assert cluster_name != CCLOUD_CLUSTER_NAME


@pytest.mark.asyncio
async def test_consequence_replay_and_conflicting_key() -> None:
    memory, connection, _, _ = memory_fixture()
    report = consequence_report()
    assert await memory.append_consequence(report) == report.consequence_id
    assert await memory.append_consequence(report) == report.consequence_id
    assert len(connection.state["consequences"]) == 1
    conflicting = redigest_report(
        replace(report, consequence_id="consequence-2", report_digest="a" * 64)
    )
    with pytest.raises(MemoryConflictError):
        await memory.append_consequence(conflicting)


@pytest.mark.asyncio
async def test_re_evaluation_preserves_history_and_rejects_stale_prior() -> None:
    memory, connection, snapshot, first = memory_fixture()
    await memory.append_proposal_and_evaluation(snapshot.proposal, snapshot, first)
    prior = prior_from(snapshot, first)
    second_snapshot = fixtures.make_snapshot(evaluation_id="evaluation-second")
    second_snapshot = replace(
        second_snapshot, prior_evaluation=prior, snapshot_digest="a" * 64
    )
    second_snapshot = replace(
        second_snapshot, snapshot_digest=snapshot_digest(second_snapshot)
    )
    second = fixtures.evaluate_proposal(second_snapshot, fixtures.default_rule_config())
    assert isinstance(second, CheckResult)
    await memory.append_re_evaluation(second_snapshot, second)
    assert set(connection.state["evaluations"]) == {
        first.evaluation_id,
        second.evaluation_id,
    }
    assert connection.state["evaluations"][first.evaluation_id]["trace_digest"] == (
        first.trace_digest
    )

    stale_snapshot = fixtures.make_snapshot(evaluation_id="evaluation-stale")
    stale_snapshot = replace(
        stale_snapshot, prior_evaluation=prior, snapshot_digest="a" * 64
    )
    stale_snapshot = replace(
        stale_snapshot, snapshot_digest=snapshot_digest(stale_snapshot)
    )
    stale_result = fixtures.evaluate_proposal(
        stale_snapshot, fixtures.default_rule_config()
    )
    assert isinstance(stale_result, CheckResult)
    with pytest.raises(MemoryConflictError, match="stale"):
        await memory.append_re_evaluation(stale_snapshot, stale_result)
