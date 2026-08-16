from __future__ import annotations

import importlib
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

import pytest

import src.consequences as consequences
from src.consequences import DivergenceLeaf, compare_json, report_consequence
from src.memory import MemoryConflictError, MemoryIntegrityError
from src.models import CheckResult, ConsequenceRef, ConsequenceReport, ExecutionStatus

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")


class SerializationFailure(RuntimeError):
    sqlstate = "40001"


class ReportConnection:
    def __init__(self, receipt: dict[str, Any]) -> None:
        self.receipt = receipt
        self.report: dict[str, Any] | None = None
        self.serialize_once = False

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, Any] | None:
        if "WHERE idempotency_key" in query:
            return self.report
        if "FROM execution_receipts AS r" in query:
            if self.serialize_once:
                self.serialize_once = False
                raise SerializationFailure("restart transaction")
            return self.receipt
        raise AssertionError(query)


class ReportMemory:
    def __init__(self, receipt: dict[str, Any]) -> None:
        self.connection = ReportConnection(receipt)
        self.append_count = 0
        self.transaction_count = 0

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[ReportConnection]:
        self.transaction_count += 1
        yield self.connection

    async def append_consequence(self, report: ConsequenceReport) -> str:
        self.append_count += 1
        self.connection.report = {
            "id": report.consequence_id,
            "consequence_id": report.consequence_id,
            "proposal_id": report.proposal_id,
            "receipt_id": report.receipt_id,
            "receipt_terminal_status": report.receipt_terminal_status.value,
            "receipt_digest": report.receipt_digest,
            "observation_number": report.observation_number,
            "predicted_snapshot_digest": report.predicted_snapshot_digest,
            "actual_snapshot_digest": report.actual_snapshot_digest,
            "comparison_version": report.comparison_version,
            "predicted_outcome": report.predicted_outcome_json,
            "actual_outcome": report.actual_outcome_json,
            "leaf_report": report.leaf_report_json,
            "divergence_score": report.divergence_score,
            "divergence_threshold": report.divergence_threshold,
            "divergence_summary": report.divergence_summary,
            "reported_by": report.reported_by,
            "report_digest": report.report_digest,
            "idempotency_key": report.idempotency_key,
        }
        return report.consequence_id


def receipt_row() -> dict[str, Any]:
    row: dict[str, Any] = {
        "receipt_id": "10000000-0000-0000-0000-000000000001",
        "attempt_id": "10000000-0000-0000-0000-000000000002",
        "attempt_digest": "1" * 64,
        "proposal_id": "10000000-0000-0000-0000-000000000003",
        "evaluation_id": "10000000-0000-0000-0000-000000000004",
        "evaluation_trace_digest": "2" * 64,
        "decision_id": "10000000-0000-0000-0000-000000000005",
        "decision_value": "APPROVE",
        "decision_digest": "3" * 64,
        "action_digest": "4" * 64,
        "target_key": "demo_kv:test",
        "attempt_terminal_status": "OBSERVED",
        "outcome_digest": "5" * 64,
        "before_effect_digest": "6" * 64,
        "after_effect_digest": "7" * 64,
        "observed_effect_version": 1,
        "executor_id": "executor",
        "receipt_idempotency_key": "receipt-key",
        "verified": True,
        "receipt_digest": "0" * 64,
        "predicted_outcome": '{"rows_affected":100}',
        "evaluation_status": "FINALIZED",
        "demo_effect_id": "10000000-0000-0000-0000-000000000006",
    }
    receipt = consequences._receipt_from_row(row)
    row["receipt_digest"] = consequences._receipt_digest(receipt)
    return row


def report_fixture(
    consequence_id: str = "20000000-0000-0000-0000-000000000001",
    *,
    divergence: Decimal = Decimal("0.750000"),
) -> tuple[ConsequenceReport, dict[str, Any]]:
    provisional = ConsequenceReport(
        consequence_id=consequence_id,
        proposal_id="20000000-0000-0000-0000-000000000002",
        receipt_id="20000000-0000-0000-0000-000000000003",
        receipt_terminal_status=ExecutionStatus.OBSERVED,
        receipt_digest="1" * 64,
        observation_number=1,
        predicted_snapshot_digest="2" * 64,
        actual_snapshot_digest="3" * 64,
        comparison_version="json-divergence-v1",
        predicted_outcome_json="{}",
        actual_outcome_json="{}",
        leaf_report_json="[]",
        divergence_score=divergence,
        divergence_threshold=Decimal("0.500000"),
        divergence_summary="MORE",
        reported_by="human",
        report_digest="0" * 64,
        idempotency_key=f"report-{consequence_id}",
    )
    report = replace(
        provisional,
        report_digest=consequences._record_digest(
            provisional, "gam.consequence-report.v1", "report_digest"
        ),
    )
    row = {
        "id": report.consequence_id,
        "consequence_id": report.consequence_id,
        **{
            field: getattr(report, field)
            for field in (
                "proposal_id",
                "receipt_id",
                "receipt_digest",
                "observation_number",
                "predicted_snapshot_digest",
                "actual_snapshot_digest",
                "comparison_version",
                "divergence_score",
                "divergence_threshold",
                "divergence_summary",
                "reported_by",
                "report_digest",
                "idempotency_key",
            )
        },
        "receipt_terminal_status": report.receipt_terminal_status.value,
        "predicted_outcome": report.predicted_outcome_json,
        "actual_outcome": report.actual_outcome_json,
        "leaf_report": report.leaf_report_json,
    }
    return report, row


class OrchestrationConnection:
    def __init__(
        self, latest: Mapping[str, Any], reports: list[dict[str, Any]]
    ) -> None:
        self.latest = latest
        self.reports = reports

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, Any] | None:
        if "gate_evaluations" in query:
            return self.latest
        if "consequence_reports" in query:
            wanted = str(args[0])
            return next(
                (row for row in self.reports if row["consequence_id"] == wanted),
                None,
            )
        raise AssertionError(query)

    async def fetch(self, query: str, *args: object) -> tuple[Mapping[str, Any], ...]:
        assert "consequence_reports" in query
        wanted = {str(item) for item in cast(tuple[object, ...], args[0])}
        return tuple(row for row in self.reports if row["consequence_id"] in wanted)


class OrchestrationMemory:
    def __init__(
        self,
        proposal: Any,
        precedents: tuple[Any, ...],
        latest: Mapping[str, Any],
        reports: list[dict[str, Any]],
    ) -> None:
        self.proposal = proposal
        self.precedents = precedents
        self.connection = OrchestrationConnection(latest, reports)
        self.appended: list[tuple[Any, Any]] = []

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[OrchestrationConnection]:
        yield self.connection

    async def get_proposal(self, _proposal_id: str) -> Any:
        return self.proposal

    async def search_precedents(
        self, _embedding: tuple[float, ...], limit: int, _evaluation_id: str
    ) -> tuple[Any, ...]:
        assert limit == 5
        return self.precedents

    async def get_exclusions(self, _action: str, _target: str) -> tuple[Any, ...]:
        return ()

    async def append_re_evaluation(self, snapshot: Any, result: Any) -> tuple[str, str]:
        self.appended.append((snapshot, result))
        return snapshot.proposal.proposal_id, result.evaluation_id


def test_worked_fixture_and_leaf_order() -> None:
    result = compare_json(
        '{"rows_affected":100,"latency_ms":50}',
        '{"rows_affected":25,"latency_ms":200}',
    )
    assert result.score == Decimal("0.750000")
    assert tuple(leaf.json_pointer for leaf in result.leaves) == (
        "/latency_ms",
        "/rows_affected",
    )
    assert all(leaf.score == Decimal("0.75") for leaf in result.leaves)
    assert result.comparison_version == "json-divergence-v1"


def test_frozen_typed_leaf() -> None:
    leaf = DivergenceLeaf("", True, True, "null", Decimal("0"))
    with pytest.raises(FrozenInstanceError):
        leaf.score = Decimal("1")  # type: ignore[misc]


@pytest.mark.parametrize(
    ("predicted", "actual", "score", "kind"),
    [
        ("null", "null", "0.000000", "null"),
        ("true", "false", "1.000000", "boolean"),
        ('"same"', '"same"', "0.000000", "string"),
        ("1", '"1"', "1.000000", "type_mismatch"),
        ("-10", "10", "1.000000", "number"),
        ("{}", "{}", "0.000000", "empty_object"),
        ("[]", "[]", "0.000000", "empty_array"),
    ],
)
def test_scalar_type_and_empty_structure_rules(
    predicted: str, actual: str, score: str, kind: str
) -> None:
    result = compare_json(predicted, actual)
    assert result.score == Decimal(score)
    assert result.leaves[0].kind == kind


def test_missing_values_and_array_order_are_not_matched() -> None:
    object_result = compare_json('{"a":1}', '{"b":1}')
    assert object_result.score == Decimal("1.000000")
    assert [
        (leaf.json_pointer, leaf.predicted_present, leaf.actual_present)
        for leaf in object_result.leaves
    ] == [
        ("/a", True, False),
        ("/b", False, True),
    ]
    assert compare_json("[1,2]", "[2,1]").score == Decimal("0.500000")


def test_rfc6901_escaping_and_utf8_key_order() -> None:
    result = compare_json('{"~":0,"/":0}', '{"~":1,"/":1}')
    assert tuple(leaf.json_pointer for leaf in result.leaves) == ("/~1", "/~0")


def test_nfc_normalization_makes_equivalent_strings_and_digests_equal() -> None:
    composed = compare_json('{"caf\u00e9":"\u00e9"}', '{"cafe\u0301":"e\u0301"}')
    assert composed.score == Decimal("0.000000")
    assert composed.predicted_digest == composed.actual_digest


@pytest.mark.parametrize(
    "invalid",
    [
        '{"a":1,"a":2}',
        '{"\u00e9":1,"e\u0301":2}',
        "NaN",
        "Infinity",
        "-Infinity",
        "{",
    ],
)
def test_invalid_json_is_rejected(invalid: str) -> None:
    with pytest.raises(MemoryIntegrityError):
        compare_json(invalid, "null")


def test_half_even_quantization_and_exact_threshold() -> None:
    result = compare_json("[0,0,0]", "[1,1,0]")
    assert result.score == Decimal("0.666667")
    assert compare_json("[1,2]", "[2,1]").score >= Decimal("0.500000")
    assert compare_json("1", "1.499999").score < Decimal("0.500000")


def test_canonical_digests_ignore_json_layout() -> None:
    first = compare_json('{"b":2, "a":1}', '{"a":1,"b":2}')
    assert first.predicted_digest == first.actual_digest
    assert first.score == Decimal("0.000000")


def test_inputs_must_be_json_text_and_threshold_must_be_decimal() -> None:
    with pytest.raises(MemoryIntegrityError):
        compare_json(json.loads("{}"), "{}")
    with pytest.raises(MemoryIntegrityError):
        compare_json("{}", "{}", threshold=0.5)  # type: ignore[arg-type]
    with pytest.raises(MemoryIntegrityError):
        compare_json("{}", "{}", threshold=Decimal("1.1"))


@pytest.mark.asyncio
async def test_idempotent_report_replay_preserves_digest_and_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory = ReportMemory(receipt_row())
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    receipt_id = UUID(memory.connection.receipt["receipt_id"])
    first = await report_consequence(
        receipt_id, 7, '{"rows_affected":25}', "human", "same"
    )
    second = await report_consequence(
        receipt_id, 7, '{"rows_affected":25}', "human", "same"
    )
    assert second == first
    assert second.observation_number == 7
    assert second.report_digest == first.report_digest
    assert memory.append_count == 1


@pytest.mark.asyncio
async def test_conflicting_idempotency_reuse_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory = ReportMemory(receipt_row())
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    receipt_id = UUID(memory.connection.receipt["receipt_id"])
    await report_consequence(receipt_id, 1, "{}", "human", "same")
    with pytest.raises(MemoryConflictError):
        await report_consequence(receipt_id, 2, "{}", "human", "same")
    assert memory.append_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", ["error", "digest", "unobserved"])
async def test_invalid_receipts_cannot_produce_consequences(
    monkeypatch: pytest.MonkeyPatch, defect: str
) -> None:
    row = receipt_row()
    if defect == "error":
        row["attempt_terminal_status"] = "ERROR"
    elif defect == "digest":
        row["receipt_digest"] = "f" * 64
    else:
        row["demo_effect_id"] = None
    memory = ReportMemory(row)
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    with pytest.raises(MemoryIntegrityError):
        await report_consequence(UUID(row["receipt_id"]), 1, "{}", "human", "key")
    assert memory.append_count == 0


@pytest.mark.asyncio
async def test_serialization_retry_appends_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory = ReportMemory(receipt_row())
    memory.connection.serialize_once = True
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    report = await report_consequence(
        UUID(memory.connection.receipt["receipt_id"]), 1, "{}", "human", "retry"
    )
    assert report.idempotency_key == "retry"
    assert memory.transaction_count == 2
    assert memory.append_count == 1


@pytest.mark.asyncio
async def test_warning_retrieval_requires_exact_same_after_near(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, row = report_fixture()
    proposal = fixtures.make_proposal()
    consequence_ref = ConsequenceRef(
        consequence_id=report.consequence_id,
        receipt_id=report.receipt_id,
        receipt_terminal_status=report.receipt_terminal_status,
        receipt_digest=report.receipt_digest,
        predicted_snapshot_digest=report.predicted_snapshot_digest,
        actual_snapshot_digest=report.actual_snapshot_digest,
        comparison_version=report.comparison_version,
        divergence=report.divergence_score,
        divergence_threshold=report.divergence_threshold,
        report_digest=report.report_digest,
    )
    same = fixtures.make_precedent(consequences=(consequence_ref,))
    different = fixtures.make_precedent(
        target_key="different", consequences=(consequence_ref,), proposal_id="other"
    )
    memory = OrchestrationMemory(
        proposal,
        (same, different),
        {"id": "evaluation-current"},
        [row],
    )
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    warnings = await consequences.get_divergence_warnings(
        UUID("30000000-0000-0000-0000-000000000001")
    )
    assert warnings == (report,)


@pytest.mark.asyncio
async def test_reevaluation_appends_new_genealogy_without_mutating_prior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, row = report_fixture()
    consequence_ref = ConsequenceRef(
        consequence_id=report.consequence_id,
        receipt_id=report.receipt_id,
        receipt_terminal_status=report.receipt_terminal_status,
        receipt_digest=report.receipt_digest,
        predicted_snapshot_digest=report.predicted_snapshot_digest,
        actual_snapshot_digest=report.actual_snapshot_digest,
        comparison_version=report.comparison_version,
        divergence=report.divergence_score,
        divergence_threshold=report.divergence_threshold,
        report_digest=report.report_digest,
    )
    base = fixtures.make_snapshot(
        precedents=(fixtures.make_precedent(consequences=(consequence_ref,)),)
    )
    prior = fixtures.evaluate(base)
    assert isinstance(prior, CheckResult)
    prior_bytes = prior.trace_digest
    latest_row = {"input_snapshot": "stored", "id": prior.evaluation_id}
    memory = OrchestrationMemory(base.proposal, base.precedents, latest_row, [row])
    monkeypatch.setattr(consequences, "_APP_MEMORY", memory)
    monkeypatch.setattr(consequences, "_result_from_row", lambda _row: prior)
    monkeypatch.setattr(consequences, "_snapshot_from_json", lambda _value: base)
    monkeypatch.setattr(consequences, "finalize_snapshot", lambda snapshot: snapshot)

    def evaluate(snapshot: Any, _config: Any) -> CheckResult:
        return replace(
            prior,
            evaluation_id=snapshot.evaluation_id,
            prior_evaluation_id=prior.evaluation_id,
            changed_fact_rule_ids=("F08_DIVERGENCE_BOUNDARY",),
            input_snapshot_digest=snapshot.snapshot_digest,
            trace_digest="9" * 64,
        )

    monkeypatch.setattr(consequences, "evaluate_proposal", evaluate)
    result = await consequences.reevaluate_with_consequence(
        UUID("30000000-0000-0000-0000-000000000002"),
        UUID(report.consequence_id),
        "human",
    )
    assert result.prior_evaluation_id == prior.evaluation_id
    assert result.changed_fact_rule_ids == ("F08_DIVERGENCE_BOUNDARY",)
    assert len(memory.appended) == 1
    assert prior.trace_digest == prior_bytes
    snapshot, appended = memory.appended[0]
    assert snapshot.prior_evaluation is not None
    assert snapshot.prior_evaluation.trace_digest == prior_bytes
    assert appended is result
