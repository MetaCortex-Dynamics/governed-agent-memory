"""Deterministic consequence comparison and append-only persistence."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any, NoReturn, cast
from uuid import UUID, uuid4

from src.governance import default_rule_config, evaluate_proposal
from src.memory import (
    AppMemory,
    MemoryConflictError,
    MemoryIntegrityError,
    _result_from_row,
    _snapshot_from_json,
)
from src.models import (
    BlockedResult,
    CheckResult,
    ConsequenceReport,
    DecisionValue,
    EvaluationSnapshot,
    ExecutionReceipt,
    ExecutionStatus,
    PriorEvaluationTrace,
)
from src.traces import canonical_json_bytes, canonical_sha256, finalize_snapshot

_COMPARISON_VERSION = "json-divergence-v1"
_DEFAULT_THRESHOLD = Decimal("0.500000")
_NEAR_THRESHOLD = Decimal("0.85000000")
_SIX_PLACES = Decimal("0.000001")
_MAX_RETRIES = 4


@dataclass(frozen=True, slots=True)
class DivergenceLeaf:
    json_pointer: str
    predicted_present: bool
    actual_present: bool
    kind: str
    score: Decimal


@dataclass(frozen=True, slots=True)
class DivergenceResult:
    comparison_version: str
    predicted_digest: str
    actual_digest: str
    leaves: tuple[DivergenceLeaf, ...]
    score: Decimal
    threshold: Decimal


_APP_MEMORY = AppMemory()


def _reject(message: str) -> NoReturn:
    raise MemoryIntegrityError(message)


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, value in pairs:
        key = unicodedata.normalize("NFC", raw_key)
        if key in result:
            _reject("duplicate or normalized-colliding JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    _reject("non-finite JSON number")


def _normalize_json(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, Decimal)):
        return value
    if isinstance(value, list):
        return tuple(_normalize_json(item) for item in value)
    if isinstance(value, dict):
        return {key: _normalize_json(item) for key, item in value.items()}
    _reject("unsupported JSON value")


def _parse_json(text: str) -> Any:
    if not isinstance(text, str):
        _reject("JSON input must be text")
    try:
        value = json.loads(
            text,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=_reject_constant,
            object_pairs_hook=_json_pairs,
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise MemoryIntegrityError("invalid JSON input") from error
    return _normalize_json(value)


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        _reject("non-finite JSON number")
    if value.is_zero():
        return "0"
    text = format(value.normalize(), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _plain_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, Decimal):
        return _decimal_text(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, tuple):
        return "[" + ",".join(_plain_json(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-8"))
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, ensure_ascii=False)}:{_plain_json(item)}"
                for key, item in items
            )
            + "}"
        )
    _reject("unsupported JSON value")


def _database_json(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, Decimal):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, tuple):
        return "array"
    if isinstance(value, dict):
        return "object"
    _reject("unsupported JSON value")


def _pointer(path: str, component: str) -> str:
    escaped = component.replace("~", "~0").replace("/", "~1")
    return f"{path}/{escaped}"


def _leaf(
    path: str, predicted: bool, actual: bool, kind: str, score: Decimal
) -> DivergenceLeaf:
    return DivergenceLeaf(path, predicted, actual, kind, score)


def _compare(predicted: Any, actual: Any, path: str) -> list[DivergenceLeaf]:
    predicted_kind = _kind(predicted)
    actual_kind = _kind(actual)
    if predicted_kind != actual_kind:
        return [_leaf(path, True, True, "type_mismatch", Decimal("1"))]
    if predicted_kind == "number":
        p = cast(Decimal, predicted)
        a = cast(Decimal, actual)
        score = min(Decimal("1"), abs(p - a) / max(abs(p), abs(a), Decimal("1")))
        return [_leaf(path, True, True, "number", score)]
    if predicted_kind in {"boolean", "string"}:
        score = Decimal("0") if predicted == actual else Decimal("1")
        return [_leaf(path, True, True, predicted_kind, score)]
    if predicted_kind == "null":
        return [_leaf(path, True, True, "null", Decimal("0"))]
    if predicted_kind == "object":
        p_map = cast(dict[str, Any], predicted)
        a_map = cast(dict[str, Any], actual)
        if not p_map and not a_map:
            return [_leaf(path, True, True, "empty_object", Decimal("0"))]
        result: list[DivergenceLeaf] = []
        keys = sorted(set(p_map) | set(a_map), key=lambda key: key.encode("utf-8"))
        for key in keys:
            child = _pointer(path, key)
            if key not in p_map:
                result.append(
                    _leaf(child, False, True, "missing_predicted", Decimal("1"))
                )
            elif key not in a_map:
                result.append(_leaf(child, True, False, "missing_actual", Decimal("1")))
            else:
                result.extend(_compare(p_map[key], a_map[key], child))
        return result
    p_items = cast(tuple[Any, ...], predicted)
    a_items = cast(tuple[Any, ...], actual)
    if not p_items and not a_items:
        return [_leaf(path, True, True, "empty_array", Decimal("0"))]
    result = []
    for index in range(max(len(p_items), len(a_items))):
        child = _pointer(path, str(index))
        if index >= len(p_items):
            result.append(_leaf(child, False, True, "missing_predicted", Decimal("1")))
        elif index >= len(a_items):
            result.append(_leaf(child, True, False, "missing_actual", Decimal("1")))
        else:
            result.extend(_compare(p_items[index], a_items[index], child))
    return result


def compare_json(
    predicted_json: str,
    actual_json: str,
    *,
    threshold: Decimal = _DEFAULT_THRESHOLD,
) -> DivergenceResult:
    """Compare two JSON texts under the packet's deterministic recursive rules."""
    if not isinstance(threshold, Decimal) or not threshold.is_finite():
        _reject("divergence threshold must be a finite Decimal")
    if threshold < Decimal("0") or threshold > Decimal("1"):
        _reject("divergence threshold is outside [0,1]")
    predicted = _parse_json(predicted_json)
    actual = _parse_json(actual_json)
    leaves = tuple(_compare(predicted, actual, ""))
    score = (sum((leaf.score for leaf in leaves), Decimal("0")) / len(leaves)).quantize(
        _SIX_PLACES, rounding=ROUND_HALF_EVEN
    )
    return DivergenceResult(
        comparison_version=_COMPARISON_VERSION,
        predicted_digest=canonical_sha256(predicted),
        actual_digest=canonical_sha256(actual),
        leaves=leaves,
        score=score,
        threshold=threshold,
    )


def _record_digest(record: Any, schema: str, digest_field: str) -> str:
    return canonical_sha256(
        {
            "schema": schema,
            **{
                field.name: getattr(record, field.name)
                for field in fields(record)
                if field.name != digest_field
            },
        }
    )


def _receipt_from_row(row: Mapping[str, Any]) -> ExecutionReceipt:
    return ExecutionReceipt(
        receipt_id=str(row["receipt_id"]),
        attempt_id=str(row["attempt_id"]),
        attempt_digest=str(row["attempt_digest"]),
        proposal_id=str(row["proposal_id"]),
        evaluation_id=str(row["evaluation_id"]),
        evaluation_trace_digest=str(row["evaluation_trace_digest"]),
        decision_id=str(row["decision_id"]),
        decision_value=DecisionValue(str(row["decision_value"])),
        decision_digest=str(row["decision_digest"]),
        action_digest=str(row["action_digest"]),
        target_key=str(row["target_key"]),
        attempt_terminal_status=ExecutionStatus(str(row["attempt_terminal_status"])),
        outcome_digest=str(row["outcome_digest"]),
        before_effect_digest=str(row["before_effect_digest"]),
        after_effect_digest=(
            str(row["after_effect_digest"])
            if row.get("after_effect_digest") is not None
            else None
        ),
        observed_effect_version=(
            int(row["observed_effect_version"])
            if row.get("observed_effect_version") is not None
            else None
        ),
        executor_id=str(row["executor_id"]),
        idempotency_key=str(row["receipt_idempotency_key"]),
        verified=bool(row["verified"]),
        receipt_digest=str(row["receipt_digest"]),
    )


def _receipt_digest(receipt: ExecutionReceipt) -> str:
    return canonical_sha256(
        {
            "schema": "gam.execution-receipt.v1",
            **{
                name: getattr(receipt, name)
                for name in (
                    "attempt_id",
                    "attempt_digest",
                    "proposal_id",
                    "evaluation_id",
                    "evaluation_trace_digest",
                    "decision_id",
                    "decision_digest",
                    "action_digest",
                    "attempt_terminal_status",
                    "target_key",
                    "outcome_digest",
                    "before_effect_digest",
                    "after_effect_digest",
                    "observed_effect_version",
                    "executor_id",
                    "idempotency_key",
                    "verified",
                )
            },
        }
    )


def _report_from_row(row: Mapping[str, Any]) -> ConsequenceReport:
    report = ConsequenceReport(
        consequence_id=str(row.get("consequence_id", row["id"])),
        proposal_id=str(row["proposal_id"]),
        receipt_id=str(row["receipt_id"]),
        receipt_terminal_status=ExecutionStatus(str(row["receipt_terminal_status"])),
        receipt_digest=str(row["receipt_digest"]),
        observation_number=int(row["observation_number"]),
        predicted_snapshot_digest=str(row["predicted_snapshot_digest"]),
        actual_snapshot_digest=str(row["actual_snapshot_digest"]),
        comparison_version=str(row["comparison_version"]),
        predicted_outcome_json=_plain_json(
            _parse_json(_database_json(row["predicted_outcome"]))
        ),
        actual_outcome_json=_plain_json(
            _parse_json(_database_json(row["actual_outcome"]))
        ),
        leaf_report_json=canonical_json_bytes(
            _parse_json(_database_json(row["leaf_report"]))
        ).decode("utf-8"),
        divergence_score=Decimal(str(row["divergence_score"])),
        divergence_threshold=Decimal(str(row["divergence_threshold"])),
        divergence_summary=str(row["divergence_summary"]),
        reported_by=str(row["reported_by"]),
        report_digest=str(row["report_digest"]),
        idempotency_key=str(row["idempotency_key"]),
    )
    if report.report_digest != _record_digest(
        report, "gam.consequence-report.v1", "report_digest"
    ):
        _reject("stored consequence report digest mismatch")
    return report


def _serialization_failure(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) == "40001"


async def _serializable[T](operation: Callable[[], Awaitable[T]]) -> T:
    for attempt in range(_MAX_RETRIES):
        try:
            return await operation()
        except Exception as error:
            if not _serialization_failure(error) or attempt + 1 == _MAX_RETRIES:
                raise
    raise MemoryIntegrityError("serialization retry loop was not total")


async def report_consequence(
    receipt_id: UUID,
    observation_number: int,
    actual_outcome_json: str,
    reported_by: str,
    idempotency_key: str,
) -> ConsequenceReport:
    """Atomically append one receipt-bound consequence report."""
    if observation_number <= 0 or not reported_by or not idempotency_key:
        _reject("consequence identity fields are invalid")
    actual = _parse_json(actual_outcome_json)
    actual_text = _plain_json(actual)

    async def operation() -> ConsequenceReport:
        async with _APP_MEMORY.transaction() as connection:
            existing = await connection.fetchrow(
                "SELECT *, id AS consequence_id FROM consequence_reports "
                "WHERE idempotency_key = $1",
                idempotency_key,
            )
            if existing is not None:
                report = _report_from_row(existing)
                if (
                    report.receipt_id == str(receipt_id)
                    and report.observation_number == observation_number
                    and report.actual_outcome_json == actual_text
                    and report.reported_by == reported_by
                ):
                    return report
                raise MemoryConflictError("consequence idempotency key conflicts")
            row = await connection.fetchrow(
                """
SELECT r.id AS receipt_id, r.attempt_id, r.attempt_digest, r.proposal_id,
       r.evaluation_id, r.evaluation_trace_digest, r.decision_id,
       r.decision_value, r.decision_digest, r.action_digest, r.target_key,
       r.attempt_terminal_status, r.outcome_digest, r.before_effect_digest,
       r.after_effect_digest, r.observed_effect_version, r.executor_id,
       r.idempotency_key AS receipt_idempotency_key, r.verified, r.receipt_digest,
       p.predicted_outcome::STRING AS predicted_outcome,
       g.status AS evaluation_status, a.demo_effect_id
FROM execution_receipts AS r
JOIN execution_attempts AS a ON a.id = r.attempt_id
JOIN decisions AS d ON d.id = r.decision_id
JOIN gate_evaluations AS g ON g.id = r.evaluation_id
JOIN proposals AS p ON p.id = r.proposal_id
WHERE r.id = $1::UUID
FOR UPDATE OF r
""",
                str(receipt_id),
            )
            if row is None:
                _reject("execution receipt was not found")
            receipt = _receipt_from_row(row)
            if receipt.receipt_digest != _receipt_digest(receipt):
                _reject("execution receipt digest mismatch")
            if (
                receipt.attempt_terminal_status is not ExecutionStatus.OBSERVED
                or not receipt.verified
                or receipt.after_effect_digest is None
                or receipt.observed_effect_version is None
                or row.get("demo_effect_id") is None
                or str(row["evaluation_status"]) != "FINALIZED"
            ):
                _reject("receipt does not bind an observed finalized effect")
            predicted = _parse_json(_database_json(row["predicted_outcome"]))
            predicted_text = _plain_json(predicted)
            divergence = compare_json(predicted_text, actual_text)
            leaf_text = canonical_json_bytes(divergence.leaves).decode("utf-8")
            provisional = ConsequenceReport(
                consequence_id=str(uuid4()),
                proposal_id=receipt.proposal_id,
                receipt_id=receipt.receipt_id,
                receipt_terminal_status=ExecutionStatus.OBSERVED,
                receipt_digest=receipt.receipt_digest,
                observation_number=observation_number,
                predicted_snapshot_digest=divergence.predicted_digest,
                actual_snapshot_digest=divergence.actual_digest,
                comparison_version=divergence.comparison_version,
                predicted_outcome_json=predicted_text,
                actual_outcome_json=actual_text,
                leaf_report_json=leaf_text,
                divergence_score=divergence.score,
                divergence_threshold=divergence.threshold,
                divergence_summary=(
                    "MORE" if divergence.score >= divergence.threshold else "LESS"
                ),
                reported_by=reported_by,
                report_digest="0" * 64,
                idempotency_key=idempotency_key,
            )
            report = replace(
                provisional,
                report_digest=_record_digest(
                    provisional, "gam.consequence-report.v1", "report_digest"
                ),
            )
            await _APP_MEMORY.append_consequence(report)
            return report

    return await _serializable(operation)


async def get_divergence_warnings(
    current_proposal_id: UUID,
    *,
    limit: int = 3,
) -> tuple[ConsequenceReport, ...]:
    """Return qualifying warnings after NEAR and exact SAME classification."""
    if limit <= 0:
        _reject("warning limit must be positive")

    async def operation() -> tuple[ConsequenceReport, ...]:
        async with _APP_MEMORY.transaction() as connection:
            proposal = await _APP_MEMORY.get_proposal(str(current_proposal_id))
            latest = await connection.fetchrow(
                "SELECT id FROM gate_evaluations WHERE proposal_id = $1::UUID "
                "AND status = 'FINALIZED' ORDER BY created_at DESC, id DESC LIMIT 1",
                str(current_proposal_id),
            )
            if latest is None:
                _reject("current proposal has no finalized evaluation")
            precedents = await _APP_MEMORY.search_precedents(
                proposal.embedding, 5, str(latest["id"])
            )
            qualifying_ids = {
                consequence.consequence_id
                for precedent in precedents
                if precedent.similarity is not None
                and precedent.similarity >= _NEAR_THRESHOLD
                and precedent.action_type_key == proposal.action_type_key
                and precedent.target_key == proposal.target_key
                for consequence in precedent.consequence_refs
                if consequence.receipt_terminal_status is ExecutionStatus.OBSERVED
                and consequence.divergence >= _DEFAULT_THRESHOLD
            }
            if not qualifying_ids:
                return ()
            rows = await connection.fetch(
                "SELECT *, id AS consequence_id FROM consequence_reports "
                "WHERE id = ANY($1::UUID[])",
                tuple(sorted(qualifying_ids)),
            )
            reports = [_report_from_row(row) for row in rows]
            reports.sort(
                key=lambda item: (-item.divergence_score, UUID(item.consequence_id))
            )
            return tuple(reports[:limit])

    return await _serializable(operation)


def _prior(result: CheckResult, proposal_id: str) -> PriorEvaluationTrace:
    return PriorEvaluationTrace(
        evaluation_id=result.evaluation_id,
        proposal_id=proposal_id,
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


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


async def reevaluate_with_consequence(
    proposal_id: UUID,
    consequence_id: UUID,
    requested_by: str,
) -> CheckResult | BlockedResult:
    """Append a human-requested evaluation over a new consequence snapshot."""
    if not requested_by:
        _reject("requesting human identity is empty")

    async def operation() -> CheckResult | BlockedResult:
        async with _APP_MEMORY.transaction() as connection:
            proposal = await _APP_MEMORY.get_proposal(str(proposal_id))
            latest_row = await connection.fetchrow(
                "SELECT *, id AS evaluation_id FROM gate_evaluations "
                "WHERE proposal_id = $1::UUID AND status = 'FINALIZED' "
                "ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE",
                str(proposal_id),
            )
            if latest_row is None:
                _reject("proposal has no finalized evaluation")
            latest = _result_from_row(latest_row)
            if not isinstance(latest, CheckResult):
                _reject("latest finalized evaluation is invalid")
            consequence_row = await connection.fetchrow(
                "SELECT *, id AS consequence_id FROM consequence_reports "
                "WHERE id = $1::UUID",
                str(consequence_id),
            )
            if consequence_row is None:
                _reject("named consequence was not found")
            consequence = _report_from_row(consequence_row)
            base = _snapshot_from_json(latest_row["input_snapshot"])
            precedents = await _APP_MEMORY.search_precedents(
                proposal.embedding, 5, latest.evaluation_id
            )
            if not any(
                ref.consequence_id == consequence.consequence_id
                for precedent in precedents
                for ref in precedent.consequence_refs
            ):
                _reject("named consequence is not a current precedent")
            exclusions = await _APP_MEMORY.get_exclusions(
                proposal.action_type_key, proposal.target_key
            )
            evaluation_id = str(uuid4())
            snapshot = finalize_snapshot(
                EvaluationSnapshot(
                    evaluation_id=evaluation_id,
                    snapshot_id=str(uuid4()),
                    profile_version=base.profile_version,
                    proposal=proposal,
                    policy=base.policy,
                    precedents=precedents,
                    exclusions=exclusions,
                    capabilities=base.capabilities,
                    dependencies=base.dependencies,
                    prior_evaluation=_prior(latest, str(proposal_id)),
                    captured_at=_utc_now(),
                    snapshot_digest="0" * 64,
                )
            )
            result = evaluate_proposal(snapshot, default_rule_config())
            if result.prior_evaluation_id != latest.evaluation_id:
                _reject("evaluator returned invalid prior genealogy")
            await _APP_MEMORY.append_re_evaluation(snapshot, result)
            return result

    return await _serializable(operation)
