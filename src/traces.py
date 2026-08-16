"""Canonical serialization and validation for sparse governance traces."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from decimal import Decimal
from enum import Enum
from types import MappingProxyType
from typing import Any, NoReturn, TypeVar, cast

from src.models import (
    BlockedResult,
    CheckResult,
    DecisionValue,
    DependencyState,
    EvaluationSnapshot,
    EvidenceGap,
    ExecutionStatus,
    OperatorTraceStep,
    PolicyEffect,
    PrecedentRef,
    PriorEvaluationTrace,
    Proposal,
    ReducerTraceStep,
)
from src.operators import ALLOWED_POLES, OperatorFamily
from src.verdict import Risk, Verdict
from src.witnesses import Witness

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
FACT_RULE_ID = re.compile(r"^F(?:0[1-9]|1[0-2])(?:_[A-Z0-9_]+)?$")
STEP_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
STEP_ID = re.compile(r"^(.+):(\d{2}):([A-Z][A-Z0-9_]{0,63})$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
PINNED_EMBEDDING_MODEL = "text-embedding-3-small"
PINNED_EMBEDDING_DIMENSIONS = 1536

_ENUM_TAGS: Mapping[type[Enum], str] = MappingProxyType(
    {
        Verdict: "gam.public.v1/Verdict",
        Risk: "gam.public.v1/Risk",
        OperatorFamily: "gam.public.v1/OperatorFamily",
        Witness: "gam.public.v1/Witness",
        DependencyState: "gam.memory.v1/DependencyState",
        DecisionValue: "gam.memory.v1/DecisionValue",
        PolicyEffect: "gam.policy.v1/PolicyEffect",
        ExecutionStatus: "gam.execution.v1/ExecutionStatus",
    }
)
_REDUCER_BINDINGS = MappingProxyType(
    {
        "R1": (OperatorFamily.EVERY_SOME, "SOME"),
        "R2": (OperatorFamily.EVERY_SOME, "SOME"),
        "R3": (OperatorFamily.EVERY_SOME, "SOME"),
        "R4": (OperatorFamily.EVERY_SOME, "EVERY"),
    }
)

TraceStep = OperatorTraceStep | ReducerTraceStep
Result = CheckResult | BlockedResult
T = TypeVar("T")

__all__ = [
    "BlockedResult",
    "CheckResult",
    "EvaluationSnapshot",
    "OperatorTraceStep",
    "PriorEvaluationTrace",
    "ReducerTraceStep",
    "canonical_json_bytes",
    "canonical_sha256",
    "check_result_digest",
    "blocked_result_digest",
    "snapshot_digest",
    "make_step_id",
    "finalize_check_result",
    "finalize_blocked_result",
    "finalize_snapshot",
    "validate_check_result",
    "validate_blocked_result",
    "validate_snapshot",
]


class ContractViolation(ValueError):
    """One public canonical-contract violation."""


def _reject(message: str) -> NoReturn:
    raise ContractViolation(message)


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        _reject("non-finite Decimal")
    if value.is_zero():
        return "0"
    normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _normalized_mapping(value: Mapping[Any, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, item in value.items():
        if not isinstance(raw_key, str):
            _reject("canonical mapping key is not a string")
        key = unicodedata.normalize("NFC", raw_key)
        if key in result:
            _reject("normalized mapping-key collision")
        result[key] = _canonical_value(item)
    return result


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Enum):
        enum_type = type(value)
        tag = _ENUM_TAGS.get(enum_type)
        if tag is None:
            _reject("unregistered Enum type")
        return {"$enum": tag, "member": value.name}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_canonical_value(item) for item in value]
    if isinstance(value, Mapping):
        return _normalized_mapping(value)
    if isinstance(value, Decimal):
        return {"$decimal": _decimal_text(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            _reject("non-finite float")
        return {"$float": format(value, ".17g")}
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    _reject(f"unsupported canonical type: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return stable UTF-8 canonical JSON for a supported immutable value."""
    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return the complete lowercase SHA-256 canonical digest."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject("duplicate JSON key")
        normalized = unicodedata.normalize("NFC", key)
        if normalized in value:
            _reject("normalized JSON key collision")
        value[normalized] = item
    return value


def _canonical_plain_json(text: str) -> None:
    def reject_constant(_: str) -> NoReturn:
        _reject("non-finite JSON number")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ContractViolation("invalid canonical JSON text") from error
    observed = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    if observed != text:
        _reject("JSON text is not canonical")


def _validate_digest(value: str, field_name: str) -> None:
    if not HEX_64.fullmatch(value):
        _reject(f"invalid digest: {field_name}")


def _validate_dataclass_fields(value: Any) -> None:
    if not is_dataclass(value) or isinstance(value, type):
        _reject("expected dataclass record")
    for field in fields(value):
        item = getattr(value, field.name)
        if field.name.endswith("_digest") and item is not None:
            if not isinstance(item, str):
                _reject(f"digest is not text: {field.name}")
            _validate_digest(item, field.name)
        if field.name.endswith("_json") and item is not None:
            if not isinstance(item, str):
                _reject(f"JSON field is not text: {field.name}")
            _canonical_plain_json(item)
        if isinstance(item, tuple):
            for child in item:
                if is_dataclass(child) and not isinstance(child, type):
                    _validate_dataclass_fields(child)
        elif is_dataclass(item) and not isinstance(item, type):
            _validate_dataclass_fields(item)


def make_step_id(evaluation_id: str, ordinal: int, rule_id: str) -> str:
    """Build the deterministic 01-based trace-step identity."""
    if not evaluation_id or not 1 <= ordinal <= 99:
        _reject("invalid trace ordinal")
    if not STEP_RULE_ID.fullmatch(rule_id):
        _reject("invalid trace rule ID")
    return f"{evaluation_id}:{ordinal:02d}:{rule_id}"


def _validate_proposal(proposal: Proposal) -> None:
    _validate_dataclass_fields(proposal)
    if (
        proposal.embedding_model != PINNED_EMBEDDING_MODEL
        or len(proposal.embedding) != PINNED_EMBEDDING_DIMENSIONS
        or any(not math.isfinite(value) for value in proposal.embedding)
    ):
        _reject("proposal embedding contract mismatch")
    lineage = (
        proposal.parent_proposal_id,
        proposal.source_modify_decision_id,
        proposal.source_modify_decision_value,
    )
    if all(item is None for item in lineage):
        return
    if (
        lineage[0] is None
        or lineage[1] is None
        or lineage[2] is not DecisionValue.MODIFY
    ):
        _reject("proposal MODIFY lineage is incomplete")


def _validate_precedent(precedent: PrecedentRef) -> None:
    _validate_dataclass_fields(precedent)
    decision_fields = (
        precedent.decision,
        precedent.decision_id,
        precedent.decision_digest,
    )
    if not (
        all(item is None for item in decision_fields)
        or all(item is not None for item in decision_fields)
    ):
        _reject("precedent decision binding is partial")
    receipt_fields = (
        precedent.receipt_id,
        precedent.receipt_digest,
        precedent.receipt_terminal_status,
    )
    if not (
        all(item is None for item in receipt_fields)
        or all(item is not None for item in receipt_fields)
    ):
        _reject("precedent receipt binding is partial")
    if precedent.consequence_refs and (
        precedent.receipt_terminal_status is not ExecutionStatus.OBSERVED
    ):
        _reject("consequence requires an OBSERVED receipt")
    similarity = precedent.similarity
    error = precedent.similarity_error_code
    if (similarity is None) == (error is None):
        _reject("precedent similarity/error binding mismatch")
    if similarity is not None and not similarity.is_finite():
        _reject("precedent similarity is non-finite")


def _validate_gap_scope(gaps: tuple[EvidenceGap, ...]) -> None:
    ids: set[str] = set()
    for gap in gaps:
        _validate_dataclass_fields(gap)
        if not gap.gap_id or gap.gap_id in ids or not gap.resolution_rule_id:
            _reject("evidence gap identity is invalid")
        ids.add(gap.gap_id)


def _validate_trace(
    evaluation_id: str,
    trace: tuple[TraceStep, ...],
    because_step_id: str | None,
    *,
    blocked: bool,
) -> None:
    if not trace or len(trace) > 99:
        _reject("trace cardinality is invalid")
    step_ids: set[str] = set()
    rule_positions: dict[str, list[int]] = {}
    for ordinal, step in enumerate(trace, start=1):
        _validate_dataclass_fields(step)
        expected = make_step_id(evaluation_id, ordinal, step.rule_id)
        if step.step_id != expected or step.step_id in step_ids:
            _reject("trace step identity/ordinal mismatch")
        step_ids.add(step.step_id)
        rule_positions.setdefault(step.rule_id, []).append(ordinal)
        if step.pole not in ALLOWED_POLES[step.family]:
            _reject("operator pole is not allowed for family")
        if isinstance(step, ReducerTraceStep):
            binding = _REDUCER_BINDINGS.get(step.rule_id)
            if binding is None or binding != (step.family, step.pole):
                _reject("reducer family/pole binding mismatch")
            if (
                not step.decisive_fact_step_ids
                or any(item not in step_ids for item in step.decisive_fact_step_ids)
                or step.step_id in step.decisive_fact_step_ids
            ):
                _reject("reducer decisive-step binding mismatch")
        elif blocked is False and step.rule_id in _REDUCER_BINDINGS:
            _reject("reducer step is not typed ReducerTraceStep")
    for rule_id, positions in rule_positions.items():
        if rule_id == "F10_DEPENDENCY_FORMULA":
            if len(positions) % 2 or any(
                right != left + 1
                for left, right in zip(positions[::2], positions[1::2], strict=True)
            ):
                _reject("F10 trace pairs are not adjacent")
        elif len(positions) != 1:
            _reject("duplicate trace rule ID")
    if blocked:
        if any(isinstance(step, ReducerTraceStep) for step in trace):
            _reject("BLOCKED trace contains a reducer")
        if because_step_id is not None:
            _reject("BLOCKED trace cannot name terminal BECAUSE")
        return
    if because_step_id is None or because_step_id not in step_ids:
        _reject("terminal BECAUSE step is absent")
    terminal = trace[-1]
    if (
        terminal.step_id != because_step_id
        or terminal.family is not OperatorFamily.BECAUSE
        or terminal.pole != "BECAUSE"
    ):
        _reject("BECAUSE must be the terminal trace step")


def _result_payload(result: Result) -> dict[str, Any]:
    status = "BLOCKED" if isinstance(result, BlockedResult) else "FINALIZED"
    return {
        "schema": "gam.evaluation-trace.v1",
        "status": status,
        **{
            field.name: getattr(result, field.name)
            for field in fields(result)
            if field.name != "trace_digest"
        },
    }


def _prior_payload(prior: PriorEvaluationTrace) -> dict[str, Any]:
    return {
        "schema": "gam.evaluation-trace.v1",
        "status": "FINALIZED",
        **{
            field.name: getattr(prior, field.name)
            for field in fields(prior)
            if field.name not in {"proposal_id", "trace_digest"}
        },
    }


def check_result_digest(result: CheckResult) -> str:
    """Recompute every finalized trace field except its digest."""
    return canonical_sha256(_result_payload(result))


def blocked_result_digest(result: BlockedResult) -> str:
    """Recompute every BLOCKED trace field except its digest."""
    return canonical_sha256(_result_payload(result))


def snapshot_digest(snapshot: EvaluationSnapshot) -> str:
    """Recompute every snapshot field except its digest."""
    return canonical_sha256(
        {
            "schema": "gam.evaluation-snapshot.v1",
            **{
                field.name: getattr(snapshot, field.name)
                for field in fields(snapshot)
                if field.name != "snapshot_digest"
            },
        }
    )


def _validate_changed_fact_ids(values: tuple[str, ...]) -> None:
    if values != tuple(sorted(set(values))):
        _reject("changed fact-rule IDs are not sorted and unique")
    if any(not FACT_RULE_ID.fullmatch(value) for value in values):
        _reject("changed fact-rule ID is outside F01-F12")


def validate_check_result(result: CheckResult) -> CheckResult:
    """Validate one complete FINALIZED result and its full digest."""
    _validate_dataclass_fields(result)
    _validate_gap_scope(result.evidence_gaps)
    _validate_changed_fact_ids(result.changed_fact_rule_ids)
    _validate_trace(
        result.evaluation_id,
        result.operator_trace,
        result.because_step_id,
        blocked=False,
    )
    if result.verdict is Verdict.IFF and not any(
        item.state is DependencyState.UNRESOLVED for item in result.dependencies
    ):
        _reject("IFF result has no unresolved dependency")
    if result.profile_version is not None and not result.profile_version:
        _reject("empty profile version")
    if result.trace_digest != check_result_digest(result):
        _reject("finalized trace digest mismatch")
    return result


def validate_blocked_result(result: BlockedResult) -> BlockedResult:
    """Validate one infrastructure-BLOCKED result and its full digest."""
    _validate_dataclass_fields(result)
    _validate_gap_scope(result.evidence_gaps)
    if result.profile_version is not None or result.changed_fact_rule_ids:
        _reject("BLOCKED profile/changed-fact fields must be empty")
    _validate_trace(
        result.evaluation_id,
        cast(tuple[TraceStep, ...], result.operator_trace),
        None,
        blocked=True,
    )
    if not result.error_code or not result.safe_message:
        _reject("BLOCKED safe error fields are empty")
    if result.trace_digest != blocked_result_digest(result):
        _reject("BLOCKED trace digest mismatch")
    return result


def _validate_prior(prior: PriorEvaluationTrace, proposal_id: str) -> None:
    _validate_dataclass_fields(prior)
    if prior.proposal_id != proposal_id:
        _reject("prior evaluation belongs to another proposal")
    _validate_changed_fact_ids(prior.changed_fact_rule_ids)
    _validate_gap_scope(prior.evidence_gaps)
    _validate_trace(
        prior.evaluation_id,
        prior.operator_trace,
        prior.because_step_id,
        blocked=False,
    )
    if prior.trace_digest != canonical_sha256(_prior_payload(prior)):
        _reject("prior evaluation trace digest mismatch")


def validate_snapshot(snapshot: EvaluationSnapshot) -> EvaluationSnapshot:
    """Validate a frozen input snapshot and its prior-trace genealogy."""
    _validate_dataclass_fields(snapshot)
    _validate_proposal(snapshot.proposal)
    if snapshot.evaluation_id == "" or snapshot.snapshot_id == "":
        _reject("snapshot identity is empty")
    if snapshot.prior_evaluation is not None:
        _validate_prior(snapshot.prior_evaluation, snapshot.proposal.proposal_id)
    for precedent in snapshot.precedents:
        _validate_precedent(precedent)
    for capability in snapshot.capabilities:
        _validate_dataclass_fields(capability)
    dependency_ids = [item.dependency_id for item in snapshot.dependencies]
    if len(dependency_ids) != len(set(dependency_ids)):
        _reject("duplicate snapshot dependency ID")
    if snapshot.snapshot_digest != snapshot_digest(snapshot):
        _reject("snapshot digest mismatch")
    return snapshot


def finalize_check_result(result: CheckResult) -> CheckResult:
    """Return a frozen result with its complete canonical digest populated."""
    finalized = replace(result, trace_digest=check_result_digest(result))
    return validate_check_result(finalized)


def finalize_blocked_result(result: BlockedResult) -> BlockedResult:
    """Return a frozen BLOCKED result with its canonical digest populated."""
    finalized = replace(result, trace_digest=blocked_result_digest(result))
    return validate_blocked_result(finalized)


def finalize_snapshot(snapshot: EvaluationSnapshot) -> EvaluationSnapshot:
    """Return a frozen snapshot with its complete canonical digest populated."""
    finalized = replace(snapshot, snapshot_digest=snapshot_digest(snapshot))
    return validate_snapshot(finalized)
