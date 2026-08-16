"""Frozen/slotted public type and sparse-trace contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from src.models import (
    CheckResult,
    DependencyState,
    EvidenceGap,
    EvidenceRef,
    OperatorTraceStep,
    ReducerTraceStep,
)
from src.operators import OperatorFamily
from src.traces import ContractViolation, finalize_check_result, make_step_id
from src.verdict import Risk, Verdict
from src.witnesses import Witness

DIGEST = "0" * 64


def _result() -> CheckResult:
    evaluation_id = "evaluation-1"
    first = OperatorTraceStep(
        step_id=make_step_id(evaluation_id, 1, "F01"),
        rule_id="F01",
        family=OperatorFamily.THIS,
        pole="THIS",
        subject_ref="proposal-1",
        object_refs=(),
        result_json="true",
        evidence_refs=(EvidenceRef("e-1", "fixture", DIGEST),),
    )
    reducer = ReducerTraceStep(
        step_id=make_step_id(evaluation_id, 2, "R4_YES"),
        rule_id="R4_YES",
        family=OperatorFamily.EVERY_SOME,
        pole="EVERY",
        decisive_fact_step_ids=(first.step_id,),
        result_json='"YES"',
    )
    because = OperatorTraceStep(
        step_id=make_step_id(evaluation_id, 3, "F02"),
        rule_id="F02",
        family=OperatorFamily.BECAUSE,
        pole="BECAUSE",
        subject_ref="evaluation-1",
        object_refs=(reducer.step_id,),
        result_json='"terminal"',
        evidence_refs=(),
    )
    return CheckResult(
        verdict=Verdict.YES,
        risk=Risk.LOW,
        operator_trace=(first, reducer, because),
        evidence_gaps=(),
        dependencies=(),
        precedent_refs=(),
        consequence_warning_refs=(),
        because_step_id=because.step_id,
        evaluation_id=evaluation_id,
        profile_version=None,
        prior_evaluation_id=None,
        changed_fact_rule_ids=(),
        evaluator_version="public-contract-test",
        rule_config_digest=DIGEST,
        input_snapshot_digest=DIGEST,
        policy_digest=DIGEST,
        trace_digest=DIGEST,
    )


def test_records_are_frozen_and_slotted() -> None:
    gap = EvidenceGap(
        "gap-1",
        Witness.WHAT,
        "proposal-1",
        "What evidence is required?",
        "one fixture",
        "RESOLVE-1",
    )
    assert not hasattr(gap, "__dict__")
    with pytest.raises(FrozenInstanceError):
        gap.question = "changed"  # type: ignore[misc]


def test_trace_has_contiguous_ids_typed_reducer_and_terminal_because() -> None:
    result = finalize_check_result(_result())
    assert len(result.trace_digest) == 64
    assert isinstance(result.operator_trace[1], ReducerTraceStep)
    assert result.operator_trace[-1].step_id == result.because_step_id
    assert result.operator_trace[-1].family is OperatorFamily.BECAUSE


@pytest.mark.parametrize(
    ("legacy_rule_id", "pole"),
    (("R1", "SOME"), ("R2", "SOME"), ("R3", "SOME"), ("R4", "EVERY")),
)
def test_abbreviated_reducer_ids_are_rejected(legacy_rule_id: str, pole: str) -> None:
    original = _result()
    first, reducer, because = original.operator_trace
    assert isinstance(reducer, ReducerTraceStep)
    assert isinstance(first, OperatorTraceStep)
    assert isinstance(because, OperatorTraceStep)
    legacy = replace(
        reducer,
        step_id=make_step_id(original.evaluation_id, 2, legacy_rule_id),
        rule_id=legacy_rule_id,
        pole=pole,
    )
    terminal = replace(because, object_refs=(legacy.step_id,))
    with pytest.raises(ContractViolation, match="reducer family/pole"):
        finalize_check_result(
            replace(original, operator_trace=(first, legacy, terminal))
        )


def test_nonterminal_because_is_rejected() -> None:
    original = _result()
    reordered = CheckResult(
        **{
            **{name: getattr(original, name) for name in original.__dataclass_fields__},
            "operator_trace": (
                original.operator_trace[2],
                original.operator_trace[0],
                original.operator_trace[1],
            ),
        }
    )
    with pytest.raises(ContractViolation):
        finalize_check_result(reordered)


def test_iff_requires_an_unresolved_dependency() -> None:
    original = _result()
    iff = CheckResult(
        **{
            **{name: getattr(original, name) for name in original.__dataclass_fields__},
            "verdict": Verdict.IFF,
        }
    )
    assert DependencyState.UNRESOLVED.value == "UNRESOLVED"
    with pytest.raises(ContractViolation, match="unresolved dependency"):
        finalize_check_result(iff)
