"""Explicit reducer precedence and totality tests."""

from __future__ import annotations

import importlib
from decimal import Decimal
from typing import Any

from src.models import (
    CapabilityFact,
    CheckResult,
    DependencyState,
    PolicyEffect,
    ReducerTraceStep,
)
from src.verdict import Risk, Verdict

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")
DIGEST = fixtures.DIGEST
evaluate = fixtures.evaluate
make_consequence = fixtures.make_consequence
make_dependency = fixtures.make_dependency
make_policy = fixtures.make_policy
make_precedent = fixtures.make_precedent
make_snapshot = fixtures.make_snapshot


def reducer_id(result: CheckResult) -> str:
    reducer = next(
        step for step in result.operator_trace if isinstance(step, ReducerTraceStep)
    )
    return reducer.rule_id


def test_all_yes_conditions_select_r4() -> None:
    result = evaluate(make_snapshot())
    assert (result.verdict, result.risk, reducer_id(result)) == (
        Verdict.YES,
        Risk.LOW,
        "R4_YES",
    )


def test_complete_unresolved_dependency_selects_r3() -> None:
    dependency = make_dependency(DependencyState.UNRESOLVED)
    result = evaluate(make_snapshot(dependencies=(dependency,)))
    assert (result.verdict, result.risk, reducer_id(result)) == (
        Verdict.IFF,
        Risk.MEDIUM,
        "R3_IFF",
    )


def test_incomplete_dependency_selects_r2_over_r3() -> None:
    complete = make_dependency(DependencyState.UNRESOLVED, dependency_id="b")
    incomplete = make_dependency(
        DependencyState.UNRESOLVED, dependency_id="a", complete=False
    )
    result = evaluate(make_snapshot(dependencies=(complete, incomplete)))
    assert result.verdict is Verdict.MAYBE
    assert reducer_id(result) == "R2_MAYBE"


def test_r1_retains_lower_reasons_but_suppresses_gaps() -> None:
    high = make_precedent(consequences=(make_consequence(Decimal("0.50000")),))
    result = evaluate(
        make_snapshot(
            policy=make_policy(effect=PolicyEffect.DENY, require_consequence=True),
            precedents=(high,),
        )
    )
    assert result.verdict is Verdict.NO
    assert result.risk is Risk.HIGH
    assert result.evidence_gaps == ()
    aggregate = next(
        step for step in result.operator_trace if step.rule_id.startswith("F11")
    )
    assert "F08_HIGH_DIVERGENCE" in aggregate.result_json


def test_false_required_capability_beats_unresolved_dependency() -> None:
    dependency = make_dependency(DependencyState.UNRESOLVED)
    capability = CapabilityFact(
        capability_id="capability-1",
        subject_ref="proposal-current",
        state=DependencyState.FALSE,
        snapshot_digest=DIGEST,
        evidence_refs=(),
    )
    result = evaluate(
        make_snapshot(
            policy=make_policy(required_capability_ids=("capability-1",)),
            capabilities=(capability,),
            dependencies=(dependency,),
        )
    )
    assert result.verdict is Verdict.NO
    assert reducer_id(result) == "R1_NO"
