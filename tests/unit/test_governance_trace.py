"""Sparse typed trace construction tests."""

from __future__ import annotations

import importlib
import json
from typing import Any

from src.models import OperatorTraceStep, ReducerTraceStep
from src.operators import OperatorFamily

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")
evaluate = fixtures.evaluate
make_snapshot = fixtures.make_snapshot


def test_ordinals_are_contiguous_and_terminal_because_is_exact() -> None:
    result = evaluate(make_snapshot())
    for ordinal, step in enumerate(result.operator_trace, start=1):
        assert step.step_id == f"{result.evaluation_id}:{ordinal:02d}:{step.rule_id}"
    terminal = result.operator_trace[-1]
    assert isinstance(terminal, OperatorTraceStep)
    assert terminal.family is OperatorFamily.BECAUSE
    assert terminal.pole == "BECAUSE"
    assert result.because_step_id == terminal.step_id


def test_reducer_is_typed_and_binds_decisive_facts() -> None:
    result = evaluate(make_snapshot())
    reducer = next(
        step for step in result.operator_trace if isinstance(step, ReducerTraceStep)
    )
    assert reducer.rule_id == "R4_YES"
    assert reducer.family is OperatorFamily.EVERY_SOME
    assert reducer.pole == "EVERY"
    prior_ids = {
        step.step_id
        for step in result.operator_trace
        if not isinstance(step, ReducerTraceStep)
        and step.rule_id != "F12_FINAL_BECAUSE"
    }
    assert set(reducer.decisive_fact_step_ids) <= prior_ids
    because = result.operator_trace[-1]
    assert reducer.step_id in because.object_refs


def test_sparse_trace_does_not_emit_inapplicable_facts() -> None:
    result = evaluate(make_snapshot())
    rules = [step.rule_id for step in result.operator_trace]
    assert "F03_EXCLUSION_IDENTITY" not in rules
    assert "F09_CAPABILITY_SNAPSHOT" not in rules
    assert "F10_DEPENDENCY_FORMULA" not in rules
    assert len(result.operator_trace) < 15
    for step in result.operator_trace:
        json.loads(step.result_json)
