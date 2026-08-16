"""Input permutation, hashing, and numeric-reducer prohibitions."""

from __future__ import annotations

import ast
import importlib
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

from src.governance import default_rule_config, evaluate_proposal
from src.models import CheckResult, DecisionValue, PriorEvaluationTrace
from src.traces import snapshot_digest

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")
evaluate = fixtures.evaluate
make_consequence = fixtures.make_consequence
make_precedent = fixtures.make_precedent
make_snapshot = fixtures.make_snapshot

ROOT = Path(__file__).parents[2]


def test_collection_permutation_produces_identical_trace_digest() -> None:
    first = make_precedent(proposal_id="a")
    second = make_precedent(
        proposal_id="b",
        similarity=Decimal("0.86000000"),
        decision=DecisionValue.APPROVE,
        consequences=(make_consequence(),),
    )
    canonical = make_snapshot(precedents=(first, second))
    left = evaluate(canonical)
    right = evaluate(replace(canonical, precedents=(second, first)))
    assert left.trace_digest == right.trace_digest


def test_re_evaluation_reports_only_semantic_fact_changes() -> None:
    policy = fixtures.make_policy(require_consequence=True)
    low_snapshot = make_snapshot(
        policy=policy,
        precedents=(make_precedent(consequences=(make_consequence(),)),),
    )
    low = evaluate(low_snapshot)
    prior = PriorEvaluationTrace(
        evaluation_id=low.evaluation_id,
        proposal_id=low_snapshot.proposal.proposal_id,
        verdict=low.verdict,
        risk=low.risk,
        operator_trace=low.operator_trace,
        evidence_gaps=low.evidence_gaps,
        dependencies=low.dependencies,
        precedent_refs=low.precedent_refs,
        consequence_warning_refs=low.consequence_warning_refs,
        because_step_id=low.because_step_id,
        profile_version=low.profile_version,
        prior_evaluation_id=low.prior_evaluation_id,
        changed_fact_rule_ids=low.changed_fact_rule_ids,
        evaluator_version=low.evaluator_version,
        rule_config_digest=low.rule_config_digest,
        input_snapshot_digest=low.input_snapshot_digest,
        policy_digest=low.policy_digest,
        trace_digest=low.trace_digest,
    )
    high = make_snapshot(
        policy=policy,
        precedents=(
            make_precedent(consequences=(make_consequence(Decimal("0.50000")),)),
        ),
        evaluation_id="evaluation-current-2",
    )
    high = replace(high, prior_evaluation=prior, snapshot_digest="a" * 64)
    high = replace(high, snapshot_digest=snapshot_digest(high))
    result = evaluate_proposal(high, default_rule_config())
    assert isinstance(result, CheckResult)
    assert result.changed_fact_rule_ids == (
        "F08_DIVERGENCE_BOUNDARY",
        "F11_CONDITION_AGGREGATE",
        "F12_FINAL_BECAUSE",
    )


def test_governance_never_uses_numeric_verdict_reduction() -> None:
    tree = ast.parse((ROOT / "src/governance.py").read_text(encoding="utf-8"))

    def mentions_verdict(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Name) and child.id == "Verdict"
            for child in ast.walk(node)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            assert not mentions_verdict(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"sorted", "min", "max", "sum", "int"}:
                assert not mentions_verdict(node)
        if isinstance(node, ast.BinOp):
            assert not mentions_verdict(node)
