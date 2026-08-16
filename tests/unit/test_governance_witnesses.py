"""Atomic witness-gap finalization tests."""

from __future__ import annotations

import importlib
from dataclasses import replace
from typing import Any

from src.governance import policy_input_digest
from src.models import EvidenceRequirement, PolicyInput, PolicyRule
from src.witnesses import Witness

fixtures: Any = importlib.import_module("tests.unit.test_governance_rules")
evaluate = fixtures.evaluate
make_policy = fixtures.make_policy
make_snapshot = fixtures.make_snapshot


def test_each_standard_witness_is_retained_as_one_atomic_gap() -> None:
    base = make_policy()
    requirements = tuple(
        EvidenceRequirement(
            requirement_id=f"requirement-{witness.name}",
            kind=f"kind-{witness.name}",
            witness=witness,
            subject_ref=f"subject-{witness.name}",
            resolution_rule_id="F07_EVIDENCE_COMPLETENESS",
        )
        for witness in Witness
    )
    rule = base.rules[0]
    policy = PolicyInput(
        policy_version=base.policy_version,
        policy_digest=base.policy_digest,
        rules=(
            PolicyRule(
                rule_id=rule.rule_id,
                action_type_key=rule.action_type_key,
                target_key=rule.target_key,
                effect=rule.effect,
                because=rule.because,
                required_evidence=requirements,
                required_capability_ids=(),
                require_consequence=False,
            ),
        ),
    )
    policy = replace(policy, policy_digest=policy_input_digest(policy))
    result = evaluate(make_snapshot(policy=policy))
    gaps = [
        gap for gap in result.evidence_gaps if gap.resolution_rule_id.startswith("F07")
    ]
    assert {gap.witness for gap in gaps} == set(Witness)
    assert len(gaps) == 7
    assert len({gap.gap_id for gap in gaps}) == 7


def test_no_policy_emits_source_and_location_gaps() -> None:
    policy = PolicyInput(policy_version="empty", policy_digest="a" * 64, rules=())
    policy = replace(policy, policy_digest=policy_input_digest(policy))
    result = evaluate(make_snapshot(policy=policy))
    assert {gap.witness for gap in result.evidence_gaps} >= {
        Witness.WHENCE,
        Witness.WHERE,
    }
