"""Fact-rule fixtures and boundary tests for deterministic governance."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from src.governance import (
    F02,
    F03,
    F04,
    F05,
    F08,
    F09,
    F10,
    default_rule_config,
    evaluate_proposal,
    normalize_action_target_key,
    policy_input_digest,
    proposal_action_digest,
    proposal_record_digest,
)
from src.models import (
    BlockedResult,
    CapabilityFact,
    CheckResult,
    ConsequenceRef,
    DecisionValue,
    DependencyRef,
    DependencyState,
    EvaluationSnapshot,
    EvidenceRef,
    ExclusionRef,
    ExecutionStatus,
    OperatorTraceStep,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PrecedentRef,
    Proposal,
)
from src.traces import finalize_snapshot
from src.verdict import Verdict

DIGEST = "a" * 64


def make_proposal(
    *,
    dependencies: tuple[DependencyRef, ...] = (),
    evidence_refs: tuple[EvidenceRef, ...] = (),
) -> Proposal:
    proposal = Proposal(
        proposal_id="proposal-current",
        parent_proposal_id=None,
        source_modify_decision_id=None,
        source_modify_decision_value=None,
        agent_id="agent",
        session_id="session",
        action_type="  Set\tDemo Value  ",
        action_type_key="set demo value",
        target=" Demo\nKey ",
        target_key="demo key",
        reasoning="bounded test",
        purpose="verify deterministic evaluation",
        parameters_json='{"value":1}',
        impact_assessment_json="{}",
        predicted_outcome_json='{"value":1}',
        evidence_refs=evidence_refs,
        dependencies=dependencies,
        embedding=(0.0,) * 1536,
        embedding_model="text-embedding-3-small",
        embedding_input_digest=DIGEST,
        action_digest=DIGEST,
        proposal_digest=DIGEST,
    )
    proposal = replace(proposal, action_digest=proposal_action_digest(proposal))
    return replace(proposal, proposal_digest=proposal_record_digest(proposal))


def make_policy(
    *,
    effect: PolicyEffect = PolicyEffect.ALLOW,
    target_key: str | None = "demo key",
    required_capability_ids: tuple[str, ...] = (),
    require_consequence: bool = False,
) -> PolicyInput:
    policy = PolicyInput(
        policy_version="policy/1",
        policy_digest=DIGEST,
        rules=(
            PolicyRule(
                rule_id="policy-rule",
                action_type_key="set demo value",
                target_key=target_key,
                effect=effect,
                because="bounded demo",
                required_evidence=(),
                required_capability_ids=required_capability_ids,
                require_consequence=require_consequence,
            ),
        ),
    )
    return replace(policy, policy_digest=policy_input_digest(policy))


def make_consequence(divergence: Decimal = Decimal("0.10000")) -> ConsequenceRef:
    return ConsequenceRef(
        consequence_id=f"consequence-{divergence}",
        receipt_id="receipt-1",
        receipt_terminal_status=ExecutionStatus.OBSERVED,
        receipt_digest=DIGEST,
        predicted_snapshot_digest=DIGEST,
        actual_snapshot_digest=DIGEST,
        comparison_version="compare/1",
        divergence=divergence,
        divergence_threshold=Decimal("0.50000"),
        report_digest=DIGEST,
    )


def make_precedent(
    *,
    similarity: Decimal | None = Decimal("0.90000000"),
    similarity_error_code: str | None = None,
    target_key: str = "demo key",
    decision: DecisionValue | None = DecisionValue.APPROVE,
    consequences: tuple[ConsequenceRef, ...] = (),
    proposal_id: str = "proposal-prior",
) -> PrecedentRef:
    decided = decision is not None
    return PrecedentRef(
        proposal_id=proposal_id,
        proposal_digest=DIGEST,
        action_digest=DIGEST,
        action_type_key="set demo value",
        target_key=target_key,
        decision=decision,
        decision_id="decision-1" if decided else None,
        decision_digest=DIGEST if decided else None,
        similarity=similarity,
        similarity_error_code=similarity_error_code,
        evaluation_id=f"evaluation-{proposal_id}",
        trace_digest=DIGEST,
        receipt_id="receipt-1" if consequences else None,
        receipt_digest=DIGEST if consequences else None,
        receipt_terminal_status=ExecutionStatus.OBSERVED if consequences else None,
        consequence_refs=consequences,
    )


def make_dependency(
    state: DependencyState,
    *,
    dependency_id: str = "dependency-1",
    complete: bool = True,
) -> DependencyRef:
    return DependencyRef(
        dependency_id=dependency_id,
        subject_ref="proposal-current",
        predicate="service_ready",
        expected_json="true",
        observed_json="true" if state is DependencyState.TRUE else None,
        state=state,
        snapshot_digest=DIGEST,
        evidence_refs=(),
        necessary_for_yes=complete,
        sufficient_if_true=complete,
    )


def make_snapshot(
    *,
    policy: PolicyInput | None = None,
    precedents: tuple[PrecedentRef, ...] | None = None,
    exclusions: tuple[ExclusionRef, ...] = (),
    capabilities: tuple[CapabilityFact, ...] = (),
    dependencies: tuple[DependencyRef, ...] = (),
    proposal: Proposal | None = None,
    evaluation_id: str = "evaluation-current",
) -> EvaluationSnapshot:
    ordered_dependencies = tuple(
        sorted(dependencies, key=lambda item: item.dependency_id)
    )
    ordered_precedents = tuple(
        sorted(
            precedents if precedents is not None else (make_precedent(),),
            key=lambda item: (item.proposal_id, item.evaluation_id),
        )
    )
    supplied_policy = policy or make_policy()
    ordered_policy = replace(
        supplied_policy,
        rules=tuple(
            replace(
                rule,
                required_evidence=tuple(
                    sorted(rule.required_evidence, key=lambda item: item.requirement_id)
                ),
                required_capability_ids=tuple(sorted(rule.required_capability_ids)),
            )
            for rule in sorted(supplied_policy.rules, key=lambda item: item.rule_id)
        ),
    )
    ordered_policy = replace(
        ordered_policy, policy_digest=policy_input_digest(ordered_policy)
    )
    actual_proposal = proposal or make_proposal(dependencies=ordered_dependencies)
    snapshot = EvaluationSnapshot(
        evaluation_id=evaluation_id,
        snapshot_id=f"snapshot-{evaluation_id}",
        profile_version=None,
        proposal=actual_proposal,
        policy=ordered_policy,
        precedents=ordered_precedents,
        exclusions=exclusions,
        capabilities=capabilities,
        dependencies=ordered_dependencies,
        prior_evaluation=None,
        captured_at="2026-08-16T12:00:00.000000Z",
        snapshot_digest=DIGEST,
    )
    return finalize_snapshot(snapshot)


def fact(result: CheckResult, rule_id: str) -> OperatorTraceStep | None:
    return next(
        (
            step
            for step in result.operator_trace
            if isinstance(step, OperatorTraceStep) and step.rule_id == rule_id
        ),
        None,
    )


def evaluate(snapshot: EvaluationSnapshot) -> CheckResult:
    result = evaluate_proposal(snapshot, default_rule_config())
    assert isinstance(result, CheckResult), result
    return result


def test_normalization_order_and_empty_rejection() -> None:
    assert normalize_action_target_key("  A\t B\n") == "a b"


def test_digest_or_config_mismatch_blocks() -> None:
    snapshot = make_snapshot()
    broken = replace(snapshot, snapshot_digest="b" * 64)
    assert isinstance(evaluate_proposal(broken, default_rule_config()), BlockedResult)
    config = replace(default_rule_config(), precedent_top_k=4)
    assert isinstance(evaluate_proposal(snapshot, config), BlockedResult)


def test_hard_policy_and_exact_exclusion_are_no() -> None:
    exclusion = ExclusionRef(
        exclusion_id="exclusion-1",
        action_type="Set Demo Value",
        action_type_key="set demo value",
        target="Demo Key",
        target_key="demo key",
        reason="prior rejection",
        source_proposal_id="source-proposal",
        source_evaluation_id="source-evaluation",
        source_evaluation_trace_digest=DIGEST,
        source_decision_id="source-decision",
        source_decision_value=DecisionValue.REJECT,
        source_decision_digest=DIGEST,
        exclusion_digest=DIGEST,
        idempotency_key="exclusion-key",
    )
    result = evaluate(
        make_snapshot(
            policy=make_policy(effect=PolicyEffect.DENY), exclusions=(exclusion,)
        )
    )
    assert result.verdict is Verdict.NO
    assert fact(result, F02).pole == "OUTSIDE"  # type: ignore[union-attr]
    assert fact(result, F03).pole == "SAME"  # type: ignore[union-attr]


def test_similarity_and_divergence_equality_are_fail_closed() -> None:
    precedent = make_precedent(
        similarity=Decimal("0.85000000"),
        consequences=(make_consequence(Decimal("0.50000")),),
    )
    result = evaluate(
        make_snapshot(
            policy=make_policy(require_consequence=True), precedents=(precedent,)
        )
    )
    assert fact(result, F04).pole == "NEAR"  # type: ignore[union-attr]
    assert fact(result, F08).pole == "MORE"  # type: ignore[union-attr]
    assert result.verdict is Verdict.MAYBE


def test_near_different_target_does_not_qualify() -> None:
    result = evaluate(make_snapshot(precedents=(make_precedent(target_key="other"),)))
    assert fact(result, F05).pole == "NOT-SAME"  # type: ignore[union-attr]
    assert result.verdict is Verdict.MAYBE


def test_false_capability_and_dependency_are_terminal_no() -> None:
    capability = CapabilityFact(
        capability_id="capability-1",
        subject_ref="proposal-current",
        state=DependencyState.FALSE,
        snapshot_digest=DIGEST,
        evidence_refs=(),
    )
    dependency = make_dependency(DependencyState.FALSE)
    result = evaluate(
        make_snapshot(
            policy=make_policy(required_capability_ids=("capability-1",)),
            capabilities=(capability,),
            dependencies=(dependency,),
        )
    )
    assert result.verdict is Verdict.NO
    assert fact(result, F09).pole == "CANNOT"  # type: ignore[union-attr]
    assert len([step for step in result.operator_trace if step.rule_id == F10]) == 2
