"""Frozen public governance and persistence records."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from src.operators import OperatorFamily
from src.verdict import Risk, Verdict
from src.witnesses import Witness


class DependencyState(str, Enum):  # noqa: UP042 - exact public contract
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNRESOLVED = "UNRESOLVED"


class DecisionValue(str, Enum):  # noqa: UP042 - exact public contract
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    MODIFY = "MODIFY"


class PolicyEffect(str, Enum):  # noqa: UP042 - exact public contract
    ALLOW = "ALLOW"
    DENY = "DENY"


class ExecutionStatus(str, Enum):  # noqa: UP042 - exact public contract
    OBSERVED = "OBSERVED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    ref_id: str
    kind: str
    digest: str


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    gap_id: str
    witness: Witness
    subject_ref: str
    question: str
    needed: str
    resolution_rule_id: str


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    requirement_id: str
    kind: str
    witness: Witness
    subject_ref: str
    resolution_rule_id: str


@dataclass(frozen=True, slots=True)
class DependencyRef:
    dependency_id: str
    subject_ref: str
    predicate: str
    expected_json: str
    observed_json: str | None
    state: DependencyState
    snapshot_digest: str
    evidence_refs: tuple[EvidenceRef, ...]
    necessary_for_yes: bool
    sufficient_if_true: bool


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    action_type_key: str
    target_key: str | None
    effect: PolicyEffect
    because: str
    required_evidence: tuple[EvidenceRequirement, ...]
    required_capability_ids: tuple[str, ...]
    require_consequence: bool


@dataclass(frozen=True, slots=True)
class PolicyInput:
    policy_version: str
    policy_digest: str
    rules: tuple[PolicyRule, ...]


@dataclass(frozen=True, slots=True)
class ExclusionRef:
    exclusion_id: str
    action_type: str
    action_type_key: str
    target: str
    target_key: str
    reason: str
    source_proposal_id: str
    source_evaluation_id: str
    source_evaluation_trace_digest: str
    source_decision_id: str
    source_decision_value: DecisionValue
    source_decision_digest: str
    exclusion_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class ConsequenceRef:
    consequence_id: str
    receipt_id: str
    receipt_terminal_status: ExecutionStatus
    receipt_digest: str
    predicted_snapshot_digest: str
    actual_snapshot_digest: str
    comparison_version: str
    divergence: Decimal
    divergence_threshold: Decimal
    report_digest: str


@dataclass(frozen=True, slots=True)
class PrecedentRef:
    proposal_id: str
    proposal_digest: str
    action_digest: str
    action_type_key: str
    target_key: str
    decision: DecisionValue | None
    decision_id: str | None
    decision_digest: str | None
    similarity: Decimal | None
    similarity_error_code: str | None
    evaluation_id: str
    trace_digest: str
    receipt_id: str | None
    receipt_digest: str | None
    receipt_terminal_status: ExecutionStatus | None
    consequence_refs: tuple[ConsequenceRef, ...]


@dataclass(frozen=True, slots=True)
class CapabilityFact:
    capability_id: str
    subject_ref: str
    state: DependencyState
    snapshot_digest: str
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    parent_proposal_id: str | None
    source_modify_decision_id: str | None
    source_modify_decision_value: DecisionValue | None
    agent_id: str
    session_id: str
    action_type: str
    action_type_key: str
    target: str
    target_key: str
    reasoning: str
    purpose: str
    parameters_json: str
    impact_assessment_json: str
    predicted_outcome_json: str
    evidence_refs: tuple[EvidenceRef, ...]
    dependencies: tuple[DependencyRef, ...]
    embedding: tuple[float, ...]
    embedding_model: str
    embedding_input_digest: str
    action_digest: str
    proposal_digest: str


@dataclass(frozen=True, slots=True)
class OperatorTraceStep:
    step_id: str
    rule_id: str
    family: OperatorFamily
    pole: str
    subject_ref: str
    object_refs: tuple[str, ...]
    result_json: str
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class ReducerTraceStep:
    step_id: str
    rule_id: str
    family: OperatorFamily
    pole: str
    decisive_fact_step_ids: tuple[str, ...]
    result_json: str


@dataclass(frozen=True, slots=True)
class PriorEvaluationTrace:
    evaluation_id: str
    proposal_id: str
    verdict: Verdict
    risk: Risk
    operator_trace: tuple[OperatorTraceStep | ReducerTraceStep, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    dependencies: tuple[DependencyRef, ...]
    precedent_refs: tuple[str, ...]
    consequence_warning_refs: tuple[str, ...]
    because_step_id: str
    profile_version: str | None
    prior_evaluation_id: str | None
    changed_fact_rule_ids: tuple[str, ...]
    evaluator_version: str
    rule_config_digest: str
    input_snapshot_digest: str
    policy_digest: str
    trace_digest: str


@dataclass(frozen=True, slots=True)
class EvaluationSnapshot:
    evaluation_id: str
    snapshot_id: str
    profile_version: str | None
    proposal: Proposal
    policy: PolicyInput
    precedents: tuple[PrecedentRef, ...]
    exclusions: tuple[ExclusionRef, ...]
    capabilities: tuple[CapabilityFact, ...]
    dependencies: tuple[DependencyRef, ...]
    prior_evaluation: PriorEvaluationTrace | None
    captured_at: str
    snapshot_digest: str


@dataclass(frozen=True, slots=True)
class CheckResult:
    verdict: Verdict
    risk: Risk
    operator_trace: tuple[OperatorTraceStep | ReducerTraceStep, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    dependencies: tuple[DependencyRef, ...]
    precedent_refs: tuple[str, ...]
    consequence_warning_refs: tuple[str, ...]
    because_step_id: str
    evaluation_id: str
    profile_version: str | None
    prior_evaluation_id: str | None
    changed_fact_rule_ids: tuple[str, ...]
    evaluator_version: str
    rule_config_digest: str
    input_snapshot_digest: str
    policy_digest: str
    trace_digest: str


@dataclass(frozen=True, slots=True)
class BlockedResult:
    evaluation_id: str
    profile_version: str | None
    prior_evaluation_id: str | None
    changed_fact_rule_ids: tuple[str, ...]
    error_code: str
    safe_message: str
    operator_trace: tuple[OperatorTraceStep, ...]
    evidence_gaps: tuple[EvidenceGap, ...]
    dependencies: tuple[DependencyRef, ...]
    evaluator_version: str
    rule_config_digest: str
    input_snapshot_digest: str
    policy_digest: str
    trace_digest: str


@dataclass(frozen=True, slots=True)
class DependencyFact:
    fact_id: str
    dependency_key: str
    fact_version: int
    prior_fact_id: str | None
    prior_fact_version: int | None
    subject_ref: str
    predicate: str
    observed_value_json: str | None
    state: DependencyState
    snapshot_digest: str
    evidence_refs: tuple[EvidenceRef, ...]
    recorded_by: str
    fact_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    decision_id: str
    proposal_id: str
    evaluation_id: str
    evaluation_trace_digest: str
    decision: DecisionValue
    decided_by: str
    rationale: str
    conditions_json: str
    decision_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class ConsequenceReport:
    consequence_id: str
    proposal_id: str
    receipt_id: str
    receipt_terminal_status: ExecutionStatus
    receipt_digest: str
    observation_number: int
    predicted_snapshot_digest: str
    actual_snapshot_digest: str
    comparison_version: str
    predicted_outcome_json: str
    actual_outcome_json: str
    leaf_report_json: str
    divergence_score: Decimal
    divergence_threshold: Decimal
    divergence_summary: str
    reported_by: str
    report_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class ToolEvidence:
    evidence_id: str
    tool_name: str
    tool_version: str
    redacted_command_argv_json: str
    command_digest: str
    help_digest: str
    config_digest: str
    cluster_name: str
    cluster_name_digest: str
    observed_cluster_id_digest: str
    observed_version: str
    observed_state: str
    observed_plan: str
    observed_cloud: str
    normalized_redacted_output_json: str
    redaction_manifest_json: str
    raw_output_digest: str
    normalized_output_digest: str
    exit_status: int
    captured_at: str
    expires_at: str
    captured_by: str
    evidence_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class DemoExecutionCommand:
    decision_id: str
    executor_id: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    attempt_id: str
    proposal_id: str
    evaluation_id: str
    evaluation_trace_digest: str
    decision_id: str
    decision_value: DecisionValue
    decision_digest: str
    action_type_key: str
    action_digest: str
    target_key: str
    effect_key: str
    requested_value_json: str
    started_at: str
    finished_at: str
    terminal_status: ExecutionStatus
    demo_effect_id: str | None
    before_effect_digest: str
    after_effect_digest: str | None
    observed_effect_version: int | None
    outcome_json: str
    outcome_digest: str
    attempt_digest: str
    executor_id: str
    idempotency_key: str
    error_code: str | None
    safe_message: str | None


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    receipt_id: str
    attempt_id: str
    attempt_digest: str
    proposal_id: str
    evaluation_id: str
    evaluation_trace_digest: str
    decision_id: str
    decision_value: DecisionValue
    decision_digest: str
    action_digest: str
    target_key: str
    attempt_terminal_status: ExecutionStatus
    outcome_digest: str
    before_effect_digest: str
    after_effect_digest: str | None
    observed_effect_version: int | None
    executor_id: str
    idempotency_key: str
    verified: bool
    receipt_digest: str
