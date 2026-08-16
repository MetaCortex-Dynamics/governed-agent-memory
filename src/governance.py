"""Deterministic four-valued governance evaluation over frozen snapshots."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, fields, replace
from decimal import Decimal
from typing import Any, NoReturn

from src.models import (
    BlockedResult,
    CapabilityFact,
    CheckResult,
    DecisionValue,
    DependencyState,
    EvaluationSnapshot,
    EvidenceGap,
    EvidenceRef,
    ExecutionStatus,
    OperatorTraceStep,
    PolicyEffect,
    PolicyInput,
    PrecedentRef,
    PriorEvaluationTrace,
    Proposal,
    ReducerTraceStep,
)
from src.operators import OperatorFamily
from src.traces import (
    ContractViolation,
    canonical_sha256,
    check_result_digest,
    finalize_blocked_result,
    make_step_id,
    snapshot_digest,
    validate_snapshot,
)
from src.verdict import Risk, Verdict
from src.witnesses import Witness

_ASCII_SPACE = re.compile(r"[\t\n\v\f\r ]+")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ZERO_DIGEST = "0" * 64

F01 = "F01_THIS_BIND"
F02 = "F02_SCOPE_BOUNDARY"
F03 = "F03_EXCLUSION_IDENTITY"
F04 = "F04_PRECEDENT_RETRIEVAL"
F05 = "F05_PRECEDENT_IDENTITY"
F06 = "F06_PRECEDENT_CONFLICT"
F07 = "F07_EVIDENCE_COMPLETENESS"
F08 = "F08_DIVERGENCE_BOUNDARY"
F09 = "F09_CAPABILITY_SNAPSHOT"
F10 = "F10_DEPENDENCY_FORMULA"
F11 = "F11_CONDITION_AGGREGATE"
F12 = "F12_FINAL_BECAUSE"


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Immutable evaluator configuration bound by its canonical digest."""

    rule_config_digest: str
    evaluator_version: str = "gam-gate/1.1"
    similarity_threshold: Decimal = Decimal("0.85000000")
    divergence_threshold: Decimal = Decimal("0.50000")
    precedent_top_k: int = 5
    require_consequence_for_yes: bool = True
    similarity_equal_qualifies: bool = True
    divergence_equal_is_high: bool = True
    normalization_version: str = "gam-normalize/1.1"
    action_type_key: str = "normalized(action_type)"
    target_key: str = "normalized(target)"
    exact_class_key: str = "action_type_key + U+001F + target_key"


@dataclass(frozen=True, slots=True)
class _Step:
    rule_id: str
    family: OperatorFamily
    pole: str
    subject_ref: str
    object_refs: tuple[str, ...]
    result: dict[str, Any]
    evidence_refs: tuple[EvidenceRef, ...] = ()


class _Blocked(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _stop(code: str, message: str) -> NoReturn:
    raise _Blocked(code, message)


def _json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def normalize_action_target_key(value: str) -> str:
    """Apply the exact versioned action/target key normalization."""
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.strip("\t\n\v\f\r ")
    normalized = _ASCII_SPACE.sub(" ", normalized).lower()
    normalized = unicodedata.normalize("NFC", normalized)
    if not normalized:
        _stop("EMPTY_NORMALIZED_KEY", "action or target key normalizes to empty")
    return normalized


def rule_config_payload(config: RuleConfig) -> dict[str, Any]:
    """Return the exact digest payload, excluding the digest field itself."""
    return {
        "schema": "gam.rule-config.v1",
        **{
            field.name: getattr(config, field.name)
            for field in fields(config)
            if field.name != "rule_config_digest"
        },
    }


def compute_rule_config_digest(config: RuleConfig) -> str:
    return canonical_sha256(rule_config_payload(config))


def policy_input_digest(policy: PolicyInput) -> str:
    rules = tuple(
        replace(
            rule,
            required_evidence=tuple(
                sorted(rule.required_evidence, key=lambda item: item.requirement_id)
            ),
            required_capability_ids=tuple(sorted(set(rule.required_capability_ids))),
        )
        for rule in sorted(policy.rules, key=lambda item: item.rule_id)
    )
    return canonical_sha256(
        {
            "schema": "gam.policy-input.v1",
            "policy_version": policy.policy_version,
            "rules": rules,
        }
    )


def proposal_action_digest(proposal: Proposal) -> str:
    return canonical_sha256(
        {
            "schema": "gam.action.v1",
            "action_type": proposal.action_type,
            "action_type_key": proposal.action_type_key,
            "target": proposal.target,
            "target_key": proposal.target_key,
            "parameters_json": proposal.parameters_json,
        }
    )


def proposal_record_digest(proposal: Proposal) -> str:
    return canonical_sha256(
        {
            "schema": "gam.proposal.v1",
            **{
                field.name: getattr(proposal, field.name)
                for field in fields(proposal)
                if field.name != "proposal_digest"
            },
        }
    )


def default_rule_config() -> RuleConfig:
    provisional = RuleConfig(rule_config_digest=_ZERO_DIGEST)
    return RuleConfig(rule_config_digest=compute_rule_config_digest(provisional))


def _validate_config(config: RuleConfig) -> None:
    expected = RuleConfig(rule_config_digest=config.rule_config_digest)
    if config != expected or config.rule_config_digest != compute_rule_config_digest(
        config
    ):
        _stop("INVALID_RULE_CONFIG", "rule configuration is not the pinned contract")


def _prior_digest(prior: PriorEvaluationTrace) -> str:
    result = CheckResult(
        verdict=prior.verdict,
        risk=prior.risk,
        operator_trace=prior.operator_trace,
        evidence_gaps=prior.evidence_gaps,
        dependencies=prior.dependencies,
        precedent_refs=prior.precedent_refs,
        consequence_warning_refs=prior.consequence_warning_refs,
        because_step_id=prior.because_step_id,
        evaluation_id=prior.evaluation_id,
        profile_version=prior.profile_version,
        prior_evaluation_id=prior.prior_evaluation_id,
        changed_fact_rule_ids=prior.changed_fact_rule_ids,
        evaluator_version=prior.evaluator_version,
        rule_config_digest=prior.rule_config_digest,
        input_snapshot_digest=prior.input_snapshot_digest,
        policy_digest=prior.policy_digest,
        trace_digest=prior.trace_digest,
    )
    return check_result_digest(result)


def _validate_exact_prior(snapshot: EvaluationSnapshot) -> None:
    prior = snapshot.prior_evaluation
    if prior is None:
        return
    if (
        prior.proposal_id != snapshot.proposal.proposal_id
        or prior.trace_digest != _prior_digest(prior)
        or not prior.operator_trace
        or prior.because_step_id != prior.operator_trace[-1].step_id
        or prior.operator_trace[-1].rule_id != F12
    ):
        _stop("INVALID_PRIOR_TRACE", "prior finalized trace does not reproduce")
    reducers = [
        step for step in prior.operator_trace if isinstance(step, ReducerTraceStep)
    ]
    if len(reducers) != 1 or reducers[0].rule_id not in {
        "R1_NO",
        "R2_MAYBE",
        "R3_IFF",
        "R4_YES",
    }:
        _stop("INVALID_PRIOR_TRACE", "prior reducer binding is invalid")
    for ordinal, step in enumerate(prior.operator_trace, start=1):
        if step.step_id != make_step_id(prior.evaluation_id, ordinal, step.rule_id):
            _stop("INVALID_PRIOR_TRACE", "prior step ordinal is invalid")


def _validate_snapshot_with_exact_reducers(snapshot: EvaluationSnapshot) -> None:
    if snapshot.snapshot_digest != snapshot_digest(snapshot):
        _stop("INVALID_SNAPSHOT", "snapshot digest does not reproduce")
    _validate_exact_prior(snapshot)


def _canonical_snapshot(snapshot: EvaluationSnapshot) -> EvaluationSnapshot:
    """Normalize every unordered collection before digest validation."""
    proposal = replace(
        snapshot.proposal,
        evidence_refs=tuple(
            sorted(snapshot.proposal.evidence_refs, key=lambda item: item.ref_id)
        ),
        dependencies=tuple(
            sorted(snapshot.proposal.dependencies, key=lambda item: item.dependency_id)
        ),
    )
    rules = tuple(
        replace(
            rule,
            required_evidence=tuple(
                sorted(rule.required_evidence, key=lambda item: item.requirement_id)
            ),
            required_capability_ids=tuple(sorted(set(rule.required_capability_ids))),
        )
        for rule in sorted(snapshot.policy.rules, key=lambda item: item.rule_id)
    )
    policy = replace(snapshot.policy, rules=rules)
    precedents = tuple(
        replace(
            precedent,
            consequence_refs=tuple(
                sorted(
                    precedent.consequence_refs,
                    key=lambda item: (item.receipt_id, item.consequence_id),
                )
            ),
        )
        for precedent in sorted(
            snapshot.precedents,
            key=lambda item: (item.proposal_id, item.evaluation_id),
        )
    )
    return replace(
        snapshot,
        proposal=proposal,
        policy=policy,
        precedents=precedents,
        exclusions=tuple(
            sorted(
                snapshot.exclusions,
                key=lambda item: (
                    item.action_type_key,
                    item.target_key,
                    item.exclusion_id,
                ),
            )
        ),
        capabilities=tuple(
            sorted(snapshot.capabilities, key=lambda item: item.capability_id)
        ),
        dependencies=tuple(
            sorted(snapshot.dependencies, key=lambda item: item.dependency_id)
        ),
    )


def _validate_input(snapshot: EvaluationSnapshot, config: RuleConfig) -> None:
    _validate_config(config)
    try:
        validate_snapshot(snapshot)
    except ContractViolation as error:
        if snapshot.prior_evaluation is None:
            raise _Blocked(
                "INVALID_SNAPSHOT", "snapshot integrity validation failed"
            ) from error
        _validate_snapshot_with_exact_reducers(snapshot)
    proposal = snapshot.proposal
    if normalize_action_target_key(proposal.action_type) != proposal.action_type_key:
        _stop("ACTION_KEY_MISMATCH", "action type key does not match display value")
    if normalize_action_target_key(proposal.target) != proposal.target_key:
        _stop("TARGET_KEY_MISMATCH", "target key does not match display value")
    if "\x1f".join((proposal.action_type_key, proposal.target_key)).count("\x1f") != 1:
        _stop("CLASS_KEY_MISMATCH", "exact action class key is malformed")
    if proposal.action_digest != proposal_action_digest(proposal):
        _stop("ACTION_DIGEST_MISMATCH", "action digest does not reproduce")
    if proposal.proposal_digest != proposal_record_digest(proposal):
        _stop("PROPOSAL_DIGEST_MISMATCH", "proposal digest does not reproduce")
    if snapshot.policy.policy_digest != policy_input_digest(snapshot.policy):
        _stop("POLICY_DIGEST_MISMATCH", "policy digest does not reproduce")
    if not snapshot.policy.policy_version:
        _stop("INVALID_POLICY", "policy version is empty")
    if snapshot.profile_version is not None and not snapshot.profile_version:
        _stop("INVALID_PROFILE", "profile version is empty")
    if len(snapshot.precedents) > config.precedent_top_k:
        _stop("PRECEDENT_LIMIT_EXCEEDED", "precedent retrieval exceeds pinned limit")
    for exclusion in snapshot.exclusions:
        if (
            normalize_action_target_key(exclusion.action_type)
            != exclusion.action_type_key
            or normalize_action_target_key(exclusion.target) != exclusion.target_key
            or exclusion.source_decision_value is not DecisionValue.REJECT
        ):
            _stop("INVALID_EXCLUSION", "exclusion identity binding is invalid")
    proposal_dependency_ids = tuple(
        sorted(item.dependency_id for item in proposal.dependencies)
    )
    snapshot_dependency_ids = tuple(
        sorted(item.dependency_id for item in snapshot.dependencies)
    )
    if proposal_dependency_ids != snapshot_dependency_ids:
        _stop("DEPENDENCY_SNAPSHOT_MISMATCH", "proposal dependency snapshot differs")


def _gap(
    witness: Witness,
    subject_ref: str,
    question: str,
    needed: str,
    rule_id: str,
) -> EvidenceGap:
    signature = {
        "witness": witness.value,
        "subject_ref": subject_ref,
        "question": question,
        "needed": needed,
        "resolution_rule_id": rule_id,
    }
    return EvidenceGap(
        gap_id=f"gap-{canonical_sha256(signature)[:24]}",
        witness=witness,
        subject_ref=subject_ref,
        question=question,
        needed=needed,
        resolution_rule_id=rule_id,
    )


def _evidence_valid(ref: EvidenceRef) -> bool:
    return bool(ref.ref_id and ref.kind and _DIGEST.fullmatch(ref.digest))


def _sorted_refs(refs: tuple[EvidenceRef, ...]) -> tuple[EvidenceRef, ...]:
    return tuple(sorted(refs, key=lambda item: item.ref_id))


def _build_operator_steps(
    evaluation_id: str, descriptors: list[_Step]
) -> tuple[OperatorTraceStep, ...]:
    return tuple(
        OperatorTraceStep(
            step_id=make_step_id(evaluation_id, ordinal, item.rule_id),
            rule_id=item.rule_id,
            family=item.family,
            pole=item.pole,
            subject_ref=item.subject_ref,
            object_refs=item.object_refs,
            result_json=_json(item.result),
            evidence_refs=_sorted_refs(item.evidence_refs),
        )
        for ordinal, item in enumerate(descriptors, start=1)
    )


def _safe_digest(value: str) -> str:
    return value if _DIGEST.fullmatch(value) else _ZERO_DIGEST


def _predicate_rule_id(predicate: str) -> str:
    by_prefix = {
        "F02": F02,
        "F03": F03,
        "F04": F04,
        "F05": F05,
        "F06": F06,
        "F07": F07,
        "F08": F08,
        "F09": F09,
        "F10": F10,
    }
    return by_prefix[predicate[:3]]


def _blocked_result(
    snapshot: EvaluationSnapshot,
    config: RuleConfig,
    code: str,
    message: str,
    prior_evaluation_id: str | None,
) -> BlockedResult:
    evaluation_id = snapshot.evaluation_id or "blocked-evaluation"
    partial = OperatorTraceStep(
        step_id=make_step_id(evaluation_id, 1, F01),
        rule_id=F01,
        family=OperatorFamily.THIS,
        pole="THIS",
        subject_ref=snapshot.proposal.proposal_id or "unbound-proposal",
        object_refs=(),
        result_json=_json({"blocked_before_finalization": True}),
        evidence_refs=(),
    )
    return finalize_blocked_result(
        BlockedResult(
            evaluation_id=evaluation_id,
            profile_version=None,
            prior_evaluation_id=prior_evaluation_id,
            changed_fact_rule_ids=(),
            error_code=code,
            safe_message=message,
            operator_trace=(partial,),
            evidence_gaps=(),
            dependencies=(),
            evaluator_version=config.evaluator_version or "gam-gate/1.1",
            rule_config_digest=_safe_digest(config.rule_config_digest),
            input_snapshot_digest=_safe_digest(snapshot.snapshot_digest),
            policy_digest=_safe_digest(snapshot.policy.policy_digest),
            trace_digest=_ZERO_DIGEST,
        )
    )


def _fact_projection(step: OperatorTraceStep) -> Any:
    result = json.loads(step.result_json)
    if step.rule_id == F01:
        for key in (
            "snapshot_id",
            "snapshot_digest",
            "profile_version",
            "prior_evaluation_id",
            "prior_trace_digest",
            "captured_at",
        ):
            result.pop(key, None)
        return step.family.value, step.pole, result
    keys: dict[str, tuple[str, ...]] = {
        F02: ("has_allow", "has_deny"),
        F03: ("some_same",),
        F04: ("some_near", "some_unresolved", "all_unresolved"),
        F05: ("some_qualifying",),
        F06: ("approved", "rejected", "modified", "undecided", "conflict"),
        F07: ("all_satisfied",),
        F08: ("some_more", "some_missing_consequence"),
        F09: ("some_false", "some_unresolved", "some_missing"),
        F10: (
            "dependency_id",
            "state",
            "necessary_for_yes",
            "sufficient_if_true",
            "predicate_satisfied",
        ),
        F11: ("triggered_predicate_ids",),
    }
    selected = {key: result.get(key) for key in keys.get(step.rule_id, ())}
    return step.family.value, step.pole, selected


def _because_projection(
    step: OperatorTraceStep,
    trace: tuple[OperatorTraceStep | ReducerTraceStep, ...],
    gaps: tuple[EvidenceGap, ...],
) -> Any:
    by_id = {item.step_id: item.rule_id for item in trace}
    result = json.loads(step.result_json)
    signatures = sorted(
        (
            gap.witness.value,
            gap.subject_ref,
            gap.question,
            gap.needed,
            gap.resolution_rule_id,
        )
        for gap in gaps
    )
    return {
        "family": step.family.value,
        "pole": step.pole,
        "verdict": result["verdict"],
        "risk": result["risk"],
        "decisive_rule_ids": sorted(
            by_id[item] for item in step.object_refs if item in by_id
        ),
        "gap_signatures": signatures,
    }


def _projections(
    trace: tuple[OperatorTraceStep | ReducerTraceStep, ...],
    gaps: tuple[EvidenceGap, ...],
) -> dict[str, Any]:
    values: dict[str, list[Any]] = {}
    for step in trace:
        if isinstance(step, ReducerTraceStep):
            continue
        projection = (
            _because_projection(step, trace, gaps)
            if step.rule_id == F12
            else _fact_projection(step)
        )
        values.setdefault(step.rule_id, []).append(projection)
    return {key: value for key, value in values.items()}


def _changed_fact_ids(
    current_trace: tuple[OperatorTraceStep | ReducerTraceStep, ...],
    current_gaps: tuple[EvidenceGap, ...],
    snapshot: EvaluationSnapshot,
) -> tuple[str, ...]:
    prior = snapshot.prior_evaluation
    if prior is None:
        return ()
    before = _projections(prior.operator_trace, prior.evidence_gaps)
    after = _projections(current_trace, current_gaps)
    return tuple(
        rule_id
        for rule_id in sorted(set(before) | set(after))
        if before.get(rule_id) != after.get(rule_id)
    )


def evaluate_proposal(
    snapshot: EvaluationSnapshot,
    config: RuleConfig,
) -> CheckResult | BlockedResult:
    """Evaluate one immutable snapshot with explicit R1→R2→R3→R4 precedence."""
    prior_id: str | None = None
    try:
        snapshot = _canonical_snapshot(snapshot)
        _validate_input(snapshot, config)
        if snapshot.prior_evaluation is not None:
            prior = snapshot.prior_evaluation
            if (
                prior.evaluator_version != config.evaluator_version
                or prior.rule_config_digest != config.rule_config_digest
                or prior.policy_digest != snapshot.policy.policy_digest
            ):
                _stop("PRIOR_BINDING_MISMATCH", "prior evaluation binding differs")
            prior_id = prior.evaluation_id

        proposal = snapshot.proposal
        descriptors: list[_Step] = []
        candidate_gaps: list[EvidenceGap] = []
        raw_r1: list[str] = []
        raw_r2: list[str] = []
        raw_r3: list[str] = []
        decisive_rules: set[str] = {F01, F11}

        descriptors.append(
            _Step(
                F01,
                OperatorFamily.THIS,
                "THIS",
                proposal.proposal_id,
                (),
                {
                    "proposal_id": proposal.proposal_id,
                    "proposal_digest": proposal.proposal_digest,
                    "action_digest": proposal.action_digest,
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_digest": snapshot.snapshot_digest,
                    "profile_version": snapshot.profile_version,
                    "prior_evaluation_id": prior_id,
                    "prior_trace_digest": (
                        snapshot.prior_evaluation.trace_digest
                        if snapshot.prior_evaluation is not None
                        else None
                    ),
                    "policy_digest": snapshot.policy.policy_digest,
                    "rule_config_digest": config.rule_config_digest,
                    "captured_at": snapshot.captured_at,
                },
            )
        )

        applicable = tuple(
            sorted(
                (
                    rule
                    for rule in snapshot.policy.rules
                    if rule.action_type_key == proposal.action_type_key
                    and rule.target_key in (None, proposal.target_key)
                ),
                key=lambda rule: rule.rule_id,
            )
        )
        deny_rules = tuple(
            rule for rule in applicable if rule.effect is PolicyEffect.DENY
        )
        allow_rules = tuple(
            rule for rule in applicable if rule.effect is PolicyEffect.ALLOW
        )
        if deny_rules:
            raw_r1.append("F02_HARD_POLICY_OUTSIDE")
            decisive_rules.add(F02)
            descriptors.append(
                _Step(
                    F02,
                    OperatorFamily.INSIDE_OUTSIDE,
                    "OUTSIDE",
                    proposal.proposal_id,
                    tuple(rule.rule_id for rule in applicable),
                    {
                        "has_allow": bool(allow_rules),
                        "has_deny": True,
                        "applicable_rule_ids": [rule.rule_id for rule in applicable],
                    },
                )
            )
        elif allow_rules:
            descriptors.append(
                _Step(
                    F02,
                    OperatorFamily.INSIDE_OUTSIDE,
                    "INSIDE",
                    proposal.proposal_id,
                    tuple(rule.rule_id for rule in applicable),
                    {
                        "has_allow": True,
                        "has_deny": False,
                        "applicable_rule_ids": [rule.rule_id for rule in applicable],
                    },
                )
            )
        else:
            raw_r2.extend(
                ("F02_POLICY_SOURCE_UNRESOLVED", "F02_TARGET_SCOPE_UNRESOLVED")
            )
            candidate_gaps.extend(
                (
                    _gap(
                        Witness.WHENCE,
                        proposal.proposal_id,
                        "Whence comes the policy authority for this action?",
                        "an applicable digest-bound policy rule",
                        F02,
                    ),
                    _gap(
                        Witness.WHERE,
                        proposal.proposal_id,
                        "Where is this target inside the allowed boundary?",
                        "an exact or wildcard target scope",
                        F02,
                    ),
                )
            )

        exclusions = tuple(
            sorted(
                snapshot.exclusions,
                key=lambda item: (
                    item.action_type_key,
                    item.target_key,
                    item.exclusion_id,
                ),
            )
        )
        if exclusions:
            exclusion_rows: list[dict[str, Any]] = []
            some_same = False
            for exclusion in exclusions:
                same = (
                    exclusion.action_type_key == proposal.action_type_key
                    and exclusion.target_key == proposal.target_key
                )
                some_same = some_same or same
                exclusion_rows.append(
                    {
                        "exclusion_id": exclusion.exclusion_id,
                        "classification": "SAME" if same else "NOT-SAME",
                        "exclusion_digest": exclusion.exclusion_digest,
                        "action_type": exclusion.action_type,
                        "action_type_key": exclusion.action_type_key,
                        "target": exclusion.target,
                        "target_key": exclusion.target_key,
                        "source_proposal_id": exclusion.source_proposal_id,
                        "source_evaluation_id": exclusion.source_evaluation_id,
                        "source_trace_digest": exclusion.source_evaluation_trace_digest,
                        "source_decision_id": exclusion.source_decision_id,
                        "source_decision": exclusion.source_decision_value.value,
                        "source_decision_digest": exclusion.source_decision_digest,
                    }
                )
            if some_same:
                raw_r1.append("F03_ACTIVE_EXCLUSION_SAME")
                decisive_rules.add(F03)
            descriptors.append(
                _Step(
                    F03,
                    OperatorFamily.SAME_NOT_SAME,
                    "SAME" if some_same else "NOT-SAME",
                    proposal.proposal_id,
                    tuple(item.exclusion_id for item in exclusions),
                    {"some_same": some_same, "exclusions": exclusion_rows},
                )
            )

        precedents = tuple(
            sorted(
                snapshot.precedents,
                key=lambda item: (item.proposal_id, item.evaluation_id),
            )
        )
        near: list[PrecedentRef] = []
        retrieval_rows: list[dict[str, Any]] = []
        unresolved_similarity = False
        for precedent in precedents:
            if precedent.similarity is None:
                classification = "UNRESOLVED"
                unresolved_similarity = True
                raw_r2.append(f"F04_SIMILARITY_UNRESOLVED:{precedent.proposal_id}")
                candidate_gaps.append(
                    _gap(
                        Witness.WHICH,
                        precedent.proposal_id,
                        "Which exact similarity can be recomputed?",
                        "a fixed-scale cosine similarity for this candidate",
                        F04,
                    )
                )
            elif precedent.similarity >= config.similarity_threshold:
                classification = "NEAR"
                near.append(precedent)
            else:
                classification = "FAR"
            retrieval_rows.append(
                {
                    "proposal_id": precedent.proposal_id,
                    "evaluation_id": precedent.evaluation_id,
                    "similarity": (
                        str(precedent.similarity)
                        if precedent.similarity is not None
                        else None
                    ),
                    "classification": classification,
                    "error_code": precedent.similarity_error_code,
                }
            )
        descriptors.append(
            _Step(
                F04,
                OperatorFamily.NEAR_FAR,
                "NEAR" if near else "FAR",
                proposal.proposal_id,
                tuple(item.proposal_id for item in precedents),
                {
                    "candidate_count": len(precedents),
                    "valid_count": sum(
                        row["classification"] != "UNRESOLVED" for row in retrieval_rows
                    ),
                    "unresolved_count": sum(
                        row["classification"] == "UNRESOLVED" for row in retrieval_rows
                    ),
                    "some_near": bool(near),
                    "some_unresolved": unresolved_similarity,
                    "all_unresolved": bool(precedents)
                    and all(
                        row["classification"] == "UNRESOLVED" for row in retrieval_rows
                    ),
                    "candidates": retrieval_rows,
                },
            )
        )

        identity_qualifying: list[PrecedentRef] = []
        if near:
            identity_rows: list[dict[str, Any]] = []
            for precedent in near:
                same = (
                    precedent.action_type_key == proposal.action_type_key
                    and precedent.target_key == proposal.target_key
                )
                if same:
                    identity_qualifying.append(precedent)
                identity_rows.append(
                    {
                        "proposal_id": precedent.proposal_id,
                        "evaluation_id": precedent.evaluation_id,
                        "retrieval_classification": "NEAR",
                        "identity_classification": "SAME" if same else "NOT-SAME",
                        "qualifying": same,
                    }
                )
            descriptors.append(
                _Step(
                    F05,
                    OperatorFamily.SAME_NOT_SAME,
                    "SAME" if identity_qualifying else "NOT-SAME",
                    proposal.proposal_id,
                    tuple(item.proposal_id for item in near),
                    {
                        "some_qualifying": bool(identity_qualifying),
                        "candidates": identity_rows,
                    },
                )
            )

        approved = [
            item
            for item in identity_qualifying
            if item.decision is DecisionValue.APPROVE
        ]
        if not approved:
            raw_r2.append("F05_NO_QUALIFYING_APPROVE")
            candidate_gaps.append(
                _gap(
                    Witness.WHICH,
                    proposal.proposal_id,
                    "Which exact approved action-type-and-target precedent qualifies?",
                    (
                        "one NEAR and exact SAME approved precedent with required "
                        "consequence"
                    ),
                    F05,
                )
            )
        if identity_qualifying:
            decisions = [item.decision for item in identity_qualifying]
            has_approved = DecisionValue.APPROVE in decisions
            has_rejected = DecisionValue.REJECT in decisions
            has_modified = DecisionValue.MODIFY in decisions
            has_undecided = None in decisions
            conflict = has_approved and (has_rejected or has_modified)
            if conflict:
                raw_r2.append("F06_PRECEDENT_CONFLICT")
                candidate_gaps.append(
                    _gap(
                        Witness.WHICH,
                        proposal.proposal_id,
                        "Which conflicting precedent decisions should govern?",
                        "human reconciliation of qualifying precedent decisions",
                        F06,
                    )
                )
            descriptors.append(
                _Step(
                    F06,
                    OperatorFamily.TOGETHER_ALONE,
                    "ALONE" if conflict else "TOGETHER",
                    proposal.proposal_id,
                    tuple(item.evaluation_id for item in identity_qualifying),
                    {
                        "approved": has_approved,
                        "rejected": has_rejected,
                        "modified": has_modified,
                        "undecided": has_undecided,
                        "conflict": conflict,
                        "decisions": [
                            {
                                "proposal_id": item.proposal_id,
                                "evaluation_id": item.evaluation_id,
                                "decision": item.decision.value
                                if item.decision
                                else None,
                                "decision_id": item.decision_id,
                            }
                            for item in identity_qualifying
                        ],
                    },
                )
            )

        requirements = tuple(
            sorted(
                (
                    requirement
                    for rule in allow_rules
                    for requirement in rule.required_evidence
                ),
                key=lambda item: item.requirement_id,
            )
        )
        evidence_by_kind = {
            item.kind: item
            for item in sorted(proposal.evidence_refs, key=lambda item: item.ref_id)
        }
        requirement_rows: list[dict[str, Any]] = []
        missing_requirements = False
        requirement_evidence: list[EvidenceRef] = []
        for requirement in requirements:
            evidence = evidence_by_kind.get(requirement.kind)
            satisfied = evidence is not None and _evidence_valid(evidence)
            missing_requirements = missing_requirements or not satisfied
            if evidence is not None:
                requirement_evidence.append(evidence)
            requirement_rows.append(
                {
                    "requirement_id": requirement.requirement_id,
                    "kind": requirement.kind,
                    "satisfied": satisfied,
                    "evidence_ref_id": evidence.ref_id if evidence else None,
                }
            )
            if not satisfied:
                raw_r2.append(f"F07_EVIDENCE_MISSING:{requirement.requirement_id}")
                candidate_gaps.append(
                    _gap(
                        requirement.witness,
                        requirement.subject_ref,
                        (
                            "What resolves evidence requirement "
                            f"{requirement.requirement_id}?"
                        ),
                        f"valid evidence of kind {requirement.kind}",
                        requirement.resolution_rule_id,
                    )
                )
        descriptors.append(
            _Step(
                F07,
                OperatorFamily.TOGETHER_ALONE,
                "ALONE" if missing_requirements else "TOGETHER",
                proposal.proposal_id,
                tuple(item.requirement_id for item in requirements),
                {
                    "all_satisfied": not missing_requirements,
                    "requirements": requirement_rows,
                },
                tuple(requirement_evidence),
            )
        )

        consequence_required = config.require_consequence_for_yes and any(
            rule.require_consequence for rule in allow_rules
        )
        consequence_warnings: list[str] = []
        if approved:
            reports = sorted(
                (
                    (precedent, report)
                    for precedent in approved
                    for report in precedent.consequence_refs
                ),
                key=lambda pair: (pair[1].receipt_id, pair[1].consequence_id),
            )
            for _, report in reports:
                if (
                    report.receipt_terminal_status is not ExecutionStatus.OBSERVED
                    or report.divergence_threshold != config.divergence_threshold
                ):
                    _stop("INVALID_CONSEQUENCE", "consequence binding is invalid")
            missing_consequence_ids = [
                precedent.proposal_id
                for precedent in approved
                if not precedent.consequence_refs
            ]
            report_rows: list[dict[str, Any]] = []
            some_more = False
            for precedent, report in reports:
                more = report.divergence >= config.divergence_threshold
                some_more = some_more or more
                if more:
                    consequence_warnings.append(report.consequence_id)
                    raw_r2.append(f"F08_HIGH_DIVERGENCE:{report.consequence_id}")
                    candidate_gaps.append(
                        _gap(
                            Witness.WHAT,
                            report.consequence_id,
                            (
                                "What accepted outcome or mitigation resolves the "
                                "observed divergence?"
                            ),
                            "reviewed actual outcome or a new bounded proposal",
                            F08,
                        )
                    )
                report_rows.append(
                    {
                        "precedent_proposal_id": precedent.proposal_id,
                        "receipt_id": report.receipt_id,
                        "consequence_id": report.consequence_id,
                        "divergence": str(report.divergence),
                        "classification": "MORE" if more else "LESS",
                    }
                )
            if consequence_required:
                for precedent_id in missing_consequence_ids:
                    raw_r2.append(f"F08_MISSING_CONSEQUENCE:{precedent_id}")
                    candidate_gaps.extend(
                        (
                            _gap(
                                Witness.WHEN,
                                precedent_id,
                                "When was the approved effect observed?",
                                "a fresh OBSERVED receipt-bound consequence report",
                                F08,
                            ),
                            _gap(
                                Witness.WHAT,
                                precedent_id,
                                "What actual outcome followed the approved effect?",
                                (
                                    "canonical actual outcome bound to that OBSERVED "
                                    "receipt"
                                ),
                                F08,
                            ),
                        )
                    )
            descriptors.append(
                _Step(
                    F08,
                    OperatorFamily.MORE_LESS,
                    "MORE" if some_more else "LESS",
                    proposal.proposal_id,
                    tuple(item.proposal_id for item in approved),
                    {
                        "qualifying_precedent_ids": [
                            item.proposal_id for item in approved
                        ],
                        "missing_consequence_precedent_ids": missing_consequence_ids,
                        "report_count": len(reports),
                        "some_more": some_more,
                        "some_missing_consequence": bool(
                            consequence_required and missing_consequence_ids
                        ),
                        "reports": report_rows,
                    },
                )
            )

        required_capability_ids = tuple(
            sorted(
                {
                    capability_id
                    for rule in allow_rules
                    for capability_id in rule.required_capability_ids
                }
            )
        )
        capabilities_by_id: dict[str, CapabilityFact] = {}
        for capability in snapshot.capabilities:
            if capability.capability_id in capabilities_by_id:
                _stop("DUPLICATE_CAPABILITY", "capability identity is duplicated")
            capabilities_by_id[capability.capability_id] = capability
        if required_capability_ids:
            capability_rows: list[dict[str, Any]] = []
            some_false = False
            some_unresolved = False
            some_missing = False
            capability_evidence: list[EvidenceRef] = []
            for capability_id in required_capability_ids:
                cap_entry = capabilities_by_id.get(capability_id)
                if cap_entry is None:
                    state = "MISSING"
                    some_missing = True
                    raw_r2.append(f"F09_CAPABILITY_MISSING:{capability_id}")
                    candidate_gaps.extend(
                        (
                            _gap(
                                Witness.WHICH,
                                capability_id,
                                "Which exact required capability is available?",
                                "a bound capability identity and snapshot",
                                F09,
                            ),
                            _gap(
                                Witness.HOW,
                                capability_id,
                                "How was the required capability validated?",
                                "fresh capability proof",
                                F09,
                            ),
                        )
                    )
                else:
                    state = cap_entry.state.value
                    capability_evidence.extend(cap_entry.evidence_refs)
                    if cap_entry.state is DependencyState.FALSE:
                        some_false = True
                        raw_r1.append(f"F09_CAPABILITY_FALSE:{capability_id}")
                        decisive_rules.add(F09)
                    elif cap_entry.state is DependencyState.UNRESOLVED:
                        some_unresolved = True
                        raw_r2.append(f"F09_CAPABILITY_UNRESOLVED:{capability_id}")
                        candidate_gaps.append(
                            _gap(
                                Witness.HOW,
                                capability_id,
                                "How can this capability be resolved?",
                                "fresh bound capability proof",
                                F09,
                            )
                        )
                capability_rows.append({"capability_id": capability_id, "state": state})
            descriptors.append(
                _Step(
                    F09,
                    OperatorFamily.CAN_CANNOT,
                    "CANNOT"
                    if some_false or some_unresolved or some_missing
                    else "CAN",
                    proposal.proposal_id,
                    required_capability_ids,
                    {
                        "some_false": some_false,
                        "some_unresolved": some_unresolved,
                        "some_missing": some_missing,
                        "capabilities": capability_rows,
                    },
                    tuple(capability_evidence),
                )
            )

        dependencies = tuple(
            sorted(snapshot.dependencies, key=lambda item: item.dependency_id)
        )
        for dependency in dependencies:
            predicate_satisfied = dependency.state is DependencyState.TRUE
            dependency_result = {
                "dependency_id": dependency.dependency_id,
                "predicate": dependency.predicate,
                "expected_json": dependency.expected_json,
                "observed_json": dependency.observed_json,
                "state": dependency.state.value,
                "necessary_for_yes": dependency.necessary_for_yes,
                "sufficient_if_true": dependency.sufficient_if_true,
                "predicate_satisfied": predicate_satisfied,
                "snapshot_digest": dependency.snapshot_digest,
            }
            descriptors.extend(
                (
                    _Step(
                        F10,
                        OperatorFamily.IF_THEN,
                        "IF",
                        dependency.dependency_id,
                        (),
                        dependency_result,
                        dependency.evidence_refs,
                    ),
                    _Step(
                        F10,
                        OperatorFamily.IF_THEN,
                        "THEN",
                        dependency.dependency_id,
                        (),
                        {
                            **dependency_result,
                            "then": (
                                "dependency TRUE under a fresh bound snapshot permits "
                                "re-evaluation"
                            ),
                        },
                        dependency.evidence_refs,
                    ),
                )
            )
            if dependency.state is DependencyState.FALSE:
                raw_r1.append(f"F10_DEPENDENCY_FALSE:{dependency.dependency_id}")
                decisive_rules.add(F10)
            elif dependency.state is DependencyState.UNRESOLVED:
                if dependency.necessary_for_yes and dependency.sufficient_if_true:
                    raw_r3.append(f"F10_COMPLETE_FORMULA:{dependency.dependency_id}")
                else:
                    raw_r2.append(f"F10_INCOMPLETE_FORMULA:{dependency.dependency_id}")
                    candidate_gaps.extend(
                        (
                            _gap(
                                Witness.WHICH,
                                dependency.dependency_id,
                                "Which exact dependency state applies?",
                                "a fresh dependency fact",
                                F10,
                            ),
                            _gap(
                                Witness.HOW,
                                dependency.dependency_id,
                                "How can the dependency predicate be validated?",
                                "bound dependency evidence",
                                F10,
                            ),
                        )
                    )

        triggered = tuple(sorted(set((*raw_r1, *raw_r2, *raw_r3))))
        descriptors.append(
            _Step(
                F11,
                OperatorFamily.EVERY_SOME,
                "SOME" if triggered else "EVERY",
                proposal.proposal_id,
                (),
                {"triggered_predicate_ids": list(triggered)},
            )
        )

        if raw_r1:
            reducer_id = "R1_NO"
            verdict = Verdict.NO
            risk = Risk.HIGH
            gaps: tuple[EvidenceGap, ...] = ()
            for predicate in raw_r1:
                decisive_rules.add(_predicate_rule_id(predicate))
        elif raw_r2:
            reducer_id = "R2_MAYBE"
            verdict = Verdict.MAYBE
            risk = (
                Risk.HIGH
                if any(item.startswith("F08_HIGH") for item in raw_r2)
                else Risk.MEDIUM
            )
            gaps = tuple(sorted(set(candidate_gaps), key=lambda item: item.gap_id))
            decisive_rules.update(item.resolution_rule_id for item in gaps)
            decisive_rules.update(_predicate_rule_id(item) for item in raw_r2)
        elif raw_r3:
            reducer_id = "R3_IFF"
            verdict = Verdict.IFF
            risk = Risk.MEDIUM
            gaps = ()
            decisive_rules.add(F10)
        elif (
            allow_rules
            and approved
            and not missing_requirements
            and (
                not consequence_required
                or all(item.consequence_refs for item in approved)
            )
            and all(
                report.divergence < config.divergence_threshold
                for precedent in approved
                for report in precedent.consequence_refs
            )
            and all(
                capabilities_by_id[item].state is DependencyState.TRUE
                for item in required_capability_ids
            )
            and all(item.state is DependencyState.TRUE for item in dependencies)
        ):
            reducer_id = "R4_YES"
            verdict = Verdict.YES
            risk = Risk.LOW
            gaps = ()
            decisive_rules.update(
                {F02, F04, F05, F06, F07}
                | ({F08} if approved else set())
                | ({F09} if required_capability_ids else set())
                | ({F10} if dependencies else set())
            )
        else:
            _stop("REDUCER_NON_TOTAL", "validated inputs reached no reducer branch")

        if len(descriptors) + 2 > 99:
            _stop("TRACE_LIMIT_EXCEEDED", "sparse trace exceeds 99 steps")
        operator_steps = _build_operator_steps(snapshot.evaluation_id, descriptors)
        decisive_step_ids = tuple(
            step.step_id for step in operator_steps if step.rule_id in decisive_rules
        )
        reducer_ordinal = len(operator_steps) + 1
        reducer = ReducerTraceStep(
            step_id=make_step_id(snapshot.evaluation_id, reducer_ordinal, reducer_id),
            rule_id=reducer_id,
            family=OperatorFamily.EVERY_SOME,
            pole="EVERY" if reducer_id == "R4_YES" else "SOME",
            decisive_fact_step_ids=decisive_step_ids,
            result_json=_json(
                {
                    "verdict": verdict.name,
                    "risk": risk.value,
                    "decisive_fact_step_ids": list(decisive_step_ids),
                }
            ),
        )
        because_ordinal = reducer_ordinal + 1
        because = OperatorTraceStep(
            step_id=make_step_id(snapshot.evaluation_id, because_ordinal, F12),
            rule_id=F12,
            family=OperatorFamily.BECAUSE,
            pole="BECAUSE",
            subject_ref=proposal.proposal_id,
            object_refs=(
                reducer.step_id,
                *decisive_step_ids,
                *(gap.gap_id for gap in gaps),
                *(
                    item.dependency_id
                    for item in dependencies
                    if item.state is DependencyState.UNRESOLVED
                ),
            ),
            result_json=_json({"verdict": verdict.name, "risk": risk.value}),
            evidence_refs=(),
        )
        trace: tuple[OperatorTraceStep | ReducerTraceStep, ...] = (
            *operator_steps,
            reducer,
            because,
        )
        changed = _changed_fact_ids(trace, gaps, snapshot)
        check_result = CheckResult(
            verdict=verdict,
            risk=risk,
            operator_trace=trace,
            evidence_gaps=gaps,
            dependencies=dependencies,
            precedent_refs=tuple(item.proposal_id for item in precedents),
            consequence_warning_refs=tuple(sorted(consequence_warnings)),
            because_step_id=because.step_id,
            evaluation_id=snapshot.evaluation_id,
            profile_version=snapshot.profile_version,
            prior_evaluation_id=prior_id,
            changed_fact_rule_ids=changed,
            evaluator_version=config.evaluator_version,
            rule_config_digest=config.rule_config_digest,
            input_snapshot_digest=snapshot.snapshot_digest,
            policy_digest=snapshot.policy.policy_digest,
            trace_digest=_ZERO_DIGEST,
        )
        return replace(check_result, trace_digest=check_result_digest(check_result))
    except _Blocked as error:
        return _blocked_result(snapshot, config, error.code, error.message, prior_id)
    except (ContractViolation, ValueError, TypeError, KeyError):
        return _blocked_result(
            snapshot,
            config,
            "INTERNAL_EVALUATOR_ERROR",
            "deterministic evaluator rejected malformed input",
            prior_id,
        )


__all__ = [
    "RuleConfig",
    "compute_rule_config_digest",
    "default_rule_config",
    "evaluate_proposal",
    "normalize_action_target_key",
    "policy_input_digest",
    "proposal_action_digest",
    "proposal_record_digest",
    "rule_config_payload",
]
