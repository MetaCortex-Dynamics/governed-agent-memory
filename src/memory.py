"""Append-only application memory with bounded CockroachDB retries."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar, Token
from dataclasses import fields
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, cast

import asyncpg  # type: ignore[import-untyped]

from src.config import AppDbConfig
from src.models import (
    BlockedResult,
    CapabilityFact,
    CheckResult,
    ConsequenceRef,
    ConsequenceReport,
    DecisionValue,
    DependencyFact,
    DependencyRef,
    DependencyState,
    EvaluationSnapshot,
    EvidenceGap,
    EvidenceRef,
    ExclusionRef,
    ExecutionStatus,
    OperatorTraceStep,
    PolicyEffect,
    PolicyInput,
    PolicyRule,
    PrecedentRef,
    PriorEvaluationTrace,
    Proposal,
    ReducerTraceStep,
    ToolEvidence,
)
from src.operators import OperatorFamily
from src.traces import (
    ContractViolation,
    canonical_json_bytes,
    canonical_sha256,
    validate_blocked_result,
    validate_check_result,
    validate_snapshot,
)
from src.verdict import Risk, Verdict
from src.witnesses import Witness


class MemoryIntegrityError(ValueError):
    """Stored or requested bytes violate an append-only binding."""


class MemoryConflictError(MemoryIntegrityError):
    """An idempotency key or lineage binding names different bytes."""


CCLOUD_CLUSTER_NAME = "kingly-dreamer"
CCLOUD_CLUSTER_NAME_DIGEST = hashlib.sha256(
    CCLOUD_CLUSTER_NAME.encode("utf-8")
).hexdigest()


class _Transaction(Protocol):
    async def __aenter__(self) -> object: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class Connection(Protocol):
    def transaction(self, *, isolation: str) -> _Transaction: ...

    async def execute(self, query: str, *args: object) -> str: ...

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, Any] | None: ...

    async def fetch(self, query: str, *args: object) -> Sequence[Mapping[str, Any]]: ...


class _Acquire(Protocol):
    async def __aenter__(self) -> Connection: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class Pool(Protocol):
    def acquire(self) -> _Acquire: ...

    async def close(self) -> None: ...


def _dump(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _plain_json(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )


def _json_sha256(value: object) -> str:
    """Hash the canonical plain-JSON domain used by external tool evidence."""
    return hashlib.sha256(_plain_json(value).encode("utf-8")).hexdigest()


def _loaded(value: object) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _enum[T](value: object, enum_type: type[T]) -> T:
    if isinstance(value, str):
        if value in enum_type.__members__:  # type: ignore[attr-defined]
            return cast(T, enum_type[value])  # type: ignore[index]
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as error:
            raise MemoryIntegrityError("stored enum member is invalid") from error
    else:
        raw = value
    if isinstance(raw, Mapping) and "$enum" in raw:
        return cast(T, enum_type[cast(str, raw["member"])])  # type: ignore[index]
    if isinstance(raw, str) and raw in enum_type.__members__:  # type: ignore[attr-defined]
        return cast(T, enum_type[raw])  # type: ignore[index]
    try:
        return enum_type(raw)  # type: ignore[call-arg]
    except (TypeError, ValueError) as error:
        raise MemoryIntegrityError("stored enum member is invalid") from error


def _decimal(value: object) -> Decimal:
    raw = _loaded(value)
    if isinstance(raw, Mapping) and "$decimal" in raw:
        raw = raw["$decimal"]
    try:
        result = Decimal(str(raw))
    except Exception as error:
        raise MemoryIntegrityError("stored Decimal is invalid") from error
    if not result.is_finite():
        raise MemoryIntegrityError("stored Decimal is non-finite")
    return result


def _float(value: object) -> float:
    raw = _loaded(value)
    if isinstance(raw, Mapping) and "$float" in raw:
        raw = raw["$float"]
    result = float(raw)
    if not -float("inf") < result < float("inf"):
        raise MemoryIntegrityError("stored float is non-finite")
    return result


def _tuple(value: object) -> tuple[Any, ...]:
    raw = _loaded(value)
    if not isinstance(raw, list):
        raise MemoryIntegrityError("stored array is invalid")
    return tuple(raw)


def _evidence(value: object) -> EvidenceRef:
    raw = cast(Mapping[str, Any], value)
    return EvidenceRef(str(raw["ref_id"]), str(raw["kind"]), str(raw["digest"]))


def _gap(value: object) -> EvidenceGap:
    raw = cast(Mapping[str, Any], value)
    return EvidenceGap(
        gap_id=str(raw["gap_id"]),
        witness=_enum(raw["witness"], Witness),
        subject_ref=str(raw["subject_ref"]),
        question=str(raw["question"]),
        needed=str(raw["needed"]),
        resolution_rule_id=str(raw["resolution_rule_id"]),
    )


def _dependency(value: object) -> DependencyRef:
    raw = cast(Mapping[str, Any], value)
    return DependencyRef(
        dependency_id=str(raw["dependency_id"]),
        subject_ref=str(raw["subject_ref"]),
        predicate=str(raw["predicate"]),
        expected_json=str(raw["expected_json"]),
        observed_json=(
            str(raw["observed_json"]) if raw.get("observed_json") is not None else None
        ),
        state=_enum(raw["state"], DependencyState),
        snapshot_digest=str(raw["snapshot_digest"]),
        evidence_refs=tuple(_evidence(item) for item in _tuple(raw["evidence_refs"])),
        necessary_for_yes=bool(raw["necessary_for_yes"]),
        sufficient_if_true=bool(raw["sufficient_if_true"]),
    )


def _trace_step(value: object) -> OperatorTraceStep | ReducerTraceStep:
    raw = cast(Mapping[str, Any], value)
    if "decisive_fact_step_ids" in raw:
        return ReducerTraceStep(
            step_id=str(raw["step_id"]),
            rule_id=str(raw["rule_id"]),
            family=_enum(raw["family"], OperatorFamily),
            pole=str(raw["pole"]),
            decisive_fact_step_ids=tuple(
                str(item) for item in _tuple(raw["decisive_fact_step_ids"])
            ),
            result_json=str(raw["result_json"]),
        )
    return OperatorTraceStep(
        step_id=str(raw["step_id"]),
        rule_id=str(raw["rule_id"]),
        family=_enum(raw["family"], OperatorFamily),
        pole=str(raw["pole"]),
        subject_ref=str(raw["subject_ref"]),
        object_refs=tuple(str(item) for item in _tuple(raw["object_refs"])),
        result_json=str(raw["result_json"]),
        evidence_refs=tuple(_evidence(item) for item in _tuple(raw["evidence_refs"])),
    )


def _policy_rule(value: object) -> PolicyRule:
    raw = cast(Mapping[str, Any], value)
    from src.models import EvidenceRequirement

    requirements = tuple(
        EvidenceRequirement(
            requirement_id=str(item["requirement_id"]),
            kind=str(item["kind"]),
            witness=_enum(item["witness"], Witness),
            subject_ref=str(item["subject_ref"]),
            resolution_rule_id=str(item["resolution_rule_id"]),
        )
        for item in _tuple(raw["required_evidence"])
    )
    return PolicyRule(
        rule_id=str(raw["rule_id"]),
        action_type_key=str(raw["action_type_key"]),
        target_key=(
            str(raw["target_key"]) if raw.get("target_key") is not None else None
        ),
        effect=_enum(raw["effect"], PolicyEffect),
        because=str(raw["because"]),
        required_evidence=requirements,
        required_capability_ids=tuple(
            str(item) for item in _tuple(raw["required_capability_ids"])
        ),
        require_consequence=bool(raw["require_consequence"]),
    )


def _proposal_from_mapping(raw: Mapping[str, Any]) -> Proposal:
    embedding_raw = _loaded(raw["embedding"])
    if isinstance(embedding_raw, str):
        embedding_raw = json.loads(embedding_raw)
    return Proposal(
        proposal_id=str(raw.get("proposal_id", raw.get("id"))),
        parent_proposal_id=(
            str(raw["parent_proposal_id"])
            if raw.get("parent_proposal_id") is not None
            else None
        ),
        source_modify_decision_id=(
            str(raw["source_modify_decision_id"])
            if raw.get("source_modify_decision_id") is not None
            else None
        ),
        source_modify_decision_value=(
            _enum(raw["source_modify_decision_value"], DecisionValue)
            if raw.get("source_modify_decision_value") is not None
            else None
        ),
        agent_id=str(raw["agent_id"]),
        session_id=str(raw["session_id"]),
        action_type=str(raw["action_type"]),
        action_type_key=str(raw["action_type_key"]),
        target=str(raw["target"]),
        target_key=str(raw["target_key"]),
        reasoning=str(raw["reasoning"]),
        purpose=str(raw["purpose"]),
        parameters_json=_plain_json(raw["parameters"]),
        impact_assessment_json=_plain_json(raw["impact_assessment"]),
        predicted_outcome_json=_plain_json(raw["predicted_outcome"]),
        evidence_refs=tuple(_evidence(item) for item in _tuple(raw["evidence"])),
        dependencies=tuple(_dependency(item) for item in _tuple(raw["dependencies"])),
        embedding=tuple(_float(item) for item in cast(Sequence[object], embedding_raw)),
        embedding_model=str(raw["embedding_model"]),
        embedding_input_digest=str(raw["embedding_input_digest"]),
        action_digest=str(raw["action_digest"]),
        proposal_digest=str(raw["proposal_digest"]),
    )


def _prior(value: object) -> PriorEvaluationTrace:
    raw = cast(Mapping[str, Any], value)
    return PriorEvaluationTrace(
        evaluation_id=str(raw["evaluation_id"]),
        proposal_id=str(raw["proposal_id"]),
        verdict=_enum(raw["verdict"], Verdict),
        risk=_enum(raw["risk"], Risk),
        operator_trace=tuple(
            _trace_step(item) for item in _tuple(raw["operator_trace"])
        ),
        evidence_gaps=tuple(_gap(item) for item in _tuple(raw["evidence_gaps"])),
        dependencies=tuple(_dependency(item) for item in _tuple(raw["dependencies"])),
        precedent_refs=tuple(str(item) for item in _tuple(raw["precedent_refs"])),
        consequence_warning_refs=tuple(
            str(item) for item in _tuple(raw["consequence_warning_refs"])
        ),
        because_step_id=str(raw["because_step_id"]),
        profile_version=(
            str(raw["profile_version"])
            if raw.get("profile_version") is not None
            else None
        ),
        prior_evaluation_id=(
            str(raw["prior_evaluation_id"])
            if raw.get("prior_evaluation_id") is not None
            else None
        ),
        changed_fact_rule_ids=tuple(
            str(item) for item in _tuple(raw["changed_fact_rule_ids"])
        ),
        evaluator_version=str(raw["evaluator_version"]),
        rule_config_digest=str(raw["rule_config_digest"]),
        input_snapshot_digest=str(raw["input_snapshot_digest"]),
        policy_digest=str(raw["policy_digest"]),
        trace_digest=str(raw["trace_digest"]),
    )


def _snapshot_from_json(value: object) -> EvaluationSnapshot:
    raw = cast(Mapping[str, Any], _loaded(value))
    proposal = _proposal_from_mapping(cast(Mapping[str, Any], raw["proposal"]))
    policy_raw = cast(Mapping[str, Any], raw["policy"])
    policy = PolicyInput(
        policy_version=str(policy_raw["policy_version"]),
        policy_digest=str(policy_raw["policy_digest"]),
        rules=tuple(_policy_rule(item) for item in _tuple(policy_raw["rules"])),
    )
    capabilities = tuple(
        CapabilityFact(
            capability_id=str(item["capability_id"]),
            subject_ref=str(item["subject_ref"]),
            state=_enum(item["state"], DependencyState),
            snapshot_digest=str(item["snapshot_digest"]),
            evidence_refs=tuple(
                _evidence(ref) for ref in _tuple(item["evidence_refs"])
            ),
        )
        for item in _tuple(raw["capabilities"])
    )
    return EvaluationSnapshot(
        evaluation_id=str(raw["evaluation_id"]),
        snapshot_id=str(raw["snapshot_id"]),
        profile_version=(
            str(raw["profile_version"])
            if raw.get("profile_version") is not None
            else None
        ),
        proposal=proposal,
        policy=policy,
        precedents=(),
        exclusions=(),
        capabilities=capabilities,
        dependencies=tuple(_dependency(item) for item in _tuple(raw["dependencies"])),
        prior_evaluation=(
            _prior(raw["prior_evaluation"])
            if raw.get("prior_evaluation") is not None
            else None
        ),
        captured_at=str(raw["captured_at"]),
        snapshot_digest=str(raw["snapshot_digest"]),
    )


def _result_from_row(row: Mapping[str, Any]) -> CheckResult | BlockedResult:
    evaluation_id = str(row.get("evaluation_id", row.get("id")))
    profile_version = (
        str(row["profile_version"]) if row.get("profile_version") is not None else None
    )
    prior_evaluation_id = (
        str(row["prior_evaluation_id"])
        if row.get("prior_evaluation_id") is not None
        else None
    )
    changed = tuple(str(item) for item in _tuple(row["changed_fact_rule_ids"]))
    trace = tuple(_trace_step(item) for item in _tuple(row["operator_trace"]))
    gaps = tuple(_gap(item) for item in _tuple(row["evidence_gaps"]))
    dependencies = tuple(_dependency(item) for item in _tuple(row["dependencies"]))
    if str(row["status"]) == "BLOCKED":
        blocked_reason = str(row["blocked_reason"])
        error_code, separator, safe_message = blocked_reason.partition(":")
        if not separator or not error_code or not safe_message:
            raise MemoryIntegrityError("stored BLOCKED reason is malformed")
        blocked = BlockedResult(
            evaluation_id=evaluation_id,
            profile_version=profile_version,
            prior_evaluation_id=prior_evaluation_id,
            changed_fact_rule_ids=changed,
            error_code=error_code,
            safe_message=safe_message,
            operator_trace=cast(tuple[OperatorTraceStep, ...], trace),
            evidence_gaps=gaps,
            dependencies=dependencies,
            evaluator_version=str(row["evaluator_version"]),
            rule_config_digest=str(row["rule_config_digest"]),
            input_snapshot_digest=str(row["input_snapshot_digest"]),
            policy_digest=str(row["policy_digest"]),
            trace_digest=str(row["trace_digest"]),
        )
        return validate_blocked_result(blocked)
    checked = CheckResult(
        verdict=_enum(row["verdict"], Verdict),
        risk=_enum(row["risk"], Risk),
        operator_trace=trace,
        evidence_gaps=gaps,
        dependencies=dependencies,
        precedent_refs=tuple(str(item) for item in _tuple(row["precedent_refs"])),
        consequence_warning_refs=tuple(
            str(item) for item in _tuple(row["consequence_warning_refs"])
        ),
        because_step_id=str(row["because_step_id"]),
        evaluation_id=evaluation_id,
        profile_version=profile_version,
        prior_evaluation_id=prior_evaluation_id,
        changed_fact_rule_ids=changed,
        evaluator_version=str(row["evaluator_version"]),
        rule_config_digest=str(row["rule_config_digest"]),
        input_snapshot_digest=str(row["input_snapshot_digest"]),
        policy_digest=str(row["policy_digest"]),
        trace_digest=str(row["trace_digest"]),
    )
    return validate_check_result(checked)


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


def _proposal_action_digest(proposal: Proposal) -> str:
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


def _proposal_digest(proposal: Proposal) -> str:
    return _record_digest(proposal, "gam.proposal.v1", "proposal_digest")


def _policy_digest(policy: PolicyInput) -> str:
    return canonical_sha256(
        {
            "schema": "gam.policy-input.v1",
            "policy_version": policy.policy_version,
            "rules": tuple(sorted(policy.rules, key=lambda item: item.rule_id)),
        }
    )


def _timestamp(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


def _validate_report(report: ConsequenceReport) -> None:
    if (
        report.receipt_terminal_status is not ExecutionStatus.OBSERVED
        or report.observation_number <= 0
        or report.report_digest
        != _record_digest(report, "gam.consequence-report.v1", "report_digest")
    ):
        raise MemoryIntegrityError("consequence report digest or receipt is invalid")


def _validate_dependency_fact(fact: DependencyFact) -> None:
    if fact.fact_digest != _record_digest(
        fact, "gam.dependency-fact.v1", "fact_digest"
    ):
        raise MemoryIntegrityError("dependency fact digest is invalid")
    if (fact.fact_version == 1) != (
        fact.prior_fact_id is None and fact.prior_fact_version is None
    ):
        raise MemoryIntegrityError("dependency fact lineage is invalid")


def _validate_tool_evidence(evidence: ToolEvidence) -> None:
    if (
        evidence.tool_name != "ccloud"
        or evidence.cluster_name != CCLOUD_CLUSTER_NAME
        or evidence.cluster_name_digest != CCLOUD_CLUSTER_NAME_DIGEST
        or evidence.exit_status != 0
        or evidence.evidence_digest != _tool_evidence_digest(evidence)
    ):
        raise MemoryIntegrityError("tool evidence binding is invalid")


def _tool_evidence_digest(evidence: ToolEvidence) -> str:
    return _json_sha256(
        {
            "schema": "gam.tool-evidence.v1",
            "tool_name": evidence.tool_name,
            "tool_version": evidence.tool_version,
            "redacted_command_argv": _loaded(evidence.redacted_command_argv_json),
            "command_digest": evidence.command_digest,
            "help_digest": evidence.help_digest,
            "config_digest": evidence.config_digest,
            "cluster_name": evidence.cluster_name,
            "cluster_name_digest": evidence.cluster_name_digest,
            "observed_cluster_id_digest": evidence.observed_cluster_id_digest,
            "observed_version": evidence.observed_version,
            "observed_state": evidence.observed_state,
            "observed_plan": evidence.observed_plan,
            "observed_cloud": evidence.observed_cloud,
            "normalized_redacted_output": _loaded(
                evidence.normalized_redacted_output_json
            ),
            "redaction_manifest": _loaded(evidence.redaction_manifest_json),
            "raw_output_digest": evidence.raw_output_digest,
            "normalized_output_digest": evidence.normalized_output_digest,
            "exit_status": evidence.exit_status,
            "captured_at": evidence.captured_at,
            "expires_at": evidence.expires_at,
            "captured_by": evidence.captured_by,
            "idempotency_key": evidence.idempotency_key,
        }
    )


def _is_serialization_failure(error: BaseException) -> bool:
    return getattr(error, "sqlstate", None) == "40001"


def _vector_text(values: tuple[float, ...]) -> str:
    if len(values) != 1536:
        raise MemoryIntegrityError("query embedding dimensions are invalid")
    return "[" + ",".join(format(value, ".17g") for value in values) + "]"


_INSERT_PROPOSAL = """
INSERT INTO proposals (
    id, parent_proposal_id, source_modify_decision_id,
    source_modify_decision_value, agent_id, session_id, action_type,
    action_type_key, target, target_key, reasoning, purpose, parameters,
    impact_assessment, predicted_outcome, evidence, dependencies, embedding,
    embedding_model, embedding_dimensions, embedding_input_digest,
    action_digest, proposal_digest
) VALUES (
    $1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13::JSONB, $14::JSONB, $15::JSONB, $16::JSONB, $17::JSONB,
    $18::VECTOR, $19, 1536, $20, $21, $22
)
"""

_INSERT_EVALUATION = """
INSERT INTO gate_evaluations (
    id, proposal_id, prior_evaluation_id, evaluator_version,
    rule_config_digest, input_snapshot, input_snapshot_digest,
    profile_version, policy_snapshot, policy_digest, similarity_threshold,
    divergence_threshold, verdict, risk, operator_trace, evidence_gaps,
    dependencies, precedent_refs, consequence_warning_refs,
    changed_fact_rule_ids, because_step_id, trace_digest, status, blocked_reason
) VALUES (
    $1::UUID, $2::UUID, $3::UUID, $4, $5, $6::JSONB, $7, $8,
    $9::JSONB, $10, 0.8500, 0.5000, $11, $12, $13::JSONB,
    $14::JSONB, $15::JSONB, $16::JSONB, $17::JSONB, $18::JSONB,
    $19, $20, $21, $22
)
"""


class AppMemory:
    """Application-role persistence only; no decision or execution methods."""

    def __init__(
        self,
        config: AppDbConfig | None = None,
        *,
        pool: Pool | None = None,
    ) -> None:
        self._config = config
        self._pool = pool
        self._active: ContextVar[Connection | None] = ContextVar(
            "app_memory_connection", default=None
        )

    async def _get_pool(self) -> Pool:
        if self._pool is None:
            config = self._config or AppDbConfig.from_env()
            created = await asyncpg.create_pool(
                dsn=config.database_url,
                min_size=1,
                max_size=4,
                command_timeout=30,
            )
            self._pool = cast(Pool, created)
            self._config = config
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Connection]:
        """Open one serializable unit that nested AppMemory calls reuse."""
        active = self._active.get()
        if active is not None:
            yield active
            return
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            async with connection.transaction(isolation="serializable"):
                context_handle: Token[Connection | None] = self._active.set(connection)
                try:
                    yield connection
                finally:
                    self._active.reset(context_handle)

    async def _retry(self, operation: Callable[[Connection], Any]) -> Any:
        if self._active.get() is not None:
            return await operation(cast(Connection, self._active.get()))
        retries = self._config.max_serialization_retries if self._config else 4
        for attempt in range(retries):
            try:
                async with self.transaction() as connection:
                    return await operation(connection)
            except Exception as error:
                if not _is_serialization_failure(error) or attempt + 1 == retries:
                    raise
        raise MemoryIntegrityError("serialization retry loop was not total")

    @staticmethod
    def _validate_evaluation_binding(
        snapshot: EvaluationSnapshot,
        result: CheckResult | BlockedResult,
    ) -> None:
        try:
            validate_snapshot(snapshot)
            if isinstance(result, CheckResult):
                validate_check_result(result)
            else:
                validate_blocked_result(result)
        except ContractViolation as error:
            raise MemoryIntegrityError(
                "snapshot or evaluation digest validation failed"
            ) from error
        if (
            snapshot.proposal.action_digest
            != _proposal_action_digest(snapshot.proposal)
            or snapshot.proposal.proposal_digest != _proposal_digest(snapshot.proposal)
            or snapshot.policy.policy_digest != _policy_digest(snapshot.policy)
        ):
            raise MemoryIntegrityError("proposal or policy digest validation failed")
        if (
            result.evaluation_id != snapshot.evaluation_id
            or result.input_snapshot_digest != snapshot.snapshot_digest
            or result.policy_digest != snapshot.policy.policy_digest
            or result.profile_version != snapshot.profile_version
        ):
            raise MemoryIntegrityError("evaluation and snapshot bindings differ")

    @staticmethod
    def _proposal_args(proposal: Proposal) -> tuple[object, ...]:
        return (
            proposal.proposal_id,
            proposal.parent_proposal_id,
            proposal.source_modify_decision_id,
            (
                proposal.source_modify_decision_value.value
                if proposal.source_modify_decision_value
                else None
            ),
            proposal.agent_id,
            proposal.session_id,
            proposal.action_type,
            proposal.action_type_key,
            proposal.target,
            proposal.target_key,
            proposal.reasoning,
            proposal.purpose,
            proposal.parameters_json,
            proposal.impact_assessment_json,
            proposal.predicted_outcome_json,
            _dump(proposal.evidence_refs),
            _dump(proposal.dependencies),
            _vector_text(proposal.embedding),
            proposal.embedding_model,
            proposal.embedding_input_digest,
            proposal.action_digest,
            proposal.proposal_digest,
        )

    @staticmethod
    def _evaluation_args(
        proposal_id: str,
        snapshot: EvaluationSnapshot,
        result: CheckResult | BlockedResult,
    ) -> tuple[object, ...]:
        if isinstance(result, CheckResult):
            verdict = result.verdict.name
            risk = result.risk.value
            precedent_refs = _dump(result.precedent_refs)
            warning_refs = _dump(result.consequence_warning_refs)
            because_step_id = result.because_step_id
            status = "FINALIZED"
            blocked_reason = None
        else:
            verdict = None
            risk = None
            precedent_refs = "[]"
            warning_refs = "[]"
            because_step_id = None
            status = "BLOCKED"
            blocked_reason = f"{result.error_code}:{result.safe_message}"
        return (
            result.evaluation_id,
            proposal_id,
            result.prior_evaluation_id,
            result.evaluator_version,
            result.rule_config_digest,
            _dump(snapshot),
            result.input_snapshot_digest,
            result.profile_version,
            _dump(snapshot.policy),
            result.policy_digest,
            verdict,
            risk,
            _dump(result.operator_trace),
            _dump(result.evidence_gaps),
            _dump(result.dependencies),
            precedent_refs,
            warning_refs,
            _dump(result.changed_fact_rule_ids),
            because_step_id,
            result.trace_digest,
            status,
            blocked_reason,
        )

    async def append_proposal_and_evaluation(
        self,
        proposal: Proposal,
        snapshot: EvaluationSnapshot,
        result: CheckResult | BlockedResult,
    ) -> tuple[str, str]:
        self._validate_evaluation_binding(snapshot, result)
        if (
            snapshot.proposal != proposal
            or snapshot.prior_evaluation is not None
            or result.prior_evaluation_id is not None
            or result.changed_fact_rule_ids
        ):
            raise MemoryIntegrityError("first evaluation genealogy is invalid")

        async def operation(connection: Connection) -> tuple[str, str]:
            existing = await connection.fetchrow(
                "SELECT id, proposal_digest FROM proposals WHERE id = $1::UUID",
                proposal.proposal_id,
            )
            if existing is not None:
                evaluation = await connection.fetchrow(
                    "SELECT id, trace_digest FROM gate_evaluations "
                    "WHERE id = $1::UUID AND proposal_id = $2::UUID",
                    result.evaluation_id,
                    proposal.proposal_id,
                )
                if (
                    str(existing["proposal_digest"]) == proposal.proposal_digest
                    and evaluation is not None
                    and str(evaluation["trace_digest"]) == result.trace_digest
                ):
                    return proposal.proposal_id, result.evaluation_id
                raise MemoryConflictError("proposal/evaluation replay conflicts")
            await connection.execute(_INSERT_PROPOSAL, *self._proposal_args(proposal))
            await connection.execute(
                _INSERT_EVALUATION,
                *self._evaluation_args(proposal.proposal_id, snapshot, result),
            )
            return proposal.proposal_id, result.evaluation_id

        return cast(tuple[str, str], await self._retry(operation))

    async def append_re_evaluation(
        self,
        snapshot: EvaluationSnapshot,
        result: CheckResult | BlockedResult,
    ) -> tuple[str, str]:
        self._validate_evaluation_binding(snapshot, result)
        prior = snapshot.prior_evaluation
        if (
            prior is None
            or result.prior_evaluation_id != prior.evaluation_id
            or prior.proposal_id != snapshot.proposal.proposal_id
        ):
            raise MemoryIntegrityError("re-evaluation prior binding is invalid")

        async def operation(connection: Connection) -> tuple[str, str]:
            existing = await connection.fetchrow(
                "SELECT id, trace_digest FROM gate_evaluations WHERE id = $1::UUID",
                result.evaluation_id,
            )
            if existing is not None:
                if str(existing["trace_digest"]) == result.trace_digest:
                    return snapshot.proposal.proposal_id, result.evaluation_id
                raise MemoryConflictError("re-evaluation identity conflicts")
            latest = await connection.fetchrow(
                "SELECT id, trace_digest FROM gate_evaluations "
                "WHERE proposal_id = $1::UUID ORDER BY created_at DESC, id DESC "
                "LIMIT 1 FOR UPDATE",
                snapshot.proposal.proposal_id,
            )
            if (
                latest is None
                or str(latest["id"]) != prior.evaluation_id
                or str(latest["trace_digest"]) != prior.trace_digest
            ):
                raise MemoryConflictError("re-evaluation prior is stale")
            await connection.execute(
                _INSERT_EVALUATION,
                *self._evaluation_args(snapshot.proposal.proposal_id, snapshot, result),
            )
            return snapshot.proposal.proposal_id, result.evaluation_id

        return cast(tuple[str, str], await self._retry(operation))

    async def get_proposal(self, proposal_id: str) -> Proposal:
        async def operation(connection: Connection) -> Proposal:
            row = await connection.fetchrow(
                "SELECT *, id AS proposal_id FROM proposals WHERE id = $1::UUID",
                proposal_id,
            )
            if row is None:
                raise MemoryIntegrityError("proposal was not found")
            return _proposal_from_mapping(row)

        return cast(Proposal, await self._retry(operation))

    async def get_evaluation(self, evaluation_id: str) -> CheckResult | BlockedResult:
        async def operation(connection: Connection) -> CheckResult | BlockedResult:
            row = await connection.fetchrow(
                "SELECT *, id AS evaluation_id FROM gate_evaluations "
                "WHERE id = $1::UUID",
                evaluation_id,
            )
            if row is None:
                raise MemoryIntegrityError("evaluation was not found")
            return _result_from_row(row)

        return cast(CheckResult | BlockedResult, await self._retry(operation))

    async def list_evaluations(
        self, proposal_id: str
    ) -> tuple[CheckResult | BlockedResult, ...]:
        async def operation(
            connection: Connection,
        ) -> tuple[CheckResult | BlockedResult, ...]:
            rows = await connection.fetch(
                "SELECT *, id AS evaluation_id FROM gate_evaluations "
                "WHERE proposal_id = $1::UUID ORDER BY created_at, id",
                proposal_id,
            )
            return tuple(_result_from_row(row) for row in rows)

        return cast(
            tuple[CheckResult | BlockedResult, ...], await self._retry(operation)
        )

    async def search_precedents(
        self,
        embedding: tuple[float, ...],
        limit: int,
        current_evaluation_id: str,
    ) -> tuple[PrecedentRef, ...]:
        if limit != 5:
            raise MemoryIntegrityError("precedent search limit must be five")
        vector = _vector_text(embedding)

        async def operation(connection: Connection) -> tuple[PrecedentRef, ...]:
            rows = await connection.fetch(
                """
WITH candidates AS (
    SELECT p.*, 1 - (p.embedding <=> $1::VECTOR) AS similarity
    FROM proposals AS p
    ORDER BY embedding <=> $1::VECTOR LIMIT 5
)
SELECT c.id AS proposal_id, c.proposal_digest, c.action_digest,
       c.action_type_key, c.target_key, c.similarity,
       g.id AS evaluation_id, g.trace_digest,
       d.decision, d.id AS decision_id, d.decision_digest,
       r.id AS receipt_id, r.receipt_digest, r.attempt_terminal_status,
       cr.id AS consequence_id, cr.predicted_snapshot_digest,
       cr.actual_snapshot_digest, cr.comparison_version,
       cr.divergence_score, cr.divergence_threshold, cr.report_digest
FROM candidates AS c
JOIN gate_evaluations AS g ON g.proposal_id = c.id AND g.status = 'FINALIZED'
LEFT JOIN decisions AS d ON d.evaluation_id = g.id
LEFT JOIN execution_receipts AS r ON r.decision_id = d.id
LEFT JOIN consequence_reports AS cr ON cr.receipt_id = r.id
WHERE g.id <> $2::UUID
ORDER BY c.id, g.id, r.id, cr.id
""",
                vector,
                current_evaluation_id,
            )
            grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
            for row in rows:
                key = (str(row["proposal_id"]), str(row["evaluation_id"]))
                grouped.setdefault(key, []).append(row)
            result: list[PrecedentRef] = []
            for key in sorted(grouped):
                group = grouped[key]
                first = group[0]
                consequences = tuple(
                    ConsequenceRef(
                        consequence_id=str(row["consequence_id"]),
                        receipt_id=str(row["receipt_id"]),
                        receipt_terminal_status=_enum(
                            row["attempt_terminal_status"], ExecutionStatus
                        ),
                        receipt_digest=str(row["receipt_digest"]),
                        predicted_snapshot_digest=str(row["predicted_snapshot_digest"]),
                        actual_snapshot_digest=str(row["actual_snapshot_digest"]),
                        comparison_version=str(row["comparison_version"]),
                        divergence=_decimal(row["divergence_score"]),
                        divergence_threshold=_decimal(row["divergence_threshold"]),
                        report_digest=str(row["report_digest"]),
                    )
                    for row in group
                    if row.get("consequence_id") is not None
                )
                result.append(
                    PrecedentRef(
                        proposal_id=key[0],
                        proposal_digest=str(first["proposal_digest"]),
                        action_digest=str(first["action_digest"]),
                        action_type_key=str(first["action_type_key"]),
                        target_key=str(first["target_key"]),
                        decision=(
                            _enum(first["decision"], DecisionValue)
                            if first.get("decision") is not None
                            else None
                        ),
                        decision_id=(
                            str(first["decision_id"])
                            if first.get("decision_id") is not None
                            else None
                        ),
                        decision_digest=(
                            str(first["decision_digest"])
                            if first.get("decision_digest") is not None
                            else None
                        ),
                        similarity=_decimal(first["similarity"]),
                        similarity_error_code=None,
                        evaluation_id=key[1],
                        trace_digest=str(first["trace_digest"]),
                        receipt_id=(
                            str(first["receipt_id"])
                            if first.get("receipt_id") is not None
                            else None
                        ),
                        receipt_digest=(
                            str(first["receipt_digest"])
                            if first.get("receipt_digest") is not None
                            else None
                        ),
                        receipt_terminal_status=(
                            _enum(first["attempt_terminal_status"], ExecutionStatus)
                            if first.get("attempt_terminal_status") is not None
                            else None
                        ),
                        consequence_refs=consequences,
                    )
                )
            return tuple(result)

        return cast(tuple[PrecedentRef, ...], await self._retry(operation))

    async def get_exclusions(
        self, action_type_key: str, target_key: str
    ) -> tuple[ExclusionRef, ...]:
        async def operation(connection: Connection) -> tuple[ExclusionRef, ...]:
            rows = await connection.fetch(
                "SELECT * FROM exclusions WHERE action_type_key = $1 "
                "AND target_key = $2 ORDER BY action_type_key, target_key, id",
                action_type_key,
                target_key,
            )
            return tuple(
                ExclusionRef(
                    exclusion_id=str(row["id"]),
                    action_type=str(row["action_type"]),
                    action_type_key=str(row["action_type_key"]),
                    target=str(row["target"]),
                    target_key=str(row["target_key"]),
                    reason=str(row["reason"]),
                    source_proposal_id=str(row["source_proposal_id"]),
                    source_evaluation_id=str(row["source_evaluation_id"]),
                    source_evaluation_trace_digest=str(
                        row["source_evaluation_trace_digest"]
                    ),
                    source_decision_id=str(row["source_decision_id"]),
                    source_decision_value=_enum(
                        row["source_decision_value"], DecisionValue
                    ),
                    source_decision_digest=str(row["source_decision_digest"]),
                    exclusion_digest=str(row["exclusion_digest"]),
                    idempotency_key=str(row["idempotency_key"]),
                )
                for row in rows
            )

        return cast(tuple[ExclusionRef, ...], await self._retry(operation))

    async def append_dependency_fact(self, fact: DependencyFact) -> str:
        _validate_dependency_fact(fact)

        async def operation(connection: Connection) -> str:
            existing = await connection.fetchrow(
                "SELECT id, fact_digest FROM dependency_facts "
                "WHERE idempotency_key = $1",
                fact.idempotency_key,
            )
            if existing is not None:
                if str(existing["fact_digest"]) == fact.fact_digest:
                    return str(existing["id"])
                raise MemoryConflictError("dependency idempotency key conflicts")
            await connection.execute(
                """
INSERT INTO dependency_facts (
    id, dependency_key, fact_version, prior_fact_id, prior_fact_version,
    subject_ref, predicate, observed_value, state, snapshot_digest,
    evidence_refs, recorded_by, fact_digest, idempotency_key
) VALUES ($1::UUID, $2, $3, $4::UUID, $5, $6, $7, $8::JSONB, $9, $10,
          $11::JSONB, $12, $13, $14)
""",
                fact.fact_id,
                fact.dependency_key,
                fact.fact_version,
                fact.prior_fact_id,
                fact.prior_fact_version,
                fact.subject_ref,
                fact.predicate,
                fact.observed_value_json,
                fact.state.value,
                fact.snapshot_digest,
                _dump(fact.evidence_refs),
                fact.recorded_by,
                fact.fact_digest,
                fact.idempotency_key,
            )
            return fact.fact_id

        return cast(str, await self._retry(operation))

    async def get_dependency_facts(
        self, dependency_keys: tuple[str, ...]
    ) -> tuple[DependencyFact, ...]:
        if dependency_keys != tuple(sorted(set(dependency_keys))):
            raise MemoryIntegrityError("dependency keys are not sorted and unique")

        async def operation(connection: Connection) -> tuple[DependencyFact, ...]:
            rows = await connection.fetch(
                """
SELECT DISTINCT ON (dependency_key) * FROM dependency_facts
WHERE dependency_key = ANY($1::STRING[])
ORDER BY dependency_key, fact_version DESC
""",
                dependency_keys,
            )
            facts = tuple(
                DependencyFact(
                    fact_id=str(row["id"]),
                    dependency_key=str(row["dependency_key"]),
                    fact_version=int(row["fact_version"]),
                    prior_fact_id=(
                        str(row["prior_fact_id"])
                        if row.get("prior_fact_id") is not None
                        else None
                    ),
                    prior_fact_version=(
                        int(row["prior_fact_version"])
                        if row.get("prior_fact_version") is not None
                        else None
                    ),
                    subject_ref=str(row["subject_ref"]),
                    predicate=str(row["predicate"]),
                    observed_value_json=(
                        _plain_json(row["observed_value"])
                        if row.get("observed_value") is not None
                        else None
                    ),
                    state=_enum(row["state"], DependencyState),
                    snapshot_digest=str(row["snapshot_digest"]),
                    evidence_refs=tuple(
                        _evidence(item) for item in _tuple(row["evidence_refs"])
                    ),
                    recorded_by=str(row["recorded_by"]),
                    fact_digest=str(row["fact_digest"]),
                    idempotency_key=str(row["idempotency_key"]),
                )
                for row in rows
            )
            for fact in facts:
                _validate_dependency_fact(fact)
            return facts

        return cast(tuple[DependencyFact, ...], await self._retry(operation))

    async def append_consequence(self, report: ConsequenceReport) -> str:
        _validate_report(report)

        async def operation(connection: Connection) -> str:
            existing = await connection.fetchrow(
                "SELECT id, report_digest FROM consequence_reports "
                "WHERE idempotency_key = $1",
                report.idempotency_key,
            )
            if existing is not None:
                if str(existing["report_digest"]) == report.report_digest:
                    return str(existing["id"])
                raise MemoryConflictError("consequence idempotency key conflicts")
            await connection.execute(
                """
INSERT INTO consequence_reports (
    id, proposal_id, receipt_id, receipt_terminal_status, receipt_digest,
    observation_number, predicted_snapshot_digest, actual_snapshot_digest,
    comparison_version, predicted_outcome, actual_outcome, leaf_report,
    divergence_score, divergence_threshold, divergence_summary, reported_by,
    report_digest, idempotency_key
) VALUES ($1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7, $8, $9,
          $10::JSONB, $11::JSONB, $12::JSONB, $13, $14, $15, $16, $17, $18)
""",
                report.consequence_id,
                report.proposal_id,
                report.receipt_id,
                report.receipt_terminal_status.value,
                report.receipt_digest,
                report.observation_number,
                report.predicted_snapshot_digest,
                report.actual_snapshot_digest,
                report.comparison_version,
                report.predicted_outcome_json,
                report.actual_outcome_json,
                report.leaf_report_json,
                report.divergence_score,
                report.divergence_threshold,
                report.divergence_summary,
                report.reported_by,
                report.report_digest,
                report.idempotency_key,
            )
            return report.consequence_id

        return cast(str, await self._retry(operation))

    async def append_tool_evidence(self, evidence: ToolEvidence) -> str:
        _validate_tool_evidence(evidence)

        async def operation(connection: Connection) -> str:
            existing = await connection.fetchrow(
                "SELECT id, evidence_digest FROM tool_evidence "
                "WHERE idempotency_key = $1",
                evidence.idempotency_key,
            )
            if existing is not None:
                if str(existing["evidence_digest"]) == evidence.evidence_digest:
                    return str(existing["id"])
                raise MemoryConflictError("tool evidence idempotency key conflicts")
            await connection.execute(
                """
INSERT INTO tool_evidence (
    id, tool_name, tool_version, redacted_command_argv, command_digest,
    help_digest, config_digest, cluster_name, cluster_name_digest,
    observed_cluster_id_digest, observed_version, observed_state,
    observed_plan, observed_cloud, normalized_redacted_output,
    redaction_manifest, raw_output_digest, normalized_output_digest,
    exit_status, captured_at, expires_at, captured_by, evidence_digest,
    idempotency_key
) VALUES ($1::UUID, $2, $3, $4::JSONB, $5, $6, $7, $8, $9, $10, $11,
          $12, $13, $14, $15::JSONB, $16::JSONB, $17, $18, $19,
          $20::TIMESTAMPTZ, $21::TIMESTAMPTZ, $22, $23, $24)
""",
                evidence.evidence_id,
                evidence.tool_name,
                evidence.tool_version,
                evidence.redacted_command_argv_json,
                evidence.command_digest,
                evidence.help_digest,
                evidence.config_digest,
                evidence.cluster_name,
                evidence.cluster_name_digest,
                evidence.observed_cluster_id_digest,
                evidence.observed_version,
                evidence.observed_state,
                evidence.observed_plan,
                evidence.observed_cloud,
                evidence.normalized_redacted_output_json,
                evidence.redaction_manifest_json,
                evidence.raw_output_digest,
                evidence.normalized_output_digest,
                evidence.exit_status,
                evidence.captured_at,
                evidence.expires_at,
                evidence.captured_by,
                evidence.evidence_digest,
                evidence.idempotency_key,
            )
            return evidence.evidence_id

        return cast(str, await self._retry(operation))

    async def get_latest_unexpired_tool_evidence(
        self, cluster_name: str
    ) -> ToolEvidence:
        if cluster_name != CCLOUD_CLUSTER_NAME:
            raise MemoryIntegrityError("tool evidence cluster is not permitted")

        async def operation(connection: Connection) -> ToolEvidence:
            rows = await connection.fetch(
                """
SELECT * FROM tool_evidence
WHERE cluster_name = $1 AND exit_status = 0
  AND expires_at > transaction_timestamp()
ORDER BY captured_at DESC, id DESC LIMIT 2
""",
                cluster_name,
            )
            if not rows:
                raise MemoryIntegrityError("fresh tool evidence was not found")
            row = rows[0]
            evidence = ToolEvidence(
                evidence_id=str(row["id"]),
                tool_name=str(row["tool_name"]),
                tool_version=str(row["tool_version"]),
                redacted_command_argv_json=_plain_json(row["redacted_command_argv"]),
                command_digest=str(row["command_digest"]),
                help_digest=str(row["help_digest"]),
                config_digest=str(row["config_digest"]),
                cluster_name=str(row["cluster_name"]),
                cluster_name_digest=str(row["cluster_name_digest"]),
                observed_cluster_id_digest=str(row["observed_cluster_id_digest"]),
                observed_version=str(row["observed_version"]),
                observed_state=str(row["observed_state"]),
                observed_plan=str(row["observed_plan"]),
                observed_cloud=str(row["observed_cloud"]),
                normalized_redacted_output_json=_plain_json(
                    row["normalized_redacted_output"]
                ),
                redaction_manifest_json=_plain_json(row["redaction_manifest"]),
                raw_output_digest=str(row["raw_output_digest"]),
                normalized_output_digest=str(row["normalized_output_digest"]),
                exit_status=int(row["exit_status"]),
                captured_at=_timestamp(row["captured_at"]),
                expires_at=_timestamp(row["expires_at"]),
                captured_by=str(row["captured_by"]),
                evidence_digest=str(row["evidence_digest"]),
                idempotency_key=str(row["idempotency_key"]),
            )
            _validate_tool_evidence(evidence)
            if len(rows) == 2 and str(rows[1]["id"]) == evidence.evidence_id:
                raise MemoryConflictError("duplicate tool evidence identity")
            return evidence

        return cast(ToolEvidence, await self._retry(operation))


__all__ = [
    "AppMemory",
    "Connection",
    "MemoryConflictError",
    "MemoryIntegrityError",
    "Pool",
]
