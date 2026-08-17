"""Authority-bounded proposal drafting and deterministic local evaluation."""

from __future__ import annotations

import json
import os
import re
import unicodedata
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Literal, NoReturn, cast
from uuid import UUID, uuid4, uuid5

import openai
from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.ccloud_tool import CLUSTER_NAME, capture
from src.config import EmbeddingConfig
from src.embeddings import (
    EMBEDDING_MODEL,
    embed_one,
    embedding_input_digest,
    embedding_output_digest,
)
from src.governance import (
    default_rule_config,
    evaluate_proposal,
    normalize_action_target_key,
    policy_input_digest,
    proposal_action_digest,
    proposal_record_digest,
)
from src.memory import AppMemory, MemoryIntegrityError
from src.models import (
    BlockedResult,
    CapabilityFact,
    CheckResult,
    DecisionValue,
    DependencyFact,
    DependencyRef,
    DependencyState,
    EvaluationSnapshot,
    EvidenceRef,
    PolicyInput,
    PrecedentRef,
    Proposal,
    ToolEvidence,
)
from src.traces import (
    canonical_json_bytes,
    canonical_sha256,
    finalize_snapshot,
    validate_blocked_result,
    validate_check_result,
)

MODEL_SNAPSHOT = "gpt-4.1-mini-2025-04-14"
PROMPT_TEMPLATE = """You draft non-authoritative action proposals only.
Return only the strict ProposalDraft schema. Never decide, approve, promote,
execute, or provide verdict, risk, trace, witness, receipt, command, credential,
or authority fields. Evidence references must come from the supplied allowlist.
"""
PROMPT_TEMPLATE_DIGEST = canonical_sha256(PROMPT_TEMPLATE)
PROFILE_VERSION = "agent-loop/1.1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_OUTPUT_KEYS = frozenset(
    {
        "verdict",
        "risk",
        "decision",
        "trace",
        "operator",
        "witness",
        "receipt",
        "command",
        "credential",
        "execution",
    }
)

type JsonScalar = str | Decimal | bool | None
type JsonValue = JsonScalar | tuple[JsonValue, ...] | Mapping[str, JsonValue]
type AgentStage = Literal[
    "INPUT", "EMBEDDING", "CCLOUD", "OPENAI", "VALIDATION", "PERSISTENCE"
]


class AgentContractError(ValueError):
    """One safe, non-sensitive agent-boundary failure."""


def _reject(message: str) -> NoReturn:
    raise AgentContractError(message)


def _uuid(value: str, name: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise AgentContractError(f"{name} is not a UUID") from error
    if str(parsed) != value:
        _reject(f"{name} is not canonical")
    return value


def _text(value: str, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _reject(f"{name} is empty or padded")
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized.encode("utf-8", "strict")) > maximum:
        _reject(f"{name} exceeds its byte limit")
    return normalized


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        _reject("JSON number is non-finite")
    if value.is_zero():
        return "0"
    result = format(value.normalize(), "f")
    return result.rstrip("0").rstrip(".") if "." in result else result


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, bool)):
        return cast(JsonScalar, value)
    if isinstance(value, int) and not isinstance(value, bool):
        return Decimal(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            _reject("JSON number is non-finite")
        return value
    if isinstance(value, float):
        _reject("binary floating-point JSON is forbidden")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_json_value(item) for item in value)
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                _reject("JSON object key is not a string")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                _reject("JSON object has a normalized duplicate key")
            if key.casefold() in _FORBIDDEN_OUTPUT_KEYS:
                _reject("model output contains an authority field")
            result[key] = _json_value(item)
        return result
    _reject("model output contains a non-JSON value")


def _plain_json(value: JsonValue) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, Decimal):
        return _decimal_text(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, tuple):
        return "[" + ",".join(_plain_json(item) for item in value) + "]"
    return (
        "{"
        + ",".join(
            f"{json.dumps(key, ensure_ascii=False)}:{_plain_json(value[key])}"
            for key in sorted(value, key=lambda item: item.encode("utf-8"))
        )
        + "}"
    )


@dataclass(frozen=True, slots=True)
class AgentConfig:
    model_snapshot: Literal["gpt-4.1-mini-2025-04-14"]
    openai_sdk_version: str
    prompt_version: str
    request_timeout_seconds: Decimal
    max_retries: int
    max_task_bytes: int
    precedent_top_k: Literal[5]
    similarity_threshold: Decimal
    gate_config_digest: str

    def __post_init__(self) -> None:
        if (
            self.model_snapshot != MODEL_SNAPSHOT
            or self.openai_sdk_version != openai.__version__
            or not self.prompt_version
            or not Decimal("5") <= self.request_timeout_seconds <= Decimal("30")
            or not 0 <= self.max_retries <= 2
            or self.max_task_bytes <= 0
            or self.precedent_top_k != 5
            or self.similarity_threshold != Decimal("0.85000000")
            or self.gate_config_digest != default_rule_config().rule_config_digest
        ):
            raise AgentContractError("agent configuration is not the pinned contract")

    @property
    def digest(self) -> str:
        return canonical_sha256(
            {
                "schema": "gam.agent-config.v1",
                **{field.name: getattr(self, field.name) for field in fields(self)},
            }
        )


@dataclass(frozen=True, slots=True)
class CanonicalJson:
    utf8: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class DependencyRequest:
    dependency_key: str
    predicate: str
    expected_json: str
    necessary_for_yes: bool
    sufficient_if_true: bool


@dataclass(frozen=True, slots=True)
class ProposalDraft:
    action_type: str
    target: str
    reasoning: str
    purpose: str
    evidence_refs: tuple[str, ...]
    predicted_outcome: CanonicalJson
    parameters: CanonicalJson
    impact_assessment: CanonicalJson
    dependency_requests: tuple[DependencyRequest, ...]


@dataclass(frozen=True, slots=True)
class AgentResult:
    proposal_id: str
    evaluation_id: str
    trace_digest: str
    proposal_digest: str
    openai_call_digest: str
    tool_evidence_refs: tuple[str, ...]
    check_result: CheckResult

    @property
    def verdict(self) -> str:
        return self.check_result.verdict.name

    @property
    def profile_version(self) -> str | None:
        return self.check_result.profile_version


@dataclass(frozen=True, slots=True)
class AgentGateBlockedResult:
    proposal_id: str
    evaluation_id: str
    trace_digest: str
    proposal_digest: str
    openai_call_digest: str
    tool_evidence_refs: tuple[str, ...]
    blocked_result: BlockedResult


@dataclass(frozen=True, slots=True)
class AgentBlockedResult:
    request_id: str
    stage: AgentStage
    task_digest: str
    agent_config_digest: str
    error_code: str
    safe_message: str
    attempt_digest: str


class DependencyRequestSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    dependency_key: str = Field(min_length=1, max_length=128)
    predicate: str = Field(min_length=1, max_length=256)
    expected_json: Any
    necessary_for_yes: bool
    sufficient_if_true: bool


class ProposalDraftSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    action_type: str = Field(min_length=1, max_length=256)
    target: str = Field(min_length=1, max_length=1024)
    reasoning: str = Field(min_length=1, max_length=4096)
    purpose: str = Field(min_length=1, max_length=1024)
    evidence_refs: tuple[str, ...] = Field(max_length=64)
    predicted_outcome: Any
    parameters: dict[str, Any]
    impact_assessment: Any
    dependency_requests: tuple[DependencyRequestSchema, ...] = Field(max_length=32)


_MEMORY = AppMemory()
_EMBED: Callable[..., Awaitable[tuple[float, ...]]] = embed_one
_CAPTURE: Callable[..., Awaitable[ToolEvidence]] = capture


def _client(config: AgentConfig) -> AsyncOpenAI:
    key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("OPENAI_MODEL")
    if not key or model != MODEL_SNAPSHOT:
        _reject("OpenAI execution configuration is absent or unpinned")
    return AsyncOpenAI(
        api_key=key,
        timeout=float(config.request_timeout_seconds),
        max_retries=config.max_retries,
    )


_CLIENT_FACTORY: Callable[[AgentConfig], Any] = _client


def _canonical(value: object, *, require_object: bool = False) -> CanonicalJson:
    normalized = _json_value(value)
    if require_object and not isinstance(normalized, Mapping):
        _reject("proposal parameters are not an object")
    raw = _plain_json(normalized).encode("utf-8")
    return CanonicalJson(raw, canonical_sha256(normalized))


def _draft(parsed: object, allowlist: frozenset[str]) -> ProposalDraft:
    try:
        schema = (
            parsed
            if isinstance(parsed, ProposalDraftSchema)
            else ProposalDraftSchema.model_validate(parsed)
        )
    except ValidationError as error:
        raise AgentContractError("model output failed strict validation") from error
    refs = tuple(schema.evidence_refs)
    if refs != tuple(sorted(set(refs))) or any(item not in allowlist for item in refs):
        _reject("model evidence references are unknown or duplicated")
    dependencies: list[DependencyRequest] = []
    keys: set[str] = set()
    for item in schema.dependency_requests:
        key = normalize_action_target_key(item.dependency_key)
        if key in keys:
            _reject("model dependency request is duplicated")
        keys.add(key)
        dependencies.append(
            DependencyRequest(
                key,
                _text(item.predicate, "dependency predicate", maximum=256),
                _canonical(item.expected_json).utf8.decode(),
                item.necessary_for_yes,
                item.sufficient_if_true,
            )
        )
    dependencies.sort(key=lambda item: item.dependency_key)
    return ProposalDraft(
        _text(schema.action_type, "action type", maximum=256),
        _text(schema.target, "target", maximum=1024),
        _text(schema.reasoning, "reasoning"),
        _text(schema.purpose, "purpose", maximum=1024),
        refs,
        _canonical(schema.predicted_outcome),
        _canonical(schema.parameters, require_object=True),
        _canonical(schema.impact_assessment),
        tuple(dependencies),
    )


def _blocked(
    request_id: str,
    stage: AgentStage,
    task_digest: str,
    config_digest: str,
    code: str,
    message: str,
) -> AgentBlockedResult:
    payload = {
        "schema": "gam.agent-blocked.v1",
        "request_id": request_id,
        "stage": stage,
        "task_digest": task_digest,
        "agent_config_digest": config_digest,
        "error_code": code,
        "safe_message": message,
    }
    return AgentBlockedResult(
        request_id,
        stage,
        task_digest,
        config_digest,
        code,
        message,
        canonical_sha256(payload),
    )


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _policy() -> PolicyInput:
    provisional = PolicyInput(PROFILE_VERSION, "0" * 64, ())
    return replace(provisional, policy_digest=policy_input_digest(provisional))


def _evidence_ref(evidence: ToolEvidence) -> EvidenceRef:
    if evidence.tool_name != "ccloud" or not _HEX.fullmatch(evidence.evidence_digest):
        _reject("tool evidence binding is invalid")
    return EvidenceRef(evidence.evidence_id, "ccloud_cluster", evidence.evidence_digest)


def _capability(evidence: ToolEvidence, reference: EvidenceRef) -> CapabilityFact:
    if evidence.observed_state != "CREATED":
        _reject("ccloud evidence does not prove a ready cluster")
    return CapabilityFact(
        "cockroach_cluster_ready",
        f"cluster:{evidence.cluster_name}",
        DependencyState.TRUE,
        canonical_sha256(
            {
                "state": evidence.observed_state,
                "evidence_digest": evidence.evidence_digest,
            }
        ),
        (reference,),
    )


def _dependencies(
    proposal_id: str,
    requests: tuple[DependencyRequest, ...],
    facts: tuple[DependencyFact, ...],
) -> tuple[DependencyRef, ...]:
    by_key = {fact.dependency_key: fact for fact in facts}
    if len(by_key) != len(facts):
        _reject("local dependency evidence is ambiguous")
    result: list[DependencyRef] = []
    namespace = UUID(proposal_id)
    for request in requests:
        fact = by_key.get(request.dependency_key)
        if fact is None or fact.predicate != request.predicate:
            _reject("required local dependency evidence is missing")
        result.append(
            DependencyRef(
                str(uuid5(namespace, request.dependency_key)),
                fact.subject_ref,
                request.predicate,
                request.expected_json,
                fact.observed_value_json,
                fact.state,
                fact.snapshot_digest,
                fact.evidence_refs,
                request.necessary_for_yes,
                request.sufficient_if_true,
            )
        )
    return tuple(result)


async def _lineage(parent_id: str | None, decision_id: str | None) -> None:
    if parent_id is None:
        return
    async with _MEMORY.transaction() as connection:
        row = await connection.fetchrow(
            """
SELECT d.id, d.proposal_id, d.decision, d.decision_digest, p.proposal_digest
FROM decisions AS d JOIN proposals AS p ON p.id = d.proposal_id
WHERE d.id = $1::UUID AND p.id = $2::UUID
""",
            decision_id,
            parent_id,
        )
        if (
            row is None
            or str(row["decision"]) != DecisionValue.MODIFY.value
            or not _HEX.fullmatch(str(row["decision_digest"]))
            or not _HEX.fullmatch(str(row["proposal_digest"]))
        ):
            _reject("MODIFY lineage is missing or mismatched")


def _prompt(
    task: str, precedents: Sequence[PrecedentRef], evidence: ToolEvidence
) -> tuple[list[dict[str, str]], str]:
    summary = {
        "task": task,
        "evidence_allowlist": (
            {
                "ref_id": evidence.evidence_id,
                "kind": "ccloud_cluster",
                "state": evidence.observed_state,
                "digest": evidence.evidence_digest,
            },
        ),
        "precedents": tuple(
            {
                "proposal_id": item.proposal_id,
                "action_type_key": item.action_type_key,
                "target_key": item.target_key,
                "similarity": str(item.similarity),
                "trace_digest": item.trace_digest,
            }
            for item in precedents
        ),
    }
    return [
        {"role": "system", "content": PROMPT_TEMPLATE},
        {"role": "user", "content": canonical_json_bytes(summary).decode()},
    ], canonical_sha256(summary)


async def process_task(
    task_description: str,
    *,
    request_id: str,
    agent_id: str,
    session_id: str,
    requester_ref: str,
    config: AgentConfig,
    parent_proposal_id: str | None = None,
    source_modify_decision_id: str | None = None,
) -> AgentResult | AgentGateBlockedResult | AgentBlockedResult:
    """Draft, locally evaluate, and atomically persist one proposal."""
    task_digest = (
        canonical_sha256(task_description)
        if isinstance(task_description, str)
        else "0" * 64
    )
    config_digest = config.digest
    try:
        _uuid(request_id, "request_id")
        task = _text(task_description, "task", maximum=config.max_task_bytes)
        agent_id = _text(agent_id, "agent_id", maximum=256)
        session_id = _text(session_id, "session_id", maximum=256)
        requester_ref = _text(requester_ref, "requester_ref", maximum=256)
        task_digest = canonical_sha256(task)
        lineage = (parent_proposal_id, source_modify_decision_id)
        if any(item is None for item in lineage) and not all(
            item is None for item in lineage
        ):
            _reject("MODIFY lineage arguments are partial")
        if parent_proposal_id is not None:
            _uuid(parent_proposal_id, "parent_proposal_id")
            _uuid(cast(str, source_modify_decision_id), "source_modify_decision_id")
        proposal_id, evaluation_id = str(uuid4()), str(uuid4())
    except Exception:
        return _blocked(
            request_id,
            "INPUT",
            task_digest,
            config_digest,
            "INVALID_INPUT",
            "agent input validation failed",
        )
    try:
        embedding_config = EmbeddingConfig.from_env()
        embedding = await _EMBED(task, config=embedding_config)
        input_digest = embedding_input_digest((task,))
        embedding_output_digest((task,), (embedding,))
        precedents = await _MEMORY.search_precedents(
            embedding, config.precedent_top_k, evaluation_id
        )
    except Exception:
        return _blocked(
            request_id,
            "EMBEDDING",
            task_digest,
            config_digest,
            "EMBEDDING_FAILED",
            "embedding or precedent retrieval failed",
        )
    try:
        evidence = await _CAPTURE(purpose="runtime")
        await _MEMORY.append_tool_evidence(evidence)
        reference = _evidence_ref(evidence)
    except Exception:
        return _blocked(
            request_id,
            "CCLOUD",
            task_digest,
            config_digest,
            "CCLOUD_EVIDENCE_FAILED",
            "fresh ccloud evidence is unavailable",
        )
    prompt, prompt_input_digest = _prompt(task, precedents, evidence)
    started_at = _utc_now()
    try:
        response = await _CLIENT_FACTORY(config).responses.parse(
            model=MODEL_SNAPSHOT, input=prompt, text_format=ProposalDraftSchema
        )
        response_model = getattr(response, "model", None)
        if response_model not in (None, MODEL_SNAPSHOT):
            _reject("OpenAI returned an unbound model identity")
        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            _reject("OpenAI response was refused or incomplete")
        draft = _draft(parsed, frozenset({evidence.evidence_id}))
        response_output_digest = canonical_sha256(
            {
                "action_type": draft.action_type,
                "target": draft.target,
                "reasoning": draft.reasoning,
                "purpose": draft.purpose,
                "evidence_refs": draft.evidence_refs,
                "predicted_outcome_digest": draft.predicted_outcome.digest,
                "parameters_digest": draft.parameters.digest,
                "impact_assessment_digest": draft.impact_assessment.digest,
                "dependency_requests": draft.dependency_requests,
            }
        )
        call_digest = canonical_sha256(
            {
                "provider": "openai",
                "endpoint": "responses",
                "model_requested": MODEL_SNAPSHOT,
                "model_returned_if_available": response_model,
                "model_snapshot": MODEL_SNAPSHOT,
                "openai_sdk_version": config.openai_sdk_version,
                "prompt_version": config.prompt_version,
                "prompt_template_digest": PROMPT_TEMPLATE_DIGEST,
                "task_digest": task_digest,
                "requester_ref_digest": canonical_sha256(requester_ref),
                "prompt_input_digest": prompt_input_digest,
                "agent_config_digest": config_digest,
                "response_id": getattr(response, "id", None),
                "response_output_digest": response_output_digest,
                "parsed_schema_digest": canonical_sha256(
                    _json_value(ProposalDraftSchema.model_json_schema())
                ),
                "attempt_number": 1,
                "started_at": started_at,
                "completed_at": _utc_now(),
                "status": "PARSED",
            }
        )
    except Exception:
        return _blocked(
            request_id,
            "OPENAI",
            task_digest,
            config_digest,
            "OPENAI_OUTPUT_BLOCKED",
            "OpenAI response was unavailable or invalid",
        )
    try:
        action_key = normalize_action_target_key(draft.action_type)
        target_key = normalize_action_target_key(draft.target)
        exact_precedents = tuple(
            item
            for item in precedents
            if item.similarity is not None
            and item.similarity >= config.similarity_threshold
            and item.action_type_key == action_key
            and item.target_key == target_key
        )
        exclusions = await _MEMORY.get_exclusions(action_key, target_key)
        facts = await _MEMORY.get_dependency_facts(
            tuple(item.dependency_key for item in draft.dependency_requests)
        )
        dependencies = _dependencies(proposal_id, draft.dependency_requests, facts)
        await _lineage(parent_proposal_id, source_modify_decision_id)
        refs = (reference,) if draft.evidence_refs else ()
        provisional = Proposal(
            proposal_id,
            parent_proposal_id,
            source_modify_decision_id,
            DecisionValue.MODIFY if parent_proposal_id is not None else None,
            agent_id,
            session_id,
            draft.action_type,
            action_key,
            draft.target,
            target_key,
            draft.reasoning,
            draft.purpose,
            draft.parameters.utf8.decode(),
            draft.impact_assessment.utf8.decode(),
            draft.predicted_outcome.utf8.decode(),
            refs,
            dependencies,
            embedding,
            EMBEDDING_MODEL,
            input_digest,
            "0" * 64,
            "0" * 64,
        )
        proposal = replace(
            provisional, action_digest=proposal_action_digest(provisional)
        )
        proposal = replace(proposal, proposal_digest=proposal_record_digest(proposal))
        policy = _policy()
        snapshot = finalize_snapshot(
            EvaluationSnapshot(
                evaluation_id,
                str(uuid4()),
                PROFILE_VERSION,
                proposal,
                policy,
                exact_precedents,
                exclusions,
                (_capability(evidence, reference),),
                dependencies,
                None,
                _utc_now(),
                "0" * 64,
            )
        )
        result = evaluate_proposal(snapshot, default_rule_config())
        validate_check_result(result) if isinstance(
            result, CheckResult
        ) else validate_blocked_result(result)
    except Exception:
        return _blocked(
            request_id,
            "VALIDATION",
            task_digest,
            config_digest,
            "LOCAL_VALIDATION_FAILED",
            "proposal or gate input validation failed",
        )
    try:

        async def persist(_: object) -> tuple[str, str]:
            fresh = await _MEMORY.get_latest_unexpired_tool_evidence(CLUSTER_NAME)
            if (
                fresh.evidence_id != evidence.evidence_id
                or fresh.evidence_digest != evidence.evidence_digest
            ):
                raise MemoryIntegrityError("tool evidence changed before persistence")
            await _lineage(parent_proposal_id, source_modify_decision_id)
            return await _MEMORY.append_proposal_and_evaluation(
                proposal, snapshot, result
            )

        await _MEMORY._retry(persist)  # noqa: SLF001 - one governed retry envelope
    except Exception:
        return _blocked(
            request_id,
            "PERSISTENCE",
            task_digest,
            config_digest,
            "ATOMIC_PERSISTENCE_FAILED",
            "proposal and evaluation were not committed",
        )
    if isinstance(result, CheckResult):
        return AgentResult(
            proposal_id,
            evaluation_id,
            result.trace_digest,
            proposal.proposal_digest,
            call_digest,
            tuple(item.ref_id for item in refs),
            result,
        )
    return AgentGateBlockedResult(
        proposal_id,
        evaluation_id,
        result.trace_digest,
        proposal.proposal_digest,
        call_digest,
        tuple(item.ref_id for item in refs),
        result,
    )


__all__ = [
    "AgentBlockedResult",
    "AgentConfig",
    "AgentGateBlockedResult",
    "AgentResult",
    "CanonicalJson",
    "DependencyRequest",
    "MODEL_SNAPSHOT",
    "PROFILE_VERSION",
    "PROMPT_TEMPLATE_DIGEST",
    "ProposalDraft",
    "ProposalDraftSchema",
    "process_task",
]
