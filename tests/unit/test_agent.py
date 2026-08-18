from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, fields
from decimal import Decimal
from typing import Any
from uuid import uuid4

import openai
import pytest
from openai.lib._pydantic import to_strict_json_schema
from pydantic import ValidationError

import src.agent as agent
from src.agent import (
    MODEL_SNAPSHOT,
    AgentBlockedResult,
    AgentConfig,
    AgentResult,
    ProposalDraftSchema,
    process_task,
)
from src.embeddings import EMBEDDING_DIMENSIONS
from src.governance import default_rule_config
from src.models import ToolEvidence


def config() -> AgentConfig:
    return AgentConfig(
        "gpt-4.1-mini-2025-04-14",
        openai.__version__,
        "proposal-draft/1.1",
        Decimal("20"),
        2,
        4096,
        5,
        Decimal("0.85000000"),
        default_rule_config().rule_config_digest,
    )


def evidence() -> ToolEvidence:
    return ToolEvidence(
        str(uuid4()),
        "ccloud",
        "v0.6.12",
        '["ccloud","cluster","info","kingly-dreamer","--output=json"]',
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "kingly-dreamer",
        "4" * 64,
        "5" * 64,
        "v26.2.5",
        "CREATED",
        "BASIC",
        "AWS",
        "{}",
        "[]",
        "6" * 64,
        "7" * 64,
        0,
        "2026-08-17T12:00:00.000000Z",
        "2026-08-17T12:15:00.000000Z",
        "ccloud-evidence-adapter",
        "8" * 64,
        "unit-ccloud-capture",
    )


def draft(evidence_id: str, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "action_type": "Create report",
        "target": "local report",
        "reasoning": "The requested report is bounded.",
        "purpose": "Produce a local report.",
        "evidence_refs": (evidence_id,),
        "predicted_outcome": '{"created":true}',
        "parameters": '{"format":"json"}',
        "impact_assessment": '{"remote_effect":false}',
        "dependency_requests": (),
    }
    value.update(changes)
    return value


@dataclass
class Response:
    output_parsed: object
    id: str = "response-unit"
    model: str = MODEL_SNAPSHOT


class Responses:
    def __init__(self, output: object) -> None:
        self.output = output
        self.calls = 0

    async def parse(self, **kwargs: object) -> Response:
        self.calls += 1
        assert kwargs["model"] == MODEL_SNAPSHOT
        assert kwargs["text_format"] is ProposalDraftSchema
        return Response(self.output)


class Client:
    def __init__(self, output: object) -> None:
        self.responses = Responses(output)


class Memory:
    def __init__(self, item: ToolEvidence) -> None:
        self.item = item
        self.proposals: list[Any] = []
        self.evaluations: list[Any] = []
        self.tool_appends = 0
        self.retry_attempts = 0
        self.serialize_once = False
        self._serialized = False
        self.fail_append = False

    async def search_precedents(
        self, embedding: tuple[float, ...], limit: int, evaluation_id: str
    ) -> tuple[()]:
        assert len(embedding) == EMBEDDING_DIMENSIONS
        assert limit == 5
        assert evaluation_id
        return ()

    async def append_tool_evidence(self, item: ToolEvidence) -> str:
        self.tool_appends += 1
        assert item == self.item
        return item.evidence_id

    async def get_exclusions(self, action: str, target: str) -> tuple[()]:
        assert action == "create report"
        assert target == "local report"
        return ()

    async def get_dependency_facts(self, keys: tuple[str, ...]) -> tuple[()]:
        assert keys == ()
        return ()

    async def get_latest_unexpired_tool_evidence(self, name: str) -> ToolEvidence:
        assert name == "kingly-dreamer"
        return self.item

    async def append_proposal_and_evaluation(
        self, proposal: Any, snapshot: object, result: Any
    ) -> tuple[str, str]:
        if self.fail_append:
            raise RuntimeError("unit persistence failure")
        self.proposals.append(proposal)
        self.evaluations.append(result)
        return (proposal.proposal_id, result.evaluation_id)

    async def _retry(self, operation: Any) -> object:
        self.retry_attempts += 1
        if self.serialize_once and not self._serialized:
            self._serialized = True
            try:
                raise RuntimeError("unit serialization restart")
            except RuntimeError:
                pass
        return await operation(object())

    @asynccontextmanager
    async def transaction(self) -> Any:
        yield object()


async def run(
    monkeypatch: pytest.MonkeyPatch,
    output: object | None,
    *,
    serialize_once: bool = False,
) -> tuple[object, Memory, Client, dict[str, int]]:
    item = evidence()
    if output is None:
        output = draft(item.evidence_id)
    memory = Memory(item)
    memory.serialize_once = serialize_once
    client = Client(output)
    counts = {"embedding": 0, "ccloud": 0}

    async def embed(_: str, **__: object) -> tuple[float, ...]:
        counts["embedding"] += 1
        return (0.0,) * EMBEDDING_DIMENSIONS

    async def capture(*, purpose: str) -> ToolEvidence:
        counts["ccloud"] += 1
        assert purpose == "runtime"
        return item

    monkeypatch.setattr(agent, "_MEMORY", memory)
    monkeypatch.setattr(agent, "_EMBED", embed)
    monkeypatch.setattr(agent, "_CAPTURE", capture)
    monkeypatch.setattr(agent, "_CLIENT_FACTORY", lambda _: client)
    monkeypatch.setenv("OPENAI_API_KEY", "unit-only")
    result = await process_task(
        "Create the bounded report",
        request_id=str(uuid4()),
        agent_id="unit-agent",
        session_id="unit-session",
        requester_ref="human:unit",
        config=config(),
    )
    return result, memory, client, counts


@pytest.mark.asyncio
async def test_process_task_persists_proposal_and_gate_result_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, memory, client, counts = await run(monkeypatch, None)
    assert isinstance(result, AgentResult)
    assert result.proposal_id == memory.proposals[0].proposal_id
    assert result.evaluation_id == memory.evaluations[0].evaluation_id
    assert result.trace_digest == result.check_result.trace_digest
    assert len(result.trace_digest) == 64
    assert result.profile_version == agent.PROFILE_VERSION
    assert counts == {"embedding": 1, "ccloud": 1}
    assert client.responses.calls == 1
    assert memory.retry_attempts == 1
    assert len(memory.proposals) == len(memory.evaluations) == 1


@pytest.mark.asyncio
async def test_authority_field_and_unknown_evidence_fail_before_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, memory, _, _ = await run(
        monkeypatch,
        draft("not-allowlisted", parameters='{"verdict":"YES"}'),
    )
    assert isinstance(result, AgentBlockedResult)
    assert result.stage == "OPENAI"
    assert memory.proposals == memory.evaluations == []


@pytest.mark.asyncio
async def test_persistence_retry_never_repeats_external_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, memory, client, counts = await run(monkeypatch, None, serialize_once=True)
    assert isinstance(result, AgentResult)
    assert counts == {"embedding": 1, "ccloud": 1}
    assert client.responses.calls == 1
    assert memory.tool_appends == 1


@pytest.mark.asyncio
async def test_incomplete_model_response_fails_without_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, memory, _, _ = await run(monkeypatch, None)
    assert isinstance(result, AgentResult)
    memory.proposals.clear()
    memory.evaluations.clear()
    client = Client(None)
    monkeypatch.setattr(agent, "_CLIENT_FACTORY", lambda _: client)
    blocked = await process_task(
        "Create the bounded report",
        request_id=str(uuid4()),
        agent_id="unit-agent",
        session_id="unit-session",
        requester_ref="human:unit",
        config=config(),
    )
    assert isinstance(blocked, AgentBlockedResult)
    assert blocked.stage == "OPENAI"
    assert memory.proposals == memory.evaluations == []


@pytest.mark.asyncio
async def test_invalid_request_id_stops_before_any_external_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    touched = False

    async def forbidden(*_: object, **__: object) -> object:
        nonlocal touched
        touched = True
        raise AssertionError

    monkeypatch.setattr(agent, "_EMBED", forbidden)
    result = await process_task(
        "task",
        request_id="not-a-uuid",
        agent_id="agent",
        session_id="session",
        requester_ref="human:test",
        config=config(),
    )
    assert isinstance(result, AgentBlockedResult)
    assert result.stage == "INPUT"
    assert not touched


def test_config_rejects_alias_wrong_sdk_and_gate_digest() -> None:
    base = config()
    for replacement in (
        {"model_snapshot": "gpt-4.1-mini"},
        {"openai_sdk_version": "0.0.0"},
        {"gate_config_digest": "0" * 64},
    ):
        values = {field.name: getattr(base, field.name) for field in fields(base)}
        values.update(replacement)
        with pytest.raises(ValueError):
            AgentConfig(**values)


def test_schema_forbids_model_authority_fields() -> None:
    item = evidence()
    with pytest.raises(ValidationError):
        ProposalDraftSchema.model_validate(draft(item.evidence_id, verdict="YES"))


def test_openai_strict_schema_has_only_concrete_closed_types() -> None:
    schema = to_strict_json_schema(ProposalDraftSchema)

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            assert value
            if value.get("type") == "object":
                properties = value.get("properties")
                assert isinstance(properties, dict)
                assert value.get("additionalProperties") is False
                assert set(value.get("required", ())) == set(properties)
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    inspect(schema)
    rendered = str(schema)
    assert "Any" not in rendered


def test_json_text_fields_reject_unstructured_values_and_non_object_parameters() -> (
    None
):
    item = evidence()
    for field in ("predicted_outcome", "parameters", "impact_assessment"):
        with pytest.raises(ValidationError):
            ProposalDraftSchema.model_validate(draft(item.evidence_id, **{field: {}}))
    parsed = ProposalDraftSchema.model_validate(
        draft(item.evidence_id, parameters='["not","an","object"]')
    )
    with pytest.raises(agent.AgentContractError, match="parameters"):
        agent._draft(parsed, frozenset({item.evidence_id}))
