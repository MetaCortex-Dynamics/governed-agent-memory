"""Allowlisted, append-only demo effect executor."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, NoReturn, cast
from uuid import UUID, uuid4

from src.config import AppDbConfig, ConfigError
from src.governance import proposal_action_digest, proposal_record_digest
from src.memory import AppMemory, Connection, MemoryIntegrityError
from src.models import (
    CheckResult,
    DecisionRecord,
    DecisionValue,
    DemoExecutionCommand,
    ExecutionAttempt,
    ExecutionReceipt,
    ExecutionStatus,
    Proposal,
)
from src.traces import canonical_sha256, validate_check_result

_HEX = re.compile(r"^[0-9a-f]{64}$")
_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ZERO = "0" * 64


class ExecutionBlocked(RuntimeError):
    """A safe precondition, authority, or recovery failure."""


@dataclass(frozen=True, slots=True)
class _FailedEffect:
    command: DemoExecutionCommand
    proposal: Proposal
    evaluation: CheckResult
    decision: DecisionRecord
    effect_key: str
    value_json: str
    before: str


class _ProvenRollback(RuntimeError):
    def __init__(self, context: _FailedEffect) -> None:
        super().__init__("effect transaction was rolled back")
        self.context = context


def _blocked(message: str) -> NoReturn:
    raise ExecutionBlocked(message)


def _uuid(value: str, name: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ExecutionBlocked(f"{name} is invalid") from error
    if str(parsed) != value:
        _blocked(f"{name} is invalid")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _json_scalar(text: str) -> tuple[object, str]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                _blocked("parameters contain a duplicate key")
            result[key] = value
        return result

    try:
        parameters = json.loads(
            text,
            parse_float=Decimal,
            parse_int=Decimal,
            parse_constant=lambda _: _blocked("parameters contain a non-finite value"),
            object_pairs_hook=pairs,
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ExecutionBlocked("parameters are not canonical JSON") from error
    if not isinstance(parameters, dict) or set(parameters) != {"value"}:
        _blocked("parameters must contain exactly value")
    value = parameters["value"]
    if isinstance(value, (dict, list)):
        _blocked("demo value must be a JSON scalar")
    if isinstance(value, Decimal) and not value.is_finite():
        _blocked("demo value must be finite")
    canonical = _plain_json(value)
    if len(canonical.encode("utf-8")) > 256:
        _blocked("demo value exceeds its byte limit")
    if text != '{"value":' + canonical + "}":
        _blocked("parameters are not canonical JSON")
    return value, canonical


def _plain_json(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, Decimal):
        if not value.is_finite():
            _blocked("JSON number is non-finite")
        if value.is_zero():
            return "0"
        text = format(value.normalize(), "f")
        return text.rstrip("0").rstrip(".") if "." in text else text
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    _blocked("value is not a JSON scalar")


def decision_digest(decision: DecisionRecord) -> str:
    return canonical_sha256(
        {
            "schema": "gam.decision.v1",
            "proposal_id": decision.proposal_id,
            "evaluation_id": decision.evaluation_id,
            "evaluation_trace_digest": decision.evaluation_trace_digest,
            "decision": decision.decision,
            "decided_by": decision.decided_by,
            "rationale": decision.rationale,
            "conditions": decision.conditions_json,
            "idempotency_key": decision.idempotency_key,
        }
    )


def attempt_digest(attempt: ExecutionAttempt) -> str:
    return canonical_sha256(
        {
            "schema": "gam.execution-attempt.v1",
            "proposal_id": attempt.proposal_id,
            "evaluation_id": attempt.evaluation_id,
            "evaluation_trace_digest": attempt.evaluation_trace_digest,
            "decision_id": attempt.decision_id,
            "decision_value": attempt.decision_value,
            "decision_digest": attempt.decision_digest,
            "action_type_key": attempt.action_type_key,
            "action_digest": attempt.action_digest,
            "target_key": attempt.target_key,
            "effect_key": attempt.effect_key,
            "requested_value": attempt.requested_value_json,
            "started_at": attempt.started_at,
            "finished_at": attempt.finished_at,
            "terminal_status": attempt.terminal_status,
            "demo_effect_id": attempt.demo_effect_id,
            "before_effect_digest": attempt.before_effect_digest,
            "after_effect_digest": attempt.after_effect_digest,
            "observed_effect_version": attempt.observed_effect_version,
            "outcome": attempt.outcome_json,
            "outcome_digest": attempt.outcome_digest,
            "executor_id": attempt.executor_id,
            "idempotency_key": attempt.idempotency_key,
            "error_code": attempt.error_code,
            "safe_message": attempt.safe_message,
        }
    )


def receipt_digest(receipt: ExecutionReceipt) -> str:
    return canonical_sha256(
        {
            "schema": "gam.execution-receipt.v1",
            "attempt_id": receipt.attempt_id,
            "attempt_digest": receipt.attempt_digest,
            "proposal_id": receipt.proposal_id,
            "evaluation_id": receipt.evaluation_id,
            "evaluation_trace_digest": receipt.evaluation_trace_digest,
            "decision_id": receipt.decision_id,
            "decision_digest": receipt.decision_digest,
            "action_digest": receipt.action_digest,
            "attempt_terminal_status": receipt.attempt_terminal_status,
            "target_key": receipt.target_key,
            "outcome_digest": receipt.outcome_digest,
            "before_effect_digest": receipt.before_effect_digest,
            "after_effect_digest": receipt.after_effect_digest,
            "observed_effect_version": receipt.observed_effect_version,
            "executor_id": receipt.executor_id,
            "idempotency_key": receipt.idempotency_key,
            "verified": receipt.verified,
        }
    )


def derive_executor_id(database_principal: str) -> str:
    if not database_principal or database_principal != database_principal.strip():
        _blocked("database principal is invalid")
    return canonical_sha256(
        {
            "schema": "gam.executor-principal.v1",
            "database_principal": database_principal,
        }
    )


class ExecutorConfig:
    """Executor connection plus opaque derived-principal binding."""

    __slots__ = ("database_url", "executor_id")

    def __init__(self, database_url: str, executor_id: str) -> None:
        try:
            AppDbConfig(database_url)
        except ConfigError as error:
            raise ExecutionBlocked(
                "executor database configuration is invalid"
            ) from error
        if _HEX.fullmatch(executor_id) is None:
            _blocked("executor identity binding is invalid")
        self.database_url = database_url
        self.executor_id = executor_id

    @classmethod
    def from_env(cls) -> ExecutorConfig:
        url = os.environ.get("DATABASE_URL_EXECUTOR")
        identity = os.environ.get("EXECUTOR_ID")
        if not url or not identity:
            _blocked("executor environment is incomplete")
        return cls(url, identity)


def _decision(row: Mapping[str, Any]) -> DecisionRecord:
    record = DecisionRecord(
        decision_id=str(row["decision_id"]),
        proposal_id=str(row["proposal_id"]),
        evaluation_id=str(row["evaluation_id"]),
        evaluation_trace_digest=str(row["evaluation_trace_digest"]),
        decision=DecisionValue(str(row["decision"])),
        decided_by=str(row["decided_by"]),
        rationale=str(row["rationale"]),
        conditions_json=_database_json(row["conditions"]),
        decision_digest=str(row["decision_digest"]),
        idempotency_key=str(row["decision_idempotency_key"]),
    )
    if record.decision_digest != decision_digest(record):
        _blocked("decision digest mismatch")
    return record


def _database_json(value: object) -> str:
    if isinstance(value, str):
        parsed = json.loads(value, parse_float=Decimal, parse_int=Decimal)
    else:
        parsed = value
    if isinstance(parsed, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key)}:{_plain_json(item)}"
                for key, item in sorted(parsed.items())
            )
            + "}"
        )
    return _plain_json(parsed)


def _receipt(row: Mapping[str, Any]) -> ExecutionReceipt:
    result = ExecutionReceipt(
        receipt_id=str(row["receipt_id"]),
        attempt_id=str(row["attempt_id"]),
        attempt_digest=str(row["attempt_digest"]),
        proposal_id=str(row["proposal_id"]),
        evaluation_id=str(row["evaluation_id"]),
        evaluation_trace_digest=str(row["evaluation_trace_digest"]),
        decision_id=str(row["decision_id"]),
        decision_value=DecisionValue(str(row["decision_value"])),
        decision_digest=str(row["decision_digest"]),
        action_digest=str(row["action_digest"]),
        target_key=str(row["target_key"]),
        attempt_terminal_status=ExecutionStatus(str(row["attempt_terminal_status"])),
        outcome_digest=str(row["outcome_digest"]),
        before_effect_digest=str(row["before_effect_digest"]),
        after_effect_digest=(
            str(row["after_effect_digest"])
            if row.get("after_effect_digest") is not None
            else None
        ),
        observed_effect_version=(
            int(row["observed_effect_version"])
            if row.get("observed_effect_version") is not None
            else None
        ),
        executor_id=str(row["executor_id"]),
        idempotency_key=str(row["receipt_idempotency_key"]),
        verified=bool(row["verified"]),
        receipt_digest=str(row["receipt_digest"]),
    )
    if not result.verified or result.receipt_digest != receipt_digest(result):
        _blocked("execution receipt digest mismatch")
    return result


class ExecutorMemory:
    """Least-authority execution adapter over AppMemory transactions."""

    def __init__(self, config: ExecutorConfig) -> None:
        self.config = config
        self.memory = AppMemory(AppDbConfig(config.database_url))

    async def verified_executor_id(self) -> str:
        async with self.memory.transaction() as connection:
            principal = await connection.fetchrow("SELECT current_user")
            if principal is None or len(principal) != 1:
                _blocked("executor principal could not be verified")
            derived = derive_executor_id(str(next(iter(principal.values()))))
            if derived != self.config.executor_id:
                _blocked("executor identity binding mismatch")
            return derived

    async def execute_demo_and_record(
        self, command: DemoExecutionCommand
    ) -> ExecutionReceipt:
        _uuid(command.decision_id, "decision_id")
        _uuid(command.idempotency_key, "idempotency_key")
        if command.executor_id != self.config.executor_id:
            _blocked("executor command identity mismatch")

        async def operation(connection: Connection) -> ExecutionReceipt:
            return await self._execute(connection, command)

        try:
            return cast(
                ExecutionReceipt,
                await self.memory._retry(operation),  # noqa: SLF001
            )
        except _ProvenRollback as failure:
            return await self._append_error(failure.context)

    async def _append_error(self, failed: _FailedEffect) -> ExecutionReceipt:
        async def operation(connection: Connection) -> ExecutionReceipt:
            existing = await connection.fetchrow(
                """
SELECT r.id AS receipt_id, r.*, r.idempotency_key AS receipt_idempotency_key
FROM execution_receipts AS r WHERE r.idempotency_key=$1
""",
                failed.command.idempotency_key,
            )
            if existing is not None:
                result = _receipt(existing)
                if (
                    result.decision_id != failed.decision.decision_id
                    or result.attempt_terminal_status is not ExecutionStatus.ERROR
                ):
                    _blocked("ERROR recovery binding conflicts")
                return result
            effect = await connection.fetchrow(
                "SELECT id FROM demo_kv WHERE decision_id=$1::UUID",
                failed.decision.decision_id,
            )
            if effect is not None:
                _blocked("effect commit is ambiguous; ERROR is forbidden")
            return await _append_error_chain(connection, failed)

        return cast(
            ExecutionReceipt,
            await self.memory._retry(operation),  # noqa: SLF001
        )

    async def _execute(
        self, connection: Connection, command: DemoExecutionCommand
    ) -> ExecutionReceipt:
        existing = await connection.fetchrow(
            """
SELECT r.id AS receipt_id, r.*, r.idempotency_key AS receipt_idempotency_key
FROM execution_receipts AS r
WHERE r.idempotency_key = $1 OR r.decision_id = $2::UUID
ORDER BY r.id LIMIT 2
""",
            command.idempotency_key,
            command.decision_id,
        )
        if existing is not None:
            result = _receipt(existing)
            if (
                result.decision_id != command.decision_id
                or result.executor_id != command.executor_id
            ):
                _blocked("execution idempotency binding conflicts")
            return result
        row = await connection.fetchrow(
            """
SELECT d.id AS decision_id, d.*, d.idempotency_key AS decision_idempotency_key,
       g.status AS evaluation_status, g.trace_digest AS stored_trace_digest,
       p.*
FROM decisions AS d
JOIN gate_evaluations AS g ON g.id = d.evaluation_id
JOIN proposals AS p ON p.id = d.proposal_id
WHERE d.id = $1::UUID
FOR UPDATE OF d
""",
            command.decision_id,
        )
        if row is None:
            _blocked("approved decision was not found")
        decision = _decision(row)
        if decision.decision is not DecisionValue.APPROVE:
            _blocked("only APPROVE can authorize execution")
        proposal = await self.memory.get_proposal(decision.proposal_id)
        evaluation = await self.memory.get_evaluation(decision.evaluation_id)
        if not isinstance(evaluation, CheckResult):
            _blocked("decision evaluation is not finalized")
        validate_check_result(evaluation)
        if (
            evaluation.trace_digest != decision.evaluation_trace_digest
            or str(row["evaluation_status"]) != "FINALIZED"
            or str(row["stored_trace_digest"]) != decision.evaluation_trace_digest
            or proposal.proposal_digest != proposal_record_digest(proposal)
            or proposal.action_digest != proposal_action_digest(proposal)
        ):
            _blocked("execution authority binding mismatch")
        effect_key, value_json = _validate_effect(proposal)
        prior = await connection.fetchrow(
            """
SELECT id, effect_version, effect_digest FROM demo_kv
WHERE effect_key = $1 ORDER BY effect_version DESC LIMIT 1 FOR UPDATE
""",
            effect_key,
        )
        version = 1 if prior is None else int(prior["effect_version"]) + 1
        prior_id = None if prior is None else str(prior["id"])
        prior_version = None if prior is None else int(prior["effect_version"])
        before = _ZERO if prior is None else str(prior["effect_digest"])
        effect_id = str(uuid4())
        effect_digest = canonical_sha256(
            {
                "schema": "gam.demo-effect.v1",
                "proposal_id": proposal.proposal_id,
                "evaluation_id": evaluation.evaluation_id,
                "evaluation_trace_digest": evaluation.trace_digest,
                "decision_id": decision.decision_id,
                "decision_digest": decision.decision_digest,
                "action_digest": proposal.action_digest,
                "effect_key": effect_key,
                "effect_version": version,
                "target_key": proposal.target_key,
                "prior_effect_id": prior_id,
                "prior_effect_version": prior_version,
                "before_effect_digest": before,
                "effect_value": value_json,
                "executor_id": command.executor_id,
                "idempotency_key": command.idempotency_key,
            }
        )
        failed = _FailedEffect(
            command,
            proposal,
            evaluation,
            decision,
            effect_key,
            value_json,
            before,
        )
        try:
            await _insert_effect(
                connection,
                failed,
                effect_id,
                version,
                prior_id,
                prior_version,
                effect_digest,
            )
        except Exception as error:
            sqlstate = getattr(error, "sqlstate", None)
            if isinstance(sqlstate, str) and sqlstate != "40001":
                raise _ProvenRollback(failed) from error
            raise
        return await _append_observed(
            connection,
            command,
            proposal,
            evaluation,
            decision,
            effect_key,
            value_json,
            effect_id,
            version,
            before,
            effect_digest,
        )


async def _insert_effect(
    connection: Connection,
    failed: _FailedEffect,
    effect_id: str,
    version: int,
    prior_id: str | None,
    prior_version: int | None,
    effect_digest: str,
) -> None:
    proposal = failed.proposal
    await connection.execute(
        """
INSERT INTO demo_kv (
 id, proposal_id, evaluation_id, evaluation_trace_digest, decision_id,
 decision_digest, target_key, effect_key, effect_version, prior_effect_id,
 prior_effect_version, before_effect_digest, effect_value, effect_digest,
 action_digest, executor_id, idempotency_key
) VALUES ($1::UUID,$2::UUID,$3::UUID,$4,$5::UUID,$6,$7,$8,$9,$10::UUID,
          $11,$12,$13::JSONB,$14,$15,$16,$17)
""",
        effect_id,
        proposal.proposal_id,
        failed.evaluation.evaluation_id,
        failed.evaluation.trace_digest,
        failed.decision.decision_id,
        failed.decision.decision_digest,
        proposal.target_key,
        failed.effect_key,
        version,
        prior_id,
        prior_version,
        failed.before,
        failed.value_json,
        effect_digest,
        proposal.action_digest,
        failed.command.executor_id,
        failed.command.idempotency_key,
    )
    observed = await connection.fetchrow(
        "SELECT effect_version, effect_value::STRING AS effect_value, "
        "effect_digest FROM demo_kv WHERE id=$1::UUID",
        effect_id,
    )
    if (
        observed is None
        or int(observed["effect_version"]) != version
        or _database_json(observed["effect_value"]) != failed.value_json
        or str(observed["effect_digest"]) != effect_digest
    ):
        raise MemoryIntegrityError("effect read-back mismatch")


def _validate_effect(proposal: Proposal) -> tuple[str, str]:
    if (
        proposal.action_type != "SET_DEMO_VALUE"
        or proposal.action_type_key != "set_demo_value"
    ):
        _blocked("proposal action is not allowlisted")
    prefix = "demo_kv:"
    if (
        not proposal.target.startswith(prefix)
        or proposal.target_key != proposal.target.lower()
    ):
        _blocked("demo target binding is invalid")
    key = proposal.target[len(prefix) :]
    if _KEY.fullmatch(key) is None or proposal.target_key != prefix + key:
        _blocked("demo effect key is invalid")
    if len(proposal.target_key.encode("utf-8")) > 256:
        _blocked("demo target exceeds its byte limit")
    _, value_json = _json_scalar(proposal.parameters_json)
    return key, value_json


async def _append_observed(
    connection: Connection,
    command: DemoExecutionCommand,
    proposal: Proposal,
    evaluation: CheckResult,
    decision: DecisionRecord,
    effect_key: str,
    value_json: str,
    effect_id: str,
    version: int,
    before: str,
    after: str,
) -> ExecutionReceipt:
    started = _utc_now()
    finished = _utc_now()
    outcome_json = json.dumps(
        {
            "after_effect_digest": after,
            "before_effect_digest": before,
            "demo_effect_id": effect_id,
            "effect_key": effect_key,
            "observed_effect_version": version,
            "status": "OBSERVED",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    outcome_digest = canonical_sha256(json.loads(outcome_json))
    provisional = ExecutionAttempt(
        str(uuid4()),
        proposal.proposal_id,
        evaluation.evaluation_id,
        evaluation.trace_digest,
        decision.decision_id,
        DecisionValue.APPROVE,
        decision.decision_digest,
        proposal.action_type_key,
        proposal.action_digest,
        proposal.target_key,
        effect_key,
        value_json,
        started,
        finished,
        ExecutionStatus.OBSERVED,
        effect_id,
        before,
        after,
        version,
        outcome_json,
        outcome_digest,
        _ZERO,
        command.executor_id,
        command.idempotency_key,
        None,
        None,
    )
    attempt = replace(provisional, attempt_digest=attempt_digest(provisional))
    await connection.execute(
        """
INSERT INTO execution_attempts (
 id,proposal_id,evaluation_id,evaluation_trace_digest,decision_id,
 decision_digest,action_digest,target_key,effect_key,requested_value,started_at,
 finished_at,terminal_status,demo_effect_id,before_effect_digest,
 after_effect_digest,observed_effect_version,outcome,outcome_digest,
 attempt_digest,executor_id,idempotency_key
) VALUES ($1::UUID,$2::UUID,$3::UUID,$4,$5::UUID,$6,$7,$8,$9,$10::JSONB,
 $11::TIMESTAMPTZ,$12::TIMESTAMPTZ,$13,$14::UUID,$15,$16,$17,$18::JSONB,
 $19,$20,$21,$22)
""",
        attempt.attempt_id,
        attempt.proposal_id,
        attempt.evaluation_id,
        attempt.evaluation_trace_digest,
        attempt.decision_id,
        attempt.decision_digest,
        attempt.action_digest,
        attempt.target_key,
        attempt.effect_key,
        attempt.requested_value_json,
        attempt.started_at,
        attempt.finished_at,
        attempt.terminal_status.value,
        attempt.demo_effect_id,
        attempt.before_effect_digest,
        attempt.after_effect_digest,
        attempt.observed_effect_version,
        attempt.outcome_json,
        attempt.outcome_digest,
        attempt.attempt_digest,
        attempt.executor_id,
        attempt.idempotency_key,
    )
    provisional_receipt = ExecutionReceipt(
        str(uuid4()),
        attempt.attempt_id,
        attempt.attempt_digest,
        attempt.proposal_id,
        attempt.evaluation_id,
        attempt.evaluation_trace_digest,
        attempt.decision_id,
        DecisionValue.APPROVE,
        attempt.decision_digest,
        attempt.action_digest,
        attempt.target_key,
        ExecutionStatus.OBSERVED,
        attempt.outcome_digest,
        before,
        after,
        version,
        attempt.executor_id,
        command.idempotency_key,
        True,
        _ZERO,
    )
    receipt = replace(
        provisional_receipt,
        receipt_digest=receipt_digest(provisional_receipt),
    )
    await connection.execute(
        """
INSERT INTO execution_receipts (
 id,attempt_id,attempt_digest,proposal_id,evaluation_id,
 evaluation_trace_digest,decision_id,decision_digest,action_digest,target_key,
 attempt_terminal_status,outcome_digest,before_effect_digest,
 after_effect_digest,observed_effect_version,executor_id,idempotency_key,
 verified,receipt_digest
) VALUES ($1::UUID,$2::UUID,$3,$4::UUID,$5::UUID,$6,$7::UUID,$8,$9,$10,
 $11,$12,$13,$14,$15,$16,$17,$18,$19)
""",
        receipt.receipt_id,
        receipt.attempt_id,
        receipt.attempt_digest,
        receipt.proposal_id,
        receipt.evaluation_id,
        receipt.evaluation_trace_digest,
        receipt.decision_id,
        receipt.decision_digest,
        receipt.action_digest,
        receipt.target_key,
        receipt.attempt_terminal_status.value,
        receipt.outcome_digest,
        receipt.before_effect_digest,
        receipt.after_effect_digest,
        receipt.observed_effect_version,
        receipt.executor_id,
        receipt.idempotency_key,
        receipt.verified,
        receipt.receipt_digest,
    )
    return receipt


async def _append_error_chain(
    connection: Connection, failed: _FailedEffect
) -> ExecutionReceipt:
    started = _utc_now()
    finished = _utc_now()
    error_code = "EFFECT_TRANSACTION_ROLLED_BACK"
    safe_message = "effect attempt was proven not committed"
    outcome_json = json.dumps(
        {
            "before_effect_digest": failed.before,
            "effect_key": failed.effect_key,
            "error_code": error_code,
            "safe_message": safe_message,
            "status": "ERROR",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    outcome_digest = canonical_sha256(json.loads(outcome_json))
    provisional = ExecutionAttempt(
        str(uuid4()),
        failed.proposal.proposal_id,
        failed.evaluation.evaluation_id,
        failed.evaluation.trace_digest,
        failed.decision.decision_id,
        DecisionValue.APPROVE,
        failed.decision.decision_digest,
        failed.proposal.action_type_key,
        failed.proposal.action_digest,
        failed.proposal.target_key,
        failed.effect_key,
        failed.value_json,
        started,
        finished,
        ExecutionStatus.ERROR,
        None,
        failed.before,
        None,
        None,
        outcome_json,
        outcome_digest,
        _ZERO,
        failed.command.executor_id,
        failed.command.idempotency_key,
        error_code,
        safe_message,
    )
    attempt = replace(provisional, attempt_digest=attempt_digest(provisional))
    await connection.execute(
        """
INSERT INTO execution_attempts (
 id,proposal_id,evaluation_id,evaluation_trace_digest,decision_id,
 decision_digest,action_digest,target_key,effect_key,requested_value,started_at,
 finished_at,terminal_status,demo_effect_id,before_effect_digest,
 after_effect_digest,observed_effect_version,outcome,outcome_digest,
 attempt_digest,executor_id,idempotency_key,error_code,safe_message
) VALUES ($1::UUID,$2::UUID,$3::UUID,$4,$5::UUID,$6,$7,$8,$9,$10::JSONB,
 $11::TIMESTAMPTZ,$12::TIMESTAMPTZ,$13,$14::UUID,$15,$16,$17,$18::JSONB,
 $19,$20,$21,$22,$23,$24)
""",
        attempt.attempt_id,
        attempt.proposal_id,
        attempt.evaluation_id,
        attempt.evaluation_trace_digest,
        attempt.decision_id,
        attempt.decision_digest,
        attempt.action_digest,
        attempt.target_key,
        attempt.effect_key,
        attempt.requested_value_json,
        attempt.started_at,
        attempt.finished_at,
        attempt.terminal_status.value,
        None,
        attempt.before_effect_digest,
        None,
        None,
        attempt.outcome_json,
        attempt.outcome_digest,
        attempt.attempt_digest,
        attempt.executor_id,
        attempt.idempotency_key,
        attempt.error_code,
        attempt.safe_message,
    )
    provisional_receipt = ExecutionReceipt(
        str(uuid4()),
        attempt.attempt_id,
        attempt.attempt_digest,
        attempt.proposal_id,
        attempt.evaluation_id,
        attempt.evaluation_trace_digest,
        attempt.decision_id,
        DecisionValue.APPROVE,
        attempt.decision_digest,
        attempt.action_digest,
        attempt.target_key,
        ExecutionStatus.ERROR,
        attempt.outcome_digest,
        failed.before,
        None,
        None,
        attempt.executor_id,
        failed.command.idempotency_key,
        True,
        _ZERO,
    )
    receipt = replace(
        provisional_receipt,
        receipt_digest=receipt_digest(provisional_receipt),
    )
    await connection.execute(
        """
INSERT INTO execution_receipts (
 id,attempt_id,attempt_digest,proposal_id,evaluation_id,
 evaluation_trace_digest,decision_id,decision_digest,action_digest,target_key,
 attempt_terminal_status,outcome_digest,before_effect_digest,
 after_effect_digest,observed_effect_version,executor_id,idempotency_key,
 verified,receipt_digest
) VALUES ($1::UUID,$2::UUID,$3,$4::UUID,$5::UUID,$6,$7::UUID,$8,$9,$10,
 $11,$12,$13,$14,$15,$16,$17,$18,$19)
""",
        receipt.receipt_id,
        receipt.attempt_id,
        receipt.attempt_digest,
        receipt.proposal_id,
        receipt.evaluation_id,
        receipt.evaluation_trace_digest,
        receipt.decision_id,
        receipt.decision_digest,
        receipt.action_digest,
        receipt.target_key,
        receipt.attempt_terminal_status.value,
        receipt.outcome_digest,
        receipt.before_effect_digest,
        None,
        None,
        receipt.executor_id,
        receipt.idempotency_key,
        receipt.verified,
        receipt.receipt_digest,
    )
    return receipt


_EXECUTOR_MEMORY: ExecutorMemory | None = None


async def execute_approved_demo_value(
    command: DemoExecutionCommand,
) -> ExecutionReceipt:
    """Execute only an exact approved SET_DEMO_VALUE command."""
    global _EXECUTOR_MEMORY
    memory = _EXECUTOR_MEMORY
    if memory is None:
        memory = ExecutorMemory(ExecutorConfig.from_env())
        _EXECUTOR_MEMORY = memory
    if await memory.verified_executor_id() != command.executor_id:
        _blocked("executor identity changed before execution")
    return await memory.execute_demo_and_record(command)


__all__ = [
    "ExecutionBlocked",
    "ExecutorConfig",
    "ExecutorMemory",
    "attempt_digest",
    "decision_digest",
    "derive_executor_id",
    "execute_approved_demo_value",
    "receipt_digest",
]
