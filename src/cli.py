"""Local human review, decision, execution, and history CLI."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn, cast
from uuid import UUID, uuid4

from src.config import AppDbConfig
from src.consequences import reevaluate_with_consequence, report_consequence
from src.executor import (
    ExecutionBlocked,
    ExecutorConfig,
    ExecutorMemory,
    decision_digest,
    execute_approved_demo_value,
)
from src.memory import AppMemory, Connection, MemoryConflictError, MemoryIntegrityError
from src.models import (
    CheckResult,
    DecisionRecord,
    DecisionValue,
    DemoExecutionCommand,
    ExclusionRef,
    ReducerTraceStep,
)
from src.traces import canonical_sha256, validate_check_result

ADVISORY = "GATE VERDICT IS ADVISORY TO THE HUMAN DECISION."
EXPLICIT_EXECUTE = "APPROVE DOES NOT EXECUTE. USE THE EXPLICIT EXECUTE COMMAND."
_HEX = re.compile(r"^[0-9a-f]{64}$")


class CliBlocked(RuntimeError):
    """A safe human-CLI binding failure."""


def _blocked(message: str) -> NoReturn:
    raise CliBlocked(message)


def _uuid(value: str, name: str) -> str:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise CliBlocked(f"{name} is invalid") from error
    if str(parsed) != value:
        _blocked(f"{name} is invalid")
    return value


def _digest(value: str, name: str) -> str:
    if _HEX.fullmatch(value) is None:
        _blocked(f"{name} is invalid")
    return value


def _text(value: str, name: str, maximum: int = 4096) -> str:
    if not value or value != value.strip() or len(value.encode("utf-8")) > maximum:
        _blocked(f"{name} is invalid")
    return value


def _conditions(value: object) -> str:
    if isinstance(value, str):
        parsed = json.loads(value)
    else:
        parsed = value
    if not isinstance(parsed, dict):
        _blocked("decision conditions are invalid")
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def _decision_from_row(row: Mapping[str, Any]) -> DecisionRecord:
    record = DecisionRecord(
        str(row["decision_id"]),
        str(row["proposal_id"]),
        str(row["evaluation_id"]),
        str(row["evaluation_trace_digest"]),
        DecisionValue(str(row["decision"])),
        str(row["decided_by"]),
        str(row["rationale"]),
        _conditions(row["conditions"]),
        str(row["decision_digest"]),
        str(row["decision_idempotency_key"]),
    )
    if record.decision_digest != decision_digest(record):
        _blocked("stored decision digest mismatch")
    return record


def _exclusion_digest(value: ExclusionRef) -> str:
    return canonical_sha256(
        {
            "schema": "gam.exclusion.v1",
            "action_type": value.action_type,
            "action_type_key": value.action_type_key,
            "target": value.target,
            "target_key": value.target_key,
            "reason": value.reason,
            "source_proposal_id": value.source_proposal_id,
            "source_evaluation_id": value.source_evaluation_id,
            "source_evaluation_trace_digest": value.source_evaluation_trace_digest,
            "source_decision_id": value.source_decision_id,
            "source_decision_value": value.source_decision_value,
            "source_decision_digest": value.source_decision_digest,
            "idempotency_key": value.idempotency_key,
        }
    )


class DeciderMemory:
    """Append-only human decision adapter over AppMemory transactions."""

    def __init__(self, memory: AppMemory) -> None:
        self.memory = memory

    async def exact_evaluation(
        self, proposal_id: str, evaluation_id: str, trace_digest: str
    ) -> tuple[object, CheckResult]:
        _uuid(proposal_id, "proposal_id")
        _uuid(evaluation_id, "evaluation_id")
        _digest(trace_digest, "trace_digest")
        proposal = await self.memory.get_proposal(proposal_id)
        result = await self.memory.get_evaluation(evaluation_id)
        if not isinstance(result, CheckResult):
            _blocked("evaluation is not finalized")
        validate_check_result(result)
        if result.evaluation_id != evaluation_id or result.trace_digest != trace_digest:
            _blocked("evaluation digest binding mismatch")
        async with self.memory.transaction() as connection:
            latest = await connection.fetchrow(
                """
SELECT id, trace_digest FROM gate_evaluations
WHERE proposal_id=$1::UUID AND status='FINALIZED'
ORDER BY created_at DESC, id DESC LIMIT 1
""",
                proposal_id,
            )
            if (
                latest is None
                or str(latest["id"]) != evaluation_id
                or str(latest["trace_digest"]) != trace_digest
            ):
                _blocked("evaluation is stale or superseded")
        return proposal, result

    async def append_decision(
        self,
        *,
        proposal_id: str,
        evaluation_id: str,
        trace_digest: str,
        decision: DecisionValue,
        decided_by: str,
        rationale: str,
        idempotency_key: str,
        exclusion_requested: bool,
    ) -> tuple[DecisionRecord, ExclusionRef | None]:
        if exclusion_requested and decision is not DecisionValue.REJECT:
            _blocked("only REJECT may request an exclusion")
        _uuid(idempotency_key, "idempotency_key")
        _text(decided_by, "decided_by", 256)
        _text(rationale, "rationale")
        proposal, evaluation = await self.exact_evaluation(
            proposal_id, evaluation_id, trace_digest
        )

        async def operation(
            connection: Connection,
        ) -> tuple[DecisionRecord, ExclusionRef | None]:
            replay = await connection.fetchrow(
                """
SELECT id AS decision_id, *, idempotency_key AS decision_idempotency_key
FROM decisions WHERE idempotency_key=$1
""",
                idempotency_key,
            )
            if replay is not None:
                existing = _decision_from_row(replay)
                if (
                    existing.proposal_id != proposal_id
                    or existing.evaluation_id != evaluation_id
                    or existing.evaluation_trace_digest != trace_digest
                    or existing.decision is not decision
                    or existing.decided_by != decided_by
                    or existing.rationale != rationale
                ):
                    raise MemoryConflictError("decision idempotency key conflicts")
                exclusion = await self._load_exclusion(connection, existing)
                if exclusion_requested != (exclusion is not None):
                    raise MemoryConflictError("decision exclusion replay conflicts")
                return existing, exclusion
            prior = await connection.fetchrow(
                "SELECT id FROM decisions WHERE proposal_id=$1::UUID",
                proposal_id,
            )
            if prior is not None:
                _blocked("proposal already has a terminal decision")
            provisional = DecisionRecord(
                str(uuid4()),
                proposal_id,
                evaluation_id,
                trace_digest,
                decision,
                decided_by,
                rationale,
                "{}",
                "0" * 64,
                idempotency_key,
            )
            record = replace(provisional, decision_digest=decision_digest(provisional))
            await connection.execute(
                """
INSERT INTO decisions (
 id,proposal_id,evaluation_id,evaluation_trace_digest,decision,decided_by,
 rationale,conditions,decision_digest,idempotency_key
) VALUES ($1::UUID,$2::UUID,$3::UUID,$4,$5,$6,$7,$8::JSONB,$9,$10)
""",
                record.decision_id,
                record.proposal_id,
                record.evaluation_id,
                record.evaluation_trace_digest,
                record.decision.value,
                record.decided_by,
                record.rationale,
                record.conditions_json,
                record.decision_digest,
                record.idempotency_key,
            )
            exclusion = None
            if exclusion_requested:
                exclusion = await self._append_exclusion(
                    connection, cast(Any, proposal), record
                )
            return record, exclusion

        return cast(
            tuple[DecisionRecord, ExclusionRef | None],
            await self.memory._retry(operation),  # noqa: SLF001
        )

    async def _append_exclusion(
        self, connection: Connection, proposal: Any, decision: DecisionRecord
    ) -> ExclusionRef:
        key = (
            "exclude:"
            + hashlib.sha256(
                ("gam.exclusion-idempotency.v1\0" + decision.idempotency_key).encode()
            ).hexdigest()
        )
        provisional = ExclusionRef(
            str(uuid4()),
            proposal.action_type,
            proposal.action_type_key,
            proposal.target,
            proposal.target_key,
            decision.rationale,
            decision.proposal_id,
            decision.evaluation_id,
            decision.evaluation_trace_digest,
            decision.decision_id,
            DecisionValue.REJECT,
            decision.decision_digest,
            "0" * 64,
            key,
        )
        exclusion = replace(
            provisional, exclusion_digest=_exclusion_digest(provisional)
        )
        await connection.execute(
            """
INSERT INTO exclusions (
 id,action_type,action_type_key,target,target_key,reason,source_proposal_id,
 source_evaluation_id,source_evaluation_trace_digest,source_decision_id,
 source_decision_digest,exclusion_digest,idempotency_key
) VALUES ($1::UUID,$2,$3,$4,$5,$6,$7::UUID,$8::UUID,$9,$10::UUID,$11,$12,$13)
""",
            exclusion.exclusion_id,
            exclusion.action_type,
            exclusion.action_type_key,
            exclusion.target,
            exclusion.target_key,
            exclusion.reason,
            exclusion.source_proposal_id,
            exclusion.source_evaluation_id,
            exclusion.source_evaluation_trace_digest,
            exclusion.source_decision_id,
            exclusion.source_decision_digest,
            exclusion.exclusion_digest,
            exclusion.idempotency_key,
        )
        return exclusion

    async def _load_exclusion(
        self, connection: Connection, decision: DecisionRecord
    ) -> ExclusionRef | None:
        row = await connection.fetchrow(
            "SELECT * FROM exclusions WHERE source_decision_id=$1::UUID",
            decision.decision_id,
        )
        if row is None:
            return None
        result = ExclusionRef(
            str(row["id"]),
            str(row["action_type"]),
            str(row["action_type_key"]),
            str(row["target"]),
            str(row["target_key"]),
            str(row["reason"]),
            str(row["source_proposal_id"]),
            str(row["source_evaluation_id"]),
            str(row["source_evaluation_trace_digest"]),
            str(row["source_decision_id"]),
            DecisionValue(str(row["source_decision_value"])),
            str(row["source_decision_digest"]),
            str(row["exclusion_digest"]),
            str(row["idempotency_key"]),
        )
        if result.exclusion_digest != _exclusion_digest(result):
            _blocked("stored exclusion digest mismatch")
        return result


def _decider() -> DeciderMemory:
    url = os.environ.get("DATABASE_URL_DECIDER")
    if not url:
        _blocked("DATABASE_URL_DECIDER is not configured")
    return DeciderMemory(AppMemory(AppDbConfig(url)))


def render_review(proposal: Any, result: CheckResult) -> str:
    lines = [
        f"proposal_id={proposal.proposal_id}",
        f"evaluation_id={result.evaluation_id}",
        f"trace_digest={result.trace_digest}",
        f"verdict={result.verdict.name}",
        f"risk={result.risk.value}",
        "operator_trace:",
    ]
    for step in result.operator_trace:
        evidence = () if isinstance(step, ReducerTraceStep) else step.evidence_refs
        lines.append(
            "  "
            + " | ".join(
                (
                    step.step_id,
                    step.rule_id,
                    step.family.value,
                    step.pole,
                    step.result_json,
                    ",".join(item.ref_id for item in evidence),
                )
            )
        )
    lines.append("evidence_gaps:")
    for gap in result.evidence_gaps:
        lines.append(
            "  "
            + " | ".join(
                (
                    gap.witness.name.replace("FOR_WHAT", "FOR-WHAT"),
                    gap.gap_id,
                    gap.question,
                    gap.needed,
                    gap.resolution_rule_id,
                )
            )
        )
    lines.extend(
        (
            "dependencies="
            + json.dumps([item.dependency_id for item in result.dependencies]),
            "precedent_refs=" + json.dumps(result.precedent_refs),
            "consequence_warning_refs=" + json.dumps(result.consequence_warning_refs),
            f"because_step_id={result.because_step_id}",
            ADVISORY,
            EXPLICIT_EXECUTE,
        )
    )
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python -m src")
    commands = root.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show")
    _evaluation_arguments(show)
    decide = commands.add_parser("decide")
    _evaluation_arguments(decide)
    decide.add_argument(
        "--decision", choices=[item.value for item in DecisionValue], required=True
    )
    decide.add_argument("--decided-by", required=True)
    decide.add_argument("--rationale", required=True)
    decide.add_argument("--idempotency-key", required=True)
    decide.add_argument("--exclude", action="store_true")
    execute = commands.add_parser("execute")
    execute.add_argument("--decision-id", required=True)
    execute.add_argument("--idempotency-key", required=True)
    consequence = commands.add_parser("consequence")
    consequence.add_argument("--receipt-id", required=True)
    consequence.add_argument("--actual-outcome-file", required=True)
    consequence.add_argument("--reported-by", required=True)
    consequence.add_argument("--idempotency-key", required=True)
    reevaluate = commands.add_parser("reevaluate")
    reevaluate.add_argument("--proposal-id", required=True)
    reevaluate.add_argument("--consequence-id", required=True)
    reevaluate.add_argument("--requested-by", required=True)
    history = commands.add_parser("history")
    history.add_argument("--proposal-id", required=True)
    return root


def _evaluation_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--proposal-id", required=True)
    command.add_argument("--evaluation-id", required=True)
    command.add_argument("--trace-digest", required=True)


async def run(arguments: argparse.Namespace) -> str:
    if arguments.command == "show":
        proposal, result = await _decider().exact_evaluation(
            arguments.proposal_id, arguments.evaluation_id, arguments.trace_digest
        )
        return render_review(proposal, result)
    if arguments.command == "decide":
        record, exclusion = await _decider().append_decision(
            proposal_id=arguments.proposal_id,
            evaluation_id=arguments.evaluation_id,
            trace_digest=arguments.trace_digest,
            decision=DecisionValue(arguments.decision),
            decided_by=arguments.decided_by,
            rationale=arguments.rationale,
            idempotency_key=arguments.idempotency_key,
            exclusion_requested=arguments.exclude,
        )
        return (
            json.dumps(
                {
                    "decision_id": record.decision_id,
                    "decision": record.decision.value,
                    "decision_digest": record.decision_digest,
                    "exclusion_id": exclusion.exclusion_id if exclusion else None,
                    "executed": False,
                },
                sort_keys=True,
            )
            + "\n"
            + EXPLICIT_EXECUTE
        )
    if arguments.command == "execute":
        _uuid(arguments.decision_id, "decision_id")
        _uuid(arguments.idempotency_key, "idempotency_key")
        config = ExecutorConfig.from_env()
        memory = ExecutorMemory(config)
        executor_id = await memory.verified_executor_id()
        import src.executor as executor_module

        executor_module._EXECUTOR_MEMORY = memory  # noqa: SLF001
        receipt = await execute_approved_demo_value(
            DemoExecutionCommand(
                arguments.decision_id, executor_id, arguments.idempotency_key
            )
        )
        return json.dumps(
            {
                "receipt_id": receipt.receipt_id,
                "status": receipt.attempt_terminal_status.value,
                "receipt_digest": receipt.receipt_digest,
            },
            sort_keys=True,
        )
    if arguments.command == "consequence":
        path = Path(arguments.actual_outcome_file)
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65_536:
            _blocked("actual outcome file is invalid")
        report = await report_consequence(
            UUID(_uuid(arguments.receipt_id, "receipt_id")),
            1,
            path.read_text(encoding="utf-8"),
            _text(arguments.reported_by, "reported_by", 256),
            _uuid(arguments.idempotency_key, "idempotency_key"),
        )
        return json.dumps(
            {
                "consequence_id": report.consequence_id,
                "report_digest": report.report_digest,
            },
            sort_keys=True,
        )
    if arguments.command == "reevaluate":
        reevaluation = await reevaluate_with_consequence(
            UUID(_uuid(arguments.proposal_id, "proposal_id")),
            UUID(_uuid(arguments.consequence_id, "consequence_id")),
            _text(arguments.requested_by, "requested_by", 256),
        )
        return json.dumps(
            {
                "evaluation_id": reevaluation.evaluation_id,
                "trace_digest": reevaluation.trace_digest,
            },
            sort_keys=True,
        )
    if arguments.command == "history":
        proposal_id = _uuid(arguments.proposal_id, "proposal_id")
        history_memory = _decider().memory
        proposal = await history_memory.get_proposal(proposal_id)
        evaluations = await history_memory.list_evaluations(proposal_id)
        async with history_memory.transaction() as connection:
            decisions = await connection.fetch(
                "SELECT id,decision,decision_digest,created_at FROM decisions "
                "WHERE proposal_id=$1::UUID ORDER BY created_at,id",
                proposal_id,
            )
            attempts = await connection.fetch(
                "SELECT id,terminal_status,attempt_digest,created_at "
                "FROM execution_attempts WHERE proposal_id=$1::UUID "
                "ORDER BY created_at,id",
                proposal_id,
            )
            receipts = await connection.fetch(
                "SELECT id,attempt_terminal_status,receipt_digest,created_at "
                "FROM execution_receipts WHERE proposal_id=$1::UUID "
                "ORDER BY created_at,id",
                proposal_id,
            )
            consequences = await connection.fetch(
                "SELECT id,report_digest,created_at FROM consequence_reports "
                "WHERE proposal_id=$1::UUID ORDER BY created_at,id",
                proposal_id,
            )
        return json.dumps(
            {
                "proposal_id": proposal.proposal_id,
                "evaluations": [
                    {
                        "evaluation_id": item.evaluation_id,
                        "trace_digest": item.trace_digest,
                    }
                    for item in evaluations
                ],
                "decisions": [dict(item) for item in decisions],
                "attempts": [dict(item) for item in attempts],
                "receipts": [dict(item) for item in receipts],
                "consequences": [dict(item) for item in consequences],
            },
            default=str,
            sort_keys=True,
        )
    _blocked("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        output = asyncio.run(run(parser().parse_args(argv)))
    except (CliBlocked, ExecutionBlocked, MemoryIntegrityError, ValueError, OSError):
        print("BLOCKED")
        return 1
    print(output)
    return 0


__all__ = [
    "ADVISORY",
    "CliBlocked",
    "DeciderMemory",
    "main",
    "parser",
    "render_review",
    "run",
]
