"""Exact public verdict, risk, operator, and witness identities."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src.operators import ALLOWED_POLES, OperatorFamily
from src.verdict import Risk, Verdict
from src.witnesses import Witness

ROOT = Path(__file__).parents[2]


def test_exact_verdict_and_risk_identities() -> None:
    assert {item.name: item.value for item in Verdict} == {
        "NO": 0,
        "YES": 1,
        "MAYBE": 2,
        "IFF": 3,
    }
    assert tuple(item.value for item in Risk) == ("LOW", "MEDIUM", "HIGH")


def test_exact_active_operator_families_and_poles() -> None:
    assert tuple(item.value for item in OperatorFamily) == (
        "THIS",
        "SAME/NOT-SAME",
        "IF/THEN",
        "BECAUSE",
        "INSIDE/OUTSIDE",
        "NEAR/FAR",
        "CAN/CANNOT",
        "TOGETHER/ALONE",
        "MORE/LESS",
        "EVERY/SOME",
    )
    assert set(ALLOWED_POLES) == set(OperatorFamily)
    assert ALLOWED_POLES[OperatorFamily.BECAUSE] == ("BECAUSE",)
    with pytest.raises(TypeError):
        ALLOWED_POLES[OperatorFamily.THIS] = ("OTHER",)  # type: ignore[index]
    assert not hasattr(OperatorFamily, "NO")
    assert not hasattr(OperatorFamily, "MAYBE")


def test_exact_witness_values() -> None:
    assert tuple(item.value for item in Witness) == (
        "WHAT",
        "WHERE",
        "WHICH",
        "WHEN",
        "FOR-WHAT",
        "HOW",
        "WHENCE",
    )
    assert Witness.FOR_WHAT.value == "FOR-WHAT"


def test_production_does_not_reduce_verdicts_numerically() -> None:
    forbidden_calls = {"min", "max", "sorted", "sum"}

    def mentions_verdict(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Name) and child.id == "Verdict"
            for child in ast.walk(node)
        )

    for relative in ("src/traces.py", "src/models.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert not (node.func.id in forbidden_calls and mentions_verdict(node))
            if isinstance(node, ast.BinOp) and mentions_verdict(node):
                assert not isinstance(
                    node.op,
                    (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod),
                )
