from __future__ import annotations

from dataclasses import dataclass
from math import nan
from typing import Any

import pytest

from src.config import EmbeddingConfig
from src.embeddings import (
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
    EmbeddingError,
    embed_many,
    embed_one,
    embedding_input_digest,
    embedding_output_digest,
)


@dataclass
class Item:
    index: int
    embedding: list[float]


@dataclass
class Response:
    data: list[Item]


class Endpoint:
    def __init__(self, response: Response | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    async def create(
        self, *, model: str, input: list[str], dimensions: int
    ) -> Response:
        self.calls.append({"model": model, "input": input, "dimensions": dimensions})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class Client:
    def __init__(self, response: Response | Exception) -> None:
        self.embeddings = Endpoint(response)


def vector(value: float = 0.0) -> list[float]:
    return [value] * EMBEDDING_DIMENSIONS


def config() -> EmbeddingConfig:
    return EmbeddingConfig("unit-only-value")


@pytest.mark.asyncio
async def test_embed_one_uses_exact_model_dimensions_and_input() -> None:
    client = Client(Response([Item(0, vector(0.25))]))
    result = await embed_one("task", config=config(), client=client)
    assert result == tuple(vector(0.25))
    assert client.embeddings.calls == [
        {"model": EMBEDDING_MODEL, "input": ["task"], "dimensions": 1536}
    ]


@pytest.mark.asyncio
async def test_embed_many_preserves_cardinality_and_order() -> None:
    client = Client(Response([Item(0, vector(0.1)), Item(1, vector(0.2))]))
    result = await embed_many(("first", "second"), config=config(), client=client)
    assert result[0][0] == 0.1
    assert result[1][0] == 0.2


@pytest.mark.parametrize("texts", ((), ("",), (" padded ",)))
@pytest.mark.asyncio
async def test_empty_or_padded_inputs_are_rejected(texts: tuple[str, ...]) -> None:
    with pytest.raises(EmbeddingError):
        await embed_many(texts, config=config(), client=Client(Response([])))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "items",
    (
        [],
        [Item(0, [0.0])],
        [Item(1, vector())],
        [Item(0, vector(nan))],
        [Item(0, ["0"] * EMBEDDING_DIMENSIONS)],  # type: ignore[list-item]
        [Item(0, [True] * EMBEDDING_DIMENSIONS)],
    ),
)
async def test_response_cardinality_order_dimensions_and_finiteness(
    items: list[Item],
) -> None:
    with pytest.raises(EmbeddingError):
        await embed_one("task", config=config(), client=Client(Response(items)))


@pytest.mark.asyncio
async def test_transport_error_is_redacted() -> None:
    marker = "unit-sensitive-marker"
    with pytest.raises(EmbeddingError) as captured:
        await embed_one("task", config=config(), client=Client(RuntimeError(marker)))
    assert marker not in str(captured.value)


def test_input_and_output_digests_are_deterministic_and_bound() -> None:
    texts = ("first", "second")
    vectors = (tuple(vector(0.1)), tuple(vector(0.2)))
    assert embedding_input_digest(texts) == embedding_input_digest(texts)
    assert embedding_input_digest(texts) != embedding_input_digest(
        tuple(reversed(texts))
    )
    assert embedding_output_digest(texts, vectors) == embedding_output_digest(
        texts, vectors
    )
    changed = (vectors[0], tuple(vector(0.3)))
    assert embedding_output_digest(texts, vectors) != embedding_output_digest(
        texts, changed
    )


@pytest.mark.asyncio
async def test_nfc_input_is_the_exact_transmitted_and_digested_value() -> None:
    client = Client(Response([Item(0, vector())]))
    await embed_one("e\u0301", config=config(), client=client)
    assert client.embeddings.calls[0]["input"] == ["é"]
    assert embedding_input_digest(("e\u0301",)) == embedding_input_digest(("é",))


def test_credential_does_not_affect_digests_or_representation() -> None:
    first = EmbeddingConfig("first-unit-value")
    second = EmbeddingConfig("second-unit-value")
    assert first.config_digest == second.config_digest
    assert "first-unit-value" not in repr(first)
