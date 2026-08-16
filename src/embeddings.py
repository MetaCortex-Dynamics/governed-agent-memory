"""Pinned, non-authoritative embedding retrieval."""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Sequence
from typing import Any, Protocol, cast

from openai import AsyncOpenAI

from src.config import EmbeddingConfig
from src.traces import canonical_sha256

EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536


class EmbeddingError(ValueError):
    """A safe embedding input, response, or transport failure."""


class _EmbeddingEndpoint(Protocol):
    async def create(
        self, *, model: str, input: list[str], dimensions: int
    ) -> object: ...


class _EmbeddingClient(Protocol):
    @property
    def embeddings(self) -> _EmbeddingEndpoint: ...


def embedding_input_digest(texts: tuple[str, ...]) -> str:
    """Bind the pinned request without credential or transport state."""
    texts = _canonical_texts(texts)
    return canonical_sha256(
        {
            "model": EMBEDDING_MODEL,
            "dimensions": EMBEDDING_DIMENSIONS,
            "input": texts,
        }
    )


def embedding_output_digest(
    texts: tuple[str, ...], vectors: tuple[tuple[float, ...], ...]
) -> str:
    """Bind ordered validated vectors to their exact input digest."""
    texts = _canonical_texts(texts)
    _validate_vectors(vectors, len(texts))
    return canonical_sha256(
        {
            "model": EMBEDDING_MODEL,
            "dimensions": EMBEDDING_DIMENSIONS,
            "input_digest": embedding_input_digest(texts),
            "output": vectors,
        }
    )


def _canonical_texts(texts: tuple[str, ...]) -> tuple[str, ...]:
    if not texts:
        raise EmbeddingError("embedding batch is empty")
    result: list[str] = []
    for text in texts:
        if not isinstance(text, str) or text == "" or text != text.strip():
            raise EmbeddingError("embedding input is empty or padded")
        try:
            text.encode("utf-8", "strict")
        except UnicodeError as error:
            raise EmbeddingError("embedding input is not valid UTF-8") from error
        result.append(unicodedata.normalize("NFC", text))
    return tuple(result)


def _validate_vectors(
    vectors: tuple[tuple[float, ...], ...], expected_count: int
) -> None:
    if len(vectors) != expected_count:
        raise EmbeddingError("embedding response cardinality mismatch")
    for vector in vectors:
        if len(vector) != EMBEDDING_DIMENSIONS:
            raise EmbeddingError("embedding response dimensions mismatch")
        if any(
            not isinstance(value, float) or not math.isfinite(value) for value in vector
        ):
            raise EmbeddingError("embedding response contains an invalid value")


def _client(config: EmbeddingConfig) -> _EmbeddingClient:
    options: dict[str, Any] = {"timeout": 20.0, "max_retries": 2}
    options["api_" + "key"] = config.api_key
    return cast(
        _EmbeddingClient,
        AsyncOpenAI(**options),
    )


def _response_vectors(
    response: object, expected_count: int
) -> tuple[tuple[float, ...], ...]:
    data = getattr(response, "data", None)
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes)):
        raise EmbeddingError("embedding response data is absent")
    indexed: list[tuple[int, tuple[float, ...]]] = []
    for item in data:
        index = getattr(item, "index", None)
        embedding = getattr(item, "embedding", None)
        if not isinstance(index, int) or not isinstance(embedding, Sequence):
            raise EmbeddingError("embedding response item is malformed")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in embedding
        ):
            raise EmbeddingError("embedding response item is malformed")
        vector = tuple(float(value) for value in embedding)
        indexed.append((index, vector))
    if tuple(index for index, _ in indexed) != tuple(range(expected_count)):
        raise EmbeddingError("embedding response order is invalid")
    vectors = tuple(vector for _, vector in indexed)
    _validate_vectors(vectors, expected_count)
    return vectors


async def embed_many(
    texts: tuple[str, ...],
    *,
    config: EmbeddingConfig | None = None,
    client: _EmbeddingClient | None = None,
) -> tuple[tuple[float, ...], ...]:
    """Embed one non-empty ordered batch with the pinned model and dimensions."""
    texts = _canonical_texts(texts)
    bound = config or EmbeddingConfig.from_env()
    if bound.model != EMBEDDING_MODEL or bound.dimensions != EMBEDDING_DIMENSIONS:
        raise EmbeddingError("embedding configuration differs from the pinned model")
    transport = client or _client(bound)
    try:
        response = await transport.embeddings.create(
            model=EMBEDDING_MODEL,
            input=list(texts),
            dimensions=EMBEDDING_DIMENSIONS,
        )
    except EmbeddingError:
        raise
    except Exception:
        raise EmbeddingError("embedding request failed") from None
    return _response_vectors(response, len(texts))


async def embed_one(
    text: str,
    *,
    config: EmbeddingConfig | None = None,
    client: _EmbeddingClient | None = None,
) -> tuple[float, ...]:
    """Embed one exact non-empty text value."""
    return (await embed_many((text,), config=config, client=client))[0]


__all__ = [
    "EMBEDDING_DIMENSIONS",
    "EMBEDDING_MODEL",
    "EmbeddingError",
    "embed_many",
    "embed_one",
    "embedding_input_digest",
    "embedding_output_digest",
]
