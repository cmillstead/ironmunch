"""Tests for embedding providers — ABC contract, env var handling, local provider."""

from __future__ import annotations

import importlib.util
import os

import pytest

from codesight_mcp.embeddings.providers import (
    EmbeddingProvider,
    LocalEmbeddingProvider,
    get_embedding_provider,
    get_embedding_provider_or_reason,
)


# ------------------------------------------------------------------
# Helper: real env var context manager
# ------------------------------------------------------------------


class _env_override:  # noqa: N801
    """Context manager that sets/unsets real env vars and restores on exit."""

    def __init__(self, **kwargs: str | None) -> None:
        self._overrides = kwargs
        self._originals: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for key, value in self._overrides.items():
            self._originals[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def __exit__(self, *args: object) -> None:
        for key, original in self._originals.items():
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original


# ------------------------------------------------------------------
# ABC contract
# ------------------------------------------------------------------


class TestEmbeddingProviderABC:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            EmbeddingProvider()  # type: ignore[abstract]


# ------------------------------------------------------------------
# Factory env-var handling (no fastembed required)
# ------------------------------------------------------------------


class TestGetEmbeddingProviderEnvVars:
    def test_no_semantic_returns_none(self) -> None:
        with _env_override(CODESIGHT_NO_SEMANTIC="1"):
            assert get_embedding_provider() is None

    def test_unknown_provider_returns_none(self) -> None:
        with _env_override(CODESIGHT_EMBED_PROVIDER="unknown", CODESIGHT_NO_SEMANTIC=None):
            assert get_embedding_provider() is None


# ------------------------------------------------------------------
# Tests that require fastembed
# ------------------------------------------------------------------

_HAS_FASTEMBED = importlib.util.find_spec("fastembed") is not None
requires_fastembed = pytest.mark.skipif(
    not _HAS_FASTEMBED, reason="fastembed not installed (semantic extra)"
)


@requires_fastembed
class TestLocalEmbeddingProvider:
    @pytest.fixture(scope="class")
    def provider(self) -> LocalEmbeddingProvider:
        """Shared provider instance — model download is expensive."""
        return LocalEmbeddingProvider()

    def test_embed_single_text(self, provider: LocalEmbeddingProvider) -> None:
        result = provider.embed(["hello world"])
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], list)
        assert all(isinstance(v, float) for v in result[0])

    def test_dimensions_matches_vector_length(self, provider: LocalEmbeddingProvider) -> None:
        result = provider.embed(["test"])
        assert len(result[0]) == provider.dimensions

    def test_batch_embed_two_texts(self, provider: LocalEmbeddingProvider) -> None:
        result = provider.embed(["first text", "second text"])
        assert len(result) == 2
        assert len(result[0]) == provider.dimensions
        assert len(result[1]) == provider.dimensions

    def test_embed_empty_list(self, provider: LocalEmbeddingProvider) -> None:
        result = provider.embed([])
        assert result == []

    def test_model_name_property(self, provider: LocalEmbeddingProvider) -> None:
        assert provider.model_name == "BAAI/bge-base-en-v1.5"

    def test_embed_model_env_var_respected(self) -> None:
        with _env_override(
            CODESIGHT_EMBED_MODEL="BAAI/bge-small-en-v1.5",
            CODESIGHT_NO_SEMANTIC=None,
            CODESIGHT_EMBED_PROVIDER=None,
        ):
            result = get_embedding_provider()
            assert result is not None
            assert result.model_name == "BAAI/bge-small-en-v1.5"

    def test_factory_local_provider(self) -> None:
        with _env_override(
            CODESIGHT_EMBED_PROVIDER="local",
            CODESIGHT_NO_SEMANTIC=None,
            CODESIGHT_EMBED_MODEL=None,
        ):
            result = get_embedding_provider()
            assert result is not None
            assert isinstance(result, LocalEmbeddingProvider)


# ------------------------------------------------------------------
# Not-implemented provider routing
# ------------------------------------------------------------------


class TestNotImplementedProviders:
    def test_anthropic_provider_returns_none(self) -> None:
        """CODESIGHT_EMBED_PROVIDER=anthropic returns None (not yet implemented)."""
        with _env_override(CODESIGHT_EMBED_PROVIDER="anthropic", CODESIGHT_NO_SEMANTIC=None):  # mock-ok: env var for test isolation
            result = get_embedding_provider()
            assert result is None

    def test_openai_provider_returns_none(self) -> None:
        """CODESIGHT_EMBED_PROVIDER=openai returns None (not yet implemented)."""
        with _env_override(CODESIGHT_EMBED_PROVIDER="openai", CODESIGHT_NO_SEMANTIC=None):  # mock-ok: env var for test isolation
            result = get_embedding_provider()
            assert result is None

    def test_get_provider_or_reason_anthropic(self) -> None:
        """get_embedding_provider_or_reason with anthropic returns not_implemented reason."""
        with _env_override(CODESIGHT_EMBED_PROVIDER="anthropic", CODESIGHT_NO_SEMANTIC=None):  # mock-ok: env var for test isolation
            provider, reason = get_embedding_provider_or_reason()
            assert provider is None
            assert reason == "not_implemented:anthropic"

    def test_get_provider_or_reason_openai(self) -> None:
        """get_embedding_provider_or_reason with openai returns not_implemented reason."""
        with _env_override(CODESIGHT_EMBED_PROVIDER="openai", CODESIGHT_NO_SEMANTIC=None):  # mock-ok: env var for test isolation
            provider, reason = get_embedding_provider_or_reason()
            assert provider is None
            assert reason == "not_implemented:openai"

    def test_get_provider_or_reason_disabled(self) -> None:
        """get_embedding_provider_or_reason returns disabled reason when CODESIGHT_NO_SEMANTIC=1."""
        with _env_override(CODESIGHT_NO_SEMANTIC="1"):  # mock-ok: env var for test isolation
            provider, reason = get_embedding_provider_or_reason()
            assert provider is None
            assert reason == "disabled"

    def test_get_provider_or_reason_unknown(self) -> None:
        """get_embedding_provider_or_reason returns unknown reason for unrecognized provider."""
        with _env_override(CODESIGHT_EMBED_PROVIDER="foobar", CODESIGHT_NO_SEMANTIC=None):  # mock-ok: env var for test isolation
            provider, reason = get_embedding_provider_or_reason()
            assert provider is None
            assert reason == "unknown:foobar"
