"""Tests for calculate_symbol_score and search_symbols tool behaviour."""

import tempfile
from pathlib import Path

import pytest

from codesight_mcp.tools._common import calculate_symbol_score
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.core.validation import ValidationError


def _make_store_with_symbol(tmp: str) -> IndexStore:
    """Create a minimal index with a single symbol for tool tests."""
    symbols = [Symbol(
        id="src/mod.py::myfunc#function",
        file="src/mod.py",
        name="myfunc",
        qualified_name="myfunc",
        kind="function",
        language="python",
        signature="def myfunc():",
        docstring="",
        summary="my function",
        decorators=[],
        keywords=[],
        parent=None,
        line=1, end_line=3,
        byte_offset=0, byte_length=30,
        content_hash="c" * 64,
    )]
    store = IndexStore(tmp)
    content_dir = Path(tmp) / "owner__myrepo"
    content_dir.mkdir(parents=True, exist_ok=True)
    src_dir = content_dir / "src"
    src_dir.mkdir()
    (src_dir / "mod.py").write_text("def myfunc():\n    pass\n")
    store.save_index(
        owner="owner", name="myrepo",
        source_files=["src/mod.py"],
        symbols=symbols,
        raw_files={"src/mod.py": "def myfunc():\n    pass\n"},
        languages={"python": 1},
    )
    return store


def test_exact_match_scores_higher_than_partial():
    """Exact name match should score higher than partial match for query 'foo'."""
    query = "foo"
    query_lower = query.lower()
    query_words = set(query_lower.split())

    exact_sym = {
        "name": "foo",
        "signature": "def foo():",
        "summary": "",
        "keywords": [],
        "docstring": "",
    }
    partial_sym = {
        "name": "foobar",
        "signature": "def foobar():",
        "summary": "",
        "keywords": [],
        "docstring": "",
    }

    exact_score = calculate_symbol_score(exact_sym, query_lower, query_words)
    partial_score = calculate_symbol_score(partial_sym, query_lower, query_words)

    assert exact_score > partial_score, (
        f"Exact match score ({exact_score}) should exceed partial match score ({partial_score})"
    )


def test_unrelated_symbol_scores_zero():
    """A symbol unrelated to the query should score 0."""
    query = "foo"
    query_lower = query.lower()
    query_words = set(query_lower.split())

    unrelated_sym = {
        "name": "bar",
        "signature": "def bar():",
        "summary": "computes bar",
        "keywords": ["bar"],
        "docstring": "Computes bar value.",
    }

    score = calculate_symbol_score(unrelated_sym, query_lower, query_words)

    assert score == 0, f"Unrelated symbol should score 0, got {score}"


class TestSearchSymbolsScoreRounding:
    """ADV-MED-8: search_symbols score must be rounded to 1 decimal place."""

    def test_score_has_at_most_one_decimal(self):
        """Returned score values must have at most 1 decimal place."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_symbol(tmp)
            result = search_symbols(
                repo="owner/myrepo", query="myfunc", storage_path=tmp
            )
            for r in result.get("results", []):
                score = r["score"]
                # round(x, 1) == x for any value with at most 1 decimal place
                assert round(score, 1) == score, (
                    f"Score {score!r} has more than 1 decimal place"
                )


class TestGetFileOutlineFileValidation:
    """ADV-MED-9: get_file_outline must reject file paths not tracked by the index."""

    def test_unknown_file_raises_validation_error(self):
        """file_path not in index.source_files must raise ValidationError."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_symbol(tmp)
            with pytest.raises(ValidationError, match="File not found in index"):
                get_file_outline(
                    repo="owner/myrepo",
                    file_path="src/nonexistent.py",
                    storage_path=tmp,
                )

    def test_known_file_returns_result(self):
        """file_path present in index.source_files must return a result dict."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_symbol(tmp)
            result = get_file_outline(
                repo="owner/myrepo", file_path="src/mod.py", storage_path=tmp
            )
            assert "error" not in result
            assert result.get("symbols") is not None


def test_search_symbols_accepts_all_supported_languages():
    """All 15 supported languages must be accepted as filter values."""
    ALL_LANGUAGES = [
        "python", "javascript", "typescript", "go", "rust", "java", "php",
        "c", "cpp", "c_sharp", "ruby", "swift", "kotlin", "dart", "perl",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _make_store_with_symbol(tmp)
        for lang in ALL_LANGUAGES:
            result = search_symbols(
                repo="owner/myrepo",
                query="foo",
                language=lang,
                storage_path=tmp,
            )
            assert "Invalid language" not in result.get("error", ""), f"Language {lang!r} rejected"
