"""Tests for tools/_common.py: parse_repo, calculate_symbol_score, RepoContext, prepare_graph_query."""

import pytest

from codesight_mcp.core.errors import RepoNotFoundError
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools._common import (
    RepoContext,
    calculate_symbol_score,
    parse_repo,
    prepare_graph_query,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store_with_repo(tmp_path, owner="acme", name="myproject"):
    """Create an IndexStore with one indexed repo and return (store, sym_id)."""
    src = "def hello():\n    return 1\n"
    symbols = [
        Symbol(
            id="hello-py::hello",
            file="hello.py",
            name="hello",
            qualified_name="hello",
            kind="function",
            language="python",
            signature="def hello():",
            summary="Says hello",
            byte_offset=0,
            byte_length=len(src),
        )
    ]
    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner=owner,
        name=name,
        source_files=["hello.py"],
        symbols=symbols,
        raw_files={"hello.py": src},
        languages={"python": 1},
    )
    return store, "hello-py::hello"


# ---------------------------------------------------------------------------
# parse_repo
# ---------------------------------------------------------------------------


class TestParseRepo:
    """Tests for parse_repo()."""

    def test_owner_slash_repo(self, tmp_path):
        """owner/repo format returns (owner, repo)."""
        owner, name = parse_repo("acme/widget", storage_path=str(tmp_path))
        assert owner == "acme"
        assert name == "widget"

    def test_bare_name_exact_match(self, tmp_path):
        """Bare repo name resolves via exact suffix match on indexed repos."""
        _make_store_with_repo(tmp_path, owner="acme", name="myproject")
        owner, name = parse_repo("myproject", storage_path=str(tmp_path))
        assert owner == "acme"
        assert name == "myproject"

    def test_bare_name_not_found(self, tmp_path):
        """Bare name with no matching indexed repo raises RepoNotFoundError."""
        # Empty store
        IndexStore(base_path=str(tmp_path))
        with pytest.raises(RepoNotFoundError, match="not found"):
            parse_repo("nonexistent", storage_path=str(tmp_path))

    def test_local_prefix(self, tmp_path):
        """local/something format parses directly."""
        owner, name = parse_repo("local/something", storage_path=str(tmp_path))
        assert owner == "local"
        assert name == "something"

    def test_multiple_slashes_rejected(self, tmp_path):
        """owner/name/extra is rejected by sanitize_repo_identifier."""
        with pytest.raises(RepoNotFoundError):
            parse_repo("org/repo/sub", storage_path=str(tmp_path))

    def test_bare_name_hash_suffix_match(self, tmp_path):
        """Bare name matches local hash-suffixed repos (e.g. local/myproject-abcdef123456)."""
        _make_store_with_repo(tmp_path, owner="local", name="myproject-abcdef123456")
        owner, name = parse_repo("myproject", storage_path=str(tmp_path))
        assert owner == "local"
        assert name == "myproject-abcdef123456"

    def test_ambiguous_bare_name(self, tmp_path):
        """Ambiguous bare name (matches multiple repos) raises RepoNotFoundError."""
        # Create two repos with same suffix name
        src = "x = 1\n"
        symbols = [
            Symbol(
                id="x-py::x", file="x.py", name="x", qualified_name="x",
                kind="constant", language="python", signature="x = 1",
                byte_offset=0, byte_length=len(src),
            )
        ]
        store = IndexStore(base_path=str(tmp_path))
        for org in ("org1", "org2"):
            store.save_index(
                owner=org, name="widget",
                source_files=["x.py"], symbols=symbols,
                raw_files={"x.py": src}, languages={"python": 1},
            )
        with pytest.raises(RepoNotFoundError, match="Ambiguous"):
            parse_repo("widget", storage_path=str(tmp_path))

    def test_empty_string_raises(self, tmp_path):
        """Empty string raises RepoNotFoundError (no indexed repos match '')."""
        IndexStore(base_path=str(tmp_path))
        with pytest.raises(RepoNotFoundError):
            parse_repo("", storage_path=str(tmp_path))


# ---------------------------------------------------------------------------
# calculate_symbol_score
# ---------------------------------------------------------------------------


class TestCalculateSymbolScore:
    """Tests for calculate_symbol_score()."""

    def _sym(self, name="foo", signature="", summary="", docstring="", keywords=None):
        return {
            "name": name,
            "signature": signature,
            "summary": summary,
            "docstring": docstring,
            "keywords": keywords or [],
        }

    def test_exact_name_match_highest(self):
        """Exact name match yields 20 + word overlap points."""
        sym = self._sym(name="login")
        score = calculate_symbol_score(sym, "login", {"login"})
        assert score >= 20

    def test_name_contains_query(self):
        """Name containing query yields partial score (10)."""
        sym = self._sym(name="user_login_handler")
        score = calculate_symbol_score(sym, "login", {"login"})
        assert 10 <= score < 20 + 10  # 10 for contains + word overlap

    def test_signature_match_boosts_score(self):
        """Query found in signature adds 8 points."""
        sym = self._sym(name="unrelated", signature="def process(data: str)")
        score_with = calculate_symbol_score(sym, "data", {"data"})
        sym_no = self._sym(name="unrelated", signature="def process(x: int)")
        score_without = calculate_symbol_score(sym_no, "data", {"data"})
        assert score_with > score_without

    def test_case_insensitive(self):
        """Matching is case-insensitive."""
        sym = self._sym(name="MyClass")
        score = calculate_symbol_score(sym, "myclass", {"myclass"})
        assert score >= 20  # exact match after lowering

    def test_word_overlap(self):
        """Multi-word query scores partial word overlap."""
        sym = self._sym(name="process_data")
        score = calculate_symbol_score(sym, "process data", {"process", "data"})
        # Should get name-contains + word overlap for both words
        assert score > 0

    def test_empty_query_returns_low_score(self):
        """Empty query returns score based on empty-string containment checks."""
        sym = self._sym(name="anything", signature="def anything():")
        score = calculate_symbol_score(sym, "", set())
        # Empty string is "in" every string, so containment checks fire.
        # The important thing is it doesn't crash and returns an integer.
        assert isinstance(score, int)

    def test_summary_match(self):
        """Query in summary adds 5 points."""
        sym = self._sym(name="x", summary="Validates user input")
        score = calculate_symbol_score(sym, "validates", {"validates"})
        assert score >= 5

    def test_keyword_match(self):
        """Matching keywords add 3 points each."""
        sym = self._sym(name="x", keywords=["auth", "login"])
        score = calculate_symbol_score(sym, "auth login", {"auth", "login"})
        assert score >= 6  # 3 * 2 keywords

    def test_docstring_match(self):
        """Query word in docstring adds 1 point."""
        sym = self._sym(name="x", docstring="This handles authentication")
        score = calculate_symbol_score(sym, "authentication", {"authentication"})
        assert score >= 1

    def test_no_match_zero(self):
        """Completely unrelated query returns 0."""
        sym = self._sym(name="foo", signature="def foo():")
        score = calculate_symbol_score(sym, "zzzzz", {"zzzzz"})
        assert score == 0

    def test_score_is_integer(self):
        """Score is always an integer."""
        sym = self._sym(name="test", signature="def test():", summary="A test")
        score = calculate_symbol_score(sym, "test", {"test"})
        assert isinstance(score, int)


# ---------------------------------------------------------------------------
# RepoContext.resolve
# ---------------------------------------------------------------------------


class TestRepoContext:
    """Tests for RepoContext.resolve()."""

    def test_valid_repo_returns_context(self, tmp_path):
        """Valid repo returns a RepoContext instance."""
        _make_store_with_repo(tmp_path)
        ctx = RepoContext.resolve("acme/myproject", storage_path=str(tmp_path))
        assert isinstance(ctx, RepoContext)
        assert ctx.owner == "acme"
        assert ctx.name == "myproject"
        assert ctx.index is not None

    def test_nonexistent_repo_returns_error(self, tmp_path):
        """Non-existent repo returns error dict."""
        result = RepoContext.resolve("ghost/repo", storage_path=str(tmp_path))
        assert isinstance(result, dict)
        assert "error" in result

    def test_error_dict_structure(self, tmp_path):
        """Error dict has exactly one 'error' key with a string value."""
        result = RepoContext.resolve("ghost/repo", storage_path=str(tmp_path))
        assert isinstance(result["error"], str)
        assert len(result["error"]) > 0


# ---------------------------------------------------------------------------
# prepare_graph_query
# ---------------------------------------------------------------------------


class TestPrepareGraphQuery:
    """Tests for prepare_graph_query()."""

    def test_valid_repo_and_symbol(self, tmp_path):
        """Valid repo + symbol returns 5-tuple."""
        _make_store_with_repo(tmp_path)
        result = prepare_graph_query(
            "acme/myproject", symbol_id="hello-py::hello",
            storage_path=str(tmp_path),
        )
        assert isinstance(result, tuple)
        assert len(result) == 5
        owner, name, index, graph, symbol_info = result
        assert owner == "acme"
        assert name == "myproject"
        assert symbol_info is not None
        assert symbol_info["name"] == "hello"

    def test_missing_repo(self, tmp_path):
        """Missing repo returns error dict."""
        result = prepare_graph_query(
            "ghost/repo", symbol_id="any",
            storage_path=str(tmp_path),
        )
        assert isinstance(result, dict)
        assert "error" in result

    def test_missing_symbol(self, tmp_path):
        """Existing repo but missing symbol returns error dict."""
        _make_store_with_repo(tmp_path)
        result = prepare_graph_query(
            "acme/myproject", symbol_id="nonexistent::sym",
            storage_path=str(tmp_path),
        )
        assert isinstance(result, dict)
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_none_symbol_id_skips_lookup(self, tmp_path):
        """symbol_id=None skips symbol lookup and returns None for symbol_info."""
        _make_store_with_repo(tmp_path)
        result = prepare_graph_query(
            "acme/myproject", symbol_id=None,
            storage_path=str(tmp_path),
        )
        assert isinstance(result, tuple)
        _, _, _, _, symbol_info = result
        assert symbol_info is None
