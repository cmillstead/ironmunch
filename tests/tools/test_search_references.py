"""Tests for the search_references tool.

Verifies that each text match is enriched with the innermost enclosing symbol
(or null when the hit falls outside all symbol ranges), and that all security
constraints (spotlighting, redaction-sentinel guard, _no_redact gate) hold.
"""

import tempfile
from unittest.mock import patch

import pytest

import codesight_mcp.security as security_mod
from codesight_mcp.storage import IndexStore
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.tools.search_references import search_references, _find_enclosing_symbol


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sym(
    file: str,
    name: str,
    line: int,
    end_line: int,
    kind: str = "function",
    signature: str = "",
) -> Symbol:
    """Build a minimal Symbol for testing."""
    sym_id = f"{file}::{name}#{kind}"
    return Symbol(
        id=sym_id,
        file=file,
        name=name,
        qualified_name=name,
        kind=kind,
        language="python",
        signature=signature or f"def {name}():",
        line=line,
        end_line=end_line,
    )


def _make_store(
    tmp: str,
    owner: str,
    name: str,
    files: dict[str, str],
    symbols: list[Symbol],
) -> IndexStore:
    """Build an IndexStore with provided files and symbols."""
    store = IndexStore(base_path=tmp)
    store.save_index(
        owner=owner,
        name=name,
        source_files=list(files.keys()),
        symbols=symbols,
        raw_files=files,
        languages={"python": len(files)},
    )
    return store


# ---------------------------------------------------------------------------
# _find_enclosing_symbol unit tests
# ---------------------------------------------------------------------------

class TestFindEnclosingSymbol:
    """Direct tests for the helper that maps a line to an enclosing symbol."""

    def _make_sym_dict(self, file: str, name: str, line: int, end_line: int, kind: str = "function") -> dict:
        return {
            "id": f"{file}::{name}#{kind}",
            "file": file,
            "name": name,
            "kind": kind,
            "signature": f"def {name}():",
            "line": line,
            "end_line": end_line,
        }

    def test_returns_none_when_no_symbols(self):
        result = _find_enclosing_symbol([], "foo.py", 5)
        assert result is None

    def test_returns_none_when_line_outside_all_symbols(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 1, 3)]
        result = _find_enclosing_symbol(syms, "foo.py", 10)
        assert result is None

    def test_returns_symbol_when_line_within_range(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 1, 5)]
        result = _find_enclosing_symbol(syms, "foo.py", 3)
        assert result is not None
        assert result["name"] == "alpha"

    def test_returns_innermost_when_nested(self):
        """A method nested inside a class should be preferred over the class."""
        syms = [
            self._make_sym_dict("foo.py", "MyClass", 1, 20, "class"),
            self._make_sym_dict("foo.py", "my_method", 5, 10, "method"),
        ]
        result = _find_enclosing_symbol(syms, "foo.py", 7)
        assert result is not None
        assert result["name"] == "my_method"

    def test_ignores_symbols_from_other_files(self):
        syms = [self._make_sym_dict("other.py", "alpha", 1, 10)]
        result = _find_enclosing_symbol(syms, "foo.py", 5)
        assert result is None

    def test_boundary_start_line_included(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 3, 7)]
        result = _find_enclosing_symbol(syms, "foo.py", 3)
        assert result is not None

    def test_boundary_end_line_included(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 3, 7)]
        result = _find_enclosing_symbol(syms, "foo.py", 7)
        assert result is not None

    def test_line_just_before_symbol_is_none(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 3, 7)]
        result = _find_enclosing_symbol(syms, "foo.py", 2)
        assert result is None

    def test_line_just_after_symbol_is_none(self):
        syms = [self._make_sym_dict("foo.py", "alpha", 3, 7)]
        result = _find_enclosing_symbol(syms, "foo.py", 8)
        assert result is None

    def test_symbols_with_zero_lines_skipped(self):
        syms = [self._make_sym_dict("foo.py", "broken", 0, 0)]
        result = _find_enclosing_symbol(syms, "foo.py", 1)
        assert result is None


# ---------------------------------------------------------------------------
# Integration tests via search_references()
# ---------------------------------------------------------------------------

class TestSearchReferencesBasic:
    """Basic functionality: finds hits and returns correct structure."""

    def test_finds_reference_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"utils.py": "def helper():\n    return True\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="helper", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] >= 1

    def test_result_has_required_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"utils.py": "def helper():\n    return True\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="helper", storage_path=tmp)
            assert "error" not in result
            for match in result["results"]:
                assert "file" in match
                assert "line" in match
                assert "text" in match
                assert "enclosing_symbol" in match

    def test_line_numbers_are_correct(self):
        """The 'line' field must reflect the 1-indexed line where the term appears."""
        content = "x = 1\nfoo = 'target'\ny = 3\n"
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": content},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="target", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] == 1
            assert result["results"][0]["line"] == 2

    def test_empty_query_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = search_references(repo="owner/repo", query="", storage_path=tmp)
            assert "error" in result

    def test_whitespace_only_query_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = search_references(repo="owner/repo", query="   ", storage_path=tmp)
            assert "error" in result

    def test_unknown_repo_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = search_references(repo="nobody/ghost", query="anything", storage_path=tmp)
            assert "error" in result

    def test_no_match_returns_empty_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": "x = 1\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="zzznomatch999", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] == 0
            assert result["results"] == []

    def test_search_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": "UPPERCASE_CONST = 42\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="uppercase_const", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] >= 1


# ---------------------------------------------------------------------------
# Enclosing symbol enrichment
# ---------------------------------------------------------------------------

class TestEnclosingSymbol:
    """Verifies that enclosing_symbol is populated correctly per match."""

    def test_hit_inside_function_has_enclosing_symbol(self):
        content = (
            "def my_func():\n"          # line 1
            "    target_value = 1\n"    # line 2
            "    return target_value\n" # line 3
        )
        sym = _sym("a.py", "my_func", line=1, end_line=3, signature="def my_func():")
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": content},
                symbols=[sym],
            )
            result = search_references(repo="owner/repo", query="target_value", storage_path=tmp)
            assert "error" not in result
            matches = result["results"]
            assert matches, "Expected at least one match"
            enc = matches[0]["enclosing_symbol"]
            assert enc is not None
            assert "my_func" in enc["name"]

    def test_hit_outside_all_symbols_has_null_enclosing(self):
        content = (
            "MODULE_CONST = 'target'\n"  # line 1 — outside any symbol
            "\n"
            "def my_func():\n"          # line 3
            "    pass\n"                # line 4
        )
        sym = _sym("a.py", "my_func", line=3, end_line=4)
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": content},
                symbols=[sym],
            )
            result = search_references(repo="owner/repo", query="target", storage_path=tmp)
            assert "error" not in result
            matches = [m for m in result["results"] if m["line"] == 1]
            assert matches, "Expected match on line 1"
            assert matches[0]["enclosing_symbol"] is None

    def test_hit_inside_nested_method_picks_narrowest(self):
        """A hit inside a method that is inside a class should yield the method."""
        content = (
            "class MyClass:\n"             # line 1
            "    def my_method(self):\n"  # line 2
            "        target_call()\n"     # line 3
            "    def other(self):\n"      # line 4
            "        pass\n"             # line 5
        )
        cls_sym = _sym("a.py", "MyClass", line=1, end_line=5, kind="class", signature="class MyClass:")
        meth_sym = _sym("a.py", "my_method", line=2, end_line=3, kind="method", signature="def my_method(self):")
        other_sym = _sym("a.py", "other", line=4, end_line=5, kind="method", signature="def other(self):")

        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": content},
                symbols=[cls_sym, meth_sym, other_sym],
            )
            result = search_references(repo="owner/repo", query="target_call", storage_path=tmp)
            assert "error" not in result
            matches = result["results"]
            assert matches
            enc = matches[0]["enclosing_symbol"]
            assert enc is not None
            assert "my_method" in enc["name"]

    def test_enclosing_symbol_fields(self):
        """enclosing_symbol must contain id, kind, name, signature."""
        content = "def alpha():\n    needle = 1\n"
        sym = _sym("b.py", "alpha", line=1, end_line=2, signature="def alpha():")
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"b.py": content},
                symbols=[sym],
            )
            result = search_references(repo="owner/repo", query="needle", storage_path=tmp)
            assert "error" not in result
            enc = result["results"][0]["enclosing_symbol"]
            assert enc is not None
            assert "id" in enc
            assert "kind" in enc
            assert "name" in enc
            assert "signature" in enc
            assert enc["kind"] == "function"


# ---------------------------------------------------------------------------
# file_pattern filter
# ---------------------------------------------------------------------------

class TestFilePatternFilter:
    """Verifies that file_pattern filters files correctly."""

    def test_file_pattern_includes_matching_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={
                    "utils.py": "needle = 1\n",
                    "config.js": "needle = 2\n",
                },
                symbols=[],
            )
            result = search_references(
                repo="owner/repo", query="needle",
                file_pattern="*.py", storage_path=tmp,
            )
            assert "error" not in result
            for match in result["results"]:
                assert "utils.py" in match["file"]

    def test_file_pattern_excludes_non_matching_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={
                    "utils.py": "needle = 1\n",
                    "config.js": "needle = 2\n",
                },
                symbols=[],
            )
            result = search_references(
                repo="owner/repo", query="needle",
                file_pattern="*.py", storage_path=tmp,
            )
            assert "error" not in result
            for match in result["results"]:
                assert "config.js" not in match["file"]

    def test_file_pattern_no_match_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"utils.py": "needle = 1\n"},
                symbols=[],
            )
            result = search_references(
                repo="owner/repo", query="needle",
                file_pattern="*.rs", storage_path=tmp,
            )
            assert "error" not in result
            assert result["result_count"] == 0


# ---------------------------------------------------------------------------
# Spotlighting / security
# ---------------------------------------------------------------------------

class TestSpotlighting:
    """All user-facing strings must be wrapped with spotlighting markers."""

    def test_file_field_is_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"mod.py": "def helper():\n    return True\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="helper", storage_path=tmp)
            assert "error" not in result
            for match in result["results"]:
                assert match["file"].startswith("<<<UNTRUSTED_CODE_")

    def test_text_field_is_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"mod.py": "result = compute()\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="compute", storage_path=tmp)
            assert "error" not in result
            for match in result["results"]:
                assert match["text"].startswith("<<<UNTRUSTED_CODE_")

    def test_enclosing_symbol_fields_are_wrapped(self):
        content = "def alpha():\n    needle = 1\n"
        sym = _sym("c.py", "alpha", line=1, end_line=2)
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"c.py": content},
                symbols=[sym],
            )
            result = search_references(repo="owner/repo", query="needle", storage_path=tmp)
            assert "error" not in result
            enc = result["results"][0]["enclosing_symbol"]
            assert enc is not None
            assert enc["id"].startswith("<<<UNTRUSTED_CODE_")
            assert enc["name"].startswith("<<<UNTRUSTED_CODE_")
            assert enc["signature"].startswith("<<<UNTRUSTED_CODE_")

    def test_redaction_sentinel_query_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = search_references(repo="owner/repo", query="<REDACTED>", storage_path=tmp)
            assert "error" in result
            assert "redaction" in result["error"].lower()

    def test_redaction_sentinel_prefix_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = search_references(repo="owner/repo", query="<REDA", storage_path=tmp)
            assert "error" in result
            assert "redaction" in result["error"].lower()

    def test_short_prefix_allowed(self):
        """Prefixes shorter than 4 chars should not be blocked."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"x.py": "<RE is fine\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="<RE", storage_path=tmp)
            # Should not be blocked (only 3 chars)
            assert "error" not in result

    def test_no_redact_env_blocks_tool(self):
        """When _NO_REDACT is True the tool must be disabled."""
        with patch.object(security_mod, "_NO_REDACT", True):
            with tempfile.TemporaryDirectory() as tmp:
                result = search_references(repo="owner/repo", query="anything", storage_path=tmp)
                assert "error" in result
                assert "CODESIGHT_NO_REDACT" in result["error"]


# ---------------------------------------------------------------------------
# Meta envelope
# ---------------------------------------------------------------------------

class TestMetaEnvelope:
    """_meta envelope must be present and well-formed."""

    def test_meta_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": "x = 1\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="x", storage_path=tmp)
            assert "error" not in result
            assert "_meta" in result
            meta = result["_meta"]
            assert "timing_ms" in meta
            assert "files_searched" in meta
            assert "truncated" in meta
            assert "source" in meta
            assert meta["source"] == "code_index"

    def test_result_count_matches_results_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": "x = 1\nx = 2\nx = 3\n"},
                symbols=[],
            )
            result = search_references(repo="owner/repo", query="x", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] == len(result["results"])

    def test_max_results_cap(self):
        """max_results limits the number of returned matches."""
        content = "\n".join(f"needle_{i} = {i}" for i in range(50)) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(
                tmp, "owner", "repo",
                files={"a.py": content},
                symbols=[],
            )
            result = search_references(
                repo="owner/repo", query="needle",
                max_results=5, storage_path=tmp,
            )
            assert "error" not in result
            assert len(result["results"]) <= 5
            assert result["_meta"]["truncated"] is True
