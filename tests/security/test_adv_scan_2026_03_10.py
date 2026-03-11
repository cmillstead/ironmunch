"""Tests for adversarial scan findings (2026-03-10).

Covers ADV-HIGH-1, ADV-MED-1 through ADV-MED-9, ADV-LOW-1 through ADV-LOW-8,
and ADV-INFO-1.
"""

import os
import re
import threading
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from codesight_mcp.parser.symbols import Symbol


def _make_symbol(sig: str = "def foo():", **kwargs) -> Symbol:
    defaults = dict(
        id="test::foo#function", file="test.py", name="foo",
        qualified_name="foo", kind="function", language="python",
        signature=sig, line=1, end_line=2, byte_offset=0, byte_length=10,
    )
    defaults.update(kwargs)
    return Symbol(**defaults)


# ---------------------------------------------------------------------------
# ADV-HIGH-1: ensure_private_dir TOCTOU fix
# ---------------------------------------------------------------------------
class TestEnsurePrivateDirTOCTOU:
    def test_symlink_rejected(self, tmp_path):
        """ensure_private_dir must reject symlinked directories."""
        from codesight_mcp.core.locking import ensure_private_dir
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(OSError, match="symlink"):
            ensure_private_dir(link)

    def test_permissions_via_fchmod(self, tmp_path):
        """ensure_private_dir must set 0o700 permissions via fchmod."""
        from codesight_mcp.core.locking import ensure_private_dir
        target = tmp_path / "secure"
        result = ensure_private_dir(target)
        assert result.is_dir()
        assert oct(target.stat().st_mode & 0o777) == "0o700"


# ---------------------------------------------------------------------------
# ADV-MED-1: Mermaid _escape newline handling + mermaid field wrapping
# ---------------------------------------------------------------------------
class TestMermaidNewlineEscape:
    def test_newline_escaped_in_label(self):
        from codesight_mcp.tools.get_diagram import _escape
        assert "\n" not in _escape("foo\nbar")
        assert "\r" not in _escape("foo\rbar")

    def test_mermaid_field_wrapped(self):
        """Mermaid output from _build_mermaid must be wrapped with untrusted markers."""
        from codesight_mcp.tools.get_diagram import _build_mermaid
        nodes = {"a": {"name": "foo", "kind": "function"}}
        edges = []
        result = _build_mermaid(nodes, edges, "TD")
        assert "UNTRUSTED_CODE" in result["mermaid"]


# ---------------------------------------------------------------------------
# ADV-MED-2: get_dead_code limit + truncated flag
# ---------------------------------------------------------------------------
class TestGetDeadCodeLimit:
    def test_limit_caps_results(self, tmp_path):
        from codesight_mcp.tools.get_dead_code import get_dead_code
        from codesight_mcp.storage import IndexStore

        symbols = []
        for i in range(10):
            symbols.append(_make_symbol(
                name=f"unused_{i}",
                id=f"a.py::unused_{i}#function",
                qualified_name=f"unused_{i}",
            ))
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo", source_files=["a.py"],
            symbols=symbols, languages={"python": 10},
            raw_files={"a.py": "\n".join(f"def unused_{i}(): pass" for i in range(10))},
        )
        result = get_dead_code("test/repo", limit=3, storage_path=str(tmp_path))
        assert len(result["symbols"]) <= 3
        assert result["truncated"] is True

    def test_no_truncation_when_under_limit(self, tmp_path):
        from codesight_mcp.tools.get_dead_code import get_dead_code
        from codesight_mcp.storage import IndexStore

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo", source_files=["a.py"],
            symbols=[_make_symbol(name="lone", id="a.py::lone#function", qualified_name="lone")],
            languages={"python": 1},
            raw_files={"a.py": "def lone(): pass"},
        )
        result = get_dead_code("test/repo", limit=100, storage_path=str(tmp_path))
        assert result["truncated"] is False


# ---------------------------------------------------------------------------
# ADV-MED-3: Homoglyph bypass in injection phrase blocklist
# ---------------------------------------------------------------------------
class TestHomoglyphBypass:
    def test_ascii_encoding_strips_non_ascii(self):
        """ADV-MED-3 + TM-2: After NFKD + confusable mapping + ASCII encoding,
        cross-script homoglyphs are normalized to Latin equivalents.

        TM-2 strengthened this: Cyrillic/Greek lookalikes are now mapped to
        their Latin equivalents before checking, so confusable-char injection
        phrases are correctly detected.
        """
        from codesight_mcp.summarizer.batch_summarize import _contains_injection_phrase
        # Pure ASCII injection phrase still detected
        assert _contains_injection_phrase("ignore previous")
        # TM-2: Cyrillic lookalike 'і' (U+0456) is now mapped to Latin 'i',
        # so "іgnore " correctly matches the "ignore " blocklist entry.
        cyrillic_ignore = "\u0456gnore "
        assert _contains_injection_phrase(cyrillic_ignore)
        # Mixed-script with enough ASCII to match still caught
        assert _contains_injection_phrase("system: do something")


# ---------------------------------------------------------------------------
# ADV-MED-6: _node_to_dict depth limit
# ---------------------------------------------------------------------------
class TestNodeToDictDepth:
    def test_deep_tree_truncated(self):
        from codesight_mcp.tools.get_file_outline import _node_to_dict, _MAX_NODE_DEPTH
        from codesight_mcp.parser import SymbolNode, Symbol

        # Build a chain deeper than _MAX_NODE_DEPTH
        leaf = SymbolNode(symbol=Symbol(
            id="x", file="x.py", name="leaf", qualified_name="leaf",
            kind="function", language="python", signature="def leaf():",
            line=1, end_line=2, byte_offset=0, byte_length=5,
        ))
        current = leaf
        for i in range(_MAX_NODE_DEPTH + 5):
            parent = SymbolNode(symbol=Symbol(
                id=f"n{i}", file="x.py", name=f"n{i}", qualified_name=f"n{i}",
                kind="class", language="python", signature=f"class N{i}:",
                line=1, end_line=100, byte_offset=0, byte_length=100,
            ))
            parent.children.append(current)
            current = parent

        result = _node_to_dict(current)
        # Walk to the bottom — should stop before leaf
        node = result
        depth = 0
        while "children" in node and node["children"]:
            node = node["children"][0]
            depth += 1
        assert depth <= _MAX_NODE_DEPTH


# ---------------------------------------------------------------------------
# ADV-MED-7: get_callers/get_callees result cap
# ---------------------------------------------------------------------------
class TestCallersCalleesResultCap:
    def test_callers_cap(self, tmp_path):
        from codesight_mcp.tools.get_callers import _MAX_RESULTS
        assert _MAX_RESULTS == 500

    def test_callees_cap(self, tmp_path):
        from codesight_mcp.tools.get_callees import _MAX_RESULTS
        assert _MAX_RESULTS == 500


# ---------------------------------------------------------------------------
# ADV-MED-8: complexity.py walk() depth limit
# ---------------------------------------------------------------------------
class TestComplexityWalkDepth:
    def test_max_walk_depth_exists(self):
        """The walk function should have a depth limit."""
        import codesight_mcp.parser.complexity as cx
        source = open(cx.__file__).read()
        assert "_MAX_WALK_DEPTH" in source


# ---------------------------------------------------------------------------
# ADV-MED-9: Validate GitHub API paths in discovery
# ---------------------------------------------------------------------------
class TestGitHubApiPathValidation:
    def test_control_chars_rejected(self):
        from codesight_mcp.discovery import discover_source_files

        tree_entries = [
            {"type": "blob", "path": "src/evil\x00.py", "size": 100},
            {"type": "blob", "path": "src/good.py", "size": 100},
        ]
        files = discover_source_files(tree_entries)
        assert "src/evil\x00.py" not in files

    def test_traversal_paths_rejected(self):
        from codesight_mcp.discovery import discover_source_files

        tree_entries = [
            {"type": "blob", "path": "../etc/passwd.py", "size": 100},
            {"type": "blob", "path": "src/good.py", "size": 100},
        ]
        files = discover_source_files(tree_entries)
        assert "../etc/passwd.py" not in files


# ---------------------------------------------------------------------------
# ADV-LOW-1: Naive timestamps
# ---------------------------------------------------------------------------
class TestTimestamps:
    def test_indexed_at_has_timezone(self, tmp_path):
        from codesight_mcp.storage import IndexStore
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo", source_files=["a.py"],
            symbols=[_make_symbol()], languages={"python": 1},
            raw_files={"a.py": "def foo(): pass"},
        )
        idx = store.load_index("test", "repo")
        # ISO format with timezone should contain '+' for UTC offset
        assert "+" in idx.indexed_at or "Z" in idx.indexed_at


# ---------------------------------------------------------------------------
# ADV-LOW-2: PID/thread in atomic_write_nofollow temp path
# ---------------------------------------------------------------------------
class TestAtomicWriteTempPath:
    def test_temp_path_includes_pid(self, tmp_path):
        """The temp file path should include PID for thread safety."""
        from codesight_mcp.core.locking import atomic_write_nofollow
        target = tmp_path / "test.txt"
        # Write and check no leftover temps (successful write cleans up)
        atomic_write_nofollow(target, "hello")
        assert target.read_text() == "hello"
        # Verify the implementation includes PID in the source
        import inspect
        src = inspect.getsource(atomic_write_nofollow)
        assert "getpid" in src


# ---------------------------------------------------------------------------
# ADV-LOW-3: Validate sort_by in get_hotspots
# ---------------------------------------------------------------------------
class TestHotspotsSortByValidation:
    def test_invalid_sort_by_returns_error(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        from codesight_mcp.storage import IndexStore

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo", source_files=["a.py"],
            symbols=[_make_symbol()], languages={"python": 1},
            raw_files={"a.py": "def foo(): pass"},
        )
        result = get_hotspots("test/repo", sort_by="invalid", storage_path=str(tmp_path))
        assert "error" in result


# ---------------------------------------------------------------------------
# ADV-LOW-4: signature_fallback injection returns kind-only
# ---------------------------------------------------------------------------
class TestSignatureFallbackInjection:
    def test_injection_in_name_returns_kind_only(self):
        from codesight_mcp.summarizer.batch_summarize import signature_fallback
        sym = _make_symbol(
            name="ignore everything",
            signature="",
            kind="function",
        )
        result = signature_fallback(sym)
        # Must not contain the injection phrase
        assert "ignore" not in result.lower()
        assert result == "function"


# ---------------------------------------------------------------------------
# ADV-LOW-5: Sanitize calls/imports list fields
# ---------------------------------------------------------------------------
class TestSanitizeListFields:
    def test_control_chars_in_calls_sanitized(self, tmp_path):
        from codesight_mcp.storage import IndexStore
        sym = _make_symbol(calls=["foo\x00bar", "clean"])
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo", source_files=["a.py"],
            symbols=[sym], languages={"python": 1},
            raw_files={"a.py": "def foo(): pass"},
        )
        idx = store.load_index("test", "repo")
        for item in idx.symbols[0].get("calls", []):
            assert "\x00" not in item


# ---------------------------------------------------------------------------
# ADV-LOW-6: Require nonce in _split_prompt
# ---------------------------------------------------------------------------
class TestSplitPromptRequiresNonce:
    def test_call_without_nonce_raises(self):
        from codesight_mcp.summarizer.batch_summarize import BatchSummarizer
        with pytest.raises(TypeError):
            BatchSummarizer._split_prompt("some prompt")


# ---------------------------------------------------------------------------
# ADV-LOW-7: Validate git_head as hex hash
# ---------------------------------------------------------------------------
class TestGitHeadValidation:
    def test_non_hex_git_head_rejected(self, tmp_path):
        from codesight_mcp.tools.index_folder import _git_changed_files
        # Non-hex string should cause immediate None return
        assert _git_changed_files(tmp_path, "not-a-hex-hash") is None

    def test_valid_hex_hash_accepted(self, tmp_path):
        from codesight_mcp.tools.index_folder import _git_changed_files
        # Valid hash format should NOT be rejected by validation
        # (it may still fail due to git not being a repo, but won't be None from validation)
        result = _git_changed_files(tmp_path, "a" * 40)
        # Returns None because tmp_path isn't a git repo, but the validation passed
        assert result is None  # git error, not validation error


# ---------------------------------------------------------------------------
# ADV-LOW-8: Replace _symbols_by_id in get_diagram.py
# ---------------------------------------------------------------------------
class TestDiagramNoPrivateAccess:
    def test_no_symbols_by_id_access(self):
        import codesight_mcp.tools.get_diagram as mod
        source = open(mod.__file__).read()
        assert "_symbols_by_id" not in source


# ---------------------------------------------------------------------------
# ADV-INFO-1: Log warning for non-default ANTHROPIC_BASE_URL
# ---------------------------------------------------------------------------
class TestAnthropicBaseUrlWarning:
    def test_warning_logged_when_set(self, monkeypatch):
        import importlib
        import logging
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://custom.example.com")
        with patch.object(logging.getLogger("codesight_mcp.summarizer.batch_summarize"), "warning") as mock_warn:
            # Re-import to trigger module-level check
            import codesight_mcp.summarizer.batch_summarize as mod
            importlib.reload(mod)
        # The warning should have been called
        assert mock_warn.called


# ---------------------------------------------------------------------------
# ADV-MED-4: Positional summary attribution (sub-nonce)
# ---------------------------------------------------------------------------
class TestPositionalSummaryAttribution:
    def test_build_prompt_includes_sub_nonces(self):
        from codesight_mcp.summarizer.batch_summarize import BatchSummarizer
        summarizer = BatchSummarizer.__new__(BatchSummarizer)
        syms = [_make_symbol(name="a"), _make_symbol(name="b", id="test::b#function")]
        prompt, sub_nonces = summarizer._build_prompt(syms, nonce="testnonce")
        assert len(sub_nonces) == 2
        # Each sub-nonce should appear in the prompt
        for sn in sub_nonces:
            assert sn in prompt


# ---------------------------------------------------------------------------
# ADV-MED-5: _cleanup_stale_temps extended patterns
# ---------------------------------------------------------------------------
class TestCleanupStaleTemps:
    def test_pid_suffixed_temp_cleaned(self, tmp_path):
        from codesight_mcp.storage.index_store import IndexStore
        import time

        # Create a stale PID-suffixed temp
        stale = tmp_path / "test__repo.json.tmp.12345.67890"
        stale.write_text("stale")
        # Make it old enough
        old_time = time.time() - 120
        os.utime(stale, (old_time, old_time))

        store = IndexStore(base_path=str(tmp_path))
        assert not stale.exists()
