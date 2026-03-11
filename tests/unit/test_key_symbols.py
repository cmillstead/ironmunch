"""Unit tests for get_key_symbols tool."""

import pytest
from codesight_mcp.parser import Symbol
from codesight_mcp.storage import IndexStore


def _make_store(tmp_path, symbols):
    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="test", name="repo",
        source_files=list({s.file for s in symbols}),
        symbols=symbols,
        raw_files={s.file: "# stub" for s in symbols},
        languages={"python": len(set(s.file for s in symbols))},
    )
    return store


def _sym(name, kind="function", file="a.py", calls=None):
    from codesight_mcp.parser.symbols import make_symbol_id
    sid = make_symbol_id(file, name, kind)
    return Symbol(
        id=sid, file=file, name=name, qualified_name=name,
        kind=kind, language="python", signature=f"def {name}():",
        byte_offset=0, byte_length=10, line=1, end_line=5,
        calls=calls or [],
    )


class TestGetKeySymbols:

    def test_hub_ranks_highest(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [
            _sym("hub"),
            _sym("a", calls=["hub"]),
            _sym("b", calls=["hub"]),
            _sym("c", calls=["hub"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", storage_path=str(tmp_path))
        assert "hub" in result["key_symbols"][0]["name"]

    def test_path_filter(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [
            _sym("a", file="src/a.py"),
            _sym("b", file="tests/b.py", calls=["a"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", path="src/", storage_path=str(tmp_path))
        # Names are wrapped with untrusted content markers; check inner content
        assert len(result["key_symbols"]) == 1
        assert "\na\n" in result["key_symbols"][0]["name"]

    def test_kind_filter(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [
            _sym("MyClass", kind="class"),
            _sym("func", kind="function"),
        ]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", kind="class", storage_path=str(tmp_path))
        kinds = {s["kind"] for s in result["key_symbols"]}
        assert kinds == {"class"}

    def test_limit(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [_sym(f"f{i}") for i in range(10)]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", limit=3, storage_path=str(tmp_path))
        assert len(result["key_symbols"]) == 3

    def test_includes_fan_in_out_impact(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [
            _sym("hub"),
            _sym("caller", calls=["hub"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", storage_path=str(tmp_path))
        hub = [s for s in result["key_symbols"] if "hub" in s["name"]][0]
        assert "fan_in" in hub
        assert "fan_out" in hub
        assert "rank" in hub

    def test_total_symbols_count(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        symbols = [_sym(f"f{i}") for i in range(5)]
        _make_store(tmp_path, symbols)
        result = get_key_symbols(repo="test/repo", storage_path=str(tmp_path))
        assert result["total_symbols"] == 5

    def test_empty_repo(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        _make_store(tmp_path, [])
        result = get_key_symbols(repo="test/repo", storage_path=str(tmp_path))
        assert result["key_symbols"] == []

    def test_key_symbols_caps_candidates(self, tmp_path):
        """Verify that get_key_symbols does not process more than _MAX_CANDIDATES symbols."""
        from codesight_mcp.tools.get_key_symbols import get_key_symbols, _MAX_CANDIDATES
        from unittest.mock import patch

        # Create more symbols than _MAX_CANDIDATES
        num_symbols = _MAX_CANDIDATES + 50
        symbols = [_sym(f"f{i}") for i in range(num_symbols)]
        _make_store(tmp_path, symbols)

        # Track how many times get_impact is called
        call_count = 0
        original_get_impact = None

        from codesight_mcp.parser.graph import CodeGraph
        original_get_impact = CodeGraph.get_impact

        def counting_get_impact(self, sid, max_depth=5):
            nonlocal call_count
            call_count += 1
            return original_get_impact(self, sid, max_depth=max_depth)

        with patch.object(CodeGraph, "get_impact", counting_get_impact):
            result = get_key_symbols(repo="test/repo", storage_path=str(tmp_path))

        # get_impact should be called at most _MAX_CANDIDATES times
        assert call_count <= _MAX_CANDIDATES
