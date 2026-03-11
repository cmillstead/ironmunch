"""Unit tests for get_hotspots tool."""

import pytest
from codesight_mcp.parser import Symbol
from codesight_mcp.storage import IndexStore


def _make_store(tmp_path, symbols):
    """Helper: save symbols to a test index."""
    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="test",
        name="repo",
        source_files=list({s.file for s in symbols}),
        symbols=symbols,
        raw_files={s.file: "# stub" for s in symbols},
        languages={"python": len(set(s.file for s in symbols))},
    )
    return store


def _sym(name, kind="function", file="a.py", complexity=None, calls=None):
    """Helper: create a Symbol with complexity."""
    from codesight_mcp.parser.symbols import make_symbol_id
    sid = make_symbol_id(file, name, kind)
    return Symbol(
        id=sid, file=file, name=name, qualified_name=name,
        kind=kind, language="python", signature=f"def {name}():",
        byte_offset=0, byte_length=10, line=1, end_line=5,
        complexity=complexity or {},
        calls=calls or [],
    )


class TestGetHotspots:

    def test_returns_sorted_by_risk(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("simple", complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 0, "loc": 3}),
            _sym("complex", complexity={"cyclomatic": 10, "cognitive": 20, "max_nesting": 4, "param_count": 5, "loc": 80}),
            _sym("medium", complexity={"cyclomatic": 5, "cognitive": 8, "max_nesting": 2, "param_count": 2, "loc": 30}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", storage_path=str(tmp_path))
        assert "hotspots" in result
        names = [h["name"] for h in result["hotspots"]]
        # complex should be first (highest risk) — name is wrapped
        assert "complex" in names[0]

    def test_sort_by_cyclomatic(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("a", complexity={"cyclomatic": 3, "cognitive": 20, "max_nesting": 0, "param_count": 0, "loc": 5}),
            _sym("b", complexity={"cyclomatic": 10, "cognitive": 1, "max_nesting": 0, "param_count": 0, "loc": 5}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", sort_by="complexity", storage_path=str(tmp_path))
        assert "b" in result["hotspots"][0]["name"]

    def test_sort_by_cognitive(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("a", complexity={"cyclomatic": 20, "cognitive": 1, "max_nesting": 0, "param_count": 0, "loc": 5}),
            _sym("b", complexity={"cyclomatic": 1, "cognitive": 20, "max_nesting": 0, "param_count": 0, "loc": 5}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", sort_by="cognitive", storage_path=str(tmp_path))
        assert "b" in result["hotspots"][0]["name"]

    def test_path_filter(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("a", file="src/a.py", complexity={"cyclomatic": 5, "cognitive": 5, "max_nesting": 2, "param_count": 0, "loc": 10}),
            _sym("b", file="tests/b.py", complexity={"cyclomatic": 10, "cognitive": 10, "max_nesting": 3, "param_count": 0, "loc": 20}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", path="src/", storage_path=str(tmp_path))
        names = [h["name"] for h in result["hotspots"]]
        assert any("\na\n" in n for n in names)
        assert not any("\nb\n" in n for n in names)

    def test_limit(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym(f"f{i}", complexity={"cyclomatic": i, "cognitive": i, "max_nesting": 1, "param_count": 0, "loc": 5})
            for i in range(10)
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", limit=3, storage_path=str(tmp_path))
        assert len(result["hotspots"]) == 3

    def test_excludes_classes_and_constants(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("MyClass", kind="class"),
            _sym("MY_CONST", kind="constant"),
            _sym("func", complexity={"cyclomatic": 5, "cognitive": 5, "max_nesting": 1, "param_count": 0, "loc": 10}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", storage_path=str(tmp_path))
        kinds = {h["kind"] for h in result["hotspots"]}
        assert "class" not in kinds
        assert "constant" not in kinds

    def test_includes_fan_in_fan_out(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [
            _sym("hub", calls=[], complexity={"cyclomatic": 5, "cognitive": 5, "max_nesting": 1, "param_count": 0, "loc": 10}),
            _sym("caller1", calls=["hub"], complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 0, "loc": 3}),
            _sym("caller2", calls=["hub"], complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 0, "loc": 3}),
        ]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", storage_path=str(tmp_path))
        hub = [h for h in result["hotspots"] if "hub" in h["name"]][0]
        assert hub["fan_in"] == 2

    def test_empty_complexity_skipped(self, tmp_path):
        """Symbols with no complexity data are excluded."""
        from codesight_mcp.tools.get_hotspots import get_hotspots
        symbols = [_sym("bare", complexity={})]
        _make_store(tmp_path, symbols)
        result = get_hotspots(repo="test/repo", storage_path=str(tmp_path))
        assert len(result["hotspots"]) == 0


class TestGetHotspotsPathValidation:
    """Path parameter validation for get_hotspots and get_key_symbols."""

    def test_hotspots_rejects_path_traversal(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        result = get_hotspots(repo="test/repo", path="../etc/passwd", storage_path=str(tmp_path))
        assert "error" in result
        assert "traversal" in result["error"]

    def test_hotspots_rejects_null_bytes_in_path(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        result = get_hotspots(repo="test/repo", path="src/\x00evil", storage_path=str(tmp_path))
        assert "error" in result
        assert "null" in result["error"]

    def test_hotspots_rejects_mid_path_traversal(self, tmp_path):
        from codesight_mcp.tools.get_hotspots import get_hotspots
        result = get_hotspots(repo="test/repo", path="src/../../etc", storage_path=str(tmp_path))
        assert "error" in result
        assert "traversal" in result["error"]

    def test_key_symbols_rejects_path_traversal(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        result = get_key_symbols(repo="test/repo", path="../etc/passwd", storage_path=str(tmp_path))
        assert "error" in result
        assert "traversal" in result["error"]

    def test_key_symbols_rejects_null_bytes_in_path(self, tmp_path):
        from codesight_mcp.tools.get_key_symbols import get_key_symbols
        result = get_key_symbols(repo="test/repo", path="src/\x00evil", storage_path=str(tmp_path))
        assert "error" in result
        assert "null" in result["error"]


def test_get_hotspots_rejects_invalid_sort_by(tmp_path):
    """get_hotspots should reject sort_by values not in the allowlist."""
    from codesight_mcp.tools.get_hotspots import get_hotspots
    # Create a real indexed repo so the error comes from sort_by validation, not missing repo
    symbols = [
        _sym("func", complexity={"cyclomatic": 5, "cognitive": 5, "max_nesting": 1, "param_count": 0, "loc": 10}),
    ]
    _make_store(tmp_path, symbols)
    result = get_hotspots(repo="test/repo", sort_by="<script>", storage_path=str(tmp_path))
    assert "error" in result
    assert "sort_by" in result["error"].lower() or "invalid" in result["error"].lower()
