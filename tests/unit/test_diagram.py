"""Unit tests for get_diagram tool."""

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


def _sym(name, kind="function", file="a.py", calls=None, inherits_from=None, implements=None, imports=None):
    from codesight_mcp.parser.symbols import make_symbol_id
    sid = make_symbol_id(file, name, kind)
    return Symbol(
        id=sid, file=file, name=name, qualified_name=name,
        kind=kind, language="python", signature=f"def {name}():",
        byte_offset=0, byte_length=10, line=1, end_line=5,
        calls=calls or [],
        inherits_from=inherits_from or [],
        implements=implements or [],
        imports=imports or [],
    )


class TestCallGraphDiagram:

    def test_basic_call_graph(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [
            _sym("foo", calls=["bar"]),
            _sym("bar"),
            _sym("baz", calls=["foo"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo",
            diagram_type="call_graph",
            symbol_id="a.py::foo#function",
            storage_path=str(tmp_path),
        )
        assert "mermaid" in result
        assert "graph" in result["mermaid"]
        assert result["diagram_type"] == "call_graph"
        assert result["node_count"] >= 2

    def test_call_graph_direction(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [_sym("foo"), _sym("bar", calls=["foo"])]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="call_graph",
            symbol_id="a.py::foo#function", direction="LR",
            storage_path=str(tmp_path),
        )
        assert result["mermaid"].startswith("graph LR")

    def test_call_graph_missing_symbol(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        _make_store(tmp_path, [_sym("foo")])
        result = get_diagram(
            repo="test/repo", diagram_type="call_graph",
            symbol_id="a.py::nonexistent#function",
            storage_path=str(tmp_path),
        )
        assert "error" in result


class TestTypeHierarchyDiagram:

    def test_basic_hierarchy(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [
            _sym("Base", kind="class"),
            _sym("Child", kind="class", inherits_from=["Base"]),
            _sym("GrandChild", kind="class", inherits_from=["Child"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="type_hierarchy",
            symbol_id="a.py::Base#class",
            storage_path=str(tmp_path),
        )
        assert "mermaid" in result
        assert result["node_count"] >= 2


class TestImportsDiagram:

    def test_basic_imports(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [
            _sym("foo", file="a.py", imports=["b"]),
            _sym("bar", file="b.py", imports=["c"]),
            _sym("baz", file="c.py"),
        ]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="imports",
            path="a.py",
            storage_path=str(tmp_path),
        )
        assert "mermaid" in result
        assert result["diagram_type"] == "imports"

    def test_imports_default_lr(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [_sym("foo", file="a.py", imports=["b"])]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="imports", path="a.py",
            storage_path=str(tmp_path),
        )
        assert "LR" in result["mermaid"]


class TestImpactDiagram:

    def test_basic_impact(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [
            _sym("core"),
            _sym("mid", calls=["core"]),
            _sym("outer", calls=["mid"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="impact",
            symbol_id="a.py::core#function",
            storage_path=str(tmp_path),
        )
        assert "mermaid" in result
        assert result["node_count"] >= 2

    def test_impact_diagram_no_self_loops(self, tmp_path):
        """Impact diagram should connect predecessor to current, not self-loops."""
        from codesight_mcp.tools.get_diagram import get_diagram, _render_impact
        from codesight_mcp.parser.graph import CodeGraph

        # A -> B -> C (call chain); impact of C should show B->C and A->B edges
        symbols = [
            _sym("A", calls=["B"]),
            _sym("B", calls=["C"]),
            _sym("C"),
        ]
        _make_store(tmp_path, symbols)

        # Build graph directly to inspect _render_impact output
        sym_dicts = [
            {"id": "a.py::A#function", "file": "a.py", "name": "A", "kind": "function",
             "calls": ["B"], "imports": [], "inherits_from": [], "implements": []},
            {"id": "a.py::B#function", "file": "a.py", "name": "B", "kind": "function",
             "calls": ["C"], "imports": [], "inherits_from": [], "implements": []},
            {"id": "a.py::C#function", "file": "a.py", "name": "C", "kind": "function",
             "calls": [], "imports": [], "inherits_from": [], "implements": []},
        ]
        graph = CodeGraph.build(sym_dicts)
        result = _render_impact(graph, "a.py::C#function", None, 3, "TD")

        # Parse mermaid output for self-loop edges (n1 --> n1)
        mermaid = result["mermaid"]
        import re
        edge_pattern = re.compile(r'(n\d+)\s+-->(?:\|[^|]*\|)?\s+(n\d+)')
        for m in edge_pattern.finditer(mermaid):
            src, dst = m.group(1), m.group(2)
            assert src != dst, f"Self-loop detected: {src} --> {dst} in:\n{mermaid}"


class TestDiagramEdgeCases:

    def test_invalid_type(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        _make_store(tmp_path, [_sym("foo")])
        result = get_diagram(
            repo="test/repo", diagram_type="invalid",
            storage_path=str(tmp_path),
        )
        assert "error" in result

    def test_node_limit(self, tmp_path):
        """Diagrams with >50 nodes are truncated."""
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [_sym(f"f{i}", calls=["hub"]) for i in range(60)]
        symbols.append(_sym("hub"))
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="call_graph",
            symbol_id="a.py::hub#function",
            storage_path=str(tmp_path),
        )
        assert result["node_count"] <= 50

    def test_mermaid_escaping(self, tmp_path):
        """Special characters in symbol names are escaped for Mermaid."""
        from codesight_mcp.tools.get_diagram import get_diagram
        symbols = [
            _sym("foo_bar"),
            _sym("call()", calls=["foo_bar"]),
        ]
        _make_store(tmp_path, symbols)
        result = get_diagram(
            repo="test/repo", diagram_type="call_graph",
            symbol_id="a.py::foo_bar#function",
            storage_path=str(tmp_path),
        )
        # Should not crash from special chars
        assert "mermaid" in result

    def test_requires_symbol_id_for_call_graph(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        _make_store(tmp_path, [_sym("foo")])
        result = get_diagram(
            repo="test/repo", diagram_type="call_graph",
            storage_path=str(tmp_path),
        )
        assert "error" in result

    def test_requires_path_for_imports(self, tmp_path):
        from codesight_mcp.tools.get_diagram import get_diagram
        _make_store(tmp_path, [_sym("foo")])
        result = get_diagram(
            repo="test/repo", diagram_type="imports",
            storage_path=str(tmp_path),
        )
        assert "error" in result
