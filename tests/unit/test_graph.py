"""Unit tests for CodeGraph."""

from codesight_mcp.parser.graph import CodeGraph


def _make_symbols(*specs):
    """Helper: specs are (id, file, name, calls, inherits_from)."""
    symbols = []
    for sid, file, name, calls, inherits in specs:
        symbols.append({
            "id": sid, "file": file, "name": name,
            "kind": "function", "calls": calls,
            "imports": [], "inherits_from": inherits, "implements": [],
        })
    return symbols


def test_empty_graph():
    g = CodeGraph.build([])
    assert g.get_callers("anything") == []
    assert g.get_callees("anything") == []


def test_direct_call():
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("a.py::bar", "a.py", "bar", [], []),
    )
    g = CodeGraph.build(syms)
    assert g.get_callees("a.py::foo") == ["a.py::bar"]
    assert g.get_callers("a.py::bar") == ["a.py::foo"]


def test_cross_file_call():
    """Calls across files resolve when the callee name is unique."""
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("b.py::bar", "b.py", "bar", [], []),
    )
    g = CodeGraph.build(syms)
    assert g.get_callees("a.py::foo") == ["b.py::bar"]
    assert g.get_callers("b.py::bar") == ["a.py::foo"]


def test_cycle():
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("a.py::bar", "a.py", "bar", ["foo"], []),
    )
    g = CodeGraph.build(syms)
    assert "a.py::bar" in g.get_callees("a.py::foo")
    assert "a.py::foo" in g.get_callees("a.py::bar")


def test_disconnected_subgraphs():
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("a.py::bar", "a.py", "bar", [], []),
        ("b.py::baz", "b.py", "baz", [], []),
    )
    g = CodeGraph.build(syms)
    # baz has no callers
    assert g.get_callers("b.py::baz") == []


def test_self_referential_call():
    """Self-calls are filtered out by the graph builder (target != sid)."""
    syms = _make_symbols(
        ("a.py::rec", "a.py", "rec", ["rec"], []),
    )
    g = CodeGraph.build(syms)
    # Self-calls are excluded by _resolve_calls (target != sid check)
    assert g.get_callees("a.py::rec") == []
    assert g.get_callers("a.py::rec") == []


def test_cache_hit():
    syms = _make_symbols(("a.py::foo", "a.py", "foo", [], []))
    g1 = CodeGraph.get_or_build(syms)
    g2 = CodeGraph.get_or_build(syms)
    assert g1 is g2
    CodeGraph.clear_cache()


def test_cache_miss_after_clear():
    """After clearing cache, get_or_build must return a new instance."""
    syms = _make_symbols(("a.py::foo", "a.py", "foo", [], []))
    g1 = CodeGraph.get_or_build(syms)
    CodeGraph.clear_cache()
    g2 = CodeGraph.get_or_build(syms)
    assert g1 is not g2
    CodeGraph.clear_cache()


def test_call_chain():
    """get_call_chain finds paths between two symbols."""
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("a.py::bar", "a.py", "bar", ["baz"], []),
        ("a.py::baz", "a.py", "baz", [], []),
    )
    g = CodeGraph.build(syms)
    chains = g.get_call_chain("a.py::foo", "a.py::baz", max_depth=5)
    assert len(chains) >= 1
    assert chains[0] == ["a.py::foo", "a.py::bar", "a.py::baz"]


def test_call_chain_no_path():
    """get_call_chain returns empty when no path exists."""
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", [], []),
        ("a.py::bar", "a.py", "bar", [], []),
    )
    g = CodeGraph.build(syms)
    assert g.get_call_chain("a.py::foo", "a.py::bar") == []


def test_type_hierarchy():
    """get_type_hierarchy returns parents and children."""
    syms = [
        {"id": "a.py::Base", "file": "a.py", "name": "Base",
         "kind": "class", "calls": [], "imports": [],
         "inherits_from": [], "implements": []},
        {"id": "a.py::Child", "file": "a.py", "name": "Child",
         "kind": "class", "calls": [], "imports": [],
         "inherits_from": ["Base"], "implements": []},
    ]
    g = CodeGraph.build(syms)
    hierarchy = g.get_type_hierarchy("a.py::Base")
    assert "a.py::Child" in hierarchy["children"]
    child_h = g.get_type_hierarchy("a.py::Child")
    assert "a.py::Base" in child_h["parents"]


def test_impact():
    """get_impact computes transitive reverse closure."""
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", ["bar"], []),
        ("a.py::bar", "a.py", "bar", ["baz"], []),
        ("a.py::baz", "a.py", "baz", [], []),
    )
    g = CodeGraph.build(syms)
    affected = g.get_impact("a.py::baz", max_depth=5)
    assert "a.py::bar" in affected
    assert "a.py::foo" in affected
    assert "a.py::baz" not in affected
