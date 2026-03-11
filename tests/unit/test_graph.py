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
    result = g.get_call_chain("a.py::foo", "a.py::baz", max_depth=5)
    chains = result["paths"]
    assert len(chains) >= 1
    assert chains[0] == ["a.py::foo", "a.py::bar", "a.py::baz"]


def test_call_chain_no_path():
    """get_call_chain returns empty when no path exists."""
    syms = _make_symbols(
        ("a.py::foo", "a.py", "foo", [], []),
        ("a.py::bar", "a.py", "bar", [], []),
    )
    g = CodeGraph.build(syms)
    assert g.get_call_chain("a.py::foo", "a.py::bar") == {"paths": [], "truncated": False}


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


class TestPageRank:
    """Test PageRank on the call graph."""

    def test_empty_graph(self):
        g = CodeGraph.build([])
        ranks = g.pagerank()
        assert ranks == {}

    def test_single_node(self):
        syms = _make_symbols(("a.py::foo", "a.py", "foo", [], []))
        g = CodeGraph.build(syms)
        ranks = g.pagerank()
        assert "a.py::foo" in ranks
        assert abs(ranks["a.py::foo"] - 1.0) < 0.01

    def test_hub_gets_highest_rank(self):
        """A symbol called by many others should rank highest."""
        syms = _make_symbols(
            ("a.py::hub", "a.py", "hub", [], []),
            ("a.py::a", "a.py", "a", ["hub"], []),
            ("b.py::b", "b.py", "b", ["hub"], []),
            ("c.py::c", "c.py", "c", ["hub"], []),
            ("d.py::d", "d.py", "d", ["hub"], []),
        )
        g = CodeGraph.build(syms)
        ranks = g.pagerank()
        assert ranks["a.py::hub"] > ranks["a.py::a"]
        assert ranks["a.py::hub"] > ranks["b.py::b"]

    def test_chain_rank_propagation(self):
        """Rank propagates through call chains: a->b->c, c gets rank from b."""
        syms = _make_symbols(
            ("a.py::a", "a.py", "a", ["b"], []),
            ("a.py::b", "a.py", "b", ["c"], []),
            ("a.py::c", "a.py", "c", [], []),
        )
        g = CodeGraph.build(syms)
        ranks = g.pagerank()
        assert ranks["a.py::c"] > ranks["a.py::a"]

    def test_ranks_sum_to_n(self):
        """All ranks should sum approximately to N."""
        syms = _make_symbols(
            ("a.py::a", "a.py", "a", ["b"], []),
            ("a.py::b", "a.py", "b", ["c"], []),
            ("a.py::c", "a.py", "c", [], []),
        )
        g = CodeGraph.build(syms)
        ranks = g.pagerank()
        total = sum(ranks.values())
        assert abs(total - len(ranks)) < 0.01

    def test_damping_factor(self):
        """Custom damping factor is respected."""
        syms = _make_symbols(
            ("a.py::a", "a.py", "a", ["b"], []),
            ("a.py::b", "a.py", "b", [], []),
        )
        g = CodeGraph.build(syms)
        ranks_85 = g.pagerank(damping=0.85)
        ranks_50 = g.pagerank(damping=0.50)
        assert ranks_85 != ranks_50


class TestPageRankParameterValidation:
    """Task 24: PageRank must clamp parameters to safe bounds."""

    def test_pagerank_clamps_parameters(self):
        """Extreme parameter values should be clamped, not cause divergence."""
        syms = _make_symbols(
            ("a.py::a", "a.py", "a", ["b"], []),
            ("a.py::b", "a.py", "b", [], []),
        )
        g = CodeGraph.build(syms)

        # damping > 0.99 gets clamped to 0.99
        ranks_high_damping = g.pagerank(damping=5.0)
        assert all(r > 0 for r in ranks_high_damping.values())

        # damping < 0.1 gets clamped to 0.1
        ranks_low_damping = g.pagerank(damping=-1.0)
        assert all(r > 0 for r in ranks_low_damping.values())

        # max_iterations = 0 gets clamped to 1
        ranks_zero_iter = g.pagerank(max_iterations=0)
        assert len(ranks_zero_iter) == 2

        # tolerance = 0.0 gets clamped to 1e-10
        ranks_zero_tol = g.pagerank(tolerance=0.0)
        assert len(ranks_zero_tol) == 2

        # Very large max_iterations gets clamped to 1000
        ranks_huge_iter = g.pagerank(max_iterations=999999)
        assert len(ranks_huge_iter) == 2


class TestFingerprint:
    """Test _symbol_fingerprint includes relationship edges."""

    def test_fingerprint_changes_when_calls_change(self):
        from codesight_mcp.parser.graph import _symbol_fingerprint
        syms_v1 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": ["b"],
             "imports": [], "inherits_from": [], "implements": []},
            {"id": "b", "file": "f.py", "name": "b", "calls": [],
             "imports": [], "inherits_from": [], "implements": []},
        ]
        syms_v2 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": ["c"],
             "imports": [], "inherits_from": [], "implements": []},
            {"id": "b", "file": "f.py", "name": "b", "calls": [],
             "imports": [], "inherits_from": [], "implements": []},
        ]
        fp1 = _symbol_fingerprint(syms_v1)
        fp2 = _symbol_fingerprint(syms_v2)
        assert fp1 != fp2, "Fingerprint should change when call lists differ"

    def test_fingerprint_changes_when_inherits_change(self):
        from codesight_mcp.parser.graph import _symbol_fingerprint
        syms_v1 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": [],
             "imports": [], "inherits_from": ["Base"], "implements": []},
        ]
        syms_v2 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": [],
             "imports": [], "inherits_from": ["OtherBase"], "implements": []},
        ]
        fp1 = _symbol_fingerprint(syms_v1)
        fp2 = _symbol_fingerprint(syms_v2)
        assert fp1 != fp2, "Fingerprint should change when inherits_from differs"

    def test_fingerprint_changes_when_imports_change(self):
        from codesight_mcp.parser.graph import _symbol_fingerprint
        syms_v1 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": [],
             "imports": ["os"], "inherits_from": [], "implements": []},
        ]
        syms_v2 = [
            {"id": "a", "file": "f.py", "name": "a", "calls": [],
             "imports": ["sys"], "inherits_from": [], "implements": []},
        ]
        fp1 = _symbol_fingerprint(syms_v1)
        fp2 = _symbol_fingerprint(syms_v2)
        assert fp1 != fp2, "Fingerprint should change when imports differ"
