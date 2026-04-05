"""Tests for circular dependency detection in CodeGraph."""

from codesight_mcp.parser.graph import CodeGraph, _build_import_resolution_map


def _make_symbols_with_imports(*specs):
    """Create symbol dicts with explicit imports.

    Args:
        specs: Tuples of (id, file, name, imports).

    Returns:
        List of symbol dicts suitable for CodeGraph.build().
    """
    return [
        {
            "id": sid,
            "file": f,
            "name": n,
            "kind": "function",
            "calls": [],
            "imports": imps,
            "inherits_from": [],
            "implements": [],
        }
        for sid, f, n, imps in specs
    ]


class TestBuildImportResolutionMap:
    """Tests for the _build_import_resolution_map helper."""

    def test_stem_key(self):
        result = _build_import_resolution_map(["pkg/utils.py"])
        assert result["pkg/utils"] == "pkg/utils.py"

    def test_dotted_key(self):
        result = _build_import_resolution_map(["pkg/utils.py"])
        assert result["pkg.utils"] == "pkg/utils.py"

    def test_basename_key(self):
        result = _build_import_resolution_map(["pkg/utils.py"])
        assert result["utils"] == "pkg/utils.py"

    def test_ambiguous_basename_is_none(self):
        result = _build_import_resolution_map(["a/utils.py", "b/utils.py"])
        assert result["utils"] is None

    def test_ambiguous_basename_but_stems_unambiguous(self):
        result = _build_import_resolution_map(["a/utils.py", "b/utils.py"])
        assert result["a/utils"] == "a/utils.py"
        assert result["b/utils"] == "b/utils.py"

    def test_no_extension_file(self):
        result = _build_import_resolution_map(["Makefile"])
        assert result["Makefile"] == "Makefile"

    def test_flat_file(self):
        result = _build_import_resolution_map(["helpers.py"])
        # stem == basename for flat files
        assert result["helpers"] == "helpers.py"


class TestFindImportCyclesTwoNode:
    """Two-node cycle: a.py -> b.py -> a.py."""

    def test_detects_two_node_cycle(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["b"]),
            ("b.py::g#function", "b.py", "g", ["a"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(["a.py", "b.py"])
        assert total == 1
        assert not truncated
        assert cycles == [["a.py", "b.py"]]


class TestFindImportCyclesThreeNode:
    """Three-node cycle: a -> b -> c -> a."""

    def test_detects_three_node_cycle(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["b"]),
            ("b.py::g#function", "b.py", "g", ["c"]),
            ("c.py::h#function", "c.py", "h", ["a"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["a.py", "b.py", "c.py"],
        )
        assert total == 1
        assert cycles == [["a.py", "b.py", "c.py"]]


class TestFindImportCyclesDAG:
    """DAG (no cycles): a -> b -> c."""

    def test_dag_has_no_cycles(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["b"]),
            ("b.py::g#function", "b.py", "g", ["c"]),
            ("c.py::h#function", "c.py", "h", []),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["a.py", "b.py", "c.py"],
        )
        assert total == 0
        assert cycles == []
        assert not truncated


class TestFindImportCyclesMixed:
    """Mixed: one cycle (a <-> b) and one clean branch (c -> d)."""

    def test_mixed_cycles_and_clean(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["b"]),
            ("b.py::g#function", "b.py", "g", ["a"]),
            ("c.py::h#function", "c.py", "h", ["d"]),
            ("d.py::i#function", "d.py", "i", []),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["a.py", "b.py", "c.py", "d.py"],
        )
        assert total == 1
        assert cycles == [["a.py", "b.py"]]


class TestFindImportCyclesMaxCap:
    """max_cycles cap with 3 SCCs -- deterministic order."""

    def test_max_cycles_truncates(self):
        # Three independent 2-node cycles
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["b"]),
            ("b.py::g#function", "b.py", "g", ["a"]),
            ("c.py::h#function", "c.py", "h", ["d"]),
            ("d.py::i#function", "d.py", "i", ["c"]),
            ("e.py::j#function", "e.py", "j", ["f_mod"]),
            ("f_mod.py::k#function", "f_mod.py", "k", ["e"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["a.py", "b.py", "c.py", "d.py", "e.py", "f_mod.py"],
            max_cycles=2,
        )
        assert total == 3
        assert truncated is True
        assert len(cycles) == 2
        # First two in sorted order
        assert cycles[0] == ["a.py", "b.py"]
        assert cycles[1] == ["c.py", "d.py"]


class TestFindImportCyclesExternalExcluded:
    """External imports should not appear in cycles."""

    def test_external_imports_excluded(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["flask", "b"]),
            ("b.py::g#function", "b.py", "g", ["sqlalchemy"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(["a.py", "b.py"])
        assert total == 0
        assert cycles == []


class TestFindImportCyclesAmbiguousSkipped:
    """Ambiguous basename collisions should be skipped (not form cycles)."""

    def test_ambiguous_keys_skipped(self):
        # Both a/utils.py and b/utils.py exist -> "utils" is ambiguous
        # c.py imports "utils" -> should NOT resolve to either -> no cycle
        symbols = _make_symbols_with_imports(
            ("a/utils.py::f#function", "a/utils.py", "f", ["c"]),
            ("b/utils.py::g#function", "b/utils.py", "g", []),
            ("c.py::h#function", "c.py", "h", ["utils"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["a/utils.py", "b/utils.py", "c.py"],
        )
        # "utils" is ambiguous, so c.py -> utils does not resolve
        # a/utils.py -> c.py is one-way, no cycle
        assert total == 0
        assert cycles == []


class TestFindImportCyclesSelfImportExcluded:
    """Self-imports should not form a cycle."""

    def test_self_import_excluded(self):
        symbols = _make_symbols_with_imports(
            ("a.py::f#function", "a.py", "f", ["a"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(["a.py"])
        assert total == 0
        assert cycles == []


class TestFindImportCyclesDottedForm:
    """Dotted import form (pkg.utils) should resolve to pkg/utils.py."""

    def test_dotted_import_cycle(self):
        symbols = _make_symbols_with_imports(
            ("pkg/a.py::f#function", "pkg/a.py", "f", ["pkg.b"]),
            ("pkg/b.py::g#function", "pkg/b.py", "g", ["pkg.a"]),
        )
        graph = CodeGraph.build(symbols)
        cycles, total, truncated = graph.find_import_cycles(
            ["pkg/a.py", "pkg/b.py"],
        )
        assert total == 1
        assert cycles == [["pkg/a.py", "pkg/b.py"]]


class TestFindImportCyclesIntegration:
    """Integration test with a realistic symbol set."""

    def test_realistic_project_cycle(self):
        symbols = _make_symbols_with_imports(
            ("src/app.py::main#function", "src/app.py", "main",
             ["flask", "src.models", "src.utils"]),
            ("src/models.py::User#class", "src/models.py", "User",
             ["sqlalchemy", "src.utils"]),
            ("src/utils.py::helper#function", "src/utils.py", "helper",
             ["os", "src.models"]),
            ("src/cli.py::run#function", "src/cli.py", "run",
             ["click", "src.app"]),
        )
        graph = CodeGraph.build(symbols)
        source_files = [
            "src/app.py", "src/models.py", "src/utils.py", "src/cli.py",
        ]
        cycles, total, truncated = graph.find_import_cycles(source_files)
        # models <-> utils is a cycle
        assert total == 1
        assert cycles == [["src/models.py", "src/utils.py"]]
        assert not truncated
