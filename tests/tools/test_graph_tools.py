"""Tests for the 6 code graph tools: callers, callees, call_chain,
type_hierarchy, imports, and impact.

Each tool is tested at the function level (not through the MCP server)
using a temporary IndexStore with purpose-built symbol graphs.
"""

import re

import pytest

from codesight_mcp.parser import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.get_callees import get_callees
from codesight_mcp.tools.get_call_chain import get_call_chain
from codesight_mcp.tools.get_type_hierarchy import get_type_hierarchy
from codesight_mcp.tools.get_imports import get_imports
from codesight_mcp.tools.get_impact import get_impact

_BOUNDARY_RE = re.compile(r"<<<(?:END_)?UNTRUSTED_CODE_[0-9a-f]+>>>\n?")


def _unwrap(value: str) -> str:
    """Strip content boundary markers from a wrapped string."""
    return _BOUNDARY_RE.sub("", value).strip()


# ---------------------------------------------------------------------------
# Fixture: a small call graph with known relationships
# ---------------------------------------------------------------------------
#
#   main  --calls-->  process  --calls-->  validate
#     \                                      ^
#      `--calls-->  helper  --calls---------'
#
#   BaseModel  <--inherits--  User  --implements-->  Serializable
#                             User  <--inherits--  AdminUser
#
#   File imports:  app.py imports "utils", server.py imports "utils"
#
# ---------------------------------------------------------------------------

SRC = "# stub\n"


def _make_sym(
    file: str,
    name: str,
    kind: str = "function",
    calls: list[str] | None = None,
    imports: list[str] | None = None,
    inherits_from: list[str] | None = None,
    implements: list[str] | None = None,
) -> Symbol:
    sid = f"{file.replace('.', '-').replace('/', '-')}::{name}#{kind}"
    return Symbol(
        id=sid,
        file=file,
        name=name,
        qualified_name=name,
        kind=kind,
        language="python",
        signature=f"def {name}():" if kind == "function" else f"class {name}:",
        summary=f"Stub {name}",
        byte_offset=0,
        byte_length=len(SRC),
        calls=calls or [],
        imports=imports or [],
        inherits_from=inherits_from or [],
        implements=implements or [],
    )


@pytest.fixture
def graph_index(tmp_path):
    """Build an index with a small call graph, type hierarchy, and import edges."""
    symbols = [
        # Call graph
        _make_sym("app.py", "main", calls=["process", "helper"], imports=["utils"]),
        _make_sym("app.py", "process", calls=["validate"]),
        _make_sym("app.py", "helper", calls=["validate"]),
        _make_sym("utils.py", "validate"),
        # Type hierarchy
        _make_sym("models.py", "BaseModel", kind="class"),
        _make_sym("models.py", "User", kind="class", inherits_from=["BaseModel"], implements=["Serializable"]),
        _make_sym("models.py", "AdminUser", kind="class", inherits_from=["User"]),
        _make_sym("models.py", "Serializable", kind="class"),
        # Import edges
        _make_sym("server.py", "serve", imports=["utils"]),
    ]

    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="local",
        name="testgraph",
        source_files=["app.py", "utils.py", "models.py", "server.py"],
        symbols=symbols,
        raw_files={f: SRC for f in ["app.py", "utils.py", "models.py", "server.py"]},
        languages={"python": 4},
    )
    return {"store": store, "path": str(tmp_path)}


def _repo():
    return "local/testgraph"


# ===================================================================
# get_callers
# ===================================================================


class TestGetCallers:
    def test_direct_callers(self, graph_index):
        result = get_callers(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(c["name"]) for c in result["callers"]}
        assert "process" in names
        assert "helper" in names
        assert result["caller_count"] == 2

    def test_transitive_callers_depth_2(self, graph_index):
        result = get_callers(_repo(), "utils-py::validate#function", max_depth=2, storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(c["name"]) for c in result["callers"]}
        # depth 1: process, helper; depth 2: main (calls both)
        assert "main" in names
        assert result["caller_count"] == 3

    def test_no_callers(self, graph_index):
        result = get_callers(_repo(), "app-py::main#function", storage_path=graph_index["path"])
        assert "error" not in result
        assert result["caller_count"] == 0

    def test_symbol_not_found(self, graph_index):
        result = get_callers(_repo(), "nonexistent", storage_path=graph_index["path"])
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_repo_not_found(self, graph_index):
        result = get_callers("local/nosuchrepo", "foo", storage_path=graph_index["path"])
        assert "error" in result

    def test_depth_clamped_to_1(self, graph_index):
        result = get_callers(_repo(), "utils-py::validate#function", max_depth=0, storage_path=graph_index["path"])
        assert result["max_depth"] == 1

    def test_depth_clamped_to_5(self, graph_index):
        result = get_callers(_repo(), "utils-py::validate#function", max_depth=99, storage_path=graph_index["path"])
        assert result["max_depth"] == 5

    def test_result_includes_depth_field(self, graph_index):
        result = get_callers(_repo(), "utils-py::validate#function", max_depth=2, storage_path=graph_index["path"])
        depths = {_unwrap(c["name"]): c["depth"] for c in result["callers"]}
        assert depths["process"] == 1
        assert depths["helper"] == 1
        assert depths["main"] == 2


# ===================================================================
# get_callees
# ===================================================================


class TestGetCallees:
    def test_direct_callees(self, graph_index):
        result = get_callees(_repo(), "app-py::main#function", storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(c["name"]) for c in result["callees"]}
        assert "process" in names
        assert "helper" in names
        assert result["callee_count"] == 2

    def test_transitive_callees_depth_2(self, graph_index):
        result = get_callees(_repo(), "app-py::main#function", max_depth=2, storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(c["name"]) for c in result["callees"]}
        # depth 1: process, helper; depth 2: validate (called by both)
        assert "validate" in names

    def test_no_callees(self, graph_index):
        result = get_callees(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        assert "error" not in result
        assert result["callee_count"] == 0

    def test_symbol_not_found(self, graph_index):
        result = get_callees(_repo(), "nonexistent", storage_path=graph_index["path"])
        assert "error" in result

    def test_depth_clamped(self, graph_index):
        result = get_callees(_repo(), "app-py::main#function", max_depth=99, storage_path=graph_index["path"])
        assert result["max_depth"] == 5


# ===================================================================
# get_call_chain
# ===================================================================


class TestGetCallChain:
    def test_direct_path(self, graph_index):
        result = get_call_chain(
            _repo(), "app-py::main#function", "app-py::process#function",
            storage_path=graph_index["path"],
        )
        assert "error" not in result
        assert result["path_count"] >= 1
        # The path should be [main, process]
        first_path_names = [_unwrap(s["name"]) for s in result["paths"][0]]
        assert first_path_names == ["main", "process"]

    def test_two_hop_path(self, graph_index):
        result = get_call_chain(
            _repo(), "app-py::main#function", "utils-py::validate#function",
            storage_path=graph_index["path"],
        )
        assert "error" not in result
        # Two paths: main->process->validate and main->helper->validate
        assert result["path_count"] == 2

    def test_no_path(self, graph_index):
        result = get_call_chain(
            _repo(), "utils-py::validate#function", "app-py::main#function",
            storage_path=graph_index["path"],
        )
        assert "error" not in result
        assert result["path_count"] == 0

    def test_symbol_not_found(self, graph_index):
        result = get_call_chain(
            _repo(), "nonexistent", "app-py::main#function",
            storage_path=graph_index["path"],
        )
        assert "error" in result

    def test_depth_clamped(self, graph_index):
        result = get_call_chain(
            _repo(), "app-py::main#function", "utils-py::validate#function",
            max_depth=99, storage_path=graph_index["path"],
        )
        assert result["max_depth"] == 10


# ===================================================================
# get_type_hierarchy
# ===================================================================


class TestGetTypeHierarchy:
    def test_parents(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::User#class", storage_path=graph_index["path"])
        assert "error" not in result
        parent_names = {_unwrap(p["name"]) for p in result["parents"]}
        assert "BaseModel" in parent_names

    def test_children(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::User#class", storage_path=graph_index["path"])
        child_names = {_unwrap(c["name"]) for c in result["children"]}
        assert "AdminUser" in child_names

    def test_implements(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::User#class", storage_path=graph_index["path"])
        parent_entries = {_unwrap(p["name"]): p for p in result["parents"]}
        assert "Serializable" in parent_entries
        assert parent_entries["Serializable"]["relationship"] == "implements"

    def test_root_class_no_parents(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::BaseModel#class", storage_path=graph_index["path"])
        assert "error" not in result
        assert result["parent_count"] == 0

    def test_leaf_class_no_children(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::AdminUser#class", storage_path=graph_index["path"])
        assert "error" not in result
        assert result["child_count"] == 0

    def test_grandparent_traversal(self, graph_index):
        result = get_type_hierarchy(_repo(), "models-py::AdminUser#class", storage_path=graph_index["path"])
        parent_names = {_unwrap(p["name"]) for p in result["parents"]}
        # AdminUser -> User -> BaseModel
        assert "User" in parent_names
        assert "BaseModel" in parent_names

    def test_symbol_not_found(self, graph_index):
        result = get_type_hierarchy(_repo(), "nonexistent", storage_path=graph_index["path"])
        assert "error" in result


# ===================================================================
# get_imports
# ===================================================================


class TestGetImports:
    def test_imports_direction(self, graph_index):
        result = get_imports(_repo(), "app.py", direction="imports", storage_path=graph_index["path"])
        assert "error" not in result
        import_names = {_unwrap(r["import_name"]) for r in result["results"]}
        assert "utils" in import_names

    def test_importers_direction(self, graph_index):
        result = get_imports(_repo(), "utils.py", direction="importers", storage_path=graph_index["path"])
        assert "error" not in result
        importer_files = {_unwrap(r["file"]) for r in result["results"]}
        assert "app.py" in importer_files
        assert "server.py" in importer_files

    def test_invalid_direction(self, graph_index):
        result = get_imports(_repo(), "app.py", direction="bogus", storage_path=graph_index["path"])
        assert "error" in result
        assert "invalid direction" in result["error"].lower()

    def test_file_not_in_index(self, graph_index):
        with pytest.raises(Exception):
            get_imports(_repo(), "nonexistent.py", direction="imports", storage_path=graph_index["path"])

    def test_no_imports(self, graph_index):
        result = get_imports(_repo(), "models.py", direction="imports", storage_path=graph_index["path"])
        assert "error" not in result
        assert result["result_count"] == 0


# ===================================================================
# get_impact
# ===================================================================


class TestGetImpact:
    def test_direct_impact(self, graph_index):
        result = get_impact(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(i["name"]) for i in result["impacted"]}
        # validate is called by process and helper
        assert "process" in names
        assert "helper" in names

    def test_transitive_impact(self, graph_index):
        result = get_impact(_repo(), "utils-py::validate#function", max_depth=3, storage_path=graph_index["path"])
        assert "error" not in result
        names = {_unwrap(i["name"]) for i in result["impacted"]}
        # Transitive: validate <- process <- main, validate <- helper <- main
        assert "main" in names

    def test_impact_includes_relationship(self, graph_index):
        result = get_impact(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        for entry in result["impacted"]:
            assert "relationship" in entry

    def test_impact_includes_importers(self, graph_index):
        # validate is in utils.py; app.py and server.py import utils
        result = get_impact(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        names = {_unwrap(i["name"]) for i in result["impacted"]}
        # serve is in server.py which imports utils
        assert "serve" in names

    def test_impact_affected_files(self, graph_index):
        result = get_impact(_repo(), "utils-py::validate#function", storage_path=graph_index["path"])
        assert "affected_files" in result
        assert len(result["affected_files"]) > 0

    def test_no_impact(self, graph_index):
        result = get_impact(_repo(), "app-py::main#function", storage_path=graph_index["path"])
        assert "error" not in result
        # main is the root — nothing calls it
        call_impacts = [i for i in result["impacted"] if i["relationship"] == "calls"]
        assert len(call_impacts) == 0

    def test_symbol_not_found(self, graph_index):
        result = get_impact(_repo(), "nonexistent", storage_path=graph_index["path"])
        assert "error" in result

    def test_depth_clamped_to_10(self, graph_index):
        result = get_impact(_repo(), "utils-py::validate#function", max_depth=99, storage_path=graph_index["path"])
        assert result["max_depth"] == 10


# ===================================================================
# CodeGraph unit tests
# ===================================================================


class TestCodeGraphUnit:
    """Direct tests of CodeGraph.build and query methods."""

    def test_build_empty(self):
        from codesight_mcp.parser.graph import CodeGraph
        graph = CodeGraph.build([])
        assert graph.get_callers("anything") == []
        assert graph.get_callees("anything") == []

    def test_call_chain_cycle_safe(self):
        from codesight_mcp.parser.graph import CodeGraph
        # a -> b -> c -> a (cycle)
        symbols = [
            {"id": "a", "file": "f.py", "name": "a", "calls": ["b"], "imports": [], "inherits_from": [], "implements": []},
            {"id": "b", "file": "f.py", "name": "b", "calls": ["c"], "imports": [], "inherits_from": [], "implements": []},
            {"id": "c", "file": "f.py", "name": "c", "calls": ["a"], "imports": [], "inherits_from": [], "implements": []},
        ]
        graph = CodeGraph.build(symbols)
        # Should not infinite-loop; a->b->c is a valid path
        paths = graph.get_call_chain("a", "c", max_depth=10)
        assert len(paths) >= 1
        assert paths[0] == ["a", "b", "c"]

    def test_name_resolution_same_file_preferred(self):
        from codesight_mcp.parser.graph import CodeGraph
        symbols = [
            {"id": "f1::helper", "file": "f1.py", "name": "helper", "calls": [], "imports": [], "inherits_from": [], "implements": []},
            {"id": "f2::helper", "file": "f2.py", "name": "helper", "calls": [], "imports": [], "inherits_from": [], "implements": []},
            {"id": "f1::main", "file": "f1.py", "name": "main", "calls": ["helper"], "imports": [], "inherits_from": [], "implements": []},
        ]
        graph = CodeGraph.build(symbols)
        # main in f1.py calls "helper" -- should resolve to f1::helper (same file)
        callees = graph.get_callees("f1::main")
        assert callees == ["f1::helper"]

    def test_unresolved_inheritance(self):
        from codesight_mcp.parser.graph import CodeGraph
        symbols = [
            {"id": "cls", "file": "f.py", "name": "Foo", "calls": [], "imports": [], "inherits_from": ["ExternalBase"], "implements": []},
        ]
        graph = CodeGraph.build(symbols)
        hierarchy = graph.get_type_hierarchy("cls")
        # ExternalBase can't be resolved, stored as-is
        assert "ExternalBase" in hierarchy["parents"]
