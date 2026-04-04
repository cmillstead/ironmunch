"""Integration tests for the 5 newest tools (RC-003, AEGIS remediation).

Covers the full pipeline: create temp files -> index -> tool call -> verify output.

Tools tested:
    1. get_symbol_context
    2. search_references
    3. get_dependencies
    4. compare_symbols
    5. get_changes
"""

import subprocess

import pytest

from codesight_mcp.tools.index_folder import index_folder
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.get_symbol_context import get_symbol_context
from codesight_mcp.tools.search_references import search_references
from codesight_mcp.tools.get_dependencies import get_dependencies
from codesight_mcp.tools.compare_symbols import compare_symbols
from codesight_mcp.tools.get_changes import get_changes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unwrap(wrapped: str) -> str:
    """Strip untrusted-content boundary markers to get the raw value."""
    lines = wrapped.strip().split("\n")
    if len(lines) >= 3 and lines[0].startswith("<<<UNTRUSTED_CODE_"):
        return "\n".join(lines[1:-1])
    return wrapped


# ---------------------------------------------------------------------------
# Shared fixture: 3 Python files with functions, classes, imports, and calls
# ---------------------------------------------------------------------------

@pytest.fixture
def indexed_project(tmp_path):
    """Create a small Python project, index it, return (repo_id, storage_path, project_dir)."""
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()

    # --- src/utils.py: standalone helpers with stdlib import ---
    (project_dir / "utils.py").write_text(
        "import os\n"
        "import json\n"
        "\n"
        "def helper():\n"
        "    return 42\n"
        "\n"
        "def format_output(data):\n"
        "    return json.dumps(data)\n"
    )

    # --- src/models.py: class hierarchy with internal import ---
    (project_dir / "models.py").write_text(
        "from utils import helper\n"
        "\n"
        "class BaseModel:\n"
        "    def validate(self):\n"
        "        pass\n"
        "\n"
        "class UserModel(BaseModel):\n"
        "    def validate(self):\n"
        "        return helper()\n"
    )

    # --- src/main.py: calls across modules ---
    (project_dir / "main.py").write_text(
        "from utils import helper, format_output\n"
        "from models import UserModel\n"
        "\n"
        "def process():\n"
        "    h = helper()\n"
        "    u = UserModel()\n"
        "    u.validate()\n"
        "    return format_output(h)\n"
    )

    storage = tmp_path / "storage"
    result = index_folder(
        path=str(project_dir),
        use_ai_summaries=False,
        storage_path=str(storage),
        allowed_roots=[str(project_dir)],
    )
    assert result["success"] is True, f"Index failed: {result}"
    return result["repo"], str(storage), str(project_dir)


# ---------------------------------------------------------------------------
# get_symbol_context tests
# ---------------------------------------------------------------------------

class TestGetSymbolContext:
    """Tests for get_symbol_context tool."""

    def test_context_returns_symbol_and_siblings(self, indexed_project):
        """Get context for a function -- verify symbol + siblings returned."""
        repo, storage, _ = indexed_project

        # Find the helper function
        search = search_symbols(repo=repo, query="helper", storage_path=storage)
        helper_results = [
            r for r in search["results"]
            if _unwrap(r["name"]) == "helper" and r["kind"] == "function"
        ]
        assert len(helper_results) >= 1, "helper function not found in index"
        sym_id = _unwrap(helper_results[0]["id"])

        result = get_symbol_context(
            repo=repo, symbol_id=sym_id, storage_path=storage,
        )
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert "symbol" in result
        assert _unwrap(result["symbol"]["name"]) == "helper"
        assert result["symbol"]["kind"] == "function"
        assert "source" in result["symbol"]
        assert _unwrap(result["symbol"]["source"]) != ""

        # Siblings: format_output is a sibling (same file, same parent=None)
        sibling_names = [_unwrap(s["name"]) for s in result["siblings"]]
        assert "format_output" in sibling_names

    def test_context_with_graph(self, indexed_project):
        """Get context with include_graph=True -- verify callers/callees present."""
        repo, storage, _ = indexed_project

        search = search_symbols(repo=repo, query="helper", storage_path=storage)
        helper_results = [
            r for r in search["results"]
            if _unwrap(r["name"]) == "helper" and r["kind"] == "function"
        ]
        assert len(helper_results) >= 1
        sym_id = _unwrap(helper_results[0]["id"])

        result = get_symbol_context(
            repo=repo, symbol_id=sym_id, include_graph=True, storage_path=storage,
        )
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert "graph" in result, "graph section missing when include_graph=True"
        assert "callers" in result["graph"]
        assert "callees" in result["graph"]

    def test_context_nonexistent_symbol(self, indexed_project):
        """Get context for non-existent symbol_id -- verify error handling."""
        repo, storage, _ = indexed_project

        result = get_symbol_context(
            repo=repo, symbol_id="nonexistent::symbol#function", storage_path=storage,
        )
        assert "error" in result
        assert "not found" in result["error"].lower()


# ---------------------------------------------------------------------------
# search_references tests
# ---------------------------------------------------------------------------

class TestSearchReferences:
    """Tests for search_references tool."""

    def test_search_returns_enclosing_symbol(self, indexed_project):
        """Search for a function name -- verify results include enclosing symbol context."""
        repo, storage, _ = indexed_project

        result = search_references(
            repo=repo, query="helper", storage_path=storage,
        )
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert result["result_count"] >= 1

        # At least one hit should have an enclosing symbol
        hits_with_symbol = [
            r for r in result["results"]
            if r.get("enclosing_symbol") is not None
        ]
        assert len(hits_with_symbol) >= 1, "No results had enclosing_symbol context"

        # Verify the enclosing symbol has expected fields
        enc = hits_with_symbol[0]["enclosing_symbol"]
        assert "id" in enc
        assert "kind" in enc
        assert "name" in enc

    def test_search_no_matches(self, indexed_project):
        """Search with no matches -- verify empty result."""
        repo, storage, _ = indexed_project

        result = search_references(
            repo=repo, query="zzz_nonexistent_token_zzz", storage_path=storage,
        )
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert result["result_count"] == 0
        assert result["results"] == []

    def test_search_result_structure(self, indexed_project):
        """Verify results include file, line, and matched text."""
        repo, storage, _ = indexed_project

        result = search_references(
            repo=repo, query="format_output", storage_path=storage,
        )
        assert "error" not in result
        assert result["result_count"] >= 1

        first = result["results"][0]
        assert "file" in first
        assert "line" in first
        assert isinstance(first["line"], int)
        assert "text" in first
        assert "format_output" in _unwrap(first["text"]).lower()


# ---------------------------------------------------------------------------
# get_dependencies tests
# ---------------------------------------------------------------------------

class TestGetDependencies:
    """Tests for get_dependencies tool."""

    def test_internal_imports_detected(self, indexed_project):
        """Analyze dependencies -- verify internal imports detected."""
        repo, storage, _ = indexed_project

        result = get_dependencies(repo=repo, storage_path=storage)
        assert "error" not in result, f"Unexpected error: {result.get('error')}"

        # internal should contain 'utils' or 'models' (imported by main.py/models.py)
        internal_modules = [_unwrap(dep["module"]) for dep in result["internal"]]
        assert len(internal_modules) >= 1, (
            f"Expected at least 1 internal dependency, got: {internal_modules}"
        )
        assert any(
            mod in ("utils", "models") for mod in internal_modules
        ), f"Expected utils or models in internal deps, got: {internal_modules}"

    def test_external_imports_classified(self, indexed_project):
        """Verify external imports (os, json) classified correctly."""
        repo, storage, _ = indexed_project

        result = get_dependencies(repo=repo, storage_path=storage)
        assert "error" not in result

        external_modules = [_unwrap(dep["module"]) for dep in result["external"]]
        # os and json are stdlib, should be classified as external
        assert any(
            mod in ("os", "json") for mod in external_modules
        ), f"Expected os or json in external deps, got: {external_modules}"


# ---------------------------------------------------------------------------
# compare_symbols tests
# ---------------------------------------------------------------------------

class TestCompareSymbols:
    """Tests for compare_symbols tool."""

    def test_detect_diff_after_modification(self, tmp_path):
        """Index same repo twice with a modification -- verify diff detected."""
        project_dir = tmp_path / "compareproj"
        project_dir.mkdir()
        storage = tmp_path / "storage"

        # Version 1
        (project_dir / "app.py").write_text(
            "def greet():\n"
            "    return 'hello'\n"
        )
        result_v1 = index_folder(
            path=str(project_dir),
            use_ai_summaries=False,
            storage_path=str(storage),
            allowed_roots=[str(project_dir)],
        )
        assert result_v1["success"] is True
        repo_v1 = result_v1["repo"]

        # Modify the file and re-index under a different repo name
        project_dir2 = tmp_path / "compareproj_v2"
        project_dir2.mkdir()
        (project_dir2 / "app.py").write_text(
            "def greet():\n"
            "    return 'goodbye'\n"
            "\n"
            "def farewell():\n"
            "    return 'bye'\n"
        )
        result_v2 = index_folder(
            path=str(project_dir2),
            use_ai_summaries=False,
            storage_path=str(storage),
            allowed_roots=[str(project_dir2)],
        )
        assert result_v2["success"] is True
        repo_v2 = result_v2["repo"]

        # Compare
        diff = compare_symbols(
            base_repo=repo_v1, head_repo=repo_v2, storage_path=str(storage),
        )
        assert "error" not in diff, f"Unexpected error: {diff.get('error')}"
        assert "summary" in diff

        total_changes = diff["summary"]["added"] + diff["summary"]["modified"]
        assert total_changes >= 1, (
            f"Expected at least 1 added or modified symbol, got summary: {diff['summary']}"
        )

    def test_compare_identical_indexes(self, tmp_path):
        """Compare identical indexes -- verify no diff."""
        project_dir = tmp_path / "identproj"
        project_dir.mkdir()
        storage = tmp_path / "storage"

        (project_dir / "app.py").write_text(
            "def greet():\n"
            "    return 'hello'\n"
        )
        result = index_folder(
            path=str(project_dir),
            use_ai_summaries=False,
            storage_path=str(storage),
            allowed_roots=[str(project_dir)],
        )
        assert result["success"] is True
        repo_id = result["repo"]

        # Compare repo against itself
        diff = compare_symbols(
            base_repo=repo_id, head_repo=repo_id, storage_path=str(storage),
        )
        assert "error" not in diff, f"Unexpected error: {diff.get('error')}"
        assert diff["summary"]["added"] == 0
        assert diff["summary"]["removed"] == 0
        assert diff["summary"]["modified"] == 0


# ---------------------------------------------------------------------------
# get_changes tests
# ---------------------------------------------------------------------------

class TestGetChanges:
    """Tests for get_changes tool."""

    def test_changes_detects_affected_symbols(self, tmp_path):
        """In a git repo, make a change and commit -- verify affected symbols identified."""
        project_dir = tmp_path / "gitproject"
        project_dir.mkdir()
        storage = tmp_path / "storage"

        # Initialize git repo
        subprocess.run(
            ["git", "init"],
            cwd=str(project_dir), capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(project_dir), capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(project_dir), capture_output=True, check=True,
        )

        # Initial commit
        (project_dir / "app.py").write_text(
            "def greet():\n"
            "    return 'hello'\n"
            "\n"
            "def farewell():\n"
            "    return 'goodbye'\n"
        )
        subprocess.run(
            ["git", "add", "."],
            cwd=str(project_dir), capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=str(project_dir), capture_output=True, check=True,
        )

        # Index after first commit
        idx_result = index_folder(
            path=str(project_dir),
            use_ai_summaries=False,
            storage_path=str(storage),
            allowed_roots=[str(project_dir)],
        )
        assert idx_result["success"] is True
        repo = idx_result["repo"]

        # Modify greet(), leave farewell() unchanged
        (project_dir / "app.py").write_text(
            "def greet():\n"
            "    return 'hi there'\n"
            "\n"
            "def farewell():\n"
            "    return 'goodbye'\n"
        )
        subprocess.run(
            ["git", "add", "."],
            cwd=str(project_dir), capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "update greet"],
            cwd=str(project_dir), capture_output=True, check=True,
        )

        # Re-index to pick up updated symbols
        idx_result2 = index_folder(
            path=str(project_dir),
            use_ai_summaries=False,
            storage_path=str(storage),
            allowed_roots=[str(project_dir)],
        )
        assert idx_result2["success"] is True

        result = get_changes(
            repo=repo,
            git_ref="HEAD~1..HEAD",
            repo_path=str(project_dir),
            storage_path=str(storage),
            allowed_roots=[str(project_dir)],
        )
        assert "error" not in result, f"Unexpected error: {result.get('error')}"
        assert result["changed_files"] >= 1
        assert result["affected_symbol_count"] >= 1

        # greet should be among the affected symbols
        affected_names = [
            _unwrap(s["name"]) for s in result["affected_symbols"]
        ]
        assert "greet" in affected_names, (
            f"Expected 'greet' in affected symbols, got: {affected_names}"
        )
