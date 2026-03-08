"""Integration tests: full index -> search -> get_symbol -> graph pipeline."""

import pytest

from codesight_mcp.tools.index_folder import index_folder
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.get_symbol import get_symbol
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.get_callees import get_callees
from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.tools.get_file_tree import get_file_tree
from codesight_mcp.tools.get_repo_outline import get_repo_outline


@pytest.fixture
def indexed_project(tmp_path):
    """Create a small Python project, index it, return (repo_id, storage_path)."""
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()

    (project_dir / "main.py").write_text(
        "from helper import helper\n\n"
        "def main():\n"
        "    return helper()\n"
    )
    (project_dir / "helper.py").write_text(
        "from util import util\n\n"
        "def helper():\n"
        "    return util()\n"
    )
    (project_dir / "util.py").write_text(
        "def util():\n"
        "    return 42\n"
    )

    storage = tmp_path / "storage"
    result = index_folder(
        path=str(project_dir),
        use_ai_summaries=False,
        storage_path=str(storage),
        allowed_roots=[str(project_dir)],
    )
    assert result["success"] is True, f"Index failed: {result}"
    return result["repo"], str(storage)


def _unwrap(wrapped: str) -> str:
    """Strip untrusted-content boundary markers to get the raw value."""
    lines = wrapped.strip().split("\n")
    # Markers are first and last lines; content is in between
    if len(lines) >= 3 and lines[0].startswith("<<<UNTRUSTED_CODE_"):
        return "\n".join(lines[1:-1])
    return wrapped


def test_index_then_search(indexed_project):
    repo, storage = indexed_project
    result = search_symbols(repo=repo, query="main", storage_path=storage)
    assert result["result_count"] >= 1
    names = [_unwrap(r["name"]) for r in result["results"]]
    assert "main" in names


def test_index_then_get_symbol(indexed_project):
    repo, storage = indexed_project
    search = search_symbols(repo=repo, query="helper", storage_path=storage)
    assert search["result_count"] >= 1
    # Symbol IDs are wrapped; unwrap before passing to get_symbol
    sym_id = _unwrap(search["results"][0]["id"])
    result = get_symbol(repo=repo, symbol_id=sym_id, storage_path=storage)
    assert "error" not in result
    assert "source" in result


def test_index_then_file_outline(indexed_project):
    repo, storage = indexed_project
    result = get_file_outline(repo=repo, file_path="main.py", storage_path=storage)
    assert "error" not in result
    assert len(result.get("symbols", [])) >= 1


def test_index_then_file_tree(indexed_project):
    repo, storage = indexed_project
    result = get_file_tree(repo=repo, storage_path=storage)
    assert "error" not in result
    assert "tree" in result
    assert len(result["tree"]) >= 1


def test_index_then_repo_outline(indexed_project):
    repo, storage = indexed_project
    result = get_repo_outline(repo=repo, storage_path=storage)
    assert "error" not in result
    assert result["file_count"] >= 3
    assert result["symbol_count"] >= 3


def test_index_then_callers(indexed_project):
    repo, storage = indexed_project
    search = search_symbols(repo=repo, query="util", storage_path=storage)
    util_results = [r for r in search["results"] if _unwrap(r["name"]) == "util"]
    if util_results:
        sym_id = _unwrap(util_results[0]["id"])
        result = get_callers(repo=repo, symbol_id=sym_id, storage_path=storage)
        assert "error" not in result
        assert "callers" in result


def test_index_then_callees(indexed_project):
    repo, storage = indexed_project
    search = search_symbols(repo=repo, query="main", storage_path=storage)
    main_results = [r for r in search["results"] if _unwrap(r["name"]) == "main"]
    if main_results:
        sym_id = _unwrap(main_results[0]["id"])
        result = get_callees(repo=repo, symbol_id=sym_id, storage_path=storage)
        assert "error" not in result
        assert "callees" in result


def test_search_with_kind_filter(indexed_project):
    """Search with kind filter returns only matching kinds."""
    repo, storage = indexed_project
    result = search_symbols(repo=repo, query="main", kind="function", storage_path=storage)
    assert result["result_count"] >= 1
    # All results should be functions
    for r in result["results"]:
        assert r["kind"] == "function"


def test_roundtrip_symbol_content(indexed_project):
    """Symbol source from get_symbol should contain the original function body."""
    repo, storage = indexed_project
    search = search_symbols(repo=repo, query="util", storage_path=storage)
    util_results = [r for r in search["results"] if _unwrap(r["name"]) == "util"]
    assert len(util_results) >= 1
    sym_id = _unwrap(util_results[0]["id"])
    result = get_symbol(repo=repo, symbol_id=sym_id, storage_path=storage)
    assert "error" not in result
    source = _unwrap(result["source"])
    assert "42" in source
