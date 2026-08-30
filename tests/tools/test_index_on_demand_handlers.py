"""Handler-level tests for index-on-demand (Task 3).

Task 2 wired on-demand indexing into ``RepoContext.resolve``; Task 3 threads a
host ``repo_path`` through the read handlers (and ``prepare_graph_query``) so the
capability is reachable end-to-end. These tests drive one non-graph op
(``search_text``) and one graph op (``get_callers``) through a real read call:

- never-indexed repo + a valid ``repo_path`` under an allowed root -> the op
  indexes on demand and returns real results, surfacing ``freshly_indexed`` in
  ``_meta`` (no silent data loss, CLAUDE.md rule 8);
- no ``repo_path`` supplied -> unchanged "not indexed"/"not found" error.

Real temp dirs only (no mocks). The allowlist is injected exactly as server.py
does, via ``set_allowed_roots_fn``.
"""

import re

import pytest

from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools._common import _clear_shared_stores
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.index_folder import (
    folder_repo_identity,
    index_folder,
    set_allowed_roots_fn,
)
from codesight_mcp.tools.search_text import search_text

_SPOTLIGHT_RE = re.compile(
    r"<<<UNTRUSTED_CODE_[0-9a-f]+>>>\n|\n<<<END_UNTRUSTED_CODE_[0-9a-f]+>>>"
)


def _unwrap(value: str) -> str:
    return _SPOTLIGHT_RE.sub("", value)


@pytest.fixture(autouse=True)
def _hygiene():
    _clear_shared_stores()
    yield
    set_allowed_roots_fn(None)
    _clear_shared_stores()


@pytest.fixture
def allow(tmp_path):
    def _set(*roots) -> None:
        resolved = [str(r) for r in roots] or [str(tmp_path)]
        set_allowed_roots_fn(lambda: resolved)
    return _set


def _make_repo(tmp_path):
    """A folder with a caller->callee call edge and a unique text token."""
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text(
        "def callee():\n"
        "    \"\"\"UNIQ_TOKEN marker.\"\"\"\n"
        "    return 1\n"
        "\n"
        "def caller():\n"
        "    return callee()\n"
    )
    return repo_dir


# ---------------------------------------------------------------------------
# non-graph op: search_text
# ---------------------------------------------------------------------------

def test_search_text_indexes_on_demand_with_repo_path(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"
    allow(tmp_path)

    result = search_text(
        repo="myrepo",
        query="UNIQ_TOKEN",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" not in result, f"search_text errored instead of indexing: {result}"
    assert result["result_count"] >= 1, f"no matches served on demand: {result}"
    # No data-loss silence: the on-demand build is surfaced.
    assert result["_meta"].get("freshly_indexed") is True
    # The freshly built index was persisted under the path-derived identity.
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is not None


def test_search_text_without_repo_path_unchanged_error(tmp_path):
    storage = tmp_path / "_storage"
    result = search_text(
        repo="local/nonexistent",
        query="anything",
        storage_path=str(storage),
    )
    assert "error" in result
    msg = result["error"].lower()
    assert "not indexed" in msg or "not found" in msg
    # Nothing was indexed on the no-path branch.
    assert result.get("_meta", {}).get("freshly_indexed") is None


# ---------------------------------------------------------------------------
# graph op: get_callers (via prepare_graph_query)
# ---------------------------------------------------------------------------

def _discover_callee_id(repo_dir, tmp_path):
    """Index into a throwaway storage to learn the callee's symbol id.

    The id is path-derived and therefore identical in any storage, so it is
    valid to reuse against a fresh (empty) storage in the on-demand call.
    """
    probe = tmp_path / "_probe"
    res = index_folder(
        path=str(repo_dir),
        use_ai_summaries=False,
        storage_path=str(probe),
        allowed_roots=[str(tmp_path)],
    )
    assert res.get("success") is True, f"probe index failed: {res}"
    owner, name = folder_repo_identity(str(repo_dir))
    idx = IndexStore(base_path=str(probe)).load_index(owner, name)
    callee = next(s for s in idx.symbols if s.get("name") == "callee")
    _clear_shared_stores()
    return callee["id"]


def test_get_callers_indexes_on_demand_with_repo_path(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    allow(tmp_path)
    callee_id = _discover_callee_id(repo_dir, tmp_path)

    storage = tmp_path / "_storage"  # fresh, empty -> forces on-demand
    owner, name = folder_repo_identity(str(repo_dir))

    result = get_callers(
        repo=f"{owner}/{name}",
        symbol_id=callee_id,
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" not in result, f"get_callers errored instead of indexing: {result}"
    caller_names = {_unwrap(c["name"]) for c in result["callers"]}
    assert "caller" in caller_names, f"caller edge not served on demand: {caller_names}"
    assert result["_meta"].get("freshly_indexed") is True
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is not None


def test_get_callers_without_repo_path_unchanged_error(tmp_path):
    storage = tmp_path / "_storage"
    result = get_callers(
        repo="local/nonexistent",
        symbol_id="app-py::callee",
        storage_path=str(storage),
    )
    assert "error" in result
    msg = result["error"].lower()
    assert "not indexed" in msg or "not found" in msg
