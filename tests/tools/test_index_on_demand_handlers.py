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

import gzip
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

from codesight_mcp.core.freshness import INDEX_AGE_THRESHOLD_DAYS
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools._common import _clear_shared_stores
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.tools.get_file_tree import get_file_tree
from codesight_mcp.tools.get_imports import get_imports
from codesight_mcp.tools.index_folder import (
    folder_repo_identity,
    index_folder,
    set_allowed_roots_fn,
)
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.search_text import search_text

_SPOTLIGHT_RE = re.compile(
    r"<<<UNTRUSTED_CODE_[0-9a-f]+>>>\n|\n<<<END_UNTRUSTED_CODE_[0-9a-f]+>>>"
)


def _unwrap(value: str) -> str:
    return _SPOTLIGHT_RE.sub("", value)


@pytest.fixture(autouse=True)
def _hygiene():
    # On-demand indexing is opt-in (default OFF); enable it for these tests via
    # real environment config (not a mock) and restore the prior value after.
    _clear_shared_stores()
    _prev_autoindex = os.environ.get("CODESIGHT_AUTOINDEX")
    os.environ["CODESIGHT_AUTOINDEX"] = "on"
    yield
    if _prev_autoindex is None:
        os.environ.pop("CODESIGHT_AUTOINDEX", None)
    else:
        os.environ["CODESIGHT_AUTOINDEX"] = _prev_autoindex
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


# ---------------------------------------------------------------------------
# helpers for the staleness / warning / early-return tests below
# ---------------------------------------------------------------------------

def _preindex(folder, storage, roots):
    """Index *folder* up front (not on demand) and return (owner, name)."""
    result = index_folder(
        path=str(folder),
        use_ai_summaries=False,
        storage_path=str(storage),
        allowed_roots=[str(r) for r in roots],
    )
    assert result.get("success") is True, f"pre-index failed: {result}"
    return folder_repo_identity(str(folder))


def _backdate(storage, owner, name, days):
    """Rewrite the stored index's ``indexed_at`` to *days* ago (on disk)."""
    store = IndexStore(base_path=str(storage))
    path = store._index_path(owner, name)
    data = json.loads(gzip.decompress(path.read_bytes()))
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    data["indexed_at"] = old
    path.write_bytes(gzip.compress(json.dumps(data).encode("utf-8")))
    _clear_shared_stores()


# ---------------------------------------------------------------------------
# Finding 1: _meta.index_warnings surfaces in an op's OUTPUT (no silent data
# loss, CLAUDE.md rule 8). A skipped secret file trips an index warning that
# must reach the read op's _meta.
# ---------------------------------------------------------------------------

def test_search_text_surfaces_index_warnings_in_meta(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    # A .env file is a secret file -> discovery skips it and emits a warning.
    (repo_dir / ".env").write_text("SECRET=abc123\n")
    storage = tmp_path / "_storage"
    allow(tmp_path)

    result = search_text(
        repo="myrepo",
        query="UNIQ_TOKEN",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" not in result, f"search_text errored instead of indexing: {result}"
    assert result["_meta"].get("freshly_indexed") is True
    warnings = result["_meta"].get("index_warnings")
    assert warnings, f"expected index_warnings in _meta, got: {result['_meta']}"
    assert any("secret" in w.lower() for w in warnings), warnings


# ---------------------------------------------------------------------------
# Finding 2b: no-path + stale index -> handler serves the stale index and
# surfaces _meta.stale=True (availability-monotonic; never errors on this
# branch).
# ---------------------------------------------------------------------------

def test_search_text_no_path_stale_surfaces_stale_meta(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    # Backdate past the 7-day policy. Changing this requires a spec change.
    _backdate(storage, owner, name, INDEX_AGE_THRESHOLD_DAYS + 1)

    # No repo_path -> cannot reindex; the stale index must still serve.
    result = search_text(
        repo=f"{owner}/{name}",
        query="UNIQ_TOKEN",
        storage_path=str(storage),
    )

    assert "error" not in result, f"stale no-path branch errored: {result}"
    assert result["result_count"] >= 1, f"stale index not served: {result}"
    assert result["_meta"].get("stale") is True
    assert result["_meta"].get("freshly_indexed") is None


# ---------------------------------------------------------------------------
# Finding 3: search_symbols on-demand provenance travels through the bespoke
# _ctx_meta intermediate into the top-level _meta (single-repo mode).
# ---------------------------------------------------------------------------

def test_search_symbols_surfaces_freshly_indexed_in_meta(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"  # empty -> forces on-demand
    allow(tmp_path)

    result = search_symbols(
        repo="myrepo",
        query="callee",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" not in result, f"search_symbols errored instead of indexing: {result}"
    assert result["_meta"].get("freshly_indexed") is True


# ---------------------------------------------------------------------------
# Finding 4: early returns must not drop provenance flags. A freshly-indexed
# repo whose target file/path yields no results STILL surfaces
# _meta.freshly_indexed (no silent data loss).
# ---------------------------------------------------------------------------

def test_get_file_outline_missing_file_keeps_provenance(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"  # empty -> forces on-demand
    allow(tmp_path)

    # "missing.py" is not a tracked source file -> "File not found in index"
    # early return, but the index was still freshly built on demand.
    result = get_file_outline(
        repo="myrepo",
        file_path="missing.py",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" in result, f"expected file-not-found error, got: {result}"
    assert "File not found in index" in result["error"]
    assert result.get("_meta", {}).get("freshly_indexed") is True


def test_get_callers_missing_symbol_keeps_provenance(tmp_path, allow):
    """A graph op whose on-demand build SUCCEEDS but whose requested symbol is
    absent still surfaces _meta.freshly_indexed (Finding 4: post-resolution
    error returns from prepare_graph_query must not drop provenance)."""
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"  # empty -> forces on-demand
    allow(tmp_path)

    result = get_callers(
        repo="myrepo",
        symbol_id="does-not-exist::nope",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    # The symbol is absent -> a "Symbol not found" error, but the index WAS
    # freshly built on demand: that provenance must survive the early return.
    assert "error" in result, f"expected symbol-not-found error, got: {result}"
    assert "not found" in result["error"].lower()
    assert result.get("_meta", {}).get("freshly_indexed") is True


def test_get_file_tree_empty_prefix_keeps_provenance(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"  # empty -> forces on-demand
    allow(tmp_path)

    # A prefix that matches no files -> empty-tree early return, but the index
    # was still freshly built on demand.
    result = get_file_tree(
        repo="myrepo",
        path_prefix="does_not_exist/",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    assert "error" not in result, f"get_file_tree errored: {result}"
    assert result["tree"] == []
    assert result.get("_meta", {}).get("freshly_indexed") is True


# ---------------------------------------------------------------------------
# Finding 3 (get_imports provenance): an on-demand build that SUCCEEDS but whose
# requested import file is absent must return an error DICT carrying
# _meta.freshly_indexed -- previously get_imports raised, and the server
# converted the exception to a plain error, dropping the provenance.
# ---------------------------------------------------------------------------

def test_get_imports_missing_file_returns_error_dict_with_provenance(tmp_path, allow):
    repo_dir = _make_repo(tmp_path)
    storage = tmp_path / "_storage"  # empty -> forces on-demand
    allow(tmp_path)

    # "missing.py" is not a tracked source file -> "File not found in index",
    # but the index WAS freshly built on demand: that provenance must survive.
    result = get_imports(
        repo="myrepo",
        file="missing.py",
        storage_path=str(storage),
        repo_path=str(repo_dir),
    )

    # Returned as a dict (not raised), and the provenance is preserved.
    assert isinstance(result, dict)
    assert "error" in result, f"expected file-not-found error, got: {result}"
    assert "File not found in index" in result["error"]
    assert result.get("_meta", {}).get("freshly_indexed") is True
