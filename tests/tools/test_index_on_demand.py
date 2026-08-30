"""Behavioral tests for on-demand indexing in RepoContext.resolve (Task 2).

When a read op resolves a repo that is missing or stale (>7d) AND a folder
``path`` is supplied, the folder is indexed on demand through the existing
validated pipeline, then served -- instead of returning "not indexed".

Real temp dirs / real git subprocesses only (no mocks). Freshness is exercised
by backdating the STORED ``indexed_at`` on disk, never ``time.sleep``. The
allowlist is injected exactly as server.py does, via ``set_allowed_roots_fn``.
"""

import gzip
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from codesight_mcp.core.freshness import (
    INDEX_AGE_THRESHOLD_DAYS,
    age_threshold_exceeded,
)
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools._common import RepoContext, _clear_shared_stores
from codesight_mcp.tools.index_folder import (
    folder_repo_identity,
    index_folder,
    set_allowed_roots_fn,
)
from codesight_mcp.tools.search_symbols import search_symbols

_SPOTLIGHT_RE = re.compile(
    r"<<<UNTRUSTED_CODE_[0-9a-f]+>>>\n|\n<<<END_UNTRUSTED_CODE_[0-9a-f]+>>>"
)


def _unwrap(value: str) -> str:
    """Strip untrusted-content boundary markers to recover the raw string."""
    return _SPOTLIGHT_RE.sub("", value)


def _py(func_name: str) -> str:
    return f"def {func_name}():\n    \"\"\"Return a value.\"\"\"\n    return 1\n"


@pytest.fixture(autouse=True)
def _store_and_allowlist_hygiene():
    """Clear the shared store cache and reset the injected allowlist around
    every test so a leaked in-memory index or allowlist can't mask a bug.

    On-demand indexing is a durable write and therefore opt-in (default OFF);
    these tests exercise the enabled behavior, so the CODESIGHT_AUTOINDEX flag
    is turned on for the duration of each test and restored to its prior value
    in teardown (real environment config, not a mock)."""
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
    """Return a callable that injects allowed roots, mirroring server.py."""
    def _set(*roots) -> None:
        resolved = [str(r) for r in roots] or [str(tmp_path)]
        set_allowed_roots_fn(lambda: resolved)
    return _set


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
# (a) never-indexed + path -> indexed then served
# ---------------------------------------------------------------------------

def test_never_indexed_with_path_indexes_and_serves(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), f"expected served context, got error: {ctx}"
    assert ctx.freshly_indexed is True
    names = {sym.get("name") for sym in ctx.index.symbols}
    assert "bar" in names, f"expected symbol 'bar', got {names}"

    # Persisted under the path-derived identity.
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is not None


def test_freshly_indexed_result_is_servable_through_read_op(tmp_path, allow):
    """After on-demand indexing, a real read op (no path) serves the index."""
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("uniquesym"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))
    assert not isinstance(ctx, dict)

    owner, name = folder_repo_identity(str(repo_dir))
    result = search_symbols(repo=f"{owner}/{name}", query="uniquesym", storage_path=str(storage))
    assert "error" not in result, f"read op errored: {result}"
    found = {_unwrap(r["name"]) for r in result["results"]}
    assert "uniquesym" in found, f"symbol not served via read op: {found}"


# ---------------------------------------------------------------------------
# (b) already-indexed fresh -> served WITHOUT reindex
# ---------------------------------------------------------------------------

def test_fresh_index_with_path_not_reindexed(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    _clear_shared_stores()
    stamp1 = IndexStore(base_path=str(storage)).load_index(owner, name).indexed_at

    ctx = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    assert ctx.freshly_indexed is False
    # A reindex would rewrite indexed_at; a fresh serve leaves it untouched.
    assert ctx.index.indexed_at == stamp1


# ---------------------------------------------------------------------------
# (c) stale + matching path -> reindexed fresh
# ---------------------------------------------------------------------------

def test_stale_index_with_matching_path_reindexes(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    # Backdate past the 7-day policy. Changing this requires a spec change.
    _backdate(storage, owner, name, INDEX_AGE_THRESHOLD_DAYS + 1)

    ctx = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    assert ctx.freshly_indexed is True
    # After reindex the stored stamp is recent -> no longer stale.
    assert age_threshold_exceeded(ctx.index.indexed_at) is False


# ---------------------------------------------------------------------------
# (d) no path -> exact existing fallback error
# ---------------------------------------------------------------------------

def test_missing_no_path_returns_existing_error(tmp_path):
    storage = tmp_path / "_storage"
    result = RepoContext.resolve("local/nonexistent", storage_path=str(storage))
    assert isinstance(result, dict) and "error" in result
    msg = result["error"].lower()
    assert "not indexed" in msg or "not found" in msg


def test_missing_bare_name_no_path_returns_not_found(tmp_path):
    storage = tmp_path / "_storage"
    result = RepoContext.resolve("nonexistent", storage_path=str(storage))
    assert isinstance(result, dict) and "error" in result
    assert "not found" in result["error"].lower()


def test_stale_no_path_serves_stale_context(tmp_path, allow):
    """no-path + stale index -> serve the stale index (availability-monotonic),
    never an error. ``stale`` is flagged; ``freshly_indexed`` stays False."""
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    # Backdate past the 7-day policy. Changing this requires a spec change.
    _backdate(storage, owner, name, INDEX_AGE_THRESHOLD_DAYS + 1)

    # No path supplied -> cannot reindex; the stale index must still serve.
    ctx = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage))

    assert not isinstance(ctx, dict), f"stale no-path branch errored: {ctx}"
    assert ctx.stale is True
    assert ctx.freshly_indexed is False
    assert "bar" in {s.get("name") for s in ctx.index.symbols}


# ---------------------------------------------------------------------------
# (e) indexing fails -> fail-safe, nothing persisted or served
# ---------------------------------------------------------------------------

def test_index_failure_no_source_files_falls_back(tmp_path, allow):
    """A folder with no parseable source files fails to index -> error, nothing persisted."""
    repo_dir = tmp_path / "empty"
    repo_dir.mkdir()
    (repo_dir / "notes.txt").write_text("just text, not code\n")
    storage = tmp_path / "_storage"
    allow(tmp_path)

    result = RepoContext.resolve("empty", storage_path=str(storage), path=str(repo_dir))

    assert isinstance(result, dict) and "error" in result
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None


# ---------------------------------------------------------------------------
# (f) freshly_indexed flag surfaced (True on fresh build, False on cache serve)
#     -- covered by (a) True and (b) False; explicit combined assertion here.
# ---------------------------------------------------------------------------

def test_freshly_indexed_flag_true_then_false(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx1 = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))
    assert not isinstance(ctx1, dict)
    assert ctx1.freshly_indexed is True

    ctx2 = RepoContext.resolve(
        f"{ctx1.owner}/{ctx1.name}", storage_path=str(storage), path=str(repo_dir)
    )
    assert not isinstance(ctx2, dict)
    assert ctx2.freshly_indexed is False


# ---------------------------------------------------------------------------
# (g) truncation / exclusion warnings carried forward (no silent data loss)
# ---------------------------------------------------------------------------

def test_index_warnings_carried_into_context(tmp_path, allow):
    """A skipped secret file surfaces a warning that reaches ctx.index_warnings."""
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    (repo_dir / ".env").write_text("SECRET=abc123\n")
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    assert ctx.freshly_indexed is True
    assert ctx.index_warnings, "expected a non-empty warning list (secret skip)"
    assert any("secret" in w.lower() for w in ctx.index_warnings), ctx.index_warnings


# ---------------------------------------------------------------------------
# Storage-key collision: two same-basename folders resolve to their own index
# ---------------------------------------------------------------------------

def test_same_basename_distinct_paths_resolve_independently(tmp_path, allow):
    dir_a = tmp_path / "one" / "myapp"
    dir_a.mkdir(parents=True)
    (dir_a / "a.py").write_text(_py("alpha"))
    dir_b = tmp_path / "two" / "myapp"
    dir_b.mkdir(parents=True)
    (dir_b / "b.py").write_text(_py("beta"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    # Resolve each by its own path-derived identity so the bare-name prefix
    # match cannot short-circuit onto the first-indexed dir. Each path must
    # key to its OWN index (distinct keys via the path hash).
    owner_a, name_a = folder_repo_identity(str(dir_a))
    owner_b, name_b = folder_repo_identity(str(dir_b))
    ctx_a = RepoContext.resolve(f"{owner_a}/{name_a}", storage_path=str(storage), path=str(dir_a))
    ctx_b = RepoContext.resolve(f"{owner_b}/{name_b}", storage_path=str(storage), path=str(dir_b))

    assert not isinstance(ctx_a, dict) and not isinstance(ctx_b, dict)
    assert (ctx_a.owner, ctx_a.name) != (ctx_b.owner, ctx_b.name)
    assert "alpha" in {s.get("name") for s in ctx_a.index.symbols}
    assert "beta" in {s.get("name") for s in ctx_b.index.symbols}


# ---------------------------------------------------------------------------
# Finding 1 (C28 dual-resolution): a bare name + a matching-basename path is
# path-authoritative; a mismatched-basename path is ignored for identity.
# ---------------------------------------------------------------------------

def test_bare_name_matching_path_wins_over_existing_index(tmp_path, allow):
    """A supplied repo_path whose basename matches the bare name is
    authoritative -- it wins over a coincidentally same-named existing index,
    which must be left untouched (Finding 1a)."""
    dir_a = tmp_path / "a" / "myapp"
    dir_a.mkdir(parents=True)
    (dir_a / "a.py").write_text(_py("alpha_unique"))
    dir_b = tmp_path / "b" / "myapp"
    dir_b.mkdir(parents=True)
    (dir_b / "b.py").write_text(_py("beta_unique"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    # Pre-index dir_a so a fresh index named "myapp-<hashA>" already exists.
    owner_a, name_a = _preindex(dir_a, storage, [tmp_path])
    _clear_shared_stores()

    # Resolve the bare name but point at dir_b (same basename, different path).
    ctx = RepoContext.resolve("myapp", storage_path=str(storage), path=str(dir_b))

    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    names = {s.get("name") for s in ctx.index.symbols}
    assert "beta_unique" in names, f"dir_b not served: {names}"
    assert "alpha_unique" not in names, f"served dir_a instead of dir_b: {names}"

    # dir_b was indexed under its OWN path-derived identity.
    owner_b, name_b = folder_repo_identity(str(dir_b))
    assert (owner_b, name_b) != (owner_a, name_a)
    assert IndexStore(base_path=str(storage)).load_index(owner_b, name_b) is not None
    # dir_a's index is untouched (still has alpha, never beta).
    idx_a = IndexStore(base_path=str(storage)).load_index(owner_a, name_a)
    assert "alpha_unique" in {s.get("name") for s in idx_a.symbols}
    assert "beta_unique" not in json.dumps(idx_a.symbols)


def test_bare_name_mismatched_path_ignored_not_indexed(tmp_path, allow):
    """A supplied repo_path whose basename does NOT match the bare name is
    ignored for identity -- the requested repo is served and the unrelated
    folder is never indexed (Finding 1b, cwd-injection guard)."""
    other = tmp_path / "otherrepo"
    other.mkdir()
    (other / "o.py").write_text(_py("other_sym"))
    cwd = tmp_path / "somecwd"
    cwd.mkdir()
    (cwd / "c.py").write_text(_py("cwd_sym"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner_o, name_o = _preindex(other, storage, [tmp_path])
    _clear_shared_stores()

    ctx = RepoContext.resolve("otherrepo", storage_path=str(storage), path=str(cwd))

    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    names = {s.get("name") for s in ctx.index.symbols}
    assert "other_sym" in names, f"otherrepo not served: {names}"
    assert "cwd_sym" not in names, f"served the injected cwd folder: {names}"
    # The cwd folder was never indexed.
    owner_c, name_c = folder_repo_identity(str(cwd))
    assert IndexStore(base_path=str(storage)).load_index(owner_c, name_c) is None


# ---------------------------------------------------------------------------
# Finding 3 (fail-safe): a malformed/unresolvable path on the stale branch must
# never crash the read -- serve the stale index (or a documented error).
# ---------------------------------------------------------------------------

def test_stale_branch_bad_path_serves_stale_not_crash(tmp_path, allow):
    """A stale index is present and repo_path is unresolvable (embedded NUL).
    The directory-swap guard must not raise out of resolve; the stale index is
    served instead (Finding 3)."""
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("stalesym"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    # Backdate past the 7-day policy. Changing this requires a spec change.
    _backdate(storage, owner, name, INDEX_AGE_THRESHOLD_DAYS + 1)

    # An embedded NUL makes Path(...).resolve() raise if used unguarded.
    ctx = RepoContext.resolve("myrepo", storage_path=str(storage), path="bad\x00path")

    assert not isinstance(ctx, dict), f"expected served stale context, got: {ctx}"
    assert ctx.stale is True
    assert ctx.freshly_indexed is False
    assert "stalesym" in {s.get("name") for s in ctx.index.symbols}


# ---------------------------------------------------------------------------
# Idempotence: a second on-demand resolve serves from the persisted index
# ---------------------------------------------------------------------------

def test_idempotent_second_resolve_serves_from_cache(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx1 = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))
    assert not isinstance(ctx1, dict)
    stamp1 = ctx1.index.indexed_at

    ctx2 = RepoContext.resolve(
        f"{ctx1.owner}/{ctx1.name}", storage_path=str(storage), path=str(repo_dir)
    )
    assert not isinstance(ctx2, dict)
    assert ctx2.freshly_indexed is False
    # No second build: the stored stamp is unchanged.
    assert ctx2.index.indexed_at == stamp1


# ---------------------------------------------------------------------------
# Regression: an already-indexed local repo still resolves by bare name, no path
# ---------------------------------------------------------------------------

def test_already_indexed_bare_name_resolves_without_path(tmp_path, allow):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    _preindex(repo_dir, storage, [tmp_path])
    _clear_shared_stores()

    ctx = RepoContext.resolve("myrepo", storage_path=str(storage))
    assert not isinstance(ctx, dict), f"bare-name resolve broke: {ctx}"
    assert ctx.freshly_indexed is False
    assert "bar" in {s.get("name") for s in ctx.index.symbols}


# ---------------------------------------------------------------------------
# Git repo: on-demand indexing works through the real diff-aware pipeline
# ---------------------------------------------------------------------------

def test_never_indexed_git_repo_on_demand(tmp_path, allow):
    repo_dir = tmp_path / "gitrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("gitsym"))
    subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True, check=True)
    storage = tmp_path / "_storage"
    allow(tmp_path)

    ctx = RepoContext.resolve("gitrepo", storage_path=str(storage), path=str(repo_dir))
    assert not isinstance(ctx, dict), f"expected served context, got: {ctx}"
    assert ctx.freshly_indexed is True
    assert "gitsym" in {s.get("name") for s in ctx.index.symbols}


# ---------------------------------------------------------------------------
# Finding 1 (read-only contract): CODESIGHT_AUTOINDEX gates the durable write.
# Default is OFF; when OFF the read path performs NO write, so readOnlyHint
# stays honest. These two tests set the flag OFF explicitly (the autouse
# fixture turns it on, then restores the prior value in teardown).
# ---------------------------------------------------------------------------

def test_flag_off_missing_with_path_returns_error_and_writes_nothing(tmp_path, allow):
    """Flag OFF + a missing repo + a valid repo_path -> the existing
    "not indexed"/"not found" error and NOT a single index is written. The
    read-only contract is preserved: no on-demand write happens."""
    os.environ["CODESIGHT_AUTOINDEX"] = "off"
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    result = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))

    assert isinstance(result, dict) and "error" in result
    msg = result["error"].lower()
    assert "not indexed" in msg or "not found" in msg
    # No index was written anywhere on the read path (readOnlyHint honest).
    assert IndexStore(base_path=str(storage)).list_repos() == []
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None


def test_flag_off_stale_with_path_serves_stale_no_reindex(tmp_path, allow):
    """Flag OFF + a stale index + a matching repo_path -> the stale index is
    served (availability-monotonic, the pre-feature behavior) and NOT
    reindexed: the stored ``indexed_at`` is untouched and the served context is
    flagged stale, never freshly_indexed."""
    os.environ["CODESIGHT_AUTOINDEX"] = "off"
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text(_py("bar"))
    storage = tmp_path / "_storage"
    allow(tmp_path)

    owner, name = _preindex(repo_dir, storage, [tmp_path])
    # Backdate past the 7-day policy. Changing this requires a spec change.
    _backdate(storage, owner, name, INDEX_AGE_THRESHOLD_DAYS + 1)
    _clear_shared_stores()
    stale_stamp = IndexStore(base_path=str(storage)).load_index(owner, name).indexed_at

    ctx = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), f"expected served stale context, got: {ctx}"
    assert ctx.stale is True
    assert ctx.freshly_indexed is False
    # No reindex happened: the stored stamp is unchanged (still the stale one).
    _clear_shared_stores()
    assert IndexStore(base_path=str(storage)).load_index(owner, name).indexed_at == stale_stamp
