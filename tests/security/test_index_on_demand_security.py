"""Security tests for on-demand indexing in RepoContext.resolve (Task 2).

On-demand indexing turns a *read* op into an *index* op, so it inherits the
whole index_folder attack surface. Every test proves the reused pipeline's
guard still fires when the trigger is a read (CLAUDE.md rule 3: any diff to the
_common.py read path needs a test proving the old attack still fails).

Real temp dirs / real git subprocesses / real gzip bombs only -- NO mocks.
The allowlist is injected exactly as server.py does, via set_allowed_roots_fn.
"""

import gzip
import json
import os
from datetime import datetime, timedelta, timezone
from threading import Thread

import pytest

from codesight_mcp.core.freshness import INDEX_AGE_THRESHOLD_DAYS
from codesight_mcp.core.limits import (
    MAX_FILE_COUNT,
    MAX_FILE_SIZE,
    MAX_INDEX_SIZE,
)
from codesight_mcp.security import sanitize_signature_for_api
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools._common import RepoContext, _clear_shared_stores
from codesight_mcp.tools.index_folder import (
    folder_repo_identity,
    index_folder,
    set_allowed_roots_fn,
)


@pytest.fixture(autouse=True)
def _hygiene():
    # On-demand indexing is opt-in (default OFF); these tests prove the reused
    # pipeline's guards still fire when the trigger is a read, so the flag is
    # enabled via real environment config (not a mock) and restored afterward.
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


def _symbol_names(ctx) -> set:
    return {sym.get("name") for sym in ctx.index.symbols}


def _index_files(storage) -> list:
    return list(storage.glob("*.json.gz")) if storage.exists() else []


def _backdate(storage, owner, name, days):
    """Rewrite a stored index's ``indexed_at`` to *days* ago (real on-disk state)."""
    store = IndexStore(base_path=str(storage))
    path = store._index_path(owner, name)
    data = json.loads(gzip.decompress(path.read_bytes()))
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    data["indexed_at"] = old
    path.write_bytes(gzip.compress(json.dumps(data).encode("utf-8")))
    _clear_shared_stores()


# ---------------------------------------------------------------------------
# 1. On-demand indexing OUTSIDE the trusted prefix is refused (nothing written)
# ---------------------------------------------------------------------------

def test_ondemand_outside_allowed_root_refused(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "foo.py").write_text("def bar():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(inside)])  # only 'inside' is trusted

    result = RepoContext.resolve("outside", storage_path=str(storage), path=str(outside))

    assert isinstance(result, dict) and "error" in result
    owner, name = folder_repo_identity(str(outside))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None
    assert _index_files(storage) == []  # nothing was crawled or persisted


# ---------------------------------------------------------------------------
# 2. On-demand with the allowlist UNSET refuses (default-deny)
# ---------------------------------------------------------------------------

def test_ondemand_allowlist_unset_refused(tmp_path):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text("def bar():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(None)  # no allowlist -> default-deny

    result = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))

    assert isinstance(result, dict) and "error" in result
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None
    assert _index_files(storage) == []


# ---------------------------------------------------------------------------
# 3. A symlinked FILE inside the folder is not followed
# ---------------------------------------------------------------------------

def test_ondemand_symlink_file_not_followed(tmp_path):
    secret = tmp_path / "secret_target.py"
    secret.write_text("def leaked_secret_symbol():\n    return 'TOPSECRET'\n")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "real.py").write_text("def realsym():\n    return 1\n")
    (repo_dir / "link.py").symlink_to(secret)
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("repo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    names = _symbol_names(ctx)
    assert "realsym" in names
    assert "leaked_secret_symbol" not in names  # symlink target never indexed


# ---------------------------------------------------------------------------
# 4. A symlinked DIRECTORY escaping the root is not descended into
# ---------------------------------------------------------------------------

def test_ondemand_symlinked_dir_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "escaped.py").write_text("def escaped_symbol():\n    return 1\n")
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "real.py").write_text("def realsym():\n    return 1\n")
    (repo_dir / "sub").symlink_to(outside, target_is_directory=True)
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("repo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    names = _symbol_names(ctx)
    assert "realsym" in names
    assert "escaped_symbol" not in names  # symlinked dir not descended


# ---------------------------------------------------------------------------
# 5. An over-COUNT repo is capped at MAX_FILE_COUNT with a surfaced warning
# ---------------------------------------------------------------------------

@pytest.mark.stress
def test_ondemand_over_count_truncated_and_warned(tmp_path):
    repo_dir = tmp_path / "big"
    repo_dir.mkdir()
    # One more than the cap. Changing MAX_FILE_COUNT requires a spec change.
    for i in range(MAX_FILE_COUNT + 1):
        (repo_dir / f"m{i}.py").write_text(f"def f{i}():\n    return {i}\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("big", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    assert len(ctx.index.source_files) <= MAX_FILE_COUNT
    assert ctx.index_warnings, "truncation must surface a warning (no silent loss)"
    assert any("truncat" in w.lower() for w in ctx.index_warnings), ctx.index_warnings


# ---------------------------------------------------------------------------
# 6. An over-SIZE single file is skipped (per-file cap)
# ---------------------------------------------------------------------------

def test_ondemand_oversize_file_skipped(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "small.py").write_text("def smallsym():\n    return 1\n")
    # A file larger than the 500 KB cap. Changing MAX_FILE_SIZE requires a spec change.
    huge = "# " + ("a" * (MAX_FILE_SIZE + 10)) + "\ndef hugesym():\n    return 1\n"
    (repo_dir / "huge.py").write_text(huge)
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("repo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    names = _symbol_names(ctx)
    assert "smallsym" in names
    assert "hugesym" not in names  # oversize file excluded


# ---------------------------------------------------------------------------
# 7. A secret file is never indexed on demand (excluded + warned, no leak)
# ---------------------------------------------------------------------------

def test_ondemand_secret_file_excluded(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("def appsym():\n    return 1\n")
    (repo_dir / ".env").write_text("API_KEY=sk-supersecretvalue123456\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("repo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    assert "appsym" in _symbol_names(ctx)
    assert any("secret" in w.lower() for w in ctx.index_warnings), ctx.index_warnings
    # The secret value must not appear in any served symbol field.
    for sym in ctx.index.symbols:
        assert "supersecretvalue" not in json.dumps(sym)


# ---------------------------------------------------------------------------
# 8. A traversal path resolving outside the allowlist is refused (nothing written)
# ---------------------------------------------------------------------------

def test_ondemand_traversal_path_refused(tmp_path):
    safe = tmp_path / "safe"
    safe.mkdir()
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "foo.py").write_text("def evilsym():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(safe)])  # only 'safe' trusted

    traversal = str(safe / ".." / "evil")  # resolves to tmp_path/evil, outside safe
    result = RepoContext.resolve("evil", storage_path=str(storage), path=traversal)

    assert isinstance(result, dict) and "error" in result
    owner, name = folder_repo_identity(traversal)
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None
    assert _index_files(storage) == []


# ---------------------------------------------------------------------------
# 9. A folder basename that yields an unsafe identifier is refused cleanly
# ---------------------------------------------------------------------------

def test_ondemand_identifier_injection_refused(tmp_path):
    bad = tmp_path / "bad name"  # space -> generated repo_name has an unsafe char
    bad.mkdir()
    (bad / "foo.py").write_text("def badsym():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(tmp_path)])

    result = RepoContext.resolve("badname", storage_path=str(storage), path=str(bad))

    assert isinstance(result, dict) and "error" in result
    # sanitize_repo_identifier rejected the generated name -> nothing indexed.
    assert IndexStore(base_path=str(storage)).list_repos() == []


# ---------------------------------------------------------------------------
# 10. Stale-reindex directory-swap poisoning is blocked
# ---------------------------------------------------------------------------

def test_stale_directory_swap_poisoning_blocked(tmp_path):
    dir_a = tmp_path / "a" / "proj"
    dir_a.mkdir(parents=True)
    (dir_a / "a.py").write_text("def alpha_only():\n    return 1\n")
    dir_b = tmp_path / "b" / "proj"
    dir_b.mkdir(parents=True)
    (dir_b / "b.py").write_text("def beta_evil():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(tmp_path)])

    # Index dir_a, then make it stale.
    result = index_folder(
        path=str(dir_a), use_ai_summaries=False,
        storage_path=str(storage), allowed_roots=[str(tmp_path)],
    )
    assert result.get("success") is True, result
    owner_a, name_a = folder_repo_identity(str(dir_a))
    _backdate(storage, owner_a, name_a, INDEX_AGE_THRESHOLD_DAYS + 1)

    # Request dir_a's identity but hand over dir_b's path (the swap).
    ctx = RepoContext.resolve(f"{owner_a}/{name_a}", storage_path=str(storage), path=str(dir_b))

    # The swap must NOT be adopted under dir_a's name: serve the stale index.
    assert not isinstance(ctx, dict), ctx
    assert ctx.stale is True
    assert ctx.freshly_indexed is False
    names = _symbol_names(ctx)
    assert "alpha_only" in names
    assert "beta_evil" not in names
    # dir_b's content was never written under dir_a's key.
    idx_a = IndexStore(base_path=str(storage)).load_index(owner_a, name_a)
    assert "beta_evil" not in json.dumps(idx_a.symbols)


# ---------------------------------------------------------------------------
# 10b. Top-level symlink: the persisted identity is derived from the RESOLVED
#      canonical target, consistent with the files that were discovered/read
#      (Finding 2 -- no read-target vs stored-identity mismatch; the identity is
#      taken from the already-resolved folder_path, not a second raw resolve).
# ---------------------------------------------------------------------------

def test_toplevel_symlink_identity_matches_resolved_target(tmp_path):
    real = tmp_path / "realtarget"
    real.mkdir()
    (real / "app.py").write_text("def resolved_target_symbol():\n    return 1\n")
    link = tmp_path / "linkname"  # different basename than the target
    link.symlink_to(real, target_is_directory=True)
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(tmp_path)])

    # Index via the symlink path.
    result = index_folder(
        path=str(link), use_ai_summaries=False,
        storage_path=str(storage), allowed_roots=[str(tmp_path)],
    )
    assert result.get("success") is True, result

    # The stored identity is the RESOLVED target's identity (basename + hash of
    # the canonical path), so read-target and stored-identity never diverge.
    owner, name = folder_repo_identity(str(real))
    assert folder_repo_identity(str(link)) == (owner, name)
    store = IndexStore(base_path=str(storage))
    idx = store.load_index(owner, name)
    assert idx is not None, "index not stored under the resolved-target identity"
    # The files actually read are the target's -> served under that same key.
    assert "resolved_target_symbol" in {s.get("name") for s in idx.symbols}
    # Exactly one index was written (no split between link-name and target-name).
    assert len(_index_files(storage)) == 1, _index_files(storage)


# ---------------------------------------------------------------------------
# 10c. Finding 2: the ON-DEMAND read path (RepoContext.resolve) canonicalizes
#      the supplied path exactly once, so the identity guarded, the identity
#      indexed, and the identity reloaded are all derived from the SAME single
#      resolution. Indexing a symlinked top-level dir on demand must persist and
#      serve under the RESOLVED canonical target's identity, with
#      freshly_indexed set only because the reload matches that identity.
# ---------------------------------------------------------------------------

def test_ondemand_symlink_single_resolution_identity(tmp_path):
    real = tmp_path / "realtarget"
    real.mkdir()
    (real / "app.py").write_text("def resolved_only_symbol():\n    return 1\n")
    link = tmp_path / "linkname"  # different basename than the resolved target
    link.symlink_to(real, target_is_directory=True)
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(tmp_path)])

    # The path-derived identity of the LINK and of the RESOLVED target are the
    # same single resolution -- folder_repo_identity resolves before hashing.
    resolved_identity = folder_repo_identity(str(real))
    assert folder_repo_identity(str(link)) == resolved_identity

    # Resolve on demand via the symlink path (owner/name == resolved identity).
    owner, name = resolved_identity
    ctx = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage), path=str(link))

    assert not isinstance(ctx, dict), ctx
    # freshly_indexed is set only because the reload under the canonical identity
    # succeeded and is fresh (single-resolution invariant held).
    assert ctx.freshly_indexed is True
    assert (ctx.owner, ctx.name) == resolved_identity
    assert "resolved_only_symbol" in _symbol_names(ctx)
    # Persisted exactly once, under the resolved-target identity.
    store = IndexStore(base_path=str(storage))
    assert store.load_index(owner, name) is not None
    assert len(_index_files(storage)) == 1, _index_files(storage)


# ---------------------------------------------------------------------------
# 14. Finding 1 (read-only contract, security angle): with CODESIGHT_AUTOINDEX
#     OFF, the read path performs NO durable write even given a valid path under
#     an allowed root -- the on-demand write is an explicit operator opt-in.
# ---------------------------------------------------------------------------

def test_flag_off_read_path_writes_nothing(tmp_path):
    os.environ["CODESIGHT_AUTOINDEX"] = "off"
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text("def bar():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(tmp_path)])  # a valid, trusted root

    result = RepoContext.resolve("myrepo", storage_path=str(storage), path=str(repo_dir))

    # Missing index + flag off -> the pre-feature error, and nothing written.
    assert isinstance(result, dict) and "error" in result
    owner, name = folder_repo_identity(str(repo_dir))
    assert IndexStore(base_path=str(storage)).load_index(owner, name) is None
    assert _index_files(storage) == []


# ---------------------------------------------------------------------------
# 11. On-demand defaults to AI-off (no network / no API key required)
# ---------------------------------------------------------------------------

def test_ondemand_no_ai_no_network_by_default(tmp_path):
    # With use_ai_summaries=False (the on-demand default), summarize_symbols
    # never instantiates the AI client, so no network call can occur even when
    # a key is configured. The summary is the deterministic Tier-3 signature
    # fallback, not an AI-generated sentence -- an AI summary would fail this
    # exact-value assertion.
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text("def plainsym():\n    return 1\n")  # no docstring
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])

    ctx = RepoContext.resolve("repo", storage_path=str(storage), path=str(repo_dir))

    assert not isinstance(ctx, dict), ctx
    sym = next(s for s in ctx.index.symbols if s.get("name") == "plainsym")
    # Tier-3 fallback for a function == the sanitized signature (deterministic).
    assert sym["summary"] == sanitize_signature_for_api(sym["signature"][:120])


# ---------------------------------------------------------------------------
# 12. Concurrent on-demand resolves of the same path -> one intact index
# ---------------------------------------------------------------------------

def test_concurrent_ondemand_single_intact_index(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "foo.py").write_text("def concsym():\n    return 1\n")
    storage = tmp_path / "_storage"
    set_allowed_roots_fn(lambda: [str(repo_dir)])
    owner, name = folder_repo_identity(str(repo_dir))

    results: dict[int, object] = {}

    def worker(i: int) -> None:
        results[i] = RepoContext.resolve(
            f"{owner}/{name}", storage_path=str(storage), path=str(repo_dir)
        )

    threads = [Thread(target=worker, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for i, res in results.items():
        assert not isinstance(res, dict), f"thread {i} errored: {res}"
        assert "concsym" in _symbol_names(res)
    # The exclusive file lock + deterministic key -> exactly one intact index.
    repos = IndexStore(base_path=str(storage)).list_repos()
    matching = [r for r in repos if r["repo"] == f"{owner}/{name}"]
    assert len(matching) == 1, repos


# ---------------------------------------------------------------------------
# 13. The follow-on load still rejects a malformed / gzip-bomb index
# ---------------------------------------------------------------------------

def test_resolve_rejects_corrupt_index_fails_safe(tmp_path):
    """A corrupt index at the target key makes resolve fail safe, not crash."""
    storage = tmp_path / "_storage"
    storage.mkdir()
    store = IndexStore(base_path=str(storage))
    owner, name = "local", "corrupt-0123456789ab"
    path = store._index_path(owner, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"this is not a valid gzip index at all")
    _clear_shared_stores()

    result = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage))

    assert isinstance(result, dict) and "error" in result


@pytest.mark.stress
def test_resolve_rejects_gzip_bomb_at_key(tmp_path):
    """A gzip bomb at the target key is rejected by the guarded load in resolve."""
    storage = tmp_path / "_storage"
    storage.mkdir()
    store = IndexStore(base_path=str(storage))
    owner, name = "local", "bomb-0123456789ab"
    path = store._index_path(owner, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Decompresses beyond MAX_INDEX_SIZE. Changing it requires a spec change.
    path.write_bytes(gzip.compress(b"\x00" * (MAX_INDEX_SIZE + 1024)))
    _clear_shared_stores()

    result = RepoContext.resolve(f"{owner}/{name}", storage_path=str(storage))

    assert isinstance(result, dict) and "error" in result
