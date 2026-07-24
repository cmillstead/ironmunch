# SPEC_5 — Freshness & Resolved Call Graph

Applies to: M6 (§1–§2), M7 (§3–§5). Implements audit §7 "Incremental-index daemon using existing hooks" and audit §8 step 1 "Precision & resolution" + step 2 "Incremental / watch-based indexing".

## §1 Freshness architecture (M6)

Baseline: `core/freshness.py` `INDEX_AGE_THRESHOLD_DAYS = 7`; live corpus at audit time had 232/322 repos stale. `hooks/post-commit` and `hooks/post-push` already reindex incrementally via the `codesight-mcp index` CLI with a hardened env-file loader (600-perms check). `IndexStore.incremental_save` + content hashing exist.

[DECISION] D11: **No background daemon and no file-watcher.** Freshness = (a) the existing git hooks, (b) a new `codesight-mcp reindex-stale` CLI subcommand suitable for cron/launchd, (c) staleness surfaced prominently in `get-status`/`list-repos` output. Rationale: this is personal tooling on one Mac Studio; a daemon adds a supervision/failure surface that hooks + cron cover, and the audit's own operational data (hooks exist, staleness persists) shows the gap is *coverage of repos without hooks installed*, which a sweep command fixes.

### §1.1 `reindex-stale` subcommand

- CLI: `codesight-mcp reindex-stale [--max-repos N] [--dry-run] [--no-ai]` (default `--max-repos 25` per run to bound a cron tick; `--no-ai` default **on** — summaries are never regenerated in bulk sweeps. [DECISION] D11a: bulk reindex must not burn Anthropic tokens; rationale: 322-repo sweeps at summary cost would be an expensive no-op.)
- Behavior: iterate sidecar metadata (`.meta.json`, cheap — no gzip decompress), select **local** repos whose age exceeds `INDEX_AGE_THRESHOLD_DAYS` and whose recorded source path still exists and remains inside `CODESIGHT_ALLOWED_ROOTS`; reindex incrementally, oldest first; print a JSON summary `{scanned, stale, reindexed, skipped, errors}`. GitHub-origin indexes are skipped (no silent network fan-out; [DECISION] D11b — remote reindex stays an explicit per-repo user action).
- All existing validation applies unchanged — the sweep goes through the same `index-folder` code path, rate limiter included.
- Install docs: `docs/development-guide.md` gains a "Keeping indexes fresh" section with a crontab line (`0 7 * * * $CODESIGHT_BIN reindex-stale`) and a launchd plist snippet, plus hook installation reminder (`cp hooks/post-commit .git/hooks/`).

### §1.2 Surfacing

- `get-status` output gains `stale_repo_count` and `freshest_options` hint text; `list-repos` already shows ages — add a `stale: true` boolean per repo derived from the single policy source `INDEX_AGE_THRESHOLD_DAYS` (never re-derive the number elsewhere).

### §1.3 Tests (M6)

`tests/tools/test_reindex_stale.py`: `test_selects_only_stale_local_repos`, `test_respects_max_repos_oldest_first`, `test_skips_github_origin`, `test_skips_missing_or_disallowed_paths`, `test_dry_run_writes_nothing`, `test_summary_json_shape`. Fixtures: temp `CODE_INDEX_PATH` with hand-written `.meta.json` sidecars at controlled mtimes/ages.

## §2 M6 exit criteria

`make check` green; `reindex-stale` demonstrated on the live corpus (Cevin runs it once manually; result recorded in `docs/MILESTONE.md`); cron/launchd docs merged. Gate G3(a) then measures the 20% staleness target over two weeks.

## §3 Resolved call graph (M7) — design

Baseline: `parser/graph.py` edges are **name-based** — a call to `save()` links to every symbol named `save`. `incremental_save` prunes phantom edges (CHAIN-2) but cross-file resolution is heuristic. This is the accuracy ceiling for `get-callers`, `get-impact`, `trace-taint`, `scan-security`.

[DECISION] D12: Implement **two-pass, import- and scope-aware resolution on top of tree-sitter** in `parser/resolution.py` (stubbed since M0). **LSP integration is rejected for this spec** — revisit only after Stage 4. Rationale: LSP means per-language server processes, lifecycle management, and a giant new attack/complexity surface inside a security-hardened single-process design; import-aware tree-sitter resolution captures the bulk of precision for the top languages actually in the corpus.

[DECISION] D12a: Resolution ships for an explicit language allowlist first: `python`, `typescript`, `javascript`, `go`, `rust` — all other languages keep name-based edges, marked as such. Rationale: these five have the clearest import semantics and dominate Cevin's corpus; 66-language resolution is the breadth-over-precision trap the audit warned about.

### §3.1 Edge model

Each call edge gains two fields: `resolution: "resolved" | "name-based"` and `confidence: 1.0 | 0.5` (exactly these two values; no invented gradations — `# Changing this requires a spec change.`). Existing consumers default absent fields to `"name-based"`/`0.5` so v2 indexes load unchanged.

### §3.2 Pass 1 — import maps (`build_import_map`)

Per file, from the already-extracted import nodes (`LanguageSpec.import_node_types` + `extract_import`): produce `{local_alias: canonical_target}` where canonical_target is `"<module_path>:<symbol>"` or `"<module_path>:*"`. Handle per-language: Python (`import x.y as z`, `from x import y as z`, relative dots resolved against the file's package path), TS/JS (default/named/namespace imports, relative path normalization with extension stripping, `index.*` folding), Go (package alias → package path; calls are `alias.Func`), Rust (`use` trees with `as`, `crate::`/`super::` normalization). No filesystem access beyond what the index already stores (`source_files` list is the module universe).

### §3.3 Pass 2 — edge resolution (`resolve_call_edges`)

For each call site: (1) same-file lexical scope (innermost enclosing class/function locals, then module scope) — resolved if the target symbol is defined in-file; (2) import map — if the call head matches an alias, resolve to the symbol in the target module *if that module is in the index* and defines the name; (3) method calls on `self`/`this` → enclosing class hierarchy (use existing `hierarchy.py` data); (4) otherwise fall back to today's name-based edge, marked `name-based`. Never drop an edge that the old algorithm produced — resolution reclassifies and *retargets*; recall must not regress (Gate G3(b) recall ≥ 80% refers to resolved-tier edges against the labeled fixture).

### §3.4 Storage: INDEX_VERSION 3

Bump `INDEX_VERSION` to 3 in the same commit that writes the new edge fields. v3 readers **must** still read v2 (absent fields defaulted per §3.1); forward-version rejection unchanged (`stored_version > INDEX_VERSION` → reject). `_validate_index_schema`/`_sanitize_loaded_symbols` extend to validate `resolution` against the two-value enum and `confidence` against the two floats — reject anything else (crafted-index defense, same posture as the existing `kind` allowlist). Update guard test `test_index_version_is_2` → `test_index_version_is_3` in the same commit, plus spec amendment note in `docs/MILESTONE.md`. Version bump to v0.8.0 (SPEC_1 §9).

## §4 Precision benchmark (M7, ships before the algorithm)

Create `tests/benchmark/resolution_corpus/` — a small fixed fixture package per allowlisted language (~30 call sites each) with a hand-labeled ground truth file `edges_expected.json` (`{caller_id, callee_id}` pairs). Test `tests/benchmark/test_resolution_precision.py::test_precision_and_recall_targets` computes precision/recall of resolved-tier edges against ground truth and asserts **precision ≥ 0.90, recall ≥ 0.80** (Gate G3(b) numbers; `# Changing this requires a spec change.`). Write the fixture and the failing test FIRST (marked `xfail(strict=False)` until the implementation lands within M7 — the xfail is removed in the implementation commit, never later).

## §5 Consumer updates (M7)

- `get-callers`/`get-callees`/`get-impact`/`get-call-chain`/`trace-taint` outputs include per-edge `resolution` and order resolved edges before name-based ones; response schemas in tool `input_schema`/docs updated (counts untouched — no new operations).
- `get-impact` gains optional `min_confidence` param (enum `[0.5, 1.0]`, default 0.5 — backward compatible).
- Contract regeneration (`make contract`) + `make stamp` in the same commit (SPEC_1 §2 rule 5).
- Existing CHAIN-2 phantom-edge pruning stays — it now applies to name-based tier only.
