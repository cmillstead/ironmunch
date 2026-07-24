# CLAUDE.md — codesight-mcp

You are building codesight-mcp per the spec set in `docs/spec/`. This file is binding.
When code you find conflicts with this file or the spec, the code is wrong — fix it,
don't imitate it.

## Orientation (read once)

codesight-mcp is a security-hardened, token-efficient Python MCP server (tree-sitter indexing, 34 operations, 66 languages, gzipped byte-offset indexes under `~/.code-index/`) in daily production use on Cevin's machine (322 indexed repos). Its central invariant: **the security posture is monotonic — validation steps, caps, `O_NOFOLLOW`, sanitizers, and fail-closed branches are never removed or weakened.** The 2026-07-18 audit found the engine excellent and the periphery broken (onboarding, doc-count gate, config-language noise); the spec fixes the periphery first (Stage 1–2), then builds freshness, a resolved call graph, and federated/semantic/SAST features (Stage 3–4). Everything gates on `make check`.

## How to load context (do this, not more)

1. Always: this file + `docs/spec/MASTER_SPEC.md` (index) + `docs/spec/SPEC_7_MILESTONE_PLAN.md` section for the current milestone.
2. Then ONLY the part-files the index's reading list names for your milestone.
3. Current milestone lives in `docs/MILESTONE.md`. Update it when an item or milestone completes.

## Binding rules (violations are bugs, not style choices)

1. **Authority order on conflict:** this file > `SPEC_1_BASELINE_AND_SCAFFOLD` > your milestone's SPEC part > other SPEC parts > the audit document > existing code > your judgment.
2. **[DECISION] markers are final.** Do not reopen or work around them. If one blocks you, stop and ask Cevin.
3. **Security is monotonic.** Any diff touching `core/validation.py`, `core/limits.py`, `security.py`, `discovery.py`, or `storage/index_store.py` read paths needs a test proving the old attack still fails, and the full `tests/security` + `tests/fuzz` suites green.
4. **Fail-safe defaults.** Missing metadata, unknown enum values, unparseable index fields → reject or fall back to the safe branch (deny, name-based, heuristic). Never guess permissive.
5. **Never-waive gate:** `make check` (lint + mypy + counts + full tests) green before anything is "done". No exceptions, including "just this once". The counts gate inside it is the one this project already got burned by.
6. **Counts are generated.** Operation/language/test counts in README/docs come only from `make stamp` (`scripts/check_counts.py --write`). Hand-typing a count is a bug. Tool-count changes are atomic: registry + `make contract` + `make stamp` + wrapper regen (post-M4) in one commit.
7. **No mocks (M12 target).** Tests use real temp dirs, real git repos, real subprocesses. `unittest.mock`/`MagicMock`/`AsyncMock` are being removed from `tests/`; the zero-mock guard test lands in **M12 (De-mock tests + enforce zero-mock guard)**. Until M12 the existing mock usages are tracked, not enforced — do not add new ones.
8. **No data-loss silences.** Truncation (file caps, repo caps, federated budgets) must surface a warning/`truncated` flag in output — never drop silently.
9. **Hostile-input posture.** Index files, git refs, gitignore patterns, GitHub responses, and repo content are attacker-controlled. New parsers validate against closed allowlists (see `_validate_index_schema` for the pattern).
10. **Naming/conventions:** ruff `E,F,W`, line-length 120; Python ≥ 3.10 syntax only; one tool module per operation under `tools/`; kebab-case operation names; error messages routed through `core/errors.sanitize_error`.

## Code navigation — MANDATORY (preserved repo policy)

**DO NOT use Grep/Bash grep/rg/find to search this codebase.** This repo is indexed in codesight-mcp; use the `mcp__codesight__query` dispatch tool for ALL search: `query({operation: "search-text", params: {repo: "codesight-mcp", query: "...", maxResults: 10}})`. Key operations: `search-symbols`, `search-text`, `search-references`, `get-file-outline`, `get-symbol`, `get-symbol-context`, `get-callers`, `get-callees`, `get-impact`, `get-dead-code`, `analyze-complexity`. Use `Read` for reading files; codesight for *finding* things. (If the codesight MCP server is unavailable in a session, say so and fall back — do not silently grep.)

## Key numbers (memorize; from SPEC_1 §4 — agents hallucinate these)

- `MAX_FILE_SIZE` 500 KB · `MAX_FILE_COUNT` 5000 · `MAX_INDEX_SIZE` 200 MB · `MAX_DIRECTORY_DEPTH` 10 · `MAX_PATH_LENGTH` 512
- `MAX_ARGUMENT_LENGTH` 10 000 · `MAX_BATCH_SYMBOLS` 50 · `MAX_SEARCH_RESULTS` 50 · `MAX_CONTEXT_LINES` 100
- `INDEX_VERSION` 2 (becomes 3 only in M7) · `_MAX_REPOS` 500 · LRU index cache 4 · gzip level 6
- `INDEX_AGE_THRESHOLD_DAYS` 7 · `_GIT_REF_MAX` 200 · `MAX_GITIGNORE_PATTERN_LEN` 200 · GitHub timeout 30 s
- Operations 34 (36 after M9) · Languages 66 · structural-only tier: exactly {yaml, json, toml, xml, html, css, scss}
- Resolution edge fields: `resolution ∈ {"resolved","name-based"}`, `confidence ∈ {1.0, 0.5}` — no other values
- Gates: resolution precision ≥ 0.90 / recall ≥ 0.80 · staleness target < 20% · hybrid ranking 0.6 keyword / 0.4 vector
- Federated caps: 100 repos/call, 20 s budget · `reindex-stale` default 25 repos, `--no-ai` on

## Workflow expectations

- `make check` green before claiming any task complete. New behavior needs tests in the same commit; spec constants in tests carry `# Changing this requires a spec change.`
- Interface stubs (`NotImplementedError` + `Spec:` docstring) are contracts: implement to the cited section, keep the signature. Stub tool modules are never `register()`-ed before their milestone ([DECISION] D17).
- Doc/count edits: `make stamp` after, never hand-edit numbers.
- No new top-level packages or runtime dependencies beyond those the SPEC parts name (SPEC_1 §3).
- Commit style: `M<n>.<i>: imperative summary`. One milestone item minimum per session; never span milestones.
- `HUMAN` checklist items (PyPI binding, branch protection, cron install): prepare everything, then stop and tell Cevin exactly what to click.

## Current state

See `docs/MILESTONE.md`. Scaffold ships with: Makefile + guard tests + `--write` counts mode real; `parser/resolution.py`, `tools/_federated.py`, `scripts/generate_wrapper.py` stubbed as contracts (M7/M9/M4); everything else is the live production v0.6.0 codebase — treat it with production care.
