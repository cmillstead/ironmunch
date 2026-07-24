# SPEC_3 — Precision Tiering & Repo Hygiene

Applies to: M2. Fixes audit §6 corrections #3 (config-language noise), #6 (repo hygiene), #9 (stale TODO.md); implements audit §7 "Config-language tiering".

## §1 The problem (verified)

`get-dead-code` on codesight-mcp itself returns 40 findings that are 100% `_bmad/` and `.github` YAML/XML mapping keys (`version`, `updates`, `<task>`), burying real dead code. Two causes: (a) config-format languages contribute "symbols" to analysis tools where the concept is meaningless; (b) committed agent-tooling directories get indexed at all.

## §2 `structural_only` language tier

[DECISION] D5: Add `structural_only: bool = False` to the `LanguageSpec` dataclass (`parser/languages.py:8`, next to `signature_from_name` at L76) and set it `True` for exactly these 7 registry keys: `yaml`, `json`, `toml`, `xml`, `html`, `css`, `scss`. Rationale: these are the formats whose "symbols" are mapping keys/selectors with no call/reference semantics; the audit names yaml/json/toml/xml/html/css explicitly and scss is css-equivalent. Borderline formats stay code-tier deliberately: `dockerfile`, `make`, `cmake`, `hcl`, `nix`, `sql`, `proto`, `graphql` have real dependency/complexity semantics — revisit only via spec amendment.

Semantics of the flag (binding):
- **Still indexed, searchable, retrievable.** `search-symbols`, `search-text`, `get-symbol`, `get-file-outline`, `get-file-tree`, `get-repo-outline` are unaffected. Structural files remain first-class for retrieval — the tier only gates *analysis*.
- **Excluded from analysis outputs:** `get-dead-code`, `analyze-complexity`, `get-key-symbols` (PageRank), and call-graph *edge creation* (`parser/graph.py`) skip symbols whose language spec has `structural_only=True`. `get-callers`/`get-callees`/`get-call-chain`/`get-impact`/`trace-taint` therefore never see them (edges were never created).
- Each affected tool's JSON output gains a boolean-driven note only when relevant: `"excluded_structural_languages": ["yaml", ...]` listing tiers excluded for that repo, so results stay honest about scope.
- Implementation point: one helper in `parser/languages.py` — `def is_structural(language: str) -> bool` — used by tools and `graph.py`. Do not scatter per-tool language string lists.

## §3 Tests for tiering (M2, same commit as the behavior)

`tests/parser/test_structural_tier.py`:
- `test_structural_flag_set_for_exactly_seven_languages` — assert the set equals `{"yaml","json","toml","xml","html","css","scss"}`. `# Changing this requires a spec change.`
- `test_dead_code_excludes_yaml_keys` — index a temp repo containing a `.py` file with one uncalled function and a `.github/dependabot.yml`-style YAML; assert dead-code findings contain the Python symbol and zero YAML symbols.
- `test_complexity_excludes_structural`, `test_key_symbols_excludes_structural` — same fixture pattern.
- `test_graph_has_no_structural_edges` — after indexing, assert no call edge originates from or targets a symbol whose language is structural.
- `test_structural_symbols_still_searchable` — `search-symbols` still returns the YAML key.
- Self-check (integration): `test_self_index_dead_code_has_no_config_findings` — index the repo root (respecting new SKIP_PATTERNS) and assert 0 findings with language in the structural set. This is Gate G1(c).

## §4 Stop indexing agent scaffolding; untrack it

[DECISION] D6: (a) Append to `SKIP_PATTERNS` in `discovery.py:30`: `"_bmad/", "_bmad-output/", ".base/", ".aegis/", ".paul/", ".worktrees/"`. (b) Untrack the same directories plus `.mcp.json`... `.mcp.json` is NOT untracked — it is fixed in M1 (SPEC_2 §3) and stays. Untrack directories with `git rm -r --cached _bmad _bmad-output .base .aegis .paul .worktrees` and add all six to `.gitignore` — **keep them on disk**. Rationale: they may be live local agent tooling; deleting working files from Cevin's machine is not the executing agent's call, but tracking them bloats the tree and pollutes self-indexing. If any of the six do not exist as tracked paths, skip silently.

Tests: extend `tests/spec/test_spec_guards.py` with `test_skip_patterns_include_agent_dirs` (all six strings present in `SKIP_PATTERNS`) and `test_gitignore_covers_agent_dirs`. Add `test_discovery_skips_bmad` in `tests/discovery/` (temp tree with `_bmad/x.yaml` → not discovered).

Doc counts: untracking changes nothing pytest-collected, but the self-index integration test in §3 depends on (a) — land (a) and §3 in the same commit.

## §5 TODO.md → ROADMAP.md

[DECISION] D18: Delete `TODO.md` (3 of its 4 items are checked-off harness chores; the live PyPI item moves to M3/M5). Create `ROADMAP.md` generated from this spec's stage plan: a table of Stages 1–4 with milestone names, one-line goals, and status checkboxes, plus a pointer to `docs/MILESTONE.md` and `docs/spec/MASTER_SPEC.md`. Keep it under 60 lines; it is a signpost, not a second plan. Update the `_DOCS` list in `check_counts.py` only if ROADMAP.md ever states counts (it should not — write it count-free).
