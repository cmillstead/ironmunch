# SPEC_6 — Federated Corpus, Semantic Search, SAST Mode, Benchmark Publication

Applies to: M9 (§1–§2), M10 (§3), M11 (§4–§5). Implements audit §8 steps 3–6.

## §1 Federated multi-repo — scope (M9)

The `~/.code-index/` corpus (322 repos at audit time) is the moat. A cross-repo test already exists in the suite; generalize it.

[DECISION] D13: Add exactly **two new operations** — `search-federated` and `impact-federated` — rather than overloading existing tools with a `repo="*"` wildcard. Rationale: federated calls have different cost, caps, and output shape; a wildcard on 34 existing ops multiplies the trust-boundary matrix, while two explicit ops keep the contract additive (34 → 36) and the wrapper generation mechanical.

Registry/count discipline (binding): both tools register in one commit together with `make contract`, `make stamp`, doc updates, and the guard test `test_ops_count_matches_contract` staying green. Language count untouched.

## §2 Federated operation design (M9)

Shared plumbing in `tools/_federated.py` (stubbed since M0):
- `iter_all_indexes(store, limit)` — iterate sidecars, load indexes through the existing LRU (size 4) **without** growing it; process serially, oldest-loaded evicted naturally. Hard caps: `_FED_MAX_REPOS = 100` repos per call (newest-indexed first), and per-call wall budget 20s — on budget exhaustion return partial results with `"truncated": true` and the repos actually scanned. `# Changing these caps requires a spec change.`
- `merge_ranked_results(per_repo, cap)` — merge using the existing `calculate_symbol_score` from `tools/_common.py`, tie-broken by repo freshness (younger index wins), capped at `MAX_SEARCH_RESULTS` (50).

`search-federated` params: `{query: string (required), kind?: enum, language?: string, limit?: 1..50 default 20}` — no `repo` param. Output: search-symbols shape plus `repo` field per hit and a `repos_scanned` count. Untrusted-output framing: same `untrusted: true` classification as `search-symbols`.

`impact-federated` params: `{repo: string (required), symbol_id: string (required), limit?: 1..100 default 50}` — "who across all indexed repos calls/imports anything with this symbol's name (resolved tier preferred)". Cross-repo edges are name-based by definition (indexes are per-repo); output labels every cross-repo edge `resolution: "name-based"` and includes the same honesty note used by scan-security ("potential dependents, not confirmed"). [DECISION] D13a: no cross-repo resolved linking in this spec — building a global symbol table is a Stage-5-sized project; name-based cross-repo hits are already valuable for "who uses this shared lib".

Tests `tests/tools/test_federated.py`: `test_search_spans_multiple_temp_repos`, `test_repo_cap_and_truncation_flag`, `test_results_capped_at_max_search_results`, `test_impact_federated_labels_name_based`, `test_ops_count_is_36_and_contract_synced`, `test_rate_limit_applies_to_federated_ops`.

## §3 Semantic search maturation (M10)

Baseline: `embeddings/providers.py` has `EmbeddingProvider` ABC + working `LocalEmbeddingProvider` (fastembed, `BAAI/bge-base-en-v1.5`); `TODO(Phase 3)` markers for Anthropic/OpenAI providers; `scoring.py` + `store.py` exist; hybrid ranking incomplete; `tests/benchmark/` harness exists.

[DECISION] D14: **Drop the planned AnthropicEmbeddingProvider** (Anthropic has no first-party embeddings API — the TODO's "Voyager" reference is a third-party product) and implement `OpenAIEmbeddingProvider` as an optional extra instead; local fastembed remains the default and the only offline path. Rationale: ship what exists; one hosted provider proves the ABC without a dependency on a partner product.

Work items:
1. `OpenAIEmbeddingProvider(model="text-embedding-3-small", dimensions=1536)` in `providers.py`; activated only when `OPENAI_API_KEY` is set AND `CODESIGHT_EMBEDDING_PROVIDER=openai` (explicit opt-in; [DECISION] D14a: never auto-select a provider that sends code to a hosted API — privacy fail-safe consistent with the repo's security posture). New optional extra `[project.optional-dependencies] semantic-openai = ["openai>=1.0.0,<3.0.0"]`. Remove the two `TODO(Phase 3)` comment lines.
2. Finish hybrid ranking in `embeddings/scoring.py`: final score `0.6 * keyword_score_normalized + 0.4 * cosine_similarity`, both min-max normalized per query. `# [DECISION] D14b: fixed 60/40 weights, tunable only via spec change after M10 eval evidence — no config knob. Rationale: unmeasured knobs rot.`
3. Evaluation harness `tests/benchmark/test_semantic_ranking.py`: a fixed query set (≥ 20 queries with labeled expected top-hit symbols over a fixture corpus) computing MRR. Assert `hybrid_MRR >= keyword_only_MRR` (hybrid must not regress keyword search — the honest bar; a bigger win is measured and *reported*, not asserted). Record measured MRRs in `docs/MILESTONE.md` at M10 exit.
4. README Semantic Search section updated (providers table: local default, openai opt-in, privacy note).

## §4 SAST-grade `scan-security` (M11)

Baseline: heuristic call-name matching, self-labeled "potential hotspots, not confirmed vulnerabilities"; `trace_taint` does forward BFS over the graph. M7 gives resolved edges.

[DECISION] D21: Add `mode: "heuristic" | "resolved"` parameter to `scan-security` (default `"heuristic"`). Resolved mode: for each rule hit, attempt a source→sink chain over **resolved-tier edges only** (confidence 1.0), reusing `trace_taint`'s BFS; findings with a complete chain are labeled `"confirmed_flow": true` and carry `evidence: [symbol_id, ...]` (the chain); everything else stays a hotspot. Default stays heuristic until Gate G4(b) evidence exists. Rationale: "confirmed" claims are only defensible on resolved edges; defaulting to resolved before the precision gate would launder heuristics as facts.

Fixtures (create first): `tests/security/sast_corpus/vulnerable/` — small Python package with a seeded genuine flow (e.g. `flask` request param → `subprocess.run(shell=True)` through two call hops) — and `sast_corpus/clean/` — same shape, flow broken by sanitization/no path. Tests `tests/security/test_scan_security_resolved.py`: `test_vulnerable_fixture_yields_confirmed_chain_with_evidence`, `test_clean_fixture_yields_zero_confirmed`, `test_default_mode_is_heuristic`, `test_resolved_mode_only_uses_confidence_1_edges`. These four tests ARE Gate G4(b).

Honesty rule (binding): output text for confirmed findings says "data-flow path found via resolved call graph" — never "vulnerability confirmed"; SECURITY.md gains a paragraph defining both tiers.

## §5 Benchmark publication (M11)

Make the ~99% token-efficiency claim independently reproducible:
1. Promote `benchmark/four_way_benchmark.py` + `benchmark/token_efficiency.py` into a documented flow: `docs/benchmark.md` with exact commands, corpus definition (a pinned public repo + tag, chosen at execution time from the already-indexed public set), environment, and a results table generated by the scripts (`--markdown` output flag added to both).
2. The README claim links to `docs/benchmark.md` and states the measured number from the last run instead of a hand-waved "~99%" (number is script-generated; treat like a count — regenerate, don't hand-edit; add the file to `check_counts.py` `_DOCS` ONLY if a marker is added for it, else keep it script-stamped with its own `<!-- codesight:benchmark ... -->` marker and a `test_benchmark_doc_fresh` guard that tolerates ±5 percentage points before failing).
3. CI: benchmarks stay out of `make check` and CI required jobs (runtime cost); a manual `workflow_dispatch` job `benchmark` runs them and uploads the markdown artifact.

## §6 M9–M11 shared exit discipline

Every milestone here that touches operations or docs ends with: `make contract && make stamp && make check` green, wrapper regenerated (`make wrapper`, drift job green), `docs/MILESTONE.md` updated with measured numbers (staleness ratio, MRRs, precision/recall, benchmark %), and usage-stats note for Gate G4(a) tracking.
