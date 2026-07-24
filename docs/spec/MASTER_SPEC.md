# codesight-mcp — Master Specification (Index)

**Version:** 1.0 (2026-07-18)
**Status:** Ready for execution (Claude Opus). Cross-model review packet prepared but not yet run — see `CROSS_MODEL_REVIEW.md`.
**Supersedes:** Nothing. Derived from `codesight-mcp-audit.md` (2026-07-18, repo at git `00241d6`, v0.6.0).
**Positioning:** Take a mature, security-hardened MCP code-intelligence server from "excellent engine, broken periphery" to a distributable, precise, fresh, multi-repo tool — corrections first, roadmap second.

Full spec is split under `spec/` so agents load only what a task needs.
**Do not load the whole set for a single milestone.**

## Orientation for a fresh agent (read this paragraph, then your reading list)

codesight-mcp (`/Users/cevin/src/codesight-mcp`) is a Python 3.10+ MCP server (v0.6.0) that indexes codebases with tree-sitter and serves 34 operations over 66 languages from gzipped byte-offset indexes in `~/.code-index/`. It is in daily production use (322 repos indexed) and its security layer (`core/validation.py`, `security.py`) is the crown jewel — **nothing you do may weaken it**. The 2026-07-18 audit found no P1 security defects but three P2 periphery failures: the README onboarding dead-ends into a never-installed second repo, the CI doc-count gate (`scripts/check_counts.py`) is failing live on `main`, and config-file "symbols" (YAML/XML keys) drown real results in the analysis tools. This spec fixes all audit findings (Stage 1), unifies distribution around a single installable entrypoint (Stage 2), then builds the roadmap: freshness + resolved call graph (Stage 3) and federated multi-repo / semantic / SAST capabilities (Stage 4). The central invariant across all stages: **`make check` green, counts gate honest, security posture monotonically non-decreasing.**

## The spec set

| File | Contents | Sections |
|---|---|---|
| `spec/SPEC_1_BASELINE_AND_SCAFFOLD.md` | Repo reality map, binding conventions, key constants, Makefile + CI definitions, milestone-0 scaffold (exact files, stubs, guard tests), doc-count drift fix | §1–§9 |
| `spec/SPEC_2_ONBOARDING_AND_DISTRIBUTION.md` | README Quick Start rewrite, `.mcp.json` fix, wrapper generation from `contract/operations.json`, PyPI trusted publisher + uvx | §1–§6 |
| `spec/SPEC_3_PRECISION_AND_HYGIENE.md` | `structural_only` language tiering, `SKIP_PATTERNS` additions, agent-dir untracking, TODO.md → ROADMAP.md | §1–§5 |
| `spec/SPEC_4_SECURITY_AND_TYPING.md` | git-ref argument-injection fix, pip-audit gating, mypy expansion schedule, `scan_security` I/O, PyPI squat closure | §1–§6 |
| `spec/SPEC_5_FRESHNESS_AND_RESOLUTION.md` | `reindex-stale` CLI + hook hardening, resolved call graph design, INDEX_VERSION 3 migration | §1–§5 |
| `spec/SPEC_6_CORPUS_SEMANTICS_SAST.md` | Federated search/impact, embeddings provider completion + hybrid ranking eval, SAST-grade scan-security, benchmark publication | §1–§5 |
| `spec/SPEC_7_MILESTONE_PLAN.md` | All milestones M0–M11 with tasks, exit criteria, stage gates + fallbacks | §1–§6 |

Companion documents (same directory as this index): `RISK_REGISTER.md`, `CLAUDE.handoff.md` (becomes the repo's `CLAUDE.md`), `MILESTONE.md` (becomes `docs/MILESTONE.md`), `CROSS_MODEL_REVIEW.md`, `EXECUTION_PROMPT.md`.

## Reading lists per milestone (load these, nothing more)

| Working on | Load |
|---|---|
| Any task (always) | This index + `SPEC_7_MILESTONE_PLAN.md` §(current milestone) + repo `CLAUDE.md` |
| M0 — Scaffold + counts truth | `SPEC_1` (all) |
| M1 — Onboarding fix | `SPEC_2` §1–§3 |
| M2 — Precision & hygiene | `SPEC_3` (all) + `SPEC_1` §4 (constants) |
| M3 — Security & typing batch 1 | `SPEC_4` §1–§4 |
| M4 — Wrapper unification | `SPEC_2` §4–§5 + `SPEC_1` §4 |
| M5 — PyPI publish | `SPEC_2` §6 + `SPEC_4` §5 |
| M6 — Freshness | `SPEC_5` §1–§2 |
| M7 — Resolved call graph | `SPEC_5` §3–§5 + `SPEC_1` §4 |
| M8 — mypy completion | `SPEC_4` §6 |
| M9 — Federated ops | `SPEC_6` §1–§2 |
| M10 — Semantic maturation | `SPEC_6` §3 |
| M11 — SAST mode + benchmark publication | `SPEC_6` §4–§5 |

## Global conventions (binding for every part)

1. **Authority order on conflict:** repo `CLAUDE.md` > `SPEC_1_BASELINE_AND_SCAFFOLD` > the SPEC part for your milestone > other SPEC parts > `codesight-mcp-audit.md` > existing code > your judgment. When code conflicts with spec, the code is wrong — fix it, don't imitate it.
2. **[DECISION] markers are final.** Do not reopen or work around them. If one blocks you, stop and ask Cevin.
3. **Security posture is monotonic.** Never remove a validation step, cap, `O_NOFOLLOW`, sanitizer, or fail-closed branch. Any change touching `core/validation.py`, `core/limits.py`, `security.py`, `storage/index_store.py` read paths, or `discovery.py` needs a test proving the old attack still fails.
4. **Counts are generated, never hand-typed.** Operation/language/test counts in docs come from `scripts/check_counts.py --write`. Hand-editing a count is a bug.
5. **No mocks.** The test suite policy is real temp dirs, real servers, zero `unittest.mock`. Preserve it.
6. **`make check` green before "done".** No exceptions, including "just this once". The counts gate inside it is never waived.
7. **New behavior ships with tests in the same commit.** Spec constants encoded in tests carry the comment `# Changing this requires a spec change.`
8. **Tool count changes are atomic:** registry change + `scripts/export_contract.py --write` + `scripts/check_counts.py --write` + doc regeneration in one commit, or the gates fail.
9. **Commit style:** `M<n>.<i>: imperative summary` (e.g. `M0.3: add Makefile with check target`).
10. **Stubs are contracts.** `NotImplementedError` bodies with `Spec:` docstrings are implemented to the cited section with the given signature — and stub tool modules are NOT registered until their milestone ([DECISION] D17, SPEC_1 §7).

## Stage-gated build plan

Each stage ends in something whole and usable. Gates measure indispensability via the repo's own `get-usage-stats` operation and hard external checks — not mere shipment. Full milestone detail in `SPEC_7_MILESTONE_PLAN.md`.

### Stage 1 — Truth & Remediation (M0–M3) — every audit §6 correction
Scaffold + doc-count truth (M0), onboarding that works from this repo alone (M1), precision tiering + repo hygiene (M2), git-ref fix + pip-audit gating + mypy batch 1 + scan_security I/O (M3).
**Gate G1:** (a) fresh-machine test: a new user (or clean VM) completes README Quick Start end-to-end using ONLY this repo, ≤ 10 minutes; (b) `make check` green including counts gate; (c) `get-dead-code` on codesight-mcp itself returns 0 config-format findings.
**Fallback if G1 fails:** if the fresh-machine test fails on the wrapper path, demote the wrapper to an "Advanced" README appendix and ship the Python-direct path as the only documented route; if config noise persists, additionally drop structural languages from indexing by default (flag-gated) rather than only from analysis tools.

### Stage 2 — Distribution & Single Source of Truth (M4–M5)
Generate the TS dispatch wrapper in-repo from `contract/operations.json` with a CI drift gate (M4); publish to PyPI via trusted publisher, `uvx codesight-mcp` path, pre-commit count stamping (M5).
**Gate G2:** (a) `uvx codesight-mcp` + `claude mcp add` works on a machine that has never cloned the repo; (b) CI wrapper-drift job green for 2 consecutive weeks; (c) PyPI name owned by Cevin.
**Fallback if G2 fails:** if trusted-publisher setup stalls, ship `pipx install git+https://github.com/cmillstead/codesight-mcp` as the documented path and keep only the name-squat placeholder on PyPI; if wrapper generation proves brittle, freeze the wrapper as vendored static code with a checksum drift gate instead of regeneration.

### Stage 3 — Freshness & Resolution (M6–M8)
`reindex-stale` CLI + hook-driven freshness (M6); resolved, import/scope-aware call graph at INDEX_VERSION 3 (M7); mypy across all 68 modules (M8).
**Gate G3:** (a) stale-repo ratio (repos > 7 days old per `list-repos`) below 20% for 2 consecutive weeks on the live corpus (audit baseline: 232/322 = 72%); (b) resolved-graph precision ≥ 90% and recall ≥ 80% on the labeled benchmark fixture (SPEC_5 §4); (c) `uv run mypy` covers all modules, zero errors.
**Fallback if G3 fails:** resolution below target → ship resolved mode as opt-in `resolution="strict"` parameter, keep name-based as default, and cap Stage 4 SAST claims accordingly; staleness target missed → add cron installation instructions to README rather than building a daemon.

### Stage 4 — Corpus, Semantics, SAST (M9–M11)
Federated cross-repo search/impact (M9); hybrid semantic ranking with measured quality (M10); `scan-security` resolved mode with source→sink evidence + published token-efficiency benchmark (M11).
**Gate G4:** (a) `get-usage-stats` shows federated or semantic operations invoked in ≥ 2 distinct weeks within 30 days of shipping (Cevin actually reaches for them); (b) resolved scan-security produces ≥ 1 true-positive chain with evidence on the seeded vulnerable fixture and 0 false "confirmed" labels on the clean fixture; (c) benchmark results reproducible by a third party from README instructions.
**Fallback if G4 fails:** federated/semantic unused → freeze features, document as experimental, no further investment (the single-repo core remains the product); SAST precision unattainable → permanently keep the "heuristic hotspots" honesty labeling and delete the "confirmed" tier.
