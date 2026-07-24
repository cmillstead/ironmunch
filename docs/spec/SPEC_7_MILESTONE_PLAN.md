# SPEC_7 — Milestone Plan (M0–M11)

Always loaded (with MASTER_SPEC.md). Each milestone lists tasks, the spec sections that define them, and machine-checkable exit criteria. `HUMAN` marks items only Cevin can do; the agent prepares them and stops.

## §1 Stage 1 — Truth & Remediation

### M0 — Enforcement scaffold + counts truth (SPEC_1 §5–§9)
- [ ] M0.1 Create `Makefile` (SPEC_1 §5 verbatim); extend `scripts/ci-local.sh` with typecheck + counts.
- [ ] M0.2 Add `--write` mode to `scripts/check_counts.py` + `tests/scripts/test_check_counts_write.py` (SPEC_1 §6).
- [ ] M0.3 Run `make stamp`; commit regenerated counts (fixes live 2562→actual drift; counts gate goes green).
- [ ] M0.4 Copy spec set → `docs/spec/`; `RISK_REGISTER.md` → `docs/spec/`; `MILESTONE.md` → `docs/MILESTONE.md`.
- [ ] M0.5 Replace `CLAUDE.md` with handoff version (SPEC_1 §8).
- [ ] M0.6 Guard tests `tests/spec/test_spec_guards.py` (SPEC_1 §7.5).
- [ ] M0.7 Stubs: `parser/resolution.py`, `tools/_federated.py`, `scripts/generate_wrapper.py` — unregistered (SPEC_1 §7.6, D17).
- [ ] M0.8 CI: add `wrapper-drift` job with documented pre-M4 skip (SPEC_1 §7.7).

**Exit:** `make check` green end-to-end on a clean checkout (the counts gate passing is the proof the P2 drift correction landed); guard tests green; `git log` shows `M0.*` commits only.

### M1 — Onboarding that works (SPEC_2 §1–§3)
- [ ] M1.1 README Quick Start rewrite: Python entrypoint primary (D1); wrapper → Advanced section with real prerequisites.
- [ ] M1.2 Replace `.mcp.json` with codesight self-registration example.
- [ ] M1.3 `tests/docs/test_readme_onboarding.py` (3 tests, SPEC_2 §2).
- [ ] M1.4 `make stamp` (README edits may touch counted phrases).

**Exit:** onboarding tests green; `make check` green; manual smoke: `claude mcp add codesight -- .venv/bin/codesight-mcp` registers and `get-status` answers (record output in MILESTONE log).

### M2 — Precision & hygiene (SPEC_3)
- [ ] M2.1 `structural_only` flag + `is_structural()` + set for the 7 languages (D5).
- [ ] M2.2 Exclusions in dead-code/complexity/key-symbols/graph edges + `excluded_structural_languages` note.
- [ ] M2.3 `tests/parser/test_structural_tier.py` incl. self-index Gate-G1(c) test.
- [ ] M2.4 SKIP_PATTERNS + untrack `_bmad/ _bmad-output/ .base/ .aegis/ .paul/ .worktrees/` via `git rm -r --cached` + `.gitignore` (D6).
- [ ] M2.5 `TODO.md` → `ROADMAP.md` (D18).

**Exit:** self-index dead-code test shows 0 structural findings; `make check` green; tracked-file list free of the six dirs.

### M3 — Security & typing batch 1 (SPEC_4 §1–§5, §6 batch 1)
- [ ] M3.1 Git-ref: leading-dash rejection + `--` separator + `tests/security/test_git_ref_injection.py` (D4).
- [ ] M3.2 Dependabot leftovers (`pathspec`, `pytest-asyncio`) resolved; lockfile current.
- [ ] M3.3 pip-audit blocking: ignore file + `scripts/run_pip_audit.py` + CI change + `make audit` (D7).
- [ ] M3.4 `scan_security` one-read-per-file restructure + identity tests (D15).
- [ ] M3.5 mypy batch 1: all `core/*` in `[tool.mypy].files`, green (D8).
- [ ] M3.6 HUMAN: PyPI placeholder + trusted-publisher checklist doc (SPEC_4 §5).

**Exit:** `make check` + `make audit` green; injection tests prove option-refs rejected; mypy covers 3+9 core modules.

**GATE G1** (MASTER_SPEC): fresh-machine onboarding ≤ 10 min from README alone; `make check` green; 0 config-format dead-code findings on self-index. **Fallback:** wrapper path fails fresh-machine → Python-direct becomes the only documented route; noise persists → flag-gated skip of structural languages at indexing.

## §2 Stage 2 — Distribution & Single Source of Truth

### M4 — Wrapper unification (SPEC_2 §4–§5)
- [ ] M4.1 Implement `scripts/generate_wrapper.py` (`--write`/`--check`); extend contract with `untrusted` if absent (atomic).
- [ ] M4.2 Generate `wrapper/mcp-server.ts`; `make wrapper` target.
- [ ] M4.3 `tests/contract/test_wrapper_generation.py` (5 tests).
- [ ] M4.4 Remove `wrapper-drift` CI skip forever; README Advanced section points in-repo; deprecate codesight-plugin (one-line note + link).

**Exit:** drift job green on a real PR; generated wrapper runs (`bun run wrapper/mcp-server.ts` handshake smoke-tested manually, output recorded).

### M5 — PyPI publish (SPEC_2 §6)
- [ ] M5.1 `release.yml` (tag-triggered, trusted publishing, SHA-pinned).
- [ ] M5.2 pyproject: drop do-not-install warnings, add `[project.urls]`, bump 0.7.0 (D23).
- [ ] M5.3 HUMAN: PyPI trusted-publisher binding; HUMAN: branch protection on `main` (D19).
- [ ] M5.4 README: `uvx codesight-mcp` primary install; pre-commit config + docs.
- [ ] M5.5 `tests/ci/test_release_workflow.py`.

**Exit:** v0.7.0 live on PyPI; `uvx codesight-mcp` works on a machine without the repo. **GATE G2** per MASTER_SPEC (uvx works; drift green 2 weeks; name owned). **Fallback:** pipx-from-git documented path; wrapper frozen with checksum gate.

## §3 Stage 3 — Freshness & Resolution

### M6 — Freshness (SPEC_5 §1–§2)
- [ ] M6.1 `reindex-stale` subcommand (D11, caps/defaults per spec) + tests.
- [ ] M6.2 `get-status`/`list-repos` staleness surfacing.
- [ ] M6.3 Cron/launchd docs; hook install reminder.
- [ ] M6.4 HUMAN: install cron entry; record first sweep result.

**Exit:** tests green; live sweep executed; staleness metric recorded as G3(a) baseline.

### M7 — Resolved call graph (SPEC_5 §3–§5)
- [ ] M7.1 Benchmark corpus + labeled ground truth + xfail precision test FIRST (SPEC_5 §4).
- [ ] M7.2 `build_import_map` for python/ts/js/go/rust (D12a).
- [ ] M7.3 `resolve_call_edges` two-pass; edge fields `resolution`/`confidence` (§3.1–§3.3).
- [ ] M7.4 INDEX_VERSION → 3 + v2 read compat + schema validation of new fields; guard test updated; version 0.8.0.
- [ ] M7.5 Consumer updates + `min_confidence` on get-impact + `make contract && make stamp`.

**Exit:** precision ≥ 0.90 / recall ≥ 0.80 test green (xfail removed); v2 indexes still load; `make check` green.

### M8 — mypy completion (SPEC_4 §6 batches A–D)
- [ ] M8.1–M8.4 Batches A (parser/discovery/security), B (embeddings/summarizer), C (tools), D (server/cli/scripts → collapse files list).

**Exit:** `uv run --group typecheck mypy` green over `src/codesight_mcp` + `scripts`. **GATE G3** per MASTER_SPEC (staleness < 20% two weeks; precision/recall targets; full mypy). **Fallback:** resolution below target → opt-in `resolution="strict"`, name-based default, Stage-4 SAST claims capped.

## §4 Stage 4 — Corpus, Semantics, SAST

### M9 — Federated ops (SPEC_6 §1–§2)
- [ ] M9.1 Implement `tools/_federated.py` helpers (replace stubs) with caps `_FED_MAX_REPOS=100`, 20s budget.
- [ ] M9.2 `search-federated` + `impact-federated` tools registered atomically; ops 34→36; contract+stamp+wrapper regenerated.
- [ ] M9.3 `tests/tools/test_federated.py` (6 tests).

**Exit:** all gates green with 36 ops everywhere; federated smoke on live corpus recorded.

### M10 — Semantic maturation (SPEC_6 §3)
- [ ] M10.1 `OpenAIEmbeddingProvider` opt-in + `semantic-openai` extra (D14/D14a); delete Anthropic TODO.
- [ ] M10.2 Hybrid 60/40 scoring (D14b).
- [ ] M10.3 MRR eval harness; record measured MRRs.

**Exit:** `test_semantic_ranking` green (hybrid ≥ keyword); README providers table updated.

### M11 — SAST mode + benchmark publication (SPEC_6 §4–§5)
- [ ] M11.1 SAST fixtures (vulnerable + clean) first.
- [ ] M11.2 `scan-security` `mode` param, resolved-tier chains + evidence (D21); SECURITY.md tiers paragraph.
- [ ] M11.3 `docs/benchmark.md` + `--markdown` flags + README claim linked and script-stamped.
- [ ] M11.4 `workflow_dispatch` benchmark CI job.

**Exit:** the four SAST tests green (= Gate G4(b)); benchmark doc reproducible. **GATE G4** per MASTER_SPEC (usage evidence; SAST fixture results; third-party reproducible benchmark). **Fallback:** unused features frozen as experimental; SAST stays heuristic-labeled permanently.

## §5 Session discipline

One milestone item (M<i>.<j>) minimum per session; never span two milestones in one session; `make check` before every "done"; update `docs/MILESTONE.md` checkboxes + measured numbers in the same commit as the work.

## §6 Spec amendments

Any change to a [DECISION], a spec constant, or a gate number requires: edit the spec file in `docs/spec/`, note it in `docs/MILESTONE.md` under "Amendments", and update `CLAUDE.md` key numbers if affected — never amend ad hoc in code. Amendments require Cevin's sign-off.
