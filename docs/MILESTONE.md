# Current Milestone

**Active: M1 — Onboarding that works.** Goal: a new user (or clean VM) completes README Quick Start end-to-end using ONLY this repo, in ≤ 10 minutes. Baseline: M0 merged (PR #73, `b3c9567`) — enforcement scaffold in place, `make check` green, CI doc-count gate green.

Reading list: `docs/spec/SPEC_2_ONBOARDING_AND_DISTRIBUTION.md` §1–§3 + `docs/spec/SPEC_7_MILESTONE_PLAN.md` §1/M1.

Remaining:
- [ ] M1.1 README Quick Start rewrite: Python entrypoint primary ([DECISION] D1); wrapper → Advanced section with real prerequisites
- [ ] M1.2 Replace `.mcp.json` with a codesight self-registration example
- [ ] M1.3 `tests/docs/test_readme_onboarding.py` — 3 tests (SPEC_2 §2)
- [ ] M1.4 `make stamp` (README edits may touch counted phrases)

Exit criteria: onboarding tests green; `make check` exits 0; manual smoke — `claude mcp add codesight -- .venv/bin/codesight-mcp` registers and `get-status` answers (record the output in this file's Log).

Log: (M1 not started)

Next: **M2 — Precision & hygiene** — reading list `SPEC_3` (all) + `SPEC_1` §4 (constants).

---

## Completed milestones

### M0 — Enforcement scaffold + counts truth ✅ 2026-07-24

Merged via PR #73, merge commit `b3c9567`. Ten items, all commits matching `^M0\.\d+: `. Exit criteria met: `make check` exit 0; `uv run pytest tests/spec tests/scripts -q` green (13); `docs/spec/` holds MASTER_SPEC + SPEC_1..7 + RISK_REGISTER; CI green on the remote (lint, typecheck, test 1–4, wrapper-drift). Live counts at completion: ops=34 langs=66 tests=2591.

- [x] M0.1 `Makefile` (SPEC_1 §5 verbatim); typecheck + counts steps in `scripts/ci-local.sh`
- [x] M0.2 `scripts/check_counts.py --write` mode + `tests/scripts/test_check_counts_write.py` (SPEC_1 §6)
- [x] M0.3 `make stamp`; commit regenerated counts — turns the failing CI doc-count gate green (audit P2 #2)
- [x] M0.4 Spec set + RISK_REGISTER into `docs/spec/`; this file into `docs/MILESTONE.md`
- [x] M0.5 Replace repo `CLAUDE.md` with the handoff version (SPEC_1 §8, [DECISION] D16)
- [x] M0.6 Guard tests `tests/spec/test_spec_guards.py` — 8 tests pinning spec constants (SPEC_1 §7 item 5); mock-import guard deferred to M12 — see Amendments
- [x] M0.7 Unregistered stubs: `src/codesight_mcp/parser/resolution.py`, `src/codesight_mcp/tools/_federated.py`, `scripts/generate_wrapper.py` (SPEC_1 §7 item 6)
- [x] M0.8 CI `wrapper-drift` job with documented pre-M4 skip (SPEC_1 §7 item 7)
- [x] M0.9 Spec amendments (see Amendments below)
- [x] M0.10 Make pytest collection environment-independent so the counts gate has one truth (see Incidents)

---

## Amendments

Spec amendments are cross-milestone history — they persist here as milestones advance. Per `SPEC_7` §6, amendments require Cevin's sign-off and are made in `docs/spec/`, never ad hoc in code.

- **2026-07-24 — M12 added** (Cevin-approved). `SPEC_7_MILESTONE_PLAN.md` §4 gains **M12 — De-mock tests + enforce zero-mock guard** after M11; `MASTER_SPEC.md` Stage 4 range becomes M9–M12 and its reading list gains an M12 row.
- **2026-07-24 — mock-import guard deferred, M0.6 ships 8 guards not 9.** `SPEC_1 §7` item 5 listed `test_no_mock_imports_in_tests` as the 9th guard, but `tests/` currently carries ~108 `unittest.mock`/`MagicMock`/`AsyncMock` hits across 18 files, so the guard cannot pass on the M0 tree. It moves to M12.2; `SPEC_1 §7` item 5 records the deferral, and repo `CLAUDE.md` rule 7 is worded "No mocks (M12 target)".
- **2026-07-24 — commit-format enforcement resolved.** The `M<n>.<i>: ` commit prefix required by M0 exit criteria is not in the harness git-safety hook's built-in prefix list. Allowed via the hook's repo env-allow escape hatch: `GIT_SAFETY_EXTRA_COMMIT_PREFIX_RE="^M\d+\.\d+: "` set in `.claude/settings.local.json`. No hook bypass; no spec change to the commit convention.

## Incidents

- **2026-07-24 — counts gate had two truths (found by CI on PR #73; fixed in M0.10).** After M0.3 stamped 2591, CI still failed `Check doc counts` expecting **2575**. Root cause: `check_counts.py::_test_count()` runs `pytest --collect-only`, which counts *collected* items, and `tests/unit/embeddings/test_providers.py` used a **module-level** `pytest.importorskip("fastembed")`. A module-level skip aborts collection of the whole module, so all 16 of its tests were invisible wherever `fastembed` was absent. `fastembed` ships in the `semantic` extra; CI installs `--extra test` only, dev machines often have it. The gate was therefore a property of the machine, not the repo (2591 − 2575 = exactly that module).
  **Fix:** replaced module-level `importorskip` with `importlib.util.find_spec` + `pytest.mark.skipif` in `tests/unit/embeddings/test_providers.py` (class-level mark) and `tests/benchmark/test_semantic_benchmark.py` (`pytestmark` list). Tests now always **collect** and skip at runtime, so collection is 2591 in every environment. The `RUN_BENCHMARKS` module-level skip was deliberately left intact.
  **Side effect (coverage gain):** 9 tests in `test_providers.py` that never needed `fastembed` were being taken down with the module and had never run on CI. They now run and pass.
  **Verified:** collection = 2591 with fastembed, without fastembed, and in a `uv sync --frozen --extra test` CI replica; `check_counts.py` exits 0 in that replica against the already-committed docs (no re-stamp needed — 2591 was correct all along).
  **Standing rule:** never gate optional-dependency tests with a module-level skip in this repo, and never re-stamp to whichever count CI reports — that flips which side is red and violates `CLAUDE.md` rule 6.
- **2026-07-24 — `tree-sitter-language-pack` major-bump hazard (open; tracked in `TODO.md`).** Under unpinned resolution (`tree-sitter-language-pack` 1.13.3 / `tree-sitter` 0.26.0 instead of the locked 0.13.0 / 0.25.2), three Nim tests fail: `test_nim_import_extraction`, `test_nim_symbols`, `test_grammar_parses_minimal_source[nim]`. The lockfile pins this away and all three pass under `uv sync --frozen`, but Dependabot is enabled on this repo, so a major bump will land as a red PR.
