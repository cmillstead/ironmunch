# Current Milestone

<!-- This file becomes docs/MILESTONE.md in the repo (task M0.4). -->

**Active: M0 — Enforcement scaffold + counts truth** (nothing prior; this is the first execution milestone. Baseline: live v0.6.0 repo at git `00241d6` with a failing counts gate, no Makefile, and audit findings unfixed.)

Reading list: `docs/spec/SPEC_1_BASELINE_AND_SCAFFOLD.md` (all sections) + `docs/spec/SPEC_7_MILESTONE_PLAN.md` §1/M0.

Remaining:
- [x] M0.1 Create `Makefile` (SPEC_1 §5 verbatim); add typecheck + counts steps to `scripts/ci-local.sh`
- [x] M0.2 `scripts/check_counts.py --write` mode + `tests/scripts/test_check_counts_write.py` (SPEC_1 §6)
- [x] M0.3 Run `make stamp`; commit regenerated counts — this turns the failing CI doc-count gate green (audit P2 #2)
- [x] M0.4 Copy spec set + RISK_REGISTER into `docs/spec/`; this file into `docs/MILESTONE.md`
- [x] M0.5 Replace repo `CLAUDE.md` with the handoff version (SPEC_1 §8, [DECISION] D16)
- [x] M0.6 Guard tests `tests/spec/test_spec_guards.py` — 8 tests pinning spec constants (SPEC_1 §7.5); mock-import guard deferred to M12 — see Amendments
- [x] M0.7 Unregistered stubs: `src/codesight_mcp/parser/resolution.py`, `src/codesight_mcp/tools/_federated.py`, `scripts/generate_wrapper.py` (SPEC_1 §7.6)
- [x] M0.8 CI `wrapper-drift` job with documented pre-M4 skip (SPEC_1 §7.7)
- [x] M0.10 Make pytest collection environment-independent so the counts gate has one truth (see Incidents)

Exit criteria (machine-checkable): `make check` exits 0 on a clean checkout (proves counts gate green); `uv run pytest tests/spec tests/scripts -q` green; `docs/spec/` contains MASTER_SPEC + SPEC_1..7 + RISK_REGISTER; all M0 commits match `^M0\.\d: `.

Amendments:
- **2026-07-24 — M12 added** (Cevin-approved). `SPEC_7_MILESTONE_PLAN.md` §4 gains **M12 — De-mock tests + enforce zero-mock guard** after M11; `MASTER_SPEC.md` Stage 4 range becomes M9–M12 and its reading list gains an M12 row.
- **2026-07-24 — mock-import guard deferred, M0.6 ships 8 guards not 9.** `SPEC_1 §7` item 5 listed `test_no_mock_imports_in_tests` as the 9th guard, but `tests/` currently carries ~108 `unittest.mock`/`MagicMock`/`AsyncMock` hits across 18 files, so the guard cannot pass on the M0 tree. It moves to M12.2; `SPEC_1 §7` item 5 records the deferral, and repo `CLAUDE.md` rule 7 is worded "No mocks (M12 target)".
- **2026-07-24 — commit-format enforcement resolved.** The `M<n>.<i>: ` commit prefix required by M0 exit criteria is not in the harness git-safety hook's built-in prefix list. Allowed via the hook's repo env-allow escape hatch: `GIT_SAFETY_EXTRA_COMMIT_PREFIX_RE="^M\d+\.\d+: "` set in `.claude/settings.local.json`. No hook bypass; no spec change to the commit convention.

Incidents:
- **2026-07-24 — counts gate had two truths (found by CI on PR #73; fixed in M0.10).** After M0.3 stamped 2591, CI still failed `Check doc counts` expecting **2575**. Root cause: `check_counts.py::_test_count()` runs `pytest --collect-only`, which counts *collected* items, and `tests/unit/embeddings/test_providers.py` used a **module-level** `pytest.importorskip("fastembed")`. A module-level skip aborts collection of the whole module, so all 16 of its tests were invisible wherever `fastembed` was absent. `fastembed` ships in the `semantic` extra; CI installs `--extra test` only, dev machines often have it. The gate was therefore a property of the machine, not the repo (2591 − 2575 = exactly that module).
  **Fix:** replaced module-level `importorskip` with `importlib.util.find_spec` + `pytest.mark.skipif` in `tests/unit/embeddings/test_providers.py` (class-level mark) and `tests/benchmark/test_semantic_benchmark.py` (`pytestmark` list). Tests now always **collect** and skip at runtime, so collection is 2591 in every environment. The `RUN_BENCHMARKS` module-level skip was deliberately left intact.
  **Side effect (coverage gain):** 9 tests in `test_providers.py` that never needed `fastembed` were being taken down with the module and had never run on CI. They now run and pass.
  **Verified:** collection = 2591 with fastembed, without fastembed, and in a `uv sync --frozen --extra test` CI replica; `check_counts.py` exits 0 in that replica against the already-committed docs (no re-stamp needed — 2591 was correct all along).
- **2026-07-24 — latent dependency hazard (not fixed, no action taken).** Under unpinned resolution (`tree-sitter-language-pack` 1.13.3 / `tree-sitter` 0.26.0 instead of the locked 0.13.0 / 0.25.2), three Nim tests fail: `test_nim_import_extraction`, `test_nim_symbols`, `test_grammar_parses_minimal_source[nim]`. The lockfile pins this away and all three pass under `uv sync --frozen`, but Dependabot is enabled on this repo, so a `tree-sitter-language-pack` major bump will surface them.

Next: **M1 — Onboarding that works** — reading list in `docs/spec/MASTER_SPEC.md` (load `SPEC_2` §1–§3).
