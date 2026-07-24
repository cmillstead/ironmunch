# Current Milestone

<!-- This file becomes docs/MILESTONE.md in the repo (task M0.4). -->

**Active: M0 — Enforcement scaffold + counts truth** (nothing prior; this is the first execution milestone. Baseline: live v0.6.0 repo at git `00241d6` with a failing counts gate, no Makefile, and audit findings unfixed.)

Reading list: `docs/spec/SPEC_1_BASELINE_AND_SCAFFOLD.md` (all sections) + `docs/spec/SPEC_7_MILESTONE_PLAN.md` §1/M0.

Remaining:
- [x] M0.1 Create `Makefile` (SPEC_1 §5 verbatim); add typecheck + counts steps to `scripts/ci-local.sh`
- [x] M0.2 `scripts/check_counts.py --write` mode + `tests/scripts/test_check_counts_write.py` (SPEC_1 §6)
- [ ] M0.3 Run `make stamp`; commit regenerated counts — this turns the failing CI doc-count gate green (audit P2 #2)
- [x] M0.4 Copy spec set + RISK_REGISTER into `docs/spec/`; this file into `docs/MILESTONE.md`
- [ ] M0.5 Replace repo `CLAUDE.md` with the handoff version (SPEC_1 §8, [DECISION] D16)
- [ ] M0.6 Guard tests `tests/spec/test_spec_guards.py` — 9 tests pinning spec constants (SPEC_1 §7.5)
- [ ] M0.7 Unregistered stubs: `src/codesight_mcp/parser/resolution.py`, `src/codesight_mcp/tools/_federated.py`, `scripts/generate_wrapper.py` (SPEC_1 §7.6)
- [ ] M0.8 CI `wrapper-drift` job with documented pre-M4 skip (SPEC_1 §7.7)

Exit criteria (machine-checkable): `make check` exits 0 on a clean checkout (proves counts gate green); `uv run pytest tests/spec tests/scripts -q` green; `docs/spec/` contains MASTER_SPEC + SPEC_1..7 + RISK_REGISTER; all M0 commits match `^M0\.\d: `.

Amendments: (none yet)

Incidents: (none yet)

Next: **M1 — Onboarding that works** — reading list in `docs/spec/MASTER_SPEC.md` (load `SPEC_2` §1–§3).
