# SPEC_4 — Security Hardening Leftovers & Typing

Applies to: M3 (§1–§5) and M8 (§6). Fixes audit §6 corrections #4 (git-ref injection), #5 (mypy scope), #7 (dependency gating), #8 (scan_security I/O), #10 (PyPI squat).

Reminder (binding): security posture is monotonic. Every change here adds a check; none removes one.

## §1 Git-ref argument injection (M3, first task)

Location: `tools/get_changes.py` — `_GIT_REF_RE = re.compile(r"^[a-zA-Z0-9_.^~/:@{}\-]+$")` (L17) permits a leading `-`, and the ref is passed positionally with no `--` separator to `subprocess.run(["git", "diff", "--unified=0", git_ref], ...)` (~L213). Option-like refs (`--no-index`, `-G<re>`, `--ext-diff`) are currently accepted as git options.

[DECISION] D4: Apply **both** defenses. (1) `_validate_ref` additionally rejects any ref whose first character is `-` (error message: `"Invalid git ref: must not start with '-'"`, routed through the existing ValidationError/sanitize path). (2) The subprocess call becomes `["git", "diff", "--unified=0", git_ref, "--"]` — note git requires the `--` *after* the ref (it separates refs from paths); verify against `git diff HEAD~1 --` locally in the test. Rationale: belt-and-suspenders is cheap; the regex fix stops the class, the separator stops path-argument confusion.

Tests in `tests/security/test_git_ref_injection.py` (real git repo in tmp dir, no mocks):
- `test_leading_dash_ref_rejected` — `--no-index`, `-Gx`, `--ext-diff` all return the validation error and never reach subprocess (assert error string).
- `test_valid_refs_still_work` — `HEAD`, `HEAD~1..HEAD`, `main`, a 40-hex SHA, `v1.0^{}`-style refs pass validation and produce a diff against a real temp repo with two commits.
- `test_ref_max_length_enforced` — 201 chars rejected (pins `_GIT_REF_MAX = 200`). `# Changing this requires a spec change.`

## §2 Dependabot leftovers (M3)

Close out the two open Dependabot PRs recorded in the CHANGELOG (`pathspec` #45, `pytest-asyncio` #47): update both constraints in `pyproject.toml` within existing ranges, `uv lock`, run `make check`. If either PR is already merged/closed by execution time, verify the lockfile is current and note it in the milestone log. No behavior change permitted; if tests break, pin to the last green version and record a `KNOWN-ISSUE` line in `docs/MILESTONE.md`.

## §3 pip-audit becomes blocking (M3)

Today: `dependency-audit` CI job is `schedule`-only with `continue-on-error: true`; CHANGELOG records 36 known vulns across 10 packages as tracked-but-ungated.

[DECISION] D7: Make pip-audit **blocking on PRs and pushes** with an explicit, reviewed ignore list; keep the weekly scheduled run as the full unfiltered report. Rationale: blocking-with-allowlist converts "tracked" into "triaged" without freezing development on unfixable transitive vulns.

Implementation:
1. New file `scripts/pip_audit_ignore.txt`: one vulnerability ID per line (`GHSA-…` / `PYSEC-…`), each with a trailing `# reason (YYYY-MM-DD, revisit-by YYYY-MM-DD)` comment. Seed it by running `uv run --with pip-audit pip-audit` at execution time and triaging: anything with no upstream fix available goes on the list with reason "no fix released"; anything fixable gets fixed instead (dependency bump) — do not blanket-add all 36.
2. New script `scripts/run_pip_audit.py`: reads the ignore file, invokes `pip-audit` with `--ignore-vuln` per ID, exits nonzero on any unignored finding. Unit-test the parser (`tests/scripts/test_pip_audit_ignore.py`: `test_parse_ignores_comments_and_blanks`, `test_expired_revisit_by_fails`) — a `revisit-by` date in the past makes the run fail, forcing re-triage.
3. `ci.yml`: change `dependency-audit` to also run on `pull_request` and `push` (drop the `if: schedule` guard for the blocking variant), remove `continue-on-error: true`, and call `uv run --with pip-audit python scripts/run_pip_audit.py`. The weekly `schedule` run additionally executes bare `pip-audit` with `continue-on-error: true` as the drift radar.
4. Add `audit:` target to the Makefile: `uv run --with pip-audit python scripts/run_pip_audit.py`. It is part of CI but **not** part of `make check` ([DECISION] D7a: network-dependent checks stay out of the local never-waive gate so `make check` works offline; CI enforces audit).

## §4 `scan_security` I/O (M3)

Today `scan-security` opens/seeks/reads **every** symbol's content per scan — O(symbols) file opens; heavy on 100k-symbol repos.

[DECISION] D15: Restructure to **one read per file, prefiltered by candidate rule hits**, preserving identical findings output. Rationale: the rules match call-name patterns; a file whose full text contains no candidate token can be skipped without reading per-symbol slices, and per-file reads amortize the rest.

Implementation constraints:
- Group symbols by `source_file`; for each file, single `O_NOFOLLOW` open + full read (bounded by `MAX_FILE_SIZE` — files were already capped at index time), then slice per-symbol spans in memory.
- Fast prefilter: build one compiled alternation of all rule call-name tokens; skip files with no match. Findings must be byte-identical to the old implementation on the test corpus.
- No caching across calls in M3 (no invalidation complexity); revisit only if M3 benchmarks still show pain. `# [DECISION] D15a: correctness before cleverness — cross-call caches need invalidation tied to content_hash and are not justified yet.`
- Tests `tests/tools/test_scan_security_io.py`: `test_findings_identical_to_naive_scan` (fixture repo with seeded hits; compare against a reference brute-force implementation written inside the test), `test_open_count_at_most_files` (count opens via a tiny `os.open` wrapper injected at module seam — the repo bans `unittest.mock`, so expose an injectable `opener` parameter defaulting to the real one), `test_symlinked_file_still_refused`.

## §5 PyPI name-squat closure (M3, HUMAN-REQUIRED)

The `pyproject.toml` header documents the squat risk; `TODO.md`'s only live item. The agent cannot create PyPI accounts. Produce `docs/handoff/pypi-placeholder-checklist.md` with the exact steps for Cevin: register the `codesight-mcp` project name (placeholder 0.0.1.dev0 upload via `uv build` + `twine` or reserve-by-first-publish), enable 2FA, configure trusted publisher for `release.yml` (SPEC_2 §6). Mark the milestone item `HUMAN` in `docs/MILESTONE.md`. M5's real publish supersedes the placeholder.

## §6 mypy expansion to all 68 modules (M3 batch 1, then M8 completion)

Today `[tool.mypy].files` lists 3 modules (`core/locking.py`, `core/rate_limiting.py`, `storage/index_store.py`).

[DECISION] D8: Expand module-by-module in dependency order, keeping today's flags (no `--strict`; `warn_unused_ignores = true` stays). Order: `core/*` (M3) → `parser/*` + `discovery.py` + `security.py` + `security_rules.py` (M8 batch A) → `storage`(done) + `embeddings/*` + `summarizer/*` (M8 batch B) → `tools/*` (M8 batch C) → `server.py` + `cli_format.py` + `scripts/*.py` (M8 batch D, endpoint: replace the `files` list with `files = ["src/codesight_mcp", "scripts"]`). Rationale: leaves-first ordering means each batch type-checks against already-typed dependencies; big-bang `--strict` on 68 modules would stall the milestone on annotation churn.

Rules per batch: fix annotations, never change runtime behavior to satisfy the checker; `# type: ignore[code]` requires a trailing reason comment; a batch is done when `uv run --group typecheck mypy` is green with the batch added. M3 exit includes all of `core/` green. M8 exit: full-tree green and the `files` list collapsed to the two roots.
