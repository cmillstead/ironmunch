# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Index-on-demand.** Repo-scoped read operations now index a repository on first
  access when its index is missing or stale (older than `INDEX_AGE_THRESHOLD_DAYS`,
  7 days), instead of returning "Repository not indexed" — provided the caller
  supplies the working folder via the `repo_path` argument. On-demand indexing reuses
  the existing validated pipeline unchanged (the `CODESIGHT_ALLOWED_ROOTS` allowlist
  with default-deny, `O_NOFOLLOW`, every cap, and the sanitizers), with AI summaries
  disabled for speed. Results carry `_meta.freshly_indexed`, `_meta.stale`, and
  `_meta.index_warnings` so freshness and any truncation are surfaced, never silent.
  Behavior fails safe to the prior error when no path is available or indexing fails,
  and a directory-swap guard refuses to reindex a mismatched folder under a known repo
  name. `compare-symbols` and `verify` are intentionally excluded.

## [0.6.0] - 2026-07-15

This is a catch-up release: `pyproject.toml` was never bumped past `0.1.0`
during the v0.6.0 Competitive Gap Closure milestone. This entry documents
both that milestone and the subsequent audit remediation work, and brings
the package version in line with what has actually shipped on `main`.

### Added — v0.6.0 Competitive Gap Closure milestone (36/38 features)

- License analysis (`check-licenses`) and Software Bill of Materials
  generation (`generate-sbom`) in CycloneDX, SPDX, and internal JSON formats.
- Forward BFS source-to-sink taint analysis (`trace-taint`) via the code graph.
- Complexity and risk analysis (`analyze-complexity`): cyclomatic complexity,
  cognitive complexity, nesting depth, fan-in/fan-out, composite risk scoring.
- Dead code detection (`get-dead-code`): symbols with zero callers or importers.
- Index quality auditing (`lint-index`) and integrity verification (`verify`):
  checksums, symbol consistency, file existence.
- Usage telemetry (`get-usage-stats`): per-operation call counts, error rates,
  average response times, uncalled operations.
- Mermaid diagram generation (`get-diagram`) for call graphs, type hierarchies,
  import trees, and impact diagrams.
- PageRank-based structural importance ranking (`get-key-symbols`).
- Dependency and diffing tools: `get-dependencies`, `compare-symbols`,
  `get-changes`.
- Semantic search (hybrid keyword + vector scoring) via optional `[semantic]`
  extra, on-device embeddings.
- Full expansion to 66 supported languages and 34 operations exposed through
  the single `query` dispatch tool.

### Added — Audit remediation

- Shared index-age/staleness surface exposed through `get-status`.
- Operation-contract export (`scripts/export_contract.py`) with a byte-compare
  drift test, plus tool trust-flag reconciliation across the registry.
- Word-boundary injection phrase matcher and bounded rule-ID telemetry for
  the prompt injection defense layer.
- Scoped `mypy` type checking wired into CI as a dedicated `typecheck` group
  (9 type fixes required to bring the scoped file set clean).
- Centralized POSIX-only startup check and platform classifiers in
  `pyproject.toml` (Windows was never supported; this makes it explicit).
- Machine-readable `limit` parameter bounds surfaced in tool contracts.
- Single canonical registry bootstrap, `load_all_specs()`, used for
  side-effect-free operation counting (no longer requires importing `server.py`).
- Fixed BMAD `output_folder` configuration and removed committed gitignore
  cruft.
- Pruned stale branches: 4 local branches and 15 merged remote branches.
- `scripts/check_counts.py`: verifies documented operation/language/test
  counts against running code (registry, `LANGUAGE_REGISTRY`, live pytest
  collection) and fails CI on drift, including drift in visible prose counts
  that aren't covered by the stale-literal denylist.

### Security

- **Finding A** (HIGH, found and fixed during audit remediation, user-approved):
  `index_repo` and `index_folder` echoed attacker-controlled filenames and the
  `repo` field back to the caller with no trust framing. Fixed by marking both
  tool specs `untrusted=True` and wrapping filenames and the `repo` value via
  `make_meta(source="index", trusted=False)` and `wrap_untrusted_content`
  before they reach the response.

### Notes / Deferred

- Dependabot dependency updates: `pytest` (#46) and `pytest-cov` (#48) were
  merged; `setup-uv` v8.0.0 (#41), `upload-artifact` (#42), and
  `nick-fields/retry` (#43) were applied to CI. **`pathspec` (#45) and
  `pytest-asyncio` (#47) remain OPEN** — not all 8 open Dependabot PRs were
  merged as part of this work.
- Item 10 (`src/codesight_mcp/parser/languages.py` module split) is deferred
  to a follow-up milestone.
- `pip-audit` CI gating is deferred; 36 known vulnerabilities across 10
  packages remain tracked but non-blocking (weekly `dependency-audit` job
  runs with `continue-on-error: true`).
- Cross-repo parity work in `codesight-plugin` is deferred.
