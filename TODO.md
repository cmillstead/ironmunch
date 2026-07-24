# TODO

> Note: this file becomes `ROADMAP.md` in M2.5 ([DECISION] D18). Entries carry over.

- [ ] Register `codesight-mcp` on PyPI as placeholder — needs API token or trusted publisher setup
- [ ] **Nim grammar breaks under `tree-sitter-language-pack` 1.x — decide before Dependabot bumps it.**
      Locked at `tree-sitter-language-pack` 0.13.0 / `tree-sitter` 0.25.2, where everything passes. Verified 2026-07-24: under 1.13.3 / 0.26.0 these three fail —
      `tests/test_language_depth_batch1.py::TestNimImportExtraction::test_nim_import_extraction`,
      `tests/test_languages_batch2.py::TestNimSymbols::test_nim_symbols`,
      `tests/unit/test_tree_sitter_smoke.py::TestMinimalParse::test_grammar_parses_minimal_source[nim]`.
      Not reachable in CI today (`uv sync --frozen` pins it), but Dependabot is enabled and branch protection has auto-merge off, so a major bump arrives as a red PR needing manual triage.
      Reproduce: `uv venv /tmp/tslp1 && VIRTUAL_ENV=/tmp/tslp1 uv pip install -e '.[test]'` (unpinned resolution), then run the three tests.
      Decide between: (a) adopt 1.x and fix the Nim queries/expectations, (b) pin an upper bound `<1.0.0` in `pyproject.toml` with a comment pointing here, or (c) drop Nim from the supported set — note (c) changes the language count and therefore needs a spec amendment + `make stamp` (`CLAUDE.md` rule 6).
      Context: `docs/MILESTONE.md` → Incidents (2026-07-24).
- [x] Harden psmm-injector.py — type check on sessions dict (all 3 repos: axon, codesight-mcp, engram)
- [x] ct-builder.md — check #7 "Output correctness" added to Pre-Report Self-Check
- [x] Pre-completion hook — added `cargo fmt` to verification patterns, Rust commands in error message
