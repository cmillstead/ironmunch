# SPEC_2 — Onboarding & Distribution

Applies to: M1 (§1–§3), M4 (§4–§5), M5 (§6).
Fixes audit §6 corrections #1 (broken README onboarding) and audit §7 items "Publish to PyPI", "Unify or vendor the dispatch wrapper".

## §1 The problem (verified)

`README.md` Quick Start Step 1 installs only this repo (`git clone … && uv sync`). Step 2 registers `bun run ~/src/codesight-plugin/mcp-server.ts` — a separate, never-cloned TypeScript repo with an undocumented `bun` prerequisite. Meanwhile `pyproject.toml [project.scripts]` already ships a working stdio entrypoint: `codesight-mcp = "codesight_mcp.server:main"`, which exposes all 34 tools individually with per-tool `ToolAnnotations` and warning suffixes — and the README never mentions it. The committed `.mcp.json` registers an unrelated `base-mcp` server.

## §2 Primary install path (M1)

[DECISION] D1: The **Python stdio entrypoint is the primary documented path**; the TS wrapper is demoted to an "Advanced: single-tool dispatch wrapper" section until M4 brings it in-repo. Rationale: it is the only path that works with this repo alone, it exercises the per-tool annotation machinery that is currently dead code on the documented path, and it removes the bun/second-repo prerequisites.

Rewrite README "Quick Start" Step 2 to exactly this shape (keep Step 1 and Step 3 structure):

```bash
claude mcp add codesight \
  -e CODESIGHT_ALLOWED_ROOTS=/Users/you/src \
  -e GITHUB_TOKEN=ghp_... \
  -- /absolute/path/to/codesight-mcp/.venv/bin/codesight-mcp
```

Requirements for the rewritten section:
- State explicitly: "This registers 34 individual tools with per-tool read-only/destructive annotations."
- Keep the existing env-var table (`CODESIGHT_ALLOWED_ROOTS` required for local, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`) unchanged.
- Move the current wrapper instructions (bun + codesight-plugin) into a new `### Advanced: single query dispatch tool` subsection, adding the missing prerequisites: link to the codesight-plugin repo, `bun` install note, and a warning that it is a separate repo until M4 replaces it with `wrapper/mcp-server.ts` in this repo.
- Update the prose in Features/intro that says "exposes 34 operations through a single `query` dispatch tool" to say the server exposes 34 operations, available either as individual MCP tools (default) or through the single `query` dispatch wrapper (advanced). Counts remain marker-generated (`make stamp` after edits).
- Add a "Verify" step: `codesight-mcp --help` (or `uv run codesight-mcp` note that it waits on stdio) plus asking the client to run `get-status`.

Tests (M1): `tests/docs/test_readme_onboarding.py` — `test_quickstart_has_no_external_repo_in_primary_path` (assert the string `codesight-plugin` does not appear between the "Quick Start" and "Advanced" headings), `test_entrypoint_documented` (assert `codesight-mcp` console-script invocation appears in Quick Start), `test_console_script_exists` (import `codesight_mcp.server` and assert `main` is callable; parse `pyproject.toml` for the `[project.scripts]` entry).

## §3 `.mcp.json` (M1)

[DECISION] D-mcpjson: Replace the committed `.mcp.json` contents with a codesight self-registration example (the repo dogfoods itself per CLAUDE.md navigation policy):

```json
{
  "mcpServers": {
    "codesight": {
      "type": "stdio",
      "command": ".venv/bin/codesight-mcp",
      "env": { "CODESIGHT_ALLOWED_ROOTS": "${HOME}/src" }
    }
  }
}
```

Rationale: the current file registers `.base/base-mcp` (agent scaffolding being untracked in M2, SPEC_3 §4); a reference config should show the product. If Cevin's local workflow needs base-mcp, that belongs in untracked local config.

## §4 Wrapper generation from the contract (M4)

[DECISION] D9: Generate the TS dispatch wrapper **inside this repo** at `wrapper/mcp-server.ts` from `contract/operations.json` via `scripts/generate_wrapper.py`; the external `codesight-plugin` repo is deprecated to a consumer that just copies the generated file. Rationale: the trust boundary (path_class validation, `<UNTRUSTED_OUTPUT>` framing) currently lives in two repos that the CHANGELOG admits have drifted; the contract file already encodes per-(operation,parameter) `path_class` exactly so a generator can emit the three trust loops mechanically.

`scripts/generate_wrapper.py` (replaces the M0 stub):
- `python scripts/generate_wrapper.py --write` renders `wrapper/mcp-server.ts`; `--check` re-renders to a temp buffer and exits 1 on any byte difference (CI drift gate).
- Input: `contract/operations.json` only. No imports from `codesight_mcp` at render time beyond reading the JSON — the contract is the interface.
- Generated wrapper behavior (mirror today's codesight-plugin semantics):
  1. Registers exactly one MCP tool `query` with schema `{operation: string enum(all op names), params: object}`.
  2. Spawns the Python server via the `CODESIGHT_BIN` env var (default `codesight-mcp` on PATH) and proxies tool calls 1:1 (`query(op, params)` → tool `op` with `params`).
  3. Before dispatch, validates every param classified `host_path` against `CODESIGHT_ALLOWED_ROOTS` prefixes and every `repo_relative_path` against `..`/absolute rejection — the classifications come from `path_class` in the contract.
  4. Wraps output of operations whose contract entry has `"untrusted": true` in `<UNTRUSTED_OUTPUT>` / `</UNTRUSTED_OUTPUT>` framing. Note: today's contract carries `destructive` and `index_gate`; if `untrusted` is absent from the contract schema, extend `scripts/export_contract.py` to emit it from `ToolSpec.untrusted` in the same commit (atomic per SPEC_1 §2 rule 5).
  5. A generated header comment: `// GENERATED by scripts/generate_wrapper.py from contract/operations.json — DO NOT EDIT. Regenerate: make wrapper`.
- Add `wrapper: ` target to the Makefile: `uv run python scripts/generate_wrapper.py --write`.
- [DECISION] D9a: The wrapper stays dependency-light — plain `@modelcontextprotocol/sdk` + Node/Bun stdlib, no build step, executable via `bun run wrapper/mcp-server.ts` or `node --experimental-strip-types`. Rationale: zero-toolchain execution is the whole point of a wrapper.

Tests (M4): `tests/contract/test_wrapper_generation.py` — `test_generate_is_deterministic` (two renders byte-identical), `test_check_mode_detects_drift` (mutate temp copy, expect exit 1), `test_all_operations_present_in_wrapper` (every contract op name appears in the generated file), `test_untrusted_ops_get_framing` (each contract op with `untrusted: true` maps to framing code — assert via generated-source string checks), `test_wrapper_header_marks_generated`.

## §5 CI drift gate goes live (M4)

Remove the pre-M4 skip from the `wrapper-drift` job (SPEC_1 §7.7) **forever** — the job body becomes:

```yaml
- name: Check wrapper drift
  run: |
    uv sync --frozen
    uv run python scripts/generate_wrapper.py --check
```

Also update README "Advanced" section to point at `wrapper/mcp-server.ts` in this repo and mark `codesight-plugin` deprecated (one line + link).

## §6 PyPI publish (M5)

[DECISION] D10: Publish for real (not placeholder-only) at v0.7.0 using **GitHub Actions Trusted Publishing** (OIDC, no long-lived token), with the name-squat placeholder registered earlier as a human task in M3 (SPEC_4 §5). Rationale: audit calls install friction the biggest adoption blocker; trusted publisher is the current PyPA-recommended path and avoids token handling.

Work items:
1. Remove the "not registered on PyPI / do not install from PyPI" security header comment in `pyproject.toml` and the matching README/SECURITY.md warnings — replaced by "install via `uvx codesight-mcp`". Add `[project.urls]` (Homepage, Repository, Changelog).
2. New workflow `.github/workflows/release.yml`:
   - Trigger: `on: push: tags: ["v*"]`.
   - Job `build`: `uv build`, upload `dist/*` as artifact.
   - Job `publish`: `environment: pypi`, `permissions: id-token: write`, `pypa/gh-action-pypi-publish@release/v1` (pin the commit SHA like the other actions in `ci.yml`).
   - Publish job requires `build` and runs `make check` first — a release cannot ship red.
3. HUMAN-REQUIRED (cannot be automated by the agent): create the PyPI project + trusted-publisher binding (repo `cmillstead/codesight-mcp`, workflow `release.yml`, environment `pypi`) in the PyPI UI. The agent prepares everything and stops with explicit instructions.
4. README Quick Start Step 1 gains the preferred path:
   ```bash
   uvx codesight-mcp            # run without installing
   # or: uv tool install codesight-mcp
   ```
   with `claude mcp add codesight -e CODESIGHT_ALLOWED_ROOTS=... -- uvx codesight-mcp` as the one-command registration. Source install remains documented below it.
5. Semantic extra note: `uvx --with 'codesight-mcp[semantic]' codesight-mcp` documented under Semantic Search.
6. Pre-commit stamping: add `.pre-commit-config.yaml` with a local hook running `uv run python scripts/check_counts.py --write` on `README.md` and `docs/*.md` changes, plus `ruff check`. Document `pre-commit install` in `docs/development-guide.md`. [DECISION] D19: drift prevention is pre-commit + make check + CI, and enabling GitHub branch protection on `main` (require CI green) is a HUMAN-REQUIRED checklist item recorded in MILESTONE M5 — the audit proved red-on-main is otherwise possible.

Tests (M5): `tests/ci/test_release_workflow.py` — `test_release_workflow_exists_and_pinned` (parse YAML: tag trigger, id-token permission, SHA-pinned publish action), `test_version_is_0_7_0` at release time (guard test updated with the version bump commit).
