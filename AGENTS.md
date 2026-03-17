# Codesight MCP — Agent Navigation

Code indexing MCP server that reduces AI token costs by providing symbol-level code navigation.

## Quick Reference

- **Setup & tools**: See `CLAUDE.md` for all MCP tool descriptions and usage rules
- **Architecture**: See `docs/architecture.md`
- **Development guide**: See `docs/development-guide.md`
- **CI**: See `docs/ci.md` and `docs/ci-secrets-checklist.md`
- **Security**: See `SECURITY.md` for threat model
- **Project overview**: See `docs/project-overview.md`
- **Source tree**: See `docs/source-tree-analysis.md`

## 1. Environment — Check Before Starting

- **Repository state**: `git status`, `git stash list`, `git branch`
- **CI/PR state**: `gh run list --limit 5`, `gh pr list`, `gh pr view`
- **Recent history**: `git log --oneline -20`
- **Escalation**: If CI is already failing on an unrelated issue, note it and proceed

## 2. Memory — Check Prior Knowledge

- **Git memory**: `git log --oneline -- <file>`, `git blame -L <start>,<end> <file>`
- **QMD vault**: Use QMD `search` and `vector_search` tools. QMD indexes `~/src/**/*.md`
- **ContextKeep**: `list_all_memories`, `retrieve_memory` (when configured, skip if unavailable)
- **Escalation**: If Memory reveals a prior decision that contradicts the current task, surface to user

## 3. Task — Assemble Context for the Work

- **Find code** via codesight-mcp (this repo indexes itself): `search_symbols`, `get_symbol`, `get_callers`, `get_impact`, `get_file_outline`. See `CLAUDE.md` for the full tool list
- Read specific functions, not whole files
- Read test files for modules you'll change
- Check prior analysis: scan reports in `docs/`
- Don't pre-load — load incrementally

## Commands

```bash
.venv/bin/pytest --tb=short -q    # Run tests (must use venv)
uv lock                           # Regenerate lockfile after dependency changes
```

## Key Rules

- Never use bare `pytest` — always `.venv/bin/pytest`
- After `pyproject.toml` changes, run `uv lock` (CI uses `uv sync --frozen`)

## 4. Validation — Before Claiming Done

- **Self-review**: `git diff --stat`, `git diff`, re-read task/issue for acceptance criteria
- **Local verification**: `.venv/bin/pytest --tb=short -q`
- **After pushing**: `gh run list --limit 1`, `gh run view <id>`, fix CI failures immediately
- **Common CI failures**: stale `uv.lock` after dependency changes
- **Don't claim done until**: local tests pass, CI green, diff is intentional only
