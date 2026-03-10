# codesight-mcp — Documentation Index

> Generated: 2026-03-09 | Scan Level: Exhaustive

## Project Overview

- **Type:** Monolith library
- **Primary Language:** Python 3.10+
- **Architecture:** Layered library with declarative tool registry
- **Repository:** [cmillstead/codesight-mcp](https://github.com/cmillstead/codesight-mcp)

## Quick Reference

- **Tech Stack:** Python 3.10+, MCP SDK, tree-sitter (15 languages), httpx, Anthropic SDK
- **Entry Point:** `codesight_mcp.server:main`
- **Architecture Pattern:** Layered library — thin server dispatcher + 22 tool modules
- **Tools:** 22 MCP tools (indexing, navigation, search, code graph, analysis)
- **Tests:** 1,073 tests (39% security/adversarial)
- **Build:** hatchling + uv lockfile

## Generated Documentation

- [Project Overview](./project-overview.md) — Summary, classification, tech stack, key metrics
- [Architecture](./architecture.md) — Layer diagram, security model, data flow, design decisions
- [Source Tree Analysis](./source-tree-analysis.md) — Annotated directory structure, critical folders, key symbols, hotspots
- [Development Guide](./development-guide.md) — Setup, build, test commands, adding tools/languages, CI/CD

## Existing Documentation

- [README.md](../README.md) — User guide: features, 22-tool reference, quick start, security model, env vars, git hooks
- [SECURITY.md](../SECURITY.md) — Threat model, 53-row defense matrix, validation chain, resource limits
- [CLAUDE.md](../CLAUDE.md) — AI navigation guide (use codesight-mcp tools instead of reading files)
- [.github/workflows/ci.yml](../.github/workflows/ci.yml) — CI: Python 3.12, uv, pytest, SHA-pinned actions

## Historical Plans

19 plan documents in [docs/plans/](./plans/):

| Date | Topic |
|------|-------|
| 2026-03-03 | Security scan plans, adversarial testing, security fixes |
| 2026-03-04 | Security scan iterations (v2-v5), adversarial scans (v2-v3), code scan |
| 2026-03-08 | Full audit refactor, adversarial scan plans (v1-v3) |
| 2026-03-09 | New features design and implementation plan |

## Getting Started

```bash
# Clone and install
git clone git@github.com:cmillstead/codesight-mcp.git
cd codesight-mcp
uv sync

# Set required env var (restricts filesystem access)
export CODESIGHT_ALLOWED_ROOTS="/Users/you/src"

# Run tests
uv run pytest --tb=short -q

# Run as MCP server
uv run codesight-mcp
```

See [Development Guide](./development-guide.md) for full setup details.
