# CLAUDE.md

## Code Navigation — MANDATORY

**DO NOT use Grep to search this codebase. DO NOT use Bash grep, rg, or find.**
**DO NOT use the Agent tool's Explore subagent for code search.**

This repo is indexed in codesight-mcp. You MUST use codesight-mcp tools for ALL search:
- **Text search**: `search_text` (replaces Grep)
- **Symbol search**: `search_symbols` (replaces Grep for function/class names)
- **Symbol source**: `get_symbol` or `get_symbol_context` when you know the symbol ID

Use `Read` for reading files (code or config). Use codesight for *finding* things.

### Indexing
- `index_repo` — index a local or GitHub repository
- `index_folder` — index a specific folder within a repo
- `list_repos` — list all indexed repositories
- `invalidate_cache` — delete index and cached files for a repo

### Navigation
- `get_repo_outline` — directory structure and language breakdown
- `get_file_tree` — detailed file listing with symbol counts
- `get_file_outline` — all symbols in a file with signatures
- `get_symbol` — full source of a specific symbol by ID
- `get_symbols` — batch retrieve multiple symbols by ID
- `get_symbol_context` — symbol + siblings + parent in one call; pass `include_graph=true` for callers/callees/hierarchy too

### Search
- `search_symbols` — find functions, classes, methods by name, signature, or summary
- `search_text` — full-text search across all files (returns file, line number, and matched text)
- `search_references` — text search enriched with enclosing symbol context (function/class each hit is in)

### Code Graph
- `get_callers` — find all callers of a symbol
- `get_callees` — find all symbols called by a symbol
- `get_call_chain` — trace call paths between two symbols
- `get_type_hierarchy` — show inheritance chains for a class
- `get_imports` — show import relationships for a symbol
- `get_impact` — analyze impact of changing a symbol (callers + inheritors + importers)

### Dependencies & Diffing
- `get_dependencies` — external vs internal import analysis across the repo
- `compare_symbols` — symbol-level diff between two indexed versions (by content hash)
- `get_changes` — git diff → affected symbols → optional impact analysis

Use `Read` only when you need content that isn't a named symbol (e.g. config files, pyproject.toml).

## Running Tests

Always use the project venv to run tests:

```bash
.venv/bin/pytest --tb=short -q
```

Do NOT use bare `pytest` or `python -m pytest` — the package must be installed in the venv for imports to resolve.

## Dependencies

After changing dependencies in `pyproject.toml`, always regenerate the lockfile:

```bash
uv lock
```

CI uses `uv sync --frozen` which only installs what's in `uv.lock` — if the lockfile is stale, CI will fail.
