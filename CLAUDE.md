# CLAUDE.md

## Code Navigation

This repo is indexed in codesight-mcp. Use codesight-mcp MCP tools for code exploration instead of reading full files:

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

### Search
- `search_symbols` — find functions, classes, methods by name, signature, or summary
- `search_text` — full-text search across all files (requires `confirm_sensitive_search=True`)

### Code Graph
- `get_callers` — find all callers of a symbol
- `get_callees` — find all symbols called by a symbol
- `get_call_chain` — trace call paths between two symbols
- `get_type_hierarchy` — show inheritance chains for a class
- `get_imports` — show import relationships for a symbol
- `get_impact` — analyze impact of changing a symbol (callers + inheritors + importers)

Use `Read` only when you need content that isn't a named symbol (e.g. config files, pyproject.toml).

## Running Tests

Always use the project venv to run tests:

```bash
.venv/bin/pytest --tb=short -q
```

Do NOT use bare `pytest` or `python -m pytest` — the package must be installed in the venv for imports to resolve.
