# Development Guide — codesight-mcp

> Generated: 2026-03-09 | Project Type: Python Library (MCP Server)

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | CI uses 3.12 |
| uv | Latest | Package manager (preferred over pip) |
| Git | Any | For cloning and hooks |

**Optional:**
- `ANTHROPIC_API_KEY` — Enables AI-generated symbol summaries (falls back to docstrings)
- `GITHUB_TOKEN` — Required for GitHub repo indexing; recommended to avoid API rate limits

## Installation

```bash
# Clone (not on PyPI — install from source only)
git clone git@github.com:cmillstead/codesight-mcp.git
cd codesight-mcp

# Install with uv (recommended — uses lockfile with pinned versions)
uv sync

# Or with pip (uses version ranges, not the lockfile)
pip install -e .
```

## Environment Setup

```bash
# Required for local folder indexing — restricts accessible directories
export CODESIGHT_ALLOWED_ROOTS="/Users/you/src"

# Optional: custom index storage location (default: ~/.code-index/)
export CODE_INDEX_PATH="/path/to/custom/index"

# Optional: GitHub token for repo indexing
export GITHUB_TOKEN="ghp_..."

# Optional: AI summaries
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: disable secret redaction (testing only, logs a warning)
export CODESIGHT_NO_REDACT=1
```

## Running the Server

```bash
# Run as MCP server (standard way — connected via MCP client)
codesight-mcp

# Or via uv
uv run codesight-mcp
```

The server communicates via MCP protocol (stdio). It's typically configured in an MCP client (Claude Desktop, Claude Code) rather than run directly.

## Running Tests

```bash
# Install test dependencies
uv sync --extra test

# Run all tests (1,073 tests)
uv run pytest --tb=short -q

# Run specific test categories
uv run pytest tests/unit/              # Parser & analysis (276 tests)
uv run pytest tests/security/          # Adversarial & security (417 tests)
uv run pytest tests/tools/             # Tool functions (201 tests)
uv run pytest tests/server/            # Server & registry (76 tests)
uv run pytest tests/core/              # Core infrastructure (79 tests)
uv run pytest tests/storage/           # Storage persistence (15 tests)
uv run pytest tests/integration/       # End-to-end pipeline (9 tests)

# Run with verbose output
uv run pytest -v

# Run a specific test file
uv run pytest tests/unit/test_parser.py

# Run tests matching a pattern
uv run pytest -k "test_validation"
```

**Test configuration** is in `pyproject.toml`:
- `testpaths = ["tests"]`
- `asyncio_mode = "auto"` (pytest-asyncio)

## Build

```bash
# Build wheel/sdist
uv build

# Build system: hatchling 1.27.0
# Wheel packages: src/codesight_mcp/
```

## Project Structure

```
src/codesight_mcp/
├── server.py           # Entry point, MCP protocol, tool dispatch
├── discovery.py        # File discovery (local + GitHub)
├── security.py         # Secret/binary classification, redaction
├── core/               # Infrastructure primitives
├── parser/             # AST parsing (15 languages)
├── storage/            # Index persistence (gzip)
├── summarizer/         # AI symbol summarization
└── tools/              # 22 MCP tool implementations
```

See [source-tree-analysis.md](./source-tree-analysis.md) for the full annotated directory tree.

## Key Development Patterns

### Adding a New Tool

1. Create `src/codesight_mcp/tools/your_tool.py`
2. Define a `ToolSpec` with name, description, parameters
3. Implement the tool function (receives `arguments` dict)
4. Register via `@register` decorator or add to `registry.py`
5. The server auto-discovers registered tools via `get_all_specs()`

### Adding a New Language

1. Install tree-sitter grammar package in `pyproject.toml`
2. Create a `LanguageSpec` in `parser/languages.py` with:
   - `ts_language` — tree-sitter language name
   - `symbol_node_types` — AST node type → symbol kind mapping
   - Import/call/type extractors (use existing ones or write new)
3. Add to `_LANGUAGE_BINDINGS` in `parser/extractor.py`
4. Write tests in `tests/unit/test_new_languages.py`

### Security Requirements

- All file paths must pass `validate_path()` (6-step chain)
- All tool responses wrap untrusted content via `wrap_untrusted_content()`
- Error messages must go through `sanitize_error()`
- New tools must respect `ALLOWED_ROOTS` for filesystem access
- Secret patterns in `security.py` must be kept updated

## CI/CD

**GitHub Actions** (`.github/workflows/ci.yml`):
- Triggers: push/PR to `main`
- Runner: `ubuntu-latest`
- Steps: checkout → install uv → Python 3.12 → `uv sync --frozen --extra test` → `uv run pytest --tb=short -q`
- No secrets required in CI
- Deterministic: uses frozen lockfile

## Git Hooks

Auto-reindex hooks available in `hooks/`:
- `post-commit` — updates local folder index
- `post-push` — updates GitHub repo index

```bash
# Install hooks
cp hooks/post-commit .git/hooks/post-commit
cp hooks/post-push .git/hooks/post-push
chmod +x .git/hooks/post-commit .git/hooks/post-push
```

Hooks require `~/.config/codesight-mcp/env` with `GITHUB_TOKEN` and `CODESIGHT_BIN`.

## Dependencies

### Runtime
| Package | Version | Purpose |
|---------|---------|---------|
| mcp | >=1.26.0 | MCP SDK (server protocol) |
| httpx | >=0.27.0 | HTTP client (GitHub API) |
| anthropic | >=0.40.0 | AI summarization |
| tree-sitter | >=0.23.0 | AST parsing engine |
| tree-sitter-{language} | Various | 13 standalone language grammars |
| tree-sitter-language-pack | >=0.13.0 | Dart + Perl grammars |
| pathspec | >=0.12.0 | Gitignore pattern matching |

### Test
| Package | Version | Purpose |
|---------|---------|---------|
| pytest | >=7.0.0 | Test framework |
| pytest-asyncio | >=0.21.0 | Async test support |
