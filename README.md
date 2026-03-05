# ironmunch

Security-hardened, token-efficient MCP server for code exploration via tree-sitter AST parsing.

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle, hardened with security patterns from [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

## Key Features

- **Tree-sitter AST parsing** for 7 languages: Python, JavaScript, TypeScript, Go, Rust, Java, PHP
- **Byte-offset O(1) symbol retrieval** -- cut token costs by ~99% compared to sending full files
- **Incremental indexing** via content hashing -- skip unchanged files on re-index
- **6-step path validation chain** -- null bytes, traversal, limits, resolution, containment, symlinks
- **Content boundary markers** -- indirect prompt injection defense based on Microsoft spotlighting research
- **Error sanitization** -- raw exceptions never reach the AI; system paths are always stripped
- **49 adversarial security tests** -- real temp directories, no mocking
- **Local + GitHub repository indexing** -- index folders on disk or fetch from GitHub

## Installation

```bash
pip install ironmunch
```

## Quick Start

**Step 1: Configure your MCP client.**

Add ironmunch to your MCP client configuration. For Claude Desktop:

```json
{
  "mcpServers": {
    "ironmunch": {
      "command": "ironmunch",
      "env": {
        "IRONMUNCH_ALLOWED_ROOTS": "/Users/you/src",
        "GITHUB_TOKEN": "ghp_...",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

- `IRONMUNCH_ALLOWED_ROOTS` is required for local folder indexing — set it to the parent directory of your projects (colon-separated for multiple roots).
- `GITHUB_TOKEN` is required for private repos and to avoid rate limits on public ones.
- `ANTHROPIC_API_KEY` is optional — enables AI-generated symbol summaries.

**Step 2: Index a repository.**

Before any other tools work, you must index at least one repository. Ask your AI:

- For a local folder: `"Index the repo at ~/src/myproject"`
- For a GitHub repo: `"Index the GitHub repo owner/myproject"`

The AI will call `index_folder` or `index_repo`. This fetches files, parses ASTs, and extracts symbols into local storage. You only need to do this once -- subsequent calls skip unchanged files.

**Step 3: Add a CLAUDE.md to each repo.**

Claude Code won't automatically reach for ironmunch over its built-in file tools — you need to tell it to. Add a `CLAUDE.md` at the repo root:

```markdown
## Code Navigation

This repo is indexed in ironmunch. Use ironmunch MCP tools for code
exploration instead of reading full files:

- `search_symbols` — find functions/classes/types by name or description
- `get_file_outline` — all symbols in a file with signatures
- `get_symbol` — full source of a specific symbol
- `get_repo_outline` — directory structure and language breakdown
- `search_text` — full-text search across all files

Use `Read` only for content that isn't a named symbol (config files, etc).
```

Claude Code loads `CLAUDE.md` automatically at the start of every session in that directory.

**Step 4: Explore the codebase.**

Once indexed, the AI will use `get_repo_outline`, `search_symbols`, and `get_symbol` to navigate efficiently -- retrieving only the symbols it needs instead of entire files.

**Step 5 (optional): Install git hooks for automatic reindexing.**

Keep indexes current without thinking about it:

```bash
cp /path/to/ironmunch/hooks/post-commit .git/hooks/post-commit
cp /path/to/ironmunch/hooks/post-push   .git/hooks/post-push
chmod +x .git/hooks/post-commit .git/hooks/post-push
```

The hooks need their own env file since git hooks don't inherit your shell environment:

```bash
mkdir -p ~/.config/ironmunch
cat > ~/.config/ironmunch/env <<'EOF'
export GITHUB_TOKEN=ghp_...
export IRONMUNCH_BIN=/path/to/.venv/bin/ironmunch
EOF
chmod 600 ~/.config/ironmunch/env
```

`IRONMUNCH_BIN` must point to the same binary your MCP client uses — without it the hooks may resolve to a version manager shim that doesn't have the module installed.

## Git Hooks: Auto-Reindex on Commit and Push

ironmunch includes two git hooks that keep indexes current automatically:

| Hook | Trigger | Updates |
|------|---------|---------|
| `post-commit` | every commit | local folder index |
| `post-push` | every push | GitHub repo index (auto-detects remote) |

**Install in any repo:**

```bash
cp /path/to/ironmunch/hooks/post-commit .git/hooks/post-commit
cp /path/to/ironmunch/hooks/post-push   .git/hooks/post-push
chmod +x .git/hooks/post-commit .git/hooks/post-push
```

Both hooks run in the background so they never block your workflow. Remove `--no-ai` from either hook if you want AI-generated summaries updated automatically.

**One-time hook setup** (git hooks don't inherit your shell environment):

```bash
mkdir -p ~/.config/ironmunch
cat > ~/.config/ironmunch/env <<EOF
export GITHUB_TOKEN=ghp_...
export IRONMUNCH_BIN=/path/to/.venv/bin/ironmunch
EOF
chmod 600 ~/.config/ironmunch/env
```

`IRONMUNCH_BIN` should point to the same `ironmunch` binary used by your MCP client. Without it, the hooks may resolve to a shim (e.g. pyenv) that doesn't have the module installed.

You can also call the indexer directly from the command line:

```bash
ironmunch index ~/src/myproject              # index a local folder
ironmunch index ~/src/myproject --no-ai     # skip AI summaries (faster)
ironmunch index-repo owner/myproject        # index a GitHub repo
ironmunch index-repo owner/myproject --no-ai
```

## Security Model

ironmunch treats the connected AI as an untrusted principal. Every tool argument is validated before use. Every file path from the index is re-validated at retrieval time. Error messages are sanitized so system paths never leak.

See [SECURITY.md](SECURITY.md) for the full threat model, defense matrix, and validation chain details.

## Tools

ironmunch exposes 11 MCP tools:

| Tool | Description |
|------|-------------|
| `index_repo` | Index a GitHub repository (fetch, parse ASTs, extract symbols) |
| `index_folder` | Index a local folder (walk, parse ASTs, extract symbols) |
| `list_repos` | List all indexed repositories |
| `get_repo_outline` | High-level overview: directories, file counts, language breakdown |
| `get_file_tree` | File tree of an indexed repository, optionally filtered by path prefix |
| `get_file_outline` | All symbols in a file with signatures and summaries |
| `get_symbol` | Full source code of a specific symbol (byte-offset retrieval) |
| `get_symbols` | Batch retrieval of multiple symbols in one call |
| `search_symbols` | Search symbols by name, signature, summary, or docstring |
| `search_text` | Full-text search across indexed file contents |
| `invalidate_cache` | Delete an index to force full re-index |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IRONMUNCH_ALLOWED_ROOTS` | Colon-separated list of directories `index_folder` is allowed to index. **Required** for local folder indexing — denied by default if unset. Example: `/Users/you/src:/home/you/projects` |
| `GITHUB_TOKEN` | GitHub personal access token. Required for private repos; strongly recommended to avoid rate limits on public repos. |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI-generated symbol summaries. Optional — falls back to docstrings if unset. |
| `CODE_INDEX_PATH` | Custom storage directory for indexes. Default: `~/.code-index/` |

## Attribution

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle. Security hardening inspired by [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

## License

MIT -- see [LICENSE](LICENSE).
