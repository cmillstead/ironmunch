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

Add ironmunch to your MCP client configuration. For Claude Desktop:

```json
{
  "mcpServers": {
    "ironmunch": {
      "command": "ironmunch",
      "env": {
        "GITHUB_TOKEN": "ghp_...",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

**Step 1: Index a repository.**

Before any other tools work, you must index at least one repository. Ask your AI:

- For a local folder: `"Index the repo at ~/src/myproject"`
- For a GitHub repo: `"Index the GitHub repo owner/myproject"`

The AI will call `index_folder` or `index_repo`. This fetches files, parses ASTs, and extracts symbols into local storage. You only need to do this once -- subsequent calls skip unchanged files.

**Step 2: Explore the codebase.**

Once indexed, the AI can use `get_repo_outline`, `search_symbols`, and `get_symbol` to navigate the codebase efficiently -- retrieving only the symbols it needs instead of entire files.

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
| `CODE_INDEX_PATH` | Custom storage directory for indexes (default: `~/.ironmunch/`) |
| `GITHUB_TOKEN` | GitHub personal access token for private repos and higher rate limits |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI-generated symbol summaries |

## Attribution

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle. Security hardening inspired by [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

## License

MIT -- see [LICENSE](LICENSE).
