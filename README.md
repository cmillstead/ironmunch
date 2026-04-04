# codesight-mcp

<p align="center">
  <br>
  <b>Security-hardened, token-efficient code intelligence for AI assistants.</b>
  <br><br>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/cmillstead/codesight-mcp?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/MCP-Compatible-green?style=flat-square" alt="MCP Compatible">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-1927-brightgreen?style=flat-square" alt="Tests">
</p>

An **MCP server** that indexes local and GitHub codebases via tree-sitter AST parsing, then exposes 28 tools for symbol retrieval, code graph traversal, and impact analysis — all with byte-offset precision to cut token costs by ~99% compared to sending full files. Supports 15 languages.

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle, with code graph techniques from [CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext) and security patterns from [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

---

## Quick Navigation

- [Features](#features)
- [Supported Languages](#supported-languages)
- [Quick Start](#quick-start)
- [Tools Reference](#tools)
- [Code Graph & Relationship Analysis](#code-graph--relationship-analysis)
- [Security Model](#security-model)
- [Git Hooks](#git-hooks-auto-reindex-on-commit-and-push)
- [Semantic Search](#semantic-search)
- [Environment Variables](#environment-variables)

---

## Features

### Code Indexing & Retrieval
- **Tree-sitter AST parsing** across 15 languages with byte-offset O(1) symbol retrieval
- **Incremental indexing** via content hashing — skip unchanged files on re-index
- **Local + GitHub repository indexing** — index folders on disk or fetch from GitHub
- **AI-generated summaries** — optional Anthropic API integration for symbol descriptions
- **Full-text search** across indexed file contents with redaction-aware matching
- **Semantic search** — hybrid keyword+vector scoring via on-device embeddings (optional `[semantic]` extra)

### Code Graph & Relationship Analysis
- **Callers & callees** — who calls a function, and what does it call?
- **Call chains** — trace the full path between any two symbols
- **Type hierarchy** — inheritance trees and interface implementations
- **Import graphs** — which files import what, and from where?
- **Impact analysis** — change a function, see everything affected downstream

### Security
- **6-step path validation chain** — null bytes, traversal, limits, resolution, containment, symlinks
- **Content boundary markers** — indirect prompt injection defense (Microsoft spotlighting research)
- **Error sanitization** — raw exceptions never reach the AI; system paths are always stripped
- **MCP ToolAnnotations** — readOnlyHint, destructiveHint, idempotentHint, openWorldHint on all 28 tools for client permission decisions
- **1,927 tests** — adversarial, security, integration, benchmark, fuzz, and stress coverage with real temp directories

---

## Supported Languages

| | Language | | Language | | Language |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 🐍 | **Python** | 📜 | **JavaScript** | 🔷 | **TypeScript** |
| 🏗️ | **C / C++** | #️⃣ | **C#** | ☕ | **Java** |
| 🐹 | **Go** | 🦀 | **Rust** | 🐘 | **PHP** |
| 💎 | **Ruby** | 🍎 | **Swift** | 🎨 | **Kotlin** |
| 🎯 | **Dart** | 🐪 | **Perl** | | |

Each language parser extracts functions, classes, methods, parameters, call relationships, imports, and inheritance to build a comprehensive code graph.

---

## Quick Start

### Step 1: Install

```bash
# From source (recommended — not published to PyPI)
git clone https://github.com/cmillstead/codesight-mcp.git
cd codesight-mcp
uv sync            # recommended — uses lockfile with pinned versions
# or: pip install -e .  (uses version ranges, not the lockfile)
```

### Step 2: Configure your MCP client

Add codesight-mcp to your MCP client configuration. For **Claude Desktop**:

```json
{
  "mcpServers": {
    "codesight-mcp": {
      "command": "codesight-mcp",
      "env": {
        "CODESIGHT_ALLOWED_ROOTS": "/Users/you/src",
        "GITHUB_TOKEN": "ghp_...",
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

For **Claude Code**, add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "codesight-mcp": {
      "command": "/path/to/.venv/bin/codesight-mcp",
      "env": {
        "CODESIGHT_ALLOWED_ROOTS": "/Users/you/src",
        "GITHUB_TOKEN": "ghp_..."
      }
    }
  }
}
```

| Variable | Required | Description |
|----------|----------|-------------|
| `CODESIGHT_ALLOWED_ROOTS` | Yes (local) | Colon-separated directories `index_folder` may access. Denied by default if unset. |
| `GITHUB_TOKEN` | Yes (GitHub) | Required for private repos; recommended to avoid rate limits on public repos. |
| `ANTHROPIC_API_KEY` | No | Enables AI-generated symbol summaries. Falls back to docstrings if unset. |

### Step 3: Index a repository

Before any other tools work, you must index at least one repository. Ask your AI:

- **Local folder:** *"Index the repo at ~/src/myproject"*
- **GitHub repo:** *"Index the GitHub repo owner/myproject"*

The AI calls `index_folder` or `index_repo`, which fetches files, parses ASTs, and extracts symbols into `~/.code-index/`. Subsequent calls skip unchanged files automatically.

### Step 4: Explore

Once indexed, the AI uses `get_repo_outline`, `search_symbols`, and `get_symbol` to navigate your codebase — retrieving only the symbols it needs instead of entire files.

### Step 5 (Claude Code): Configure permissions

All 28 tools include [MCP ToolAnnotations](https://modelcontextprotocol.io/docs/concepts/tools#annotations) (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), so MCP clients can make informed permission decisions. For Claude Code, allow all tools with a single wildcard in `~/.claude/settings.json`:

```json
"permissions": {
  "allow": [
    "mcp__codesight-mcp__*"
  ]
}
```

Claude Code will auto-approve read-only tools and prompt for confirmation on write (`index_repo`, `index_folder`) and destructive (`invalidate_cache`) operations based on the annotations.

Add a `CLAUDE.md` to each indexed repo so Claude Code prefers codesight-mcp over reading full files:

```markdown
## Code Navigation

This repo is indexed in codesight-mcp. Use codesight-mcp MCP tools for code
exploration instead of reading full files:

- `search_symbols` — find functions/classes/types by name or description
- `get_file_outline` — all symbols in a file with signatures
- `get_symbol` — full source of a specific symbol
- `get_repo_outline` — directory structure and language breakdown
- `get_callers` / `get_callees` — call graph navigation
- `get_call_chain` — trace execution paths between two symbols
- `get_impact` — see what's affected by changing a symbol

Use `Read` only for content that isn't a named symbol (config files, etc).
```

---

## Tools

codesight-mcp exposes **28 MCP tools** organized into six categories:

### Indexing

| Tool | Description |
|------|-------------|
| `index_repo` | Index a GitHub repository (fetch, parse ASTs, extract symbols) |
| `index_folder` | Index a local folder (walk, parse ASTs, extract symbols) |
| `list_repos` | List all indexed repositories |
| `invalidate_cache` | Delete an index to force full re-index |

### Navigation

| Tool | Description |
|------|-------------|
| `get_repo_outline` | High-level overview: directories, file counts, language breakdown |
| `get_file_tree` | File tree of an indexed repo, optionally filtered by path prefix |
| `get_file_outline` | All symbols in a file with signatures and summaries |
| `get_symbol` | Full source code of a specific symbol (byte-offset retrieval) |
| `get_symbols` | Batch retrieval of multiple symbols in one call |
| `get_symbol_context` | Symbol + sibling symbols + parent class info in one call |

### Search

| Tool | Description |
|------|-------------|
| `search_symbols` | Search symbols by name, signature, summary, or docstring |
| `search_text` | Full-text search across indexed files (matches against redacted content) |
| `search_references` | Text search enriched with enclosing symbol context per hit |

### Code Graph

| Tool | Description |
|------|-------------|
| `get_callers` | Find all functions that call a given symbol |
| `get_callees` | Find all functions called by a given symbol |
| `get_call_chain` | Trace the execution path between two symbols (BFS with cycle detection) |
| `get_type_hierarchy` | Show inheritance tree — parents and children of a class |
| `get_imports` | Show import relationships for a file or symbol |
| `get_impact` | Impact analysis — everything affected downstream of a change |

### Analysis & Visualization

| Tool | Description |
| :--- | :--- |
| `analyze_complexity` | Find the most complex/risky symbols — cyclomatic complexity, cognitive complexity, nesting depth, fan-in/fan-out, composite risk score. Supports path filtering and sort modes. |
| `get_key_symbols` | Rank symbols by structural importance using PageRank on the call graph. Identifies the most connected and depended-upon symbols. |
| `get_diagram` | Generate Mermaid diagrams — call graphs, type hierarchies, import trees, and impact diagrams from the code graph. |
| `get_dead_code` | Find unreferenced symbols — functions and classes with zero callers or importers. |
| `get_status` | Server status — storage configuration, index stats, and feature flags. |
| `get_usage_stats` | Per-tool call counts, error rates, average response times, and uncalled tools. |

### Dependencies & Diffing

| Tool | Description |
|------|-------------|
| `get_dependencies` | External vs internal import analysis — which packages are used and by which files |
| `compare_symbols` | Symbol-level diff between two indexed versions using content hashes |
| `get_changes` | Map git diff to affected symbols with optional downstream impact analysis |

---

## Natural Language Examples

Once indexed, interact through your AI assistant using plain English:

### Finding Code
- *"Where is the `process_payment` function?"*
- *"Show me all classes related to authentication"*
- *"Find any code that handles database connections"*

### Understanding Relationships
- *"What functions call `validate_input`?"*
- *"What does `initialize_system` call?"*
- *"Show me the full call chain from `main` to `process_data`"*
- *"What's the inheritance hierarchy for `BaseController`?"*

### Impact Analysis
- *"If I change `calculate_tax`, what else is affected?"*
- *"Which files import the `utils` module?"*
- *"Show me everything downstream of `authenticate_user`"*

### Exploring Structure
- *"Give me an overview of this repository"*
- *"What symbols are in `src/server.py`?"*
- *"List all indexed repos"*

---

## Code Graph & Relationship Analysis

codesight-mcp builds an in-memory code graph from relationships extracted during AST parsing. No external graph database is required — the graph uses dict-of-sets adjacency lists, constructed at query time from the symbol index.

**How it works:**

1. During indexing, the AST parser extracts `calls`, `imports`, and `inherits_from` relationships for each symbol
2. These relationships are stored alongside symbol metadata in the JSON index
3. At query time, `CodeGraph.build(symbols)` constructs the graph from symbol dicts
4. Graph tools (callers, callees, call chains, impact) traverse this structure using BFS with cycle detection

**Compared to [CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext):** codesight-mcp uses no external database (FalkorDB/Neo4j). The trade-off is simplicity and zero-config vs. the ability to handle massive graphs. For most projects (thousands of files), the in-memory approach is fast and sufficient.

---

## Git Hooks: Auto-Reindex on Commit and Push

codesight-mcp includes git hooks that keep indexes current automatically:

| Hook | Trigger | Updates |
|------|---------|---------|
| `post-commit` | every commit | local folder index |
| `post-push` | every push | GitHub repo index (auto-detects remote) |

**Install in any repo:**

```bash
cp /path/to/codesight-mcp/hooks/post-commit .git/hooks/post-commit
cp /path/to/codesight-mcp/hooks/post-push   .git/hooks/post-push
chmod +x .git/hooks/post-commit .git/hooks/post-push
```

Both hooks run in the background so they never block your workflow. Remove `--no-ai` from either hook if you want AI-generated summaries updated automatically.

**One-time setup** — git hooks don't inherit your shell environment, so credentials and the binary path must be provided separately:

```bash
mkdir -p ~/.config/codesight-mcp
cat > ~/.config/codesight-mcp/env <<'EOF'
export GITHUB_TOKEN=ghp_...
export CODESIGHT_BIN=/path/to/.venv/bin/codesight-mcp
EOF
chmod 600 ~/.config/codesight-mcp/env
```

You can also index directly from the command line:

```bash
codesight-mcp index ~/src/myproject              # index a local folder
codesight-mcp index ~/src/myproject --no-ai     # skip AI summaries (faster)
codesight-mcp index-repo owner/myproject        # index a GitHub repo
```

---

## Security Model

codesight-mcp treats the connected AI as an untrusted principal. Every tool argument is validated before use. Every file path from the index is re-validated at retrieval time. Error messages are sanitized so system paths never leak.

| Layer | Defense |
|-------|---------|
| **Path validation** | 6-step chain: null bytes, traversal, length limits, resolution, containment, symlink checks |
| **Content boundaries** | Microsoft-style spotlighting markers to resist indirect prompt injection |
| **Error sanitization** | No raw exceptions or system paths in tool responses |
| **Allowed roots** | `CODESIGHT_ALLOWED_ROOTS` restricts which directories can be indexed |
| **Secret redaction** | Secrets in function bodies are redacted from API output; `CODESIGHT_NO_REDACT=1` disables with a logged warning |
| **Secrets at rest** | Index files in `~/.code-index/` contain raw source code including any embedded secrets. Store on an encrypted volume and restrict filesystem permissions. Override with `CODE_INDEX_PATH`. |
| **Prompt injection defense** | Nonce-based delimiters for AI summarization, injection phrase blocklist, kind-validated prompt interpolation |
| **Graph traversal limits** | BFS call-chain search capped at 5 paths and depth 50 to prevent resource exhaustion |

See [SECURITY.md](SECURITY.md) for the full threat model, defense matrix, and validation chain details. Architecture Decision Records for key security decisions are in [docs/decisions/](docs/decisions/).

---

## Data Handling

When `ANTHROPIC_API_KEY` is set, codesight-mcp sends function and class signatures to the Anthropic API for AI-generated summaries during indexing. No source code is sent — only signatures. To disable, omit the `ANTHROPIC_API_KEY` environment variable.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CODESIGHT_ALLOWED_ROOTS` | Colon-separated list of directories `index_folder` is allowed to index. **Required** for local folder indexing — denied by default if unset. Example: `/Users/you/src:/home/you/projects` |
| `GITHUB_TOKEN` | GitHub personal access token. Required for private repos; strongly recommended to avoid rate limits on public repos. |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI-generated symbol summaries. Optional — falls back to docstrings if unset. |
| `CODE_INDEX_PATH` | Custom storage directory for indexes. Default: `~/.code-index/` |
| `CODESIGHT_NO_REDACT` | Set to `1` to disable secret redaction in tool output. Logs a warning; `search_text` is disabled entirely when set. |
| `CODESIGHT_READ_ONLY` | Set to `1` to skip filesystem permission operations (fchmod/mkdir). Used automatically for non-destructive CLI commands in sandboxed environments. |
| `CODESIGHT_USAGE_LOG` | File path for persistent JSONL usage log. Without this, usage records are in-memory only (lost on restart). |
| `CODESIGHT_USAGE_ENABLED` | Set to `0` to disable usage logging. Default: `1` (enabled). |
| `CODESIGHT_USAGE_MAX_MEMORY` | Maximum number of in-memory usage records before eviction. Default: `10000`. |
| `CODESIGHT_LOG_LEVEL` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. All levels allowed. Default: `WARNING`. Takes precedence over `LOG_LEVEL`. |
| `LOG_LEVEL` | Fallback log level. Restricted to `WARNING`/`ERROR`/`CRITICAL` for security (ADV-LOW-10). Use `CODESIGHT_LOG_LEVEL` to unlock `DEBUG`/`INFO`. |

---

## Semantic Search

Search by intent instead of exact names. Requires the `semantic` extra:

```bash
pip install codesight-mcp[semantic]   # adds fastembed (~100MB ONNX runtime + model weights)
```

Without this extra, passing semantic params returns a helpful error explaining what to install.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `semantic` | bool | Hybrid keyword+semantic scoring (default weight: 0.7 semantic, 0.3 keyword) |
| `semantic_only` | bool | Pure semantic scoring, skips keyword matching entirely |
| `semantic_weight` | float | Blend ratio from 0.0 (keyword only) to 1.0 (semantic only) |

### Examples

```python
# Find by intent, not exact name
search_symbols(query="the function that validates credentials", semantic=True)

# Pure semantic search
search_symbols(query="password hashing utility", semantic_only=True)
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CODESIGHT_EMBED_PROVIDER` | Explicit provider selection (default: auto-detect) |
| `CODESIGHT_EMBED_MODEL` | Model override (default: `BAAI/bge-base-en-v1.5`) |
| `CODESIGHT_NO_SEMANTIC` | Set to `1` to disable semantic features entirely |

### How It Works

Embeddings are generated lazily on the first semantic query and cached in gzip-JSON sidecar files alongside the index. The cache is invalidated automatically on reindex. The default provider runs entirely on-device with no API calls. When `semantic=false` (the default), there is zero overhead -- embeddings are never loaded or computed.

Keyword scoring includes compound identifier splitting (`hash_password` → `{hash, password}`, `AuthManager` → `{auth, manager}`) and suffix stemming (`hashing` → `hash`, `validates` → `validate`), so intent-based queries match even without semantic search enabled.

---

## Attribution

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle. Code graph techniques adapted from [CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext). Security hardening inspired by [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

## License

MIT — see [LICENSE](LICENSE).
