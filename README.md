# codesight-mcp

<!-- codesight:counts ops=34 langs=66 tests=2594 -->

<p align="center">
  <br>
  <b>Security-hardened, token-efficient code intelligence for AI assistants.</b>
  <br><br>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/cmillstead/codesight-mcp?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/MCP-Compatible-green?style=flat-square" alt="MCP Compatible">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/tests-2594-brightgreen?style=flat-square" alt="Tests">
</p>

An **MCP server** that indexes local and GitHub codebases via tree-sitter AST parsing, then exposes 34 operations for symbol retrieval, code graph traversal, and impact analysis — available either as individual MCP tools (the default) or through a single `query` dispatch wrapper (advanced). All retrieval uses byte-offset precision to cut token costs by ~99% compared to sending full files. Supports 66 languages.

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle, with code graph techniques from [CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext) and security patterns from [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

---

## Quick Navigation

- [Features](#features)
- [Supported Languages](#supported-languages)
- [Quick Start](#quick-start)
- [Operations Reference](#operations)
- [Code Graph & Relationship Analysis](#code-graph--relationship-analysis)
- [Security Model](#security-model)
- [Git Hooks](#git-hooks-auto-reindex-on-commit-and-push)
- [Semantic Search](#semantic-search)
- [Environment Variables](#environment-variables)

---

## Features

### Code Indexing & Retrieval
- **Tree-sitter AST parsing** across 66 languages with byte-offset O(1) symbol retrieval
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
- **Per-tool trust annotations** — each of the 34 operations registers as its own MCP tool carrying `readOnlyHint`/`destructiveHint` annotations; source code in tool output is wrapped in `<<<UNTRUSTED_CODE_{random token}>>>` boundary markers (Microsoft spotlighting) that content cannot forge an end marker for, so it can never escape the boundary
- **2,594 tests** — adversarial, security, integration, benchmark, fuzz, and stress coverage with real temp directories

---

## Supported Languages

codesight-mcp supports **66 programming languages** via tree-sitter, including Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, C#, Ruby, Swift, Kotlin, PHP, Dart, Perl, Haskell, Scala, Erlang, and 49 more. See the [full language list](docs/development-guide.md) for details.

Each language parser extracts functions, classes, methods, parameters, call relationships, imports, and inheritance to build a comprehensive code graph.

---

## Quick Start

Platform support: POSIX only (Linux/macOS); Windows is not supported.

**Prerequisites:** `git`, Python ≥ 3.10, [`uv`](https://docs.astral.sh/uv/getting-started/installation/), and an MCP client (the examples below use the `claude` CLI). Everything after that comes from this repository.

### Step 1: Install

```bash
git clone https://github.com/cmillstead/codesight-mcp.git
cd codesight-mcp
uv sync            # creates .venv/ from the lockfile with pinned versions
```

`uv sync` creates the `.venv/` that every command below refers to. If you prefer pip, create the virtualenv yourself so those paths still resolve — and note this uses version ranges rather than the lockfile:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
```

Not published to PyPI — install from source only.

### Step 2: Register the MCP server

Register the `codesight-mcp` stdio entrypoint that Step 1 installed into `.venv/bin/`. Run this from the repo root:

```bash
claude mcp add codesight --scope user \
  -e CODESIGHT_ALLOWED_ROOTS="$HOME/src" \
  -e GITHUB_TOKEN=ghp_... \
  -- "$PWD/.venv/bin/codesight-mcp"
```

Two details that matter:

- **`--scope user`** registers the server for every project. Without it `claude mcp add` defaults to *local* scope, which binds the server to whichever project you ran it in — here, the codesight-mcp clone itself — so it would not load in the repos you actually want to explore.
- **The command path must be absolute.** `$PWD` expands at registration time; your client does not run from this directory. Likewise `CODESIGHT_ALLOWED_ROOTS` must cover the repos you intend to index — `$HOME/src` works on both Linux and macOS, and indexing is denied outside it.

This registers 34 MCP tools — one per operation — each carrying its own `readOnlyHint` / `destructiveHint` annotation, so your client can distinguish safe reads from index-mutating calls.

If your client reads a project-level config file instead, `.mcp.json.example` shows the equivalent registration. Its `command` is relative, which only resolves when the client is launched from this repo root; anywhere else, substitute an absolute path.

| Variable | Required | Description |
|----------|----------|-------------|
| `CODESIGHT_ALLOWED_ROOTS` | Yes (local) | Colon-separated directories `index-folder` may access. Denied by default if unset. |
| `GITHUB_TOKEN` | Yes (GitHub) | Required for private repos; recommended to avoid rate limits on public repos. |
| `ANTHROPIC_API_KEY` | No | Enables AI-generated symbol summaries. Falls back to docstrings if unset. |

### Step 3: Verify the install

```bash
.venv/bin/codesight-mcp tools        # lists every registered tool as JSON
.venv/bin/codesight-mcp get-status   # server status, storage config, index stats
```

Both exit 0 on success. Running `.venv/bin/codesight-mcp` with no arguments starts the stdio server and waits for an MCP client — it will look like it has hung, which is correct; press Ctrl-C.

Then confirm the client side. Start a new client session (or reconnect) first — an already-running session will not pick up a server registered in Step 2. Ask your AI: *"What's the codesight server status?"* It should call `get_status` and report the indexed repo count.

### Step 4: Index a repository

Before any other operations work, you must index at least one repository. Ask your AI:

- **Local folder:** *"Index the repo at ~/src/myproject"*
- **GitHub repo:** *"Index the GitHub repo owner/myproject"*

The AI calls the `index_folder` or `index_repo` tool, which fetches files, parses ASTs, and extracts symbols into `~/.code-index/`. Subsequent calls skip unchanged files automatically.

### Step 5: Explore

Once indexed, the AI uses `get_repo_outline`, `search_symbols`, and `get_symbol` to navigate your codebase — retrieving only the symbols it needs instead of entire files.

### Step 6 (optional): Add a CLAUDE.md to indexed repos

Add a `CLAUDE.md` to each indexed repo so Claude Code prefers codesight-mcp over reading full files:

```markdown
## Code Navigation

This repo is indexed in codesight-mcp. Use the codesight tools for all code
exploration instead of reading full files:

- `mcp__codesight__search_symbols` — find functions/classes/types by name or description
- `mcp__codesight__get_file_outline` — all symbols in a file with signatures
- `mcp__codesight__get_symbol` — full source of a specific symbol
- `mcp__codesight__get_repo_outline` — directory structure and language breakdown
- `mcp__codesight__get_callers` / `mcp__codesight__get_callees` — call graph navigation
- `mcp__codesight__get_call_chain` — trace execution paths between two symbols
- `mcp__codesight__get_impact` — see what's affected by changing a symbol

Use `Read` only for content that isn't a named symbol (config files, etc).
```

If you registered the dispatch wrapper instead (see below), replace those names with a single call: `mcp__codesight__query({operation: "search-symbols", params: {...}})`.

### Advanced: single `query` dispatch tool

An alternative TypeScript wrapper collapses all 34 operations behind **one** MCP tool named `query`, which accepts `{ operation, params }`. Use it if you would rather present your client with a single tool than one tool per operation, at the cost of losing per-tool annotations.

> **This is a separate repository, not part of this one.** It lives at [cmillstead/codesight-plugin](https://github.com/cmillstead/codesight-plugin) and must be cloned independently. It also requires [`bun`](https://bun.sh) (`curl -fsSL https://bun.sh/install | bash`), which nothing else here needs. A future release replaces it with a generated `wrapper/mcp-server.ts` inside this repo; until then the two codebases can drift.

```bash
git clone https://github.com/cmillstead/codesight-plugin.git ~/src/codesight-plugin

claude mcp add codesight --scope user \
  -e CODESIGHT_ALLOWED_ROOTS="$HOME/src" \
  -e CODESIGHT_BIN="$PWD/.venv/bin/codesight-mcp" \
  -e GITHUB_TOKEN=ghp_... \
  -- bun run ~/src/codesight-plugin/mcp-server.ts
```

`CODESIGHT_BIN` is required here: the wrapper spawns the Python engine from this repo, and `uv sync` does not put `.venv/bin` on your PATH. Run the command from this repo root so `$PWD` resolves correctly.

Because all operations flow through a single entry point, per-operation `readOnlyHint`/`destructiveHint` annotations do not apply in the usual per-tool way. Instead, the wrapper enforces a trust boundary at the parameter level: path-bearing fields are validated against a trusted prefix before dispatch, and output from operations that return repo-controlled text is wrapped in `<UNTRUSTED_OUTPUT>` framing tags so the consuming agent treats the content as data rather than instructions.

---

## Operations

codesight-mcp exposes **34 operations**, organized into seven categories. On the default path each is its own MCP tool, invoked by its underscored name (`mcp__codesight__get_symbol`). Through the [dispatch wrapper](#advanced-single-query-dispatch-tool) they are invoked as `mcp__codesight__query({operation: "<name>", params: {...}})` using the kebab-case names below.

### Indexing

| Operation | Description |
|-----------|-------------|
| `index-repo` | Index a GitHub repository (fetch, parse ASTs, extract symbols) |
| `index-folder` | Index a local folder (walk, parse ASTs, extract symbols) |
| `list-repos` | List all indexed repositories |
| `invalidate-cache` | Delete an index to force full re-index |

### Navigation

| Operation | Description |
|-----------|-------------|
| `get-repo-outline` | High-level overview: directories, file counts, language breakdown |
| `get-file-tree` | File tree of an indexed repo, optionally filtered by path prefix |
| `get-file-outline` | All symbols in a file with signatures and summaries |
| `get-symbol` | Full source code of a specific symbol (byte-offset retrieval) |
| `get-symbols` | Batch retrieval of multiple symbols in one call |
| `get-symbol-context` | Symbol + sibling symbols + parent class info in one call |
| `get-key-symbols` | Rank symbols by structural importance using PageRank on the call graph |

### Search

| Operation | Description |
|-----------|-------------|
| `search-symbols` | Search symbols by name, signature, summary, or docstring |
| `search-text` | Full-text search across indexed files (matches against redacted content) |
| `search-references` | Text search enriched with enclosing symbol context per hit |

### Code Graph

| Operation | Description |
|-----------|-------------|
| `get-callers` | Find all functions that call a given symbol |
| `get-callees` | Find all functions called by a given symbol |
| `get-call-chain` | Trace the execution path between two symbols (BFS with cycle detection) |
| `get-type-hierarchy` | Show inheritance tree — parents and children of a class |
| `get-imports` | Show import relationships for a file or symbol |
| `get-impact` | Impact analysis — everything affected downstream of a change |
| `get-diagram` | Generate Mermaid diagrams — call graphs, type hierarchies, import trees, and impact diagrams |

### Analysis & Visualization

| Operation | Description |
| :-------- | :---------- |
| `analyze-complexity` | Find the most complex/risky symbols — cyclomatic complexity, cognitive complexity, nesting depth, fan-in/fan-out, composite risk score. Supports path filtering and sort modes. |
| `get-dead-code` | Find unreferenced symbols — functions and classes with zero callers or importers. |
| `get-status` | Server status — storage configuration, index stats, and feature flags. |
| `get-usage-stats` | Per-operation call counts, error rates, average response times, and uncalled operations. |
| `verify` | Verify index integrity — checksums, symbol consistency, and file existence. |
| `lint-index` | Audit index quality — missing fields, orphaned symbols, stale data. |

### Security

| Operation | Description |
|-----------|-------------|
| `scan-security` | Scan symbols for dangerous API usage patterns (19 OWASP/CWE rules) |
| `generate-sbom` | Generate Software Bill of Materials (CycloneDX, SPDX, or internal JSON) |
| `check-licenses` | Analyze dependency licenses from lockfiles and flag risks |
| `trace-taint` | Forward BFS source-to-sink taint analysis via code graph |

### Dependencies & Diffing

| Operation | Description |
|-----------|-------------|
| `get-dependencies` | External vs internal import analysis — which packages are used and by which files |
| `compare-symbols` | Symbol-level diff between two indexed versions using content hashes |
| `get-changes` | Map git diff to affected symbols with optional downstream impact analysis |

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
| `CODESIGHT_ALLOWED_ROOTS` | Colon-separated list of directories `index-folder` is allowed to index. **Required** for local folder indexing — denied by default if unset. Example: `/Users/you/src:/home/you/projects` |
| `GITHUB_TOKEN` | GitHub personal access token. Required for private repos; strongly recommended to avoid rate limits on public repos. |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI-generated symbol summaries. Optional — falls back to docstrings if unset. |
| `CODE_INDEX_PATH` | Custom storage directory for indexes. Default: `~/.code-index/` |
| `CODESIGHT_NO_REDACT` | Set to `1` to disable secret redaction in tool output. Logs a warning; the `search-text` operation is disabled entirely when set. |
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
mcp__codesight__search_symbols(repo="myproject", query="the function that validates credentials", semantic=True)

# Pure semantic search
mcp__codesight__search_symbols(repo="myproject", query="password hashing utility", semantic_only=True)
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
