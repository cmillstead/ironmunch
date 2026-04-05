# codesight-mcp — Project Overview

**Generated:** 2026-03-10 | **Scan Level:** Exhaustive | **Phase:** 1 of 4

## Summary

codesight-mcp is a security-hardened MCP (Model Context Protocol) server that indexes local and GitHub codebases via tree-sitter AST parsing. It exposes 34 tools for symbol retrieval, code graph traversal, and impact analysis — all with byte-offset precision to cut token costs by ~99% compared to sending full files. Supports 66 programming languages.

Based on [jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) by J. Gravelle, with code graph techniques from [CodeGraphContext](https://github.com/CodeGraphContext/CodeGraphContext) and security patterns from [basalt-mcp](https://github.com/cmillstead/basalt-mcp).

## Project Classification

| Attribute | Value |
|-----------|-------|
| **Repository Type** | Monolith |
| **Project Type** | Python Library (MCP Server) |
| **Primary Language** | Python 3.10+ |
| **Build System** | Hatchling |
| **Package Manager** | uv (with lockfile) |
| **License** | MIT |
| **GitHub** | cmillstead/codesight-mcp |

## Technology Stack

| Category | Technology | Version | Purpose |
|----------|-----------|---------|---------|
| **Runtime** | Python | >=3.10 | Core language |
| **Protocol** | MCP SDK | >=1.26.0, <2.0.0 | Model Context Protocol server framework |
| **Parsing** | tree-sitter | >=0.23.0 | AST parsing engine |
| **Parsing** | tree-sitter-python/js/ts/go/rust/java/php/c/cpp/c#/ruby/swift/kotlin | Various | Language-specific grammars (13 standalone packages) |
| **Parsing** | tree-sitter-language-pack | >=0.13.0 | Dart + Perl grammars (no standalone PyPI packages) |
| **HTTP** | httpx | >=0.27.0, <1.0.0 | GitHub API client (`trust_env=False`) |
| **AI** | anthropic SDK | >=0.40.0, <1.0.0 | Optional AI-generated symbol summaries |
| **Filesystem** | pathspec | >=0.12.0, <1.0.0 | Gitignore pattern matching |
| **Testing** | pytest | >=7.0.0, <9.0.0 | Test framework |
| **Testing** | pytest-asyncio | >=0.21.0, <1.0.0 | Async test support |
| **CI** | GitHub Actions | SHA-pinned | CI pipeline (uv sync --frozen, pytest) |
| **Build** | hatchling | ==1.27.0 (pinned) | Wheel building |

## Architecture Pattern

**Layered library architecture** with declarative tool registry:

```
server.py (286 lines)
  ├── Dispatcher: argument sanitization, rate limiting, error sanitization
  ├── Tool Registry: declarative ToolSpec dataclass, auto-registration
  │
  ├── tools/           (34 tool modules, each exports a ToolSpec)
  │   ├── Indexing:    index_repo, index_folder, list_repos, invalidate_cache
  │   ├── Navigation:  get_repo_outline, get_file_tree, get_file_outline, get_symbol, get_symbols
  │   ├── Search:      search_symbols, search_text
  │   ├── Code Graph:  get_callers, get_callees, get_call_chain, get_type_hierarchy, get_imports, get_impact, get_dead_code
  │   └── Analysis:    analyze_complexity, get_key_symbols, get_diagram, get_status
  │
  ├── parser/          (AST parsing, symbol extraction, code graph)
  │   ├── languages.py    — LanguageSpec registry for 66 languages
  │   ├── extractor.py    — tree-sitter AST → Symbol extraction
  │   ├── symbols.py      — Symbol dataclass, ID generation, content hashing
  │   ├── hierarchy.py    — Symbol tree (nesting) from flat symbol lists
  │   ├── graph.py        — CodeGraph: adjacency-list graph, BFS, PageRank
  │   └── complexity.py   — Cyclomatic/cognitive complexity, nesting depth
  │
  ├── core/            (security + infrastructure)
  │   ├── validation.py   — 6-step path validation chain
  │   ├── boundaries.py   — Content boundary markers (spotlighting)
  │   ├── errors.py       — Error sanitization
  │   ├── limits.py       — Resource limit constants
  │   ├── rate_limiting.py — Persistent file-backed rate limiter
  │   └── locking.py      — Advisory file locks for index serialization
  │
  ├── storage/         (index persistence)
  │   └── index_store.py  — JSON/gzip index read/write/delete, atomic writes
  │
  ├── summarizer/      (AI summaries)
  │   └── batch_summarize.py — Anthropic API batch summarization with nonce protection
  │
  ├── security.py      — Secret detection, redaction, content sanitization
  └── discovery.py     — File discovery with gitignore, binary detection, secret filtering
```

## Existing Documentation

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Comprehensive user guide: features, 34-tool reference, quick start, security model, env vars, git hooks |
| [SECURITY.md](../SECURITY.md) | Full threat model, 53-row defense matrix, validation chain, resource limits, scan history |
| [CLAUDE.md](../CLAUDE.md) | AI-context: tells Claude Code to use codesight-mcp tools instead of reading files |
| [docs/plans/](./plans/) | 19 historical plan documents covering security scans, adversarial testing, feature designs, refactoring |
| [.github/workflows/ci.yml](../.github/workflows/ci.yml) | CI: Python 3.12, uv sync --frozen, pytest, SHA-pinned actions |

## Key Metrics

| Metric | Value |
|--------|-------|
| Source files | ~47 Python files |
| Test files | ~40 Python files |
| Test count | 2,495 |
| Tools | 34 MCP tools |
| Languages supported | 66 |
| Security scan rounds | 12 |
| Entry point | `codesight_mcp.server:main` |

## Entry Points

- **MCP Server:** `codesight-mcp` (stdio transport via `mcp.server.stdio`)
- **CLI:** `codesight-mcp index [path] [--no-ai]` — index a local folder
- **CLI:** `codesight-mcp index-repo <url> [--no-ai]` — index a GitHub repo
- **Git Hooks:** `hooks/post-commit` (auto-reindex on commit), `hooks/post-push` (auto-reindex on push)
