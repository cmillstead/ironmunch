# Source Tree Analysis — codesight-mcp

> Generated: 2026-03-09 | Scan Level: Exhaustive | Project Type: Python Library (MCP Server)

## Directory Structure

```
codesight-mcp/
├── pyproject.toml              # Build config (hatchling), dependencies, entry point
├── uv.lock                     # Deterministic dependency lockfile
├── README.md                   # Project overview and usage
├── SECURITY.md                 # Security policy
├── CLAUDE.md                   # AI assistant navigation guide
├── benchmark/                  # Performance benchmarks
│   └── bench_parse.py          # Parser benchmark script
├── src/codesight_mcp/          # Main package (41 source files)
│   ├── __init__.py             # Package init
│   ├── server.py               # ★ ENTRY POINT — MCP server, tool dispatch, argument sanitization
│   ├── discovery.py            # File discovery (local + GitHub), gitignore, symlink detection
│   ├── security.py             # Secret/binary classification, signature redaction, repo ID validation
│   ├── core/                   # Infrastructure & security primitives
│   │   ├── boundaries.py       # Untrusted content wrapping (prompt injection defense)
│   │   ├── errors.py           # Error sanitization (path stripping, generic fallbacks)
│   │   ├── limits.py           # Resource constants (MAX_FILE_SIZE=500KB, MAX_INDEX_SIZE=200MB, etc.)
│   │   ├── locking.py          # Atomic writes, exclusive file locks, symlink-safe I/O
│   │   ├── rate_limiting.py    # Per-tool (60/min) + global (300/min) rate limiting
│   │   └── validation.py       # 6-step path validation chain (traversal, symlinks, containment)
│   ├── parser/                 # AST parsing engine
│   │   ├── symbols.py          # Symbol dataclass (id, kind, name, signature, calls, imports, etc.)
│   │   ├── extractor.py        # tree-sitter AST parsing → Symbol extraction (15 languages)
│   │   ├── languages.py        # LanguageSpec definitions for all 15 languages
│   │   ├── complexity.py       # Cyclomatic, cognitive complexity, nesting depth metrics
│   │   ├── graph.py            # CodeGraph: call graph, type hierarchy, PageRank, impact analysis
│   │   └── hierarchy.py        # Flat symbol list → nested tree conversion
│   ├── storage/                # Index persistence
│   │   └── index_store.py      # CodeIndex + IndexStore: gzip indexes, atomic writes, incremental updates
│   ├── summarizer/             # Symbol documentation
│   │   └── batch_summarize.py  # 3-tier summarization: docstring → AI (Claude Haiku) → signature fallback
│   └── tools/                  # MCP tool implementations (22 tools)
│       ├── registry.py         # Declarative ToolSpec registry
│       ├── _common.py          # RepoContext resolution, parse_repo (fuzzy matching), graph query setup
│       ├── _indexing_common.py  # Shared indexing: parse_source_files, finalize_index
│       ├── index_repo.py       # Index GitHub repository (async fetch + parse)
│       ├── index_folder.py     # Index local folder (with ALLOWED_ROOTS security)
│       ├── invalidate_cache.py # Delete index + cached data (requires confirm=True)
│       ├── list_repos.py       # List all indexed repositories
│       ├── status.py           # Health check snapshot
│       ├── get_repo_outline.py # High-level repo overview (dirs, languages, symbol counts)
│       ├── get_file_tree.py    # Directory tree with optional path prefix filter
│       ├── get_file_outline.py # All symbols in a file with signatures
│       ├── get_symbol.py       # Full source retrieval by ID, file+line, or batch
│       ├── search_symbols.py   # Symbol search with weighted scoring (cross-repo)
│       ├── search_text.py      # Full-text search with secret redaction (cross-repo)
│       ├── get_callers.py      # Reverse call graph traversal
│       ├── get_callees.py      # Forward call graph traversal
│       ├── get_call_chain.py   # BFS path finding between two symbols
│       ├── get_type_hierarchy.py # Class inheritance tree (parents + children)
│       ├── get_imports.py      # File-level import relationships
│       ├── get_impact.py       # Transitive impact analysis (callers + inheritors + importers)
│       ├── get_hotspots.py     # Complexity/risk ranking (cyclomatic, cognitive, fan-in/out)
│       ├── get_key_symbols.py  # PageRank-based structural importance ranking
│       ├── get_diagram.py      # Mermaid diagram generation (call_graph, hierarchy, imports, impact)
│       └── get_dead_code.py    # Unused symbol detection (zero callers)
├── tests/                      # Test suite (51 files, 1,073 tests)
│   ├── conftest.py             # Shared fixtures (tmp_index_store, python_index)
│   ├── core/                   # Core infrastructure tests (79 tests)
│   │   ├── test_core_boundaries.py
│   │   ├── test_core_errors.py
│   │   ├── test_core_limits.py
│   │   ├── test_core_locking.py
│   │   ├── test_core_rate_limiting.py
│   │   └── test_core_validation.py
│   ├── unit/                   # Parser & analysis unit tests (276 tests)
│   │   ├── test_parser.py
│   │   ├── test_languages.py
│   │   ├── test_new_languages.py
│   │   ├── test_extraction_callables.py
│   │   ├── test_complexity.py
│   │   ├── test_graph.py
│   │   ├── test_discovery.py
│   │   ├── test_hotspots.py
│   │   ├── test_key_symbols.py
│   │   ├── test_diagram.py
│   │   └── test_summarizer.py
│   ├── tools/                  # Tool function tests (201 tests)
│   │   ├── test_tools_index_repo.py
│   │   ├── test_tools_index_folder.py
│   │   ├── test_tools_invalidate_cache.py
│   │   ├── test_tools_list_repos.py
│   │   ├── test_tools_status.py
│   │   ├── test_tools_repo_outline.py
│   │   ├── test_tools_file_tree.py
│   │   ├── test_tools_file_outline.py
│   │   ├── test_tools_get_symbol.py
│   │   ├── test_tools_get_symbol_file_line.py
│   │   ├── test_tools_search_symbols.py
│   │   ├── test_search_text.py
│   │   ├── test_graph_tools.py
│   │   ├── test_tools_get_dead_code.py
│   │   ├── test_cross_repo_search.py
│   │   └── test_diff_aware_indexing.py
│   ├── security/               # Adversarial & security tests (417 tests)
│   │   ├── test_adversarial.py
│   │   ├── test_adversarial_chaos.py
│   │   ├── test_adversarial_discovery.py
│   │   ├── test_adversarial_metadata.py
│   │   ├── test_adversarial_misc.py
│   │   ├── test_adversarial_storage.py
│   │   ├── test_adv_findings.py
│   │   ├── test_adv_scan_v2.py
│   │   ├── test_adv_scan_v3.py
│   │   ├── test_hardening.py
│   │   ├── test_no_redact.py
│   │   ├── test_security_facade.py
│   │   └── test_storage_hardening.py
│   ├── server/                 # Server & registry tests (76 tests)
│   │   ├── test_server.py
│   │   └── test_registry.py
│   ├── storage/                # Storage persistence tests (15 tests)
│   │   └── test_storage.py
│   └── integration/            # End-to-end pipeline tests (9 tests)
│       └── test_integration.py
└── .github/
    └── workflows/
        └── ci.yml              # GitHub Actions: Python 3.12, uv, pytest
```

## Critical Folders

| Folder | Purpose | Key Insight |
|--------|---------|-------------|
| `src/codesight_mcp/core/` | Security & infrastructure primitives | 6-step path validation chain, atomic I/O, rate limiting |
| `src/codesight_mcp/parser/` | AST parsing engine | 15-language support via declarative LanguageSpec pattern |
| `src/codesight_mcp/storage/` | Index persistence | Gzip compression, atomic writes, incremental updates |
| `src/codesight_mcp/summarizer/` | Symbol documentation | 3-tier: docstring → AI → signature fallback |
| `src/codesight_mcp/tools/` | MCP tool implementations | 22 tools with declarative ToolSpec registry |
| `tests/security/` | Adversarial testing | 417 tests (39% of suite), real filesystem, no mocking |

## Entry Points

| Entry Point | Location | Purpose |
|-------------|----------|---------|
| `main()` | `server.py:main` | MCP server startup (registered in pyproject.toml) |
| `codesight-mcp` | CLI command | Maps to `codesight_mcp.server:main` via `[project.scripts]` |

## Key Symbols by Structural Importance (PageRank)

| Rank | Symbol | File | Fan-In | Impact |
|------|--------|------|--------|--------|
| 1 | `ValidationError` | core/validation.py | 16 | 283 |
| 2 | `IndexStore` | storage/index_store.py | 155 | 463 |
| 3 | `parse_file` | parser/extractor.py | 115 | 143 |
| 4 | `sanitize_repo_identifier` | security.py | 51 | 280 |
| 5 | `sanitize_signature_for_api` | security.py | 52 | 309 |
| 6 | `RepoContext.resolve` | tools/_common.py | 57 | 444 |
| 7 | `validate_path` | core/validation.py | 59 | 112 |
| 8 | `Symbol` | parser/symbols.py | 64 | 177 |

## Hotspots (Highest Risk Score)

| Symbol | File | Risk | Cyclomatic | Cognitive | LOC |
|--------|------|------|------------|-----------|-----|
| `index_folder` | tools/index_folder.py | 0.81 | 37 | 105 | 241 |
| `discover_local_files` | discovery.py | 0.74 | 36 | 87 | 175 |
| `load_index` | storage/index_store.py | 0.67 | 40 | 58 | 124 |
| `incremental_save` | storage/index_store.py | 0.48 | 22 | 58 | 139 |
| `_sanitize_arguments` | server.py | 0.45 | 27 | 42 | 67 |
