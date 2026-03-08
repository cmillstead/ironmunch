"""Index a GitHub repository -- fetch, parse, summarize, save.

This is a thin wrapper that delegates discovery to ``codesight_mcp.discovery``
(already extracted and ported). The tool handles orchestration: fetching
content, parsing, summarizing, and saving to the IndexStore.
"""

import asyncio
import os
from typing import Optional

import httpx

from ..discovery import (
    parse_github_url,
    fetch_repo_tree,
    fetch_file_content,
    fetch_gitignore,
    discover_source_files,
)
from ..parser import parse_file, LANGUAGE_EXTENSIONS
from ..security import sanitize_repo_identifier
from ..core.errors import sanitize_error
from ..core.limits import MAX_FILE_COUNT, GITHUB_API_TIMEOUT
from ..parser.graph import CodeGraph
from ..storage import IndexStore
from ..summarizer import summarize_symbols
from .registry import ToolSpec, register


async def index_repo(
    url: str,
    use_ai_summaries: bool = True,
    github_token: Optional[str] = None,
    storage_path: Optional[str] = None,
) -> dict:
    """Index a GitHub repository.

    Args:
        url: GitHub repository URL or owner/repo string.
        use_ai_summaries: Whether to use AI for symbol summaries.
        github_token: GitHub API token (optional, for private repos/higher rate limits).
        storage_path: Custom storage path (default: ~/.code-index/).

    Returns:
        Dict with indexing results.
    """
    # Parse URL
    try:
        owner, repo = parse_github_url(url)
    except ValueError as e:
        return {"success": False, "error": sanitize_error(e)}

    # --- security gate: validate repo identifiers ---
    try:
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(repo)
    except Exception as exc:
        return {"success": False, "error": sanitize_error(exc)}

    # Get GitHub token from env if not provided
    if not github_token:
        github_token = os.environ.get("GITHUB_TOKEN")

    warnings: list[str] = []

    try:
        # Fetch tree
        try:
            tree_entries = await fetch_repo_tree(owner, repo, github_token)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"success": False, "error": f"Repository not found: {owner}/{repo}"}
            elif e.response.status_code == 403:
                return {"success": False, "error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN."}
            return {"success": False, "error": sanitize_error(e)}

        # Fetch .gitignore
        gitignore_content = await fetch_gitignore(owner, repo, github_token)

        # Discover source files (uses codesight_mcp.discovery)
        source_files = discover_source_files(tree_entries, gitignore_content)

        if not source_files:
            return {"success": False, "error": "No source files found"}

        # Fetch all file contents concurrently
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests

        async def fetch_with_limit(path: str) -> tuple[str, str]:
            async with semaphore:
                try:
                    content = await fetch_file_content(owner, repo, path, github_token)
                    return path, content
                except Exception:
                    return path, ""

        tasks = [fetch_with_limit(path) for path in source_files]
        file_contents = await asyncio.gather(*tasks)

        # Parse each file
        all_symbols = []
        languages: dict[str, int] = {}
        raw_files: dict[str, str] = {}
        parsed_files: list[str] = []
        parse_fail_count = 0

        for path, content in file_contents:
            if not content:
                continue

            _, ext = os.path.splitext(path)
            language = LANGUAGE_EXTENSIONS.get(ext)

            if not language:
                continue

            try:
                symbols = parse_file(content, path, language)
                if symbols:
                    all_symbols.extend(symbols)
                    languages[language] = languages.get(language, 0) + 1
                    raw_files[path] = content
                    parsed_files.append(path)
            except Exception:
                parse_fail_count += 1
                continue

        if parse_fail_count > 0:
            warnings.append(f"{parse_fail_count} file(s) failed to parse")

        if not all_symbols:
            return {"success": False, "error": "No symbols extracted"}

        # Generate summaries (run in thread to avoid blocking the event loop)
        all_symbols = await asyncio.to_thread(summarize_symbols, all_symbols, use_ai=use_ai_summaries)

        # Save index
        store = IndexStore(base_path=storage_path)
        store.save_index(
            owner=owner,
            name=repo,
            source_files=parsed_files,
            symbols=all_symbols,
            raw_files=raw_files,
            languages=languages,
        )

        # Clear the in-memory graph cache so stale graphs aren't reused
        CodeGraph.clear_cache()

        result: dict = {
            "success": True,
            "repo": f"{owner}/{repo}",
            "indexed_at": store.load_index(owner, repo).indexed_at,
            "file_count": len(parsed_files),
            "symbol_count": len(all_symbols),
            "languages": languages,
            "files": parsed_files[:20],  # Limit files in response
        }

        if len(source_files) >= MAX_FILE_COUNT:
            warnings.append(f"Repository has many files; indexed first {MAX_FILE_COUNT}")

        if warnings:
            result["warnings"] = warnings

        return result

    except Exception as e:
        return {"success": False, "error": sanitize_error(e)}


_spec = register(ToolSpec(
    name="index_repo",
    description=(
        "Index a GitHub repository's source code. Fetches files, "
        "parses ASTs, extracts symbols, and saves to local storage. "
        "Full file content (including function bodies) is stored locally at ~/.code-index/; "
        "secrets embedded in function bodies are redacted from API output but stored at rest."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "GitHub repository URL or owner/repo string",
            },
            "use_ai_summaries": {
                "type": "boolean",
                "description": (
                    "Use AI to generate symbol summaries (requires ANTHROPIC_API_KEY). "
                    "When true, code signatures are sent to the Anthropic API for summarization. "
                    "When false, uses docstrings or signature fallback."
                ),
                "default": True,
            },
        },
        "required": ["url"],
    },
    handler=lambda args, storage_path: index_repo(
        url=args["url"],
        use_ai_summaries=args.get("use_ai_summaries", True),
        storage_path=storage_path,
    ),
    index_gate=True,
    required_args=["url"],
))
