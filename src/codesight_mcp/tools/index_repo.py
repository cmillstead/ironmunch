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
from ..security import sanitize_repo_identifier
from ..core.errors import sanitize_error
from ..core.validation import ValidationError
from .registry import ToolSpec, register
from mcp.types import ToolAnnotations
from ._indexing_common import parse_source_files, finalize_index

# ADV-INFO-2: Freeze GITHUB_TOKEN at import time for consistency with other
# frozen env vars (_NO_REDACT, _CODE_INDEX_PATH, _ANTHROPIC_BASE_URL).
_GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "")


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
    except (ValueError, ValidationError) as exc:
        return {"success": False, "error": sanitize_error(exc)}

    # Get GitHub token from frozen env if not provided
    if not github_token:
        github_token = _GITHUB_TOKEN or None

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
        try:
            gitignore_content = await fetch_gitignore(owner, repo, github_token)
        except (httpx.HTTPError, OSError, ValueError):
            gitignore_content = ""

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
                except (httpx.HTTPError, OSError, ValueError):
                    return path, ""

        tasks = [fetch_with_limit(path) for path in source_files]
        file_contents = await asyncio.gather(*tasks)

        # Parse files using shared pipeline
        all_symbols, languages, raw_files, parsed_files, parse_fail_count = (
            parse_source_files(file_contents)
        )

        if parse_fail_count > 0:
            warnings.append(f"{parse_fail_count} file(s) failed to parse")

        if not all_symbols:
            return {"success": False, "error": "No symbols extracted"}

        # Run summarization in thread to avoid blocking the event loop
        result = await asyncio.to_thread(
            finalize_index,
            owner=owner,
            name=repo,
            all_symbols=all_symbols,
            languages=languages,
            raw_files=raw_files,
            parsed_files=parsed_files,
            warnings=warnings,
            use_ai_summaries=use_ai_summaries,
            storage_path=storage_path,
            source_file_count=len(source_files),
        )

        return result

    except Exception as e:
        # RC-011: Intentionally broad — outer error boundary for indexing pipeline.
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
    annotations=ToolAnnotations(title="Index Repository", readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True),
))
