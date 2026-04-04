"""Shared indexing pipeline used by index_folder and index_repo.

Extracts the common parse-collect and finalize-save logic so both tools
share a single implementation.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Iterable

from ..core.limits import MAX_FILE_COUNT
from ..parser import parse_file, LANGUAGE_EXTENSIONS

logger = logging.getLogger(__name__)
from ..parser.graph import CodeGraph
from ..storage import IndexStore
from ..summarizer import summarize_symbols


def parse_source_files(
    file_iterator: Iterable[tuple[str, str]],
) -> tuple[list, dict[str, int], dict[str, str], list[str], int]:
    """Parse an iterable of source files and collect symbols.

    Args:
        file_iterator: Iterable of ``(rel_path, content)`` tuples.

    Returns:
        Tuple of ``(all_symbols, languages, raw_files, parsed_files, parse_fail_count)``.
    """
    all_symbols: list = []
    languages: dict[str, int] = {}
    raw_files: dict[str, str] = {}
    parsed_files: list[str] = []
    parse_fail_count = 0

    for rel_path, content in file_iterator:
        if not content:
            continue

        _, ext = os.path.splitext(rel_path)
        language = LANGUAGE_EXTENSIONS.get(ext)

        if not language:
            continue

        try:
            symbols = parse_file(content, rel_path, language)
            if symbols:
                all_symbols.extend(symbols)
                languages[language] = languages.get(language, 0) + 1
                raw_files[rel_path] = content
                parsed_files.append(rel_path)
        except (ValueError, TypeError, KeyError, OSError) as exc:
            logger.debug("Failed to parse %s: %s", rel_path, exc)
            parse_fail_count += 1
            continue

    return all_symbols, languages, raw_files, parsed_files, parse_fail_count


def finalize_index(
    *,
    owner: str,
    name: str,
    all_symbols: list,
    languages: dict[str, int],
    raw_files: dict[str, str],
    parsed_files: list[str],
    warnings: list[str],
    use_ai_summaries: bool,
    storage_path: str | None,
    source_file_count: int,
    max_file_count: int = MAX_FILE_COUNT,
    git_head: str = "",
) -> dict:
    """Summarize symbols, save to store, and build the result dict.

    Args:
        owner: Repository owner (e.g. ``"local"`` or GitHub owner).
        name: Repository / folder name.
        all_symbols: Parsed symbols to summarize and save.
        languages: Language -> file count mapping.
        raw_files: ``{rel_path: content}`` for storage.
        parsed_files: List of successfully parsed relative paths.
        warnings: Mutable warnings list (may be appended to).
        use_ai_summaries: Whether to use AI for summaries.
        storage_path: Custom storage base path (or None for default).
        source_file_count: Total number of discovered source files (before parsing).
        max_file_count: Limit for the "many files" warning.

    Returns:
        Result dict with ``success=True`` and indexing metadata.
    """
    # Generate summaries
    all_symbols = summarize_symbols(all_symbols, use_ai=use_ai_summaries)

    # Generate indexed_at timestamp before saving to avoid re-loading the index
    indexed_at = datetime.now(timezone.utc).isoformat()

    # Save index
    store = IndexStore(base_path=storage_path)
    store.save_index(
        owner=owner,
        name=name,
        source_files=parsed_files,
        symbols=all_symbols,
        raw_files=raw_files,
        languages=languages,
        git_head=git_head,
    )

    # Clear the in-memory graph cache so stale graphs aren't reused
    CodeGraph.clear_cache()

    result: dict = {
        "success": True,
        "repo": f"{owner}/{name}",
        "indexed_at": indexed_at,
        "file_count": len(parsed_files),
        "symbol_count": len(all_symbols),
        "languages": languages,
        "files": parsed_files[:20],  # Limit files in response
    }

    if source_file_count >= max_file_count:
        warnings.append(f"Repository has many files; indexed first {max_file_count}")

    if warnings:
        result["warnings"] = warnings

    return result
