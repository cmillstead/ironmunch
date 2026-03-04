"""Get symbol source code.

**Security fix (issue #1):** context_lines is clamped to MAX_CONTEXT_LINES
and the file path from the index is validated against the content directory
before reading. This prevents path traversal via crafted symbol records.
"""

import hashlib
import time
from typing import Optional

from ..security import validate_file_access, safe_read_file
from ..core.limits import MAX_CONTEXT_LINES
from ..core.boundaries import wrap_untrusted_content, make_meta
from ..core.errors import sanitize_error
from ..core.validation import ValidationError
from ..storage import IndexStore
from ._common import parse_repo, timed, elapsed_ms


def get_symbol(
    repo: str,
    symbol_id: str,
    verify: bool = False,
    context_lines: int = 0,
    storage_path: Optional[str] = None,
) -> dict:
    """Get full source of a specific symbol.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_id: Symbol ID from get_file_outline or search_symbols.
        verify: If True, re-read source and verify content hash matches.
        context_lines: Number of lines before/after the symbol to include.
        storage_path: Custom storage path.

    Returns:
        Dict with symbol details, source code (wrapped), and _meta envelope.
    """
    start = timed()

    # --- security gate: parse + validate repo identifier ---
    parsed = parse_repo(repo, storage_path)
    if isinstance(parsed, dict):
        return parsed
    owner, name = parsed

    store = IndexStore(base_path=storage_path)
    index = store.load_index(owner, name)

    if not index:
        return {"error": f"Repository not indexed: {owner}/{name}"}

    symbol = index.get_symbol(symbol_id)

    if not symbol:
        return {"error": f"Symbol not found: {symbol_id}"}

    # Get source via byte-offset read
    try:
        source = store.get_symbol_content(owner, name, symbol_id, index=index)
    except Exception as exc:
        return {"error": sanitize_error(exc)}

    # --- security gate: clamp context_lines ---
    context_lines = min(max(context_lines, 0), MAX_CONTEXT_LINES)

    # Add context lines if requested
    context_before = ""
    context_after = ""
    if context_lines > 0 and source:
        content_dir = str(store._content_dir(owner, name))
        try:
            # --- security gate: validate file path from index ---
            file_path = validate_file_access(symbol["file"], content_dir)
            content = safe_read_file(file_path, content_dir)
            all_lines = content.split("\n")
            start_line = symbol["line"] - 1  # 0-indexed
            end_line = symbol["end_line"]     # exclusive
            before_start = max(0, start_line - context_lines)
            after_end = min(len(all_lines), end_line + context_lines)
            if before_start < start_line:
                context_before = "\n".join(all_lines[before_start:start_line])
            if end_line < after_end:
                context_after = "\n".join(all_lines[end_line:after_end])
        except (ValidationError, Exception):
            pass  # Skip context for files with unsafe paths

    meta_extra = {}
    if verify and source:
        actual_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        stored_hash = symbol.get("content_hash", "")
        meta_extra["content_verified"] = actual_hash == stored_hash if stored_hash else None

    ms = elapsed_ms(start)

    result = {
        "id": symbol["id"],
        "kind": symbol["kind"],
        "name": symbol["name"],
        "file": symbol["file"],
        "line": symbol["line"],
        "end_line": symbol["end_line"],
        "signature": symbol["signature"],
        "decorators": symbol.get("decorators", []),
        "docstring": wrap_untrusted_content(symbol.get("docstring", "")),
        "content_hash": symbol.get("content_hash", ""),
        # --- content boundary wrapping ---
        "source": wrap_untrusted_content(source) if source else "",
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            **meta_extra,
        },
    }

    if context_before:
        result["context_before"] = wrap_untrusted_content(context_before)
    if context_after:
        result["context_after"] = wrap_untrusted_content(context_after)

    return result


def get_symbols(
    repo: str,
    symbol_ids: list[str],
    storage_path: Optional[str] = None,
) -> dict:
    """Get full source of multiple symbols.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_ids: List of symbol IDs.
        storage_path: Custom storage path.

    Returns:
        Dict with symbols list, errors, and _meta envelope.
    """
    start = timed()

    # --- security gate: parse + validate repo identifier ---
    parsed = parse_repo(repo, storage_path)
    if isinstance(parsed, dict):
        return parsed
    owner, name = parsed

    store = IndexStore(base_path=storage_path)
    index = store.load_index(owner, name)

    if not index:
        return {"error": f"Repository not indexed: {owner}/{name}"}

    symbols = []
    errors = []

    for symbol_id in symbol_ids:
        symbol = index.get_symbol(symbol_id)

        if not symbol:
            errors.append({"id": symbol_id, "error": f"Symbol not found: {symbol_id}"})
            continue

        try:
            source = store.get_symbol_content(owner, name, symbol_id, index=index)
        except Exception as exc:
            errors.append({"id": symbol_id, "error": sanitize_error(exc)})
            continue

        symbols.append({
            "id": symbol["id"],
            "kind": symbol["kind"],
            "name": symbol["name"],
            "file": symbol["file"],
            "line": symbol["line"],
            "end_line": symbol["end_line"],
            "signature": symbol["signature"],
            "decorators": symbol.get("decorators", []),
            "docstring": wrap_untrusted_content(symbol.get("docstring", "")),
            "content_hash": symbol.get("content_hash", ""),
            # --- content boundary wrapping ---
            "source": wrap_untrusted_content(source) if source else "",
        })

    ms = elapsed_ms(start)

    return {
        "symbols": symbols,
        "errors": errors,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "symbol_count": len(symbols),
        },
    }
