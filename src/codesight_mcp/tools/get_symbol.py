"""Get symbol source code.

**Security fix (issue #1):** context_lines is clamped to MAX_CONTEXT_LINES
and the file path from the index is validated against the content directory
before reading. This prevents path traversal via crafted symbol records.
"""

import hashlib
from typing import Optional

from ..security import validate_file_access, safe_read_file, sanitize_signature_for_api
from ..core.limits import MAX_CONTEXT_LINES
from ..core.boundaries import wrap_untrusted_content, make_meta
from ..core.errors import sanitize_error
from ..core.validation import ValidationError
from ._common import RepoContext, timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def _find_symbol_at_line(index, file_path: str, line: int) -> Optional[dict]:
    """Find the innermost symbol whose line range contains *line*.

    When multiple symbols overlap (e.g. a method inside a class), the
    narrowest (innermost) one is returned — determined by the smallest
    ``end_line - line`` span.
    """
    candidates = []
    for sym in index.symbols:
        if sym.get("file") != file_path:
            continue
        sym_line = sym.get("line", 0)
        sym_end = sym.get("end_line", 0)
        if sym_line <= line <= sym_end:
            candidates.append(sym)

    if not candidates:
        return None

    # Pick the narrowest (innermost) symbol
    candidates.sort(key=lambda s: s.get("end_line", 0) - s.get("line", 0))
    return candidates[0]


def get_symbol(
    repo: str,
    symbol_id: str = "",
    file_path: Optional[str] = None,
    line: Optional[int] = None,
    verify: bool = False,
    context_lines: int = 0,
    storage_path: Optional[str] = None,
) -> dict:
    """Get full source of a specific symbol.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_id: Symbol ID from get_file_outline or search_symbols.
        file_path: Path to file within the repository (alternative to symbol_id).
        line: Line number within the file (used with file_path).
        verify: If True, re-read source and verify content hash matches.
        context_lines: Number of lines before/after the symbol to include.
        storage_path: Custom storage path.

    Returns:
        Dict with symbol details, source code (wrapped), and _meta envelope.

    When both ``file_path`` and ``line`` are provided and ``symbol_id`` is
    empty, the tool finds the innermost symbol whose line range contains
    the requested line.
    """
    start = timed()

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, store, index = ctx.owner, ctx.name, ctx.store, ctx.index

    # Resolve symbol_id from file:line when symbol_id is absent
    if not symbol_id and file_path is not None and line is not None:
        symbol = _find_symbol_at_line(index, file_path, line)
        if not symbol:
            return {"error": f"No symbol found at {file_path}:{line}"}
        symbol_id = symbol["id"]
    elif symbol_id:
        symbol = index.get_symbol(symbol_id)
        if not symbol:
            return {"error": f"Symbol not found: {symbol_id}"}
    else:
        return {"error": "Either symbol_id or both file_path and line are required"}

    # Get source via byte-offset read
    try:
        source = store.get_symbol_content(owner, name, symbol_id, index=index)
    except (OSError, KeyError, ValueError) as exc:
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
        except (ValidationError, OSError, IOError):
            pass  # Skip context for files with unsafe paths or I/O errors

    meta_extra = {}
    if verify and source:
        actual_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        stored_hash = symbol.get("content_hash", "")
        meta_extra["content_verified"] = actual_hash == stored_hash if stored_hash else None

    ms = elapsed_ms(start)

    result = {
        "id": wrap_untrusted_content(symbol["id"]),
        "kind": symbol["kind"],
        "name": wrap_untrusted_content(symbol["name"]),
        "file": wrap_untrusted_content(symbol["file"]),
        "line": symbol["line"],
        "end_line": symbol["end_line"],
        # --- content boundary wrapping (SEC-MED-2 followup) ---
        "signature": wrap_untrusted_content(symbol.get("signature", "")),
        "decorators": [wrap_untrusted_content(d) for d in symbol.get("decorators", [])],
        "docstring": wrap_untrusted_content(symbol.get("docstring", "")),
        "content_hash": symbol.get("content_hash", ""),
        "source": wrap_untrusted_content(sanitize_signature_for_api(source)) if source else "",
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            **meta_extra,
        },
    }

    if context_before:
        result["context_before"] = wrap_untrusted_content(sanitize_signature_for_api(context_before))
    if context_after:
        result["context_after"] = wrap_untrusted_content(sanitize_signature_for_api(context_after))

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

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, store, index = ctx.owner, ctx.name, ctx.store, ctx.index

    symbols = []
    errors = []

    for symbol_id in symbol_ids:
        symbol = index.get_symbol(symbol_id)

        if not symbol:
            errors.append({"id": symbol_id, "error": f"Symbol not found: {symbol_id}"})
            continue

        try:
            source = store.get_symbol_content(owner, name, symbol_id, index=index)
        except (OSError, KeyError, ValueError) as exc:
            errors.append({"id": symbol_id, "error": sanitize_error(exc)})
            continue

        symbols.append({
            "id": wrap_untrusted_content(symbol["id"]),
            "kind": symbol["kind"],
            "name": wrap_untrusted_content(symbol["name"]),
            "file": wrap_untrusted_content(symbol["file"]),
            "line": symbol["line"],
            "end_line": symbol["end_line"],
            # --- content boundary wrapping (SEC-MED-2 followup) ---
            "signature": wrap_untrusted_content(symbol.get("signature", "")),
            "decorators": [wrap_untrusted_content(d) for d in symbol.get("decorators", [])],
            "docstring": wrap_untrusted_content(symbol.get("docstring", "")),
            "content_hash": symbol.get("content_hash", ""),
            "source": wrap_untrusted_content(sanitize_signature_for_api(source)) if source else "",
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


_spec_get_symbol = register(ToolSpec(
    name="get_symbol",
    description=(
        "Get the full source code of a specific symbol. Use after "
        "identifying relevant symbols via get_file_outline or "
        "search_symbols. Alternatively, pass file_path and line "
        "to look up the symbol at a specific location."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "symbol_id": {
                "type": "string",
                "description": "Symbol ID from get_file_outline or search_symbols",
            },
            "file_path": {
                "type": "string",
                "description": "Path to file within the repository (alternative to symbol_id)",
            },
            "line": {
                "type": "integer",
                "description": "Line number within the file (used with file_path)",
            },
            "verify": {
                "type": "boolean",
                "description": "Verify content hash matches stored hash (detects source drift)",
                "default": False,
            },
            "context_lines": {
                "type": "integer",
                "description": "Number of lines before/after symbol to include for context",
                "default": 0,
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_symbol(
        repo=args["repo"],
        symbol_id=args.get("symbol_id", ""),
        file_path=args.get("file_path"),
        line=args.get("line"),
        verify=args.get("verify", False),
        context_lines=args.get("context_lines", 0),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo"],
    annotations=ToolAnnotations(title="Get Symbol", readOnlyHint=True, openWorldHint=False),
))

_spec_get_symbols = register(ToolSpec(
    name="get_symbols",
    description=(
        "Get full source code of multiple symbols in one call. "
        "Efficient for loading related symbols."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "symbol_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of symbol IDs to retrieve",
            },
        },
        "required": ["repo", "symbol_ids"],
    },
    handler=lambda args, storage_path: get_symbols(
        repo=args["repo"],
        symbol_ids=args["symbol_ids"],
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo", "symbol_ids"],
    annotations=ToolAnnotations(title="Get Symbols (Batch)", readOnlyHint=True, openWorldHint=False),
))
