"""Search for text across indexed files and enrich matches with enclosing symbol context.

This tool replaces the ``search_text`` → ``get_file_outline`` cross-reference
pattern by returning the innermost symbol (function/class/method) that contains
each matching line, in a single call.

**Security:** Same constraints as search_text — blocked under CODESIGHT_NO_REDACT,
redaction-sentinel queries rejected, all user-facing strings wrapped with
spotlighting markers.
"""

import fnmatch
from typing import Optional

from ..security import validate_file_access, sanitize_signature_for_api, safe_read_file, _no_redact
from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import wrap_untrusted_content, make_meta
from ..core.validation import ValidationError
from ._common import RepoContext, timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register

_REDACTION_SENTINEL = "<REDACTED>"
_MAX_SEARCH_CONTENT_SIZE = 2_000_000  # 2 MB cap before sanitization


def _find_enclosing_symbol(symbols: list[dict], file_path: str, line: int) -> Optional[dict]:
    """Find the narrowest symbol whose line range contains *line* in *file_path*.

    Iterates all symbols and selects those whose file matches and whose
    [sym.line, sym.end_line] range contains the target line.  Among all
    candidates the one with the smallest span (end_line - line) is chosen
    as the "innermost" enclosing symbol (e.g. a method inside a class).

    Args:
        symbols: List of serialised symbol dicts from the index.
        file_path: The file path to filter by.
        line: The 1-indexed line number of the text match.

    Returns:
        The narrowest enclosing symbol dict, or None if no symbol covers
        the line.
    """
    best: Optional[dict] = None
    best_span: int = -1

    for sym in symbols:
        if sym.get("file") != file_path:
            continue
        sym_start = sym.get("line", 0)
        sym_end = sym.get("end_line", 0)
        if sym_start <= 0 or sym_end <= 0:
            continue
        if sym_start <= line <= sym_end:
            span = sym_end - sym_start
            if best is None or span < best_span:
                best = sym
                best_span = span

    return best


def search_references(
    repo: str,
    query: str,
    file_pattern: Optional[str] = None,
    max_results: int = 20,
    storage_path: Optional[str] = None,
) -> dict:
    """Search for text across indexed files and return matches with enclosing symbol context.

    Like ``search_text`` but enriches every hit with the innermost function,
    class, or method that contains the matching line.  This replaces the common
    pattern of calling ``search_text`` followed by ``get_file_outline`` to
    determine where a match lives in the symbol hierarchy.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        query: Text to search for (case-insensitive substring match).
        file_pattern: Optional glob pattern to filter files (e.g., ``*.py``).
        max_results: Maximum number of matching lines to return (capped at
            ``MAX_SEARCH_RESULTS``).
        storage_path: Custom storage path (for testing).

    Returns:
        Dict with ``results`` list.  Each result has:
        - ``file``: wrapped file path
        - ``line``: 1-indexed line number
        - ``text``: wrapped matched line content
        - ``enclosing_symbol``: wrapped symbol context dict, or ``null`` if the
          hit is outside all known symbols.

        Also includes ``_meta`` envelope with timing and file count.
    """
    start = timed()

    max_results = min(max(max_results, 1), MAX_SEARCH_RESULTS)

    if not isinstance(query, str) or not query.strip():
        return {"error": "query must be a non-empty string"}

    if _no_redact():
        return {
            "error": (
                "search_references is disabled when CODESIGHT_NO_REDACT=1 is set. "
                "Full-text search with redaction disabled would expose secrets."
            )
        }

    q_upper = query.strip().upper()
    if len(q_upper) >= 4 and (
        _REDACTION_SENTINEL.startswith(q_upper) or q_upper in _REDACTION_SENTINEL
    ):
        return {"error": "Query matches redaction sentinel pattern; not allowed"}

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx

    owner, name, store, index = ctx.owner, ctx.name, ctx.store, ctx.index

    files = index.source_files
    if file_pattern:
        files = [
            f for f in files
            if fnmatch.fnmatch(f, file_pattern)
            or fnmatch.fnmatch(f, f"*/{file_pattern}")
        ]

    content_dir = str(store._content_dir(owner, name))
    query_lower = query.lower()
    matches = []
    files_searched = 0

    for file_path in files:
        try:
            validated = validate_file_access(file_path, content_dir)
        except ValidationError:
            continue

        try:
            content = safe_read_file(validated, str(content_dir))
        except (OSError, ValidationError):
            continue

        files_searched += 1
        content = content[:_MAX_SEARCH_CONTENT_SIZE]
        lines = sanitize_signature_for_api(content).split("\n")

        for line_num, line in enumerate(lines, 1):
            if query_lower not in line.lower():
                continue

            enclosing = _find_enclosing_symbol(index.symbols, file_path, line_num)
            if enclosing is not None:
                enclosing_out: Optional[dict] = {
                    "id": wrap_untrusted_content(
                        sanitize_signature_for_api(str(enclosing.get("id", "")))[:200]
                    ),
                    "kind": str(enclosing.get("kind", "")),
                    "name": wrap_untrusted_content(
                        sanitize_signature_for_api(str(enclosing.get("name", "")))[:200]
                    ),
                    "signature": wrap_untrusted_content(
                        sanitize_signature_for_api(str(enclosing.get("signature", "")))[:200]
                    ),
                }
            else:
                enclosing_out = None

            matches.append({
                "file": wrap_untrusted_content(file_path),
                "line": line_num,
                "text": wrap_untrusted_content(
                    sanitize_signature_for_api(line.rstrip()[:250])[:200]
                ),
                "enclosing_symbol": enclosing_out,
            })

            if len(matches) >= max_results:
                break

        if len(matches) >= max_results:
            break

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "query": wrap_untrusted_content(sanitize_signature_for_api(query)),
        "result_count": len(matches),
        "results": matches,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "files_searched": files_searched,
            "truncated": len(matches) >= max_results,
        },
    }


_spec = register(ToolSpec(
    name="search_references",
    description=(
        "Search for text across indexed files and return each match enriched "
        "with the enclosing symbol (function/class/method the hit falls within). "
        "Replaces the search_text → get_file_outline cross-reference pattern "
        "in a single call."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name).",
            },
            "query": {
                "type": "string",
                "description": "Text to search for (case-insensitive substring match).",
            },
            "file_pattern": {
                "type": "string",
                "description": "Optional glob pattern to filter files (e.g., '*.py').",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of matching lines to return.",
                "default": 20,
            },
        },
        "required": ["repo", "query"],
    },
    handler=lambda args, storage_path: search_references(
        repo=args["repo"],
        query=args["query"],
        file_pattern=args.get("file_pattern"),
        max_results=args.get("max_results", 20),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo", "query"],
    annotations=ToolAnnotations(title="Search References", readOnlyHint=True, openWorldHint=False),
))
