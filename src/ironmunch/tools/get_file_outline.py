"""Get file outline -- symbols in a specific file."""

import time
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.errors import sanitize_error
from ..storage import IndexStore
from ..parser import Symbol, SymbolNode, build_symbol_tree
from ._common import parse_repo, timed, elapsed_ms


def get_file_outline(
    repo: str,
    file_path: str,
    storage_path: Optional[str] = None,
) -> dict:
    """Get symbols in a file with hierarchical structure.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        file_path: Path to file within repository.
        storage_path: Custom storage path.

    Returns:
        Dict with symbols outline and _meta envelope.
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

    # Filter symbols to this file
    file_symbols = [s for s in index.symbols if s.get("file") == file_path]

    if not file_symbols:
        return {
            "repo": f"{owner}/{name}",
            "file": wrap_untrusted_content(file_path),
            "language": "",
            "symbols": [],
        }

    # Build symbol tree
    symbol_objects = [_dict_to_symbol(s) for s in file_symbols]
    tree = build_symbol_tree(symbol_objects)

    # Convert to output format
    symbols_output = [_node_to_dict(n) for n in tree]

    # Get language
    language = file_symbols[0].get("language", "")

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "file": wrap_untrusted_content(file_path),
        "language": language,
        "symbols": symbols_output,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "symbol_count": len(symbols_output),
        },
    }


def _dict_to_symbol(d: dict) -> Symbol:
    """Convert dict back to Symbol dataclass."""
    return Symbol(
        id=d["id"],
        file=d["file"],
        name=d["name"],
        qualified_name=d["qualified_name"],
        kind=d["kind"],
        language=d["language"],
        signature=d["signature"],
        docstring=d.get("docstring", ""),
        summary=d.get("summary", ""),
        decorators=d.get("decorators", []),
        keywords=d.get("keywords", []),
        parent=d.get("parent"),
        line=d["line"],
        end_line=d["end_line"],
        byte_offset=d["byte_offset"],
        byte_length=d["byte_length"],
        content_hash=d.get("content_hash", ""),
    )


def _node_to_dict(node: SymbolNode) -> dict:
    """Convert SymbolNode to output dict."""
    result = {
        "id": node.symbol.id,
        "kind": node.symbol.kind,
        "name": node.symbol.name,
        "signature": wrap_untrusted_content(node.symbol.signature),
        "summary": wrap_untrusted_content(node.symbol.summary),
        "line": node.symbol.line,
    }

    if node.children:
        result["children"] = [_node_to_dict(c) for c in node.children]

    return result
