"""Shared helpers for tool handlers.

Centralizes repo identifier parsing and validation so each tool
doesn't duplicate the logic.
"""

import time
from typing import Optional

from ..security import sanitize_repo_identifier
from ..storage import IndexStore
from ..core.errors import sanitize_error


def parse_repo(
    repo: str, storage_path: Optional[str] = None
) -> tuple[str, str] | dict:
    """Parse a repo identifier into (owner, name).

    Accepts ``owner/repo`` or a bare ``repo`` name (resolved by
    searching existing indexes).

    Returns:
        Tuple ``(owner, name)`` on success, or an error dict.
    """
    if "/" in repo:
        owner, name = repo.split("/", 1)
    else:
        store = IndexStore(base_path=storage_path)
        repos = store.list_repos()
        matching = [r for r in repos if r["repo"].endswith(f"/{repo}")]
        if not matching:
            return {"error": f"Repository not found: {repo}"}
        if len(matching) > 1:
            return {"error": "Ambiguous repository name. Use full owner/repo format (e.g., 'owner/myproject')."}
        owner, name = matching[0]["repo"].split("/", 1)

    # Validate identifiers against injection
    try:
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(name)
    except Exception as exc:
        return {"error": sanitize_error(exc)}

    return owner, name


def timed() -> float:
    """Return a perf_counter timestamp for timing calculations."""
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    """Milliseconds since *start*."""
    return round((time.perf_counter() - start) * 1000, 1)
