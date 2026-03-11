"""List indexed repositories."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..storage import IndexStore
from ._common import timed, elapsed_ms
from .registry import ToolSpec, register


def list_repos(storage_path: Optional[str] = None) -> dict:
    """List all indexed repositories.

    Returns:
        Dict with count, list of repos, and _meta envelope.
    """
    start = timed()
    store = IndexStore(base_path=storage_path)
    repos = store.list_repos()
    ms = elapsed_ms(start)

    # Wrap repo names and metadata — directory names come from disk and are attacker-influenced
    _ISO_RE = __import__("re").compile(r"\d{4}-\d{2}-\d{2}T[\d:.+Z-]+$")
    _LANG_RE = __import__("re").compile(r"[A-Za-z_#+]+$")
    for r in repos:
        if "repo" not in r:
            continue
        r["repo"] = wrap_untrusted_content(r["repo"])
        # ADV-LOW-2: Validate indexed_at format; wrap if unexpected
        if "indexed_at" in r:
            if not isinstance(r["indexed_at"], str) or not _ISO_RE.match(r["indexed_at"]):
                r["indexed_at"] = wrap_untrusted_content(str(r.get("indexed_at", "")))
        # ADV-LOW-2: Validate language keys
        if "languages" in r and isinstance(r["languages"], dict):
            r["languages"] = {
                (k if _LANG_RE.match(k) else wrap_untrusted_content(k)): v
                for k, v in r["languages"].items()
            }

    return {
        "count": len(repos),
        "repos": repos,
        "_meta": {
            **make_meta(source="index_list", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="list_repos",
    description="List all indexed repositories.",
    input_schema={
        "type": "object",
        "properties": {},
    },
    handler=lambda args, storage_path: list_repos(storage_path=storage_path),
    required_args=[],
))
