"""Deep structural integrity audit for code indexes."""

import hashlib
import os
from collections import Counter
from typing import Optional

from mcp.types import ToolAnnotations

from ..core.boundaries import make_meta, wrap_untrusted_content
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register


def lint_index(repo: str, storage_path: Optional[str] = None) -> dict:
    """Deep structural integrity audit for a code index.

    Finds orphaned symbols/content, duplicates, call graph broken
    references, and file hash corruption.
    """
    start = timed()

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx

    content_dir = ctx.store._content_dir(ctx.owner, ctx.name)

    # --- Three canonical sets ---

    # Canonical indexed files (from the index metadata)
    indexed_files = set(ctx.index.file_hashes) | set(ctx.index.source_files)

    # Files referenced by symbols
    symbol_files: set[str] = set()

    # Files actually on disk (safe walk, no symlinks, no temp files)
    disk_files: set[str] = set()
    if content_dir.is_dir():
        for entry in content_dir.rglob("*"):
            if not entry.is_file():
                continue
            if entry.is_symlink():
                continue
            if ".tmp." in entry.name or entry.name.endswith(".tmp"):
                continue
            disk_files.add(str(entry.relative_to(content_dir)))

    findings: list[dict] = []

    # --- Check a: Orphaned symbols ---
    for sym in ctx.index.symbols:
        file_path = sym.get("file")
        if not file_path:
            continue
        symbol_files.add(file_path)
        if file_path not in disk_files:
            findings.append({
                "type": "orphaned_symbol",
                "symbol_id": wrap_untrusted_content(sym["id"]),
                "reason": "content file missing",
            })

    # --- Check b: Orphaned content ---
    stray = disk_files - indexed_files
    for stray_file in sorted(stray):
        findings.append({
            "type": "orphaned_content",
            "file": wrap_untrusted_content(str(stray_file)),
            "reason": "not in index",
        })

    # --- Check c: Duplicate symbols ---
    key_counter: Counter[str] = Counter()
    for sym in ctx.index.symbols:
        file_path = sym.get("file", "")
        name = sym.get("name", "")
        kind = sym.get("kind", "")
        key = f"{file_path}:{name}#{kind}"
        key_counter[key] += 1
    for key, count in key_counter.items():
        if count > 1:
            findings.append({
                "type": "duplicate_symbol",
                "key": wrap_untrusted_content(key),
                "count": count,
                "reason": "duplicate file:name:kind",
            })

    # --- Check d: Call graph broken refs ---
    for sym in ctx.index.symbols:
        calls = sym.get("calls")
        if not calls:
            continue
        for callee_id in calls:
            if ctx.index.get_symbol(callee_id) is None:
                findings.append({
                    "type": "call_graph_broken_ref",
                    "source_symbol": wrap_untrusted_content(sym["id"]),
                    "target_symbol": wrap_untrusted_content(callee_id),
                    "reason": "callee not in index",
                })

    # --- Check e: File hash corruption ---
    for file_path, expected_hash in ctx.index.file_hashes.items():
        if file_path not in disk_files:
            findings.append({
                "type": "file_hash_mismatch",
                "file": wrap_untrusted_content(file_path),
                "reason": "content file missing",
            })
            continue

        full_path = content_dir / file_path
        try:
            fd = os.open(str(full_path), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with os.fdopen(fd, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except Exception:
                # fd is consumed by fdopen even on error; no close needed
                findings.append({
                    "type": "file_hash_mismatch",
                    "file": wrap_untrusted_content(file_path),
                    "reason": "content file missing",
                })
                continue
        except OSError:
            findings.append({
                "type": "file_hash_mismatch",
                "file": wrap_untrusted_content(file_path),
                "reason": "content file missing",
            })
            continue

        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if actual_hash != expected_hash:
            findings.append({
                "type": "file_hash_mismatch",
                "file": wrap_untrusted_content(file_path),
                "expected": expected_hash,
                "actual": actual_hash,
                "reason": "hash mismatch",
            })

    # --- Build output ---
    by_type: dict[str, int] = {}
    for finding in findings:
        by_type[finding["type"]] = by_type.get(finding["type"], 0) + 1

    return {
        "repo": wrap_untrusted_content(f"{ctx.owner}/{ctx.name}"),
        "clean": len(findings) == 0,
        "findings": findings,
        "summary": {"total_findings": len(findings), "by_type": by_type},
        "_meta": {
            **make_meta(source="lint_index", trusted=False),
            "timing_ms": elapsed_ms(start),
        },
    }


_spec = register(ToolSpec(
    name="lint_index",
    description=(
        "Deep structural integrity audit. Finds orphaned symbols/content, "
        "duplicates, call graph broken references, and file hash corruption."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: lint_index(
        repo=args["repo"], storage_path=storage_path,
    ),
    required_args=["repo"],
    annotations=ToolAnnotations(
        title="Lint Index",
        readOnlyHint=True,
        openWorldHint=False,
    ),
    ci_exit_key="clean",
))
