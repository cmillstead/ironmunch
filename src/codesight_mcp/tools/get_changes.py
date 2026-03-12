"""Map git diff output to affected symbols in the index."""

import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.validation import ValidationError, is_within
from ..parser.graph import CodeGraph
from ._common import RepoContext, elapsed_ms, timed
from .registry import ToolSpec, register

# Allowed characters in a git ref (no shell metacharacters)
_GIT_REF_RE = re.compile(r"^[a-zA-Z0-9_.^~/:@{}\-]+$")
_GIT_REF_MAX = 200

# Cap affected symbols to bound response size
_MAX_AFFECTED = 100


def _validate_ref(ref: str) -> str:
    """Validate a git ref against injection attacks.

    Args:
        ref: Git reference string (e.g. "HEAD~1..HEAD", "main", "abc123").

    Returns:
        The validated ref string.

    Raises:
        ValidationError: If the ref contains disallowed characters or is too long.
    """
    if len(ref) > _GIT_REF_MAX:
        raise ValidationError(
            f"git_ref too long: {len(ref)} chars (max {_GIT_REF_MAX})"
        )
    if not _GIT_REF_RE.match(ref):
        raise ValidationError(
            "git_ref contains disallowed characters. "
            "Allowed: a-z A-Z 0-9 _ . ^ ~ / : @ { } -"
        )
    return ref


def _parse_diff_output(diff_text: str) -> list[dict]:
    """Parse unified diff into per-file line-range hunks.

    Uses the NEW side (+start, +count) since we want to map changes
    to symbols as they exist in the current index.

    Args:
        diff_text: Raw output of ``git diff --unified=0``.

    Returns:
        List of dicts with keys ``file`` (str) and ``lines``
        (list of (start, end) tuples, 1-indexed, inclusive).
        Deleted files (+++ /dev/null) are skipped.
    """
    # Match: @@ -old_start[,old_count] +new_start[,new_count] @@
    _HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    result: list[dict] = []
    current_file: Optional[str] = None
    current_lines: list[tuple[int, int]] = []
    deleted = False

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            # Flush previous file
            if current_file and not deleted and current_lines:
                result.append({"file": current_file, "lines": current_lines})
            target = line[4:]
            if target == "/dev/null":
                current_file = None
                current_lines = []
                deleted = True
            else:
                # Strip "b/" prefix added by git
                if target.startswith("b/"):
                    target = target[2:]
                current_file = target
                current_lines = []
                deleted = False
        elif line.startswith("@@ ") and current_file and not deleted:
            m = _HUNK_RE.match(line)
            if m:
                start = int(m.group(1))
                count_str = m.group(2)
                count = int(count_str) if count_str is not None else 1
                if count == 0:
                    # Pure deletion hunk — no new lines, skip
                    continue
                end = start + count - 1
                current_lines.append((start, end))

    # Flush last file
    if current_file and not deleted and current_lines:
        result.append({"file": current_file, "lines": current_lines})

    return result


def _map_hunks_to_symbols(hunks: list[dict], index) -> list[dict]:
    """Map diff hunks to affected symbols via line-range overlap.

    A symbol is considered affected if any hunk overlaps with its line
    range: ``hunk_start <= sym.end_line and hunk_end >= sym.line``.

    Args:
        hunks: Output of :func:`_parse_diff_output`.
        index: ``CodeIndex`` instance with a ``symbols`` attribute.

    Returns:
        Deduplicated list of symbol dicts (keys: id, name, kind, file,
        line, signature).
    """
    # Pre-index symbols by file for O(H * S_file) instead of O(H * S_total)
    file_symbols: dict[str, list[dict]] = defaultdict(list)
    for sym in index.symbols:
        f = sym.get("file", "")
        if f:
            file_symbols[f].append(sym)

    seen: set[str] = set()
    affected: list[dict] = []

    for hunk in hunks:
        file_path = hunk["file"]
        for (h_start, h_end) in hunk["lines"]:
            for sym in file_symbols.get(file_path, []):
                sym_line = sym.get("line", 0)
                sym_end = sym.get("end_line", sym_line)
                # Overlap check: hunk_start <= sym_end and hunk_end >= sym_start
                if h_start <= sym_end and h_end >= sym_line:
                    sid = sym.get("id", "")
                    if sid not in seen:
                        seen.add(sid)
                        affected.append({
                            "id": wrap_untrusted_content(sid),
                            "name": wrap_untrusted_content(sym.get("name", "")),
                            "kind": sym.get("kind", ""),
                            "file": wrap_untrusted_content(sym.get("file", "")),
                            "line": sym_line,
                            "signature": wrap_untrusted_content(
                                sym.get("signature", "")
                            ),
                            "_raw_id": sid,  # Preserved for impact lookup
                        })

    return affected


def get_changes(
    repo: str,
    git_ref: str = "HEAD~1..HEAD",
    repo_path: Optional[str] = None,
    include_impact: bool = False,
    storage_path: Optional[str] = None,
    allowed_roots: Optional[list[str]] = None,
) -> dict:
    """Map a git diff to affected symbols in the codesight index.

    Runs ``git diff --unified=0`` for the given ref, parses the changed
    line ranges, and finds every indexed symbol that overlaps those ranges.
    Optionally computes downstream impact for each affected symbol.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        git_ref: Git range or ref passed to ``git diff`` (default
            ``"HEAD~1..HEAD"``).
        repo_path: Filesystem path to the git repo root. Required when
            running ``git diff``.
        include_impact: When True, build a CodeGraph and compute
            transitive downstream impact across all affected symbols.
        storage_path: Custom storage path for the codesight index.

    Returns:
        Dict with ``affected_symbols``, ``changed_files``, optional
        ``impact``, and a ``_meta`` envelope.
    """
    start = timed()

    # 1. Validate ref
    try:
        git_ref = _validate_ref(git_ref)
    except ValidationError as exc:
        return {"error": str(exc)}

    # 2. Resolve repo context
    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx

    owner, name, index = ctx.owner, ctx.name, ctx.index

    # 3. Validate repo_path against ALLOWED_ROOTS
    if not repo_path:
        return {"error": "repo_path is required to run git diff"}

    resolved_path = Path(repo_path).expanduser().resolve()
    if allowed_roots:
        allowed = [Path(r).expanduser().resolve() for r in allowed_roots if r.strip()]
        if not any(is_within(a, resolved_path) or resolved_path == a for a in allowed):
            return {"error": "repo_path is outside allowed roots"}

    if not resolved_path.is_dir():
        return {"error": "repo_path is not a directory"}

    try:
        proc = subprocess.run(
            ["git", "diff", "--unified=0", git_ref],
            cwd=str(resolved_path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return {"error": "git executable not found"}
    except subprocess.TimeoutExpired:
        return {"error": "git diff timed out after 30 seconds"}
    except OSError as exc:
        return {"error": f"Failed to run git diff: {exc}"}

    if proc.returncode != 0:
        stderr = proc.stderr.strip()[:500]
        return {"error": f"git diff failed (exit {proc.returncode}): {stderr}"}

    # 4. Parse diff → map to symbols
    hunks = _parse_diff_output(proc.stdout)
    changed_files = len({h["file"] for h in hunks})
    affected = _map_hunks_to_symbols(hunks, index)

    truncated = len(affected) > _MAX_AFFECTED
    affected = affected[:_MAX_AFFECTED]

    # 5. Optional impact analysis
    impact_result: Optional[dict] = None
    if include_impact and affected:
        graph = CodeGraph.get_or_build(index.symbols)
        downstream_ids: set[str] = set()
        for sym_entry in affected:
            downstream_ids.update(graph.get_impact(sym_entry["_raw_id"], max_depth=3))

        downstream_syms = []
        for sid in downstream_ids:
            sym = graph.get_symbol(sid)
            if sym:
                downstream_syms.append({
                    "id": wrap_untrusted_content(sid),
                    "name": wrap_untrusted_content(sym.get("name", "")),
                    "kind": sym.get("kind", ""),
                    "file": wrap_untrusted_content(sym.get("file", "")),
                    "line": sym.get("line", 0),
                    "signature": wrap_untrusted_content(sym.get("signature", "")),
                })

        impact_result = {
            "downstream_count": len(downstream_syms),
            "downstream": downstream_syms,
        }

    # Strip internal _raw_id before returning
    for sym_entry in affected:
        sym_entry.pop("_raw_id", None)

    ms = elapsed_ms(start)

    result: dict = {
        "repo": f"{owner}/{name}",
        "git_ref": wrap_untrusted_content(git_ref),
        "changed_files": changed_files,
        "affected_symbol_count": len(affected),
        "affected_symbols": affected,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "truncated": truncated,
        },
    }

    if include_impact:
        result["impact"] = impact_result or {"downstream_count": 0, "downstream": []}

    return result


def _handle_get_changes(args: dict, storage_path, *, _allowed_roots_fn=None):
    """Handler that resolves ALLOWED_ROOTS at call time."""
    if _handle_get_changes._allowed_roots_fn is not None:
        allowed = _handle_get_changes._allowed_roots_fn()
    else:
        allowed = None
    return get_changes(
        repo=args["repo"],
        git_ref=args.get("git_ref", "HEAD~1..HEAD"),
        repo_path=args.get("repo_path"),
        include_impact=args.get("include_impact", False),
        storage_path=storage_path,
        allowed_roots=allowed,
    )


_handle_get_changes._allowed_roots_fn = None


def set_allowed_roots_fn(fn):
    """Set the function that returns ALLOWED_ROOTS. Called by server.py."""
    _handle_get_changes._allowed_roots_fn = fn


_spec = register(ToolSpec(
    name="get_changes",
    description=(
        "Map a git diff to affected symbols in the codesight index. "
        "Bridges git history and the symbol graph — given a git ref "
        "(e.g. HEAD~1..HEAD or a commit SHA), returns which indexed "
        "symbols overlap the changed lines. Optionally computes "
        "downstream impact."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "git_ref": {
                "type": "string",
                "description": (
                    "Git range or ref for git diff (default: HEAD~1..HEAD). "
                    "Examples: 'HEAD~1..HEAD', 'abc123..def456', 'main'"
                ),
                "default": "HEAD~1..HEAD",
            },
            "repo_path": {
                "type": "string",
                "description": "Filesystem path to the git repository root",
            },
            "include_impact": {
                "type": "boolean",
                "description": (
                    "When true, also compute transitive downstream impact "
                    "for all affected symbols (callers/inheritors/importers)."
                ),
                "default": False,
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: _handle_get_changes(args, storage_path),
    untrusted=True,
    required_args=["repo"],
))
