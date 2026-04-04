"""Index a local folder -- walk, parse, summarize, save.

This is a thin wrapper that delegates discovery to ``codesight_mcp.discovery``
(already extracted and ported). File security filtering (symlinks, secrets,
path traversal) is handled by ``discover_local_files()``.
"""

import errno
import hashlib
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_GIT_HASH_RE = re.compile(r"^[0-9a-f]{40}$")

from ..discovery import discover_local_files  # noqa: E402
from ..parser import LANGUAGE_EXTENSIONS  # noqa: E402
from ..security import sanitize_repo_identifier  # noqa: E402
from ..core.errors import sanitize_error  # noqa: E402
from ..core.validation import is_within, ValidationError  # noqa: E402
from ..storage import IndexStore  # noqa: E402
from .registry import ToolSpec, register  # noqa: E402
from ._indexing_common import parse_source_files, finalize_index  # noqa: E402


def _is_git_repo(folder_path: Path) -> bool:
    """Check if folder_path is inside a git working tree.

    Returns False on any error (not a git repo, git not installed, etc.).
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            cwd=str(folder_path),
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git repo check failed for %s: %s", folder_path, exc)
        return False


def _git_head_commit(folder_path: Path) -> Optional[str]:
    """Get the current HEAD commit hash. Returns None on any error."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(folder_path),
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git HEAD check failed for %s: %s", folder_path, exc)
    return None


def _git_changed_files(folder_path: Path, since_commit: str) -> Optional[set[str]]:
    """Get the set of files changed since a commit hash.

    Returns None on any error (invalid commit, git failure, etc.) to signal
    that the caller should fall back to a full re-index.
    """
    # ADV-LOW-7: Validate commit hash format before passing to subprocess.
    if not _GIT_HASH_RE.fullmatch(since_commit):
        return None
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", since_commit, "HEAD", "--"],
            capture_output=True,
            text=True,
            cwd=str(folder_path),
            timeout=10,
        )
        if result.returncode != 0:
            return None
        changed = set()
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line:
                changed.add(line)
        # Also include untracked files (new files not yet committed)
        result2 = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            cwd=str(folder_path),
            timeout=10,
        )
        if result2.returncode == 0:
            for line in result2.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    changed.add(line)
        return changed
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git diff failed for %s since %s: %s", folder_path, since_commit, exc)
        return None


def index_folder(
    path: str,
    use_ai_summaries: bool = True,
    storage_path: Optional[str] = None,
    extra_ignore_patterns: Optional[list[str]] = None,
    follow_symlinks: bool = False,
    allowed_roots: Optional[list[str]] = None,
) -> dict:
    """Index a local folder containing source code.

    Args:
        path: Path to local folder (absolute or relative).
        use_ai_summaries: Whether to use AI for symbol summaries.
        storage_path: Custom storage path (default: ~/.code-index/).
        extra_ignore_patterns: Additional gitignore-style patterns to exclude.
        follow_symlinks: Whether to follow symlinks (default False for safety).
        allowed_roots: Pre-split list of allowed root directories. When None
            (not provided), indexing is denied by default. The caller
            (server.py) is responsible for reading CODESIGHT_ALLOWED_ROOTS
            from the environment and splitting it before passing it here.

    Returns:
        Dict with indexing results.
    """
    # Resolve folder path
    folder_path = Path(path).expanduser().resolve()

    # Directory allowlist check — default-deny when unset
    if not allowed_roots:
        return {
            "success": False,
            "error": "CODESIGHT_ALLOWED_ROOTS not configured. "
                     "Set it to a colon-separated list of allowed directories.",
        }
    # SEC-LOW-1: filter empty entries to prevent Path("").resolve() == CWD
    parts = [r.strip() for r in allowed_roots if r.strip()]
    if not parts:
        return {"success": False, "error": "CODESIGHT_ALLOWED_ROOTS is empty after parsing"}
    allowed = [Path(p).expanduser().resolve() for p in parts]
    if not any(is_within(a, folder_path) or folder_path == a for a in allowed):
        return {"success": False, "error": "Folder is outside allowed roots"}

    if not folder_path.exists():
        return {"success": False, "error": "Folder not found"}

    if not folder_path.is_dir():
        return {"success": False, "error": "Path is not a directory"}

    warnings: list[str] = []

    try:
        # Discover source files (with security filtering via codesight_mcp.discovery)
        source_files, discover_warnings = discover_local_files(
            folder_path,
            extra_ignore_patterns=extra_ignore_patterns,
            follow_symlinks=follow_symlinks,
        )
        warnings.extend(discover_warnings)

        if not source_files:
            return {"success": False, "error": "No source files found"}

        # Create repo identifier from folder path early — needed for diff-aware check.
        # ADV-HIGH-2: use a short SHA-256 hash of the full resolved path so that
        # two directories with the same basename (e.g. /projects/myapp and
        # /tmp/myapp) never collide in storage.
        resolved = folder_path.resolve()
        path_hash = hashlib.sha256(str(resolved).encode()).hexdigest()[:12]
        repo_name = f"{resolved.name}-{path_hash}"
        owner = "local"

        # --- security gate: validate generated identifiers ---
        try:
            sanitize_repo_identifier(owner)
            sanitize_repo_identifier(repo_name)
        except (ValueError, ValidationError) as exc:
            return {"success": False, "error": sanitize_error(exc)}

        # --- Diff-aware indexing: skip unchanged files in git repos ---
        git_head = ""
        git_changed_set: Optional[set[str]] = None  # None = full re-index
        prev_index = None  # loaded once, reused for incremental merge

        if _is_git_repo(folder_path):
            current_head = _git_head_commit(folder_path)
            if current_head:
                git_head = current_head
                # Check for a previous index with a stored commit hash
                try:
                    store = IndexStore(base_path=storage_path)
                    prev_index = store.load_index(owner, repo_name)
                    if prev_index and prev_index.git_head and prev_index.git_head != current_head:
                        changed = _git_changed_files(folder_path, prev_index.git_head)
                        if changed is not None:
                            git_changed_set = changed
                except (OSError, ValueError, KeyError) as exc:
                    logger.debug("Diff-aware check failed, falling back to full re-index: %s", exc)

        # Build (rel_path, content) iterator with security gates
        def _read_files(only_files: Optional[set[str]] = None):
            for file_path in source_files:
                # --- security gate: re-validate path before reading (defense in depth) ---
                try:
                    resolved = file_path.resolve()
                    resolved_root = folder_path.resolve()
                    if not is_within(resolved_root, resolved):
                        continue
                except (OSError, ValueError):
                    continue

                # Get relative path for storage
                try:
                    rel_path = file_path.relative_to(folder_path).as_posix()
                except ValueError:
                    warnings.append("Skipped file: could not resolve relative path")
                    continue

                # Diff-aware: skip files not in the changed set
                if only_files is not None and rel_path not in only_files:
                    continue

                try:
                    fd = os.open(str(file_path), os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError as e:
                    if e.errno == errno.ELOOP:
                        warnings.append("Skipped 1 symlink file")
                    else:
                        warnings.append("Failed to read file")
                    continue
                except (ValueError, UnicodeDecodeError):
                    warnings.append("Failed to read file")
                    continue

                # Only yield files with a known language extension
                ext = file_path.suffix
                language = LANGUAGE_EXTENSIONS.get(ext)
                if not language:
                    continue

                yield rel_path, content

        # --- Diff-aware path: incremental update ---
        if git_changed_set is not None:
            # Parse only the changed files
            new_symbols, languages, raw_files, parsed_files, parse_fail_count = (
                parse_source_files(_read_files(only_files=git_changed_set))
            )

            if parse_fail_count > 0:
                warnings.append(f"{parse_fail_count} file(s) failed to parse")

            # Reuse prev_index loaded during git_head check (avoids TOCTOU double load)
            if prev_index:
                # All discovered rel_paths (full set, not just changed)
                all_rel_paths = set()
                for fp in source_files:
                    try:
                        all_rel_paths.add(fp.relative_to(folder_path).as_posix())
                    except ValueError:
                        pass

                old_files = set(prev_index.source_files)
                deleted_files = list(old_files - all_rel_paths)
                # changed_files = files that were in old index AND in git_changed_set
                changed_files = [f for f in parsed_files if f in old_files]
                new_files = [f for f in parsed_files if f not in old_files]

                from ..summarizer import summarize_symbols
                from ..parser.graph import CodeGraph

                new_symbols = summarize_symbols(new_symbols, use_ai=use_ai_summaries)

                updated = store.incremental_save(
                    owner=owner,
                    name=repo_name,
                    changed_files=changed_files,
                    new_files=new_files,
                    deleted_files=deleted_files,
                    new_symbols=new_symbols,
                    raw_files=raw_files,
                    languages=languages,
                    git_head=git_head,
                )

                if updated:
                    CodeGraph.clear_cache()
                    result: dict = {
                        "success": True,
                        "repo": f"{owner}/{repo_name}",
                        "indexed_at": updated.indexed_at,
                        "file_count": len(updated.source_files),
                        "symbol_count": len(updated.symbols),
                        "languages": updated.languages,
                        "files": sorted(updated.source_files)[:20],
                        "incremental": True,
                        "changed_files": len(changed_files),
                        "new_files": len(new_files),
                        "deleted_files": len(deleted_files),
                    }
                    if warnings:
                        result["warnings"] = warnings
                    return result
                # incremental_save returned None (no previous index) — fall through

            # Fall through to full index if incremental failed
            git_changed_set = None

        # --- Full index path ---
        all_symbols, languages, raw_files, parsed_files, parse_fail_count = (
            parse_source_files(_read_files())
        )

        if parse_fail_count > 0:
            warnings.append(f"{parse_fail_count} file(s) failed to parse")

        if not all_symbols:
            return {"success": False, "error": "No symbols extracted from files"}

        return finalize_index(
            owner=owner,
            name=repo_name,
            all_symbols=all_symbols,
            languages=languages,
            raw_files=raw_files,
            parsed_files=parsed_files,
            warnings=warnings,
            use_ai_summaries=use_ai_summaries,
            storage_path=storage_path,
            source_file_count=len(source_files),
            git_head=git_head,
        )

    except Exception as e:
        # RC-011: Intentionally broad — outer error boundary for indexing pipeline.
        return {"success": False, "error": sanitize_error(e)}


def _handle_index_folder(args: dict, storage_path, *, _allowed_roots_fn=None):
    """Handler that resolves ALLOWED_ROOTS at call time.

    server.py injects ``_allowed_roots_fn`` via :func:`set_allowed_roots_fn`
    so the tool file never imports from server.py (avoids circular deps).
    """
    if _handle_index_folder._allowed_roots_fn is not None:
        allowed = _handle_index_folder._allowed_roots_fn()
    else:
        allowed = None
    return index_folder(
        path=args["path"],
        use_ai_summaries=args.get("use_ai_summaries", True),
        storage_path=storage_path,
        extra_ignore_patterns=args.get("extra_ignore_patterns"),
        follow_symlinks=args.get("follow_symlinks", False),
        allowed_roots=allowed,
    )


# server.py sets this at import time so we avoid circular imports
_handle_index_folder._allowed_roots_fn = None


def set_allowed_roots_fn(fn):
    """Set the function that returns ALLOWED_ROOTS. Called by server.py."""
    _handle_index_folder._allowed_roots_fn = fn


_spec = register(ToolSpec(
    name="index_folder",
    description=(
        "Index a local folder containing source code. Walks directory, "
        "parses ASTs, extracts symbols, and saves to local storage. "
        "Works with any folder containing supported language files. "
        "Full file content (including function bodies) is stored locally at ~/.code-index/; "
        "secrets embedded in function bodies are redacted from API output but stored at rest."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to local folder (absolute or relative, supports ~ for home directory)",
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
            "extra_ignore_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Additional gitignore-style patterns to exclude from indexing",
            },
            "follow_symlinks": {
                "type": "boolean",
                "description": "Whether to follow symlinks. Default false for security.",
                "default": False,
            },
        },
        "required": ["path"],
    },
    handler=_handle_index_folder,
    index_gate=True,
    required_args=["path"],
))
