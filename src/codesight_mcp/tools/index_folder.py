"""Index a local folder -- walk, parse, summarize, save.

This is a thin wrapper that delegates discovery to ``codesight_mcp.discovery``
(already extracted and ported). File security filtering (symlinks, secrets,
path traversal) is handled by ``discover_local_files()``.
"""

import errno
import hashlib
import os
from pathlib import Path
from typing import Optional

from ..discovery import discover_local_files
from ..parser import parse_file, LANGUAGE_EXTENSIONS
from ..security import sanitize_repo_identifier
from ..core.errors import sanitize_error
from ..core.limits import MAX_FILE_COUNT
from ..core.validation import validate_path, ValidationError, is_within
from ..parser.graph import CodeGraph
from ..storage import IndexStore
from ..summarizer import summarize_symbols


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

        # Read and parse files
        all_symbols = []
        languages: dict[str, int] = {}
        raw_files: dict[str, str] = {}
        parsed_files: list[str] = []
        parse_fail_count = 0

        for file_path in source_files:
            # --- security gate: re-validate path before reading (defense in depth) ---
            try:
                resolved = file_path.resolve()
                resolved_root = folder_path.resolve()
                if not is_within(resolved_root, resolved):
                    continue
            except (OSError, ValueError):
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
            except Exception:
                warnings.append("Failed to read file")
                continue

            # Get relative path for storage
            try:
                rel_path = file_path.relative_to(folder_path).as_posix()
            except ValueError:
                warnings.append("Skipped file: could not resolve relative path")
                continue

            # Determine language from extension
            ext = file_path.suffix
            language = LANGUAGE_EXTENSIONS.get(ext)

            if not language:
                continue

            # Parse file
            try:
                symbols = parse_file(content, rel_path, language)
                if symbols:
                    all_symbols.extend(symbols)
                    languages[language] = languages.get(language, 0) + 1
                    raw_files[rel_path] = content
                    parsed_files.append(rel_path)
            except Exception:
                parse_fail_count += 1
                continue

        if parse_fail_count > 0:
            warnings.append(f"{parse_fail_count} file(s) failed to parse")

        if not all_symbols:
            return {"success": False, "error": "No symbols extracted from files"}

        # Generate summaries
        all_symbols = summarize_symbols(all_symbols, use_ai=use_ai_summaries)

        # Create repo identifier from folder path.
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
        except Exception as exc:
            return {"success": False, "error": sanitize_error(exc)}

        # Save index
        store = IndexStore(base_path=storage_path)
        store.save_index(
            owner=owner,
            name=repo_name,
            source_files=parsed_files,
            symbols=all_symbols,
            raw_files=raw_files,
            languages=languages,
        )

        # Clear the in-memory graph cache so stale graphs aren't reused
        CodeGraph.clear_cache()

        result: dict = {
            "success": True,
            "repo": f"{owner}/{repo_name}",
            "indexed_at": store.load_index(owner, repo_name).indexed_at,
            "file_count": len(parsed_files),
            "symbol_count": len(all_symbols),
            "languages": languages,
            "files": parsed_files[:20],  # Limit files in response
        }

        if warnings:
            result["warnings"] = warnings

        if len(source_files) >= MAX_FILE_COUNT:
            result["note"] = f"Folder has many files; indexed first {MAX_FILE_COUNT}"

        return result

    except Exception as e:
        return {"success": False, "error": sanitize_error(e)}
