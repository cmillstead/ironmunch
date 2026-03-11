"""File discovery — local filesystem walks and GitHub tree API.

Entry point for the indexing pipeline. Discovers which files to parse
by applying security filtering, gitignore rules, and language extension checks.

Local discovery: walk filesystem with symlink/secret/binary/pattern filtering.
GitHub discovery: fetch tree via API, then filter by extension/pattern/size.
"""

import errno
import logging
import os
import stat
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, quote, unquote

import httpx
import pathspec

from .security import is_secret_file, is_binary_file, is_binary_content
from .core.limits import MAX_FILE_SIZE, MAX_FILE_COUNT, MAX_DIRECTORY_DEPTH, GITHUB_API_TIMEOUT
from .core.validation import is_within
from .parser.languages import LANGUAGE_EXTENSIONS


# File patterns to always skip (directories, generated files, lock files)
SKIP_PATTERNS = [
    "../",  # Path traversal sequences
    "node_modules/", "vendor/", "venv/", ".venv/", "__pycache__/",
    "dist/", "build/", ".git/", ".tox/", ".mypy_cache/",
    "target/",
    ".gradle/",
    "test_data/", "testdata/", "fixtures/", "snapshots/",
    "migrations/",
    ".min.js", ".min.ts", ".bundle.js",
    "package-lock.json", "yarn.lock", "go.sum",
    "generated/", "proto/",
]

# Priority directories for file count truncation
_PRIORITY_DIRS = ["src/", "lib/", "pkg/", "cmd/", "internal/"]

# ADV-MED-12: maximum length for a single gitignore pattern before it is
# dropped, to prevent ReDoS via a crafted .gitignore file.
MAX_GITIGNORE_PATTERN_LEN = 200


# ADV-LOW-8: suppress httpx DEBUG records that contain an Authorization header
# so that tokens never appear in application logs.
class _RedactAuthFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name.startswith("httpx"):
            msg = record.getMessage()
            if "authorization" in msg.lower():
                return False  # suppress the record regardless of level
        return True


logging.getLogger("httpx").addFilter(_RedactAuthFilter())


def should_skip_file(path: str) -> bool:
    """Check if a file should be skipped based on path patterns.

    Matches any substring in the normalized (forward-slash) path against
    SKIP_PATTERNS. Catches common build artifacts, caches, and lock files.
    """
    normalized = path.replace("\\", "/")
    for pattern in SKIP_PATTERNS:
        if pattern in normalized:
            return True
    return False


def _load_gitignore(folder_path: Path) -> Optional[pathspec.PathSpec]:
    """Load .gitignore from the folder root if it exists.

    Returns a compiled PathSpec for matching, or None if no .gitignore found.
    Skips files larger than 65536 bytes to prevent pathspec DoS.
    """
    gitignore_path = folder_path / ".gitignore"
    if gitignore_path.is_file():
        try:
            if gitignore_path.stat().st_size > 65536:
                return None  # Too large; skip to prevent DoS
            fd = os.open(str(gitignore_path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            lines = content.splitlines()
            # SEC-LOW-3: cap pattern count to prevent pathspec regex DoS
            if len(lines) > 2000:
                lines = lines[:2000]
            # ADV-MED-12: drop per-pattern overlong entries to prevent ReDoS
            lines = [p for p in lines if len(p) <= MAX_GITIGNORE_PATTERN_LEN]
            return pathspec.PathSpec.from_lines("gitignore", lines)
        except Exception:
            pass
    return None


def _is_symlink_escape(root: Path, file_path: Path) -> bool:
    """Check if a symlink resolves outside the root directory.

    ADV-LOW-9: delegates to is_within() to centralize containment logic.
    """
    try:
        resolved = file_path.resolve()
        resolved_root = root.resolve()
        return not is_within(resolved_root, resolved)
    except (OSError, ValueError):
        return True


def _priority_key(file_path_str: str) -> tuple:
    """Sort key that prioritizes files in standard source directories."""
    for i, prefix in enumerate(_PRIORITY_DIRS):
        if file_path_str.startswith(prefix):
            return (i, file_path_str.count("/"), file_path_str)
    return (len(_PRIORITY_DIRS), file_path_str.count("/"), file_path_str)


def discover_local_files(
    folder_path: Path,
    max_files: int = MAX_FILE_COUNT,
    max_size: int = MAX_FILE_SIZE,
    extra_ignore_patterns: Optional[list[str]] = None,
    follow_symlinks: bool = False,
) -> tuple[list[Path], list[str]]:
    """Discover source files in a local folder with security filtering.

    Walks the directory tree applying a multi-stage filter pipeline:
    1. Symlink protection (skip or validate)
    2. Path traversal check
    3. SKIP_PATTERNS matching
    4. .gitignore rules
    5. Extra ignore patterns
    6. Secret file detection
    7. Language extension filter
    8. File size limit
    9. Binary content sniffing
    10. File count cap with priority sorting

    Args:
        folder_path: Root folder to scan (will be resolved).
        max_files: Maximum number of files to return.
        max_size: Maximum file size in bytes.
        extra_ignore_patterns: Additional gitignore-style patterns to exclude.
        follow_symlinks: Whether to follow symlinks (default False for safety).

    Returns:
        Tuple of (list of Path objects for source files, list of warning strings).
    """
    files: list[Path] = []
    warnings: list[str] = []
    skipped_secret_count = 0
    skipped_binary_count = 0
    skipped_symlink_escape_count = 0
    skipped_path_traversal_count = 0
    root = folder_path.resolve()

    # Load .gitignore
    gitignore_spec = _load_gitignore(root)

    # Build extra ignore spec if provided — with limits
    extra_spec = None
    if extra_ignore_patterns:
        from .core.limits import MAX_IGNORE_PATTERNS, MAX_PATTERN_LENGTH
        bounded = [p[:MAX_PATTERN_LENGTH] for p in extra_ignore_patterns[:MAX_IGNORE_PATTERNS]]
        try:
            extra_spec = pathspec.PathSpec.from_lines("gitignore", bounded)
        except Exception:
            pass

    visited_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        current = Path(dirpath)

        # Symlink cycle protection: skip directories already visited
        try:
            resolved_dir = str(current.resolve())
        except OSError:
            dirnames.clear()
            continue
        if resolved_dir in visited_dirs:
            dirnames.clear()
            continue
        visited_dirs.add(resolved_dir)
        if len(visited_dirs) > 100_000:
            dirnames.clear()
            break

        # Depth limit — stop descending beyond MAX_DIRECTORY_DEPTH
        try:
            depth = len(current.relative_to(root).parts)
        except ValueError:
            dirnames.clear()
            continue
        if depth >= MAX_DIRECTORY_DEPTH:
            dirnames.clear()
            continue

        # ADV-MED-14: prune symlinked directories that escape the allowed root
        # before os.walk descends into them.
        if follow_symlinks:
            dirnames[:] = [
                d for d in dirnames
                if not (current / d).is_symlink()
                or not _is_symlink_escape(root, current / d)
            ]

        for filename in filenames:
            file_path = current / filename

            # Skip non-files (shouldn't happen in filenames, but defensive)
            if not file_path.is_file():
                continue

            # Symlink protection
            if not follow_symlinks and file_path.is_symlink():
                continue
            if file_path.is_symlink() and _is_symlink_escape(root, file_path):
                skipped_symlink_escape_count += 1
                continue

            # Get relative path for pattern matching
            try:
                rel_path = file_path.relative_to(root).as_posix()
            except ValueError:
                continue

            # ADV-LOW-9: Path containment check via centralized is_within()
            try:
                resolved = file_path.resolve()
                if not is_within(root, resolved):
                    skipped_path_traversal_count += 1
                    continue
            except (OSError, ValueError):
                continue

            # Skip patterns
            if should_skip_file(rel_path):
                continue

            # .gitignore matching
            if gitignore_spec and gitignore_spec.match_file(rel_path):
                continue

            # Extra ignore patterns
            if extra_spec and extra_spec.match_file(rel_path):
                continue

            # Secret detection
            if is_secret_file(rel_path):
                skipped_secret_count += 1
                continue

            # Extension filter
            ext = file_path.suffix
            if ext not in LANGUAGE_EXTENSIONS:
                continue

            # Size limit
            try:
                if file_path.stat().st_size > max_size:
                    continue
            except OSError:
                continue

            # Binary detection
            if is_binary_file(rel_path):
                skipped_binary_count += 1
                continue

            # Content-level binary sniff (O_NOFOLLOW when not following symlinks: SEC-MED-2)
            flags = os.O_RDONLY if follow_symlinks else os.O_RDONLY | os.O_NOFOLLOW
            try:
                fd = os.open(str(file_path), flags)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    os.close(fd)
                    continue
                with os.fdopen(fd, "rb") as fh:
                    head = fh.read(8192)
                if is_binary_content(head):
                    skipped_binary_count += 1
                    continue
            except OSError as e:
                if e.errno == errno.ELOOP:
                    skipped_binary_count += 1  # treat symlink-swapped file as skipped
                continue

            files.append(file_path)

    # Emit aggregate warnings for skipped files (SEC-MED-2: no per-file paths)
    if skipped_secret_count > 0:
        warnings.append(f"Skipped {skipped_secret_count} secret file(s)")
    if skipped_binary_count > 0:
        warnings.append(f"Skipped {skipped_binary_count} binary file(s)")
    if skipped_symlink_escape_count > 0:
        warnings.append(f"Skipped {skipped_symlink_escape_count} symlink escape(s)")
    if skipped_path_traversal_count > 0:
        warnings.append(f"Skipped {skipped_path_traversal_count} path traversal(s)")

    # File count limit with prioritization
    if len(files) > max_files:
        total_found = len(files)
        files.sort(key=lambda fp: _priority_key(
            fp.relative_to(root).as_posix()
        ))
        files = files[:max_files]
        warnings.append(
            f"Truncated {total_found} files to {max_files} (prioritizing src/, lib/, pkg/)"
        )

    return files, warnings


# ---------------------------------------------------------------------------
# GitHub remote discovery
# ---------------------------------------------------------------------------

def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner/repo from GitHub URL or owner/repo string.

    Supports:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - owner/repo

    Returns:
        Tuple of (owner, repo).

    Raises:
        ValueError: If the URL cannot be parsed.
    """
    # Remove .git suffix
    url = url.removesuffix(".git")

    # Validate URL scheme and hostname for full URLs
    if "://" in url:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("Only HTTPS URLs are supported")
        if parsed.hostname not in ("github.com", "www.github.com"):
            raise ValueError("Only GitHub URLs are supported")

    # If it contains a / but not ://, treat as owner/repo
    if "/" in url and "://" not in url:
        parts = url.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            if not owner or not repo:
                raise ValueError("empty owner or repo in URL")
            return owner, repo

    # Parse URL
    parsed = urlparse(url)
    path = parsed.path.strip("/")

    # Extract owner/repo from path
    parts = path.split("/")
    if len(parts) >= 2:
        owner, repo = parts[0], parts[1]
        if not owner or not repo:
            raise ValueError("empty owner or repo in URL")
        return owner, repo

    raise ValueError(f"Could not parse GitHub URL: {url}")


async def fetch_repo_tree(
    owner: str,
    repo: str,
    token: Optional[str] = None,
) -> list[dict]:
    """Fetch full repository tree via git/trees API.

    Uses recursive=1 to get all paths in a single API call.

    Args:
        owner: Repository owner.
        repo: Repository name.
        token: GitHub API token (optional).

    Returns:
        List of tree entry dicts with 'path', 'type', 'size' keys.
    """
    owner = quote(owner, safe="")
    repo = quote(repo, safe="")
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD"
    params = {"recursive": "1"}
    headers = {"Accept": "application/vnd.github.v3+json"}

    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(trust_env=False, timeout=GITHUB_API_TIMEOUT, follow_redirects=False) as client:
        response = await client.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

    if data.get("truncated"):
        logging.getLogger(__name__).warning(
            "GitHub tree was truncated; index may be incomplete"
        )
    return data.get("tree", [])


async def fetch_file_content(
    owner: str,
    repo: str,
    path: str,
    token: Optional[str] = None,
) -> str:
    """Fetch raw file content from GitHub.

    Args:
        owner: Repository owner.
        repo: Repository name.
        path: File path within the repo.
        token: GitHub API token (optional).

    Returns:
        File content as a string.
    """
    if ".." in unquote(path):
        raise ValueError("File path contains traversal sequence")
    owner = quote(owner, safe="")
    repo = quote(repo, safe="")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
    headers = {"Accept": "application/vnd.github.v3.raw"}

    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(trust_env=False, timeout=GITHUB_API_TIMEOUT, follow_redirects=False) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text


async def fetch_gitignore(
    owner: str,
    repo: str,
    token: Optional[str] = None,
) -> Optional[str]:
    """Fetch .gitignore file from a repo if it exists.

    Returns None if the file is not found or the request fails.
    """
    try:
        return await fetch_file_content(owner, repo, ".gitignore", token)
    except Exception:
        return None


def discover_source_files(
    tree_entries: list[dict],
    gitignore_content: Optional[str] = None,
    max_files: int = MAX_FILE_COUNT,
    max_size: int = MAX_FILE_SIZE,
) -> list[str]:
    """Discover source files from GitHub tree entries.

    Applies a multi-stage filter pipeline:
    1. Type filter (blobs only)
    2. Extension filter (supported languages)
    3. Skip-list patterns
    4. Secret detection
    5. Binary extension check
    6. Size limit
    7. .gitignore matching
    8. File count cap with priority sorting

    Args:
        tree_entries: List of tree entry dicts from the GitHub API.
        gitignore_content: Raw .gitignore content (optional).
        max_files: Maximum number of files to return.
        max_size: Maximum file size in bytes.

    Returns:
        List of file paths (strings) that passed all filters.
    """
    # Parse gitignore if provided — cap size to avoid pathspec DoS
    gitignore_spec = None
    if gitignore_content and len(gitignore_content) > 65536:
        gitignore_content = None  # Too large; skip
    if gitignore_content:
        try:
            lines = gitignore_content.split("\n")
            # SEC-LOW-3: cap pattern count to prevent pathspec regex DoS
            if len(lines) > 2000:
                lines = lines[:2000]
            # ADV-LOW-2: drop overlong patterns to prevent ReDoS (matches local _load_gitignore)
            lines = [p for p in lines if len(p) <= MAX_GITIGNORE_PATTERN_LEN]
            gitignore_spec = pathspec.PathSpec.from_lines(
                "gitignore",
                lines,
            )
        except Exception:
            pass

    files: list[str] = []

    for entry in tree_entries:
        # Type filter — only blobs (files)
        if entry.get("type") != "blob":
            continue

        path = entry.get("path", "")
        try:
            size = int(entry.get("size", 0))
        except (TypeError, ValueError):
            size = 0

        # Extension filter
        _, ext = os.path.splitext(path)
        if ext not in LANGUAGE_EXTENSIONS:
            continue

        # Skip list
        if should_skip_file(path):
            continue

        # Secret detection
        if is_secret_file(path):
            continue

        # Binary extension check
        if is_binary_file(path):
            continue

        # Size limit
        if size > max_size:
            continue

        # Gitignore matching
        if gitignore_spec and gitignore_spec.match_file(path):
            continue

        files.append(path)

    # File count limit with prioritization
    if len(files) > max_files:
        files.sort(key=_priority_key)
        files = files[:max_files]

    return files
