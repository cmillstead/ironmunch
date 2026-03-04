"""Index storage with save/load, byte-offset content retrieval, and incremental indexing."""

import errno
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..parser.symbols import Symbol
from ..security import sanitize_repo_identifier, sanitize_signature_for_api
from ..core.limits import MAX_INDEX_SIZE, MAX_FILE_SIZE
from ..core.validation import validate_path, ValidationError, is_within

# Bump this when the index schema changes in an incompatible way.
INDEX_VERSION = 2


def _open_nofollow_text(path: "Path") -> "io.TextIOWrapper":
    """Open a file for reading with O_NOFOLLOW to prevent symlink attacks.

    Raises OSError with errno.ELOOP if the path is a symlink.
    """
    import io
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    return io.open(fd, "r", encoding="utf-8")


def _file_hash(content: str) -> str:
    """SHA-256 hash of file content string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _makedirs_0o700(path: str) -> None:
    """Create directories with mode 0o700, respecting the umask correctly.

    Python's os.makedirs() mode argument is modified by the process umask for
    intermediate directories. To guarantee 0o700 we temporarily set umask=0o077
    (which means only the owner bits survive from 0o777, giving 0o700).
    """
    old_umask = os.umask(0o077)
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    finally:
        os.umask(old_umask)



@dataclass
class CodeIndex:
    """Index for a repository's source code."""
    repo: str                    # "owner/repo"
    owner: str
    name: str
    indexed_at: str              # ISO timestamp
    source_files: list[str]      # All indexed file paths
    languages: dict[str, int]    # Language -> file count
    symbols: list[dict]          # Serialized Symbol dicts (without source content)
    index_version: int = INDEX_VERSION
    file_hashes: dict[str, str] = field(default_factory=dict)  # file_path -> sha256
    git_head: str = ""           # HEAD commit hash at index time (for git repos)

    def get_symbol(self, symbol_id: str) -> Optional[dict]:
        """Find a symbol by ID."""
        for sym in self.symbols:
            if sym.get("id") == symbol_id:
                return sym
        return None

    def search(self, query: str, kind: Optional[str] = None, file_pattern: Optional[str] = None) -> list[dict]:
        """Search symbols with weighted scoring."""
        query_lower = query.lower()
        query_words = set(query_lower.split())

        scored = []
        for sym in self.symbols:
            # Apply filters
            if kind and sym.get("kind") != kind:
                continue
            if file_pattern and not self._match_pattern(sym.get("file", ""), file_pattern):
                continue

            # Score symbol
            score = self._score_symbol(sym, query_lower, query_words)
            if score > 0:
                scored.append((score, sym))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)
        return [sym for _, sym in scored]

    def _match_pattern(self, file_path: str, pattern: str) -> bool:
        """Match file path against glob pattern."""
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(file_path, f"*/{pattern}")

    def _score_symbol(self, sym: dict, query_lower: str, query_words: set) -> int:
        """Calculate search score for a symbol.

        Delegates to the shared implementation in tools._common so the
        ranking logic lives in exactly one place.  The import is deferred
        to method-call time to avoid the circular import that would arise
        if tools._common were imported at module level (tools._common
        itself imports storage.IndexStore).
        """
        from ..tools._common import calculate_symbol_score  # deferred – avoids circular import
        return calculate_symbol_score(sym, query_lower, query_words)


class IndexStore:
    """Storage for code indexes with byte-offset content retrieval."""

    def __init__(self, base_path: Optional[str] = None):
        """Initialize store.

        Args:
            base_path: Base directory for storage. Defaults to ~/.code-index/
        """
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = Path.home() / ".code-index"

        # SEC-LOW-4: use _makedirs_0o700 to avoid TOCTOU between mkdir and chmod
        _makedirs_0o700(str(self.base_path))
        self._cleanup_stale_temps()

    def _cleanup_stale_temps(self):
        """Remove stale .json.tmp files left by crashed writes."""
        for tmp_file in self.base_path.glob("*.json.tmp"):
            try:
                tmp_file.unlink()
            except OSError:
                pass

    def _index_path(self, owner: str, name: str) -> Path:
        """Path to index JSON file."""
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(name)
        return self.base_path / f"{owner}__{name}.json"

    def _content_dir(self, owner: str, name: str) -> Path:
        """Path to raw content directory."""
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(name)
        return self.base_path / f"{owner}__{name}"

    def _atomic_write(self, final_path: Path, data: "bytes | str") -> None:
        """Write data to final_path atomically via a .tmp file.

        Opens the .tmp file with O_NOFOLLOW | O_CREAT | O_TRUNC, writes
        data, then renames the .tmp over final_path.  Cleans up the .tmp
        on any failure so no partial file is left behind.

        Args:
            final_path: Destination path (must not be a symlink).
            data: Bytes or str to write.  str is encoded as UTF-8.
        """
        tmp_path = final_path.with_suffix(final_path.suffix + ".tmp")
        try:
            if isinstance(data, bytes):
                fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
            else:
                fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(data)
            # Atomic rename (POSIX-atomic; best-effort on Windows)
            tmp_path.replace(final_path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    def save_index(
        self,
        owner: str,
        name: str,
        source_files: list[str],
        symbols: list[Symbol],
        raw_files: dict[str, str],
        languages: dict[str, int],
        file_hashes: Optional[dict[str, str]] = None,
        git_head: str = "",
    ) -> "CodeIndex":
        """Save index and raw files to storage.

        Args:
            owner: Repository owner.
            name: Repository name.
            source_files: List of indexed file paths.
            symbols: List of Symbol objects.
            raw_files: Dict mapping file path to raw content.
            languages: Dict mapping language to file count.
            file_hashes: Optional precomputed {file_path: sha256} map.
            git_head: Optional HEAD commit hash at index time.

        Returns:
            CodeIndex object.
        """
        # Compute file hashes if not provided
        if file_hashes is None:
            file_hashes = {fp: _file_hash(content) for fp, content in raw_files.items()}

        # Create index
        index = CodeIndex(
            repo=f"{owner}/{name}",
            owner=owner,
            name=name,
            indexed_at=datetime.now().isoformat(),
            source_files=source_files,
            languages=languages,
            symbols=[self._symbol_to_dict(s) for s in symbols],
            index_version=INDEX_VERSION,
            file_hashes=file_hashes,
            git_head=git_head,
        )

        # Prepare content directory
        content_dir = self._content_dir(owner, name)
        _makedirs_0o700(str(content_dir))

        # Phase 1: write all content files to .tmp paths first so that any
        # write failure leaves the existing index intact (no split state).
        content_tmp_paths: list[tuple[Path, Path]] = []  # (final, tmp)
        try:
            for file_path, content in raw_files.items():
                dest = (content_dir / file_path).resolve()
                resolved_root = content_dir.resolve()
                if not is_within(resolved_root, dest):
                    continue  # Traversal — skip silently
                _makedirs_0o700(str(dest.parent))
                tmp_dest = dest.with_suffix(dest.suffix + ".tmp")
                try:
                    fd = os.open(
                        str(tmp_dest),
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(content)
                    content_tmp_paths.append((dest, tmp_dest))
                except OSError:
                    continue  # Symlink or permission error — skip

            # Phase 2: write the JSON index to its .tmp path
            index_path = self._index_path(owner, name)
            json_data = json.dumps(self._index_to_dict(index), indent=2)
            self._atomic_write(index_path, json_data)

            # Phase 3: rename all content .tmp → final (after JSON succeeded)
            for final, tmp in content_tmp_paths:
                tmp.replace(final)
            content_tmp_paths.clear()  # Mark all as renamed — nothing left to clean

        finally:
            # Clean up any content .tmp files that were not yet renamed
            for _final, tmp in content_tmp_paths:
                tmp.unlink(missing_ok=True)

        return index

    def load_index(self, owner: str, name: str) -> Optional[CodeIndex]:
        """Load index from storage. Rejects incompatible versions."""
        index_path = self._index_path(owner, name)

        if not index_path.exists():
            return None

        # Index size validation
        size = index_path.stat().st_size
        if size > MAX_INDEX_SIZE:
            raise ValueError(f"Index file exceeds maximum size ({size} > {MAX_INDEX_SIZE})")

        try:
            f = _open_nofollow_text(index_path)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return None  # Symlink — reject
            raise
        with f:
            data = json.load(f)

        # Version check
        stored_version = data.get("index_version", 1)
        if not isinstance(stored_version, int) or stored_version > INDEX_VERSION:
            return None  # Future or invalid version we can't read

        # Schema validation — reject malformed indexes
        required_fields = ("repo", "owner", "name", "indexed_at", "source_files", "languages", "symbols")
        for fld in required_fields:
            if fld not in data:
                return None
        if not isinstance(data["source_files"], list):
            return None
        if not isinstance(data["symbols"], list):
            return None
        if not isinstance(data["languages"], dict):
            return None
        if not all(isinstance(s, dict) for s in data["symbols"]):
            return None
        if not all(isinstance(f, str) for f in data["source_files"]):
            return None
        if not all(
            isinstance(k, str) and isinstance(v, int) and v >= 0
            for k, v in data["languages"].items()
        ):
            return None

        # SEC-LOW-5: Re-sanitize symbol text fields on load to catch secrets
        # written before current redaction rules or tampered on disk.
        for sym in data["symbols"]:
            for field in ("signature", "docstring", "summary"):
                if field in sym and isinstance(sym[field], str):
                    sym[field] = sanitize_signature_for_api(sym[field])
            if "decorators" in sym and isinstance(sym["decorators"], list):
                sym["decorators"] = [
                    sanitize_signature_for_api(d) if isinstance(d, str) else d
                    for d in sym["decorators"]
                ]

        try:
            return CodeIndex(
                repo=data["repo"],
                owner=data["owner"],
                name=data["name"],
                indexed_at=data["indexed_at"],
                source_files=data["source_files"],
                languages=data["languages"],
                symbols=data["symbols"],
                index_version=stored_version,
                file_hashes=data.get("file_hashes", {}),
                git_head=data.get("git_head", ""),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def get_symbol_content(
        self,
        owner: str,
        name: str,
        symbol_id: str,
        index: Optional["CodeIndex"] = None,
    ) -> Optional[str]:
        """Read symbol source using stored byte offsets.

        This is O(1) - no re-parsing, just seek + read.

        Args:
            owner: Repository owner.
            name: Repository name.
            symbol_id: Symbol ID to retrieve.
            index: Pre-loaded CodeIndex to avoid TOCTOU double-load.
                   If None, loads from disk (backward compat).
        """
        if index is None:
            index = self.load_index(owner, name)
        if not index:
            return None

        symbol = index.get_symbol(symbol_id)
        if not symbol:
            return None

        # --- security gate: validate symbol["file"] against content dir ---
        content_dir = self._content_dir(owner, name)
        try:
            validated_path = validate_path(symbol["file"], str(content_dir))
        except ValidationError:
            return None

        file_path = Path(validated_path)

        if not file_path.exists():
            return None

        # --- security gate: cap byte_length to MAX_FILE_SIZE ---
        byte_length = min(symbol["byte_length"], MAX_FILE_SIZE)

        byte_offset = max(symbol["byte_offset"], 0)

        # SEC-LOW-2: O_NOFOLLOW prevents symlink substitution attacks at read time
        try:
            fd = os.open(str(file_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return None  # Symlink — reject
            raise
        with os.fdopen(fd, "rb") as f:
            f.seek(byte_offset)
            source_bytes = f.read(byte_length)

        return source_bytes.decode("utf-8", errors="replace")

    def detect_changes(
        self,
        owner: str,
        name: str,
        current_files: dict[str, str],
    ) -> tuple[list[str], list[str], list[str]]:
        """Detect changed, new, and deleted files by comparing hashes.

        Args:
            owner: Repository owner.
            name: Repository name.
            current_files: Dict mapping file_path -> content for current state.

        Returns:
            Tuple of (changed_files, new_files, deleted_files).
        """
        index = self.load_index(owner, name)
        if not index:
            # No existing index: all files are new
            return [], list(current_files.keys()), []

        old_hashes = index.file_hashes
        current_hashes = {fp: _file_hash(content) for fp, content in current_files.items()}

        old_set = set(old_hashes.keys())
        new_set = set(current_hashes.keys())

        new_files = list(new_set - old_set)
        deleted_files = list(old_set - new_set)
        changed_files = [
            fp for fp in (old_set & new_set)
            if old_hashes[fp] != current_hashes[fp]
        ]

        return changed_files, new_files, deleted_files

    def incremental_save(
        self,
        owner: str,
        name: str,
        changed_files: list[str],
        new_files: list[str],
        deleted_files: list[str],
        new_symbols: list[Symbol],
        raw_files: dict[str, str],
        languages: dict[str, int],
        git_head: str = "",
    ) -> Optional[CodeIndex]:
        """Incrementally update an existing index.

        Removes symbols for deleted/changed files, adds new symbols,
        updates raw content, and saves atomically.

        Args:
            owner: Repository owner.
            name: Repository name.
            changed_files: Files that changed (symbols will be replaced).
            new_files: New files (symbols will be added).
            deleted_files: Deleted files (symbols will be removed).
            new_symbols: Symbols extracted from changed + new files.
            raw_files: Raw content for changed + new files.
            languages: Updated language counts.
            git_head: Current HEAD commit hash.

        Returns:
            Updated CodeIndex, or None if no existing index.
        """
        index = self.load_index(owner, name)
        if not index:
            return None

        # Remove symbols for deleted and changed files
        files_to_remove = set(deleted_files) | set(changed_files)
        kept_symbols = [s for s in index.symbols if s.get("file") not in files_to_remove]

        # Add new symbols
        all_symbols_dicts = kept_symbols + [self._symbol_to_dict(s) for s in new_symbols]

        # Update source files list
        old_files = set(index.source_files)
        for f in deleted_files:
            old_files.discard(f)
        for f in new_files:
            old_files.add(f)
        for f in changed_files:
            old_files.add(f)

        # Update file hashes
        file_hashes = dict(index.file_hashes)
        for f in deleted_files:
            file_hashes.pop(f, None)
        for fp, content in raw_files.items():
            file_hashes[fp] = _file_hash(content)

        # Build updated index
        updated = CodeIndex(
            repo=f"{owner}/{name}",
            owner=owner,
            name=name,
            indexed_at=datetime.now().isoformat(),
            source_files=sorted(old_files),
            languages=languages,
            symbols=all_symbols_dicts,
            index_version=INDEX_VERSION,
            file_hashes=file_hashes,
            git_head=git_head,
        )

        # Prepare content directory
        content_dir = self._content_dir(owner, name)
        _makedirs_0o700(str(content_dir))
        resolved_root = content_dir.resolve()

        # Phase 1: write changed + new content files to .tmp paths first so
        # that any write failure leaves the existing index intact (no split state).
        content_tmp_paths: list[tuple[Path, Path]] = []  # (final, tmp)
        try:
            for fp, content in raw_files.items():
                dest = (content_dir / fp).resolve()
                if not is_within(resolved_root, dest):
                    continue  # Traversal — skip silently
                _makedirs_0o700(str(dest.parent))
                tmp_dest = dest.with_suffix(dest.suffix + ".tmp")
                try:
                    fd = os.open(
                        str(tmp_dest),
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(content)
                    content_tmp_paths.append((dest, tmp_dest))
                except OSError:
                    continue  # Symlink or permission error — skip

            # Phase 2: write the updated JSON index to its .tmp path
            index_path = self._index_path(owner, name)
            json_data = json.dumps(self._index_to_dict(updated), indent=2)
            self._atomic_write(index_path, json_data)

            # Phase 3: remove deleted files from content dir (containment-validated)
            for fp in deleted_files:
                dead = (content_dir / fp).resolve()
                if not is_within(resolved_root, dead):
                    continue  # Traversal — skip silently
                if dead.exists():
                    dead.unlink()

            # Phase 4: rename all content .tmp → final (after JSON succeeded)
            for final, tmp in content_tmp_paths:
                tmp.replace(final)
            content_tmp_paths.clear()  # Mark all as renamed — nothing left to clean

        finally:
            # Clean up any content .tmp files that were not yet renamed
            for _final, tmp in content_tmp_paths:
                tmp.unlink(missing_ok=True)

        return updated

    def list_repos(self) -> list[dict]:
        """List all indexed repositories."""
        repos = []

        for index_file in self.base_path.glob("*.json"):
            # Size limit check
            try:
                if index_file.stat().st_size > MAX_INDEX_SIZE:
                    continue
            except OSError:
                continue
            try:
                f = _open_nofollow_text(index_file)
                with f:
                    data = json.load(f)

                # Validate required fields before accessing
                if not all(k in data for k in ("repo", "indexed_at", "symbols", "source_files", "languages")):
                    continue

                # Type-validate key string fields to prevent injection / errors
                if not isinstance(data.get("repo"), str) or not isinstance(data.get("indexed_at"), str):
                    continue

                repos.append({
                    "repo": data["repo"],
                    "indexed_at": data["indexed_at"],
                    "symbol_count": len(data["symbols"]),
                    "file_count": len(data["source_files"]),
                    "languages": data["languages"],
                    "index_version": data.get("index_version", 1),
                })
            except Exception:
                continue

        return repos

    def delete_index(self, owner: str, name: str) -> bool:
        """Delete an index and its raw files."""
        index_path = self._index_path(owner, name)
        content_dir = self._content_dir(owner, name)

        deleted = False

        if index_path.exists():
            index_path.unlink()
            deleted = True

        if content_dir.is_symlink():
            # Symlink to another directory — remove the link, not the target
            content_dir.unlink()
            deleted = True
        elif content_dir.exists():
            shutil.rmtree(content_dir)
            deleted = True

        return deleted

    def _safe_write_content(self, content_dir: Path, file_path: str, content: str) -> bool:
        """Write a file to the content directory after validating the path.

        Uses O_NOFOLLOW to prevent symlink race (TOCTOU) between
        containment check and file write.

        Returns True if written, False if path was rejected.
        """
        dest = (content_dir / file_path).resolve()
        resolved_root = content_dir.resolve()
        if not is_within(resolved_root, dest):
            return False  # Traversal — reject silently
        _makedirs_0o700(str(dest.parent))
        try:
            fd = os.open(
                str(dest),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            return False  # Symlink or permission error — reject
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        return True

    def _symbol_to_dict(self, symbol: Symbol) -> dict:
        """Convert Symbol to dict (without source content)."""
        return {
            "id": symbol.id,
            "file": symbol.file,
            "name": symbol.name,
            "qualified_name": symbol.qualified_name,
            "kind": symbol.kind,
            "language": symbol.language,
            "signature": symbol.signature,
            "docstring": symbol.docstring,
            "summary": symbol.summary,
            "decorators": symbol.decorators,
            "keywords": symbol.keywords,
            "parent": symbol.parent,
            "line": symbol.line,
            "end_line": symbol.end_line,
            "byte_offset": symbol.byte_offset,
            "byte_length": symbol.byte_length,
            "content_hash": symbol.content_hash,
        }

    def _index_to_dict(self, index: CodeIndex) -> dict:
        """Convert CodeIndex to dict."""
        return {
            "repo": index.repo,
            "owner": index.owner,
            "name": index.name,
            "indexed_at": index.indexed_at,
            "source_files": index.source_files,
            "languages": index.languages,
            "symbols": index.symbols,
            "index_version": index.index_version,
            "file_hashes": index.file_hashes,
            "git_head": index.git_head,
        }
