"""Security facade — combines core primitives with file-type detection.

Tools call this module, not core/ directly. Provides:
- validate_file_access() — full validation chain
- safe_read_file() — validated read with encoding safety
- is_secret_file() — secret pattern matching
- is_binary_file() — binary detection (extension)
- is_binary_content() — binary detection (content null-byte sniffing)
- should_exclude_file() — composite exclusion filter
- sanitize_repo_identifier() — owner/name validation
"""

import errno
import os
import re
from fnmatch import fnmatch
from pathlib import Path

from .core.validation import validate_path, ValidationError
from .core.limits import MAX_FILE_SIZE


# --- Secret patterns (ported from jcodemunch) ---

SECRET_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "*.keystore", "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    "*.pub", "credentials.json", "service-account*.json",
    "secret*", "*.secret", "token*", "*.token",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".htaccess",
    "wp-config.php", "config.php", "database.yml",
    "shadow", "passwd", "master.key",
    # Infrastructure secrets
    "*.tfvars", "terraform.tfstate", "terraform.tfstate.backup",
    ".dockercfg", "docker-compose*.yml",
    "kubeconfig", "*.kubeconfig",
    # SSH-related
    "known_hosts", "authorized_keys",
    # Shell/tool history
    ".bash_history", ".python_history", ".psql_history",
    # Certificate requests
    "*.csr",
    # Encryption/vault
    ".sops.yaml", "vault.json",
    # Java/JVM config
    "application.properties", "application.yml",
    # .NET config
    "appsettings*.json",
    # Node tooling
    ".yarnrc.yml",
    # Apple/PGP keys
    "*.p8", "*.asc",
]

# --- Binary extensions (ported from jcodemunch) ---

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".wasm",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".sqlite", ".db",
}

# --- Repo identifier allowlist ---

_REPO_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.]+$")


def validate_file_access(path: str, root: str) -> str:
    """Validate a file path against the root using the full chain.

    Returns the resolved absolute path if valid.
    """
    return validate_path(path, root)


def safe_read_file(abs_path: str, root: str) -> str:
    """Read a file after validation. Uses errors='replace' for encoding safety."""
    # Direct containment check for absolute paths
    resolved = str(Path(abs_path).resolve())
    resolved_root = str(Path(root).resolve())
    if not resolved.startswith(resolved_root + os.sep):
        raise ValidationError("Path resolves outside root directory")

    size = os.path.getsize(abs_path)
    if size > MAX_FILE_SIZE:
        raise ValidationError(
            f"File exceeds maximum size ({size} > {MAX_FILE_SIZE})"
        )

    try:
        fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValidationError("Path is a symlink (O_NOFOLLOW)") from exc
        raise
    with os.fdopen(fd, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def is_secret_file(file_path: str) -> bool:
    """Check if a file matches secret patterns (case-insensitive)."""
    name = Path(file_path).name.lower()
    return any(fnmatch(name, pat) for pat in SECRET_PATTERNS)


def is_binary_file(file_path: str) -> bool:
    """Check if a file is binary by extension."""
    return Path(file_path).suffix.lower() in BINARY_EXTENSIONS


def is_binary_content(data: bytes, check_size: int = 8192) -> bool:
    """Check if content contains null bytes (binary indicator)."""
    return b"\x00" in data[:check_size]


def should_exclude_file(
    file_path: str,
    check_secrets: bool = True,
    check_binary: bool = True,
) -> str | None:
    """Check if a file should be excluded. Returns reason string or None."""
    if check_secrets and is_secret_file(file_path):
        return "secret_file"
    if check_binary and is_binary_file(file_path):
        return "binary_file"
    return None


# --- Inline secret patterns for content scanning ---

_INLINE_SECRET_RE = re.compile(
    r"("
    # API key prefixes
    r"sk-[a-zA-Z0-9_\-]{20,}"
    r"|sk_live_[a-zA-Z0-9]{24,}"
    r"|ghp_[a-zA-Z0-9]{36}"
    r"|gho_[a-zA-Z0-9]{36}"
    r"|ghu_[a-zA-Z0-9]{36}"
    r"|ghs_[a-zA-Z0-9]{36}"
    r"|github_pat_[a-zA-Z0-9_]{20,}"
    r"|AKIA[A-Z0-9]{16}"
    r"|xox[bprs]-[a-zA-Z0-9\-]{10,}"
    r"|glpat-[a-zA-Z0-9\-]{20,}"
    # Connection strings with embedded credentials
    r"|(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@"
    # Bearer tokens
    r"|Bearer\s+[A-Za-z0-9\-._~+/]{20,}"
    # PEM headers
    r"|-----BEGIN [A-Z ]+ KEY-----"
    # Parameter defaults with secrets
    r"|(?:password|passwd|secret|api_key|apikey|token|auth|aws_secret_access_key|aws_session_token)\s*=\s*[\"'][^\"']{4,}[\"']"
    r")",
    re.IGNORECASE,
)


def sanitize_signature_for_api(signature: str) -> str:
    """Redact inline secrets from a code signature before sending to external APIs."""
    return _INLINE_SECRET_RE.sub("<REDACTED>", signature)


def sanitize_repo_identifier(identifier: str) -> str:
    """Validate a repository owner or name identifier.

    Allows: alphanumeric, dash, underscore, dot.
    Rejects: empty, slashes, null bytes, traversal sequences (..).
    """
    if not identifier:
        raise ValidationError("Repository identifier is empty")
    if "\x00" in identifier:
        raise ValidationError("Repository identifier contains null byte")
    if ".." in identifier:
        raise ValidationError("Repository identifier contains traversal sequence")
    if "__" in identifier:
        raise ValidationError("Repository identifier contains reserved separator")
    if not _REPO_ID_PATTERN.match(identifier):
        raise ValidationError(
            f"Repository identifier contains unsafe characters"
        )
    return identifier
