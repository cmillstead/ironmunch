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
import unicodedata
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

_REPO_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.]+\Z")


def validate_file_access(path: str, root: str) -> str:
    """Validate a file path against the root using the full chain.

    Returns the resolved absolute path if valid.
    """
    return validate_path(path, root)


def safe_read_file(abs_path: str, root: str) -> str:
    """Read a file after validation. Uses errors='replace' for encoding safety."""
    validate_path(abs_path, root)

    try:
        fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValidationError("Path is a symlink (O_NOFOLLOW)") from exc
        raise

    # ADV-LOW-1: Transfer fd ownership to fdopen immediately. If fdopen
    # fails, close fd explicitly; once fdopen succeeds, the file object
    # owns the fd and we use a with-block for cleanup.
    try:
        fh = os.fdopen(fd, encoding="utf-8", errors="replace")
    except Exception:
        os.close(fd)
        raise

    with fh:
        size = os.fstat(fh.fileno()).st_size
        if size > MAX_FILE_SIZE:
            raise ValidationError(
                f"File exceeds maximum size ({size} > {MAX_FILE_SIZE})"
            )
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
    r"|hf_[a-zA-Z0-9]{34,}"
    r"|npm_[a-zA-Z0-9]{36,}"
    r"|pypi-[a-zA-Z0-9_\-]{32,}"
    r"|AIza[a-zA-Z0-9\-_]{35}"
    r"|rk_live_[a-zA-Z0-9]{24,}"
    r"|rk_test_[a-zA-Z0-9]{24,}"
    r"|SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}"
    r"|AC[a-f0-9]{32}"
    r"|key-[a-zA-Z0-9]{32}"
    # Azure connection strings
    r"|DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\s]+"
    # Connection strings with embedded credentials
    r"|(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@"
    # Bearer tokens
    r"|Bearer\s+[A-Za-z0-9\-._~+/]{20,}"
    # PEM headers
    r"|-----BEGIN [A-Z ]+ KEY-----"
    # Parameter defaults with secrets
    r"|(?:password|passwd|secret|api_key|apikey|token|auth|aws_secret_access_key|aws_session_token|twilio)\s*=\s*[\"'][^\"']{4,}[\"']"
    r")",
    re.IGNORECASE,
)


# ADV-MED-2: Freeze at startup — a compromised in-process dependency cannot
# toggle redaction off after import by mutating os.environ.
_NO_REDACT: bool = os.environ.get("CODESIGHT_NO_REDACT", "") == "1"

if _NO_REDACT:
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "CODESIGHT_NO_REDACT=1 is set — inline secret redaction is DISABLED. "
        "Secrets in code may be sent to external APIs."
    )


def _no_redact() -> bool:
    """Check if redaction is disabled via CODESIGHT_NO_REDACT=1.

    ADV-MED-2: Frozen at module import time — runtime env mutations are ignored.
    """
    return _NO_REDACT


def sanitize_signature_for_api(signature: str) -> str:
    """Redact inline secrets from a code signature before sending to external APIs.

    ADV-MED-1: Strips DEL (0x7F), C1 controls (0x80-0x9F), and all Unicode
    category Cf (format) characters — including zero-width chars (U+200B-200F,
    U+FEFF, U+00AD, U+2060-2063) and bidi overrides (U+202A-202E, U+2066-2069).
    Also applies NFKD normalization so confusable characters (e.g. fullwidth
    letters) are reduced to their ASCII equivalents before regex matching.

    When CODESIGHT_NO_REDACT=1 is set, returns the signature unchanged
    (opt-in for trusted local usage).
    """
    if not isinstance(signature, str):
        return ""
    if len(signature) > 10000:
        signature = signature[:10000]
    if _no_redact():
        return signature
    # ADV-MED-1: Strip DEL, C1 controls, and Unicode format chars (category Cf)
    cleaned = "".join(
        c for c in signature
        if not (ord(c) == 127 or 128 <= ord(c) <= 159 or unicodedata.category(c) == "Cf")
    )
    # ADV-MED-1: NFKD normalization reduces confusables to ASCII equivalents
    cleaned = unicodedata.normalize("NFKD", cleaned)
    return _INLINE_SECRET_RE.sub("<REDACTED>", cleaned)


def sanitize_repo_identifier(identifier: str) -> str:
    """Validate a repository owner or name identifier.

    Allows: alphanumeric, dash, underscore, dot.
    Rejects: empty, too-long, slashes, null bytes, traversal sequences (..).
    """
    if not isinstance(identifier, str):
        raise ValidationError("Identifier must be a string")
    if not identifier:
        raise ValidationError("Repository identifier is empty")
    if len(identifier) > 100:
        raise ValidationError("Repository identifier too long")
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
    if identifier in (".", ".."):
        raise ValidationError("Reserved path name")
    return identifier
