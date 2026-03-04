"""Resource limit constants for ironmunch.

All limits enforced server-side. Changing these values affects security posture.
"""

# File discovery limits
MAX_FILE_SIZE: int = 500 * 1024  # 500 KB per file
MAX_FILE_COUNT: int = 500  # Max files per index

# Path limits
MAX_PATH_LENGTH: int = 512  # Max path string length
MAX_DIRECTORY_DEPTH: int = 10  # Max directory nesting

# Retrieval limits
MAX_CONTEXT_LINES: int = 100  # Max context lines around a symbol
MAX_SEARCH_RESULTS: int = 50  # Max results per search query

# Storage limits
MAX_INDEX_SIZE: int = 50 * 1024 * 1024  # 50 MB max index JSON

# Input validation limits
MAX_ARGUMENT_LENGTH: int = 10_000  # Max string argument length
MAX_BATCH_SYMBOLS: int = 50  # Max symbol IDs per get_symbols call

# Network limits
GITHUB_API_TIMEOUT: int = 30  # Seconds per GitHub API request
