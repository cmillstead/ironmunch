#!/bin/bash
# Run CI pipeline locally to debug CI-specific failures
set -euo pipefail

echo "=== CI Local Runner ==="
echo "Mirroring GitHub Actions CI environment"
echo ""

# Install dependencies exactly as CI does
echo "--- Installing dependencies (frozen) ---"
uv sync --frozen --extra test

# Run tests with same flags as CI
echo ""
echo "--- Running tests ---"
uv run pytest --tb=short -q "$@"

echo ""
echo "=== CI Local Complete ==="
