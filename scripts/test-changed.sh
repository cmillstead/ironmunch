#!/bin/bash
# Run tests only for changed files (compares against main branch)
set -euo pipefail

CHANGED_FILES=$(git diff --name-only origin/main...HEAD -- 'src/**/*.py' | sed 's|src/||' | sed 's|\.py$||' | sed 's|/|.|g')

if [ -z "$CHANGED_FILES" ]; then
    echo "No Python source files changed."
    exit 0
fi

echo "Changed modules:"
echo "$CHANGED_FILES"
echo ""

# Map changed source files to test files
TEST_FILES=""
for module in $CHANGED_FILES; do
    base=$(basename "$module")
    found=$(find tests -name "test_${base}.py" -o -name "test_*${base}*.py" 2>/dev/null || true)
    if [ -n "$found" ]; then
        TEST_FILES="$TEST_FILES $found"
    fi
done

if [ -z "$TEST_FILES" ]; then
    echo "No matching test files found. Running full suite."
    uv run pytest --tb=short -q
else
    echo "Running tests: $TEST_FILES"
    uv run pytest $TEST_FILES --tb=short -q
fi
