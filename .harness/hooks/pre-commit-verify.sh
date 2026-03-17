#!/usr/bin/env bash
# Git pre-commit hook: verify tests and lint were run before committing.
# Works with any AI agent or human — enforced at git level.
#
# Checks for a verification stamp file that gets created when tests/lint
# run successfully. If the stamp is missing or stale, blocks the commit.
#
# To create the stamp, wrap your test/lint commands:
#   npm test && touch .harness-verified
#   npm run lint && touch .harness-verified
#
# Or use the harness wrapper: harness-run <command>
#
# Skip with: git commit --no-verify (explicitly opted out)

set -euo pipefail

STAMP_FILE=".harness-verified"
MAX_AGE_MINUTES=30

# Skip for docs-only repos (no build/test infrastructure)
PROJECT_MARKERS=(
    package.json tsconfig.json deno.json
    pyproject.toml setup.py setup.cfg requirements.txt Pipfile tox.ini
    Cargo.toml
    go.mod
    pom.xml build.gradle build.gradle.kts build.sbt
    Directory.Build.props
    Gemfile Rakefile
    composer.json
    Package.swift
    pubspec.yaml
    mix.exs
    stack.yaml cabal.project
    CMakeLists.txt meson.build configure.ac
    build.zig
    deps.edn project.clj
    Project.toml
    Makefile Justfile
)

is_docs_only=true
for marker in "${PROJECT_MARKERS[@]}"; do
    if [ -f "$marker" ]; then
        is_docs_only=false
        break
    fi
done

# Also check glob patterns (.csproj, .sln, .xcodeproj)
if $is_docs_only; then
    for pattern in "*.csproj" "*.sln" "*.xcodeproj" "*.nimble"; do
        if compgen -G "$pattern" > /dev/null 2>&1; then
            is_docs_only=false
            break
        fi
    done
fi

if $is_docs_only; then
    exit 0  # docs-only repo, no verification needed
fi

# Check if stamp exists
if [ ! -f "$STAMP_FILE" ]; then
    echo "============================================"
    echo "BLOCKED: No verification stamp found"
    echo "============================================"
    echo ""
    echo "Golden Principle #8: Verify Before Claiming Done."
    echo ""
    echo "Run tests and linting before committing:"
    echo "  npm test && npm run lint && touch $STAMP_FILE"
    echo ""
    echo "Or for Python projects:"
    echo "  pytest && ruff check . && touch $STAMP_FILE"
    echo ""
    echo "Or for Rust projects:"
    echo "  cargo test && cargo clippy && touch $STAMP_FILE"
    echo ""
    echo "The stamp auto-expires after $MAX_AGE_MINUTES minutes."
    echo "Skip this check with: git commit --no-verify"
    echo ""
    exit 1
fi

# Check stamp age
if [ "$(uname)" = "Darwin" ]; then
    stamp_time=$(stat -f %m "$STAMP_FILE")
else
    stamp_time=$(stat -c %Y "$STAMP_FILE")
fi
now=$(date +%s)
age=$(( (now - stamp_time) / 60 ))

if [ "$age" -gt "$MAX_AGE_MINUTES" ]; then
    echo "============================================"
    echo "BLOCKED: Verification stamp is stale (${age}m old)"
    echo "============================================"
    echo ""
    echo "Re-run tests and linting — the stamp expires after $MAX_AGE_MINUTES minutes."
    echo "  npm test && npm run lint && touch $STAMP_FILE"
    echo ""
    rm -f "$STAMP_FILE"
    exit 1
fi

# Clean up stamp after successful commit (via post-commit hook)
# The stamp is single-use per commit cycle
