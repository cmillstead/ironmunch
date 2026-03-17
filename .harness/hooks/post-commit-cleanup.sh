#!/usr/bin/env bash
# Git post-commit hook: clean up verification stamp after successful commit.
# The stamp is single-use — must re-verify before the next commit.

rm -f .harness-verified
