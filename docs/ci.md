# CI Pipeline

## Overview

The CI pipeline runs on GitHub Actions for every push to `main` and every pull request targeting `main`. A weekly cron run validates against dependency drift.

## Pipeline Structure

### Test Job

- **Sharding**: 4 parallel shards via pytest-split for faster execution
- **Python**: 3.12 (explicit install via uv)
- **Dependencies**: Frozen lockfile (`uv sync --frozen --extra test`)
- **Retry**: Up to 3 attempts per shard (handles transient failures)
- **Timeout**: 45 minutes per job, 30 minutes per test attempt

### Triggers

| Trigger | Branches | Notes |
|---------|----------|-------|
| `push` | `main` | Every merge to main |
| `pull_request` | `main` | Every PR targeting main |
| `schedule` | — | Weekly (Sunday 00:00 UTC) |

### Caching

uv dependency cache is enabled with cache key based on `uv.lock`. Cache is shared across shards and branches.

### Artifacts

Test results are uploaded on failure only:
- Path: `test-results/`
- Retention: 30 days
- Named per shard: `test-results-shard-{N}`

## Local Development

### Run full test suite
```bash
uv run pytest --tb=short -q
```

### Mirror CI locally
```bash
./scripts/ci-local.sh
```

### Run only changed tests
```bash
./scripts/test-changed.sh
```

## Troubleshooting

### Tests fail in CI but pass locally
1. Run `./scripts/ci-local.sh` to mirror CI environment
2. Check Python version matches (3.12)
3. Ensure `uv.lock` is committed and up to date

### Cache not working
- Cache key is based on `uv.lock` hash
- First run after lockfile change will be slower
- Check Actions logs for "Cache hit" / "Cache miss"

### Shard imbalance
- pytest-split uses timing data from `.test_durations` (if present)
- Falls back to `least_duration` algorithm
- Rebalance by committing updated `.test_durations`
