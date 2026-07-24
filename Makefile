.PHONY: check lint typecheck counts test test-fast stamp contract

check: lint typecheck counts test

lint:
	uv run --with ruff ruff check .

typecheck:
	uv run --group typecheck mypy

counts:
	uv run python scripts/check_counts.py

test:
	uv run pytest --tb=short -q

test-fast:
	uv run pytest --tb=short -q -m "not stress and not benchmark and not fuzz"

stamp:
	uv run python scripts/check_counts.py --write

contract:
	uv run python scripts/export_contract.py --write
