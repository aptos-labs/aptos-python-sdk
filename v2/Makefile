.PHONY: install lint format typecheck test test-cov check clean

install:
	uv sync --extra dev

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

typecheck:
	uv run mypy src/
	uvx ty check src/

test:
	uv run pytest tests/unit -q

test-cov:
	uv run pytest tests/unit --cov=aptos_sdk_v2 --cov-report=term-missing

check: lint typecheck test

clean:
	rm -rf .venv dist build src/*.egg-info .mypy_cache .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
