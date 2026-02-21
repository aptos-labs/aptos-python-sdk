# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test:
	poetry run pytest tests/ -v

test-coverage:
	poetry run python -m coverage run -m pytest tests/ -v
	poetry run python -m coverage report

fmt:
	find ./examples ./aptos_sdk ./tests . -type f -name "*.py" | xargs poetry run autoflake -i -r --remove-all-unused-imports --remove-unused-variables --ignore-init-module-imports
	poetry run isort aptos_sdk examples tests
	poetry run black aptos_sdk examples tests

lint:
	poetry run mypy aptos_sdk
	poetry run flake8 aptos_sdk

examples:
	poetry run python -m examples.transfer_coin

.PHONY: examples fmt lint test test-coverage
