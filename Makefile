# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test:
	uv run python -m unittest discover -s aptos_sdk/ -p '*.py' -t ..
	uv run behave

test-coverage:
	uv run python -m coverage run -m unittest discover -s aptos_sdk/ -p '*.py' -t ..
	uv run python -m coverage report
	uv run python -m coverage xml -o coverage.xml
	uv run python -m coverage html

test-spec:
	uv run behave

fmt:
	uv run ruff check --fix aptos_sdk examples features
	uv run ruff format aptos_sdk examples features

lint:
	uv run mypy aptos_sdk examples features
	uv run ruff check aptos_sdk examples features

examples:
	uv run python -m examples.aptos_token
	uv run python -m examples.fee_payer_transfer_coin
	uv run python -m examples.multikey
	uv run python -m examples.rotate_key
	uv run python -m examples.read_aggregator
	uv run python -m examples.secp256k1_ecdsa_transfer_coin
	uv run python -m examples.simple_aptos_token
	uv run python -m examples.simple_nft
	uv run python -m examples.simulate_transfer_coin
	uv run python -m examples.transfer_coin
	uv run python -m examples.transfer_two_by_two

examples_cli:
	uv run python -m examples.hello_blockchain
	#	uv run python -m examples.large_package_publisher CURRENTLY BROKEN -- OUT OF GAS
	#uv run python -m examples.multisig CURRENTLY BROKEN requires aptos-core checkout
	uv run python -m examples.object_code_deployment
	uv run python -m examples.your_coin

integration_test:
	uv run python -m unittest -b examples.integration_test

.PHONY: examples fmt lint test test-coverage test-spec
