# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

test:
	poetry run python -m unittest discover -s aptos_sdk/ -p '*.py' -t ..
	poetry run behave

test-coverage:
	poetry run python -m coverage run -m unittest discover -s aptos_sdk/ -p '*.py' -t ..
	poetry run python -m coverage report

test-spec:
	poetry run behave

fmt:
	find ./examples ./aptos_sdk ./features . -type f -name "*.py" | xargs poetry run autoflake -i -r --remove-all-unused-imports --remove-unused-variables --ignore-init-module-imports
	poetry run isort aptos_sdk examples features
	poetry run black aptos_sdk examples features

lint:
	poetry run mypy aptos_sdk examples features
	poetry run flake8 aptos_sdk examples features

examples:
	poetry run python -m examples.aptos_token
	poetry run python -m examples.fee_payer_transfer_coin
	poetry run python -m examples.rotate_key
	poetry run python -m examples.read_aggregator
	poetry run python -m examples.secp256k1_ecdsa_transfer_coin
	poetry run python -m examples.simple_aptos_token
	poetry run python -m examples.simple_nft
	poetry run python -m examples.simulate_transfer_coin
	poetry run python -m examples.transfer_coin
	poetry run python -m examples.transfer_two_by_two
	poetry run python -m examples.multikey

examples_cli:
	poetry run python -m examples.hello_blockchain
	#	poetry run python -m examples.large_package_publisher CURRENTLY BROKEN -- OUT OF GAS
	poetry run python -m examples.multisig
	poetry run python -m examples.your_coin

integration_test:
	poetry run python -m unittest -b examples.integration_test

.PHONY: examples fmt lint test
