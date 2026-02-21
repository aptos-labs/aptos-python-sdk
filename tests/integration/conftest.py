# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Shared fixtures for integration tests.

Network configuration is read from environment variables, defaulting to devnet.
Set APTOS_NODE_URL and APTOS_FAUCET_URL to point at a different network
(e.g. localnet at http://127.0.0.1:8080/v1 and http://127.0.0.1:8081).
"""

import os
from collections.abc import AsyncGenerator

import pytest

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient


@pytest.fixture(scope="module")
def node_url() -> str:
    return os.getenv("APTOS_NODE_URL", "https://api.devnet.aptoslabs.com/v1")


@pytest.fixture(scope="module")
def faucet_url() -> str:
    return os.getenv("APTOS_FAUCET_URL", "https://faucet.devnet.aptoslabs.com")


@pytest.fixture(scope="module")
def api_key() -> str | None:
    return os.getenv("API_KEY")


@pytest.fixture(scope="module")
def faucet_auth_token() -> str | None:
    return os.getenv("FAUCET_AUTH_TOKEN")


@pytest.fixture()
async def rest_client(node_url: str, api_key: str | None) -> AsyncGenerator[RestClient]:
    client = RestClient(node_url, api_key=api_key)
    yield client  # type: ignore[misc]
    await client.close()


@pytest.fixture()
async def faucet_client(
    faucet_url: str,
    rest_client: RestClient,
    faucet_auth_token: str | None,
) -> FaucetClient:
    return FaucetClient(faucet_url, rest_client, auth_token=faucet_auth_token)


@pytest.fixture()
async def funded_account(faucet_client: FaucetClient) -> Account:
    """Generate an account and fund it with 100 APT."""
    account = Account.generate()
    await faucet_client.fund_account(account.address, 100_000_000)
    return account
