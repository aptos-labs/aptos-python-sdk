"""Shared fixtures for integration tests."""

import pytest

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network


@pytest.fixture
def config():
    return AptosConfig(network=Network.DEVNET)


@pytest.fixture
async def aptos(config):
    async with Aptos(config) as client:
        yield client


@pytest.fixture
async def funded_account(aptos):
    """Create and fund a fresh account with 100M octas."""
    account = Account.generate()
    await aptos.faucet.fund_account(account.address, 100_000_000)
    return account
