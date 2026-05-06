"""Unit tests for FaucetApi — fund accounts on devnet/testnet."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.api.faucet_api import FaucetApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.types.account_address import AccountAddress

FAUCET = "https://faucet.devnet.aptoslabs.com"
ADDR = AccountAddress.from_str("0x1")


@pytest.fixture
def config():
    return AptosConfig()


@pytest.fixture
async def api(config):
    client = HttpClient(config)
    yield FaucetApi(config, client)
    await client.close()


class TestFaucetApi:
    async def test_fund_account(self, api):
        with aioresponses() as m:
            m.post(f"{FAUCET}/fund", payload={"txn_hashes": ["0xabc"]})
            result = await api.fund_account(ADDR, 100_000_000)
            assert result["txn_hashes"] == ["0xabc"]

    async def test_fund_account_address_as_string(self, api):
        """Verify address is converted to string in the JSON body."""
        with aioresponses() as m:
            m.post(f"{FAUCET}/fund", payload={"txn_hashes": ["0xdef"]})
            result = await api.fund_account(ADDR, 50_000)
            assert result["txn_hashes"] == ["0xdef"]
