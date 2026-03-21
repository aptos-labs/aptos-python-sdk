"""Unit tests for CoinApi — coin balances and transfers."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.account.account import Account
from aptos_sdk_v2.api.coin_api import CoinApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.api.transaction_api import TransactionApi
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.types.account_address import AccountAddress

NODE = "https://fullnode.devnet.aptoslabs.com/v1"
ADDR = AccountAddress.from_str("0x1")


@pytest.fixture
def config():
    return AptosConfig()


@pytest.fixture
async def coin_api(config):
    client = HttpClient(config)
    txn_api = TransactionApi(config, client)
    yield CoinApi(config, client, txn_api)
    await client.close()


class TestBalance:
    async def test_balance_default_apt(self, coin_api):
        with aioresponses() as m:
            m.post(f"{NODE}/view", payload=["5000000"])
            result = await coin_api.balance(ADDR)
            assert result == 5_000_000
            assert isinstance(result, int)

    async def test_balance_custom_coin(self, coin_api):
        with aioresponses() as m:
            m.post(f"{NODE}/view", payload=["100"])
            result = await coin_api.balance(ADDR, coin_type="0xdead::my::Coin")
            assert result == 100


class TestTransfer:
    async def test_transfer(self, coin_api):
        sender = Account.generate()
        recipient = AccountAddress.from_str("0x2")
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{sender.address}",
                payload={"sequence_number": "0"},
            )
            m.get(NODE, payload={"chain_id": 4})
            m.post(f"{NODE}/transactions", payload={"hash": "0xtransfer"})
            result = await coin_api.transfer(sender, recipient, 1000)
            assert result == "0xtransfer"

    async def test_transfer_custom_coin(self, coin_api):
        sender = Account.generate()
        recipient = AccountAddress.from_str("0x3")
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{sender.address}",
                payload={"sequence_number": "5"},
            )
            m.get(NODE, payload={"chain_id": 4})
            m.post(f"{NODE}/transactions", payload={"hash": "0xcustom"})
            result = await coin_api.transfer(sender, recipient, 500, coin_type="0xdead::my::Coin")
            assert result == "0xcustom"
