"""Unit tests for FungibleAssetApi — FA balances and transfers."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.account.account import Account
from aptos_sdk_v2.api.fungible_asset_api import FungibleAssetApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.api.transaction_api import TransactionApi
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.types.account_address import AccountAddress

NODE = "https://fullnode.devnet.aptoslabs.com/v1"
ADDR = AccountAddress.from_str("0x1")
FA_ADDR = AccountAddress.from_str("0xa")


@pytest.fixture
def config():
    return AptosConfig()


@pytest.fixture
async def fa_api(config):
    client = HttpClient(config)
    txn_api = TransactionApi(config, client)
    yield FungibleAssetApi(config, client, txn_api)
    await client.close()


class TestBalance:
    async def test_balance(self, fa_api):
        with aioresponses() as m:
            m.post(f"{NODE}/view", payload=["2500"])
            result = await fa_api.balance(ADDR, FA_ADDR)
            assert result == 2500
            assert isinstance(result, int)


class TestTransfer:
    async def test_transfer(self, fa_api):
        sender = Account.generate()
        recipient = AccountAddress.from_str("0x2")
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{sender.address}",
                payload={"sequence_number": "0"},
            )
            m.get(NODE, payload={"chain_id": 4})
            m.post(f"{NODE}/transactions", payload={"hash": "0xfa_transfer"})
            result = await fa_api.transfer(sender, FA_ADDR, recipient, 1000)
            assert result == "0xfa_transfer"
