"""Unit tests for AccountApi — account info, resources, modules, balances."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.api.account_api import AccountApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.config import AptosConfig
from aptos_sdk_v2.types.account_address import AccountAddress

NODE = "https://fullnode.devnet.aptoslabs.com/v1"
ADDR = AccountAddress.from_str("0x1")


@pytest.fixture
def config():
    return AptosConfig()


@pytest.fixture
async def api(config):
    client = HttpClient(config)
    yield AccountApi(config, client)
    await client.close()


class TestAccountApi:
    async def test_get_info(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{ADDR}",
                payload={"sequence_number": "5", "authentication_key": "0xabc"},
            )
            result = await api.get_info(ADDR)
            assert result["sequence_number"] == "5"
            assert result["authentication_key"] == "0xabc"

    async def test_get_sequence_number(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{ADDR}",
                payload={"sequence_number": "42"},
            )
            result = await api.get_sequence_number(ADDR)
            assert result == 42
            assert isinstance(result, int)

    async def test_get_balance(self, api):
        with aioresponses() as m:
            m.post(
                f"{NODE}/view",
                payload=["1000000"],
            )
            result = await api.get_balance(ADDR)
            assert result == 1_000_000
            assert isinstance(result, int)

    async def test_get_balance_custom_coin(self, api):
        with aioresponses() as m:
            m.post(
                f"{NODE}/view",
                payload=["500"],
            )
            result = await api.get_balance(ADDR, coin_type="0xdead::my_coin::MyCoin")
            assert result == 500

    async def test_get_resource(self, api):
        resource_type = "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{ADDR}/resource/{resource_type}",
                payload={"type": resource_type, "data": {"coin": {"value": "100"}}},
            )
            result = await api.get_resource(ADDR, resource_type)
            assert result["type"] == resource_type

    async def test_get_resources(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{ADDR}/resources",
                payload=[{"type": "0x1::account::Account", "data": {}}],
            )
            result = await api.get_resources(ADDR)
            assert isinstance(result, list)
            assert len(result) == 1

    async def test_get_modules(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/accounts/{ADDR}/modules",
                payload=[{"bytecode": "0x...", "abi": {}}],
            )
            result = await api.get_modules(ADDR)
            assert isinstance(result, list)
            assert len(result) == 1
