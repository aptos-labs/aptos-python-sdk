"""Unit tests for GeneralApi — ledger info, blocks, view functions, table items."""

import pytest
from aioresponses import aioresponses

from aptos_sdk_v2.api.general_api import GeneralApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.config import AptosConfig

NODE = "https://fullnode.devnet.aptoslabs.com/v1"


@pytest.fixture
def config():
    return AptosConfig()


@pytest.fixture
async def api(config):
    client = HttpClient(config)
    yield GeneralApi(config, client)
    await client.close()


class TestLedgerInfo:
    async def test_get_ledger_info(self, api):
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": 4, "epoch": "100"})
            result = await api.get_ledger_info()
            assert result["chain_id"] == 4
            assert result["epoch"] == "100"

    async def test_get_chain_id(self, api):
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": 4})
            result = await api.get_chain_id()
            assert result == 4
            assert isinstance(result, int)

    async def test_get_chain_id_string_value(self, api):
        """chain_id might come as a string from the API."""
        with aioresponses() as m:
            m.get(NODE, payload={"chain_id": "25"})
            result = await api.get_chain_id()
            assert result == 25


class TestBlocks:
    async def test_get_block_by_height(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/blocks/by_height/100",
                payload={"block_height": "100", "block_hash": "0xabc"},
            )
            result = await api.get_block_by_height(100)
            assert result["block_height"] == "100"

    async def test_get_block_by_height_with_transactions(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/blocks/by_height/100?with_transactions=true",
                payload={"block_height": "100", "transactions": [{"hash": "0x1"}]},
            )
            result = await api.get_block_by_height(100, with_transactions=True)
            assert "transactions" in result

    async def test_get_block_by_version(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/blocks/by_version/500",
                payload={"block_height": "50", "first_version": "500"},
            )
            result = await api.get_block_by_version(500)
            assert result["first_version"] == "500"

    async def test_get_block_by_version_with_transactions(self, api):
        with aioresponses() as m:
            m.get(
                f"{NODE}/blocks/by_version/500?with_transactions=true",
                payload={"block_height": "50", "transactions": []},
            )
            result = await api.get_block_by_version(500, with_transactions=True)
            assert "transactions" in result


class TestTableItem:
    async def test_get_table_item(self, api):
        handle = "0xdeadbeef"
        with aioresponses() as m:
            m.post(
                f"{NODE}/tables/{handle}/item",
                payload={"value": "42"},
            )
            result = await api.get_table_item(
                handle, key_type="address", value_type="u64", key="0x1"
            )
            assert result["value"] == "42"


class TestView:
    async def test_view_function(self, api):
        with aioresponses() as m:
            m.post(f"{NODE}/view", payload=["1000"])
            result = await api.view("0x1::coin", "balance", ["0x1::aptos_coin::AptosCoin"], ["0x1"])
            assert result == ["1000"]
            assert isinstance(result, list)
