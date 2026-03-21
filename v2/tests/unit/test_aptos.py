"""Unit tests for Aptos facade — wiring, lazy properties, context manager."""

from unittest.mock import AsyncMock, patch

import pytest

from aptos_sdk_v2.api.account_api import AccountApi
from aptos_sdk_v2.api.coin_api import CoinApi
from aptos_sdk_v2.api.faucet_api import FaucetApi
from aptos_sdk_v2.api.fungible_asset_api import FungibleAssetApi
from aptos_sdk_v2.api.general_api import GeneralApi
from aptos_sdk_v2.api.http_client import HttpClient
from aptos_sdk_v2.api.transaction_api import TransactionApi
from aptos_sdk_v2.aptos import Aptos
from aptos_sdk_v2.config import AptosConfig, Network


class TestInit:
    def test_default_config(self):
        aptos = Aptos()
        assert aptos._config.network == Network.DEVNET
        assert isinstance(aptos._client, HttpClient)

    def test_custom_config(self):
        config = AptosConfig(network=Network.TESTNET, api_key="key123")
        aptos = Aptos(config)
        assert aptos._config.network == Network.TESTNET
        assert aptos._config.api_key == "key123"

    def test_none_config_uses_default(self):
        aptos = Aptos(None)
        assert aptos._config.network == Network.DEVNET


class TestLazyProperties:
    def test_account_property(self):
        aptos = Aptos()
        assert aptos._account is None
        account = aptos.account
        assert isinstance(account, AccountApi)

    def test_transaction_property(self):
        aptos = Aptos()
        assert aptos._transaction is None
        txn = aptos.transaction
        assert isinstance(txn, TransactionApi)

    def test_general_property(self):
        aptos = Aptos()
        assert aptos._general is None
        general = aptos.general
        assert isinstance(general, GeneralApi)

    def test_coin_property(self):
        aptos = Aptos()
        assert aptos._coin is None
        coin = aptos.coin
        assert isinstance(coin, CoinApi)

    def test_fungible_asset_property(self):
        aptos = Aptos()
        assert aptos._fungible_asset is None
        fa = aptos.fungible_asset
        assert isinstance(fa, FungibleAssetApi)

    def test_faucet_property(self):
        aptos = Aptos()
        assert aptos._faucet is None
        faucet = aptos.faucet
        assert isinstance(faucet, FaucetApi)


class TestCaching:
    def test_repeated_access_returns_same_instance(self):
        aptos = Aptos()
        assert aptos.account is aptos.account
        assert aptos.transaction is aptos.transaction
        assert aptos.general is aptos.general
        assert aptos.coin is aptos.coin
        assert aptos.fungible_asset is aptos.fungible_asset
        assert aptos.faucet is aptos.faucet

    def test_coin_uses_same_transaction_api(self):
        """CoinApi receives the same TransactionApi instance via aptos.transaction."""
        aptos = Aptos()
        coin = aptos.coin
        assert coin._transaction is aptos.transaction


class TestContextManager:
    async def test_async_with(self):
        async with Aptos() as aptos:
            assert isinstance(aptos, Aptos)
            assert isinstance(aptos._client, HttpClient)

    async def test_close_delegates_to_client(self):
        aptos = Aptos()
        with patch.object(HttpClient, "close", new_callable=AsyncMock) as mock_close:
            await aptos.close()
            mock_close.assert_awaited_once()

    async def test_context_manager_calls_close(self):
        aptos = Aptos()
        with patch.object(HttpClient, "close", new_callable=AsyncMock) as mock_close:
            async with aptos:
                pass
            mock_close.assert_awaited_once()
