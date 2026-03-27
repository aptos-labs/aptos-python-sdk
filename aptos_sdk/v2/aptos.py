"""Aptos facade — the primary entry point for the SDK."""

from __future__ import annotations

from .api.account_api import AccountApi
from .api.coin_api import CoinApi
from .api.faucet_api import FaucetApi
from .api.fungible_asset_api import FungibleAssetApi
from .api.general_api import GeneralApi
from .api.http_client import HttpClient
from .api.transaction_api import TransactionApi
from .config import AptosConfig


class Aptos:
    """
    Primary entry point for the Aptos Python SDK v2.

    Usage::

        async with Aptos(AptosConfig(network=Network.DEVNET)) as aptos:
            alice = Account.generate()
            await aptos.faucet.fund_account(alice.address, 100_000_000)
            balance = await aptos.coin.balance(alice.address)
    """

    __slots__ = (
        "_config",
        "_client",
        "_account",
        "_transaction",
        "_general",
        "_coin",
        "_fungible_asset",
        "_faucet",
    )

    def __init__(self, config: AptosConfig | None = None) -> None:
        self._config = config or AptosConfig()
        self._client = HttpClient(self._config)
        self._account: AccountApi | None = None
        self._transaction: TransactionApi | None = None
        self._general: GeneralApi | None = None
        self._coin: CoinApi | None = None
        self._fungible_asset: FungibleAssetApi | None = None
        self._faucet: FaucetApi | None = None

    async def __aenter__(self) -> Aptos:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.close()

    @property
    def account(self) -> AccountApi:
        if self._account is None:
            self._account = AccountApi(self._config, self._client)
        return self._account

    @property
    def transaction(self) -> TransactionApi:
        if self._transaction is None:
            self._transaction = TransactionApi(self._config, self._client)
        return self._transaction

    @property
    def general(self) -> GeneralApi:
        if self._general is None:
            self._general = GeneralApi(self._config, self._client)
        return self._general

    @property
    def coin(self) -> CoinApi:
        if self._coin is None:
            self._coin = CoinApi(self._config, self._client, self.transaction)
        return self._coin

    @property
    def fungible_asset(self) -> FungibleAssetApi:
        if self._fungible_asset is None:
            self._fungible_asset = FungibleAssetApi(self._config, self._client, self.transaction)
        return self._fungible_asset

    @property
    def faucet(self) -> FaucetApi:
        if self._faucet is None:
            self._faucet = FaucetApi(self._config, self._client)
        return self._faucet
