"""Account API — query account info, resources, modules, and balances."""

from __future__ import annotations

from typing import Any

from ..config import AptosConfig
from ..types.account_address import AccountAddress
from .http_client import HttpClient


class AccountApi:
    """Account-related queries."""

    __slots__ = ("_config", "_client")

    def __init__(self, config: AptosConfig, client: HttpClient) -> None:
        self._config = config
        self._client = client

    async def get_info(self, address: AccountAddress) -> dict[str, Any]:
        url = f"{self._config.node_url}/accounts/{address}"
        return await self._client.get(url)

    async def get_sequence_number(self, address: AccountAddress) -> int:
        info = await self.get_info(address)
        return int(info["sequence_number"])

    async def get_balance(
        self, address: AccountAddress, coin_type: str = "0x1::aptos_coin::AptosCoin"
    ) -> int:
        resource = await self.get_resource(address, f"0x1::coin::CoinStore<{coin_type}>")
        return int(resource["data"]["coin"]["value"])

    async def get_resource(self, address: AccountAddress, resource_type: str) -> dict[str, Any]:
        url = f"{self._config.node_url}/accounts/{address}/resource/{resource_type}"
        return await self._client.get(url)

    async def get_resources(self, address: AccountAddress) -> list[dict[str, Any]]:
        url = f"{self._config.node_url}/accounts/{address}/resources"
        return await self._client.get(url)  # type: ignore[return-value]

    async def get_modules(self, address: AccountAddress) -> list[dict[str, Any]]:
        url = f"{self._config.node_url}/accounts/{address}/modules"
        return await self._client.get(url)  # type: ignore[return-value]
