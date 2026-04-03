"""Faucet API — fund accounts on testnet/devnet."""

from __future__ import annotations

from typing import Any

from ..config import AptosConfig
from ..types.account_address import AccountAddress
from .http_client import HttpClient


class FaucetApi:
    """Fund accounts on testnet/devnet using the faucet."""

    __slots__ = ("_config", "_client")

    def __init__(self, config: AptosConfig, client: HttpClient) -> None:
        self._config = config
        self._client = client

    async def fund_account(
        self, address: AccountAddress, amount: int
    ) -> dict[str, Any]:
        """Fund an account with the specified amount of APT (in octas)."""
        url = f"{self._config.faucet_endpoint}/fund"
        return await self._client.post(
            url,
            json={
                "address": str(address),
                "amount": amount,
            },
        )
