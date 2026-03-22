"""Fungible Asset API — FA transfers and balances."""

from __future__ import annotations

from typing import Any

from ..account.account import Account
from ..bcs import Serializer
from ..config import AptosConfig
from ..transactions.payload import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from ..types.account_address import AccountAddress
from .http_client import HttpClient
from .transaction_api import TransactionApi


class FungibleAssetApi:
    """Fungible asset transfer and balance operations."""

    __slots__ = ("_config", "_client", "_transaction")

    def __init__(
        self, config: AptosConfig, client: HttpClient, transaction: TransactionApi
    ) -> None:
        self._config = config
        self._client = client
        self._transaction = transaction

    async def transfer(
        self,
        sender: Account,
        fa_address: AccountAddress,
        recipient: AccountAddress,
        amount: int,
    ) -> str:
        """Transfer a fungible asset and return the transaction hash."""
        payload = EntryFunction.natural(
            "0x1::primary_fungible_store",
            "transfer",
            [],
            [
                TransactionArgument(fa_address, Serializer.struct),
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )
        raw_txn = await self._transaction.build(
            sender=sender.address,
            payload=TransactionPayload(payload),
        )
        return await self._transaction.sign_and_submit(raw_txn, sender)

    async def balance(
        self,
        address: AccountAddress,
        fa_address: AccountAddress,
    ) -> int:
        """Get the balance of a fungible asset for an address."""
        result: Any = await self._client.post(
            f"{self._config.node_url}/view",
            json={
                "function": "0x1::primary_fungible_store::balance",
                "type_arguments": [],
                "arguments": [str(address), str(fa_address)],
            },
        )
        return int(result[0])
