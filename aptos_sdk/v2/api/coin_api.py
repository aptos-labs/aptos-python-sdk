"""Coin API — APT and custom coin transfers and balances."""

from __future__ import annotations

from ..account.account import Account
from ..bcs import Serializer
from ..config import AptosConfig
from ..transactions.payload import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from ..types.account_address import AccountAddress
from ..types.type_tag import StructTag, TypeTag
from .http_client import HttpClient
from .transaction_api import TransactionApi

APT_COIN_TYPE = "0x1::aptos_coin::AptosCoin"


class CoinApi:
    """Coin transfer and balance operations."""

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
        recipient: AccountAddress,
        amount: int,
        *,
        coin_type: str = APT_COIN_TYPE,
    ) -> str:
        """Transfer coins and return the transaction hash."""
        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str(coin_type))],
            [
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
        *,
        coin_type: str = APT_COIN_TYPE,
    ) -> int:
        """Get the balance of a coin type for an address using a view function."""
        result = await self._client.post_view(
            f"{self._config.node_url}/view",
            json={
                "function": "0x1::coin::balance",
                "type_arguments": [coin_type],
                "arguments": [str(address)],
            },
        )
        return int(result[0])
