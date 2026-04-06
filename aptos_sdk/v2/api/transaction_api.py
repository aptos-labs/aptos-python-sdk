"""Transaction API — build, simulate, sign, submit, and wait for transactions."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ..account.account import Account
from ..bcs import Serializer
from ..config import AptosConfig
from ..crypto.keys import PublicKey
from ..errors import TransactionFailedError, TransactionTimeoutError
from ..transactions.payload import (
    EntryFunction,
    Script,
    TransactionExecutable,
    TransactionExtraConfig,
    TransactionInnerPayload,
    TransactionPayload,
)
from ..transactions.raw_transaction import RawTransaction
from ..transactions.signed_transaction import SignedTransaction
from ..types.account_address import AccountAddress
from .http_client import HttpClient


class TransactionApi:
    """Full transaction pipeline: build -> simulate -> sign -> submit -> wait."""

    __slots__ = ("_config", "_client", "_chain_id")

    def __init__(self, config: AptosConfig, client: HttpClient) -> None:
        self._config = config
        self._client = client
        self._chain_id: int | None = None

    async def _get_chain_id(self) -> int:
        if self._chain_id is None:
            info = await self._client.get(self._config.node_url)
            self._chain_id = int(info["chain_id"])
        return self._chain_id

    async def build(
        self,
        sender: AccountAddress,
        payload: TransactionPayload,
        *,
        sequence_number: int | None = None,
        max_gas_amount: int | None = None,
        gas_unit_price: int | None = None,
        expiration_timestamps_secs: int | None = None,
        replay_protection_nonce: int | None = None,
    ) -> RawTransaction:
        """Build a RawTransaction, fetching sequence number and chain ID if needed.

        If replay_protection_nonce is provided, the payload is wrapped in a
        TransactionInnerPayload for orderless transaction support (AIP-123/129).
        The sequence_number is set to 0 (ignored on-chain for orderless txns).
        """
        if replay_protection_nonce is not None:
            if not isinstance(payload.value, (Script, EntryFunction)):
                got = type(payload.value).__name__
                msg = f"Orderless transactions require Script or EntryFunction payload, got {got}"
                raise TypeError(msg)
            inner = TransactionInnerPayload(
                executable=TransactionExecutable(payload.value),
                extra_config=TransactionExtraConfig(
                    replay_protection_nonce=replay_protection_nonce,
                ),
            )
            payload = TransactionPayload(inner)
            sequence_number = sequence_number if sequence_number is not None else 0

        if sequence_number is None:
            info = await self._client.get(f"{self._config.node_url}/accounts/{sender}")
            sequence_number = int(info["sequence_number"])

        chain_id = await self._get_chain_id()

        if expiration_timestamps_secs is None:
            expiration_timestamps_secs = int(time.time()) + self._config.expiration_ttl

        return RawTransaction(
            sender=sender,
            sequence_number=sequence_number,
            payload=payload,
            max_gas_amount=max_gas_amount or self._config.max_gas_amount,
            gas_unit_price=gas_unit_price or self._config.gas_unit_price,
            expiration_timestamps_secs=expiration_timestamps_secs,
            chain_id=chain_id,
        )

    async def simulate(
        self,
        raw_txn: RawTransaction,
        public_key: PublicKey,
    ) -> list[dict[str, Any]]:
        """Simulate a transaction without executing it on-chain."""
        auth = raw_txn.sign_simulated(public_key)
        signed = SignedTransaction(raw_txn, auth)
        ser = Serializer()
        signed.serialize(ser)
        url = f"{self._config.node_url}/transactions/simulate"
        return await self._client.post_bcs_for_simulation(url, ser.output())

    def sign(self, raw_txn: RawTransaction, account: Account) -> SignedTransaction:
        """Sign a raw transaction (synchronous — no network call)."""
        auth = raw_txn.sign(account.private_key)
        return SignedTransaction(raw_txn, auth)

    async def submit(self, signed_txn: SignedTransaction) -> str:
        """Submit a signed transaction and return its hash."""
        ser = Serializer()
        signed_txn.serialize(ser)
        url = f"{self._config.node_url}/transactions"
        result = await self._client.post_bcs(url, ser.output())
        return result["hash"]

    async def wait_for_transaction(self, txn_hash: str) -> dict[str, Any]:
        """Wait for a transaction to be committed and return its result."""
        deadline = time.time() + self._config.transaction_wait_secs

        while time.time() < deadline:
            try:
                result = await self._client.get(
                    f"{self._config.node_url}/transactions/by_hash/{txn_hash}"
                )
                if result.get("type") == "pending_transaction":
                    await asyncio.sleep(1)
                    continue
                if not result.get("success", False):
                    raise TransactionFailedError(txn_hash, result.get("vm_status", "unknown"))
                return result
            except Exception as e:
                if isinstance(e, TransactionFailedError):
                    raise
                await asyncio.sleep(1)

        raise TransactionTimeoutError(txn_hash)

    async def sign_and_submit(self, raw_txn: RawTransaction, account: Account) -> str:
        """Sign and submit a transaction, returning the hash."""
        signed = self.sign(raw_txn, account)
        return await self.submit(signed)

    async def sign_submit_and_wait(
        self, raw_txn: RawTransaction, account: Account
    ) -> dict[str, Any]:
        """Sign, submit, and wait for a transaction."""
        txn_hash = await self.sign_and_submit(raw_txn, account)
        return await self.wait_for_transaction(txn_hash)

    async def get_by_hash(self, txn_hash: str) -> dict[str, Any]:
        return await self._client.get(f"{self._config.node_url}/transactions/by_hash/{txn_hash}")

    async def get_by_version(self, version: int) -> dict[str, Any]:
        return await self._client.get(f"{self._config.node_url}/transactions/by_version/{version}")
