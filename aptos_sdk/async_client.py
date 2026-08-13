# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json as _json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import aiohttp
import httpx
import python_graphql_client

from .account import Account
from .account_address import AccountAddress
from .authenticator import Authenticator, MultiAgentAuthenticator
from .bcs import Serializer
from .metadata import Metadata
from .transactions import (
    EntryFunction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import StructTag, TypeTag

U64_MAX = 18446744073709551615

# Transient REST / faucet failures that are safe to retry. SEQUENCE_NUMBER_*
# shows up when a faucet minter races concurrent mint transactions.
_FAUCET_RETRY_MARKERS = (
    "SEQUENCE_NUMBER_TOO_OLD",
    "SEQUENCE_NUMBER_TOO_NEW",
    "TRANSACTION_EXPIRED",
)


def _retryable_http_status(status: int) -> bool:
    return status == 429 or status >= 500


def _retryable_faucet_error(status: int, body: str) -> bool:
    if _retryable_http_status(status):
        return True
    if status >= 400:
        return any(marker in body for marker in _FAUCET_RETRY_MARKERS)
    return False


@dataclass
class ClientConfig:
    """Common configuration for clients, particularly for submitting transactions"""

    expiration_ttl: int = 600
    gas_unit_price: int = 100
    max_gas_amount: int = 1_000_000
    transaction_wait_in_seconds: int = 20
    http2: bool = True
    api_key: Optional[str] = None
    http_retries: int = 3


class IndexerClient:
    """A wrapper around the Aptos Indexer Service on Hasura."""

    client: python_graphql_client.GraphqlClient

    def __init__(self, indexer_url: str, bearer_token: Optional[str] = None):
        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self.client = python_graphql_client.GraphqlClient(endpoint=indexer_url, headers=headers)

    async def query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a GraphQL query against the indexer.

        Raises:
            IndexerError: If the indexer is unreachable, times out, returns a
                non-JSON response (e.g. a rate-limit HTML body), or includes a
                top-level ``errors`` array. Other exception types — programming
                errors, ``KeyboardInterrupt``, etc. — propagate unchanged.
        """
        try:
            result = await self.client.execute_async(query, variables)
        except (
            aiohttp.ClientError,  # network / HTTP / decode errors from aiohttp
            asyncio.TimeoutError,
            _json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            raise IndexerError(f"indexer query failed: {exc}") from exc
        if isinstance(result, dict) and result.get("errors"):
            raise IndexerError(f"indexer returned errors: {result['errors']}")
        return result


class RestClient:
    """A wrapper around the Aptos-core Rest API"""

    _chain_id: Optional[int]
    client: httpx.AsyncClient
    client_config: ClientConfig
    base_url: str

    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
        self.base_url = base_url
        # Default limits
        limits = httpx.Limits()
        # Default timeouts but do not set a pool timeout, since the idea is that jobs will wait as
        # long as progress is being made.
        timeout = httpx.Timeout(60.0, pool=None)
        # Default headers
        headers = {Metadata.APTOS_HEADER: Metadata.get_aptos_header_val()}
        self.client = httpx.AsyncClient(
            http2=client_config.http2,
            limits=limits,
            timeout=timeout,
            headers=headers,
        )
        self.client_config = client_config
        self._chain_id = None
        if client_config.api_key:
            self.client.headers["Authorization"] = f"Bearer {client_config.api_key}"

    async def close(self) -> None:
        """Close the underlying HTTP client connection."""
        await self.client.aclose()

    async def chain_id(self) -> int:
        """Return the chain ID, fetching from the node if not yet cached."""
        if not self._chain_id:
            info = await self.info()
            self._chain_id = int(info["chain_id"])
        return self._chain_id

    #
    # Account accessors
    #

    async def account(
        self, account_address: AccountAddress, ledger_version: Optional[int] = None
    ) -> Dict[str, str]:
        """
        Fetch the authentication key and the sequence number for an account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: The authentication key and sequence number for the specified address.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_balance(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
        coin_type: Optional[str] = None,
    ) -> int:
        """
        Fetch the Aptos coin balance associated with the account.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :param coin_type: Coin type to get balance for, defaults to "0x1::aptos_coin::AptosCoin".
        :return: The Aptos coin balance associated with the account
        """
        coin_type = coin_type or "0x1::aptos_coin::AptosCoin"
        result = await self.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str(coin_type))],
            [TransactionArgument(account_address, Serializer.struct)],
            ledger_version,
        )
        return int(result[0])

    async def account_sequence_number(
        self, account_address: AccountAddress, ledger_version: Optional[int] = None
    ) -> int:
        """
        Fetch the current sequence number for an account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: The current sequence number for the specified address.
        """
        try:
            account_res = await self.account(account_address, ledger_version)
            return int(account_res["sequence_number"])
        except ApiError as ae:
            if ae.status_code != 404:
                raise
            return 0

    async def account_resource(
        self,
        account_address: AccountAddress,
        resource_type: str,
        ledger_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves an individual resource from a given account and at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param resource_type: Name of struct to retrieve e.g. 0x1::account::Account.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: An individual resource from a given account and at a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/resource/{resource_type}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code == 404:
            raise ResourceNotFound(resource_type, resource_type)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_resources(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves all account resources for a given account and a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: All account resources for a given account and a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/resources",
            params={"ledger_version": ledger_version},
        )
        if response.status_code == 404:
            raise AccountNotFound(f"{account_address}", account_address)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)
        return response.json()

    async def account_module(
        self,
        account_address: AccountAddress,
        module_name: str,
        ledger_version: Optional[int] = None,
    ) -> dict:
        """
        Retrieves an individual module from a given account and at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param module_name: Name of module to retrieve e.g. 'coin'
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :return: An individual module from a given account and at a specific ledger version
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/module/{module_name}",
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def account_modules(
        self,
        account_address: AccountAddress,
        ledger_version: Optional[int] = None,
        limit: Optional[int] = None,
        start: Optional[str] = None,
    ) -> dict:
        """
        Retrieves all account modules' bytecode for a given account at a specific ledger version.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :param limit: Max number of account modules to retrieve. If not provided, defaults to default page size.
        :param start: Cursor specifying where to start for pagination.
        :return: All account modules' bytecode for a given account at a specific ledger version.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/modules",
            params={
                "ledger_version": ledger_version,
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code == 404:
            raise AccountNotFound(f"{account_address}", account_address)
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    #
    # Blocks
    #

    async def blocks_by_height(
        self,
        block_height: int,
        with_transactions: bool = False,
    ) -> dict:
        """
        Fetch the transactions in a block and the corresponding block information.

        Transactions are limited by max default transactions size. If not all transactions are present, the user will
        need to query for the rest of the transactions via the get transactions API. If the block is pruned, it will
        return a 410.

        :param block_height: Block height to lookup. Starts at 0.
        :param with_transactions: If set to true, include all transactions in the block.
        :returns: Block information.
        """
        response = await self._get(
            endpoint=f"blocks/by_height/{block_height}",
            params={
                "with_transactions": with_transactions,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text}", response.status_code)

        return response.json()

    async def blocks_by_version(
        self,
        version: int,
        with_transactions: bool = False,
    ) -> dict:
        """
        Fetch the transactions in a block and the corresponding block information, given a version in the block.

        Transactions are limited by max default transactions size. If not all transactions are present, the user will
        need to query for the rest of the transactions via the get transactions API. If the block is pruned, it will
        return a 410.

        :param version: Ledger version to lookup block information for.
        :param with_transactions: If set to true, include all transactions in the block.
        :returns: Block information.
        """
        response = await self._get(
            endpoint=f"blocks/by_version/{version}",
            params={
                "with_transactions": with_transactions,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text}", response.status_code)

        return response.json()

    #
    # Events
    #

    async def event_by_creation_number(
        self,
        account_address: AccountAddress,
        creation_number: int,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve events corresponding to an account address and creation number indicating the event type emitted
        to that account.

        Creation numbers are monotonically increasing for each account address.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param creation_number: Creation number corresponding to the event stream originating from the given account.
        :param limit: Max number of events to retrieve. If not provided, defaults to default page size.
        :param start: Starting sequence number of events.If unspecified, by default will retrieve the most recent.
        :returns: Events corresponding to an account address and creation number indicating the event type emitted
        to that account.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/events/{creation_number}",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def events_by_event_handle(
        self,
        account_address: AccountAddress,
        event_handle: str,
        field_name: str,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve events corresponding to an account address, event handle (struct name) and field name.

        :param account_address: Address of the account, with or without a '0x' prefix.
        :param event_handle: Name of struct to lookup event handle e.g., '0x1::account::Account'.
        :param field_name: Name of field to lookup event handle e.g., 'withdraw_events'
        :param limit: Max number of events to retrieve. If not provided, defaults to default page size.
        :param start: Starting sequence number of events.If unspecified, by default will retrieve the most recent.
        :returns: Events corresponding to the provided account address, event handle and field name.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/events/{event_handle}/{field_name}",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(f"{response.text} - {account_address}", response.status_code)

        return response.json()

    async def current_timestamp(self) -> float:
        info = await self.info()
        return float(info["ledger_timestamp"]) / 1_000_000

    async def get_table_item(
        self,
        handle: str,
        key_type: str,
        value_type: str,
        key: Any,
        ledger_version: Optional[int] = None,
    ) -> Any:
        """
        Get a table item at a specific ledger version from the table identified by the handle and
        the key payload.

        :param handle: Table handle hex encoded 32-byte string.
        :param key_type: String representation of a MoveType for the table key.
        :param value_type: String representation of a MoveType for the table value.
        :param key: The value of the table key.
        :param ledger_version: Ledger version to get the table item. If not provided, defaults to latest.
        :returns: The table item value rendered in JSON.
        """
        response = await self._post(
            endpoint=f"tables/{handle}/item",
            data={
                "key_type": key_type,
                "value_type": value_type,
                "key": key,
            },
            params={"ledger_version": ledger_version},
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def aggregator_value(
        self,
        account_address: AccountAddress,
        resource_type: str,
        aggregator_path: List[str],
    ) -> int:
        """Read an ``OptionalAggregator`` value from an account resource.

        Aptos ``0x1::optional_aggregator::OptionalAggregator`` stores either a
        parallelizable aggregator (table handle + key) or a plain integer. Local
        networks typically use the integer variant for APT supply; mainnet and
        devnet use the aggregator variant. This helper accepts both so callers
        do not need to know which representation the chain is using.

        :param account_address: Account that holds the resource.
        :param resource_type: Move resource type, e.g. CoinInfo.
        :param aggregator_path: Field names from the resource root to the
            ``OptionalAggregator``, e.g. ``["supply"]``. The list is not mutated.
        """
        source = await self.account_resource(account_address, resource_type)
        source_data = data = source["data"]

        for key in aggregator_path:
            if key not in data:
                raise ApiError(f"aggregator path not found in data: {source_data}", source_data)
            data = data[key]

        if "vec" not in data or len(data["vec"]) != 1:
            raise ApiError(f"aggregator not found in data: {source_data}", source_data)
        optional = data["vec"][0]

        aggregator = optional.get("aggregator", {}).get("vec", [])
        if len(aggregator) == 1 and "handle" in aggregator[0] and "key" in aggregator[0]:
            handle = aggregator[0]["handle"]
            key = aggregator[0]["key"]
            return int(await self.get_table_item(handle, "address", "u128", key))

        integer = optional.get("integer", {}).get("vec", [])
        if len(integer) == 1 and "value" in integer[0]:
            return int(integer[0]["value"])

        raise ApiError(f"aggregator not found in data: {source_data}", source_data)

    #
    # Ledger accessors
    #

    async def info(self) -> Dict[str, str]:
        async def send() -> httpx.Response:
            return await self.client.get(self.base_url)

        response = await self._send_with_retry(send)
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def wait_until_ready(self, timeout_secs: float = 60.0) -> None:
        """Poll ledger info until the node responds successfully.

        Used by integration tests to wait out localnet startup races instead of
        failing on the first connection error.
        """
        deadline = time.monotonic() + timeout_secs
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            try:
                await self.info()
                return
            except (ApiError, httpx.RequestError) as exc:
                last_error = exc
            await asyncio.sleep(0.5)
        raise TimeoutError(f"node not ready after {timeout_secs}s: {last_error}")

    #
    # Transactions
    #

    async def simulate_bcs_transaction(
        self,
        signed_transaction: SignedTransaction,
        estimate_gas_usage: bool = False,
    ) -> Dict[str, Any]:
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        params = {}
        if estimate_gas_usage:
            params = {
                "estimate_gas_unit_price": "true",
                "estimate_max_gas_amount": "true",
            }

        response = await self.client.post(
            f"{self.base_url}/transactions/simulate",
            params=params,
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    async def simulate_transaction(
        self,
        transaction: RawTransaction,
        sender: Account,
        estimate_gas_usage: bool = False,
    ) -> Dict[str, Any]:
        # Note that simulated transactions are not signed and have all 0 signatures!
        authenticator = sender.sign_simulated_transaction(transaction)
        return await self.simulate_bcs_transaction(
            signed_transaction=SignedTransaction(transaction, authenticator),
            estimate_gas_usage=estimate_gas_usage,
        )

    async def submit_bcs_transaction(self, signed_transaction: SignedTransaction) -> str:
        """
        Submit a BCS-serialized signed transaction to the blockchain.

        :param signed_transaction: A BCS-serialized signed transaction.
        :returns: The hash of the submitted transaction.
        """
        headers = {"Content-Type": "application/x.aptos.signed_transaction+bcs"}
        response = await self.client.post(
            f"{self.base_url}/transactions",
            headers=headers,
            content=signed_transaction.bytes(),
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["hash"]

    async def submit_and_wait_for_bcs_transaction(
        self, signed_transaction: SignedTransaction
    ) -> Dict[str, Any]:
        txn_hash = await self.submit_bcs_transaction(signed_transaction)
        await self.wait_for_transaction(txn_hash)
        return await self.transaction_by_hash(txn_hash)

    async def transaction_pending(self, txn_hash: str) -> bool:
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        # TODO(@davidiw): consider raising a different error here, since this is an ambiguous state
        if response.status_code == 404:
            return True
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()["type"] == "pending_transaction"

    async def wait_for_transaction(self, txn_hash: str) -> None:
        """
        Waits up to the duration specified in client_config for a transaction to move past pending
        state.

        :param txn_hash: The hash of the transaction to wait for.
        :raises TransactionTimeout: If the transaction does not complete within the configured timeout.
        :raises TransactionFailed: If the transaction completes but is not successful.
        """

        count = 0
        while await self.transaction_pending(txn_hash):
            if count >= self.client_config.transaction_wait_in_seconds:
                raise TransactionTimeout(f"transaction {txn_hash} timed out")
            await asyncio.sleep(1)
            count += 1

        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        if "success" not in response.json() or not response.json()["success"]:
            raise TransactionFailed(f"{response.text} - {txn_hash}")

    async def account_transaction_sequence_number_status(
        self, address: AccountAddress, sequence_number: int
    ) -> bool:
        """Retrieve the state of a transaction by account and sequence number."""
        response = await self._get(
            endpoint=f"accounts/{address}/transactions",
            params={
                "limit": 1,
                "start": sequence_number,
            },
        )
        if response.status_code >= 400:
            logging.warning(f"Failed to retrieve account transactions: {response}")
            raise ApiError(response.text, response.status_code)
        data = response.json()
        return len(data) == 1 and data[0]["type"] != "pending_transaction"

    async def transaction_by_hash(self, txn_hash: str) -> Dict[str, Any]:
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def transaction_by_version(self, version: int) -> Dict[str, Any]:
        response = await self._get(endpoint=f"transactions/by_version/{version}")
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def transactions_by_account(
        self,
        account_address: AccountAddress,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieves on-chain committed transactions from an account.

        If the start version is too far in the past, a 410 will be returned. If no start version is given, it will
        start at version 0.

        To retrieve a pending transaction, use /transactions/by_hash.

        :param account_address: Address of account with or without a 0x prefix.
        :param limit: Max number of transactions to retrieve. If not provided, defaults to default page size.
        :param start: Account sequence number to start list of transactions. Defaults to latest transactions.
        :returns: List of on-chain committed transactions from the specified account.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/transactions",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    async def transactions(
        self,
        limit: Optional[int] = None,
        start: Optional[int] = None,
    ) -> List[dict]:
        """
        Retrieve on-chain committed transactions.

        The page size and start ledger version can be provided to get a specific sequence of transactions. If the
        version has been pruned, then a 410 will be returned. To retrieve a pending transaction,
        use /transactions/by_hash.

        :param limit: Max number of transactions to retrieve. If not provided, defaults to default page size.
        :param start: Ledger version to start list of transactions. Defaults to showing the latest transactions.
        """
        response = await self._get(
            endpoint="transactions",
            params={
                "limit": limit,
                "start": start,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.json()

    #
    # Transaction helpers
    #

    async def create_multi_agent_bcs_transaction(
        self,
        sender: Account,
        secondary_accounts: List[Account],
        payload: TransactionPayload,
    ) -> SignedTransaction:
        raw_transaction = MultiAgentRawTransaction(
            RawTransaction(
                sender.address(),
                await self.account_sequence_number(sender.address()),
                payload,
                self.client_config.max_gas_amount,
                self.client_config.gas_unit_price,
                int(time.time()) + self.client_config.expiration_ttl,
                await self.chain_id(),
            ),
            [x.address() for x in secondary_accounts],
        )

        authenticator = Authenticator(
            MultiAgentAuthenticator(
                sender.sign_transaction(raw_transaction),
                [
                    (
                        x.address(),
                        x.sign_transaction(raw_transaction),
                    )
                    for x in secondary_accounts
                ],
            )
        )

        return SignedTransaction(raw_transaction.inner(), authenticator)

    async def create_bcs_transaction(
        self,
        sender: Account | AccountAddress,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> RawTransaction:
        """
        Create a raw transaction for BCS submission.

        :param sender: The sending Account or AccountAddress.
        :param payload: The transaction payload.
        :param sequence_number: Optional sequence number; fetched from chain if not provided.
        :returns: A RawTransaction ready to be signed.
        """
        if isinstance(sender, Account):
            sender_address = sender.address()
        else:
            sender_address = sender

        sequence_number = (
            sequence_number
            if sequence_number is not None
            else await self.account_sequence_number(sender_address)
        )
        return RawTransaction(
            sender_address,
            sequence_number,
            payload,
            self.client_config.max_gas_amount,
            self.client_config.gas_unit_price,
            int(time.time()) + self.client_config.expiration_ttl,
            await self.chain_id(),
        )

    async def create_bcs_signed_transaction(
        self,
        sender: Account,
        payload: TransactionPayload,
        sequence_number: Optional[int] = None,
    ) -> SignedTransaction:
        raw_transaction = await self.create_bcs_transaction(sender, payload, sequence_number)
        authenticator = sender.sign_transaction(raw_transaction)
        return SignedTransaction(raw_transaction, authenticator)

    #
    # Transaction wrappers
    #

    # :!:>bcs_transfer
    async def bcs_transfer(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer APT from sender to recipient.

        :param sender: The sending Account.
        :param recipient: The recipient's AccountAddress.
        :param amount: Amount of APT (in octas) to transfer.
        :param sequence_number: Optional sequence number override.
        :returns: The hash of the submitted transaction.
        """
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_transaction(signed_transaction)  # <:!:bcs_transfer

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: Optional[int] = None,
    ) -> str:
        """
        Transfer coins of a specific type from sender to recipient.

        :param sender: The sending Account.
        :param recipient: The recipient's AccountAddress.
        :param coin_type: Fully qualified coin type (e.g. ``0x1::aptos_coin::AptosCoin``).
        :param amount: Amount of coins to transfer in the coin's base unit.
        :param sequence_number: Optional sequence number override.
        :returns: The hash of the submitted transaction.
        """
        transaction_arguments = [
            TransactionArgument(recipient, Serializer.struct),
            TransactionArgument(amount, Serializer.u64),
        ]

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer_coins",
            [TypeTag(StructTag.from_str(coin_type))],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            sender, TransactionPayload(payload), sequence_number=sequence_number
        )
        return await self.submit_bcs_transaction(signed_transaction)

    async def transfer_object(
        self, owner: Account, object: AccountAddress, to: AccountAddress
    ) -> str:
        transaction_arguments = [
            TransactionArgument(object, Serializer.struct),
            TransactionArgument(to, Serializer.struct),
        ]

        payload = EntryFunction.natural(
            "0x1::object",
            "transfer_call",
            [],
            transaction_arguments,
        )

        signed_transaction = await self.create_bcs_signed_transaction(
            owner,
            TransactionPayload(payload),
        )
        return await self.submit_bcs_transaction(signed_transaction)

    async def view(
        self,
        function: str,
        type_arguments: List[str],
        arguments: List[str],
        ledger_version: Optional[int] = None,
    ) -> bytes:
        """
        Execute a view Move function with the given parameters and return its execution result.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param function: Entry function id is string representation of an entry function defined on-chain.
        :param type_arguments: Type arguments of the function.
        :param arguments: Arguments of the function.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :returns: Execution result.
        """
        response = await self._post(
            endpoint="view",
            params={
                "ledger_version": ledger_version,
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            data={
                "function": function,
                "type_arguments": type_arguments,
                "arguments": arguments,
            },
        )
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)

        return response.content

    async def view_bcs_payload(
        self,
        module: str,
        function: str,
        ty_args: List[TypeTag],
        args: List[TransactionArgument],
        ledger_version: Optional[int] = None,
    ) -> Any:
        """
        Execute a view Move function with the given parameters and return its execution result.
        Note, this differs from `view` as in this expects bcs compatible inputs and submits the
        view function in bcs format. This is convenient for clients that execute functions in
        transactions similar to view functions.

        The Aptos nodes prune account state history, via a configurable time window. If the requested ledger version
        has been pruned, the server responds with a 410.

        :param function: Entry function id is string representation of an entry function defined on-chain.
        :param type_arguments: Type arguments of the function.
        :param arguments: Arguments of the function.
        :param ledger_version: Ledger version to get state of account. If not provided, it will be the latest version.
        :returns: Execution result.
        """
        request = f"{self.base_url}/view"
        if ledger_version:
            request = f"{request}?ledger_version={ledger_version}"

        view_data = EntryFunction.natural(module, function, ty_args, args)
        ser = Serializer()
        view_data.serialize(ser)
        headers = {"Content-Type": "application/x.aptos.view_function+bcs"}
        response = await self.client.post(request, headers=headers, content=ser.output())
        if response.status_code >= 400:
            raise ApiError(response.text, response.status_code)
        return response.json()

    async def _send_with_retry(
        self, send: Callable[[], Awaitable[httpx.Response]]
    ) -> httpx.Response:
        """Retry GETs and idempotent POSTs on transport errors, 429, and 5xx.

        Transaction submission must not use this helper: a lost 5xx response
        after the node accepted the transaction would double-submit.
        """
        retries = self.client_config.http_retries
        last_response: Optional[httpx.Response] = None
        for attempt in range(retries + 1):
            try:
                response = await send()
            except httpx.RequestError:
                if attempt < retries:
                    await asyncio.sleep(0.25 * (2**attempt))
                    continue
                raise
            if _retryable_http_status(response.status_code) and attempt < retries:
                last_response = response
                await asyncio.sleep(0.25 * (2**attempt))
                continue
            return response
        assert last_response is not None
        return last_response

    async def _post(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        # format params:
        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}

        async def send() -> httpx.Response:
            return await self.client.post(
                url=f"{self.base_url}/{endpoint}",
                params=params,
                headers=headers,
                json=data,
            )

        return await self._send_with_retry(send)

    async def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        # format params:
        params = {} if params is None else params
        params = {key: val for key, val in params.items() if val is not None}

        async def send() -> httpx.Response:
            return await self.client.get(
                url=f"{self.base_url}/{endpoint}",
                params=params,
            )

        return await self._send_with_retry(send)


class FaucetClient:
    """Faucet creates and funds accounts. This is a thin wrapper around that.

    Note: only devnet has a publicly accessible faucet. For testnet, you must
    provide an auth_token. See https://aptos.dev/network/faucet for details.
    """

    base_url: str
    rest_client: RestClient
    headers: Dict[str, str]
    _fund_lock: asyncio.Lock

    def __init__(self, base_url: str, rest_client: RestClient, auth_token: Optional[str] = None):
        self.base_url = base_url
        self.rest_client = rest_client
        self.headers = {"Content-Type": "application/json"}
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"
        self._fund_lock = asyncio.Lock()

    async def close(self) -> None:
        """Close the underlying REST client connection."""
        await self.rest_client.close()

    async def fund_account(
        self, address: AccountAddress, amount: int, wait_for_transaction=True
    ) -> str:
        """This creates an account if it does not exist and mints the specified amount of
        coins into that account.

        Concurrent calls on the same client are serialized so a single faucet
        minter does not race sequence numbers. Transient errors (429, 5xx,
        SEQUENCE_NUMBER_TOO_OLD/NEW) are retried.

        Note: only devnet has a publicly accessible faucet. For testnet, you must
        initialize this client with an auth_token.
        """
        async with self._fund_lock:
            return await self._fund_account_once(address, amount, wait_for_transaction)

    async def _fund_account_once(
        self, address: AccountAddress, amount: int, wait_for_transaction: bool
    ) -> str:
        retries = self.rest_client.client_config.http_retries
        last_error: Optional[ApiError] = None
        for attempt in range(retries + 1):
            try:
                response = await self.rest_client.client.post(
                    f"{self.base_url}/fund",
                    headers=self.headers,
                    json={"address": str(address), "amount": amount},
                )
            except httpx.RequestError as exc:
                last_error = ApiError(str(exc), 0)
                if attempt < retries:
                    await asyncio.sleep(0.25 * (2**attempt))
                    continue
                raise last_error from exc

            if response.status_code >= 400:
                last_error = ApiError(response.text, response.status_code)
                if (
                    _retryable_faucet_error(response.status_code, response.text)
                    and attempt < retries
                ):
                    await asyncio.sleep(0.25 * (2**attempt))
                    continue
                raise last_error

            txn_hash = response.json()["txn_hashes"][0]
            if wait_for_transaction:
                await self.rest_client.wait_for_transaction(txn_hash)
            return txn_hash

        assert last_error is not None
        raise last_error

    async def healthy(self) -> bool:
        """Return ``True`` iff the faucet's root endpoint reports ``tap:ok``."""
        try:
            response = await self.rest_client.client.get(self.base_url)
        except httpx.HTTPError:
            return False
        return response.status_code == 200 and response.text == "tap:ok"


class ApiError(Exception):
    """The API returned a non-success status code, e.g., >= 400"""

    status_code: int

    def __init__(self, message: str, status_code: int):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.status_code = status_code


class AccountNotFound(Exception):
    """The account was not found"""

    account: AccountAddress

    def __init__(self, message: str, account: AccountAddress):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.account = account


class ResourceNotFound(Exception):
    """The underlying resource was not found"""

    resource: str

    def __init__(self, message: str, resource: str):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.resource = resource


class TransactionTimeout(Exception):
    """The transaction exceeded the configured wait timeout"""


class TransactionFailed(Exception):
    """The transaction completed but was not successful"""


class IndexerError(Exception):
    """The indexer returned an error or a non-JSON response (e.g., when rate-limited)."""
