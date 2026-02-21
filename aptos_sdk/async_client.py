# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Async REST and Faucet clients for the Aptos Python SDK (Spec 06).

This module is the primary HTTP entry point for the SDK.  It contains:

* :class:`LedgerInfo` — structured ledger response dataclass.
* :class:`AccountInfo` — structured account response dataclass.
* :class:`Resource` — structured resource response dataclass.
* :class:`GasEstimate` — structured gas estimation dataclass.
* :class:`Transaction` — structured transaction response dataclass.
* :class:`RestClient` — async HTTP client for the Aptos Fullnode REST API.
* :class:`FaucetClient` — async client for the Aptos Faucet (testnet/devnet).

Design
------
All I/O is **async-only**.  The :class:`RestClient` uses ``httpx`` with
HTTP/2 enabled.  Structured dataclasses replace raw dicts for all API
responses so callers can access fields with attribute syntax.

Error handling follows the spec-aligned hierarchy from :mod:`aptos_sdk.errors`:
HTTP 400 → :class:`~aptos_sdk.errors.BadRequestError`,
HTTP 404 → :class:`~aptos_sdk.errors.NotFoundError`,
HTTP 409 → :class:`~aptos_sdk.errors.ConflictError`,
HTTP 429 → :class:`~aptos_sdk.errors.RateLimitedError`,
HTTP 5xx → :class:`~aptos_sdk.errors.InternalServerError`,
VM abort in response body → :class:`~aptos_sdk.errors.VmError`.

Usage example::

    async with RestClient(Network.TESTNET.fullnode_url) as client:
        info = await client.get_ledger_info()
        balance = await client.account_balance(address)
        txn_hash = await client.bcs_transfer(sender, recipient, amount)
        txn = await client.wait_for_transaction(txn_hash)
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

from .account import Account
from .account_address import AccountAddress
from .authenticator import (
    AccountAuthenticator,
    MultiAgentAuthenticator,
    TransactionAuthenticator,
)
from .bcs import Serializer
from .chain_id import ChainId
from .errors import (
    ApiError,
    AptosTimeoutError,
    BadRequestError,
    ConflictError,
    InternalServerError,
    NotFoundError,
    RateLimitedError,
    VmError,
)
from .transactions import (
    EntryFunction,
    MultiAgentRawTransaction,
    RawTransaction,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import StructTag, TypeTag

# ---------------------------------------------------------------------------
# Default transaction configuration
# ---------------------------------------------------------------------------

#: Default TTL for newly built transactions (seconds from now).
_DEFAULT_EXPIRATION_TTL: int = 600

#: Default gas unit price in Octas.
_DEFAULT_GAS_UNIT_PRICE: int = 100

#: Default maximum gas units per transaction.
_DEFAULT_MAX_GAS_AMOUNT: int = 100_000

#: Polling interval for wait_for_transaction (seconds).
_POLL_INTERVAL: float = 1.0


# ---------------------------------------------------------------------------
# Response dataclasses
# ---------------------------------------------------------------------------


@dataclass
class LedgerInfo:
    """
    Structured representation of the Aptos ledger information endpoint.

    Attributes
    ----------
    chain_id:
        Numeric chain identifier (1 = mainnet, 2 = testnet, 4 = localnet).
    epoch:
        Current epoch number.
    ledger_version:
        Latest committed ledger version.
    oldest_ledger_version:
        Oldest available ledger version (versions below may be pruned).
    ledger_timestamp:
        Timestamp of the latest ledger version in **microseconds** since the
        Unix epoch.
    block_height:
        Latest committed block height.
    oldest_block_height:
        Oldest available block height.
    """

    chain_id: int
    epoch: int
    ledger_version: int
    oldest_ledger_version: int
    ledger_timestamp: int
    block_height: int
    oldest_block_height: int

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "LedgerInfo":
        """Construct a :class:`LedgerInfo` from a raw API JSON dict."""
        return cls(
            chain_id=int(data["chain_id"]),
            epoch=int(data["epoch"]),
            ledger_version=int(data["ledger_version"]),
            oldest_ledger_version=int(data["oldest_ledger_version"]),
            ledger_timestamp=int(data["ledger_timestamp"]),
            block_height=int(data["block_height"]),
            oldest_block_height=int(data["oldest_block_height"]),
        )


@dataclass
class AccountInfo:
    """
    Structured representation of the Aptos account information endpoint.

    Attributes
    ----------
    sequence_number:
        The account's current on-chain sequence number.
    authentication_key:
        The account's authentication key as a hex string (``0x``-prefixed).
    """

    sequence_number: int
    authentication_key: str

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "AccountInfo":
        """Construct an :class:`AccountInfo` from a raw API JSON dict."""
        return cls(
            sequence_number=int(data["sequence_number"]),
            authentication_key=data["authentication_key"],
        )


@dataclass
class Resource:
    """
    A single on-chain Move resource returned from the resources endpoint.

    Attributes
    ----------
    type:
        The fully-qualified Move struct type, e.g.
        ``"0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"``.
    data:
        The decoded resource fields as a JSON-compatible dict.
    """

    type: str
    data: dict[str, Any]

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Resource":
        """Construct a :class:`Resource` from a raw API JSON dict."""
        return cls(
            type=data["type"],
            data=data["data"],
        )


@dataclass
class GasEstimate:
    """
    Gas price estimate returned from the ``/estimate_gas_price`` endpoint.

    Attributes
    ----------
    gas_estimate:
        The estimated gas unit price (median across recent transactions).
    deprioritized_gas_estimate:
        Lower-priority gas price (may be ``None`` if not available).
    prioritized_gas_estimate:
        Higher-priority gas price for faster inclusion (may be ``None``).
    """

    gas_estimate: int
    deprioritized_gas_estimate: int | None = None
    prioritized_gas_estimate: int | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "GasEstimate":
        """Construct a :class:`GasEstimate` from a raw API JSON dict."""
        deprioritized = data.get("deprioritized_gas_estimate")
        prioritized = data.get("prioritized_gas_estimate")
        return cls(
            gas_estimate=int(data["gas_estimate"]),
            deprioritized_gas_estimate=(
                int(deprioritized) if deprioritized is not None else None
            ),
            prioritized_gas_estimate=(
                int(prioritized) if prioritized is not None else None
            ),
        )


@dataclass
class Transaction:
    """
    A structured Aptos transaction returned from the transactions endpoint.

    Attributes
    ----------
    hash:
        The transaction hash (``0x``-prefixed hex string).
    type:
        The transaction type string, e.g. ``"user_transaction"``,
        ``"pending_transaction"``, ``"genesis_transaction"``.
    version:
        The ledger version at which the transaction was committed.
        ``None`` for pending transactions.
    success:
        Whether the transaction executed successfully.  ``None`` for
        pending transactions.
    vm_status:
        The Move VM status string.  ``None`` for pending transactions.
    sender:
        The sender address as a hex string.  ``None`` for non-user txns.
    sequence_number:
        The sender's sequence number used in this transaction.
    payload:
        The decoded transaction payload dict.  ``None`` when not present.
    events:
        List of events emitted by the transaction.
    """

    hash: str
    type: str
    version: int | None = None
    success: bool | None = None
    vm_status: str | None = None
    sender: str | None = None
    sequence_number: int | None = None
    payload: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Transaction":
        """Construct a :class:`Transaction` from a raw API JSON dict."""
        version_raw = data.get("version")
        seq_raw = data.get("sequence_number")
        return cls(
            hash=data["hash"],
            type=data["type"],
            version=int(version_raw) if version_raw is not None else None,
            success=data.get("success"),
            vm_status=data.get("vm_status"),
            sender=data.get("sender"),
            sequence_number=(int(seq_raw) if seq_raw is not None else None),
            payload=data.get("payload"),
            events=data.get("events", []),
        )

    @property
    def is_pending(self) -> bool:
        """Return ``True`` if the transaction is still pending."""
        return self.type == "pending_transaction"


# ---------------------------------------------------------------------------
# RestClient
# ---------------------------------------------------------------------------


class RestClient:
    """
    Async HTTP client for the Aptos Fullnode REST API.

    The client uses ``httpx`` with HTTP/2 enabled.  It should be used as an
    async context manager so that the underlying connection pool is closed
    properly::

        async with RestClient(Network.TESTNET.fullnode_url) as client:
            balance = await client.account_balance(address)

    When not using the context manager, call :meth:`close` explicitly.

    Parameters
    ----------
    base_url:
        The base URL of the Aptos fullnode REST API, e.g.
        ``"https://fullnode.testnet.aptoslabs.com/v1"``.
        Trailing slashes are stripped automatically.
    api_key:
        Optional API key to include in the ``Authorization: Bearer``
        header.  Required for some hosted node providers.
    timeout:
        HTTP request timeout in seconds.  Defaults to 60 seconds.
        The connection-pool timeout is unlimited (``None``) to allow
        long-running requests to make progress.
    max_retries:
        Not currently used for request-level retries; reserved for future
        retry strategy integration.

    Attributes
    ----------
    base_url : str
        The base URL (trailing slash stripped).
    """

    base_url: str
    _client: httpx.AsyncClient
    _chain_id: int | None

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._chain_id = None
        self._max_retries = max_retries

        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        self._client = httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(timeout, pool=None),
            headers=headers,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "RestClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    async def _get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Perform a GET request against *endpoint* (relative to :attr:`base_url`).

        ``None`` values in *params* are filtered out before sending so callers
        can pass optional parameters directly without conditional guards.

        Parameters
        ----------
        endpoint:
            Path relative to the base URL (no leading slash required).
        params:
            Optional query parameters.  ``None`` values are stripped.

        Returns
        -------
        httpx.Response
        """
        clean_params = (
            {k: v for k, v in params.items() if v is not None} if params else {}
        )
        return await self._client.get(
            url=f"{self.base_url}/{endpoint}",
            params=clean_params,
        )

    async def _post(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """
        Perform a POST request against *endpoint*.

        Exactly one of *data* (JSON body) or *content* (raw bytes body) should
        be provided.  ``None`` values in *params* are filtered out.

        Parameters
        ----------
        endpoint:
            Path relative to the base URL.
        params:
            Optional query parameters.  ``None`` values are stripped.
        headers:
            Optional extra request headers (merged with client-level headers).
        data:
            Optional JSON-serializable payload.
        content:
            Optional raw bytes payload.

        Returns
        -------
        httpx.Response
        """
        clean_params = (
            {k: v for k, v in params.items() if v is not None} if params else {}
        )
        if content is not None:
            return await self._client.post(
                url=f"{self.base_url}/{endpoint}",
                params=clean_params,
                headers=headers,
                content=content,
            )
        return await self._client.post(
            url=f"{self.base_url}/{endpoint}",
            params=clean_params,
            headers=headers,
            json=data,
        )

    def _raise_for_status(self, response: httpx.Response) -> None:
        """
        Inspect an HTTP response and raise the appropriate SDK error if it
        indicates a failure (status code >= 400).

        The response body is parsed for:

        * ``error_code`` — machine-readable identifier (e.g.
          ``"ACCOUNT_NOT_FOUND"``).
        * ``vm_error_code`` / abort code fields — numeric VM abort code
          present in VM execution failure responses.
        * ``message`` — human-readable server error message.

        Parameters
        ----------
        response:
            The ``httpx.Response`` to inspect.

        Raises
        ------
        BadRequestError
            HTTP 400.
        NotFoundError
            HTTP 404.
        ConflictError
            HTTP 409.
        RateLimitedError
            HTTP 429.
        InternalServerError
            HTTP 5xx.
        ApiError
            Any other 4xx status code.
        """
        status = response.status_code
        if status < 400:
            return

        # Attempt to parse a structured error body.
        message: str = response.text
        error_code: str | None = None
        vm_error_code: int | None = None

        try:
            body = response.json()
            if isinstance(body, dict):
                # Prefer a "message" field if present.
                if "message" in body:
                    message = body["message"]
                # Machine-readable error code from the API.
                if "error_code" in body:
                    error_code = str(body["error_code"])
                # VM abort code — present in VM execution failures.
                # The Aptos API surfaces this in several places.
                if "vm_error_code" in body:
                    raw_vm = body["vm_error_code"]
                    if raw_vm is not None:
                        vm_error_code = int(raw_vm)
                elif "data" in body and isinstance(body["data"], dict):
                    # Some VM errors embed the abort code inside `data`.
                    data_block = body["data"]
                    if "abort_code" in data_block:
                        raw_vm = data_block["abort_code"]
                        if raw_vm is not None:
                            vm_error_code = int(raw_vm)
        except Exception:
            # Fallback: use raw response text.
            pass

        if status == 400:
            if vm_error_code is not None:
                raise VmError(
                    message,
                    status_code=400,
                    vm_error_code=vm_error_code,
                    error_code=error_code,
                )
            raise BadRequestError(
                message, vm_error_code=vm_error_code, error_code=error_code
            )
        if status == 404:
            raise NotFoundError(message, error_code=error_code)
        if status == 409:
            raise ConflictError(
                message, vm_error_code=vm_error_code, error_code=error_code
            )
        if status == 429:
            raise RateLimitedError(
                message, vm_error_code=vm_error_code, error_code=error_code
            )
        if status >= 500:
            raise InternalServerError(
                message,
                status_code=status,
                vm_error_code=vm_error_code,
                error_code=error_code,
            )
        # Other 4xx.
        raise ApiError(
            message,
            status_code=status,
            vm_error_code=vm_error_code,
            error_code=error_code,
        )

    # ------------------------------------------------------------------
    # Ledger (P0)
    # ------------------------------------------------------------------

    async def get_ledger_info(self) -> LedgerInfo:
        """
        Fetch the current ledger state summary.

        Returns
        -------
        LedgerInfo
            The current ledger information.

        Raises
        ------
        ApiError
            On non-success HTTP response.
        """
        response = await self._client.get(self.base_url)
        self._raise_for_status(response)
        return LedgerInfo.from_json(response.json())

    async def chain_id(self) -> int:
        """
        Return the chain ID of the connected network.

        The value is fetched from the ledger info endpoint on the first call
        and cached for subsequent calls.

        Returns
        -------
        int
            The chain ID (e.g. 1 for mainnet, 2 for testnet).
        """
        if self._chain_id is None:
            info = await self.get_ledger_info()
            self._chain_id = info.chain_id
        return self._chain_id

    # ------------------------------------------------------------------
    # Accounts (P0)
    # ------------------------------------------------------------------

    async def get_account(
        self,
        address: AccountAddress,
        ledger_version: int | None = None,
    ) -> AccountInfo:
        """
        Fetch the authentication key and sequence number for an account.

        Parameters
        ----------
        address:
            The :class:`~aptos_sdk.account_address.AccountAddress` to query.
        ledger_version:
            Optional historical ledger version.  Defaults to the latest.

        Returns
        -------
        AccountInfo

        Raises
        ------
        NotFoundError
            If the account does not exist on-chain.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return AccountInfo.from_json(response.json())

    async def get_account_resources(
        self,
        address: AccountAddress,
        ledger_version: int | None = None,
    ) -> list[Resource]:
        """
        Fetch all Move resources for an account.

        Parameters
        ----------
        address:
            The account address.
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        list[Resource]

        Raises
        ------
        NotFoundError
            If the account does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}/resources",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return [Resource.from_json(item) for item in response.json()]

    async def get_account_resource(
        self,
        address: AccountAddress,
        resource_type: str,
        ledger_version: int | None = None,
    ) -> Resource:
        """
        Fetch a single named Move resource for an account.

        Parameters
        ----------
        address:
            The account address.
        resource_type:
            Fully-qualified resource type string, e.g.
            ``"0x1::account::Account"``.
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        Resource

        Raises
        ------
        NotFoundError
            If the account or resource type does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}/resource/{resource_type}",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return Resource.from_json(response.json())

    async def account_balance(
        self,
        address: AccountAddress,
        ledger_version: int | None = None,
        coin_type: str | None = None,
    ) -> int:
        """
        Fetch the coin balance for an account.

        Uses the ``0x1::coin::balance`` view function via BCS payload.

        Parameters
        ----------
        address:
            The account address to query.
        ledger_version:
            Optional historical ledger version.
        coin_type:
            Coin type to query.  Defaults to
            ``"0x1::aptos_coin::AptosCoin"`` (native APT).

        Returns
        -------
        int
            The coin balance in Octas (for APT).

        Raises
        ------
        NotFoundError
            If the account does not exist or has no balance resource.
        ApiError
            On other non-success HTTP responses.
        """
        coin_type = coin_type or "0x1::aptos_coin::AptosCoin"
        result = await self.view_bcs_payload(
            "0x1::coin",
            "balance",
            [TypeTag(StructTag.from_str(coin_type))],
            [TransactionArgument(address, Serializer.struct)],
            ledger_version,
        )
        return int(result[0])

    async def account_sequence_number(
        self,
        address: AccountAddress,
        ledger_version: int | None = None,
    ) -> int:
        """
        Fetch the current sequence number for an account.

        Returns ``0`` for accounts that have not been created on-chain yet
        (HTTP 404), consistent with the spec.

        Parameters
        ----------
        address:
            The account address to query.
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        int
            The account sequence number (0 if not found).
        """
        try:
            account_info = await self.get_account(address, ledger_version)
            return account_info.sequence_number
        except NotFoundError:
            return 0

    # ------------------------------------------------------------------
    # Modules (P1)
    # ------------------------------------------------------------------

    async def get_account_modules(
        self,
        address: AccountAddress,
        ledger_version: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch all Move modules deployed at an account address.

        Parameters
        ----------
        address:
            The account address.
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        list[dict]
            Raw module dicts (``abi`` + ``bytecode`` fields).

        Raises
        ------
        NotFoundError
            If the account does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}/modules",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return response.json()

    async def get_account_module(
        self,
        address: AccountAddress,
        module_name: str,
        ledger_version: int | None = None,
    ) -> dict[str, Any]:
        """
        Fetch a single named Move module from an account.

        Parameters
        ----------
        address:
            The account address.
        module_name:
            The module name (e.g. ``"coin"``).
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        dict
            Raw module dict with ``abi`` and ``bytecode`` fields.

        Raises
        ------
        NotFoundError
            If the account or module does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}/module/{module_name}",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    # Transactions (P0)
    # ------------------------------------------------------------------

    async def get_transaction_by_hash(self, txn_hash: str) -> Transaction:
        """
        Fetch a transaction by its hash.

        Parameters
        ----------
        txn_hash:
            The ``0x``-prefixed transaction hash string.

        Returns
        -------
        Transaction

        Raises
        ------
        NotFoundError
            If the transaction does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        self._raise_for_status(response)
        return Transaction.from_json(response.json())

    async def get_transaction_by_version(self, version: int) -> Transaction:
        """
        Fetch a transaction by its ledger version.

        Parameters
        ----------
        version:
            The ledger version number.

        Returns
        -------
        Transaction

        Raises
        ------
        NotFoundError
            If the version does not exist.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._get(endpoint=f"transactions/by_version/{version}")
        self._raise_for_status(response)
        return Transaction.from_json(response.json())

    async def get_account_transactions(
        self,
        address: AccountAddress,
        start: int | None = None,
        limit: int | None = None,
    ) -> list[Transaction]:
        """
        Fetch committed transactions sent by an account.

        Parameters
        ----------
        address:
            The account address.
        start:
            Starting sequence number.  Defaults to the most recent.
        limit:
            Maximum number of transactions to return.

        Returns
        -------
        list[Transaction]

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        response = await self._get(
            endpoint=f"accounts/{address}/transactions",
            params={"start": start, "limit": limit},
        )
        self._raise_for_status(response)
        return [Transaction.from_json(item) for item in response.json()]

    # ------------------------------------------------------------------
    # Transaction building (P0)
    # ------------------------------------------------------------------

    async def create_bcs_transaction(
        self,
        sender: "Account | AccountAddress",
        payload: TransactionPayload,
        sequence_number: int | None = None,
    ) -> RawTransaction:
        """
        Build an unsigned :class:`~aptos_sdk.transactions.RawTransaction`.

        Fetches the sender's sequence number and current gas price if not
        provided.

        Parameters
        ----------
        sender:
            The sending :class:`~aptos_sdk.account.Account` or its
            :class:`~aptos_sdk.account_address.AccountAddress`.
        payload:
            The transaction payload.
        sequence_number:
            Optional explicit sequence number.  When ``None`` the current
            on-chain sequence number is fetched.

        Returns
        -------
        RawTransaction
        """
        if isinstance(sender, Account):
            sender_address = sender.address
        else:
            sender_address = sender

        if sequence_number is None:
            sequence_number = await self.account_sequence_number(sender_address)

        cid = await self.chain_id()

        return RawTransaction(
            sender_address,
            sequence_number,
            payload,
            _DEFAULT_MAX_GAS_AMOUNT,
            _DEFAULT_GAS_UNIT_PRICE,
            int(time.time()) + _DEFAULT_EXPIRATION_TTL,
            ChainId(cid),
        )

    async def create_bcs_signed_transaction(
        self,
        sender: Account,
        payload: TransactionPayload,
        sequence_number: int | None = None,
    ) -> SignedTransaction:
        """
        Build and sign a :class:`~aptos_sdk.transactions.SignedTransaction`.

        Parameters
        ----------
        sender:
            The signing account.
        payload:
            The transaction payload.
        sequence_number:
            Optional explicit sequence number.

        Returns
        -------
        SignedTransaction
        """
        raw_txn = await self.create_bcs_transaction(sender, payload, sequence_number)
        authenticator = cast(AccountAuthenticator, sender.sign_transaction(raw_txn))
        return SignedTransaction(raw_txn, authenticator)

    async def create_multi_agent_bcs_transaction(
        self,
        sender: Account,
        secondary_accounts: list[Account],
        payload: TransactionPayload,
    ) -> SignedTransaction:
        """
        Build and sign a multi-agent
        :class:`~aptos_sdk.transactions.SignedTransaction`.

        All secondary accounts sign using the
        ``RAW_TRANSACTION_WITH_DATA`` domain prefix.

        Parameters
        ----------
        sender:
            The primary signing account.
        secondary_accounts:
            List of secondary signing accounts.
        payload:
            The transaction payload.

        Returns
        -------
        SignedTransaction
        """
        sequence_number = await self.account_sequence_number(sender.address)
        cid = await self.chain_id()

        raw_txn = RawTransaction(
            sender.address,
            sequence_number,
            payload,
            _DEFAULT_MAX_GAS_AMOUNT,
            _DEFAULT_GAS_UNIT_PRICE,
            int(time.time()) + _DEFAULT_EXPIRATION_TTL,
            ChainId(cid),
        )

        multi_agent_txn = MultiAgentRawTransaction(
            raw_txn,
            [acct.address for acct in secondary_accounts],
        )

        sender_auth = cast(
            AccountAuthenticator, sender.sign_transaction(multi_agent_txn)
        )
        secondary_auths: list[tuple[AccountAddress, AccountAuthenticator]] = [
            (
                acct.address,
                cast(AccountAuthenticator, acct.sign_transaction(multi_agent_txn)),
            )
            for acct in secondary_accounts
        ]

        authenticator = TransactionAuthenticator(
            MultiAgentAuthenticator(sender_auth, secondary_auths)
        )

        return SignedTransaction(raw_txn, authenticator)

    # ------------------------------------------------------------------
    # Transaction submission (P0)
    # ------------------------------------------------------------------

    async def submit_bcs_transaction(self, signed_txn: SignedTransaction) -> str:
        """
        Submit a BCS-encoded signed transaction and return its hash.

        The transaction is submitted in the ``application/x.aptos.signed_transaction+bcs``
        content type, which is the preferred submission format.

        Parameters
        ----------
        signed_txn:
            The signed transaction to submit.

        Returns
        -------
        str
            The transaction hash (``0x``-prefixed hex string).

        Raises
        ------
        BadRequestError
            HTTP 400 (malformed transaction).
        ConflictError
            HTTP 409 (duplicate or conflicting transaction).
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._post(
            endpoint="transactions",
            headers={"Content-Type": "application/x.aptos.signed_transaction+bcs"},
            content=signed_txn.bytes(),
        )
        self._raise_for_status(response)
        return response.json()["hash"]

    async def submit_transaction(
        self,
        account: Account,
        payload: TransactionPayload,
    ) -> str:
        """
        Build, sign, and submit a transaction.

        This is a convenience method that calls :meth:`create_bcs_signed_transaction`
        followed by :meth:`submit_bcs_transaction`.

        Parameters
        ----------
        account:
            The account that will sign and pay for the transaction.
        payload:
            The entry function or script payload.

        Returns
        -------
        str
            The submitted transaction hash.

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        signed_txn = await self.create_bcs_signed_transaction(account, payload)
        return await self.submit_bcs_transaction(signed_txn)

    async def wait_for_transaction(
        self,
        txn_hash: str,
        timeout_secs: float = 30.0,
    ) -> Transaction:
        """
        Poll until the transaction with *txn_hash* is no longer pending.

        Parameters
        ----------
        txn_hash:
            The transaction hash to wait for.
        timeout_secs:
            Maximum number of seconds to wait before raising
            :class:`~aptos_sdk.errors.AptosTimeoutError`.
            Defaults to 30 seconds.

        Returns
        -------
        Transaction
            The committed transaction.

        Raises
        ------
        AptosTimeoutError
            If the transaction is still pending after *timeout_secs*.
        ApiError
            If the transaction fails to commit successfully.
        """
        deadline = time.monotonic() + timeout_secs

        while True:
            try:
                response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
            except httpx.RequestError as exc:
                # Network-level error during polling — keep trying until timeout.
                if time.monotonic() >= deadline:
                    raise AptosTimeoutError(
                        f"Transaction {txn_hash!r} timed out after "
                        f"{timeout_secs:.0f}s (network error: {exc})"
                    )
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            if response.status_code == 404:
                # Transaction not yet visible in the node.
                if time.monotonic() >= deadline:
                    raise AptosTimeoutError(
                        f"Transaction {txn_hash!r} timed out after "
                        f"{timeout_secs:.0f}s (not found)"
                    )
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            self._raise_for_status(response)
            txn = Transaction.from_json(response.json())

            if txn.is_pending:
                if time.monotonic() >= deadline:
                    raise AptosTimeoutError(
                        f"Transaction {txn_hash!r} timed out after "
                        f"{timeout_secs:.0f}s (still pending)"
                    )
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            # Transaction is committed.
            return txn

    async def submit_and_wait(
        self,
        account: Account,
        payload: TransactionPayload,
    ) -> Transaction:
        """
        Build, sign, submit, and wait for a transaction.

        Combines :meth:`submit_transaction` with :meth:`wait_for_transaction`
        for the common case.

        Parameters
        ----------
        account:
            The signing and paying account.
        payload:
            The transaction payload.

        Returns
        -------
        Transaction
            The committed transaction.

        Raises
        ------
        AptosTimeoutError
            If the transaction does not commit within the default timeout.
        ApiError
            On non-success HTTP responses.
        """
        txn_hash = await self.submit_transaction(account, payload)
        return await self.wait_for_transaction(txn_hash)

    # ------------------------------------------------------------------
    # View functions (P1)
    # ------------------------------------------------------------------

    async def view_function(
        self,
        module: str,
        function: str,
        type_args: list[str],
        args: list[str],
        ledger_version: int | None = None,
    ) -> list[Any]:
        """
        Execute a Move view function using the JSON API.

        Parameters
        ----------
        module:
            Fully-qualified module string (e.g. ``"0x1::coin"``).
        function:
            The view function name.
        type_args:
            Generic type argument strings.
        args:
            Function argument strings (JSON-encoded).
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        list[Any]
            The decoded return values as a JSON list.

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        response = await self._post(
            endpoint="view",
            params={"ledger_version": ledger_version},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            data={
                "function": f"{module}::{function}",
                "type_arguments": type_args,
                "arguments": args,
            },
        )
        self._raise_for_status(response)
        result = response.json()
        if isinstance(result, list):
            return result
        return [result]

    async def view_bcs_payload(
        self,
        module: str,
        function: str,
        ty_args: list[TypeTag],
        args: "list[TransactionArgument | bytes]",
        ledger_version: int | None = None,
    ) -> Any:
        """
        Execute a Move view function using a BCS-encoded payload.

        This is the preferred method for view functions because:

        * BCS payloads are more compact than JSON.
        * Type information is unambiguous.
        * Arguments are pre-encoded by the caller, avoiding JSON encoding
          issues for large integers or complex types.

        Parameters
        ----------
        module:
            Fully-qualified module string (e.g. ``"0x1::coin"``).
        function:
            The view function name.
        ty_args:
            Generic :class:`~aptos_sdk.type_tag.TypeTag` arguments.
        args:
            :class:`~aptos_sdk.transactions.TransactionArgument` instances or
            pre-encoded ``bytes`` arguments.
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        Any
            The decoded return value(s) as a JSON object.

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        request_url = f"{self.base_url}/view"
        if ledger_version is not None:
            request_url = f"{request_url}?ledger_version={ledger_version}"

        view_data = EntryFunction.natural(module, function, ty_args, args)
        ser = Serializer()
        view_data.serialize(ser)

        response = await self._client.post(
            request_url,
            headers={"Content-Type": "application/x.aptos.view_function+bcs"},
            content=ser.output(),
        )
        self._raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    # Gas estimation (P1)
    # ------------------------------------------------------------------

    async def estimate_gas_price(self) -> GasEstimate:
        """
        Fetch the current gas price estimate from the node.

        Returns
        -------
        GasEstimate
            Contains the median gas estimate and optionally deprioritized
            and prioritized estimates.

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        response = await self._get(endpoint="estimate_gas_price")
        self._raise_for_status(response)
        return GasEstimate.from_json(response.json())

    # ------------------------------------------------------------------
    # Simulation (P1)
    # ------------------------------------------------------------------

    async def simulate_bcs_transaction(
        self,
        signed_txn: SignedTransaction,
        estimate_gas: bool = False,
    ) -> dict[str, Any]:
        """
        Simulate a BCS-encoded signed transaction without committing it.

        The transaction must be signed with zeroed-out signatures to
        indicate simulation intent (see
        :meth:`~aptos_sdk.transactions.RawTransaction.sign_simulated`).

        Parameters
        ----------
        signed_txn:
            A signed transaction with zeroed signatures.
        estimate_gas:
            When ``True``, ask the node to also estimate the optimal gas
            unit price and maximum gas amount.

        Returns
        -------
        dict
            Raw simulation result from the API.

        Raises
        ------
        ApiError
            On non-success HTTP responses.
        """
        params: dict[str, Any] = {}
        if estimate_gas:
            params = {
                "estimate_gas_unit_price": "true",
                "estimate_max_gas_amount": "true",
            }

        response = await self._post(
            endpoint="transactions/simulate",
            params=params,
            headers={"Content-Type": "application/x.aptos.signed_transaction+bcs"},
            content=signed_txn.bytes(),
        )
        self._raise_for_status(response)
        return response.json()

    async def simulate_transaction(
        self,
        transaction: RawTransaction,
        sender: Account,
        estimate_gas: bool = False,
    ) -> dict[str, Any]:
        """
        Simulate a raw transaction without committing it.

        Builds a zeroed-signature authenticator for simulation and delegates
        to :meth:`simulate_bcs_transaction`.

        Parameters
        ----------
        transaction:
            The unsigned raw transaction to simulate.
        sender:
            The account whose public key to embed in the simulated
            authenticator.
        estimate_gas:
            When ``True``, estimate optimal gas parameters.

        Returns
        -------
        dict
            Raw simulation result from the API.
        """
        # Build a zeroed authenticator for simulation (no valid signature).
        simulated_auth = transaction.sign_simulated(sender.public_key())
        signed_txn = SignedTransaction(transaction, simulated_auth)
        return await self.simulate_bcs_transaction(
            signed_txn, estimate_gas=estimate_gas
        )

    # ------------------------------------------------------------------
    # Tables (P1)
    # ------------------------------------------------------------------

    async def get_table_item(
        self,
        handle: str,
        key_type: str,
        value_type: str,
        key: Any,
        ledger_version: int | None = None,
    ) -> Any:
        """
        Fetch a value from a Move ``Table`` resource.

        Parameters
        ----------
        handle:
            The table handle (``0x``-prefixed hex string).
        key_type:
            The Move type of the key (e.g. ``"address"``).
        value_type:
            The Move type of the value (e.g. ``"u128"``).
        key:
            The key to look up (JSON-compatible).
        ledger_version:
            Optional historical ledger version.

        Returns
        -------
        Any
            The decoded table value.

        Raises
        ------
        NotFoundError
            If the key is not present in the table.
        ApiError
            On other non-success HTTP responses.
        """
        response = await self._post(
            endpoint=f"tables/{handle}/item",
            params={"ledger_version": ledger_version},
            data={
                "key_type": key_type,
                "value_type": value_type,
                "key": key,
            },
        )
        self._raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    # Convenience transfers
    # ------------------------------------------------------------------

    async def bcs_transfer(
        self,
        sender: Account,
        recipient: AccountAddress,
        amount: int,
        sequence_number: int | None = None,
    ) -> str:
        """
        Transfer APT coins from *sender* to *recipient*.

        Builds and submits an ``0x1::aptos_account::transfer`` entry function
        call using BCS encoding.

        Parameters
        ----------
        sender:
            The account sending APT.
        recipient:
            The destination address.
        amount:
            Amount to transfer in Octas.
        sequence_number:
            Optional explicit sequence number.

        Returns
        -------
        str
            The submitted transaction hash.
        """
        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )
        signed_txn = await self.create_bcs_signed_transaction(
            sender,
            TransactionPayload(payload),
            sequence_number=sequence_number,
        )
        return await self.submit_bcs_transaction(signed_txn)

    async def transfer_coins(
        self,
        sender: Account,
        recipient: AccountAddress,
        coin_type: str,
        amount: int,
        sequence_number: int | None = None,
    ) -> str:
        """
        Transfer a specific coin type from *sender* to *recipient*.

        Uses the ``0x1::aptos_account::transfer_coins`` generic entry function.

        Parameters
        ----------
        sender:
            The sending account.
        recipient:
            The destination address.
        coin_type:
            The fully-qualified coin type string (e.g.
            ``"0x1::aptos_coin::AptosCoin"``).
        amount:
            Amount to transfer (in the coin's smallest unit).
        sequence_number:
            Optional explicit sequence number.

        Returns
        -------
        str
            The submitted transaction hash.
        """
        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer_coins",
            [TypeTag(StructTag.from_str(coin_type))],
            [
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )
        signed_txn = await self.create_bcs_signed_transaction(
            sender,
            TransactionPayload(payload),
            sequence_number=sequence_number,
        )
        return await self.submit_bcs_transaction(signed_txn)

    # ------------------------------------------------------------------
    # Legacy compatibility aliases
    # ------------------------------------------------------------------

    async def info(self) -> dict[str, Any]:
        """
        Fetch raw ledger info as a dict.

        .. deprecated::
            Use :meth:`get_ledger_info` instead, which returns a typed
            :class:`LedgerInfo` dataclass.
        """
        response = await self._client.get(self.base_url)
        self._raise_for_status(response)
        return response.json()

    async def account(
        self,
        account_address: AccountAddress,
        ledger_version: int | None = None,
    ) -> dict[str, Any]:
        """
        Fetch raw account info as a dict.

        .. deprecated::
            Use :meth:`get_account` instead, which returns a typed
            :class:`AccountInfo` dataclass.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}",
            params={"ledger_version": ledger_version},
        )
        self._raise_for_status(response)
        return response.json()

    async def account_resource(
        self,
        account_address: AccountAddress,
        resource_type: str,
        ledger_version: int | None = None,
    ) -> dict[str, Any]:
        """
        Fetch a single resource as a raw dict.

        .. deprecated::
            Use :meth:`get_account_resource` instead.
        """
        resource = await self.get_account_resource(
            account_address, resource_type, ledger_version
        )
        return {"type": resource.type, "data": resource.data}

    async def account_resources(
        self,
        account_address: AccountAddress,
        ledger_version: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch all account resources as a list of raw dicts.

        .. deprecated::
            Use :meth:`get_account_resources` instead.
        """
        resources = await self.get_account_resources(account_address, ledger_version)
        return [{"type": r.type, "data": r.data} for r in resources]

    async def account_module(
        self,
        account_address: AccountAddress,
        module_name: str,
        ledger_version: int | None = None,
    ) -> dict[str, Any]:
        """
        Fetch a single module as a raw dict.

        .. deprecated::
            Use :meth:`get_account_module` instead.
        """
        return await self.get_account_module(
            account_address, module_name, ledger_version
        )

    async def account_modules(
        self,
        account_address: AccountAddress,
        ledger_version: int | None = None,
        limit: int | None = None,
        start: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch all account modules as a list of raw dicts.

        .. deprecated::
            Use :meth:`get_account_modules` instead.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/modules",
            params={
                "ledger_version": ledger_version,
                "limit": limit,
                "start": start,
            },
        )
        self._raise_for_status(response)
        return response.json()

    async def transaction_by_hash(self, txn_hash: str) -> dict[str, Any]:
        """
        Fetch a transaction by hash as a raw dict.

        .. deprecated::
            Use :meth:`get_transaction_by_hash` instead.
        """
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        self._raise_for_status(response)
        return response.json()

    async def transaction_by_version(self, version: int) -> dict[str, Any]:
        """
        Fetch a transaction by version as a raw dict.

        .. deprecated::
            Use :meth:`get_transaction_by_version` instead.
        """
        response = await self._get(endpoint=f"transactions/by_version/{version}")
        self._raise_for_status(response)
        return response.json()

    async def transactions_by_account(
        self,
        account_address: AccountAddress,
        limit: int | None = None,
        start: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch account transactions as a list of raw dicts.

        .. deprecated::
            Use :meth:`get_account_transactions` instead.
        """
        response = await self._get(
            endpoint=f"accounts/{account_address}/transactions",
            params={"limit": limit, "start": start},
        )
        self._raise_for_status(response)
        return response.json()

    async def transaction_pending(self, txn_hash: str) -> bool:
        """
        Return ``True`` if the given transaction is still pending.

        A ``404`` response is treated as pending (the transaction may not yet
        be visible in the node).

        .. deprecated::
            Use :meth:`wait_for_transaction` for a higher-level API.
        """
        response = await self._get(endpoint=f"transactions/by_hash/{txn_hash}")
        if response.status_code == 404:
            return True
        self._raise_for_status(response)
        return response.json()["type"] == "pending_transaction"

    async def submit_and_wait_for_bcs_transaction(
        self, signed_txn: SignedTransaction
    ) -> dict[str, Any]:
        """
        Submit a BCS-encoded transaction and wait for it to commit.

        Returns the raw transaction dict.

        .. deprecated::
            Use :meth:`submit_and_wait` for a higher-level API that returns
            a typed :class:`Transaction`.
        """
        txn_hash = await self.submit_bcs_transaction(signed_txn)
        await self.wait_for_transaction(txn_hash)
        return await self.transaction_by_hash(txn_hash)

    async def view(
        self,
        function: str,
        type_arguments: list[str],
        arguments: list[str],
        ledger_version: int | None = None,
    ) -> bytes:
        """
        Execute a view Move function and return raw response bytes.

        .. deprecated::
            Use :meth:`view_function` (returns parsed list) or
            :meth:`view_bcs_payload` (BCS-encoded request).
        """
        response = await self._post(
            endpoint="view",
            params={"ledger_version": ledger_version},
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
        self._raise_for_status(response)
        return response.content

    async def current_timestamp(self) -> float:
        """
        Return the latest ledger timestamp in seconds.

        .. deprecated::
            Use ``(await client.get_ledger_info()).ledger_timestamp / 1_000_000``
            to obtain microsecond-precision timestamp from a typed object.
        """
        info = await self.get_ledger_info()
        return info.ledger_timestamp / 1_000_000


# ---------------------------------------------------------------------------
# FaucetClient
# ---------------------------------------------------------------------------


class FaucetClient:
    """
    Async client for the Aptos Faucet (testnet/devnet only).

    The faucet is a privileged service that can mint coins and create accounts
    on test networks.  It is not available on mainnet.

    Parameters
    ----------
    base_url:
        The base URL of the faucet service, e.g.
        ``"https://faucet.testnet.aptoslabs.com"``.
        Trailing slashes are stripped.
    rest_client:
        A :class:`RestClient` instance used to wait for faucet transactions
        to confirm when ``wait_for_transaction=True``.
    auth_token:
        Optional Bearer token for authenticated faucet endpoints.

    Attributes
    ----------
    base_url : str
        The faucet base URL (trailing slash stripped).
    """

    base_url: str
    _rest_client: RestClient

    def __init__(
        self,
        base_url: str,
        rest_client: RestClient,
        *,
        auth_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._rest_client = rest_client
        self._headers: dict[str, str] = {}
        if auth_token:
            self._headers["Authorization"] = f"Bearer {auth_token}"

    async def close(self) -> None:
        """Close the underlying :class:`RestClient` connection pool."""
        await self._rest_client.close()

    async def fund_account(
        self,
        address: AccountAddress,
        amount: int,
        *,
        wait_for_transaction: bool = True,
    ) -> str:
        """
        Fund an account with the specified amount of coins.

        Creates the account on-chain if it does not yet exist.

        Parameters
        ----------
        address:
            The account address to fund.
        amount:
            Number of Octas (for APT) to mint into the account.
        wait_for_transaction:
            When ``True`` (default), poll until the funding transaction is
            committed before returning.

        Returns
        -------
        str
            The transaction hash of the funding transaction.

        Raises
        ------
        ApiError
            If the faucet returns a non-success HTTP response.
        AptosTimeoutError
            If ``wait_for_transaction=True`` and the transaction does not
            commit within the timeout.
        """
        request_url = f"{self.base_url}/mint?amount={amount}&address={address}"
        response = await self._rest_client._client.post(
            request_url, headers=self._headers
        )
        if response.status_code >= 400:
            raise ApiError(
                response.text,
                status_code=response.status_code,
            )

        body = response.json()
        # The faucet may return either a list of hashes or a single hash string.
        if isinstance(body, list):
            txn_hash: str = body[0]
        else:
            txn_hash = str(body)

        if wait_for_transaction:
            await self._rest_client.wait_for_transaction(txn_hash)

        return txn_hash

    async def healthy(self) -> bool:
        """
        Check whether the faucet service is healthy.

        Returns
        -------
        bool
            ``True`` if the faucet responds with ``"tap:ok"``.
        """
        response = await self._rest_client._client.get(self.base_url)
        return "tap:ok" == response.text
