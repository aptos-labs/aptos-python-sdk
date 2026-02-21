# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
TransactionBuilder — fluent builder pattern for constructing Aptos transactions.

Implements the ``TransactionBuilder`` pattern from the Aptos SDK Specification v1.0.0
(spec 05, P1).  Every setter returns ``self`` to allow method chaining.  Required fields
(``sender``, ``payload``, ``chain_id``) must be set before calling :meth:`build`.

Optional fields default to safe values:

* ``max_gas_amount`` — 200 000 gas units
* ``gas_unit_price`` — 100 octas per gas unit
* ``expiration_timestamp_secs`` — 60 seconds from the time :meth:`build` is called
* ``sequence_number`` — 0 (should be overridden by the client from on-chain state)

Depending on which optional builder methods are called, :meth:`build` returns one of:

* :class:`~aptos_sdk.transactions.RawTransaction` — simple transaction (default)
* :class:`~aptos_sdk.transactions.MultiAgentRawTransaction` — when
  :meth:`secondary_signers` has been called
* :class:`~aptos_sdk.transactions.FeePayerRawTransaction` — when :meth:`fee_payer`
  has been called (including a call with ``None`` for an unknown fee payer)

Example
-------
::

    from aptos_sdk.transaction_builder import TransactionBuilder
    from aptos_sdk.account_address import AccountAddress
    from aptos_sdk.chain_id import ChainId

    txn = (
        TransactionBuilder()
        .sender(AccountAddress.from_hex("0x1"))
        .chain_id(ChainId(4))
        .entry_function(
            "0x1::aptos_account",
            "transfer",
            [],
            [recipient_bytes, amount_bytes],
        )
        .sequence_number(7)
        .build()
    )
"""

import time

from .account_address import AccountAddress
from .chain_id import ChainId
from .errors import MissingChainIdError, MissingPayloadError, MissingSenderError
from .transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    MultiAgentRawTransaction,
    RawTransaction,
    TransactionPayload,
)
from .type_tag import TypeTag

# Type alias for the union of transaction types returned by build().
_BuiltTransaction = RawTransaction | MultiAgentRawTransaction | FeePayerRawTransaction


class TransactionBuilder:
    """
    Fluent builder for Aptos :class:`~aptos_sdk.transactions.RawTransaction` objects.

    Each setter returns ``self`` so calls can be chained.  Call :meth:`build` once all
    required fields have been provided to obtain the final transaction object.

    Required fields
    ---------------
    * :meth:`sender` — the sending account address
    * :meth:`payload` (or :meth:`entry_function`) — the transaction payload
    * :meth:`chain_id` — the target chain identifier

    Optional fields
    ---------------
    * :meth:`max_gas_amount` — maximum gas units (default: 200 000)
    * :meth:`gas_unit_price` — gas price in octas (default: 100)
    * :meth:`expiration` — expiration timestamp in seconds (default: now + 60)
    * :meth:`sequence_number` — account sequence number (default: 0)

    Extended behaviour
    ------------------
    * :meth:`secondary_signers` — produce a
      :class:`~aptos_sdk.transactions.MultiAgentRawTransaction`
    * :meth:`fee_payer` — produce a
      :class:`~aptos_sdk.transactions.FeePayerRawTransaction`
    """

    # ------------------------------------------------------------------
    # Internal state
    # ------------------------------------------------------------------

    _sender: AccountAddress | None
    _sequence_number: int | None
    _payload: TransactionPayload | None
    _max_gas_amount: int
    _gas_unit_price: int
    _expiration_timestamp_secs: int | None
    _chain_id: ChainId | None
    _secondary_signers: list[AccountAddress] | None
    # _fee_payer stores the fee-payer address (may itself be None for an unknown payer).
    # _has_fee_payer acts as a sentinel: True once fee_payer() has been called at all.
    _fee_payer: AccountAddress | None
    _has_fee_payer: bool

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        self._sender = None
        self._sequence_number = None
        self._payload = None
        self._max_gas_amount = 200_000
        self._gas_unit_price = 100
        self._expiration_timestamp_secs = None
        self._chain_id = None
        self._secondary_signers = None
        self._fee_payer = None
        self._has_fee_payer = False

    # ------------------------------------------------------------------
    # Required-field setters
    # ------------------------------------------------------------------

    def sender(self, address: AccountAddress) -> "TransactionBuilder":
        """Set the sender's account address.

        Parameters
        ----------
        address:
            The :class:`~aptos_sdk.account_address.AccountAddress` of the transaction
            sender.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._sender = address
        return self

    def payload(self, payload: TransactionPayload) -> "TransactionBuilder":
        """Set the transaction payload directly.

        Use :meth:`entry_function` as a convenience alternative when building
        entry-function transactions.

        Parameters
        ----------
        payload:
            A fully constructed :class:`~aptos_sdk.transactions.TransactionPayload`.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._payload = payload
        return self

    def chain_id(self, chain_id: ChainId) -> "TransactionBuilder":
        """Set the target chain ID.

        Parameters
        ----------
        chain_id:
            A :class:`~aptos_sdk.chain_id.ChainId` identifying the Aptos network.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._chain_id = chain_id
        return self

    # ------------------------------------------------------------------
    # Optional-field setters
    # ------------------------------------------------------------------

    def max_gas_amount(self, amount: int) -> "TransactionBuilder":
        """Override the maximum gas amount (default: 200 000).

        Parameters
        ----------
        amount:
            Maximum number of gas units the transaction is allowed to consume.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._max_gas_amount = amount
        return self

    def gas_unit_price(self, price: int) -> "TransactionBuilder":
        """Override the gas unit price in octas (default: 100).

        Parameters
        ----------
        price:
            Price in octas (10^-8 APT) per gas unit.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._gas_unit_price = price
        return self

    def expiration(self, timestamp_secs: int) -> "TransactionBuilder":
        """Set the expiration timestamp for the transaction.

        If not called, :meth:`build` defaults to 60 seconds from the moment it is
        invoked.

        Parameters
        ----------
        timestamp_secs:
            Unix timestamp (seconds since epoch) after which the transaction is no
            longer valid.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._expiration_timestamp_secs = timestamp_secs
        return self

    def sequence_number(self, seq: int) -> "TransactionBuilder":
        """Set the sender's account sequence number (default: 0).

        The sequence number should normally be fetched from the chain via
        :meth:`~aptos_sdk.async_client.RestClient.account_sequence_number` and set here
        before calling :meth:`build`.

        Parameters
        ----------
        seq:
            The account's current on-chain sequence number.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._sequence_number = seq
        return self

    # ------------------------------------------------------------------
    # Convenience setters
    # ------------------------------------------------------------------

    def entry_function(
        self,
        module: str,
        function: str,
        type_args: list[TypeTag],
        args: list[bytes],
    ) -> "TransactionBuilder":
        """Convenience method to build an entry-function payload and set it.

        Calls :meth:`~aptos_sdk.transactions.EntryFunction.natural` internally and
        wraps the result in a :class:`~aptos_sdk.transactions.TransactionPayload`.

        Parameters
        ----------
        module:
            Fully-qualified module identifier, e.g. ``"0x1::aptos_account"``.
        function:
            The entry function name, e.g. ``"transfer"``.
        type_args:
            List of :class:`~aptos_sdk.type_tag.TypeTag` type arguments (may be empty).
        args:
            List of BCS-encoded argument bytes.  Each element must already be BCS
            encoded (e.g. via :class:`~aptos_sdk.bcs.Serializer`).

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        # NOTE: The existing transactions.py still uses the legacy signature
        # EntryFunction.natural(..., args: list[TransactionArgument]).  The new spec
        # (design doc §3.6, breaking changes table) changes `args` to `list[bytes]`
        # (pre-BCS-encoded).  This will be resolved when transactions.py is updated
        # in Phase 3.  The type: ignore suppresses the mismatch until then.
        entry_fn = EntryFunction.natural(module, function, type_args, args)  # type: ignore[arg-type]
        self._payload = TransactionPayload(entry_fn)
        return self

    def secondary_signers(self, signers: list[AccountAddress]) -> "TransactionBuilder":
        """Configure secondary signers for a multi-agent transaction.

        When set, :meth:`build` returns a
        :class:`~aptos_sdk.transactions.MultiAgentRawTransaction` instead of a plain
        :class:`~aptos_sdk.transactions.RawTransaction`.

        Note: if both :meth:`secondary_signers` and :meth:`fee_payer` are called,
        :meth:`fee_payer` takes precedence and a
        :class:`~aptos_sdk.transactions.FeePayerRawTransaction` is produced (which
        carries the secondary signer list internally).

        Parameters
        ----------
        signers:
            List of :class:`~aptos_sdk.account_address.AccountAddress` objects for
            each secondary signer.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._secondary_signers = signers
        return self

    def fee_payer(self, address: AccountAddress | None = None) -> "TransactionBuilder":
        """Configure a fee payer for a sponsored transaction.

        When called (even with ``None``), :meth:`build` returns a
        :class:`~aptos_sdk.transactions.FeePayerRawTransaction` instead of a plain
        :class:`~aptos_sdk.transactions.RawTransaction`.

        Pass ``None`` (or call with no argument) when the fee payer's address is not yet
        known at transaction construction time; the placeholder ``0x0`` address will be
        used in serialization per the Aptos protocol.

        Parameters
        ----------
        address:
            The :class:`~aptos_sdk.account_address.AccountAddress` of the entity paying
            the gas fee, or ``None`` if the fee payer is to be determined later.

        Returns
        -------
        TransactionBuilder
            ``self`` for method chaining.
        """
        self._fee_payer = address
        self._has_fee_payer = True
        return self

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self) -> _BuiltTransaction:
        """Validate all required fields and construct the transaction object.

        Required fields
        ---------------
        * ``sender`` — raises :class:`~aptos_sdk.errors.MissingSenderError` if absent
        * ``payload`` — raises :class:`~aptos_sdk.errors.MissingPayloadError` if absent
        * ``chain_id`` — raises :class:`~aptos_sdk.errors.MissingChainIdError` if absent

        Optional field resolution
        -------------------------
        * ``sequence_number`` defaults to ``0``
        * ``max_gas_amount`` defaults to ``200_000``
        * ``gas_unit_price`` defaults to ``100``
        * ``expiration_timestamp_secs`` defaults to ``int(time.time()) + 60``

        Returns
        -------
        RawTransaction | MultiAgentRawTransaction | FeePayerRawTransaction
            * :class:`~aptos_sdk.transactions.FeePayerRawTransaction` when
              :meth:`fee_payer` was called.
            * :class:`~aptos_sdk.transactions.MultiAgentRawTransaction` when
              :meth:`secondary_signers` was called (and :meth:`fee_payer` was not).
            * :class:`~aptos_sdk.transactions.RawTransaction` otherwise.

        Raises
        ------
        MissingSenderError
            If the sender address has not been set.
        MissingPayloadError
            If no payload (entry function, script, or multisig) has been set.
        MissingChainIdError
            If the chain ID has not been set.
        """
        # ---- Validate required fields ----
        if self._sender is None:
            raise MissingSenderError(
                "Transaction sender address must be set before calling build()."
            )

        if self._payload is None:
            raise MissingPayloadError(
                "Transaction payload must be set before calling build(). "
                "Use .payload(), .entry_function(), or another payload setter."
            )

        if self._chain_id is None:
            raise MissingChainIdError(
                "Transaction chain_id must be set before calling build()."
            )

        # ---- Resolve optional fields ----
        sequence_number: int = (
            self._sequence_number if self._sequence_number is not None else 0
        )

        expiration_timestamp_secs: int = (
            self._expiration_timestamp_secs
            if self._expiration_timestamp_secs is not None
            else int(time.time()) + 60
        )

        # ---- Construct the inner RawTransaction ----
        raw_txn = RawTransaction(
            self._sender,
            sequence_number,
            self._payload,
            self._max_gas_amount,
            self._gas_unit_price,
            expiration_timestamp_secs,
            self._chain_id.value,
        )

        # ---- Wrap in extended transaction type if needed ----
        #
        # Fee-payer takes precedence over multi-agent: a fee-payer transaction may
        # also carry secondary signers.
        if self._has_fee_payer:
            secondary: list[AccountAddress] = (
                self._secondary_signers if self._secondary_signers is not None else []
            )
            return FeePayerRawTransaction(raw_txn, secondary, self._fee_payer)

        if self._secondary_signers is not None:
            return MultiAgentRawTransaction(raw_txn, self._secondary_signers)

        return raw_txn
