# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Transaction types, payloads, signing, and serialization for the Aptos Python SDK.

This module implements the full transaction lifecycle as specified in Spec 05:

* :class:`RawTransaction` — unsigned transaction with all fields.
* :class:`RawTransactionWithData` — base for multi-signer variants.
* :class:`MultiAgentRawTransaction` — multi-agent signing variant.
* :class:`FeePayerRawTransaction` — fee-payer signing variant.
* :class:`TransactionPayload` — tagged union of payload types.
* :class:`EntryFunction` — entry function call payload.
* :class:`Script` — Move script payload.
* :class:`ScriptArgument` — tagged script argument values.
* :class:`Multisig` — multisig account payload.
* :class:`ModuleId` — fully-qualified Move module identifier.
* :class:`TransactionArgument` — legacy argument encoding helper.
* :class:`SignedTransaction` — signed transaction ready for submission.

Domain-separated signing messages follow the pattern::

    signing_bytes = HashPrefix.RAW_TRANSACTION + BCS(raw_txn)
"""

from typing import Any, Callable, cast

from . import ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .authenticator import (
    AccountAuthenticator,
    Ed25519Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
    SingleKeyAuthenticator,
    SingleSenderAuthenticator,
    TransactionAuthenticator,
)
from .bcs import Deserializer, Serializer
from .chain_id import ChainId
from .errors import InvalidInputError
from .hashing import HashPrefix
from .type_tag import TypeTag

# ---------------------------------------------------------------------------
# ModuleId
# ---------------------------------------------------------------------------


class ModuleId:
    """
    A fully-qualified Move module identifier: ``address::module_name``.

    Example: ``0x1::coin``.

    This class mirrors :class:`~aptos_sdk.type_tag.MoveModuleId` and is
    kept here for backward compatibility with callers that use
    ``transactions.ModuleId``.
    """

    address: AccountAddress
    name: str

    def __init__(self, address: AccountAddress, name: str) -> None:
        self.address = address
        self.name = name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModuleId):
            return NotImplemented
        return self.address == other.address and self.name == other.name

    def __str__(self) -> str:
        return f"{self.address}::{self.name}"

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def from_str(module_id: str) -> "ModuleId":
        """
        Parse a module ID string of the form ``0x1::module_name``.

        Raises
        ------
        InvalidInputError
            If the string does not contain exactly one ``::`` separator or
            either the address or module name is empty.
        """
        parts = module_id.split("::")
        if len(parts) != 2:
            raise InvalidInputError(
                f"Invalid ModuleId: expected 'address::module', got {module_id!r}"
            )
        addr_str, name = parts[0].strip(), parts[1].strip()
        if not addr_str or not name:
            raise InvalidInputError(
                f"Invalid ModuleId: address and module name must both be non-empty "
                f"in {module_id!r}"
            )
        return ModuleId(AccountAddress.from_str_relaxed(addr_str), name)

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``struct(address) + str(name)``."""
        self.address.serialize(serializer)
        serializer.str(self.name)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ModuleId":
        """BCS deserialize a :class:`ModuleId`."""
        address = AccountAddress.deserialize(deserializer)
        name = deserializer.str()
        return ModuleId(address, name)


# ---------------------------------------------------------------------------
# TransactionArgument  (legacy compatibility)
# ---------------------------------------------------------------------------


class TransactionArgument:
    """
    A legacy transaction argument that pairs a value with its BCS encoder.

    Used as the element type of the ``args`` list passed to
    :meth:`EntryFunction.natural` when callers have not pre-encoded
    their arguments.  :meth:`encode` serializes the value using
    the provided encoder function and returns the resulting bytes.

    Example::

        TransactionArgument(recipient, Serializer.struct)
        TransactionArgument(amount, Serializer.u64)
    """

    value: Any
    encoder: Callable[[Serializer, Any], None]

    def __init__(
        self,
        value: Any,
        encoder: Callable[[Serializer, Any], None],
    ) -> None:
        self.value = value
        self.encoder = encoder

    def encode(self) -> bytes:
        """Serialize ``self.value`` via ``self.encoder`` and return the bytes."""
        ser = Serializer()
        self.encoder(ser, self.value)
        return ser.output()


# ---------------------------------------------------------------------------
# ScriptArgument
# ---------------------------------------------------------------------------


class ScriptArgument:
    """
    A tagged-union script argument for Move script payloads.

    Variant constants
    -----------------
    U8, U64, U128, ADDRESS, U8_VECTOR, BOOL, U16, U32, U256

    The on-wire format is ``u8(variant) + encoded_value``.
    """

    U8: int = 0
    U64: int = 1
    U128: int = 2
    ADDRESS: int = 3
    U8_VECTOR: int = 4
    BOOL: int = 5
    U16: int = 6
    U32: int = 7
    U256: int = 8

    variant: int
    value: Any

    def __init__(self, variant: int, value: Any) -> None:
        if variant not in (
            ScriptArgument.U8,
            ScriptArgument.U64,
            ScriptArgument.U128,
            ScriptArgument.ADDRESS,
            ScriptArgument.U8_VECTOR,
            ScriptArgument.BOOL,
            ScriptArgument.U16,
            ScriptArgument.U32,
            ScriptArgument.U256,
        ):
            raise InvalidInputError(
                f"Invalid ScriptArgument variant: {variant}. "
                "Expected 0 (U8) through 8 (U256)."
            )
        self.variant = variant
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScriptArgument):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self) -> str:
        return f"[{self.variant}] {self.value}"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``u8(variant) + encoded_value``."""
        serializer.u8(self.variant)
        match self.variant:
            case ScriptArgument.U8:
                serializer.u8(self.value)
            case ScriptArgument.U16:
                serializer.u16(self.value)
            case ScriptArgument.U32:
                serializer.u32(self.value)
            case ScriptArgument.U64:
                serializer.u64(self.value)
            case ScriptArgument.U128:
                serializer.u128(self.value)
            case ScriptArgument.U256:
                serializer.u256(self.value)
            case ScriptArgument.ADDRESS:
                serializer.struct(self.value)
            case ScriptArgument.U8_VECTOR:
                serializer.to_bytes(self.value)
            case ScriptArgument.BOOL:
                serializer.bool(self.value)
            case _:
                raise InvalidInputError(
                    f"Invalid ScriptArgument variant {self.variant}"
                )

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ScriptArgument":
        """BCS deserialize a :class:`ScriptArgument`."""
        variant = deserializer.u8()
        match variant:
            case ScriptArgument.U8:
                value: Any = deserializer.u8()
            case ScriptArgument.U16:
                value = deserializer.u16()
            case ScriptArgument.U32:
                value = deserializer.u32()
            case ScriptArgument.U64:
                value = deserializer.u64()
            case ScriptArgument.U128:
                value = deserializer.u128()
            case ScriptArgument.U256:
                value = deserializer.u256()
            case ScriptArgument.ADDRESS:
                value = AccountAddress.deserialize(deserializer)
            case ScriptArgument.U8_VECTOR:
                value = deserializer.to_bytes()
            case ScriptArgument.BOOL:
                value = deserializer.bool()
            case _:
                raise InvalidInputError(f"Unknown ScriptArgument variant: {variant}")
        return ScriptArgument(variant, value)


# ---------------------------------------------------------------------------
# Script
# ---------------------------------------------------------------------------


class Script:
    """
    A Move script payload.

    Attributes
    ----------
    code : bytes
        The compiled Move bytecode.
    ty_args : list[TypeTag]
        Generic type arguments.
    args : list[ScriptArgument]
        Positional arguments.
    """

    code: bytes
    ty_args: list[TypeTag]
    args: list[ScriptArgument]

    def __init__(
        self,
        code: bytes,
        ty_args: list[TypeTag],
        args: list[ScriptArgument],
    ) -> None:
        self.code = code
        self.ty_args = ty_args
        self.args = args

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Script):
            return NotImplemented
        return (
            self.code == other.code
            and self.ty_args == other.ty_args
            and self.args == other.args
        )

    def __str__(self) -> str:
        return f"<{self.ty_args}>({self.args})"

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``to_bytes(code) + sequence(ty_args) + sequence(args)``."""
        serializer.to_bytes(self.code)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.struct)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Script":
        """BCS deserialize a :class:`Script`."""
        code = deserializer.to_bytes()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(ScriptArgument.deserialize)
        return Script(code, ty_args, args)


# ---------------------------------------------------------------------------
# EntryFunction
# ---------------------------------------------------------------------------


class EntryFunction:
    """
    An entry function call payload.

    Attributes
    ----------
    module : ModuleId
        The module that defines the entry function.
    function : str
        The name of the entry function.
    ty_args : list[TypeTag]
        Generic type arguments.
    args : list[bytes]
        Pre-encoded argument bytes (each individually BCS-serialized).
    """

    module: ModuleId
    function: str
    ty_args: list[TypeTag]
    args: list[bytes]

    def __init__(
        self,
        module: ModuleId,
        function: str,
        ty_args: list[TypeTag],
        args: list[bytes],
    ) -> None:
        self.module = module
        self.function = function
        self.ty_args = ty_args
        self.args = args

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntryFunction):
            return NotImplemented
        return (
            self.module == other.module
            and self.function == other.function
            and self.ty_args == other.ty_args
            and self.args == other.args
        )

    def __str__(self) -> str:
        return f"{self.module}::{self.function}::<{self.ty_args}>({self.args})"

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def natural(
        module: str,
        function: str,
        ty_args: list[TypeTag],
        args: list["TransactionArgument | bytes"],
    ) -> "EntryFunction":
        """
        Convenience constructor that parses the module string and encodes args.

        Parameters
        ----------
        module:
            A ``"address::module_name"`` string, e.g. ``"0x1::aptos_account"``.
        function:
            The entry function name.
        ty_args:
            Generic type arguments.
        args:
            Either :class:`TransactionArgument` instances (legacy) or raw
            ``bytes`` (already BCS-encoded).  Both styles may be mixed.

        Returns
        -------
        EntryFunction
        """
        module_id = ModuleId.from_str(module)
        byte_args: list[bytes] = []
        for arg in args:
            if isinstance(arg, TransactionArgument):
                byte_args.append(arg.encode())
            else:
                byte_args.append(arg)
        return EntryFunction(module_id, function, ty_args, byte_args)

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``struct(module) + str(function) + sequence(ty_args) + sequence(args)``."""
        self.module.serialize(serializer)
        serializer.str(self.function)
        serializer.sequence(self.ty_args, Serializer.struct)
        serializer.sequence(self.args, Serializer.to_bytes)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "EntryFunction":
        """BCS deserialize an :class:`EntryFunction`."""
        module = ModuleId.deserialize(deserializer)
        function = deserializer.str()
        ty_args = deserializer.sequence(TypeTag.deserialize)
        args = deserializer.sequence(Deserializer.to_bytes)
        return EntryFunction(module, function, ty_args, args)


# ---------------------------------------------------------------------------
# Multisig
# ---------------------------------------------------------------------------


class Multisig:
    """
    A multisig account payload (variant index 3).

    When ``entry_function`` is ``None`` the multisig transaction executes
    whatever payload is stored on-chain for the pending transaction.

    Attributes
    ----------
    multisig_address : AccountAddress
        The address of the multisig account.
    entry_function : EntryFunction | None
        Optional inline entry function payload.
    """

    multisig_address: AccountAddress
    entry_function: "EntryFunction | None"

    def __init__(
        self,
        multisig_address: AccountAddress,
        entry_function: "EntryFunction | None" = None,
    ) -> None:
        self.multisig_address = multisig_address
        self.entry_function = entry_function

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Multisig):
            return NotImplemented
        return (
            self.multisig_address == other.multisig_address
            and self.entry_function == other.entry_function
        )

    def __str__(self) -> str:
        return (
            f"Multisig({self.multisig_address}, "
            f"entry_function={self.entry_function})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``struct(address) + option(entry_function)``."""
        self.multisig_address.serialize(serializer)
        serializer.option(
            self.entry_function,
            lambda s, ef: s.struct(ef),
        )

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Multisig":
        """BCS deserialize a :class:`Multisig`."""
        multisig_address = AccountAddress.deserialize(deserializer)
        entry_function = deserializer.option(EntryFunction.deserialize)
        return Multisig(multisig_address, entry_function)


# ---------------------------------------------------------------------------
# ModuleBundle (deprecated, kept to support deserialization of old data)
# ---------------------------------------------------------------------------


class ModuleBundle:
    """
    Deprecated ModuleBundle payload.  Construction and deserialization raise
    ``NotImplementedError``; the class exists only to complete the variant
    table.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "ModuleBundle is deprecated and cannot be constructed."
        )

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ModuleBundle":
        raise NotImplementedError(
            "ModuleBundle is deprecated and cannot be deserialized."
        )

    def serialize(self, serializer: Serializer) -> None:
        raise NotImplementedError(
            "ModuleBundle is deprecated and cannot be serialized."
        )


# ---------------------------------------------------------------------------
# TransactionPayload
# ---------------------------------------------------------------------------


class TransactionPayload:
    """
    A tagged union of transaction payload types.

    Variant constants
    -----------------
    SCRIPT : int = 0
        A Move script (``Script``).
    MODULE_BUNDLE : int = 1
        Deprecated; raises ``NotImplementedError`` if encountered.
    ENTRY_FUNCTION : int = 2
        An entry function call (``EntryFunction``).
    MULTISIG : int = 3
        A multisig account payload (``Multisig``).

    The variant is auto-detected from the concrete payload type passed to
    ``__init__``.
    """

    SCRIPT: int = 0
    MODULE_BUNDLE: int = 1
    ENTRY_FUNCTION: int = 2
    # Legacy alias kept for callers that used SCRIPT_FUNCTION
    SCRIPT_FUNCTION: int = 2
    MULTISIG: int = 3

    variant: int
    value: Any

    def __init__(self, payload: Any) -> None:
        if isinstance(payload, Script):
            self.variant = TransactionPayload.SCRIPT
        elif isinstance(payload, ModuleBundle):
            self.variant = TransactionPayload.MODULE_BUNDLE
        elif isinstance(payload, EntryFunction):
            self.variant = TransactionPayload.ENTRY_FUNCTION
        elif isinstance(payload, Multisig):
            self.variant = TransactionPayload.MULTISIG
        else:
            raise InvalidInputError(
                f"Unsupported payload type: {type(payload).__name__}. "
                "Expected Script, EntryFunction, or Multisig."
            )
        self.value = payload

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionPayload):
            return NotImplemented
        return self.variant == other.variant and self.value == other.value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return self.__str__()

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``variant_index(variant) + struct(value)``."""
        serializer.variant_index(self.variant)
        self.value.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "TransactionPayload":
        """BCS deserialize a :class:`TransactionPayload`."""
        variant = deserializer.variant_index()
        match variant:
            case TransactionPayload.SCRIPT:
                payload: Any = Script.deserialize(deserializer)
            case TransactionPayload.MODULE_BUNDLE:
                raise NotImplementedError(
                    "ModuleBundle payload (variant 1) is deprecated."
                )
            case TransactionPayload.ENTRY_FUNCTION:
                payload = EntryFunction.deserialize(deserializer)
            case TransactionPayload.MULTISIG:
                payload = Multisig.deserialize(deserializer)
            case _:
                raise InvalidInputError(
                    f"Unknown TransactionPayload variant: {variant}"
                )
        return TransactionPayload(payload)


# ---------------------------------------------------------------------------
# RawTransaction
# ---------------------------------------------------------------------------


class RawTransaction:
    """
    An unsigned Aptos transaction.

    Attributes
    ----------
    sender : AccountAddress
        The account submitting the transaction.
    sequence_number : int
        Must match the sender's on-chain sequence number.
    payload : TransactionPayload
        The script, entry function, or multisig to execute.
    max_gas_amount : int
        Maximum total gas units to spend.
    gas_unit_price : int
        APT price per gas unit (in Octas).
    expiration_timestamp_secs : int
        Unix timestamp after which the transaction is invalid.
    chain_id : ChainId
        Identifies the target Aptos network.
    """

    sender: AccountAddress
    sequence_number: int
    payload: TransactionPayload
    max_gas_amount: int
    gas_unit_price: int
    expiration_timestamp_secs: int
    chain_id: ChainId

    def __init__(
        self,
        sender: AccountAddress,
        sequence_number: int,
        payload: TransactionPayload,
        max_gas_amount: int,
        gas_unit_price: int,
        expiration_timestamp_secs: int,
        chain_id: "ChainId | int",
    ) -> None:
        self.sender = sender
        self.sequence_number = sequence_number
        self.payload = payload
        self.max_gas_amount = max_gas_amount
        self.gas_unit_price = gas_unit_price
        self.expiration_timestamp_secs = expiration_timestamp_secs
        # Accept a bare int for backward compatibility.
        if isinstance(chain_id, int):
            self.chain_id = ChainId(chain_id)
        else:
            self.chain_id = chain_id

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RawTransaction):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.sequence_number == other.sequence_number
            and self.payload == other.payload
            and self.max_gas_amount == other.max_gas_amount
            and self.gas_unit_price == other.gas_unit_price
            and self.expiration_timestamp_secs == other.expiration_timestamp_secs
            and self.chain_id == other.chain_id
        )

    def __str__(self) -> str:
        return (
            f"RawTransaction:\n"
            f"    sender: {self.sender}\n"
            f"    sequence_number: {self.sequence_number}\n"
            f"    payload: {self.payload}\n"
            f"    max_gas_amount: {self.max_gas_amount}\n"
            f"    gas_unit_price: {self.gas_unit_price}\n"
            f"    expiration_timestamp_secs: {self.expiration_timestamp_secs}\n"
            f"    chain_id: {self.chain_id}\n"
        )

    # ------------------------------------------------------------------
    # Signing helpers
    # ------------------------------------------------------------------

    def signing_message(self) -> bytes:
        """
        Return the domain-separated signing bytes for this transaction.

        Returns ``HashPrefix.RAW_TRANSACTION + BCS(self)``.
        """
        ser = Serializer()
        self.serialize(ser)
        return HashPrefix.RAW_TRANSACTION + ser.output()

    def sign(self, private_key: Any) -> AccountAuthenticator:
        """
        Sign the transaction and return an :class:`AccountAuthenticator`.

        For :class:`~aptos_sdk.ed25519.Ed25519PrivateKey`:
            Creates an :class:`~aptos_sdk.authenticator.Ed25519Authenticator`.
        For :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1PrivateKey`:
            Creates a :class:`~aptos_sdk.authenticator.SingleKeyAuthenticator`.

        Parameters
        ----------
        private_key:
            An Ed25519 or Secp256k1 private key.

        Returns
        -------
        AccountAuthenticator
        """
        message = self.signing_message()
        signature = private_key.sign(message)
        if isinstance(signature, ed25519.Ed25519Signature):
            return AccountAuthenticator(
                Ed25519Authenticator(
                    cast(ed25519.Ed25519PublicKey, private_key.public_key()),
                    signature,
                )
            )
        return AccountAuthenticator(
            SingleKeyAuthenticator(private_key.public_key(), signature)
        )

    def sign_simulated(self, public_key: Any) -> AccountAuthenticator:
        """
        Create a zero-filled authenticator for simulation.

        Parameters
        ----------
        public_key:
            An Ed25519 or Secp256k1 public key.

        Returns
        -------
        AccountAuthenticator
        """
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return AccountAuthenticator(
                Ed25519Authenticator(
                    public_key,
                    ed25519.Ed25519Signature(b"\x00" * 64),
                )
            )
        if isinstance(public_key, secp256k1_ecdsa.Secp256k1PublicKey):
            return AccountAuthenticator(
                SingleKeyAuthenticator(
                    public_key,
                    secp256k1_ecdsa.Secp256k1Signature(b"\x00" * 64),
                )
            )
        raise NotImplementedError(
            f"sign_simulated: unsupported public key type {type(public_key).__name__!r}"
        )

    def verify(self, public_key: Any, signature: Any) -> bool:
        """
        Verify *signature* over this transaction's signing message.

        Parameters
        ----------
        public_key:
            The public key that should have produced *signature*.
        signature:
            The signature to verify.

        Returns
        -------
        bool
        """
        return public_key.verify(self.signing_message(), signature)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """
        BCS serialize the raw transaction.

        Wire format:
        ``struct(sender) + u64(seq_num) + struct(payload) +
        u64(max_gas) + u64(gas_price) + u64(expiration) + u8(chain_id)``

        Note: ``chain_id`` is serialized as a plain ``u8`` (not as a
        :class:`~aptos_sdk.chain_id.ChainId` struct) for wire compatibility.
        """
        self.sender.serialize(serializer)
        serializer.u64(self.sequence_number)
        self.payload.serialize(serializer)
        serializer.u64(self.max_gas_amount)
        serializer.u64(self.gas_unit_price)
        serializer.u64(self.expiration_timestamp_secs)
        serializer.u8(self.chain_id.value)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "RawTransaction":
        """BCS deserialize a :class:`RawTransaction`."""
        sender = AccountAddress.deserialize(deserializer)
        sequence_number = deserializer.u64()
        payload = TransactionPayload.deserialize(deserializer)
        max_gas_amount = deserializer.u64()
        gas_unit_price = deserializer.u64()
        expiration_timestamp_secs = deserializer.u64()
        chain_id = ChainId(deserializer.u8())
        return RawTransaction(
            sender,
            sequence_number,
            payload,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        )


# ---------------------------------------------------------------------------
# RawTransactionWithData  (abstract base for multi-signer variants)
# ---------------------------------------------------------------------------


class RawTransactionWithData:
    """
    Base class for multi-signer raw transaction variants.

    Subclasses use ``HashPrefix.RAW_TRANSACTION_WITH_DATA`` as the signing
    message prefix instead of ``HashPrefix.RAW_TRANSACTION``.

    Concrete subclasses:

    * :class:`MultiAgentRawTransaction` — variant byte ``0``
    * :class:`FeePayerRawTransaction` — variant byte ``1``
    """

    raw_transaction: RawTransaction

    # ------------------------------------------------------------------
    # Common interface
    # ------------------------------------------------------------------

    def inner(self) -> RawTransaction:
        """Return the underlying :class:`RawTransaction`."""
        return self.raw_transaction

    def signing_message(self) -> bytes:
        """
        Return the domain-separated signing bytes.

        Returns ``HashPrefix.RAW_TRANSACTION_WITH_DATA + BCS(self)``.
        """
        ser = Serializer()
        self.serialize(ser)
        return HashPrefix.RAW_TRANSACTION_WITH_DATA + ser.output()

    def sign(self, private_key: Any) -> AccountAuthenticator:
        """
        Sign using the ``RAW_TRANSACTION_WITH_DATA`` prefix.

        Parameters
        ----------
        private_key:
            An Ed25519 or Secp256k1 private key.

        Returns
        -------
        AccountAuthenticator
        """
        message = self.signing_message()
        signature = private_key.sign(message)
        if isinstance(signature, ed25519.Ed25519Signature):
            return AccountAuthenticator(
                Ed25519Authenticator(
                    cast(ed25519.Ed25519PublicKey, private_key.public_key()),
                    signature,
                )
            )
        return AccountAuthenticator(
            SingleKeyAuthenticator(private_key.public_key(), signature)
        )

    def sign_simulated(self, public_key: Any) -> AccountAuthenticator:
        """
        Create a zero-filled authenticator for simulation (with-data prefix).

        Parameters
        ----------
        public_key:
            An Ed25519 or Secp256k1 public key.

        Returns
        -------
        AccountAuthenticator
        """
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return AccountAuthenticator(
                Ed25519Authenticator(
                    public_key,
                    ed25519.Ed25519Signature(b"\x00" * 64),
                )
            )
        if isinstance(public_key, secp256k1_ecdsa.Secp256k1PublicKey):
            return AccountAuthenticator(
                SingleKeyAuthenticator(
                    public_key,
                    secp256k1_ecdsa.Secp256k1Signature(b"\x00" * 64),
                )
            )
        raise NotImplementedError(
            f"sign_simulated: unsupported public key type {type(public_key).__name__!r}"
        )

    def verify(self, public_key: Any, signature: Any) -> bool:
        """
        Verify *signature* over this transaction's signing message.

        Returns
        -------
        bool
        """
        return public_key.verify(self.signing_message(), signature)

    def serialize(self, serializer: Serializer) -> None:
        """Implemented by concrete subclasses."""
        raise NotImplementedError

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "RawTransactionWithData":
        """
        Dispatch deserialization based on the variant byte.

        Variant ``0`` → :class:`MultiAgentRawTransaction`.
        Variant ``1`` → :class:`FeePayerRawTransaction`.
        """
        variant = deserializer.u8()
        match variant:
            case 0:
                return MultiAgentRawTransaction._deserialize_inner(deserializer)
            case 1:
                return FeePayerRawTransaction._deserialize_inner(deserializer)
            case _:
                raise InvalidInputError(
                    f"Unknown RawTransactionWithData variant: {variant}"
                )


# ---------------------------------------------------------------------------
# MultiAgentRawTransaction
# ---------------------------------------------------------------------------


class MultiAgentRawTransaction(RawTransactionWithData):
    """
    A multi-agent raw transaction (variant byte ``0``).

    All listed secondary signers must also sign the transaction using the
    ``RAW_TRANSACTION_WITH_DATA`` signing prefix.

    Attributes
    ----------
    raw_transaction : RawTransaction
        The underlying transaction.
    secondary_signers : list[AccountAddress]
        Addresses of the secondary signers.
    """

    secondary_signers: list[AccountAddress]

    def __init__(
        self,
        raw_transaction: RawTransaction,
        secondary_signers: list[AccountAddress],
    ) -> None:
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``u8(0) + struct(raw_transaction) + sequence(secondary_signers)``."""
        serializer.u8(0)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiAgentRawTransaction":
        """BCS deserialize (reads and validates the ``0`` variant byte)."""
        variant = deserializer.u8()
        if variant != 0:
            raise InvalidInputError(
                f"Expected MultiAgentRawTransaction variant byte 0, got {variant}"
            )
        return MultiAgentRawTransaction._deserialize_inner(deserializer)

    @staticmethod
    def _deserialize_inner(
        deserializer: Deserializer,
    ) -> "MultiAgentRawTransaction":
        """Deserialize fields without reading the variant byte."""
        raw_transaction = RawTransaction.deserialize(deserializer)
        secondary_signers = deserializer.sequence(AccountAddress.deserialize)
        return MultiAgentRawTransaction(raw_transaction, secondary_signers)


# ---------------------------------------------------------------------------
# FeePayerRawTransaction
# ---------------------------------------------------------------------------


class FeePayerRawTransaction(RawTransactionWithData):
    """
    A fee-payer raw transaction (variant byte ``1``).

    The fee payer is the account that pays transaction fees on behalf of the
    sender.  When ``fee_payer`` is ``None`` the fee payer address is not yet
    known; it serializes as ``AccountAddress.ZERO`` on the wire.

    Attributes
    ----------
    raw_transaction : RawTransaction
        The underlying transaction.
    secondary_signers : list[AccountAddress]
        Addresses of secondary signers.
    fee_payer : AccountAddress | None
        The fee-payer address, or ``None`` if not yet assigned.
    """

    secondary_signers: list[AccountAddress]
    fee_payer: "AccountAddress | None"

    def __init__(
        self,
        raw_transaction: RawTransaction,
        secondary_signers: list[AccountAddress],
        fee_payer: "AccountAddress | None",
    ) -> None:
        self.raw_transaction = raw_transaction
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def serialize(self, serializer: Serializer) -> None:
        """
        BCS serialize:
        ``u8(1) + struct(raw_transaction) + sequence(secondary_signers) + struct(fee_payer)``

        When ``fee_payer`` is ``None``, ``AccountAddress.ZERO`` is serialized.
        """
        serializer.u8(1)
        serializer.struct(self.raw_transaction)
        serializer.sequence(self.secondary_signers, Serializer.struct)
        fee_payer_addr = (
            AccountAddress.ZERO if self.fee_payer is None else self.fee_payer
        )
        fee_payer_addr.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "FeePayerRawTransaction":
        """BCS deserialize (reads and validates the ``1`` variant byte)."""
        variant = deserializer.u8()
        if variant != 1:
            raise InvalidInputError(
                f"Expected FeePayerRawTransaction variant byte 1, got {variant}"
            )
        return FeePayerRawTransaction._deserialize_inner(deserializer)

    @staticmethod
    def _deserialize_inner(
        deserializer: Deserializer,
    ) -> "FeePayerRawTransaction":
        """Deserialize fields without reading the variant byte."""
        raw_transaction = RawTransaction.deserialize(deserializer)
        secondary_signers = deserializer.sequence(AccountAddress.deserialize)
        fee_payer_addr = AccountAddress.deserialize(deserializer)
        fee_payer: "AccountAddress | None" = (
            None if fee_payer_addr == AccountAddress.ZERO else fee_payer_addr
        )
        return FeePayerRawTransaction(raw_transaction, secondary_signers, fee_payer)


# ---------------------------------------------------------------------------
# SignedTransaction
# ---------------------------------------------------------------------------


class SignedTransaction:
    """
    A signed, submission-ready Aptos transaction.

    The authenticator is stored as a :class:`~aptos_sdk.authenticator.TransactionAuthenticator`.
    When an :class:`~aptos_sdk.authenticator.AccountAuthenticator` is passed
    to the constructor, it is automatically promoted to the correct
    :class:`TransactionAuthenticator` variant:

    * Ed25519 / MultiEd25519 variants → wrapped directly in
      :class:`TransactionAuthenticator`.
    * SingleKey / MultiKey variants → wrapped in
      :class:`~aptos_sdk.authenticator.SingleSenderAuthenticator` first,
      then in :class:`TransactionAuthenticator`.

    Attributes
    ----------
    transaction : RawTransaction
        The unsigned transaction.
    authenticator : TransactionAuthenticator
        The top-level transaction authenticator.
    """

    transaction: RawTransaction
    authenticator: TransactionAuthenticator

    def __init__(
        self,
        transaction: RawTransaction,
        authenticator: "AccountAuthenticator | TransactionAuthenticator",
    ) -> None:
        self.transaction = transaction
        if isinstance(authenticator, AccountAuthenticator):
            # Promote AccountAuthenticator to TransactionAuthenticator.
            if authenticator.variant in (
                AccountAuthenticator.ED25519,
                AccountAuthenticator.MULTI_ED25519,
            ):
                # Direct Ed25519 / MultiEd25519 — unwrap the inner authenticator
                # and build the TransactionAuthenticator directly.
                self.authenticator = TransactionAuthenticator(
                    authenticator.authenticator  # type: ignore[arg-type]
                )
            else:
                # SingleKey / MultiKey — wrap in SingleSenderAuthenticator.
                self.authenticator = TransactionAuthenticator(
                    SingleSenderAuthenticator(authenticator)
                )
        else:
            self.authenticator = authenticator

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedTransaction):
            return NotImplemented
        return (
            self.transaction == other.transaction
            and self.authenticator == other.authenticator
        )

    def __str__(self) -> str:
        return f"Transaction: {self.transaction}Authenticator: {self.authenticator}"

    def __repr__(self) -> str:
        return self.__str__()

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def bytes(self) -> bytes:
        """Return the full BCS-encoded signed transaction."""
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self) -> bool:
        """
        Verify the authenticator's signature(s) against the transaction.

        For multi-agent and fee-payer transactions the correct
        ``RAW_TRANSACTION_WITH_DATA``-prefixed signing message is
        reconstructed before verification.

        Returns
        -------
        bool
            ``True`` when all signatures are valid.
        """
        inner = self.authenticator.authenticator
        if isinstance(inner, MultiAgentAuthenticator):
            txn_with_data: RawTransactionWithData = MultiAgentRawTransaction(
                self.transaction, inner.secondary_addresses()
            )
            message = txn_with_data.signing_message()
        elif isinstance(inner, FeePayerAuthenticator):
            fee_payer_txn = FeePayerRawTransaction(
                self.transaction,
                inner.secondary_addresses(),
                inner.fee_payer_address(),
            )
            message = fee_payer_txn.signing_message()
        else:
            message = self.transaction.signing_message()
        return self.authenticator.verify(message)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """BCS serialize: ``struct(transaction) + struct(authenticator)``."""
        self.transaction.serialize(serializer)
        self.authenticator.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SignedTransaction":
        """BCS deserialize a :class:`SignedTransaction`."""
        transaction = RawTransaction.deserialize(deserializer)
        authenticator = TransactionAuthenticator.deserialize(deserializer)
        return SignedTransaction(transaction, authenticator)


# ---------------------------------------------------------------------------
# Backward-compatible alias: Authenticator → TransactionAuthenticator
# The old code used `Authenticator` as the top-level transaction authenticator.
# ---------------------------------------------------------------------------

#: Legacy alias.  New code should use ``TransactionAuthenticator`` directly.
Authenticator = TransactionAuthenticator
