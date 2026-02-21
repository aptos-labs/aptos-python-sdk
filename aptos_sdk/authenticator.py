# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Transaction and account authenticators for the Aptos Python SDK (Spec 05/07).

This module provides two tagged-union authenticator hierarchies:

TransactionAuthenticator (also exported as ``Authenticator`` for back-compat)
    Wraps the top-level authenticator embedded in a :class:`SignedTransaction`.
    Variants: Ed25519(0), MultiEd25519(1), MultiAgent(2), FeePayer(3),
    SingleSender(4).

AccountAuthenticator
    Wraps per-account authentication information used by MultiAgent and
    FeePayer transactions, and by the SingleSender variant.
    Variants: Ed25519(0), MultiEd25519(1), SingleKey(2), MultiKey(3).

Concrete authenticator classes
    Ed25519Authenticator         — single Ed25519 key + signature
    MultiEd25519Authenticator    — multi-Ed25519 key + signature
    SingleKeyAuthenticator       — AnyPublicKey + AnySignature (any scheme)
    MultiKeyAuthenticator        — MultiKeyPublicKey + MultiKeySignature
    SingleSenderAuthenticator    — AccountAuthenticator envelope
    MultiAgentAuthenticator      — sender + secondary (address, auth) pairs
    FeePayerAuthenticator        — sender + secondary pairs + fee-payer pair
"""

from . import crypto_wrapper, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .bcs import Deserializer, Serializer
from .errors import InvalidInputError

# ---------------------------------------------------------------------------
# Ed25519Authenticator
# ---------------------------------------------------------------------------


class Ed25519Authenticator:
    """
    A single Ed25519 public key paired with its signature.

    Used as the inner payload for both :class:`TransactionAuthenticator` (variant 0)
    and :class:`AccountAuthenticator` (variant 0).

    Parameters
    ----------
    public_key:
        The :class:`~aptos_sdk.ed25519.Ed25519PublicKey` to verify against.
    signature:
        The :class:`~aptos_sdk.ed25519.Ed25519Signature` to verify.
    """

    public_key: ed25519.Ed25519PublicKey
    signature: ed25519.Ed25519Signature

    def __init__(
        self,
        public_key: ed25519.Ed25519PublicKey,
        signature: ed25519.Ed25519Signature,
    ) -> None:
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Authenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* using this authenticator's public key and signature.

        Returns ``True`` if the signature is valid; ``False`` otherwise.
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519Authenticator":
        """Deserialize an :class:`Ed25519Authenticator` from *deserializer*."""
        key = deserializer.struct(ed25519.Ed25519PublicKey)
        signature = deserializer.struct(ed25519.Ed25519Signature)
        return Ed25519Authenticator(key, signature)

    def serialize(self, serializer: Serializer) -> None:
        """Serialize this authenticator: ``struct(public_key) || struct(signature)``."""
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


# ---------------------------------------------------------------------------
# MultiEd25519Authenticator
# ---------------------------------------------------------------------------


class MultiEd25519Authenticator:
    """
    A Multi-Ed25519 public key paired with its aggregated signature.

    Used as the inner payload for both :class:`TransactionAuthenticator` (variant 1)
    and :class:`AccountAuthenticator` (variant 1).

    Parameters
    ----------
    public_key:
        The :class:`~aptos_sdk.ed25519.MultiEd25519PublicKey` to verify against.
    signature:
        The :class:`~aptos_sdk.ed25519.MultiEd25519Signature` to verify.
    """

    public_key: ed25519.MultiEd25519PublicKey
    signature: ed25519.MultiEd25519Signature

    def __init__(
        self,
        public_key: ed25519.MultiEd25519PublicKey,
        signature: ed25519.MultiEd25519Signature,
    ) -> None:
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiEd25519Authenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* using this authenticator's multi-key and multi-signature.

        Returns ``True`` if at least ``threshold`` valid signatures are present;
        ``False`` otherwise.
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiEd25519Authenticator":
        """Deserialize a :class:`MultiEd25519Authenticator` from *deserializer*."""
        key = deserializer.struct(ed25519.MultiEd25519PublicKey)
        signature = deserializer.struct(ed25519.MultiEd25519Signature)
        return MultiEd25519Authenticator(key, signature)

    def serialize(self, serializer: Serializer) -> None:
        """Serialize: ``struct(public_key) || struct(signature)``."""
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


# ---------------------------------------------------------------------------
# SingleKeyAuthenticator
# ---------------------------------------------------------------------------


class SingleKeyAuthenticator:
    """
    An :class:`~aptos_sdk.crypto_wrapper.AnyPublicKey` paired with an
    :class:`~aptos_sdk.crypto_wrapper.AnySignature`.

    Used as the inner payload for :class:`AccountAuthenticator` (variant 2).
    Supports any key scheme wrapped in the ``AnyPublicKey`` / ``AnySignature``
    tagged-union types.

    Bare concrete keys and signatures (Ed25519, Secp256k1) are automatically
    wrapped when passed to the constructor.

    Parameters
    ----------
    public_key:
        An :class:`~aptos_sdk.crypto_wrapper.AnyPublicKey`, or a concrete
        ``Ed25519PublicKey`` / ``Secp256k1PublicKey`` (auto-wrapped).
    signature:
        An :class:`~aptos_sdk.crypto_wrapper.AnySignature`, or a concrete
        ``Ed25519Signature`` / ``Secp256k1Signature`` (auto-wrapped).
    """

    public_key: crypto_wrapper.AnyPublicKey
    signature: crypto_wrapper.AnySignature

    def __init__(
        self,
        public_key: (
            crypto_wrapper.AnyPublicKey
            | ed25519.Ed25519PublicKey
            | secp256k1_ecdsa.Secp256k1PublicKey
        ),
        signature: (
            crypto_wrapper.AnySignature
            | ed25519.Ed25519Signature
            | secp256k1_ecdsa.Secp256k1Signature
        ),
    ) -> None:
        if isinstance(public_key, crypto_wrapper.AnyPublicKey):
            self.public_key = public_key
        else:
            self.public_key = crypto_wrapper.AnyPublicKey(public_key)

        if isinstance(signature, crypto_wrapper.AnySignature):
            self.signature = signature
        else:
            self.signature = crypto_wrapper.AnySignature(signature)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SingleKeyAuthenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* using the wrapped public key and signature.

        Returns ``True`` if the inner signature is valid; ``False`` otherwise.
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SingleKeyAuthenticator":
        """Deserialize a :class:`SingleKeyAuthenticator` from *deserializer*."""
        public_key = deserializer.struct(crypto_wrapper.AnyPublicKey)
        signature = deserializer.struct(crypto_wrapper.AnySignature)
        return SingleKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer) -> None:
        """Serialize: ``struct(public_key) || struct(signature)``."""
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


# ---------------------------------------------------------------------------
# MultiKeyAuthenticator
# ---------------------------------------------------------------------------


class MultiKeyAuthenticator:
    """
    A :class:`~aptos_sdk.crypto_wrapper.MultiKeyPublicKey` paired with a
    :class:`~aptos_sdk.crypto_wrapper.MultiKeySignature`.

    Used as the inner payload for :class:`AccountAuthenticator` (variant 3).

    Parameters
    ----------
    public_key:
        The :class:`~aptos_sdk.crypto_wrapper.MultiKeyPublicKey` to verify against.
    signature:
        The :class:`~aptos_sdk.crypto_wrapper.MultiKeySignature` to verify.
    """

    public_key: crypto_wrapper.MultiKeyPublicKey
    signature: crypto_wrapper.MultiKeySignature

    def __init__(
        self,
        public_key: crypto_wrapper.MultiKeyPublicKey,
        signature: crypto_wrapper.MultiKeySignature,
    ) -> None:
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiKeyAuthenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* using the multi-key set and multi-signature.

        Returns ``True`` if at least ``threshold`` valid signatures are present;
        ``False`` otherwise.
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiKeyAuthenticator":
        """Deserialize a :class:`MultiKeyAuthenticator` from *deserializer*."""
        public_key = deserializer.struct(crypto_wrapper.MultiKeyPublicKey)
        signature = deserializer.struct(crypto_wrapper.MultiKeySignature)
        return MultiKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer) -> None:
        """Serialize: ``struct(public_key) || struct(signature)``."""
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


# ---------------------------------------------------------------------------
# AccountAuthenticator
# ---------------------------------------------------------------------------

# Forward-declare the inner type alias for clarity in type annotations.
_AccountAuthInner = (
    Ed25519Authenticator
    | MultiEd25519Authenticator
    | SingleKeyAuthenticator
    | MultiKeyAuthenticator
)


class AccountAuthenticator:
    """
    A tagged-union wrapper for per-account authentication information.

    Used directly by :class:`SingleSenderAuthenticator`,
    :class:`MultiAgentAuthenticator`, and :class:`FeePayerAuthenticator`.

    Variant constants
    -----------------
    ED25519 = 0
        Inner type: :class:`Ed25519Authenticator`
    MULTI_ED25519 = 1
        Inner type: :class:`MultiEd25519Authenticator`
    SINGLE_KEY = 2
        Inner type: :class:`SingleKeyAuthenticator`
    MULTI_KEY = 3
        Inner type: :class:`MultiKeyAuthenticator`

    Parameters
    ----------
    authenticator:
        One of the four concrete inner authenticator types listed above.
        The variant index is auto-detected from the type.

    Raises
    ------
    InvalidInputError
        If *authenticator* is not one of the supported inner types.
    """

    ED25519: int = 0
    MULTI_ED25519: int = 1
    SINGLE_KEY: int = 2
    MULTI_KEY: int = 3

    variant: int
    authenticator: _AccountAuthInner

    def __init__(self, authenticator: _AccountAuthInner) -> None:
        match authenticator:
            case Ed25519Authenticator():
                self.variant = AccountAuthenticator.ED25519
            case MultiEd25519Authenticator():
                self.variant = AccountAuthenticator.MULTI_ED25519
            case SingleKeyAuthenticator():
                self.variant = AccountAuthenticator.SINGLE_KEY
            case MultiKeyAuthenticator():
                self.variant = AccountAuthenticator.MULTI_KEY
            case _:
                raise InvalidInputError(
                    f"Unsupported AccountAuthenticator inner type: "
                    f"{type(authenticator).__name__!r}. "
                    "Expected Ed25519Authenticator, MultiEd25519Authenticator, "
                    "SingleKeyAuthenticator, or MultiKeyAuthenticator."
                )
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAuthenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return str(self.authenticator)

    def verify(self, data: bytes) -> bool:
        """
        Delegate verification to the inner authenticator.

        Returns ``True`` if the inner signature(s) are valid against *data*;
        ``False`` otherwise.
        """
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AccountAuthenticator":
        """
        Deserialize an :class:`AccountAuthenticator` from *deserializer*.

        Reads a ULEB128 variant index and then the corresponding inner
        authenticator.

        Raises
        ------
        InvalidInputError
            If the variant index is not one of the four known values.
        """
        variant = deserializer.variant_index()

        match variant:
            case AccountAuthenticator.ED25519:
                inner: _AccountAuthInner = Ed25519Authenticator.deserialize(
                    deserializer
                )
            case AccountAuthenticator.MULTI_ED25519:
                inner = MultiEd25519Authenticator.deserialize(deserializer)
            case AccountAuthenticator.SINGLE_KEY:
                inner = SingleKeyAuthenticator.deserialize(deserializer)
            case AccountAuthenticator.MULTI_KEY:
                inner = MultiKeyAuthenticator.deserialize(deserializer)
            case _:
                raise InvalidInputError(
                    f"Unknown AccountAuthenticator variant index: {variant}. "
                    "Expected 0 (ED25519), 1 (MULTI_ED25519), "
                    "2 (SINGLE_KEY), or 3 (MULTI_KEY)."
                )

        return AccountAuthenticator(inner)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this authenticator.

        Writes a ULEB128 variant index followed by the inner authenticator.
        """
        serializer.variant_index(self.variant)
        serializer.struct(self.authenticator)


# ---------------------------------------------------------------------------
# SingleSenderAuthenticator
# ---------------------------------------------------------------------------


class SingleSenderAuthenticator:
    """
    A :class:`TransactionAuthenticator` variant that wraps a single
    :class:`AccountAuthenticator`.

    Used as the inner payload for :class:`TransactionAuthenticator` (variant 4).
    This variant is used for single-sender transactions that employ any
    authentication scheme (Ed25519, Secp256k1 ECDSA, MultiKey, etc.).

    Parameters
    ----------
    sender:
        The :class:`AccountAuthenticator` for the transaction sender.
    """

    sender: AccountAuthenticator

    def __init__(self, sender: AccountAuthenticator) -> None:
        self.sender = sender

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SingleSenderAuthenticator):
            return NotImplemented
        return self.sender == other.sender

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"SingleSender: {self.sender}"

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* by delegating to the wrapped :class:`AccountAuthenticator`.

        Returns ``True`` if the sender's authenticator verifies *data*.
        """
        return self.sender.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SingleSenderAuthenticator":
        """Deserialize a :class:`SingleSenderAuthenticator` from *deserializer*."""
        sender = deserializer.struct(AccountAuthenticator)
        return SingleSenderAuthenticator(sender)

    def serialize(self, serializer: Serializer) -> None:
        """Serialize: ``struct(sender)``."""
        serializer.struct(self.sender)


# ---------------------------------------------------------------------------
# MultiAgentAuthenticator
# ---------------------------------------------------------------------------


class MultiAgentAuthenticator:
    """
    A :class:`TransactionAuthenticator` variant for multi-agent transactions.

    Carries the sender's :class:`AccountAuthenticator` and a list of
    ``(address, authenticator)`` pairs for each secondary signer.

    Used as the inner payload for :class:`TransactionAuthenticator` (variant 2).

    Parameters
    ----------
    sender:
        The :class:`AccountAuthenticator` for the transaction sender.
    secondary_signers:
        An ordered list of ``(AccountAddress, AccountAuthenticator)`` tuples,
        one per secondary signer.
    """

    sender: AccountAuthenticator
    secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]],
    ) -> None:
        self.sender = sender
        self.secondary_signers = secondary_signers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiAgentAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return (
            f"MultiAgent: \n\tSender: {self.sender}"
            f"\n\tSecondary Signers: {self.secondary_signers}"
        )

    def secondary_addresses(self) -> list[AccountAddress]:
        """Return the addresses of all secondary signers."""
        return [addr for addr, _ in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* for all participants.

        Returns ``True`` only when the sender and every secondary signer
        have valid signatures over *data*.
        """
        if not self.sender.verify(data):
            return False
        return all(auth.verify(data) for _, auth in self.secondary_signers)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiAgentAuthenticator":
        """
        Deserialize a :class:`MultiAgentAuthenticator` from *deserializer*.

        Reads:
        - ``struct(AccountAuthenticator)`` — sender
        - ``sequence(AccountAddress)`` — secondary addresses
        - ``sequence(AccountAuthenticator)`` — secondary authenticators

        The two sequences are zipped to form the ``secondary_signers`` list.
        """
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_auths = deserializer.sequence(AccountAuthenticator.deserialize)
        secondary_signers = list(zip(secondary_addresses, secondary_auths))
        return MultiAgentAuthenticator(sender, secondary_signers)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this authenticator.

        Writes:
        - ``struct(sender)``
        - ``sequence(secondary_addresses)``
        - ``sequence(secondary_authenticators)``
        """
        serializer.struct(self.sender)
        serializer.sequence(
            [addr for addr, _ in self.secondary_signers], Serializer.struct
        )
        serializer.sequence(
            [auth for _, auth in self.secondary_signers], Serializer.struct
        )


# ---------------------------------------------------------------------------
# FeePayerAuthenticator
# ---------------------------------------------------------------------------


class FeePayerAuthenticator:
    """
    A :class:`TransactionAuthenticator` variant for fee-payer transactions.

    Carries the sender's :class:`AccountAuthenticator`, optional secondary
    signer pairs, and the fee-payer ``(address, authenticator)`` pair.

    Used as the inner payload for :class:`TransactionAuthenticator` (variant 3).

    Parameters
    ----------
    sender:
        The :class:`AccountAuthenticator` for the transaction sender.
    secondary_signers:
        An ordered list of ``(AccountAddress, AccountAuthenticator)`` tuples,
        one per secondary signer.  May be empty.
    fee_payer:
        A ``(AccountAddress, AccountAuthenticator)`` tuple identifying the
        account that pays the transaction gas fee.
    """

    sender: AccountAuthenticator
    secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]]
    fee_payer: tuple[AccountAddress, AccountAuthenticator]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: list[tuple[AccountAddress, AccountAuthenticator]],
        fee_payer: tuple[AccountAddress, AccountAuthenticator],
    ) -> None:
        self.sender = sender
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FeePayerAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
            and self.fee_payer == other.fee_payer
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return (
            f"FeePayer: \n\tSender: {self.sender}"
            f"\n\tSecondary Signers: {self.secondary_signers}"
            f"\n\t{self.fee_payer}"
        )

    def fee_payer_address(self) -> AccountAddress:
        """Return the :class:`~aptos_sdk.account_address.AccountAddress` of the fee payer."""
        return self.fee_payer[0]

    def secondary_addresses(self) -> list[AccountAddress]:
        """Return the addresses of all secondary signers."""
        return [addr for addr, _ in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        """
        Verify *data* for all participants.

        Returns ``True`` only when the sender, the fee payer, and every
        secondary signer have valid signatures over *data*.
        """
        if not self.sender.verify(data):
            return False
        if not self.fee_payer[1].verify(data):
            return False
        return all(auth.verify(data) for _, auth in self.secondary_signers)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "FeePayerAuthenticator":
        """
        Deserialize a :class:`FeePayerAuthenticator` from *deserializer*.

        Reads:
        - ``struct(AccountAuthenticator)`` — sender
        - ``sequence(AccountAddress)`` — secondary addresses
        - ``sequence(AccountAuthenticator)`` — secondary authenticators
        - ``struct(AccountAddress)`` — fee-payer address
        - ``struct(AccountAuthenticator)`` — fee-payer authenticator

        The two secondary sequences are zipped to form ``secondary_signers``.
        """
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_auths = deserializer.sequence(AccountAuthenticator.deserialize)
        fee_payer_address = deserializer.struct(AccountAddress)
        fee_payer_auth = deserializer.struct(AccountAuthenticator)
        secondary_signers = list(zip(secondary_addresses, secondary_auths))
        return FeePayerAuthenticator(
            sender,
            secondary_signers,
            (fee_payer_address, fee_payer_auth),
        )

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this authenticator.

        Writes:
        - ``struct(sender)``
        - ``sequence(secondary_addresses)``
        - ``sequence(secondary_authenticators)``
        - ``struct(fee_payer_address)``
        - ``struct(fee_payer_authenticator)``
        """
        serializer.struct(self.sender)
        serializer.sequence(
            [addr for addr, _ in self.secondary_signers], Serializer.struct
        )
        serializer.sequence(
            [auth for _, auth in self.secondary_signers], Serializer.struct
        )
        serializer.struct(self.fee_payer[0])
        serializer.struct(self.fee_payer[1])


# ---------------------------------------------------------------------------
# TransactionAuthenticator (top-level tagged union)
# ---------------------------------------------------------------------------

# Forward-declare the inner type alias used by TransactionAuthenticator.
_TxnAuthInner = (
    Ed25519Authenticator
    | MultiEd25519Authenticator
    | MultiAgentAuthenticator
    | FeePayerAuthenticator
    | SingleSenderAuthenticator
)


class TransactionAuthenticator:
    """
    The top-level authenticator embedded in a :class:`SignedTransaction`.

    This tagged union identifies how the transaction was signed and carries
    all public keys and signatures needed for verification.

    Variant constants
    -----------------
    ED25519 = 0
        Inner type: :class:`Ed25519Authenticator`
    MULTI_ED25519 = 1
        Inner type: :class:`MultiEd25519Authenticator`
    MULTI_AGENT = 2
        Inner type: :class:`MultiAgentAuthenticator`
    FEE_PAYER = 3
        Inner type: :class:`FeePayerAuthenticator`
    SINGLE_SENDER = 4
        Inner type: :class:`SingleSenderAuthenticator`

    Parameters
    ----------
    authenticator:
        One of the five concrete inner authenticator types listed above.
        The variant index is auto-detected from the type.

    Raises
    ------
    InvalidInputError
        If *authenticator* is not one of the supported inner types.
    """

    ED25519: int = 0
    MULTI_ED25519: int = 1
    MULTI_AGENT: int = 2
    FEE_PAYER: int = 3
    SINGLE_SENDER: int = 4

    variant: int
    authenticator: _TxnAuthInner

    def __init__(self, authenticator: _TxnAuthInner) -> None:
        match authenticator:
            case Ed25519Authenticator():
                self.variant = TransactionAuthenticator.ED25519
            case MultiEd25519Authenticator():
                self.variant = TransactionAuthenticator.MULTI_ED25519
            case MultiAgentAuthenticator():
                self.variant = TransactionAuthenticator.MULTI_AGENT
            case FeePayerAuthenticator():
                self.variant = TransactionAuthenticator.FEE_PAYER
            case SingleSenderAuthenticator():
                self.variant = TransactionAuthenticator.SINGLE_SENDER
            case _:
                raise InvalidInputError(
                    f"Unsupported TransactionAuthenticator inner type: "
                    f"{type(authenticator).__name__!r}. "
                    "Expected Ed25519Authenticator, MultiEd25519Authenticator, "
                    "MultiAgentAuthenticator, FeePayerAuthenticator, or "
                    "SingleSenderAuthenticator."
                )
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TransactionAuthenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return str(self.authenticator)

    def verify(self, data: bytes) -> bool:
        """
        Delegate verification to the inner authenticator.

        Returns ``True`` if all inner signature(s) are valid against *data*;
        ``False`` otherwise.
        """
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "TransactionAuthenticator":
        """
        Deserialize a :class:`TransactionAuthenticator` from *deserializer*.

        Reads a ULEB128 variant index and then the corresponding inner
        authenticator.

        Raises
        ------
        InvalidInputError
            If the variant index is not one of the five known values.
        """
        variant = deserializer.variant_index()

        match variant:
            case TransactionAuthenticator.ED25519:
                inner: _TxnAuthInner = Ed25519Authenticator.deserialize(deserializer)
            case TransactionAuthenticator.MULTI_ED25519:
                inner = MultiEd25519Authenticator.deserialize(deserializer)
            case TransactionAuthenticator.MULTI_AGENT:
                inner = MultiAgentAuthenticator.deserialize(deserializer)
            case TransactionAuthenticator.FEE_PAYER:
                inner = FeePayerAuthenticator.deserialize(deserializer)
            case TransactionAuthenticator.SINGLE_SENDER:
                inner = SingleSenderAuthenticator.deserialize(deserializer)
            case _:
                raise InvalidInputError(
                    f"Unknown TransactionAuthenticator variant index: {variant}. "
                    "Expected 0 (ED25519), 1 (MULTI_ED25519), 2 (MULTI_AGENT), "
                    "3 (FEE_PAYER), or 4 (SINGLE_SENDER)."
                )

        return TransactionAuthenticator(inner)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this authenticator.

        Writes a ULEB128 variant index followed by the inner authenticator.
        """
        serializer.variant_index(self.variant)
        serializer.struct(self.authenticator)


# ---------------------------------------------------------------------------
# Back-compat alias
# ---------------------------------------------------------------------------

#: Backward-compatible alias: ``Authenticator`` → :class:`TransactionAuthenticator`
Authenticator = TransactionAuthenticator
