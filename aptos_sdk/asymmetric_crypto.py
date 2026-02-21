# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Protocol definitions for asymmetric cryptography in the Aptos Python SDK (Spec 03).

This module defines the abstract protocols that all key and signature types must
satisfy, along with AIP-80 formatting utilities shared by concrete implementations.

AIP-80 Format
-------------
Private keys are represented as human-readable strings with an algorithm prefix to
prevent accidental cross-algorithm key reuse::

    "ed25519-priv-0x<64 hex chars>"
    "secp256k1-priv-0x<64 hex chars>"

See: https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md

Protocols
---------
:class:`PrivateKey`
    Key generation, signing, serialization, and AIP-80 I/O.
:class:`PublicKey`
    Bytes I/O, signature verification, and BCS serialization.
:class:`Signature`
    Bytes I/O and BCS serialization.
"""

import warnings
from enum import Enum

from typing_extensions import Protocol, runtime_checkable

from .bcs import Deserializer, Serializer
from .errors import InvalidPrivateKeyError

# ---------------------------------------------------------------------------
# Key variant enum
# ---------------------------------------------------------------------------


class PrivateKeyVariant(Enum):
    """
    Discriminant that identifies the elliptic-curve algorithm used by a key.

    Values are used to look up the corresponding AIP-80 prefix string and to
    tag private keys in human-readable serialization.
    """

    ED25519 = 0
    SECP256K1 = 1


# ---------------------------------------------------------------------------
# AIP-80 prefix table
# ---------------------------------------------------------------------------

#: Maps each :class:`PrivateKeyVariant` to its AIP-80 string prefix.
AIP80_PREFIXES: dict[PrivateKeyVariant, str] = {
    PrivateKeyVariant.ED25519: "ed25519-priv-",
    PrivateKeyVariant.SECP256K1: "secp256k1-priv-",
}


# ---------------------------------------------------------------------------
# Module-level AIP-80 helpers
# ---------------------------------------------------------------------------


def format_private_key(hex_str: str, variant: PrivateKeyVariant) -> str:
    """
    Format a hex private key string as an AIP-80 compliant string.

    Parameters
    ----------
    hex_str:
        The private key as a hex string, optionally ``0x``-prefixed.
        An already-AIP-80-prefixed value is also accepted and returned unchanged.
    variant:
        The key algorithm variant (Ed25519 or Secp256k1).

    Returns
    -------
    str
        AIP-80 string of the form ``"<prefix>0x<hex>"``.

    Examples
    --------
    >>> format_private_key("0xdeadbeef...", PrivateKeyVariant.ED25519)
    'ed25519-priv-0xdeadbeef...'
    """
    prefix = AIP80_PREFIXES[variant]

    # If it already starts with the prefix, extract the hex portion and
    # rebuild to ensure canonical form.
    if hex_str.startswith(prefix):
        hex_portion = hex_str[len(prefix) :]
        if not hex_portion.startswith("0x"):
            hex_portion = f"0x{hex_portion}"
        return f"{prefix}{hex_portion}"

    # Plain hex (with or without "0x").
    if not hex_str.startswith("0x"):
        hex_str = f"0x{hex_str}"
    return f"{prefix}{hex_str}"


def parse_hex_input(
    value: str | bytes,
    variant: PrivateKeyVariant,
    strict: bool | None = None,
) -> bytes:
    """
    Parse a private key from a hex string, AIP-80 string, or raw bytes.

    Parameters
    ----------
    value:
        - ``bytes``: returned as-is.
        - ``str`` with an AIP-80 prefix (e.g. ``"ed25519-priv-0x..."``): the hex
          portion is extracted and decoded.
        - ``str`` without an AIP-80 prefix: treated as a bare hex string (with or
          without a ``"0x"`` prefix).
    variant:
        The expected key algorithm.  The correct AIP-80 prefix is derived from this.
    strict:
        Controls behaviour when the input is not AIP-80 compliant:

        - ``True``:  raise :class:`~aptos_sdk.errors.InvalidPrivateKeyError` if the
          value is not AIP-80 prefixed.
        - ``False``: silently accept a plain hex string.
        - ``None`` (default): accept a plain hex string but emit a
          :class:`DeprecationWarning` recommending AIP-80 format.

    Returns
    -------
    bytes
        Raw private key bytes.

    Raises
    ------
    InvalidPrivateKeyError
        When *strict* is ``True`` and the input is not AIP-80 prefixed, or when
        the hex string is malformed.
    TypeError
        When *value* is not ``str`` or ``bytes``.
    """
    if isinstance(value, bytes):
        return value

    if not isinstance(value, str):
        raise TypeError(
            f"Expected str or bytes for private key input, got {type(value).__name__!r}"
        )

    prefix = AIP80_PREFIXES[variant]

    if value.startswith(prefix):
        # AIP-80 compliant: strip the prefix and decode the hex portion.
        hex_part = value[len(prefix) :]
        if hex_part.startswith("0x"):
            hex_part = hex_part[2:]
        try:
            return bytes.fromhex(hex_part)
        except ValueError as exc:
            raise InvalidPrivateKeyError(
                f"AIP-80 private key contains invalid hex digits: {value!r}"
            ) from exc

    # Not AIP-80 prefixed.
    if strict is True:
        raise InvalidPrivateKeyError(
            f"Private key must be in AIP-80 format "
            f"(expected prefix {prefix!r}), got: {value!r}"
        )

    if strict is None:
        warnings.warn(
            "It is recommended that private keys are AIP-80 compliant. "
            "See https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md",
            DeprecationWarning,
            stacklevel=3,
        )

    # Decode as plain hex.
    hex_part = value[2:] if value.startswith("0x") else value
    try:
        return bytes.fromhex(hex_part)
    except ValueError as exc:
        raise InvalidPrivateKeyError(
            f"Private key hex string contains invalid characters: {value!r}"
        ) from exc


# ---------------------------------------------------------------------------
# Signature protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Signature(Protocol):
    """
    Protocol for a cryptographic signature produced by a :class:`PrivateKey`.

    All concrete signature types (Ed25519Signature, Secp256k1Signature, …)
    must satisfy this protocol.
    """

    @staticmethod
    def from_bytes(data: bytes) -> "Signature":
        """Construct a :class:`Signature` from raw bytes."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw signature bytes."""
        ...

    def to_hex(self) -> str:
        """Return the signature as a ``0x``-prefixed lowercase hex string."""
        ...

    # BCS serialization ------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Write this signature into *serializer*."""
        ...

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Signature":
        """Read and return a :class:`Signature` from *deserializer*."""
        ...


# ---------------------------------------------------------------------------
# PublicKey protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class PublicKey(Protocol):
    """
    Protocol for an asymmetric public key used to verify signatures.

    Concrete implementations include ``Ed25519PublicKey`` and
    ``Secp256k1PublicKey``.
    """

    @staticmethod
    def from_bytes(data: bytes) -> "PublicKey":
        """Construct a :class:`PublicKey` from raw bytes."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw public key bytes."""
        ...

    def to_hex(self) -> str:
        """Return the public key as a ``0x``-prefixed lowercase hex string."""
        ...

    def verify(self, message: bytes, signature: Signature) -> bool:
        """
        Verify that *signature* is valid for *message* under this public key.

        Returns ``True`` on success; ``False`` on any verification failure.
        Does not raise on an invalid signature — callers should check the
        return value.
        """
        ...

    def to_crypto_bytes(self) -> bytes:
        """
        Return the bytes used for authentication key derivation.

        For most key types this is identical to :meth:`to_bytes`.  For
        ``MultiEd25519PublicKey`` it is a concatenation of individual key bytes
        followed by the threshold byte.
        """
        ...

    # BCS serialization ------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Write this public key into *serializer*."""
        ...

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "PublicKey":
        """Read and return a :class:`PublicKey` from *deserializer*."""
        ...


# ---------------------------------------------------------------------------
# PrivateKey protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class PrivateKey(Protocol):
    """
    Protocol for an asymmetric private key capable of generating signatures.

    Concrete implementations include ``Ed25519PrivateKey`` and
    ``Secp256k1PrivateKey``.

    Security note: ``__repr__`` must never expose key material.  Implementations
    should return a masked string such as ``"Ed25519PrivateKey(***)"`` .
    """

    @staticmethod
    def generate() -> "PrivateKey":
        """Generate a cryptographically random private key."""
        ...

    @staticmethod
    def from_bytes(data: bytes) -> "PrivateKey":
        """Construct a :class:`PrivateKey` from raw bytes."""
        ...

    @staticmethod
    def from_hex(hex_str: str) -> "PrivateKey":
        """Construct a :class:`PrivateKey` from a hex string or AIP-80 string."""
        ...

    def to_bytes(self) -> bytes:
        """Return the raw private key bytes."""
        ...

    def to_hex(self) -> str:
        """Return the private key as a ``0x``-prefixed lowercase hex string."""
        ...

    def public_key(self) -> PublicKey:
        """Derive and return the corresponding :class:`PublicKey`."""
        ...

    def sign(self, message: bytes) -> Signature:
        """Sign *message* and return the resulting :class:`Signature`."""
        ...

    # AIP-80 compliance ------------------------------------------------

    def to_aip80(self) -> str:
        """
        Serialize this private key as an AIP-80 compliant string.

        Returns a string of the form ``"<prefix>0x<hex>"``, for example::

            "ed25519-priv-0x4e5e3be6..."
        """
        ...

    @staticmethod
    def from_aip80(s: str) -> "PrivateKey":
        """
        Parse a private key from an AIP-80 string.

        Raises :class:`~aptos_sdk.errors.InvalidPrivateKeyError` if *s* does
        not carry the expected AIP-80 prefix for this key type.
        """
        ...

    @staticmethod
    def variant() -> PrivateKeyVariant:
        """Return the :class:`PrivateKeyVariant` for this key type."""
        ...

    # BCS serialization ------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Write this private key into *serializer*."""
        ...

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "PrivateKey":
        """Read and return a :class:`PrivateKey` from *deserializer*."""
        ...
