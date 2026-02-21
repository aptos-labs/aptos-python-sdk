# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Ed25519 cryptography for the Aptos Python SDK (Spec 03, P0).

This module provides:

* :class:`Ed25519PrivateKey` — 32-byte Ed25519 signing key backed by PyNaCl.
* :class:`Ed25519PublicKey` — 32-byte Ed25519 verification key.
* :class:`Ed25519Signature` — 64-byte Ed25519 signature.
* :class:`MultiEd25519PublicKey` — Multi-signature public key (keys + threshold).
* :class:`MultiEd25519Signature` — Multi-signature (indexed signatures + bitmap).

Authentication Key Derivation
-----------------------------
For an Ed25519 public key the authentication key is::

    SHA3-256(public_key_bytes || 0x00)

The scheme byte ``0x00`` is defined in
:attr:`~aptos_sdk.account_address.AuthKeyScheme.Ed25519`.

AIP-80 Private Key Format
--------------------------
Private keys are serialized in AIP-80 format as::

    "ed25519-priv-0x<64 lowercase hex chars>"

See https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md
"""

from __future__ import annotations

import nacl.exceptions
import nacl.signing

from .asymmetric_crypto import PrivateKeyVariant, format_private_key, parse_hex_input
from .bcs import Deserializer, Serializer
from .errors import (
    InvalidLengthError,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSignatureError,
)
from .hashing import sha3_256

# ---------------------------------------------------------------------------
# Ed25519Signature
# ---------------------------------------------------------------------------


class Ed25519Signature:
    """
    A 64-byte Ed25519 signature.

    Parameters
    ----------
    data:
        Exactly 64 bytes of signature data.

    Raises
    ------
    InvalidSignatureError
        If *data* is not exactly 64 bytes.
    """

    LENGTH: int = 64

    _data: bytes

    def __init__(self, data: bytes) -> None:
        if len(data) != Ed25519Signature.LENGTH:
            raise InvalidSignatureError(
                f"Ed25519 signature must be exactly {Ed25519Signature.LENGTH} bytes, "
                f"got {len(data)}."
            )
        self._data = data

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Signature):
            return NotImplemented
        return self._data == other._data

    def __repr__(self) -> str:
        return f"Ed25519Signature({self.to_hex()})"

    def __str__(self) -> str:
        return self.to_hex()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def from_bytes(data: bytes) -> "Ed25519Signature":
        """Construct an :class:`Ed25519Signature` from raw bytes."""
        return Ed25519Signature(data)

    @staticmethod
    def from_str(value: str) -> "Ed25519Signature":
        """
        Construct an :class:`Ed25519Signature` from a hex string.

        The ``0x`` prefix is optional.
        """
        if value.startswith("0x"):
            value = value[2:]
        try:
            return Ed25519Signature(bytes.fromhex(value))
        except ValueError as exc:
            raise InvalidSignatureError(
                f"Signature hex string contains invalid characters: {value!r}"
            ) from exc

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw 64-byte signature."""
        return self._data

    def to_hex(self) -> str:
        """Return the signature as a ``0x``-prefixed lowercase hex string."""
        return f"0x{self._data.hex()}"

    # Legacy accessor used by existing code (e.g. asymmetric_crypto_wrapper)
    def data(self) -> bytes:
        """Return the raw bytes (legacy alias for :meth:`to_bytes`)."""
        return self._data

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the signature bytes with a ULEB128 length prefix."""
        serializer.to_bytes(self._data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519Signature":
        """Deserialize an :class:`Ed25519Signature` from a length-prefixed buffer."""
        raw = deserializer.to_bytes()
        if len(raw) != Ed25519Signature.LENGTH:
            raise InvalidLengthError(
                f"Expected {Ed25519Signature.LENGTH} bytes for Ed25519 signature, "
                f"got {len(raw)}.",
                expected=Ed25519Signature.LENGTH,
                actual=len(raw),
            )
        return Ed25519Signature(raw)


# ---------------------------------------------------------------------------
# Ed25519PublicKey
# ---------------------------------------------------------------------------


class Ed25519PublicKey:
    """
    A 32-byte Ed25519 public key.

    Parameters
    ----------
    key:
        A PyNaCl :class:`nacl.signing.VerifyKey`.
    """

    LENGTH: int = 32

    _key: nacl.signing.VerifyKey

    def __init__(self, key: nacl.signing.VerifyKey) -> None:
        self._key = key

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PublicKey):
            return NotImplemented
        return self._key == other._key

    def __hash__(self) -> int:
        return hash(bytes(self._key))

    def __repr__(self) -> str:
        return f"Ed25519PublicKey({self.to_hex()})"

    def __str__(self) -> str:
        return self.to_hex()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def from_bytes(data: bytes) -> "Ed25519PublicKey":
        """
        Construct an :class:`Ed25519PublicKey` from raw bytes.

        Raises
        ------
        InvalidPublicKeyError
            If *data* is not exactly 32 bytes or fails curve validation.
        """
        if len(data) != Ed25519PublicKey.LENGTH:
            raise InvalidPublicKeyError(
                f"Ed25519 public key must be exactly {Ed25519PublicKey.LENGTH} bytes, "
                f"got {len(data)}."
            )
        try:
            return Ed25519PublicKey(nacl.signing.VerifyKey(data))
        except Exception as exc:
            raise InvalidPublicKeyError(
                f"Invalid Ed25519 public key bytes: {exc}"
            ) from exc

    @staticmethod
    def from_str(value: str) -> "Ed25519PublicKey":
        """
        Construct an :class:`Ed25519PublicKey` from a hex string.

        The ``0x`` prefix is optional.
        """
        if value.startswith("0x"):
            value = value[2:]
        try:
            return Ed25519PublicKey.from_bytes(bytes.fromhex(value))
        except ValueError as exc:
            raise InvalidPublicKeyError(
                f"Public key hex string contains invalid characters: {value!r}"
            ) from exc

    # ------------------------------------------------------------------
    # Byte I/O
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Return the public key as a ``0x``-prefixed lowercase hex string."""
        return f"0x{bytes(self._key).hex()}"

    def to_crypto_bytes(self) -> bytes:
        """
        Return the bytes used for authentication key derivation.

        For Ed25519 this is identical to :meth:`to_bytes`.
        """
        return self.to_bytes()

    # ------------------------------------------------------------------
    # Authentication key derivation
    # ------------------------------------------------------------------

    def auth_key(self) -> bytes:
        """
        Derive the authentication key for this public key.

        The authentication key is ``SHA3-256(public_key_bytes || 0x00)``
        where ``0x00`` is the Ed25519 scheme byte.
        """
        from .account_address import AuthKeyScheme  # noqa: PLC0415

        return sha3_256(self.to_bytes() + AuthKeyScheme.Ed25519)

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify(self, message: bytes, signature: Ed25519Signature) -> bool:
        """
        Verify that *signature* is valid for *message* under this public key.

        Returns ``True`` on success, ``False`` on any failure.
        """
        try:
            self._key.verify(message, signature.to_bytes())
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the public key bytes with a ULEB128 length prefix."""
        serializer.to_bytes(self.to_bytes())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519PublicKey":
        """Deserialize an :class:`Ed25519PublicKey` from a length-prefixed buffer."""
        raw = deserializer.to_bytes()
        if len(raw) != Ed25519PublicKey.LENGTH:
            raise InvalidLengthError(
                f"Expected {Ed25519PublicKey.LENGTH} bytes for Ed25519 public key, "
                f"got {len(raw)}.",
                expected=Ed25519PublicKey.LENGTH,
                actual=len(raw),
            )
        return Ed25519PublicKey.from_bytes(raw)


# ---------------------------------------------------------------------------
# Ed25519PrivateKey
# ---------------------------------------------------------------------------


class Ed25519PrivateKey:
    """
    A 32-byte Ed25519 private (signing) key.

    Parameters
    ----------
    key:
        A PyNaCl :class:`nacl.signing.SigningKey`.

    Security note: ``__repr__`` never exposes key material.
    """

    LENGTH: int = 32

    _key: nacl.signing.SigningKey

    def __init__(self, key: nacl.signing.SigningKey) -> None:
        self._key = key

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PrivateKey):
            return NotImplemented
        return bytes(self._key) == bytes(other._key)

    def __str__(self) -> str:
        """Return the AIP-80 representation."""
        return self.to_aip80()

    def __repr__(self) -> str:
        """Never expose key material in repr."""
        return "Ed25519PrivateKey(***)"

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def generate() -> "Ed25519PrivateKey":
        """Generate a cryptographically random Ed25519 private key."""
        return Ed25519PrivateKey(nacl.signing.SigningKey.generate())

    @staticmethod
    def from_bytes(data: bytes) -> "Ed25519PrivateKey":
        """
        Construct an :class:`Ed25519PrivateKey` from raw bytes.

        Raises
        ------
        InvalidPrivateKeyError
            If *data* is not exactly 32 bytes.
        """
        if len(data) != Ed25519PrivateKey.LENGTH:
            raise InvalidPrivateKeyError(
                f"Ed25519 private key must be exactly {Ed25519PrivateKey.LENGTH} bytes, "
                f"got {len(data)}."
            )
        try:
            return Ed25519PrivateKey(nacl.signing.SigningKey(data))
        except Exception as exc:
            raise InvalidPrivateKeyError(
                f"Invalid Ed25519 private key bytes: {exc}"
            ) from exc

    @staticmethod
    def from_hex(hex_str: str, strict: bool | None = None) -> "Ed25519PrivateKey":
        """
        Parse an Ed25519 private key from a hex or AIP-80 string.

        Parameters
        ----------
        hex_str:
            A plain hex string (with or without ``"0x"``) or an AIP-80 string
            (e.g. ``"ed25519-priv-0x..."``).
        strict:
            AIP-80 strictness flag forwarded to :func:`parse_hex_input`.

        Raises
        ------
        InvalidPrivateKeyError
            If the string is malformed or not AIP-80 when *strict=True*.
        """
        raw = parse_hex_input(hex_str, PrivateKeyVariant.ED25519, strict)
        return Ed25519PrivateKey.from_bytes(raw)

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> "Ed25519PrivateKey":
        """
        Alias for :meth:`from_hex` — parse from a hex or AIP-80 string.

        Parameters
        ----------
        value:
            A plain hex string or AIP-80 string.
        strict:
            AIP-80 strictness flag.
        """
        return Ed25519PrivateKey.from_hex(value, strict)

    @staticmethod
    def from_aip80(s: str) -> "Ed25519PrivateKey":
        """
        Parse an Ed25519 private key from an AIP-80 string.

        Raises
        ------
        InvalidPrivateKeyError
            If *s* does not start with the Ed25519 AIP-80 prefix.
        """
        return Ed25519PrivateKey.from_hex(s, strict=True)

    # Legacy alias used by existing SDK code
    @staticmethod
    def random() -> "Ed25519PrivateKey":
        """Alias for :meth:`generate` (legacy compatibility)."""
        return Ed25519PrivateKey.generate()

    # ------------------------------------------------------------------
    # Byte / string I/O
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw 32-byte private key."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Return the private key as a ``0x``-prefixed lowercase hex string."""
        return f"0x{bytes(self._key).hex()}"

    # Legacy alias used by existing SDK code
    def hex(self) -> str:
        """Return the private key as a ``0x``-prefixed hex string (legacy alias)."""
        return self.to_hex()

    def to_aip80(self) -> str:
        """
        Serialize this private key as an AIP-80 string.

        Returns a string of the form ``"ed25519-priv-0x<64 hex chars>"``.
        """
        return format_private_key(self.to_hex(), PrivateKeyVariant.ED25519)

    # Legacy alias used by existing SDK code
    def aip80(self) -> str:
        """Return AIP-80 string (legacy alias for :meth:`to_aip80`)."""
        return self.to_aip80()

    # ------------------------------------------------------------------
    # Key operations
    # ------------------------------------------------------------------

    def public_key(self) -> Ed25519PublicKey:
        """Derive and return the corresponding :class:`Ed25519PublicKey`."""
        return Ed25519PublicKey(self._key.verify_key)

    def sign(self, message: bytes) -> Ed25519Signature:
        """
        Sign *message* and return the resulting :class:`Ed25519Signature`.

        Parameters
        ----------
        message:
            Arbitrary bytes to sign.  The caller is responsible for any
            domain-separation hashing before calling this method.
        """
        return Ed25519Signature(self._key.sign(message).signature)

    # ------------------------------------------------------------------
    # Protocol accessors
    # ------------------------------------------------------------------

    @staticmethod
    def variant() -> PrivateKeyVariant:
        """Return :attr:`~PrivateKeyVariant.ED25519`."""
        return PrivateKeyVariant.ED25519

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the private key bytes with a ULEB128 length prefix."""
        serializer.to_bytes(self.to_bytes())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519PrivateKey":
        """Deserialize an :class:`Ed25519PrivateKey` from a length-prefixed buffer."""
        raw = deserializer.to_bytes()
        if len(raw) != Ed25519PrivateKey.LENGTH:
            raise InvalidLengthError(
                f"Expected {Ed25519PrivateKey.LENGTH} bytes for Ed25519 private key, "
                f"got {len(raw)}.",
                expected=Ed25519PrivateKey.LENGTH,
                actual=len(raw),
            )
        return Ed25519PrivateKey.from_bytes(raw)


# ---------------------------------------------------------------------------
# MultiEd25519PublicKey
# ---------------------------------------------------------------------------


class MultiEd25519PublicKey:
    """
    A Multi-Ed25519 public key: a list of Ed25519 public keys plus a threshold.

    Exactly ``threshold`` out of the ``len(keys)`` participating keys must
    provide valid signatures for a transaction to be considered authorized.

    Parameters
    ----------
    keys:
        List of participating :class:`Ed25519PublicKey` instances.
        Must contain between :attr:`MIN_KEYS` and :attr:`MAX_KEYS` entries.
    threshold:
        Minimum number of valid signatures required.
        Must be in ``[MIN_THRESHOLD, len(keys)]``.

    Raises
    ------
    ValueError
        If the key list size or threshold is out of range.
    """

    MIN_KEYS: int = 2
    MAX_KEYS: int = 32
    MIN_THRESHOLD: int = 1

    keys: list[Ed25519PublicKey]
    threshold: int

    def __init__(self, keys: list[Ed25519PublicKey], threshold: int) -> None:
        if not (
            MultiEd25519PublicKey.MIN_KEYS
            <= len(keys)
            <= MultiEd25519PublicKey.MAX_KEYS
        ):
            raise ValueError(
                f"Must have between {MultiEd25519PublicKey.MIN_KEYS} "
                f"and {MultiEd25519PublicKey.MAX_KEYS} keys."
            )
        if not (MultiEd25519PublicKey.MIN_THRESHOLD <= threshold <= len(keys)):
            raise ValueError(
                f"Threshold must be between {MultiEd25519PublicKey.MIN_THRESHOLD} "
                f"and {len(keys)}."
            )
        self.keys = list(keys)
        self.threshold = threshold

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiEd25519PublicKey):
            return NotImplemented
        return self.keys == other.keys and self.threshold == other.threshold

    def __str__(self) -> str:
        return f"{self.threshold}-of-{len(self.keys)} Multi-Ed25519 public key"

    # ------------------------------------------------------------------
    # Bytes I/O
    # ------------------------------------------------------------------

    def to_crypto_bytes(self) -> bytes:
        """
        Return the canonical byte encoding used for authentication key derivation.

        Format: concatenated 32-byte public keys followed by a single threshold byte.
        """
        buf = bytearray()
        for key in self.keys:
            buf.extend(key.to_bytes())
        buf.append(self.threshold)
        return bytes(buf)

    @staticmethod
    def from_crypto_bytes(data: bytes) -> "MultiEd25519PublicKey":
        """
        Reconstruct a :class:`MultiEd25519PublicKey` from its :meth:`to_crypto_bytes`
        encoding.

        Raises
        ------
        ValueError
            If *data* has an unexpected length or the key count / threshold are
            out of range.
        """
        key_size = Ed25519PublicKey.LENGTH
        # Last byte is the threshold; all preceding bytes are 32-byte keys.
        if len(data) < key_size + 1:
            raise InvalidPublicKeyError(
                f"MultiEd25519PublicKey crypto bytes too short: {len(data)} bytes."
            )
        num_keys = (len(data) - 1) // key_size
        if num_keys * key_size + 1 != len(data):
            raise InvalidPublicKeyError(
                f"MultiEd25519PublicKey crypto bytes length {len(data)} is not "
                f"consistent with an integer number of 32-byte keys plus 1 threshold byte."
            )
        keys: list[Ed25519PublicKey] = []
        for i in range(num_keys):
            start = i * key_size
            keys.append(Ed25519PublicKey.from_bytes(data[start : start + key_size]))
        threshold = data[-1]
        return MultiEd25519PublicKey(keys, threshold)

    # Legacy alias for from_crypto_bytes used by existing SDK code
    @staticmethod
    def from_bytes(data: bytes) -> "MultiEd25519PublicKey":
        """Alias for :meth:`from_crypto_bytes` (legacy compatibility)."""
        return MultiEd25519PublicKey.from_crypto_bytes(data)

    # Legacy alias for to_crypto_bytes used by existing SDK code
    def to_bytes(self) -> bytes:
        """Alias for :meth:`to_crypto_bytes` (legacy compatibility)."""
        return self.to_crypto_bytes()

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify(self, message: bytes, signature: "MultiEd25519Signature") -> bool:
        """
        Verify a :class:`MultiEd25519Signature` against *message*.

        Returns ``True`` only when at least ``threshold`` of the indexed
        signatures are valid under the corresponding public keys.
        """
        try:
            assert self.threshold <= len(signature.signatures), (
                f"Insufficient signatures: need {self.threshold}, "
                f"got {len(signature.signatures)}"
            )
            for idx, sig in signature.signatures:
                assert idx < len(
                    self.keys
                ), f"Signature index {idx} exceeds key count {len(self.keys)}"
                assert self.keys[idx].verify(
                    message, sig
                ), f"Signature at index {idx} failed verification"
        except (AssertionError, Exception):
            return False
        return True

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the multi-key as length-prefixed crypto bytes."""
        serializer.to_bytes(self.to_crypto_bytes())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiEd25519PublicKey":
        """Deserialize a :class:`MultiEd25519PublicKey` from a length-prefixed buffer."""
        raw = deserializer.to_bytes()
        return MultiEd25519PublicKey.from_crypto_bytes(raw)


# ---------------------------------------------------------------------------
# MultiEd25519Signature
# ---------------------------------------------------------------------------


class MultiEd25519Signature:
    """
    A Multi-Ed25519 signature: a list of ``(key_index, signature)`` pairs plus
    a compact bitmap.

    Parameters
    ----------
    signatures:
        A list of ``(index, Ed25519Signature)`` pairs.  Each *index* identifies
        which public key in the corresponding :class:`MultiEd25519PublicKey`
        produced the signature.  Each index must be less than
        ``BITMAP_NUM_OF_BYTES * 8 == 32``.

    Raises
    ------
    ValueError
        If any index is ``>= BITMAP_NUM_OF_BYTES * 8``.
    """

    BITMAP_NUM_OF_BYTES: int = 4

    signatures: list[tuple[int, Ed25519Signature]]

    def __init__(self, signatures: list[tuple[int, Ed25519Signature]]) -> None:
        max_index = MultiEd25519Signature.BITMAP_NUM_OF_BYTES * 8
        for idx, _sig in signatures:
            if idx >= max_index:
                raise ValueError(
                    f"Signature index {idx} exceeds maximum bitmap index {max_index - 1}."
                )
        self.signatures = list(signatures)

    # ------------------------------------------------------------------
    # Equality and display
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiEd25519Signature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        return str(self.signatures)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @staticmethod
    def from_key_map(
        public_key: MultiEd25519PublicKey,
        signatures_map: list[tuple[Ed25519PublicKey, Ed25519Signature]],
    ) -> "MultiEd25519Signature":
        """
        Build a :class:`MultiEd25519Signature` from a public-key-to-signature mapping.

        Parameters
        ----------
        public_key:
            The :class:`MultiEd25519PublicKey` whose ``keys`` list is used to
            resolve each signer's index.
        signatures_map:
            List of ``(Ed25519PublicKey, Ed25519Signature)`` pairs.  Each
            public key must appear in *public_key.keys*.

        Raises
        ------
        ValueError
            If a public key in *signatures_map* is not found in *public_key.keys*.
        """
        indexed: list[tuple[int, Ed25519Signature]] = []
        for pub, sig in signatures_map:
            try:
                idx = public_key.keys.index(pub)
            except ValueError:
                raise ValueError(
                    f"Public key {pub.to_hex()} not found in MultiEd25519PublicKey."
                )
            indexed.append((idx, sig))
        return MultiEd25519Signature(indexed)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize to BCS format: signature bytes concatenated with a 4-byte bitmap.

        The bitmap is a big-endian 32-bit integer where bit ``(31 - index)`` is
        set for each signature present.
        """
        sig_bytes = bytearray()
        bitmap = 0

        for idx, sig in self.signatures:
            shift = 31 - idx
            bitmap |= 1 << shift
            sig_bytes.extend(sig.to_bytes())

        sig_bytes.extend(
            bitmap.to_bytes(MultiEd25519Signature.BITMAP_NUM_OF_BYTES, "big")
        )
        serializer.to_bytes(bytes(sig_bytes))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiEd25519Signature":
        """
        Deserialize a :class:`MultiEd25519Signature` from a length-prefixed buffer.

        The buffer format is: ``N * 64`` signature bytes followed by 4 bitmap bytes,
        where *N* equals the number of set bits in the bitmap.
        """
        raw = deserializer.to_bytes()
        count = len(raw) // Ed25519Signature.LENGTH
        expected_len = (
            count * Ed25519Signature.LENGTH + MultiEd25519Signature.BITMAP_NUM_OF_BYTES
        )
        if expected_len != len(raw):
            raise InvalidSignatureError(
                f"MultiEd25519Signature has invalid length {len(raw)}: "
                f"expected {count} signatures ({count * Ed25519Signature.LENGTH} bytes) "
                f"+ {MultiEd25519Signature.BITMAP_NUM_OF_BYTES} bitmap bytes "
                f"= {expected_len} bytes."
            )

        bitmap = int.from_bytes(
            raw[-MultiEd25519Signature.BITMAP_NUM_OF_BYTES :], "big"
        )

        sig_index = 0
        signatures: list[tuple[int, Ed25519Signature]] = []
        for bit_pos in range(MultiEd25519Signature.BITMAP_NUM_OF_BYTES * 8):
            if bitmap & (1 << (31 - bit_pos)):
                offset = sig_index * Ed25519Signature.LENGTH
                sig = Ed25519Signature(raw[offset : offset + Ed25519Signature.LENGTH])
                signatures.append((bit_pos, sig))
                sig_index += 1

        return MultiEd25519Signature(signatures)


# ---------------------------------------------------------------------------
# Backward-compatible aliases for code that uses the old class names
# ---------------------------------------------------------------------------

#: Alias: ``PrivateKey`` → :class:`Ed25519PrivateKey`
PrivateKey = Ed25519PrivateKey

#: Alias: ``PublicKey`` → :class:`Ed25519PublicKey`
PublicKey = Ed25519PublicKey

#: Alias: ``Signature`` → :class:`Ed25519Signature`
Signature = Ed25519Signature

#: Alias: ``MultiPublicKey`` → :class:`MultiEd25519PublicKey`
MultiPublicKey = MultiEd25519PublicKey

#: Alias: ``MultiSignature`` → :class:`MultiEd25519Signature`
MultiSignature = MultiEd25519Signature
