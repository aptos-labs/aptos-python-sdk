# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Secp256k1 ECDSA implementation for the Aptos Python SDK (Spec 03).

This module provides three classes that together implement the Secp256k1 ECDSA
cryptographic scheme used by the Aptos blockchain:

* :class:`Secp256k1PrivateKey` — 32-byte private (signing) key.
* :class:`Secp256k1PublicKey` — 65-byte uncompressed public key (0x04 prefix).
* :class:`Secp256k1Signature` — 64-byte signature in ``r || s`` format,
  normalised to low-S per the Aptos canonicality requirement.

All signing and verification operations use **SHA3-256** as the hash function.

AIP-80 support
--------------
Private keys may be serialised / deserialised in the
`AIP-80 <https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md>`_
format using :meth:`Secp256k1PrivateKey.to_aip80` and the ``strict`` parameter
on :meth:`Secp256k1PrivateKey.from_hex` / :meth:`Secp256k1PrivateKey.from_str`.

Authentication key
------------------
The authentication key for a Secp256k1 account is::

    SHA3-256(public_key_bytes_with_prefix || 0x01)

where ``public_key_bytes_with_prefix`` is the 65-byte uncompressed form
(``0x04`` followed by the 64-byte raw key).

Low-S normalisation
-------------------
ECDSA signatures are malleable: both ``(r, s)`` and ``(r, n - s)`` are valid
for the same message.  To enforce a canonical form the Aptos protocol requires
*low-S* signatures, i.e. ``s <= n // 2``.  The :meth:`Secp256k1PrivateKey.sign`
method automatically normalises ``s`` if needed.

Usage
-----
::

    from aptos_sdk.secp256k1_ecdsa import (
        Secp256k1PrivateKey,
        Secp256k1PublicKey,
        Secp256k1Signature,
    )

    # Key generation
    private_key = Secp256k1PrivateKey.generate()
    public_key  = private_key.public_key()

    # Signing and verification
    sig = private_key.sign(b"Hello, Aptos!")
    assert public_key.verify(b"Hello, Aptos!", sig)

    # AIP-80 round-trip
    aip80_str   = private_key.to_aip80()   # "secp256k1-priv-0x..."
    restored    = Secp256k1PrivateKey.from_str(aip80_str, strict=True)
    assert restored == private_key
"""

import hashlib

from ecdsa import SECP256k1, SigningKey, VerifyingKey, util

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
# Module-level aliases for readability
# ---------------------------------------------------------------------------

_format_private_key = format_private_key
_parse_hex_input = parse_hex_input
_PrivateKeyVariant = PrivateKeyVariant


# ---------------------------------------------------------------------------
# Secp256k1PrivateKey
# ---------------------------------------------------------------------------


class Secp256k1PrivateKey:
    """
    A 32-byte Secp256k1 private (signing) key.

    Internally wraps an ``ecdsa.SigningKey`` configured with the SECP256k1
    curve and SHA3-256 as the default hash function.

    Class Attributes
    ----------------
    LENGTH : int
        Raw byte length of the private key scalar (32).

    Construction
    ------------
    Use :meth:`generate` for a random key, :meth:`from_bytes` when you have
    raw key material, or :meth:`from_str` / :meth:`from_hex` when deserialising
    from a hex or AIP-80 string.
    """

    LENGTH: int = 32

    _key: SigningKey

    def __init__(self, key: SigningKey) -> None:
        self._key = key

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @staticmethod
    def generate() -> "Secp256k1PrivateKey":
        """
        Generate a random Secp256k1 private key.

        Uses the system's cryptographically secure random source via the
        ``ecdsa`` library.  The key's hash function is set to SHA3-256.

        Returns
        -------
        Secp256k1PrivateKey
            A freshly generated private key.
        """
        return Secp256k1PrivateKey(
            SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha3_256)
        )

    @staticmethod
    def from_bytes(data: bytes) -> "Secp256k1PrivateKey":
        """
        Construct a private key from raw 32-byte key material.

        Parameters
        ----------
        data:
            Exactly 32 bytes of private key scalar.

        Returns
        -------
        Secp256k1PrivateKey

        Raises
        ------
        InvalidPrivateKeyError
            If ``data`` is not exactly 32 bytes, or if the bytes do not
            represent a valid scalar on the SECP256k1 curve.
        """
        if len(data) != Secp256k1PrivateKey.LENGTH:
            raise InvalidPrivateKeyError(
                f"Secp256k1 private key must be {Secp256k1PrivateKey.LENGTH} bytes, "
                f"got {len(data)}",
                error_code="INVALID_PRIVATE_KEY_LENGTH",
            )
        try:
            signing_key = SigningKey.from_string(
                data, curve=SECP256k1, hashfunc=hashlib.sha3_256
            )
        except Exception as exc:
            raise InvalidPrivateKeyError(
                "Invalid Secp256k1 private key bytes",
                error_code="INVALID_PRIVATE_KEY",
                cause=exc,
            ) from exc
        return Secp256k1PrivateKey(signing_key)

    @staticmethod
    def from_hex(
        hex_str: str | bytes, strict: bool | None = None
    ) -> "Secp256k1PrivateKey":
        """
        Parse a hex string, raw bytes, or AIP-80 string into a private key.

        Parameters
        ----------
        hex_str:
            A plain hex string (``"0x..."`` or without prefix), raw bytes,
            or an AIP-80 compliant string
            (``"secp256k1-priv-0x..."``).
        strict:
            * ``True``  — *hex_str* MUST be AIP-80 compliant; raises
              ``ValueError`` otherwise.
            * ``False`` — AIP-80 prefix is accepted but not required.
            * ``None``  — same as ``False`` but prints a deprecation warning
              when a plain hex string is supplied.

        Returns
        -------
        Secp256k1PrivateKey

        Raises
        ------
        InvalidPrivateKeyError
            If the decoded bytes are the wrong length or invalid.
        ValueError
            If ``strict=True`` and the input is not AIP-80 compliant.
        """
        try:
            raw_bytes = _parse_hex_input(hex_str, _PrivateKeyVariant.SECP256K1, strict)
        except (ValueError, TypeError) as exc:
            raise InvalidPrivateKeyError(
                f"Failed to parse Secp256k1 private key: {exc}",
                error_code="INVALID_PRIVATE_KEY_HEX",
                cause=exc,
            ) from exc

        return Secp256k1PrivateKey.from_bytes(raw_bytes)

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> "Secp256k1PrivateKey":
        """
        Parse a hex string or AIP-80 compliant string into a private key.

        This is a convenience alias for :meth:`from_hex` that only accepts
        ``str`` inputs (not raw ``bytes``).

        Parameters
        ----------
        value:
            A hex string or AIP-80 compliant string.
        strict:
            See :meth:`from_hex`.

        Returns
        -------
        Secp256k1PrivateKey
        """
        return Secp256k1PrivateKey.from_hex(value, strict)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Return the raw 32-byte private key scalar.

        Returns
        -------
        bytes
            32 bytes.
        """
        return self._key.to_string()

    def to_hex(self) -> str:
        """
        Return a ``0x``-prefixed hex representation of the private key.

        Returns
        -------
        str
            ``"0x"`` followed by 64 hex characters.
        """
        return f"0x{self._key.to_string().hex()}"

    def to_aip80(self) -> str:
        """
        Return the AIP-80 compliant string representation of this key.

        The format is ``"secp256k1-priv-0x<64-hex-chars>"``.

        Returns
        -------
        str
        """
        return _format_private_key(self.to_hex(), _PrivateKeyVariant.SECP256K1)

    # ------------------------------------------------------------------
    # Key operations
    # ------------------------------------------------------------------

    def public_key(self) -> "Secp256k1PublicKey":
        """
        Derive the corresponding Secp256k1 public key.

        Returns
        -------
        Secp256k1PublicKey
        """
        return Secp256k1PublicKey(self._key.verifying_key)

    def sign(self, message: bytes) -> "Secp256k1Signature":
        """
        Sign *message* with this private key using deterministic ECDSA.

        The signing procedure:

        1. Produce a deterministic ECDSA signature via RFC 6979 using
           SHA3-256 as the hash function.
        2. Normalise to *low-S* canonical form: if ``s > n // 2``, replace
           ``s`` with ``n - s``.  Both ``(r, s)`` and ``(r, n-s)`` are
           mathematically valid signatures, but the Aptos protocol only
           accepts the low-S form.

        Parameters
        ----------
        message:
            The raw message bytes to sign.  The message is hashed
            internally by the ECDSA algorithm.

        Returns
        -------
        Secp256k1Signature
            A 64-byte low-S normalised signature (``r || s``).
        """
        # Deterministic signing with SHA3-256
        raw_sig: bytes = self._key.sign_deterministic(
            message, hashfunc=hashlib.sha3_256
        )

        # Decode r and s from the fixed-length DER-adjacent encoding
        n = SECP256k1.generator.order()
        r, s = util.sigdecode_string(raw_sig, n)

        # Low-S normalisation: enforce s <= n // 2
        if s > (n // 2):
            s = n - s

        normalised: bytes = util.sigencode_string(r, s, n)
        return Secp256k1Signature(normalised)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256k1PrivateKey":
        """
        Deserialize a ``Secp256k1PrivateKey`` from a BCS stream.

        The key is encoded as a length-prefixed byte sequence whose payload
        is the raw 32-byte private key scalar.

        Parameters
        ----------
        deserializer:
            An active :class:`~aptos_sdk.bcs.Deserializer`.

        Returns
        -------
        Secp256k1PrivateKey

        Raises
        ------
        InvalidPrivateKeyError
            If the deserialized byte length is not 32.
        """
        raw = deserializer.to_bytes()
        if len(raw) != Secp256k1PrivateKey.LENGTH:
            raise InvalidPrivateKeyError(
                f"BCS-deserialized Secp256k1 private key has wrong length: "
                f"expected {Secp256k1PrivateKey.LENGTH}, got {len(raw)}",
                error_code="INVALID_PRIVATE_KEY_LENGTH",
            )
        return Secp256k1PrivateKey.from_bytes(raw)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this private key into a BCS stream.

        The key is written as a length-prefixed byte sequence containing
        the raw 32-byte scalar.

        Parameters
        ----------
        serializer:
            An active :class:`~aptos_sdk.bcs.Serializer`.
        """
        serializer.to_bytes(self.to_bytes())

    # ------------------------------------------------------------------
    # Dunder methods
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1PrivateKey):
            return NotImplemented
        return self._key.to_string() == other._key.to_string()

    def __str__(self) -> str:
        """Return the AIP-80 representation."""
        return self.to_aip80()

    def __repr__(self) -> str:
        """Never expose key material in repr."""
        return "Secp256k1PrivateKey(***)"


# ---------------------------------------------------------------------------
# Secp256k1PublicKey
# ---------------------------------------------------------------------------


class Secp256k1PublicKey:
    """
    A Secp256k1 public key in uncompressed form.

    The *canonical* on-wire representation used by the Aptos protocol is the
    65-byte uncompressed form: ``0x04 || <64-byte-raw-key>``.  However, this
    class also stores and exposes the 64-byte raw key (without the prefix) for
    convenience.

    Class Attributes
    ----------------
    LENGTH : int
        Raw key length without the ``0x04`` prefix byte (64).
    LENGTH_WITH_PREFIX : int
        Full uncompressed key length with the ``0x04`` prefix byte (65).

    The authentication key for a Secp256k1 account is::

        SHA3-256(to_crypto_bytes() || 0x01)
    """

    LENGTH: int = 64
    LENGTH_WITH_PREFIX: int = 65

    _key: VerifyingKey

    def __init__(self, key: VerifyingKey) -> None:
        self._key = key

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @staticmethod
    def from_bytes(data: bytes) -> "Secp256k1PublicKey":
        """
        Construct a public key from raw bytes.

        Accepts either the 64-byte raw key (no prefix) or the 65-byte
        uncompressed form with the ``0x04`` prefix byte.

        Parameters
        ----------
        data:
            64 or 65 bytes representing the public key.

        Returns
        -------
        Secp256k1PublicKey

        Raises
        ------
        InvalidPublicKeyError
            If ``data`` is neither 64 nor 65 bytes, or if the bytes do not
            represent a valid point on the SECP256k1 curve.
        InvalidLengthError
            If the byte length is completely unexpected (not 64 or 65).
        """
        if len(data) == Secp256k1PublicKey.LENGTH_WITH_PREFIX:
            # Strip the 0x04 uncompressed prefix byte
            raw = data[1:]
        elif len(data) == Secp256k1PublicKey.LENGTH:
            raw = data
        else:
            raise InvalidLengthError(
                f"Secp256k1 public key must be {Secp256k1PublicKey.LENGTH} or "
                f"{Secp256k1PublicKey.LENGTH_WITH_PREFIX} bytes, got {len(data)}",
                expected=Secp256k1PublicKey.LENGTH,
                actual=len(data),
            )

        try:
            verifying_key = VerifyingKey.from_string(
                raw, curve=SECP256k1, hashfunc=hashlib.sha3_256
            )
        except Exception as exc:
            raise InvalidPublicKeyError(
                "Invalid Secp256k1 public key bytes",
                error_code="INVALID_PUBLIC_KEY",
                cause=exc,
            ) from exc

        return Secp256k1PublicKey(verifying_key)

    @staticmethod
    def from_str(value: str) -> "Secp256k1PublicKey":
        """
        Parse a hex-encoded public key string.

        The string may be prefixed with ``"0x"`` or ``"0x04"`` (the standard
        uncompressed-point prefix).

        Parameters
        ----------
        value:
            Hex string representing either the 64-byte raw key or the
            65-byte uncompressed key.

        Returns
        -------
        Secp256k1PublicKey

        Raises
        ------
        InvalidPublicKeyError
            If the string is not a valid hex encoding of a Secp256k1 key.
        """
        stripped = value[2:] if value.startswith("0x") else value
        try:
            raw_bytes = bytes.fromhex(stripped)
        except ValueError as exc:
            raise InvalidPublicKeyError(
                f"Cannot decode Secp256k1 public key from hex: {exc}",
                error_code="INVALID_PUBLIC_KEY_HEX",
                cause=exc,
            ) from exc

        return Secp256k1PublicKey.from_bytes(raw_bytes)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Return the raw 64-byte public key (without the ``0x04`` prefix).

        Returns
        -------
        bytes
            64 bytes.
        """
        return self._key.to_string()

    def to_hex(self) -> str:
        """
        Return a hex string in the ``0x04``-prefixed uncompressed form.

        The returned string begins with ``"0x04"`` followed by 128 hex
        characters (64 bytes).

        Returns
        -------
        str
            ``"0x04"`` + 128 hex characters (65 bytes total in binary).
        """
        return f"0x04{self._key.to_string().hex()}"

    def to_crypto_bytes(self) -> bytes:
        """
        Return the 65-byte uncompressed public key (``0x04 || raw``).

        This is the canonical representation used in authentication key
        derivation and BCS serialization.

        Returns
        -------
        bytes
            65 bytes: ``b"\\x04"`` followed by the 64-byte raw key.
        """
        return b"\x04" + self._key.to_string()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, message: bytes, signature: "Secp256k1Signature") -> bool:
        """
        Verify that *signature* is a valid ECDSA signature over *message*.

        The verification uses SHA3-256 as the hash function, matching the
        hash function used during signing.

        Parameters
        ----------
        message:
            The original message bytes that were signed.
        signature:
            The :class:`Secp256k1Signature` to verify.

        Returns
        -------
        bool
            ``True`` if the signature is valid; ``False`` otherwise.
            This method never raises on invalid signatures — callers that
            want a rich error should use :meth:`verify_or_raise`.
        """
        try:
            self._key.verify(
                signature.to_bytes(),
                message,
                hashfunc=hashlib.sha3_256,
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256k1PublicKey":
        """
        Deserialize a ``Secp256k1PublicKey`` from a BCS stream.

        The key is encoded as a length-prefixed byte sequence whose payload
        is the 65-byte uncompressed form (``0x04`` prefix included).

        Parameters
        ----------
        deserializer:
            An active :class:`~aptos_sdk.bcs.Deserializer`.

        Returns
        -------
        Secp256k1PublicKey

        Raises
        ------
        InvalidPublicKeyError
            If the decoded bytes are not a valid Secp256k1 public key.
        """
        raw = deserializer.to_bytes()
        # Deserializer may produce either 64 or 65 bytes; from_bytes handles both.
        if len(raw) not in (
            Secp256k1PublicKey.LENGTH,
            Secp256k1PublicKey.LENGTH_WITH_PREFIX,
        ):
            raise InvalidPublicKeyError(
                f"BCS-deserialized Secp256k1 public key has wrong length: "
                f"expected {Secp256k1PublicKey.LENGTH} or "
                f"{Secp256k1PublicKey.LENGTH_WITH_PREFIX}, got {len(raw)}",
                error_code="INVALID_PUBLIC_KEY_LENGTH",
            )
        return Secp256k1PublicKey.from_bytes(raw)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this public key into a BCS stream.

        The key is written as a length-prefixed byte sequence containing
        the 65-byte uncompressed form (``0x04`` prefix included).

        Parameters
        ----------
        serializer:
            An active :class:`~aptos_sdk.bcs.Serializer`.
        """
        serializer.to_bytes(self.to_crypto_bytes())

    # ------------------------------------------------------------------
    # Dunder methods
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1PublicKey):
            return NotImplemented
        return self._key.to_string() == other._key.to_string()

    def __str__(self) -> str:
        """Return the ``0x04``-prefixed hex representation."""
        return self.to_hex()

    def __repr__(self) -> str:
        return f"Secp256k1PublicKey(to_hex={self.to_hex()!r})"


# ---------------------------------------------------------------------------
# Secp256k1Signature
# ---------------------------------------------------------------------------


class Secp256k1Signature:
    """
    A 64-byte Secp256k1 ECDSA signature in ``r || s`` format.

    The signature is always in *low-S* canonical form as required by the
    Aptos protocol.  :meth:`Secp256k1PrivateKey.sign` guarantees this
    property; callers constructing a ``Secp256k1Signature`` from raw bytes
    must ensure the bytes already satisfy the low-S constraint.

    Class Attributes
    ----------------
    LENGTH : int
        Expected byte length (64).
    """

    LENGTH: int = 64

    _signature: bytes

    def __init__(self, signature: bytes) -> None:
        self._signature = signature

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @staticmethod
    def from_bytes(data: bytes) -> "Secp256k1Signature":
        """
        Construct a signature from raw bytes.

        Parameters
        ----------
        data:
            Exactly 64 bytes (``r || s``).

        Returns
        -------
        Secp256k1Signature

        Raises
        ------
        InvalidSignatureError
            If ``data`` is not exactly 64 bytes.
        """
        if len(data) != Secp256k1Signature.LENGTH:
            raise InvalidSignatureError(
                f"Secp256k1 signature must be {Secp256k1Signature.LENGTH} bytes, "
                f"got {len(data)}",
                error_code="INVALID_SIGNATURE_LENGTH",
            )
        return Secp256k1Signature(data)

    @staticmethod
    def from_str(value: str) -> "Secp256k1Signature":
        """
        Parse a hex-encoded signature string.

        Parameters
        ----------
        value:
            Hex string (optionally ``"0x"``-prefixed) encoding exactly 64
            bytes.

        Returns
        -------
        Secp256k1Signature

        Raises
        ------
        InvalidSignatureError
            If the string does not decode to exactly 64 bytes.
        """
        stripped = value[2:] if value.startswith("0x") else value
        try:
            raw_bytes = bytes.fromhex(stripped)
        except ValueError as exc:
            raise InvalidSignatureError(
                f"Cannot decode Secp256k1 signature from hex: {exc}",
                error_code="INVALID_SIGNATURE_HEX",
                cause=exc,
            ) from exc
        return Secp256k1Signature.from_bytes(raw_bytes)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Return the raw 64-byte signature (``r || s``).

        Returns
        -------
        bytes
            64 bytes.
        """
        return self._signature

    def to_hex(self) -> str:
        """
        Return a ``0x``-prefixed hex encoding of the signature.

        Returns
        -------
        str
            ``"0x"`` followed by 128 hex characters.
        """
        return f"0x{self._signature.hex()}"

    # ------------------------------------------------------------------
    # Legacy compatibility shim
    # ------------------------------------------------------------------

    def data(self) -> bytes:
        """
        Return the raw signature bytes.

        This alias exists for compatibility with callers that use the older
        ``Signature.data()`` interface.  Prefer :meth:`to_bytes`.

        Returns
        -------
        bytes
            64 bytes.
        """
        return self._signature

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256k1Signature":
        """
        Deserialize a ``Secp256k1Signature`` from a BCS stream.

        The signature is encoded as a length-prefixed byte sequence.

        Parameters
        ----------
        deserializer:
            An active :class:`~aptos_sdk.bcs.Deserializer`.

        Returns
        -------
        Secp256k1Signature

        Raises
        ------
        InvalidSignatureError
            If the deserialized byte length is not 64.
        """
        raw = deserializer.to_bytes()
        if len(raw) != Secp256k1Signature.LENGTH:
            raise InvalidSignatureError(
                f"BCS-deserialized Secp256k1 signature has wrong length: "
                f"expected {Secp256k1Signature.LENGTH}, got {len(raw)}",
                error_code="INVALID_SIGNATURE_LENGTH",
            )
        return Secp256k1Signature(raw)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this signature into a BCS stream.

        The signature is written as a length-prefixed byte sequence.

        Parameters
        ----------
        serializer:
            An active :class:`~aptos_sdk.bcs.Serializer`.
        """
        serializer.to_bytes(self._signature)

    # ------------------------------------------------------------------
    # Dunder methods
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1Signature):
            return NotImplemented
        return self._signature == other._signature

    def __str__(self) -> str:
        """Return the ``0x``-prefixed hex representation."""
        return self.to_hex()

    def __repr__(self) -> str:
        return f"Secp256k1Signature(to_hex={self.to_hex()!r})"


# ---------------------------------------------------------------------------
# Convenience: auth key computation
# ---------------------------------------------------------------------------


def secp256k1_auth_key(public_key: Secp256k1PublicKey) -> bytes:
    """
    Compute the Aptos authentication key for a Secp256k1 public key.

    The authentication key is::

        SHA3-256(public_key.to_crypto_bytes() || 0x01)

    where ``to_crypto_bytes()`` returns the 65-byte uncompressed form.

    Parameters
    ----------
    public_key:
        The :class:`Secp256k1PublicKey` to derive an authentication key for.

    Returns
    -------
    bytes
        32-byte authentication key.
    """
    return sha3_256(public_key.to_crypto_bytes() + b"\x01")
