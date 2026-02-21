# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
SingleKey / MultiKey wrappers for the Aptos unified authentication scheme
(Spec 03 — crypto_wrapper).

These wrappers implement the ``AnyPublicKey`` / ``AnySignature`` tagged-union
types used by the ``SingleKey`` and ``MultiKey`` authenticators.  They allow
accounts that use a key type other than plain Ed25519 to be represented and
verified uniformly.

Public API
----------
AnyPublicKey
    Wraps :class:`~aptos_sdk.ed25519.Ed25519PublicKey` or
    :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1PublicKey` with a variant
    discriminant.  Used for auth-key derivation and signature verification.

AnySignature
    Wraps :class:`~aptos_sdk.ed25519.Ed25519Signature` or
    :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1Signature` with a variant
    discriminant.

MultiKeyPublicKey
    A *k*-of-*n* multi-key public key composed of :class:`AnyPublicKey`
    values.  The auth-key scheme byte is ``0x03``.

MultiKeySignature
    A collection of (index, :class:`AnySignature`) pairs encoded alongside
    a compact bitmap indicating which of the *n* keys provided a signature.

Helper
------
index_to_bitmap_value(i)
    Convert a key index ``i`` to the corresponding bit in the little-endian
    bitmap used by :class:`MultiKeySignature`.
"""

from typing import cast

from aptos_sdk import ed25519, secp256k1_ecdsa
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.errors import CryptoError, InvalidPublicKeyError, InvalidSignatureError

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def index_to_bitmap_value(i: int) -> int:
    """
    Return the bitmap contribution of key index *i*.

    The bitmap is stored little-endian (byte 0 = keys 0-7, byte 1 = keys
    8-15, …).  Within each byte the *most-significant* bit corresponds to
    the lowest index in that byte's group, matching the on-chain convention.

    Parameters
    ----------
    i:
        Zero-based key index (``0 <= i < MAX_KEYS``).

    Returns
    -------
    int
        An integer whose single set bit occupies the position that
        represents key *i* in the serialised bitmap.

    Examples
    --------
    >>> index_to_bitmap_value(0)   # bit 7 of byte 0  → 0x80  (128)
    128
    >>> index_to_bitmap_value(1)   # bit 6 of byte 0  → 0x40  (64)
    64
    >>> index_to_bitmap_value(8)   # bit 7 of byte 1  → 0x8000 (32768)
    32768
    """
    bit = i % 8
    byte_idx = i // 8
    return (128 >> bit) << (byte_idx * 8)


# ---------------------------------------------------------------------------
# Type aliases for inner key / signature types (for readability)
# ---------------------------------------------------------------------------

# Public key inner types accepted by AnyPublicKey.
_InnerPublicKey = ed25519.Ed25519PublicKey | secp256k1_ecdsa.Secp256k1PublicKey

# Signature inner types accepted by AnySignature.
_InnerSignature = ed25519.Ed25519Signature | secp256k1_ecdsa.Secp256k1Signature


# ---------------------------------------------------------------------------
# AnyPublicKey
# ---------------------------------------------------------------------------


class AnyPublicKey:
    """
    A tagged-union wrapper around an inner public key.

    The variant byte identifies the underlying key type so that
    deserializers can reconstruct the correct concrete key.

    Class attributes
    ----------------
    ED25519 : int
        Variant index for Ed25519 keys (``0``).
    SECP256K1_ECDSA : int
        Variant index for Secp256k1 ECDSA keys (``1``).

    Instance attributes
    -------------------
    variant : int
        One of :attr:`ED25519` or :attr:`SECP256K1_ECDSA`.
    public_key : Ed25519PublicKey | Secp256k1PublicKey
        The wrapped inner key.
    """

    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    public_key: _InnerPublicKey

    def __init__(self, public_key: _InnerPublicKey) -> None:
        """
        Wrap *public_key* and auto-detect its variant.

        Parameters
        ----------
        public_key:
            An :class:`~aptos_sdk.ed25519.Ed25519PublicKey` or
            :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1PublicKey` instance.

        Raises
        ------
        InvalidPublicKeyError
            If *public_key* is not one of the two supported concrete types.
        """
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            self.variant = AnyPublicKey.ED25519
        elif isinstance(public_key, secp256k1_ecdsa.Secp256k1PublicKey):
            self.variant = AnyPublicKey.SECP256K1_ECDSA
        else:
            raise InvalidPublicKeyError(
                f"Unsupported public key type: {type(public_key).__name__!r}. "
                "Expected Ed25519PublicKey or Secp256k1PublicKey."
            )
        self.public_key = public_key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AnyPublicKey):
            return NotImplemented
        return self.variant == other.variant and self.public_key == other.public_key

    def __hash__(self) -> int:
        return hash((self.variant, self.public_key))

    def __repr__(self) -> str:
        variant_name = (
            "ED25519" if self.variant == AnyPublicKey.ED25519 else "SECP256K1_ECDSA"
        )
        return f"AnyPublicKey(variant={variant_name}, public_key={self.public_key!r})"

    def __str__(self) -> str:
        return str(self.public_key)

    # ------------------------------------------------------------------
    # Crypto operations
    # ------------------------------------------------------------------

    def to_crypto_bytes(self) -> bytes:
        """
        Return the BCS-serialised representation of this wrapper.

        This is the byte string used for authentication-key derivation
        (prepend the scheme byte ``0x02`` and hash with SHA3-256 to get
        the :class:`~aptos_sdk.account_address.AccountAddress`).

        Returns
        -------
        bytes
            ``variant_index(variant) || inner_key.serialize()``
        """
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self, data: bytes, signature: "AnySignature") -> bool:
        """
        Verify *signature* over *data* using the wrapped inner key.

        The *signature* must be an :class:`AnySignature` whose inner
        signature type is compatible with this key's variant.

        Parameters
        ----------
        data:
            The raw message bytes that were signed.
        signature:
            An :class:`AnySignature` instance.

        Returns
        -------
        bool
            ``True`` if the signature is valid; ``False`` otherwise.
        """
        if not isinstance(signature, AnySignature):
            return False
        # Dispatch to the concrete verify() with the properly typed inner
        # signature.  match/case narrows the type so mypy is satisfied.
        match self.variant:
            case AnyPublicKey.ED25519:
                ed_key = cast(ed25519.Ed25519PublicKey, self.public_key)
                if not isinstance(signature.signature, ed25519.Ed25519Signature):
                    return False
                return ed_key.verify(data, signature.signature)
            case AnyPublicKey.SECP256K1_ECDSA:
                sec_key = cast(secp256k1_ecdsa.Secp256k1PublicKey, self.public_key)
                if not isinstance(
                    signature.signature, secp256k1_ecdsa.Secp256k1Signature
                ):
                    return False
                return sec_key.verify(data, signature.signature)
            case _:
                return False

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AnyPublicKey":
        """
        Deserialize an :class:`AnyPublicKey` from *deserializer*.

        Reads:
        - ULEB128 variant index
        - The corresponding inner public key

        Parameters
        ----------
        deserializer:
            A :class:`~aptos_sdk.bcs.Deserializer` positioned at the
            start of an encoded ``AnyPublicKey``.

        Returns
        -------
        AnyPublicKey

        Raises
        ------
        InvalidPublicKeyError
            If the variant index is not ``0`` (Ed25519) or ``1``
            (Secp256k1 ECDSA).
        """
        variant = deserializer.variant_index()

        if variant == AnyPublicKey.ED25519:
            inner: _InnerPublicKey = ed25519.Ed25519PublicKey.deserialize(deserializer)
        elif variant == AnyPublicKey.SECP256K1_ECDSA:
            inner = secp256k1_ecdsa.Secp256k1PublicKey.deserialize(deserializer)
        else:
            raise InvalidPublicKeyError(
                f"Unknown AnyPublicKey variant index: {variant}. "
                "Expected 0 (ED25519) or 1 (SECP256K1_ECDSA)."
            )

        return AnyPublicKey(inner)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this wrapper into *serializer*.

        Writes:
        - ULEB128 variant index
        - The inner public key via its ``serialize`` method
        """
        serializer.variant_index(self.variant)
        self.public_key.serialize(serializer)


# ---------------------------------------------------------------------------
# AnySignature
# ---------------------------------------------------------------------------


class AnySignature:
    """
    A tagged-union wrapper around an inner signature.

    Class attributes
    ----------------
    ED25519 : int
        Variant index for Ed25519 signatures (``0``).
    SECP256K1_ECDSA : int
        Variant index for Secp256k1 ECDSA signatures (``1``).

    Instance attributes
    -------------------
    variant : int
        One of :attr:`ED25519` or :attr:`SECP256K1_ECDSA`.
    signature : Ed25519Signature | Secp256k1Signature
        The wrapped inner signature.
    """

    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    signature: _InnerSignature

    def __init__(self, signature: _InnerSignature) -> None:
        """
        Wrap *signature* and auto-detect its variant.

        Parameters
        ----------
        signature:
            An :class:`~aptos_sdk.ed25519.Ed25519Signature` or
            :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1Signature` instance.

        Raises
        ------
        InvalidSignatureError
            If *signature* is not one of the two supported concrete types.
        """
        if isinstance(signature, ed25519.Ed25519Signature):
            self.variant = AnySignature.ED25519
        elif isinstance(signature, secp256k1_ecdsa.Secp256k1Signature):
            self.variant = AnySignature.SECP256K1_ECDSA
        else:
            raise InvalidSignatureError(
                f"Unsupported signature type: {type(signature).__name__!r}. "
                "Expected Ed25519Signature or Secp256k1Signature."
            )
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AnySignature):
            return NotImplemented
        return self.variant == other.variant and self.signature == other.signature

    def __hash__(self) -> int:
        return hash((self.variant, self.signature))

    def __repr__(self) -> str:
        variant_name = (
            "ED25519" if self.variant == AnySignature.ED25519 else "SECP256K1_ECDSA"
        )
        return f"AnySignature(variant={variant_name}, signature={self.signature!r})"

    def __str__(self) -> str:
        return str(self.signature)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "AnySignature":
        """
        Deserialize an :class:`AnySignature` from *deserializer*.

        Reads:
        - ULEB128 variant index
        - The corresponding inner signature

        Parameters
        ----------
        deserializer:
            A :class:`~aptos_sdk.bcs.Deserializer` positioned at the
            start of an encoded ``AnySignature``.

        Returns
        -------
        AnySignature

        Raises
        ------
        InvalidSignatureError
            If the variant index is not ``0`` (Ed25519) or ``1``
            (Secp256k1 ECDSA).
        """
        variant = deserializer.variant_index()

        if variant == AnySignature.ED25519:
            inner: _InnerSignature = ed25519.Ed25519Signature.deserialize(deserializer)
        elif variant == AnySignature.SECP256K1_ECDSA:
            inner = secp256k1_ecdsa.Secp256k1Signature.deserialize(deserializer)
        else:
            raise InvalidSignatureError(
                f"Unknown AnySignature variant index: {variant}. "
                "Expected 0 (ED25519) or 1 (SECP256K1_ECDSA)."
            )

        return AnySignature(inner)

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize this wrapper into *serializer*.

        Writes:
        - ULEB128 variant index
        - The inner signature via its ``serialize`` method
        """
        serializer.variant_index(self.variant)
        self.signature.serialize(serializer)


# ---------------------------------------------------------------------------
# MultiKeyPublicKey
# ---------------------------------------------------------------------------


class MultiKeyPublicKey:
    """
    A *k*-of-*n* multi-key public key using the ``AnyPublicKey`` scheme.

    Each of the *n* constituent keys is independently typed (Ed25519 and
    Secp256k1 may be freely mixed).  At least *threshold* of them must sign
    a message for authentication to succeed.

    Constraints
    -----------
    - ``MIN_KEYS (2) <= len(keys) <= MAX_KEYS (32)``
    - ``MIN_THRESHOLD (1) <= threshold <= len(keys)``

    Auth-key derivation
    -------------------
    The authentication key for a ``MultiKey`` account is::

        SHA3-256(to_crypto_bytes() || 0x03)

    Class attributes
    ----------------
    MIN_KEYS : int
        Minimum number of constituent keys (``2``).
    MAX_KEYS : int
        Maximum number of constituent keys (``32``).
    MIN_THRESHOLD : int
        Minimum signature threshold (``1``).

    Instance attributes
    -------------------
    keys : list[AnyPublicKey]
        The constituent public keys.
    threshold : int
        Minimum number of valid signatures required to authenticate.
    """

    MIN_KEYS: int = 2
    MAX_KEYS: int = 32
    MIN_THRESHOLD: int = 1

    keys: list[AnyPublicKey]
    threshold: int

    def __init__(
        self,
        keys: list[AnyPublicKey | _InnerPublicKey],
        threshold: int,
    ) -> None:
        """
        Construct a :class:`MultiKeyPublicKey`.

        Parameters
        ----------
        keys:
            A list of public keys.  Each element may be an
            :class:`AnyPublicKey`, :class:`~aptos_sdk.ed25519.Ed25519PublicKey`,
            or :class:`~aptos_sdk.secp256k1_ecdsa.Secp256k1PublicKey`; bare
            concrete keys are automatically wrapped in :class:`AnyPublicKey`.
        threshold:
            The minimum number of valid signatures required to satisfy
            this multi-key.

        Raises
        ------
        CryptoError
            If the number of keys or the threshold is out of range.
        InvalidPublicKeyError
            If any bare key cannot be wrapped (unsupported type).
        """
        n = len(keys)
        if not (self.MIN_KEYS <= n <= self.MAX_KEYS):
            raise CryptoError(
                f"MultiKeyPublicKey requires between {self.MIN_KEYS} and "
                f"{self.MAX_KEYS} keys; got {n}."
            )
        if not (self.MIN_THRESHOLD <= threshold <= n):
            raise CryptoError(
                f"MultiKeyPublicKey threshold must be between "
                f"{self.MIN_THRESHOLD} and {n}; got {threshold}."
            )

        # Wrap bare inner keys in AnyPublicKey automatically.
        wrapped: list[AnyPublicKey] = []
        for key in keys:
            if isinstance(key, AnyPublicKey):
                wrapped.append(key)
            else:
                # AnyPublicKey.__init__ validates the type and raises
                # InvalidPublicKeyError for unsupported key types.
                wrapped.append(AnyPublicKey(key))

        self.keys = wrapped
        self.threshold = threshold

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiKeyPublicKey):
            return NotImplemented
        return self.keys == other.keys and self.threshold == other.threshold

    def __str__(self) -> str:
        return (
            f"{self.threshold}-of-{len(self.keys)} MultiKey "
            f"[{', '.join(str(k) for k in self.keys)}]"
        )

    def __repr__(self) -> str:
        return f"MultiKeyPublicKey(keys={self.keys!r}, threshold={self.threshold!r})"

    # ------------------------------------------------------------------
    # Crypto operations
    # ------------------------------------------------------------------

    def to_crypto_bytes(self) -> bytes:
        """
        Return the full BCS-serialised form of this key set.

        This is the byte string hashed (with the ``0x03`` scheme byte
        appended) to derive the ``AccountAddress`` for a ``MultiKey``
        account.

        Returns
        -------
        bytes
            ``sequence(keys) || u8(threshold)``
        """
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self, data: bytes, signature: "MultiKeySignature") -> bool:
        """
        Verify a :class:`MultiKeySignature` against *data*.

        Checks:
        1. At least ``threshold`` signatures are present.
        2. Every (index, signature) pair refers to a valid key index.
        3. Every inner signature is valid against the corresponding key.

        Parameters
        ----------
        data:
            The raw message bytes that were signed.
        signature:
            A :class:`MultiKeySignature` instance.

        Returns
        -------
        bool
            ``True`` if all checks pass; ``False`` otherwise.
        """
        if not isinstance(signature, MultiKeySignature):
            return False
        try:
            if len(signature.signatures) < self.threshold:
                return False
            for idx, sig in signature.signatures:
                if idx >= len(self.keys):
                    return False
                if not self.keys[idx].verify(data, sig):
                    return False
        except Exception:
            return False
        return True

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiKeyPublicKey":
        """
        Deserialize a :class:`MultiKeyPublicKey` from *deserializer*.

        Reads:
        - ULEB128-prefixed sequence of :class:`AnyPublicKey` values
        - ``u8`` threshold

        Returns
        -------
        MultiKeyPublicKey

        Raises
        ------
        CryptoError
            If the decoded key count or threshold is out of range.
        """
        keys: list[AnyPublicKey] = deserializer.sequence(AnyPublicKey.deserialize)
        threshold = deserializer.u8()
        # Cast: list[AnyPublicKey] satisfies list[AnyPublicKey | _InnerPublicKey].
        # The constructor accepts either; the cast resolves mypy's list invariance
        # complaint without any runtime cost.
        return MultiKeyPublicKey(
            cast(list[AnyPublicKey | _InnerPublicKey], keys), threshold
        )

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize into *serializer*.

        Writes:
        - ULEB128-prefixed sequence of :class:`AnyPublicKey` values
        - ``u8`` threshold
        """
        serializer.sequence(self.keys, Serializer.struct)
        serializer.u8(self.threshold)


# ---------------------------------------------------------------------------
# MultiKeySignature
# ---------------------------------------------------------------------------


class MultiKeySignature:
    """
    A collection of (index, :class:`AnySignature`) pairs for multi-key
    authentication, encoded with a compact bitmap.

    The bitmap is stored in little-endian byte order.  Bit *i* (using the
    :func:`index_to_bitmap_value` convention) is set when key *i* has
    contributed a signature.  The signatures themselves are stored in
    ascending index order.

    Class attributes
    ----------------
    MAX_SIGNATURES : int
        Maximum number of signatures allowed per :class:`MultiKeySignature`
        (``16``).

    Instance attributes
    -------------------
    signatures : list[tuple[int, AnySignature]]
        Ordered list of ``(key_index, signature)`` pairs.  Key indices must
        be unique and strictly less than ``MAX_SIGNATURES``.
    """

    MAX_SIGNATURES: int = 16

    signatures: list[tuple[int, AnySignature]]

    def __init__(
        self,
        signatures: list[tuple[int, AnySignature | _InnerSignature]],
    ) -> None:
        """
        Construct a :class:`MultiKeySignature`.

        Parameters
        ----------
        signatures:
            A list of ``(key_index, signature)`` pairs.  Each element's
            signature may be an :class:`AnySignature` or a bare concrete
            signature (automatically wrapped in :class:`AnySignature`).

        Raises
        ------
        InvalidSignatureError
            If any key index is ``>= MAX_SIGNATURES``, or if a bare signature
            cannot be wrapped (unsupported type).
        """
        wrapped: list[tuple[int, AnySignature]] = []
        for idx, sig in signatures:
            if idx >= self.MAX_SIGNATURES:
                raise InvalidSignatureError(
                    f"MultiKeySignature key index {idx} exceeds the maximum "
                    f"of {self.MAX_SIGNATURES - 1}."
                )
            if isinstance(sig, AnySignature):
                wrapped.append((idx, sig))
            else:
                # AnySignature.__init__ validates the type and raises
                # InvalidSignatureError for unsupported signature types.
                wrapped.append((idx, AnySignature(sig)))
        self.signatures = wrapped

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiKeySignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __repr__(self) -> str:
        return f"MultiKeySignature(signatures={self.signatures!r})"

    def __str__(self) -> str:
        return str(self.signatures)

    # ------------------------------------------------------------------
    # BCS serialization
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiKeySignature":
        """
        Deserialize a :class:`MultiKeySignature` from *deserializer*.

        Reads:
        - ULEB128-prefixed sequence of :class:`AnySignature` values
        - Length-prefixed bitmap bytes (little-endian)

        The bitmap is used to reconstruct the ``(index, signature)`` pairing:
        bit *i* (via :func:`index_to_bitmap_value`) being set means the
        *next* signature in the sequence belongs to key *i*.

        Returns
        -------
        MultiKeySignature
        """
        actual_sigs: list[AnySignature] = deserializer.sequence(
            AnySignature.deserialize
        )
        bitmap_raw: bytes = deserializer.to_bytes()
        bitmap = int.from_bytes(bitmap_raw, "little")
        num_bits = len(bitmap_raw) * 8

        sig_index = 0
        indexed: list[tuple[int, AnySignature]] = []
        for i in range(num_bits):
            if (bitmap & index_to_bitmap_value(i)) != 0:
                indexed.append((i, actual_sigs[sig_index]))
                sig_index += 1

        # Cast: list[tuple[int, AnySignature]] satisfies
        # list[tuple[int, AnySignature | _InnerSignature]].
        return MultiKeySignature(
            cast(list[tuple[int, AnySignature | _InnerSignature]], indexed)
        )

    def serialize(self, serializer: Serializer) -> None:
        """
        Serialize into *serializer*.

        Writes:
        - ULEB128-prefixed sequence of the inner :class:`AnySignature`
          values (in ascending key-index order)
        - Length-prefixed bitmap bytes (little-endian) encoding which
          key indices are present
        """
        actual_sigs: list[AnySignature] = []
        bitmap = 0

        for idx, sig in self.signatures:
            bitmap |= index_to_bitmap_value(idx)
            actual_sigs.append(sig)

        serializer.sequence(actual_sigs, Serializer.struct)

        # Determine the minimum number of bytes needed to represent the bitmap.
        # At least 1 byte is always written; grow as needed for higher indices.
        if bitmap == 0:
            bitmap_bytes = b"\x00"
        else:
            # Number of bytes required to cover the highest set bit.
            byte_count = (bitmap.bit_length() + 7) // 8
            bitmap_bytes = bitmap.to_bytes(byte_count, "little")

        serializer.to_bytes(bitmap_bytes)
