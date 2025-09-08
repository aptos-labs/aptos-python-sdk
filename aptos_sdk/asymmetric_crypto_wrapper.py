# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Cryptographic wrapper classes for unified signature scheme handling in Aptos.

This module provides wrapper classes that unify different cryptographic signature
schemes (Ed25519, secp256k1) under a common interface. These wrappers enable
polymorphic handling of different key types and support multi-signature scenarios.

Key Features:
- **Algorithm Abstraction**: Unified interface for different signature schemes
- **Multi-Signature Support**: Threshold-based multi-signature authentication
- **Type-Safe Variants**: Compile-time and runtime type safety for crypto operations
- **BCS Serialization**: Full integration with Aptos Binary Canonical Serialization
- **Backward Compatibility**: Support for existing single and multi-key scenarios

Wrapper Classes:
- PublicKey: Wraps Ed25519 and secp256k1 public keys with variant tagging
- Signature: Wraps signatures from different algorithms with type identification
- MultiPublicKey: Implements threshold-based multi-signature public keys
- MultiSignature: Handles collections of signatures with bitmap-based indexing

Use Cases:
- Polymorphic signature verification across algorithms
- Multi-signature wallet implementations
- Key rotation and migration scenarios
- Account abstraction with flexible authentication

Examples:
    Single key usage::

        from aptos_sdk import ed25519
        from aptos_sdk.asymmetric_crypto_wrapper import PublicKey, Signature

        # Wrap an Ed25519 key
        ed25519_key = ed25519.PrivateKey.generate()
        wrapped_public = PublicKey(ed25519_key.public_key())

        # Sign and verify
        message = b"Hello, Aptos!"
        ed25519_sig = ed25519_key.sign(message)
        wrapped_sig = Signature(ed25519_sig)

        # Verify through wrapper
        is_valid = wrapped_public.verify(message, wrapped_sig)

    Multi-signature setup::

        from aptos_sdk.asymmetric_crypto_wrapper import MultiPublicKey, MultiSignature

        # Create multi-sig with 2-of-3 threshold
        keys = [key1.public_key(), key2.public_key(), key3.public_key()]
        multi_key = MultiPublicKey(keys, threshold=2)

        # Create multi-signature (keys 0 and 2 sign)
        sig1 = key1.sign(message)
        sig3 = key3.sign(message)
        multi_sig = MultiSignature([(0, sig1), (2, sig3)])

        # Verify multi-signature
        is_valid = multi_key.verify(message, multi_sig)

    Serialization example::

        from aptos_sdk.bcs import Serializer, Deserializer

        # Serialize wrapped key
        serializer = Serializer()
        wrapped_public.serialize(serializer)
        key_bytes = serializer.output()

        # Deserialize wrapped key
        deserializer = Deserializer(key_bytes)
        restored_key = PublicKey.deserialize(deserializer)

Note:
    These wrappers add a small overhead for type tagging and dispatching,
    but enable powerful polymorphic cryptographic operations essential
    for flexible blockchain authentication schemes.
"""

from __future__ import annotations

from typing import List, Tuple, cast

from . import asymmetric_crypto, ed25519, secp256k1_ecdsa
from .bcs import Deserializer, Serializer


class PublicKey(asymmetric_crypto.PublicKey):
    """Unified wrapper for different cryptographic public key types.

    This class provides a common interface for Ed25519 and secp256k1 public keys,
    enabling polymorphic handling of different signature schemes within the Aptos
    ecosystem. The wrapper maintains type information through variant tagging.

    Type Variants:
        ED25519 (0): Ed25519 elliptic curve signature scheme
        SECP256K1_ECDSA (1): secp256k1 ECDSA signature scheme

    Attributes:
        variant: Integer identifier for the wrapped key type
        public_key: The underlying concrete public key implementation

    Examples:
        Wrapping different key types::

            # Ed25519 key
            ed25519_private = ed25519.PrivateKey.generate()
            wrapped_ed25519 = PublicKey(ed25519_private.public_key())
            assert wrapped_ed25519.variant == PublicKey.ED25519

            # secp256k1 key
            secp256k1_private = secp256k1_ecdsa.PrivateKey.generate()
            wrapped_secp256k1 = PublicKey(secp256k1_private.public_key())
            assert wrapped_secp256k1.variant == PublicKey.SECP256K1_ECDSA

        Polymorphic verification::

            def verify_message(public_key: PublicKey, message: bytes, signature: Signature) -> bool:
                # Works regardless of underlying algorithm
                return public_key.verify(message, signature)

    Note:
        The wrapper automatically detects the key type during construction
        and sets the appropriate variant identifier for serialization.
    """

    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    public_key: asymmetric_crypto.PublicKey

    def __init__(self, public_key: asymmetric_crypto.PublicKey):
        """Initialize a public key wrapper for the given concrete key.

        Args:
            public_key: An Ed25519 or secp256k1 public key to be wrapped.

        Raises:
            NotImplementedError: If the public key type is not supported.

        Example:
            >>> ed25519_key = ed25519.PrivateKey.generate().public_key()
            >>> wrapped = PublicKey(ed25519_key)
            >>> wrapped.variant
            0
        """
        if isinstance(public_key, ed25519.PublicKey):
            self.variant = PublicKey.ED25519
        elif isinstance(public_key, secp256k1_ecdsa.PublicKey):
            self.variant = PublicKey.SECP256K1_ECDSA
        else:
            raise NotImplementedError()
        self.public_key = public_key

    def to_crypto_bytes(self) -> bytes:
        """Get the specialized cryptographic byte representation.

        Returns the public key in BCS-serialized format including the
        variant tag, suitable for cryptographic operations and storage.

        Returns:
            BCS-serialized bytes including variant tag and key data.

        Example:
            >>> wrapped_key = PublicKey(ed25519_key)
            >>> crypto_bytes = wrapped_key.to_crypto_bytes()
            >>> len(crypto_bytes)  # Includes variant byte + key bytes
            33  # 1 byte variant + 32 bytes Ed25519 key
        """
        ser = Serializer()
        self.serialize(ser)
        return ser.output()

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        """Verify a signature against this public key.

        Unwraps the signature and delegates verification to the underlying
        concrete public key implementation. Handles type coercion to ensure
        the signature wrapper matches the key type.

        Args:
            data: The original data that was signed.
            signature: A wrapped signature to verify.

        Returns:
            True if the signature is valid, False otherwise.

        Example:
            >>> message = b"Hello, Aptos!"
            >>> signature = private_key.sign(message)
            >>> wrapped_signature = Signature(signature)
            >>> wrapped_public.verify(message, wrapped_signature)
            True
        """
        # Convert signature to the original signature
        sig = cast(Signature, signature)

        return self.public_key.verify(data, sig.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        """Deserialize a public key wrapper from BCS-encoded data.

        Reads the variant tag and delegates deserialization to the appropriate
        concrete key implementation based on the detected type.

        Args:
            deserializer: BCS deserializer containing the key data.

        Returns:
            A new PublicKey wrapper containing the deserialized key.

        Raises:
            Exception: If the variant tag is not recognized.

        Example:
            >>> serializer = Serializer()
            >>> original_key.serialize(serializer)
            >>> key_bytes = serializer.output()
            >>> deserializer = Deserializer(key_bytes)
            >>> restored_key = PublicKey.deserialize(deserializer)
        """
        variant = deserializer.uleb128()

        if variant == PublicKey.ED25519:
            public_key: asymmetric_crypto.PublicKey = ed25519.PublicKey.deserialize(
                deserializer
            )
        elif variant == Signature.SECP256K1_ECDSA:
            public_key = secp256k1_ecdsa.PublicKey.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return PublicKey(public_key)

    def serialize(self, serializer: Serializer):
        """Serialize the public key wrapper to BCS format.

        Writes the variant tag followed by the underlying public key data
        in BCS format. The variant enables proper deserialization.

        Args:
            serializer: BCS serializer to write the key data to.

        Example:
            >>> serializer = Serializer()
            >>> wrapped_key.serialize(serializer)
            >>> key_bytes = serializer.output()
        """
        serializer.uleb128(self.variant)
        serializer.struct(self.public_key)


class Signature(asymmetric_crypto.Signature):
    """Unified wrapper for different cryptographic signature types.

    This class provides a common interface for Ed25519 and secp256k1 signatures,
    enabling polymorphic handling and verification across different signature
    schemes. Like PublicKey, it uses variant tagging for type identification.

    Type Variants:
        ED25519 (0): Ed25519 signature
        SECP256K1_ECDSA (1): secp256k1 ECDSA signature

    Attributes:
        variant: Integer identifier for the wrapped signature type
        signature: The underlying concrete signature implementation

    Examples:
        Wrapping different signature types::

            message = b"Hello, Aptos!"

            # Ed25519 signature
            ed25519_sig = ed25519_private.sign(message)
            wrapped_ed25519_sig = Signature(ed25519_sig)
            assert wrapped_ed25519_sig.variant == Signature.ED25519

            # secp256k1 signature
            secp256k1_sig = secp256k1_private.sign(message)
            wrapped_secp256k1_sig = Signature(secp256k1_sig)
            assert wrapped_secp256k1_sig.variant == Signature.SECP256K1_ECDSA

        Polymorphic operations::

            def verify_any_signature(key: PublicKey, msg: bytes, sig: Signature) -> bool:
                # Works regardless of underlying algorithm
                return key.verify(msg, sig)

    Note:
        The signature wrapper automatically detects and tags the signature type,
        ensuring compatibility with the corresponding public key wrapper.
    """

    ED25519: int = 0
    SECP256K1_ECDSA: int = 1

    variant: int
    signature: asymmetric_crypto.Signature

    def __init__(self, signature: asymmetric_crypto.Signature):
        """Initialize a signature wrapper for the given concrete signature.

        Args:
            signature: An Ed25519 or secp256k1 signature to be wrapped.

        Raises:
            NotImplementedError: If the signature type is not supported.

        Example:
            >>> message = b"test message"
            >>> ed25519_sig = ed25519_private.sign(message)
            >>> wrapped = Signature(ed25519_sig)
            >>> wrapped.variant
            0
        """
        if isinstance(signature, ed25519.Signature):
            self.variant = Signature.ED25519
        elif isinstance(signature, secp256k1_ecdsa.Signature):
            self.variant = Signature.SECP256K1_ECDSA
        else:
            raise NotImplementedError()
        self.signature = signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        """Deserialize a signature wrapper from BCS-encoded data.

        Reads the variant tag and delegates deserialization to the appropriate
        concrete signature implementation based on the detected type.

        Args:
            deserializer: BCS deserializer containing the signature data.

        Returns:
            A new Signature wrapper containing the deserialized signature.

        Raises:
            Exception: If the variant tag is not recognized.

        Example:
            >>> serializer = Serializer()
            >>> original_sig.serialize(serializer)
            >>> sig_bytes = serializer.output()
            >>> deserializer = Deserializer(sig_bytes)
            >>> restored_sig = Signature.deserialize(deserializer)
        """
        variant = deserializer.uleb128()

        if variant == Signature.ED25519:
            signature: asymmetric_crypto.Signature = ed25519.Signature.deserialize(
                deserializer
            )
        elif variant == Signature.SECP256K1_ECDSA:
            signature = secp256k1_ecdsa.Signature.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        """Serialize the signature wrapper to BCS format.

        Writes the variant tag followed by the underlying signature data
        in BCS format. The variant enables proper deserialization.

        Args:
            serializer: BCS serializer to write the signature data to.

        Example:
            >>> serializer = Serializer()
            >>> wrapped_signature.serialize(serializer)
            >>> sig_bytes = serializer.output()
        """
        serializer.uleb128(self.variant)
        serializer.struct(self.signature)


class MultiPublicKey(asymmetric_crypto.PublicKey):
    """Multi-signature public key implementing threshold-based authentication.

    This class represents a collection of public keys with a threshold requirement,
    enabling N-of-M multi-signature schemes. It's commonly used for multi-signature
    wallets, governance systems, and enhanced security scenarios.

    Threshold Mechanics:
    - Requires at least `threshold` valid signatures from the key set
    - Signatures are indexed by position in the key array
    - Uses bitmap encoding to identify which keys provided signatures
    - Supports heterogeneous key types (Ed25519, secp256k1) within the same set

    Constraints:
        MIN_KEYS (2): Minimum number of keys required
        MAX_KEYS (32): Maximum number of keys allowed
        MIN_THRESHOLD (1): Minimum threshold value

    Attributes:
        keys: List of wrapped public keys in the multi-signature scheme
        threshold: Minimum number of signatures required for validity

    Examples:
        Creating a 2-of-3 multi-signature key::

            key1 = ed25519.PrivateKey.generate().public_key()
            key2 = ed25519.PrivateKey.generate().public_key()
            key3 = secp256k1_ecdsa.PrivateKey.generate().public_key()

            multi_key = MultiPublicKey([key1, key2, key3], threshold=2)
            print(multi_key)  # "2-of-3 Multi key"

        Verification with multi-signature::

            message = b"Multi-sig transaction"

            # Keys 0 and 2 sign (satisfies threshold of 2)
            sig1 = private_key1.sign(message)
            sig3 = private_key3.sign(message)
            multi_sig = MultiSignature([(0, sig1), (2, sig3)])

            # Verify
            is_valid = multi_key.verify(message, multi_sig)

        Creating governance multi-sig::

            # 3-of-5 governance setup
            governance_keys = [generate_key() for _ in range(5)]
            governance_multi = MultiPublicKey(governance_keys, threshold=3)

            # Requires 3 signatures for any governance action

    Note:
        All keys are automatically wrapped in PublicKey wrappers for consistency,
        enabling mixed-algorithm multi-signature schemes.
    """

    keys: List[PublicKey]
    threshold: int

    MIN_KEYS = 2
    MAX_KEYS = 32
    MIN_THRESHOLD = 1

    def __init__(self, keys: List[asymmetric_crypto.PublicKey], threshold: int):
        """Initialize a multi-signature public key with the given parameters.

        Args:
            keys: List of public keys that can participate in signing.
                Must be between MIN_KEYS and MAX_KEYS in length.
            threshold: Minimum number of signatures required for validity.
                Must be between MIN_THRESHOLD and the number of keys.

        Raises:
            AssertionError: If key count or threshold is outside valid ranges.

        Example:
            >>> keys = [key1, key2, key3]
            >>> multi_key = MultiPublicKey(keys, threshold=2)
            >>> len(multi_key.keys)
            3
            >>> multi_key.threshold
            2
        """
        assert (
            self.MIN_KEYS <= len(keys) <= self.MAX_KEYS
        ), f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} keys."
        assert (
            self.MIN_THRESHOLD <= threshold <= len(keys)
        ), f"Threshold must be between {self.MIN_THRESHOLD} and {len(keys)}."

        # Ensure keys are wrapped
        self.keys = []
        for key in keys:
            if isinstance(key, PublicKey):
                self.keys.append(key)
            else:
                self.keys.append(PublicKey(key))

        self.threshold = threshold

    def __str__(self) -> str:
        """Return a human-readable string representation.

        Returns:
            String in the format "{threshold}-of-{total} Multi key".

        Example:
            >>> str(MultiPublicKey([key1, key2, key3], 2))
            '2-of-3 Multi key'
        """
        return f"{self.threshold}-of-{len(self.keys)} Multi key"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        """Verify a multi-signature against this multi-public-key.

        Validates that the provided multi-signature contains at least the
        threshold number of valid signatures from keys in this multi-key set.

        Args:
            data: The original data that was signed.
            signature: A MultiSignature containing indexed signatures.

        Returns:
            True if the multi-signature satisfies the threshold requirement
            and all included signatures are valid, False otherwise.

        Verification Process:
            1. Ensures sufficient signatures are provided (>= threshold)
            2. Validates each signature index is within the key set bounds
            3. Verifies each signature against its corresponding public key
            4. Returns False if any validation step fails

        Example:
            >>> message = b"transaction data"
            >>> multi_sig = MultiSignature([(0, sig1), (2, sig3)])
            >>> multi_key.verify(message, multi_sig)  # 2 sigs >= threshold
            True

        Note:
            This method uses exception handling for robustness, returning False
            for any verification failure rather than propagating exceptions.
        """
        try:
            total_sig = cast(MultiSignature, signature)
            assert self.threshold <= len(
                total_sig.signatures
            ), f"Insufficient signatures, {self.threshold} > {len(total_sig.signatures)}"

            for idx, signature in total_sig.signatures:
                assert (
                    len(self.keys) > idx
                ), f"Signature index exceeds available keys {len(self.keys)} < {idx}"
                assert self.keys[idx].verify(
                    data, signature
                ), "Unable to verify signature"

        except Exception:
            return False
        return True

    @staticmethod
    def from_crypto_bytes(indata: bytes) -> MultiPublicKey:
        """Deserialize a MultiPublicKey from its byte representation.

        Args:
            indata: BCS-serialized bytes of the multi-public-key.

        Returns:
            A new MultiPublicKey instance.

        Example:
            >>> original_bytes = multi_key.to_crypto_bytes()
            >>> restored_key = MultiPublicKey.from_crypto_bytes(original_bytes)
        """
        deserializer = Deserializer(indata)
        return deserializer.struct(MultiPublicKey)

    def to_crypto_bytes(self) -> bytes:
        """Serialize the MultiPublicKey to its byte representation.

        Returns:
            BCS-serialized bytes suitable for storage or transmission.

        Example:
            >>> multi_bytes = multi_key.to_crypto_bytes()
            >>> len(multi_bytes)  # Depends on number and types of keys
        """
        serializer = Serializer()
        serializer.struct(self)
        return serializer.output()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiPublicKey:
        """Deserialize a MultiPublicKey from a BCS deserializer.

        Args:
            deserializer: BCS deserializer containing the multi-key data.

        Returns:
            A new MultiPublicKey instance with the deserialized keys and threshold.

        Example:
            >>> deserializer = Deserializer(serialized_data)
            >>> multi_key = MultiPublicKey.deserialize(deserializer)
        """
        keys = deserializer.sequence(PublicKey.deserialize)
        threshold = deserializer.u8()
        return MultiPublicKey(keys, threshold)

    def serialize(self, serializer: Serializer):
        """Serialize the MultiPublicKey to a BCS serializer.

        Args:
            serializer: BCS serializer to write the multi-key data to.

        Example:
            >>> serializer = Serializer()
            >>> multi_key.serialize(serializer)
            >>> serialized_bytes = serializer.output()
        """
        serializer.sequence(self.keys, Serializer.struct)
        serializer.u8(self.threshold)


class MultiSignature(asymmetric_crypto.Signature):
    """Multi-signature implementation with bitmap-based key indexing.

    This class represents a collection of signatures created by different keys
    within a multi-signature scheme. It uses bitmap encoding to efficiently
    track which keys in the set provided signatures.

    Bitmap Encoding:
    - Each signature is associated with an index (position in the key array)
    - A bitmap efficiently encodes which positions have signatures
    - Supports up to MAX_SIGNATURES concurrent signatures
    - Optimizes storage and verification performance

    Constraints:
        MAX_SIGNATURES (16): Maximum number of signatures in one multi-signature

    Attributes:
        signatures: List of (index, signature) tuples where index refers
            to the position in the corresponding MultiPublicKey's key array

    Examples:
        Creating a multi-signature::

            # Keys at positions 0 and 2 sign
            sig1 = private_key1.sign(message)
            sig3 = private_key3.sign(message)  # Note: key3 is at index 2

            multi_sig = MultiSignature([(0, sig1), (2, sig3)])

        Verifying with corresponding multi-key::

            # MultiPublicKey with keys [key1, key2, key3], threshold=2
            is_valid = multi_key.verify(message, multi_sig)
            # True because we have 2 signatures >= threshold

        Mixed algorithm signatures::

            # Ed25519 signature at index 0
            ed25519_sig = ed25519_private.sign(message)

            # secp256k1 signature at index 1
            secp256k1_sig = secp256k1_private.sign(message)

            mixed_multi_sig = MultiSignature([
                (0, ed25519_sig),
                (1, secp256k1_sig)
            ])

    Note:
        Signatures are automatically wrapped in Signature wrappers to ensure
        type consistency and proper serialization.
    """

    signatures: List[Tuple[int, Signature]]
    MAX_SIGNATURES: int = 16

    def __init__(self, signatures: List[Tuple[int, asymmetric_crypto.Signature]]):
        """Initialize a multi-signature with indexed signatures.

        Args:
            signatures: List of (index, signature) tuples where index
                corresponds to the position in the MultiPublicKey's key array.

        Raises:
            AssertionError: If any index exceeds MAX_SIGNATURES.

        Example:
            >>> sig1 = private_key1.sign(message)
            >>> sig2 = private_key2.sign(message)
            >>> multi_sig = MultiSignature([(0, sig1), (1, sig2)])
            >>> len(multi_sig.signatures)
            2
        """
        # Sort first to ensure no issues in order
        # signatures.sort(key=lambda x: x[0])
        self.signatures = []
        for index, signature in signatures:
            assert index < self.MAX_SIGNATURES, "bitmap value exceeds maximum value"
            if isinstance(signature, Signature):
                self.signatures.append((index, signature))
            else:
                self.signatures.append((index, Signature(signature)))

    def __eq__(self, other: object):
        """Check equality with another MultiSignature.

        Args:
            other: Object to compare with.

        Returns:
            True if both MultiSignatures have identical signatures and indices.

        Example:
            >>> multi_sig1 == multi_sig2
            True  # If they contain the same (index, signature) pairs
        """
        if not isinstance(other, MultiSignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        """Return a string representation of the multi-signature.

        Returns:
            String representation showing the (index, signature) pairs.

        Example:
            >>> str(multi_sig)
            '[(0, <Signature>), (2, <Signature>)]'
        """
        return f"{self.signatures}"

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiSignature:
        """Deserialize a MultiSignature from BCS-encoded data.

        Reads the signature sequence and bitmap to reconstruct the indexed
        signatures. The bitmap indicates which key positions have signatures.

        Args:
            deserializer: BCS deserializer containing the multi-signature data.

        Returns:
            A new MultiSignature with the deserialized indexed signatures.

        Deserialization Process:
            1. Read the sequence of signatures
            2. Read the bitmap indicating which keys signed
            3. Reconstruct (index, signature) pairs using bitmap

        Example:
            >>> deserializer = Deserializer(serialized_data)
            >>> multi_sig = MultiSignature.deserialize(deserializer)
        """
        signatures = deserializer.sequence(Signature.deserialize)
        bitmap_raw = deserializer.to_bytes()
        bitmap = int.from_bytes(bitmap_raw, "little")
        num_bits = len(bitmap_raw) * 8
        sig_index = 0
        indexed_signatures = []

        for i in range(0, num_bits):
            has_signature = (bitmap & index_to_bitmap_value(i)) != 0
            if has_signature:
                indexed_signatures.append((i, signatures[sig_index]))
                sig_index += 1

        return MultiSignature(indexed_signatures)

    def serialize(self, serializer: Serializer):
        """Serialize the MultiSignature to BCS format.

        Creates a compact representation using a signature sequence and bitmap.
        The bitmap efficiently encodes which key indices have signatures.

        Args:
            serializer: BCS serializer to write the multi-signature data to.

        Serialization Format:
            1. Sequence of signatures (without indices)
            2. Bitmap indicating which key positions signed
            3. Variable-length bitmap encoding (1 or 2 bytes)

        Example:
            >>> serializer = Serializer()
            >>> multi_sig.serialize(serializer)
            >>> serialized_bytes = serializer.output()
        """
        actual_sigs = []
        bitmap = 0

        for i, signature in self.signatures:
            bitmap |= index_to_bitmap_value(i)
            actual_sigs.append(signature)

        serializer.sequence(actual_sigs, Serializer.struct)
        count = 1 if bitmap < 256 else 2
        serializer.to_bytes(bitmap.to_bytes(count, "little"))


def index_to_bitmap_value(i: int) -> int:
    """Convert a key index to its corresponding bitmap bit value.

    This function implements the bitmap encoding used in multi-signatures
    to efficiently represent which keys in a set have provided signatures.

    Args:
        i: The key index (0-based position in the key array).

    Returns:
        The bitmap value with the appropriate bit set for the given index.

    Bitmap Layout:
        - Bits are ordered with the most significant bit representing index 0
        - Multiple bytes are used for indices > 7
        - Little-endian byte ordering is used

    Examples:
        >>> index_to_bitmap_value(0)  # First key
        128  # Binary: 10000000
        >>> index_to_bitmap_value(7)  # Eighth key
        1    # Binary: 00000001
        >>> index_to_bitmap_value(8)  # Ninth key (second byte)
        32768  # Binary: 10000000 00000000

    Note:
        This encoding matches the Aptos blockchain's multi-signature bitmap format.
    """
    bit = i % 8
    byte = i // 8
    return (128 >> bit) << (byte * 8)
