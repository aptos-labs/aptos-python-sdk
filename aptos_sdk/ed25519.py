# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Ed25519 cryptographic primitives for the Aptos Python SDK.

This module provides Ed25519 digital signature functionality for the Aptos blockchain,
including single and multi-signature support. Ed25519 is a high-performance elliptic
curve signature scheme that provides strong security guarantees.

The module includes:
- PrivateKey: Ed25519 private keys for signing operations
- PublicKey: Ed25519 public keys for signature verification
- Signature: Ed25519 signatures
- MultiPublicKey: Multi-signature public key aggregation
- MultiSignature: Multi-signature support with threshold verification

All classes support BCS serialization for blockchain transactions and provide
standard string representations for interoperability.

Examples:
    Basic key generation and signing::

        # Generate a random private key
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        # Sign some data
        message = b"Hello, Aptos!"
        signature = private_key.sign(message)

        # Verify the signature
        is_valid = public_key.verify(message, signature)

    Multi-signature operations::

        # Create a 2-of-3 multisig
        keys = [PrivateKey.random().public_key() for _ in range(3)]
        multisig_key = MultiPublicKey(keys, threshold=2)

        # Create signatures from 2 signers
        sig1 = private_key1.sign(message)
        sig2 = private_key2.sign(message)

        # Combine into multisig
        multisig = MultiSignature.from_key_map(multisig_key, [
            (keys[0], sig1), (keys[1], sig2)
        ])

        # Verify multisig
        is_valid = multisig_key.verify(message, multisig)

    AIP-80 compliant key formats::

        # Create from AIP-80 format
        key = PrivateKey.from_str(
            "ed25519-priv-0x123...", strict=True
        )

        # Export to AIP-80 format
        aip80_string = key.aip80()
"""

from __future__ import annotations

import unittest
from typing import List, Tuple, cast

from nacl.signing import SigningKey, VerifyKey

from . import asymmetric_crypto
from .bcs import Deserializer, Serializer


class PrivateKey(asymmetric_crypto.PrivateKey):
    """Ed25519 private key for digital signatures on Aptos.

    A private key is used to create digital signatures and derive the corresponding
    public key. This implementation uses the NaCl library for cryptographic operations
    and supports AIP-80 compliant key formats for interoperability.

    The private key is exactly 32 bytes (256 bits) as specified by the Ed25519
    signature scheme.

    Attributes:
        LENGTH: The byte length of Ed25519 private keys (32)
        key: The underlying NaCl SigningKey instance

    Examples:
        Creating and using private keys::

            # Generate a random private key
            private_key = PrivateKey.random()

            # Create from hex string
            hex_key = PrivateKey.from_hex("0x123...")

            # Create from AIP-80 format
            aip80_key = PrivateKey.from_str(
                "ed25519-priv-0x123...", strict=True
            )

            # Sign data
            signature = private_key.sign(b"message")

            # Get public key
            public_key = private_key.public_key()
    """

    LENGTH: int = 32

    key: SigningKey

    def __init__(self, key: SigningKey):
        """Initialize a PrivateKey with a NaCl SigningKey.

        Args:
            key: The NaCl SigningKey instance to wrap.
        """
        self.key = key

    def __eq__(self, other: object):
        """Check equality with another PrivateKey.

        Args:
            other: The object to compare with.

        Returns:
            True if both private keys are identical.
        """
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self):
        """Get the AIP-80 compliant string representation.

        Returns:
            AIP-80 formatted private key string (e.g., "ed25519-priv-0x123...").
        """
        return self.aip80()

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> PrivateKey:
        """Parse a hex input to create an Ed25519 private key.

        Supports multiple input formats including plain hex strings, byte arrays,
        and AIP-80 compliant prefixed strings. This provides flexibility for
        different key storage and transmission formats.

        Args:
            value: A hex string (with or without "0x" prefix), byte array,
                or AIP-80 compliant string ("ed25519-priv-0x...").
            strict: If True, the value MUST be AIP-80 compliant. If False,
                accepts plain hex. If None, auto-detects format.

        Returns:
            A new PrivateKey instance.

        Raises:
            Exception: If the input format is invalid or the key data
                has incorrect length.

        Examples:
            Different input formats::

                # Plain hex string
                key1 = PrivateKey.from_hex("123abc...")

                # Hex with 0x prefix
                key2 = PrivateKey.from_hex("0x123abc...")

                # AIP-80 format (strict mode)
                key3 = PrivateKey.from_hex(
                    "ed25519-priv-0x123abc...", strict=True
                )

                # Raw bytes
                key4 = PrivateKey.from_hex(b"\x12\x3a\xbc...")
        """
        return PrivateKey(
            SigningKey(
                PrivateKey.parse_hex_input(
                    value, asymmetric_crypto.PrivateKeyVariant.Ed25519, strict
                )
            )
        )

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> PrivateKey:
        """Parse a string representation to create an Ed25519 private key.

        This is a convenience method that delegates to from_hex() for string inputs.
        Supports both plain hex strings and AIP-80 compliant formats.

        Args:
            value: A hex string (with or without "0x" prefix) or AIP-80
                compliant string ("ed25519-priv-0x...").
            strict: If True, the value MUST be AIP-80 compliant. If False,
                accepts plain hex. If None, auto-detects format.

        Returns:
            A new PrivateKey instance.

        Raises:
            Exception: If the input format is invalid or the key data
                has incorrect length.
        """
        return PrivateKey.from_hex(value, strict)

    def hex(self) -> str:
        """Get the hexadecimal representation of the private key.

        Returns:
            Hex string with "0x" prefix representing the 32-byte private key.
        """
        return f"0x{self.key.encode().hex()}"

    def aip80(self) -> str:
        """Get the AIP-80 compliant string representation.

        AIP-80 (Aptos Improvement Proposal 80) defines a standard format
        for representing private keys with type prefixes for improved
        safety and interoperability.

        Returns:
            AIP-80 formatted string ("ed25519-priv-0x...").
        """
        return PrivateKey.format_private_key(
            self.hex(), asymmetric_crypto.PrivateKeyVariant.Ed25519
        )

    def public_key(self) -> PublicKey:
        """Derive the corresponding public key from this private key.

        Returns:
            The PublicKey that corresponds to this private key.
        """
        return PublicKey(self.key.verify_key)

    @staticmethod
    def random() -> PrivateKey:
        """Generate a cryptographically secure random private key.

        Uses the system's secure random number generator to create
        a new Ed25519 private key.

        Returns:
            A new randomly generated PrivateKey instance.
        """
        return PrivateKey(SigningKey.generate())

    def sign(self, data: bytes) -> Signature:
        """Create a digital signature for the given data.

        Args:
            data: The raw bytes to sign.

        Returns:
            An Ed25519 Signature for the input data.
        """
        return Signature(self.key.sign(data).signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        """Deserialize a PrivateKey from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized PrivateKey instance.

        Raises:
            Exception: If the key data is not exactly 32 bytes.
        """
        key = deserializer.to_bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")

        return PrivateKey(SigningKey(key))

    def serialize(self, serializer: Serializer):
        """Serialize this PrivateKey to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.to_bytes(self.key.encode())


class PublicKey(asymmetric_crypto.PublicKey):
    """Ed25519 public key for signature verification on Aptos.

    A public key is derived from a private key and used to verify digital
    signatures. Ed25519 public keys are exactly 32 bytes and provide strong
    security guarantees for signature verification.

    Attributes:
        LENGTH: The byte length of Ed25519 public keys (32)
        key: The underlying NaCl VerifyKey instance

    Examples:
        Creating and using public keys::

            # Derive from private key
            private_key = PrivateKey.random()
            public_key = private_key.public_key()

            # Create from hex string
            hex_key = PublicKey.from_str("0x123abc...")

            # Verify a signature
            is_valid = public_key.verify(message, signature)
    """

    LENGTH: int = 32

    key: VerifyKey

    def __init__(self, key: VerifyKey):
        """Initialize a PublicKey with a NaCl VerifyKey.

        Args:
            key: The NaCl VerifyKey instance to wrap.
        """
        self.key = key

    def __eq__(self, other: object):
        """Check equality with another PublicKey.

        Args:
            other: The object to compare with.

        Returns:
            True if both public keys are identical.
        """
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self) -> str:
        """Get the hexadecimal string representation.

        Returns:
            Hex string with "0x" prefix representing the 32-byte public key.
        """
        return f"0x{self.key.encode().hex()}"

    @staticmethod
    def from_str(value: str) -> PublicKey:
        """Create a PublicKey from its hexadecimal string representation.

        Args:
            value: Hex string representing the public key, with or without
                "0x" prefix.

        Returns:
            A new PublicKey instance.

        Raises:
            ValueError: If the hex string is invalid or has wrong length.
        """
        if value[0:2] == "0x":
            value = value[2:]
        return PublicKey(VerifyKey(bytes.fromhex(value)))

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        """Verify a digital signature against the given data.

        Args:
            data: The original data that was signed.
            signature: The signature to verify (must be an Ed25519 Signature).

        Returns:
            True if the signature is valid for the given data, False otherwise.

        Note:
            This method safely handles verification failures and returns False
            for any exception during verification.
        """
        try:
            signature = cast(Signature, signature)
            self.key.verify(data, signature.data())
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        """Get the raw cryptographic bytes of the public key.

        Returns:
            The 32-byte Ed25519 public key as raw bytes.
        """
        return self.key.encode()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        """Deserialize a PublicKey from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized PublicKey instance.

        Raises:
            Exception: If the key data is not exactly 32 bytes.
        """
        key = deserializer.to_bytes()
        if len(key) != PublicKey.LENGTH:
            raise Exception("Length mismatch")

        return PublicKey(VerifyKey(key))

    def serialize(self, serializer: Serializer):
        """Serialize this PublicKey to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.to_bytes(self.key.encode())


class MultiPublicKey(asymmetric_crypto.PublicKey):
    """Multi-signature public key for threshold signature schemes.

    A MultiPublicKey represents a collection of Ed25519 public keys with a
    threshold requirement. It enables M-of-N signature schemes where M signatures
    from N possible signers are required to validate a transaction.

    This is useful for multi-party custody, governance, and other scenarios
    requiring distributed authorization.

    Attributes:
        keys: List of individual Ed25519 public keys.
        threshold: Minimum number of signatures required for validation.
        MIN_KEYS: Minimum number of keys allowed (2).
        MAX_KEYS: Maximum number of keys allowed (32).
        MIN_THRESHOLD: Minimum threshold value (1).

    Examples:
        Creating a 2-of-3 multisig::

            keys = [
                PrivateKey.random().public_key(),
                PrivateKey.random().public_key(),
                PrivateKey.random().public_key()
            ]
            multisig = MultiPublicKey(keys, threshold=2)

        Verifying a multisig signature::

            is_valid = multisig.verify(message, multi_signature)
    """

    keys: List[PublicKey]
    threshold: int

    MIN_KEYS = 2
    MAX_KEYS = 32
    MIN_THRESHOLD = 1

    def __init__(self, keys: List[PublicKey], threshold: int):
        """Initialize a MultiPublicKey with keys and threshold.

        Args:
            keys: List of Ed25519 public keys (2-32 keys).
            threshold: Number of signatures required (1 to len(keys)).

        Raises:
            AssertionError: If key count or threshold is outside valid ranges.
        """
        assert (
            self.MIN_KEYS <= len(keys) <= self.MAX_KEYS
        ), f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} keys."
        assert (
            self.MIN_THRESHOLD <= threshold <= len(keys)
        ), f"Threshold must be between {self.MIN_THRESHOLD} and {len(keys)}."

        self.keys = keys
        self.threshold = threshold

    def __str__(self) -> str:
        """Get string representation of the multisig configuration.

        Returns:
            Human-readable description (e.g., "2-of-3 Multi-Ed25519 public key").
        """
        return f"{self.threshold}-of-{len(self.keys)} Multi-Ed25519 public key"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        try:
            signatures = cast(MultiSignature, signature)
            assert self.threshold <= len(
                signatures.signatures
            ), f"Insufficient signatures, {self.threshold} > {len(signatures.signatures)}"

            for idx, signature in signatures.signatures:
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
        total_keys = int(len(indata) / PublicKey.LENGTH)
        keys: List[PublicKey] = []
        for idx in range(total_keys):
            start = idx * PublicKey.LENGTH
            end = (idx + 1) * PublicKey.LENGTH
            keys.append(PublicKey(VerifyKey(indata[start:end])))
        threshold = indata[-1]
        return MultiPublicKey(keys, threshold)

    def to_crypto_bytes(self) -> bytes:
        key_bytes = bytearray()
        for key in self.keys:
            key_bytes.extend(key.to_crypto_bytes())
        key_bytes.append(self.threshold)
        return key_bytes

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiPublicKey:
        indata = deserializer.to_bytes()
        return MultiPublicKey.from_crypto_bytes(indata)

    def serialize(self, serializer: Serializer):
        serializer.to_bytes(self.to_crypto_bytes())


class Signature(asymmetric_crypto.Signature):
    """Ed25519 digital signature.

    Represents a 64-byte Ed25519 signature created by signing data with
    an Ed25519 private key. Signatures can be verified using the corresponding
    public key.

    Attributes:
        LENGTH: The byte length of Ed25519 signatures (64).
        signature: The raw signature bytes.

    Examples:
        Creating and using signatures::

            private_key = PrivateKey.random()
            message = b"Hello, Aptos!"

            # Create signature
            signature = private_key.sign(message)

            # Verify signature
            public_key = private_key.public_key()
            is_valid = public_key.verify(message, signature)

            # Convert to/from hex string
            hex_sig = str(signature)
            parsed_sig = Signature.from_str(hex_sig)
    """

    LENGTH: int = 64

    signature: bytes

    def __init__(self, signature: bytes):
        """Initialize a Signature with raw signature bytes.

        Args:
            signature: The 64-byte Ed25519 signature data.
        """
        self.signature = signature

    def __eq__(self, other: object):
        """Check equality with another Signature.

        Args:
            other: The object to compare with.

        Returns:
            True if both signatures are identical.
        """
        if not isinstance(other, Signature):
            return NotImplemented
        return self.signature == other.signature

    def __str__(self) -> str:
        """Get hexadecimal string representation.

        Returns:
            Hex string with "0x" prefix representing the 64-byte signature.
        """
        return f"0x{self.signature.hex()}"

    def data(self) -> bytes:
        """Get the raw signature bytes.

        Returns:
            The 64-byte signature as raw bytes.
        """
        return self.signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        """Deserialize a Signature from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized Signature instance.

        Raises:
            Exception: If the signature data is not exactly 64 bytes.
        """
        signature = deserializer.to_bytes()
        if len(signature) != Signature.LENGTH:
            raise Exception("Length mismatch")

        return Signature(signature)

    @staticmethod
    def from_str(value: str) -> Signature:
        """Create a Signature from its hexadecimal string representation.

        Args:
            value: Hex string representing the signature, with or without
                "0x" prefix.

        Returns:
            A new Signature instance.

        Raises:
            ValueError: If the hex string is invalid or has wrong length.
        """
        if value[0:2] == "0x":
            value = value[2:]
        return Signature(bytes.fromhex(value))

    def serialize(self, serializer: Serializer):
        """Serialize this Signature to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.to_bytes(self.signature)


class MultiSignature(asymmetric_crypto.Signature):
    """Multi-signature combining multiple Ed25519 signatures.

    A MultiSignature aggregates individual signatures from multiple signers
    along with a bitmap indicating which signers participated. This enables
    efficient threshold signature verification.

    The encoding uses a 4-byte bitmap to track which of the up to 32 possible
    signers provided signatures, followed by the actual signature data.

    Attributes:
        signatures: List of (signer_index, signature) tuples.
        BITMAP_NUM_OF_BYTES: Size of the signer bitmap (4 bytes).

    Examples:
        Creating a multisig from individual signatures::

            # Create signatures from 2 of 3 signers
            sig1 = private_key1.sign(message)
            sig2 = private_key3.sign(message)  # Skip signer 2

            # Create multisig
            multisig = MultiSignature.from_key_map(
                multisig_public_key,
                [(public_key1, sig1), (public_key3, sig2)]
            )

        Verifying a multisig::

            is_valid = multisig_public_key.verify(message, multisig)
    """

    signatures: List[Tuple[int, Signature]]
    BITMAP_NUM_OF_BYTES: int = 4

    def __init__(self, signatures: List[Tuple[int, Signature]]):
        """Initialize a MultiSignature with signer indices and signatures.

        Args:
            signatures: List of (signer_index, signature) tuples where
                signer_index is the position in the MultiPublicKey.

        Raises:
            AssertionError: If any signer index exceeds bitmap capacity (32).
        """
        for signature in signatures:
            assert (
                signature[0] < self.BITMAP_NUM_OF_BYTES * 8
            ), "bitmap value exceeds maximum value"
        self.signatures = signatures

    def __eq__(self, other: object):
        """Check equality with another MultiSignature.

        Args:
            other: The object to compare with.

        Returns:
            True if both multisigs have identical signatures.
        """
        if not isinstance(other, MultiSignature):
            return NotImplemented
        return self.signatures == other.signatures

    def __str__(self) -> str:
        """Get string representation of the multisig.

        Returns:
            String showing the list of (index, signature) pairs.
        """
        return f"{self.signatures}"

    @staticmethod
    def from_key_map(
        public_key: MultiPublicKey,
        signatures_map: List[Tuple[PublicKey, Signature]],
    ) -> MultiSignature:
        """Create a MultiSignature from a key-signature mapping.

        This convenience method maps public keys to their indices in the
        MultiPublicKey and creates the appropriate MultiSignature structure.

        Args:
            public_key: The MultiPublicKey containing the signer keys.
            signatures_map: List of (public_key, signature) pairs.

        Returns:
            A new MultiSignature with the mapped indices.

        Raises:
            ValueError: If a public key is not found in the MultiPublicKey.
        """
        signatures = []

        for entry in signatures_map:
            signatures.append((public_key.keys.index(entry[0]), entry[1]))
        return MultiSignature(signatures)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiSignature:
        """Deserialize a MultiSignature from a BCS byte stream.

        The format is: [signature_1][signature_2]...[4-byte bitmap]
        The bitmap indicates which signer positions have signatures.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized MultiSignature instance.

        Raises:
            AssertionError: If the byte length doesn't match expected format.
        """
        signature_bytes = deserializer.to_bytes()
        count = len(signature_bytes) // Signature.LENGTH
        assert count * Signature.LENGTH + MultiSignature.BITMAP_NUM_OF_BYTES == len(
            signature_bytes
        ), "MultiSignature length is invalid"

        bitmap = int.from_bytes(signature_bytes[-4:], "big")

        current = 0
        position = 0
        signatures = []
        while current < count:
            to_check = 1 << (31 - position)
            if to_check & bitmap:
                left = current * Signature.LENGTH
                signature = Signature(signature_bytes[left : left + Signature.LENGTH])
                signatures.append((position, signature))
                current += 1
            position += 1

        return MultiSignature(signatures)

    def serialize(self, serializer: Serializer):
        """Serialize this MultiSignature to a BCS byte stream.

        The format is: [signature_1][signature_2]...[4-byte bitmap]
        The bitmap has bits set for each signer position that has a signature.

        Args:
            serializer: The BCS serializer to write to.
        """
        signature_bytes = bytearray()
        bitmap = 0

        for signature in self.signatures:
            shift = 31 - signature[0]
            bitmap = bitmap | (1 << shift)
            signature_bytes.extend(signature[1].data())

        signature_bytes.extend(
            bitmap.to_bytes(MultiSignature.BITMAP_NUM_OF_BYTES, "big")
        )
        serializer.to_bytes(signature_bytes)


class Test(unittest.TestCase):
    """Comprehensive test suite for Ed25519 cryptographic operations.

    Tests all aspects of Ed25519 functionality including:
    - Key generation and parsing
    - AIP-80 format compliance
    - Digital signature creation and verification
    - BCS serialization/deserialization
    - Multi-signature operations and validation
    - Range checking and error handling
    """

    def test_private_key_from_str(self):
        private_key_hex = PrivateKey.from_str(
            "0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe", False
        )
        private_key_with_prefix = PrivateKey.from_str(
            "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe",
            True,
        )
        private_key_bytes = PrivateKey.from_hex(
            bytes.fromhex(
                "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
            ),
            False,
        )
        self.assertEqual(
            private_key_hex.hex(),
            private_key_with_prefix.hex(),
            private_key_bytes.hex(),
        )

    def test_private_key_aip80_formatting(self):
        private_key_with_prefix = "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        self.assertEqual(
            str(PrivateKey.from_str(private_key_with_prefix, True)),
            private_key_with_prefix,
        )

    def test_sign_and_verify(self):
        in_value = b"test_message"

        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        signature = private_key.sign(in_value)
        self.assertTrue(public_key.verify(in_value, signature))

    def test_private_key_serialization(self):
        private_key = PrivateKey.random()
        ser = Serializer()

        private_key.serialize(ser)
        ser_private_key = PrivateKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(private_key, ser_private_key)

    def test_public_key_serialization(self):
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        ser = Serializer()
        public_key.serialize(ser)
        ser_public_key = PublicKey.deserialize(Deserializer(ser.output()))
        self.assertEqual(public_key, ser_public_key)

    def test_signature_key_serialization(self):
        private_key = PrivateKey.random()
        in_value = b"another_message"
        signature = private_key.sign(in_value)

        ser = Serializer()
        signature.serialize(ser)
        ser_signature = Signature.deserialize(Deserializer(ser.output()))
        self.assertEqual(signature, ser_signature)

    def test_multisig(self):
        # Generate signatory private keys.
        private_key_1 = PrivateKey.from_str(
            "ed25519-priv-0x4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = PrivateKey.from_str(
            "ed25519-priv-0x1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        # Generate multisig public key with threshold of 1.
        multisig_public_key = MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_public_key_bcs = (
            "41754bb6a4720a658bdd5f532995955db0971ad3519acbde2f1149c3857348006c"
            "1634cd4607073f2be4a6f2aadc2b866ddb117398a675f2096ed906b20e0bf2c901"
        )
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Get public key bytes representation.
        public_key_bytes = multisig_public_key.to_bytes()
        # Convert back to multisig class instance from bytes.
        multisig_public_key = MultiPublicKey.from_bytes(public_key_bytes)
        # Get public key BCS representation.
        serializer = Serializer()
        multisig_public_key.serialize(serializer)
        public_key_bcs = serializer.output().hex()
        # Assert BCS representation is the same.
        self.assertEqual(public_key_bcs, expected_public_key_bcs)
        # Have one signer sign arbitrary message.
        signature = private_key_2.sign(b"multisig")
        # Compose multisig signature.
        multisig_signature = MultiSignature.from_key_map(
            multisig_public_key, [(private_key_2.public_key(), signature)]
        )
        # Get signature BCS representation.
        serializer = Serializer()
        multisig_signature.serialize(serializer)
        multisig_signature_bcs = serializer.output().hex()
        # Check against expected BCS representation.
        expected_multisig_signature_bcs = (
            "4402e90d8f300d79963cb7159ffa6f620f5bba4af5d32a7176bfb5480b43897cf"
            "4886bbb4042182f4647c9b04f02dbf989966f0facceec52d22bdcc7ce631bfc0c"
            "40000000"
        )
        self.assertEqual(multisig_signature_bcs, expected_multisig_signature_bcs)
        deserializer = Deserializer(bytes.fromhex(expected_multisig_signature_bcs))
        multisig_signature_deserialized = deserializer.struct(MultiSignature)
        self.assertEqual(multisig_signature_deserialized, multisig_signature)

        self.assertTrue(multisig_public_key.verify(b"multisig", multisig_signature))

    def test_multisig_range_checks(self):
        # Generate public keys.
        keys = [
            PrivateKey.random().public_key() for x in range(MultiPublicKey.MAX_KEYS + 1)
        ]
        # Verify failure for initializing multisig instance with too few keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey([keys[0]], 1)
        # Verify failure for initializing multisig instance with too many keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey(keys, 1)
        # Verify failure for initializing multisig instance with small threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey(keys[0:4], 0)
        # Verify failure for initializing multisig instance with large threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey(keys[0:4], 5)
        # Verify failure for initializing from bytes with too few keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey([keys[0]], 1).to_bytes())
        # Verify failure for initializing from bytes with too many keys.
        with self.assertRaisesRegex(AssertionError, "Must have between 2 and 32 keys."):
            MultiPublicKey.from_bytes(MultiPublicKey(keys, 1).to_bytes())
        # Verify failure for initializing from bytes with small threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 0).to_bytes())
        # Verify failure for initializing from bytes with large threshold.
        with self.assertRaisesRegex(
            AssertionError, "Threshold must be between 1 and 4."
        ):
            MultiPublicKey.from_bytes(MultiPublicKey(keys[0:4], 5).to_bytes())
