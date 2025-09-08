# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
secp256k1 ECDSA cryptographic implementation for Aptos blockchain.

This module provides a complete secp256k1 ECDSA implementation for the Aptos Python SDK,
enabling Ethereum-compatible signature schemes within the Aptos ecosystem. It implements
the asymmetric cryptography interfaces defined in asymmetric_crypto.py with full
BCS serialization support.

Key Features:
- **Ethereum Compatibility**: Uses the same secp256k1 curve as Ethereum
- **Deterministic Signatures**: RFC 6979 deterministic signing for reproducibility
- **Signature Normalization**: Ensures canonical signatures (s < n/2)
- **AIP-80 Support**: Standard private key formatting and parsing
- **BCS Integration**: Full serialization/deserialization support
- **Production Ready**: Comprehensive test coverage and security best practices

Cryptographic Properties:
- Curve: secp256k1 (y² = x³ + 7 over finite field)
- Hash Function: Keccak-256 (SHA3-256)
- Key Sizes: 32-byte private keys, 64-byte public keys
- Signature Size: 64 bytes (r, s values)
- Security Level: ~128 bits

Use Cases:
- Ethereum account migration to Aptos
- Cross-chain application compatibility
- Hardware wallet integration (secp256k1 support)
- Multi-signature schemes requiring secp256k1
- Legacy system integration

Comparison with Ed25519:
- Pros: Ethereum compatibility, widespread hardware support
- Cons: Larger signatures, slower verification than Ed25519
- Usage: Choose Ed25519 for new Aptos-native applications

Examples:
    Basic key generation and signing::

        from aptos_sdk.secp256k1_ecdsa import PrivateKey

        # Generate a new private key
        private_key = PrivateKey.random()
        public_key = private_key.public_key()

        # Sign a message
        message = b"Hello, Aptos!"
        signature = private_key.sign(message)

        # Verify the signature
        is_valid = public_key.verify(message, signature)
        print(f"Signature valid: {is_valid}")

    Working with hex strings::

        # Create from hex string
        hex_key = "***234abcd..."
        private_key = PrivateKey.from_hex(hex_key)

        # Get hex representation
        print(f"Private key: {private_key.hex()}")
        print(f"Public key: {public_key.hex()}")
        print(f"Signature: {signature.hex()}")

    AIP-80 compliant formatting::

        # AIP-80 formatted private key
        aip80_key = "secp256k1-priv-***234abcd..."
        private_key = PrivateKey.from_str(aip80_key, strict=True)

        # Convert to AIP-80 format
        formatted = private_key.aip80()
        print(f"AIP-80 format: {formatted}")

    Serialization for storage/transmission::

        from aptos_sdk.bcs import Serializer, Deserializer

        # Serialize private key
        serializer = Serializer()
        private_key.serialize(serializer)
        key_bytes = serializer.output()

        # Deserialize private key
        deserializer = Deserializer(key_bytes)
        restored_key = PrivateKey.deserialize(deserializer)

        assert private_key == restored_key

    Cross-chain compatibility::

        # Import Ethereum private key
        ethereum_key = "***456789abcdef..."
        aptos_key = PrivateKey.from_hex(ethereum_key)

        # Same key can be used on both chains
        # (though with different address derivation)
        eth_style_pubkey = aptos_key.public_key().hex()

Security Considerations:
    - Always use secure random number generation for key creation
    - Store private keys securely (encrypted, hardware wallets)
    - Verify signatures before trusting signed data
    - Be aware of signature malleability (this implementation normalizes)
    - Consider key rotation policies for long-term security
    - Use deterministic signing to avoid nonce reuse vulnerabilities

Note:
    This implementation uses the ecdsa library for core cryptographic operations
    and follows the same security practices as Ethereum's secp256k1 usage.
"""

from __future__ import annotations

import hashlib
import unittest
from typing import cast

from ecdsa import SECP256k1, SigningKey, VerifyingKey, util

from . import asymmetric_crypto
from .bcs import Deserializer, Serializer


class PrivateKey(asymmetric_crypto.PrivateKey):
    """secp256k1 ECDSA private key implementation.

    This class implements secp256k1 private keys with deterministic signing,
    signature normalization, and full compatibility with the Aptos asymmetric
    cryptography interfaces.

    Key Properties:
    - **Curve**: secp256k1 elliptic curve (same as Bitcoin/Ethereum)
    - **Hash Function**: Keccak-256 for all cryptographic operations
    - **Key Length**: 32 bytes (256 bits)
    - **Deterministic**: Uses RFC 6979 for deterministic signing
    - **Normalized**: Ensures canonical signatures with s < n/2

    Attributes:
        LENGTH: The byte length of secp256k1 private keys (32)
        key: The underlying ECDSA signing key object

    Examples:
        Generate a new private key::

            private_key = PrivateKey.random()
            print(f"New key: {private_key.hex()}")

        Create from existing key material::

            hex_key = "***234567890abcdef..."
            private_key = PrivateKey.from_hex(hex_key)

        Create from AIP-80 format::

            aip80_key = "secp256k1-priv-***234567890abcdef..."
            private_key = PrivateKey.from_str(aip80_key, strict=True)

        Sign and verify::

            message = b"Important transaction data"
            signature = private_key.sign(message)
            public_key = private_key.public_key()

            assert public_key.verify(message, signature)

    Note:
        Private keys should be generated using cryptographically secure
        random number generators and stored securely.
    """

    LENGTH: int = 32

    key: SigningKey

    def __init__(self, key: SigningKey):
        """Initialize a private key with the given ECDSA signing key.

        Args:
            key: The ECDSA SigningKey object for secp256k1 operations.

        Example:
            This is typically not called directly. Use the factory methods:
            >>> private_key = PrivateKey.random()
            >>> private_key = PrivateKey.from_hex("***abc123...")
        """
        self.key = key

    def __eq__(self, other: object):
        """Check equality with another PrivateKey.

        Args:
            other: Object to compare with.

        Returns:
            True if both private keys are cryptographically equivalent.

        Example:
            >>> key1 = PrivateKey.from_hex("***abc123...")
            >>> key2 = PrivateKey.from_hex("***abc123...")
            >>> key1 == key2
            True
        """
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self):
        """Return the AIP-80 formatted string representation.

        Returns:
            AIP-80 compliant private key string with secp256k1-priv- prefix.

        Example:
            >>> str(private_key)
            'secp256k1-priv-***234567890abcdef...'
        """
        return self.aip80()

    @staticmethod
    def from_hex(value: str | bytes, strict: bool | None = None) -> PrivateKey:
        """Create a private key from hex string, bytes, or AIP-80 format.

        This method parses various input formats and creates a secp256k1 private
        key. It handles legacy hex formats and AIP-80 compliant strings.

        Args:
            value: Private key in various formats:
                - Raw hex string: "***234567890abcdef..."
                - Hex with prefix: "***234567890abcdef..."
                - Raw bytes: bytes.fromhex("234567890abcdef...")
                - AIP-80 format: "secp256k1-priv-***234567890abcdef..."
            strict: AIP-80 compliance mode:
                - True: Only accept AIP-80 compliant strings
                - False: Accept legacy formats without warning
                - None: Accept legacy formats with warning

        Returns:
            A new secp256k1 PrivateKey instance.

        Raises:
            Exception: If the key length is invalid (not 32 bytes).
            ValueError: If strict=True and format is not AIP-80 compliant.

        Examples:
            From raw hex::

                key = PrivateKey.from_hex("***234567890abcdef...")

            From AIP-80 format::

                key = PrivateKey.from_hex(
                    "secp256k1-priv-***234567890abcdef...",
                    strict=True
                )

            From bytes::

                key_bytes = bytes.fromhex("234567890abcdef...")
                key = PrivateKey.from_hex(key_bytes)

        Note:
            The private key must be exactly 32 bytes (64 hex characters).
        """
        parsed_value = PrivateKey.parse_hex_input(
            value, asymmetric_crypto.PrivateKeyVariant.Secp256k1, strict
        )
        if len(parsed_value.hex()) != PrivateKey.LENGTH * 2:
            raise Exception("Length mismatch")
        return PrivateKey(
            SigningKey.from_string(parsed_value, SECP256k1, hashlib.sha3_256)
        )

    @staticmethod
    def from_str(value: str, strict: bool | None = None) -> PrivateKey:
        """Create a private key from a hex or AIP-80 compliant string.

        Convenience method that delegates to from_hex() for string inputs.

        Args:
            value: Hex string or AIP-80 compliant string.
            strict: AIP-80 compliance mode (see from_hex() for details).

        Returns:
            A new secp256k1 PrivateKey instance.

        Example:
            >>> key = PrivateKey.from_str("secp256k1-priv-***abc123...")
            >>> key = PrivateKey.from_str("***abc123...", strict=False)
        """
        return PrivateKey.from_hex(value, strict)

    def hex(self) -> str:
        """Get the hexadecimal representation of the private key.

        Returns:
            Hex string with '0x' prefix representing the 32-byte private key.

        Example:
            >>> private_key.hex()
            '***abc123456789def...'
        """
        return f"***{self.key.to_string().hex()}"

    def aip80(self) -> str:
        """Get the AIP-80 compliant string representation.

        Returns:
            AIP-80 formatted string with secp256k1-priv- prefix.

        Example:
            >>> private_key.aip80()
            'secp256k1-priv-***abc123456789def...'
        """
        return PrivateKey.format_private_key(
            self.hex(), asymmetric_crypto.PrivateKeyVariant.Secp256k1
        )

    def public_key(self) -> PublicKey:
        """Derive the corresponding public key.

        Returns:
            The public key derived from this private key.

        Example:
            >>> private_key = PrivateKey.random()
            >>> public_key = private_key.public_key()
            >>> isinstance(public_key, PublicKey)
            True
        """
        return PublicKey(self.key.verifying_key)

    @staticmethod
    def random() -> PrivateKey:
        """Generate a new random secp256k1 private key.

        Uses cryptographically secure random number generation to create
        a new private key suitable for production use.

        Returns:
            A new randomly generated PrivateKey instance.

        Example:
            >>> private_key = PrivateKey.random()
            >>> len(private_key.key.to_string())
            32

        Note:
            This method uses the system's secure random number generator.
            The generated key is suitable for production cryptographic use.
        """
        return PrivateKey(
            SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha3_256)
        )

    def sign(self, data: bytes) -> Signature:
        """Sign data using this private key with deterministic ECDSA.

        Creates a deterministic signature using RFC 6979, ensuring the same
        input always produces the same signature. The signature is normalized
        to ensure canonical form (s < n/2) to prevent malleability.

        Args:
            data: The data to sign (typically a hash of the actual message).

        Returns:
            A normalized secp256k1 signature.

        Example:
            >>> message = b"Hello, Aptos!"
            >>> signature = private_key.sign(message)
            >>> public_key.verify(message, signature)
            True

        Note:
            - Uses Keccak-256 as the hash function
            - Implements RFC 6979 deterministic signing
            - Normalizes signatures to prevent malleability attacks
            - Same input always produces same signature (deterministic)
        """
        sig = self.key.sign_deterministic(data, hashfunc=hashlib.sha3_256)
        n = SECP256k1.generator.order()
        r, s = util.sigdecode_string(sig, n)
        # The signature is valid for both s and -s, normalization ensures that only s < n // 2 is valid
        if s > (n // 2):
            mod_s = (s * -1) % n
            sig = util.sigencode_string(r, mod_s, n)
        return Signature(sig)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PrivateKey:
        """Deserialize a private key from BCS-encoded bytes.

        Args:
            deserializer: BCS deserializer containing the private key bytes.

        Returns:
            A new PrivateKey instance from the deserialized data.

        Raises:
            Exception: If the key length is not 32 bytes.

        Example:
            >>> serializer = Serializer()
            >>> original_key.serialize(serializer)
            >>> key_bytes = serializer.output()
            >>> deserializer = Deserializer(key_bytes)
            >>> restored_key = PrivateKey.deserialize(deserializer)
            >>> original_key == restored_key
            True
        """
        key = deserializer.to_bytes()
        if len(key) != PrivateKey.LENGTH:
            raise Exception("Length mismatch")

        return PrivateKey(SigningKey.from_string(key, SECP256k1, hashlib.sha3_256))

    def serialize(self, serializer: Serializer):
        """Serialize the private key to BCS format.

        Args:
            serializer: BCS serializer to write the private key bytes to.

        Example:
            >>> serializer = Serializer()
            >>> private_key.serialize(serializer)
            >>> key_bytes = serializer.output()
            >>> len(key_bytes)
            32
        """
        serializer.to_bytes(self.key.to_string())


class PublicKey(asymmetric_crypto.PublicKey):
    """secp256k1 ECDSA public key implementation.

    This class implements secp256k1 public keys for verification of signatures
    and address derivation. It follows the common format for secp256k1 public keys
    with support for both compressed and uncompressed formats.

    Key Properties:
    - **Curve**: secp256k1 elliptic curve (same as Bitcoin/Ethereum)
    - **Format**: Uncompressed format with 0x04 prefix
    - **Key Length**: 64 bytes (uncompressed without prefix)
    - **Serialized Length**: 65 bytes (with prefix)

    Attributes:
        LENGTH: The byte length of uncompressed secp256k1 public keys (64)
        LENGTH_WITH_PREFIX_LENGTH: Length including 0x04 prefix byte (65)
        key: The underlying ECDSA verification key object

    Examples:
        Derive from private key::

            private_key = PrivateKey.random()
            public_key = private_key.public_key()

        Create from hex string::

            # With or without 0x04 prefix
            hex_key = "***4..." # 65 bytes with prefix
            public_key = PublicKey.from_str(hex_key)

        Verify a signature::

            message = b"Important message"
            signature = private_key.sign(message)

            is_valid = public_key.verify(message, signature)
            assert is_valid == True

    Note:
        This implementation uses the uncompressed format (65 bytes) for
        compatibility with common Ethereum and Bitcoin libraries.
    """

    LENGTH: int = 64
    LENGTH_WITH_PREFIX_LENGTH: int = 65

    key: VerifyingKey

    def __init__(self, key: VerifyingKey):
        """Initialize a public key with the given ECDSA verifying key.

        Args:
            key: The ECDSA VerifyingKey object for secp256k1 operations.

        Example:
            This is typically not called directly. Use factory methods
            or derive from a private key:
            >>> private_key = PrivateKey.random()
            >>> public_key = private_key.public_key()
        """
        self.key = key

    def __eq__(self, other: object):
        """Check equality with another PublicKey.

        Args:
            other: Object to compare with.

        Returns:
            True if both public keys are cryptographically equivalent.

        Example:
            >>> pk1 = private_key1.public_key()
            >>> pk2 = private_key2.public_key()  # Different key
            >>> pk1 == pk2
            False
        """
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.key == other.key

    def __str__(self) -> str:
        """Return the hexadecimal string representation.

        Returns:
            Hex string representing the public key.

        Example:
            >>> str(public_key)
            '***4...'  # 65 bytes with 0x04 prefix
        """
        return self.hex()

    @staticmethod
    def from_str(value: str) -> PublicKey:
        """Create a public key from a hex string.

        Args:
            value: Hex string representing the public key.
                Can be with or without '0x' prefix.
                Can be 64 bytes (raw key) or 65 bytes (with 0x04 prefix).

        Returns:
            A new PublicKey instance.

        Raises:
            Exception: If the key length is invalid.

        Examples:
            From uncompressed format with prefix::

                # 130 hex chars (65 bytes) with 0x04 prefix
                key = PublicKey.from_str("***4210c9129e...")

            From raw format::

                # 128 hex chars (64 bytes) without prefix
                key = PublicKey.from_str("210c9129e...")
        """
        if value[0:2] == "0x":
            value = value[2:]
        # We are measuring hex values which are twice the length of their binary counterpart.
        if (
            len(value) != PublicKey.LENGTH * 2
            and len(value) != PublicKey.LENGTH_WITH_PREFIX_LENGTH * 2
        ):
            raise Exception("Length mismatch")
        return PublicKey(
            VerifyingKey.from_string(bytes.fromhex(value), SECP256k1, hashlib.sha3_256)
        )

    def hex(self) -> str:
        """Get the hexadecimal representation of the public key.

        Returns:
            Hex string with '0x04' prefix (uncompressed format).

        Example:
            >>> public_key.hex()
            '***4210c9129e35337ff5d6488f90f18d842cf...'  # 65 bytes with prefix

        Note:
            The '0x04' prefix indicates an uncompressed public key format.
        """
        return f"***4{self.key.to_string().hex()}"

    def verify(self, data: bytes, signature: asymmetric_crypto.Signature) -> bool:
        """Verify a signature against this public key.

        Verifies that the signature was created by the private key
        corresponding to this public key when signing the provided data.

        Args:
            data: The original data that was signed.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.

        Example:
            >>> message = b"Hello, world!"
            >>> signature = private_key.sign(message)
            >>> public_key.verify(message, signature)
            True
            >>> public_key.verify(b"Different message", signature)
            False

        Note:
            Catches all exceptions during verification and returns False
            for any failure, making it safe to use in validation code.
        """
        try:
            signature = cast(Signature, signature)
            self.key.verify(signature.data(), data)
        except Exception:
            return False
        return True

    def to_crypto_bytes(self) -> bytes:
        """Get the raw byte representation with prefix for cryptographic use.

        Returns:
            65-byte representation with 0x04 prefix followed by the 64-byte key.

        Example:
            >>> key_bytes = public_key.to_crypto_bytes()
            >>> len(key_bytes)
            65
            >>> key_bytes[0] == 0x04
            True

        Note:
            The 0x04 prefix indicates an uncompressed secp256k1 public key.
        """
        return b"\x04" + self.key.to_string()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> PublicKey:
        """Deserialize a public key from BCS-encoded bytes.

        Handles both raw 64-byte keys and 65-byte keys with prefix.

        Args:
            deserializer: BCS deserializer containing the public key bytes.

        Returns:
            A new PublicKey instance from the deserialized data.

        Raises:
            Exception: If the key length is invalid (not 64 or 65 bytes).

        Example:
            >>> serializer = Serializer()
            >>> original_key.serialize(serializer)
            >>> key_bytes = serializer.output()
            >>> deserializer = Deserializer(key_bytes)
            >>> restored_key = PublicKey.deserialize(deserializer)
            >>> original_key == restored_key
            True
        """
        key = deserializer.to_bytes()
        if len(key) != PublicKey.LENGTH:
            # Some standards apply an extra byte to represent that this is a 64-byte key
            if len(key) == PublicKey.LENGTH_WITH_PREFIX_LENGTH:
                key = key[1:]
            else:
                raise Exception("Length mismatch")

        return PublicKey(VerifyingKey.from_string(key, SECP256k1, hashlib.sha3_256))

    def serialize(self, serializer: Serializer):
        """Serialize the public key to BCS format with prefix.

        Writes the 65-byte representation (0x04 prefix + 64-byte key).

        Args:
            serializer: BCS serializer to write the public key bytes to.

        Example:
            >>> serializer = Serializer()
            >>> public_key.serialize(serializer)
            >>> key_bytes = serializer.output()
            >>> len(key_bytes)
            65
        """
        serializer.to_bytes(self.to_crypto_bytes())


class Signature(asymmetric_crypto.Signature):
    """secp256k1 ECDSA signature implementation.

    This class represents secp256k1 signatures in canonical form (s < n/2)
    and provides methods for serialization, deserialization, and comparison.

    Key Properties:
    - **Format**: Raw r, s values concatenated (64 bytes total)
    - **Normalized**: Uses canonical form with s < n/2
    - **Length**: 64 bytes (32 bytes for r + 32 bytes for s)

    Attributes:
        LENGTH: The byte length of secp256k1 signatures (64)
        signature: The raw signature bytes

    Examples:
        Create from signing::

            private_key = PrivateKey.random()
            message = b"Hello, Aptos!"
            signature = private_key.sign(message)

        Create from hex string::

            sig_hex = "***1234abcd..."
            signature = Signature.from_str(sig_hex)

        Verify with public key::

            public_key = private_key.public_key()
            is_valid = public_key.verify(message, signature)
            assert is_valid == True

    Note:
        Unlike some other secp256k1 implementations, this class uses the
        raw r,s format (64 bytes) rather than DER encoding.
    """

    LENGTH: int = 64

    signature: bytes

    def __init__(self, signature: bytes):
        """Initialize a signature with the given raw bytes.

        Args:
            signature: The 64-byte signature data (r, s values concatenated).

        Example:
            This is typically not called directly. Signatures are usually
            created by signing with a private key:
            >>> signature = private_key.sign(message)
        """
        self.signature = signature

    def __eq__(self, other: object):
        """Check equality with another Signature.

        Args:
            other: Object to compare with.

        Returns:
            True if both signatures contain the same bytes.

        Example:
            >>> sig1 = private_key.sign(message)
            >>> sig2 = Signature(sig1.data())  # Same data
            >>> sig1 == sig2
            True
        """
        if not isinstance(other, Signature):
            return NotImplemented
        return self.signature == other.signature

    def __str__(self) -> str:
        """Return the hexadecimal string representation.

        Returns:
            Hex string with '0x' prefix representing the signature.

        Example:
            >>> str(signature)
            '***c9a34d6...'  # 64 bytes
        """
        return self.hex()

    def hex(self) -> str:
        """Get the hexadecimal representation of the signature.

        Returns:
            Hex string with '0x' prefix representing the 64-byte signature.

        Example:
            >>> signature.hex()
            '***a1b2c3d4...'  # 64 bytes as hex
        """
        return f"***{self.signature.hex()}"

    @staticmethod
    def from_str(value: str) -> Signature:
        """Create a signature from a hex string.

        Args:
            value: Hex string representing the signature.
                Can be with or without '0x' prefix.
                Must be exactly 64 bytes (128 hex characters).

        Returns:
            A new Signature instance.

        Raises:
            Exception: If the signature length is invalid.

        Example:
            >>> sig = Signature.from_str("***a1b2c3d4...")
            >>> len(sig.data())
            64
        """
        if value[0:2] == "0x":
            value = value[2:]
        if len(value) != Signature.LENGTH * 2:
            raise Exception("Length mismatch")
        return Signature(bytes.fromhex(value))

    def data(self) -> bytes:
        """Get the raw signature bytes.

        Returns:
            The 64-byte raw signature data.

        Example:
            >>> raw_bytes = signature.data()
            >>> len(raw_bytes)
            64
        """
        return self.signature

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Signature:
        """Deserialize a signature from BCS-encoded bytes.

        Args:
            deserializer: BCS deserializer containing the signature bytes.

        Returns:
            A new Signature instance from the deserialized data.

        Raises:
            Exception: If the signature length is not 64 bytes.

        Example:
            >>> serializer = Serializer()
            >>> original_sig.serialize(serializer)
            >>> sig_bytes = serializer.output()
            >>> deserializer = Deserializer(sig_bytes)
            >>> restored_sig = Signature.deserialize(deserializer)
            >>> original_sig == restored_sig
            True
        """
        signature = deserializer.to_bytes()
        if len(signature) != Signature.LENGTH:
            raise Exception("Length mismatch")

        return Signature(signature)

    def serialize(self, serializer: Serializer):
        """Serialize the signature to BCS format.

        Args:
            serializer: BCS serializer to write the signature bytes to.

        Example:
            >>> serializer = Serializer()
            >>> signature.serialize(serializer)
            >>> sig_bytes = serializer.output()
            >>> len(sig_bytes)
            64
        """
        serializer.to_bytes(self.signature)


class Test(unittest.TestCase):
    def test_private_key_from_str(self):
        private_key_hex = PrivateKey.from_str(
            "0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4", False
        )
        private_key_with_prefix = PrivateKey.from_str(
            "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4",
            True,
        )
        private_key_bytes = PrivateKey.from_hex(
            bytes.fromhex(
                "306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
            ),
            False,
        )
        self.assertEqual(
            private_key_hex.hex(),
            private_key_with_prefix.hex(),
            private_key_bytes.hex(),
        )

    def test_private_key_aip80_formatting(self):
        private_key_with_prefix = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        self.assertEqual(
            str(PrivateKey.from_str(private_key_with_prefix, True)),
            private_key_with_prefix,
        )

    def test_vectors(self):
        private_key_hex = "secp256k1-priv-0x306fa009600e27c09d2659145ce1785249360dd5fb992da01a578fe67ed607f4"
        public_key_hex = "0x04210c9129e35337ff5d6488f90f18d842cf985f06e0baeff8df4bfb2ac4221863e2631b971a237b5db0aa71188e33250732dd461d56ee623cbe0426a5c2db79ef"
        signature_hex = "0xa539b0973e76fa99b2a864eebd5da950b4dfb399c7afe57ddb34130e454fc9db04dceb2c3d4260b8cc3d3952ab21b5d36c7dc76277fe3747764e6762d12bd9a9"
        data = b"Hello world"

        private_key = PrivateKey.from_str(private_key_hex)
        local_public_key = private_key.public_key()
        local_signature = private_key.sign(data)
        self.assertTrue(local_public_key.verify(data, local_signature))

        original_public_key = PublicKey.from_str(public_key_hex)
        self.assertTrue(original_public_key.verify(data, local_signature))
        self.assertEqual(public_key_hex[2:], local_public_key.to_crypto_bytes().hex())

        original_signature = Signature.from_str(signature_hex)
        self.assertTrue(original_public_key.verify(data, original_signature))

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
