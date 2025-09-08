# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Asymmetric cryptographic interfaces and protocols for the Aptos Python SDK.

This module defines the foundational cryptographic interfaces used throughout
the Aptos ecosystem, including protocols for private keys, public keys, and
signatures. It provides standardized interfaces that concrete implementations
must follow, ensuring consistency across different cryptographic schemes.

Key Components:
- **Protocol Definitions**: Abstract interfaces for cryptographic primitives
- **AIP-80 Compliance**: Standard formatting for private key serialization
- **Multi-Algorithm Support**: Extensible framework for Ed25519, secp256k1, etc.
- **BCS Integration**: Seamless serialization/deserialization support

Supported Key Types:
- Ed25519: Primary signature scheme used by Aptos
- secp256k1: ECDSA signature scheme for Ethereum compatibility

AIP-80 Standard:
The Aptos Improvement Proposal 80 (AIP-80) defines standard string formats
for private keys to improve interoperability and user experience. This module
provides utilities for parsing and formatting keys according to this standard.

Examples:
    Working with private key formatting::

        from aptos_sdk.asymmetric_crypto import PrivateKey, PrivateKeyVariant

        # Format a raw hex key as AIP-80 compliant
        raw_key = "0x1234abcd..."
        formatted = PrivateKey.format_private_key(raw_key, PrivateKeyVariant.Ed25519)
        # Returns: "ed25519-priv-0x1234abcd..."

        # Parse various formats to bytes
        key_bytes = PrivateKey.parse_hex_input(
            "ed25519-priv-0x1234abcd...",
            PrivateKeyVariant.Ed25519
        )

    Using protocol interfaces::

        # All concrete key implementations follow these protocols
        def sign_data(private_key: PrivateKey, message: bytes) -> Signature:
            return private_key.sign(message)

        def verify_signature(public_key: PublicKey, message: bytes, sig: Signature) -> bool:
            return public_key.verify(message, sig)

Note:
    This module defines protocols and interfaces only. Concrete implementations
    are provided in separate modules (e.g., ed25519.py, secp256k1_ecdsa.py).
"""

from __future__ import annotations

from enum import Enum

from typing_extensions import Protocol

from .bcs import Deserializable, Serializable


class PrivateKeyVariant(Enum):
    """Enumeration of supported private key cryptographic algorithms.

    This enum defines the cryptographic signature schemes supported by the
    Aptos blockchain and their corresponding string identifiers used in
    AIP-80 compliant formatting.

    Attributes:
        Ed25519: The Ed25519 signature scheme (primary for Aptos).
        Secp256k1: The secp256k1 ECDSA signature scheme (Ethereum compatibility).

    Examples:
        Using the enum values::

            # Check key type
            if key_type == PrivateKeyVariant.Ed25519:
                print("Using Ed25519 cryptography")

            # Get string representation
            scheme_name = PrivateKeyVariant.Secp256k1.value  # "secp256k1"

        Iterating over supported schemes::

            for scheme in PrivateKeyVariant:
                print(f"Supported: {scheme.value}")

    Note:
        These values are used internally for key type identification and
        correspond to the prefixes defined in the AIP-80 standard.
    """

    Ed25519 = "ed25519"
    Secp256k1 = "secp256k1"


class PrivateKey(Deserializable, Serializable, Protocol):
    """Protocol defining the interface for asymmetric cryptographic private keys.

    This protocol establishes the standard interface that all private key
    implementations must follow in the Aptos SDK. It combines cryptographic
    operations with serialization capabilities and AIP-80 compliance utilities.

    The protocol ensures that all private key types can:
    - Generate corresponding public keys
    - Sign arbitrary data
    - Serialize/deserialize for network transmission
    - Format according to AIP-80 standards

    Key Management Standards:
    - Implements AIP-80 compliant string formatting
    - Supports multiple input formats (hex, bytes, AIP-80 strings)
    - Provides type-safe parsing and validation
    - Maintains backward compatibility with legacy formats

    Methods:
        hex() -> str: Get hexadecimal representation of the private key
        public_key() -> PublicKey: Derive the corresponding public key
        sign(data: bytes) -> Signature: Sign data and return signature

    Static Methods:
        format_private_key(): Format keys as AIP-80 compliant strings
        parse_hex_input(): Parse various input formats to bytes

    Examples:
        Implementing a private key class::

            class MyPrivateKey(PrivateKey):
                def __init__(self, key_bytes: bytes):
                    self._key_bytes = key_bytes

                def hex(self) -> str:
                    return self._key_bytes.hex()

                def public_key(self) -> PublicKey:
                    # Derive public key from private key
                    return MyPublicKey.from_private(self)

                def sign(self, data: bytes) -> Signature:
                    # Implementation-specific signing
                    return MySignature(self._sign_bytes(data))

        Using the formatting utilities::

            # Format existing key
            formatted = PrivateKey.format_private_key(
                "0xabcd1234...",
                PrivateKeyVariant.Ed25519
            )

            # Parse different input formats
            key_bytes = PrivateKey.parse_hex_input(
                "ed25519-priv-0xabcd1234...",
                PrivateKeyVariant.Ed25519
            )

    Note:
        This is a Protocol (structural typing), not a base class. Concrete
        implementations don't need to explicitly inherit from this protocol,
        they just need to implement the required methods.
    """

    def hex(self) -> str:
        """Return the hexadecimal string representation of the private key.

        Returns:
            Hexadecimal string of the private key bytes, typically prefixed with '0x'.

        Example:
            >>> private_key.hex()
            '0x1234abcd...'
        """
        ...

    def public_key(self) -> PublicKey:
        """Derive the corresponding public key from this private key.

        Returns:
            The public key derived from this private key using the appropriate
            cryptographic algorithm.

        Example:
            >>> pub_key = private_key.public_key()
            >>> isinstance(pub_key, PublicKey)
            True
        """
        ...

    def sign(self, data: bytes) -> Signature:
        """Sign the given data using this private key.

        Args:
            data: The raw bytes to be signed.

        Returns:
            A signature object that can be used to verify the data was signed
            by the holder of this private key.

        Example:
            >>> message = b"Hello, Aptos!"
            >>> signature = private_key.sign(message)
            >>> public_key.verify(message, signature)
            True
        """
        ...

    """
    AIP-80 compliant prefixes for private key serialization.

    The Aptos Improvement Proposal 80 (AIP-80) defines standardized string
    formats for private keys to improve interoperability and user experience.
    Each supported cryptographic scheme has a unique prefix that identifies
    the key type.

    Format: "{algorithm}-priv-{hex_value}"

    Supported Prefixes:
        - "ed25519-priv-": For Ed25519 private keys
        - "secp256k1-priv-": For secp256k1 ECDSA private keys

    Examples:
        Ed25519 key: "ed25519-priv-0x1234abcd..."
        secp256k1 key: "secp256k1-priv-0xabcd1234..."

    References:
        [AIP-80 Specification](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md)
    """
    AIP80_PREFIXES: dict[PrivateKeyVariant, str] = {
        PrivateKeyVariant.Ed25519: "ed25519-priv-",
        PrivateKeyVariant.Secp256k1: "secp256k1-priv-",
    }

    @staticmethod
    def format_private_key(
        private_key: bytes | str, key_type: PrivateKeyVariant
    ) -> str:
        """Format a private key as an AIP-80 compliant string.

        This method converts various private key input formats into the standardized
        AIP-80 string format, which includes the algorithm prefix and ensures
        consistent representation across the Aptos ecosystem.

        Args:
            private_key: The private key in hex string or bytes format.
                Can be a raw hex string (with or without '0x' prefix),
                bytes object, or already AIP-80 formatted string.
            key_type: The cryptographic algorithm type for this key.

        Returns:
            AIP-80 compliant string in the format:
            "{algorithm}-priv-{hex_value}"

        Raises:
            ValueError: If the key_type is not supported.
            TypeError: If the private_key is not string or bytes.

        Examples:
            Format a raw hex string::

                key = "0x1234abcd..."
                formatted = PrivateKey.format_private_key(
                    key, PrivateKeyVariant.Ed25519
                )
                # Returns: "ed25519-priv-0x1234abcd..."

            Format bytes::

                key_bytes = bytes.fromhex("1234abcd")
                formatted = PrivateKey.format_private_key(
                    key_bytes, PrivateKeyVariant.Secp256k1
                )
                # Returns: "secp256k1-priv-0x1234abcd"

            Handle already formatted keys::

                formatted_key = "ed25519-priv-0x1234abcd..."
                result = PrivateKey.format_private_key(
                    formatted_key, PrivateKeyVariant.Ed25519
                )
                # Returns: "ed25519-priv-0x1234abcd..." (unchanged)

        Note:
            If the input is already AIP-80 compliant for the specified key type,
            the method will extract and reformat the hex portion to ensure
            consistency.
        """
        if key_type not in PrivateKey.AIP80_PREFIXES:
            raise ValueError(f"Unknown private key type: {key_type}")
        aip80_prefix = PrivateKey.AIP80_PREFIXES[key_type]

        key_value: str | None = None
        if isinstance(private_key, str):
            if private_key.startswith(aip80_prefix):
                key_value = private_key.split("-")[2]
            else:
                key_value = private_key
        elif isinstance(private_key, bytes):
            key_value = f"0x{private_key.hex()}"
        else:
            raise TypeError("Input value must be a string or bytes.")

        return f"{aip80_prefix}{key_value}"

    @staticmethod
    def parse_hex_input(
        value: str | bytes, key_type: PrivateKeyVariant, strict: bool | None = None
    ) -> bytes:
        """Parse various private key input formats to standardized bytes.

        This method handles multiple input formats for private keys and converts
        them to a consistent bytes representation. It supports legacy hex strings,
        AIP-80 compliant strings, and raw bytes.

        Args:
            value: The private key in various formats:
                - Raw hex string ("1234abcd" or "0x1234abcd")
                - AIP-80 compliant string ("ed25519-priv-0x1234abcd")
                - Raw bytes object
            key_type: The expected cryptographic algorithm type.
            strict: AIP-80 compliance mode:
                - True: Only accept AIP-80 compliant strings
                - False: Accept legacy hex formats without warning
                - None (default): Accept legacy formats with deprecation warning

        Returns:
            The private key as a bytes object, ready for cryptographic operations.

        Raises:
            ValueError: If key_type is unsupported, or if strict=True and input
                is not AIP-80 compliant, or if input format is invalid.
            TypeError: If value is not string or bytes.

        Examples:
            Parse AIP-80 compliant string::

                key_bytes = PrivateKey.parse_hex_input(
                    "ed25519-priv-0x1234abcd...",
                    PrivateKeyVariant.Ed25519
                )

            Parse legacy hex string::

                key_bytes = PrivateKey.parse_hex_input(
                    "0x1234abcd...",
                    PrivateKeyVariant.Ed25519,
                    strict=False  # Suppress warning
                )

            Parse raw bytes::

                key_bytes = PrivateKey.parse_hex_input(
                    bytes.fromhex("1234abcd"),
                    PrivateKeyVariant.Ed25519
                )

            Strict mode (AIP-80 only)::

                try:
                    key_bytes = PrivateKey.parse_hex_input(
                        "0x1234abcd...",  # Legacy format
                        PrivateKeyVariant.Ed25519,
                        strict=True
                    )
                except ValueError:
                    print("Must use AIP-80 format in strict mode")

        Note:
            When strict=None (default), legacy hex formats trigger a deprecation
            warning encouraging migration to AIP-80 compliant formats.
        """
        if key_type not in PrivateKey.AIP80_PREFIXES:
            raise ValueError(f"Unknown private key type: {key_type}")
        aip80_prefix = PrivateKey.AIP80_PREFIXES[key_type]

        if isinstance(value, str):
            if not strict and not value.startswith(aip80_prefix):
                # Non-AIP-80 compliant hex string
                if strict is None:
                    print(
                        "It is recommended that private keys are AIP-80 compliant (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-80.md)."
                    )
                if value[0:2] == "0x":
                    value = value[2:]
                return bytes.fromhex(value)
            elif value.startswith(aip80_prefix):
                # AIP-80 compliant string
                value = value.split("-")[2]
                if value[0:2] == "0x":
                    value = value[2:]
                return bytes.fromhex(value)
            else:
                if strict:
                    raise ValueError(
                        "Invalid HexString input. Must be AIP-80 compliant string."
                    )
                raise ValueError("Invalid HexString input.")
        elif isinstance(value, bytes):
            return value
        else:
            raise TypeError("Input value must be a string or bytes.")


class PublicKey(Deserializable, Serializable, Protocol):
    """Protocol defining the interface for asymmetric cryptographic public keys.

    This protocol establishes the standard interface that all public key
    implementations must follow in the Aptos SDK. Public keys are used for
    signature verification and address derivation in the Aptos blockchain.

    The protocol ensures that all public key types can:
    - Verify signatures created by corresponding private keys
    - Serialize for network transmission and storage
    - Generate specialized byte representations for different contexts

    Key Features:
    - **Signature Verification**: Cryptographic validation of signed data
    - **Flexible Encoding**: Support for both BCS and specialized encodings
    - **Multi-Algorithm Support**: Compatible with Ed25519, secp256k1, etc.
    - **Address Derivation**: Foundation for generating blockchain addresses

    Methods:
        to_crypto_bytes() -> bytes: Get specialized cryptographic byte encoding
        verify(data: bytes, signature: Signature) -> bool: Verify a signature

    Examples:
        Implementing a public key class::

            class MyPublicKey(PublicKey):
                def __init__(self, key_bytes: bytes):
                    self._key_bytes = key_bytes

                def to_crypto_bytes(self) -> bytes:
                    # Return algorithm-specific encoding
                    return self._key_bytes

                def verify(self, data: bytes, signature: Signature) -> bool:
                    # Implementation-specific verification
                    return self._verify_signature(data, signature)

                def serialize(self, serializer) -> None:
                    # BCS serialization
                    serializer.bytes(self._key_bytes)

        Using public key verification::

            message = b"Hello, Aptos!"
            signature = private_key.sign(message)

            # Verify the signature
            if public_key.verify(message, signature):
                print("Signature is valid!")
            else:
                print("Invalid signature!")

    Note:
        The to_crypto_bytes() method exists for historical reasons where
        some key types (like MultiEd25519) require special encoding beyond
        standard BCS serialization.
    """

    def to_crypto_bytes(self) -> bytes:
        """Get the specialized cryptographic byte representation.

        This method provides an algorithm-specific byte encoding that may
        differ from the standard BCS serialization. It exists primarily
        for compatibility with legacy systems and specialized key types
        like MultiEd25519.

        Returns:
            The public key in its specialized cryptographic byte format.

        Note:
            For most single-signature schemes, this typically returns the
            same bytes as BCS serialization. Multi-signature schemes may
            use different encodings.

        Example:
            >>> crypto_bytes = public_key.to_crypto_bytes()
            >>> len(crypto_bytes)  # Length depends on algorithm
            32  # Ed25519 public keys are 32 bytes

        A long time ago, someone decided that we should have both bcs and a special representation
        for MultiEd25519, so we use this to let keys self-define a special encoding.
        """
        ...

    def verify(self, data: bytes, signature: Signature) -> bool:
        """Verify that a signature was created by the corresponding private key.

        This method performs cryptographic verification to ensure that the
        given signature was created by signing the provided data with the
        private key corresponding to this public key.

        Args:
            data: The original data that was signed.
            signature: The signature to verify.

        Returns:
            True if the signature is valid for the given data and this public key,
            False otherwise.

        Example:
            >>> message = b"transaction data"
            >>> signature = private_key.sign(message)
            >>> public_key.verify(message, signature)
            True
            >>> public_key.verify(b"different data", signature)
            False

        Note:
            This method should be constant-time to prevent timing attacks
            in security-critical applications.
        """
        ...


class Signature(Deserializable, Serializable, Protocol):
    """Protocol defining the interface for cryptographic signatures.

    This protocol establishes the standard interface that all signature
    implementations must follow in the Aptos SDK. Signatures are the
    cryptographic proofs that verify the authenticity and integrity of
    signed data.

    The protocol ensures that all signature types can:
    - Serialize for network transmission and storage
    - Deserialize from various input formats
    - Integrate seamlessly with the BCS serialization system

    Key Properties:
    - **Immutable**: Signatures should be treated as immutable once created
    - **Verifiable**: Can be verified using corresponding public keys
    - **Serializable**: Compatible with Aptos network protocols
    - **Type-Safe**: Maintains algorithm-specific signature formats

    Examples:
        Implementing a signature class::

            class MySignature(Signature):
                def __init__(self, signature_bytes: bytes):
                    self._signature_bytes = signature_bytes

                def serialize(self, serializer) -> None:
                    # BCS serialization
                    serializer.bytes(self._signature_bytes)

                @classmethod
                def deserialize(cls, deserializer) -> 'MySignature':
                    # BCS deserialization
                    signature_bytes = deserializer.bytes()
                    return cls(signature_bytes)

        Using signatures in verification::

            # Create signature
            message = b"Hello, Aptos!"
            signature = private_key.sign(message)

            # Verify signature
            is_valid = public_key.verify(message, signature)

            # Serialize for transmission
            serializer = Serializer()
            signature.serialize(serializer)
            signature_bytes = serializer.output()

    Note:
        This is a Protocol (structural typing), not a base class. Concrete
        signature implementations don't need to explicitly inherit from this
        protocol, they just need to implement the required serialization methods.
    """

    ...
