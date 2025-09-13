# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Account address management for the Aptos blockchain.

This module provides comprehensive support for managing account addresses on the Aptos
blockchain, including address parsing, validation, derivation, and formatting according
to the AIP-40 address standard.

Key features:
- AIP-40 compliant address parsing and formatting
- Address derivation from public keys and seeds
- Support for special address formats
- Resource account and named object address generation
- Strict and relaxed parsing modes

The module implements the Aptos address standard defined in AIP-40, which specifies
that addresses should be represented in either LONG form (64 hex characters) or
SHORT form for special addresses (addresses 0x0 through 0xf).

Examples:
    Basic address operations::

        # Parse from string (strict)
        addr = AccountAddress.from_str("0x1")

        # Parse from string (relaxed)
        addr = AccountAddress.from_str_relaxed("1")

        # Derive from public key
        addr = AccountAddress.from_key(public_key)

    Special address handling::

        # Special addresses use SHORT form
        special_addr = AccountAddress.from_str("0xa")
        print(special_addr)  # "0xa"

        # Non-special addresses use LONG form
        regular_addr = AccountAddress.from_str(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )

    Resource and object addresses::

        # Create resource account address
        resource_addr = AccountAddress.for_resource_account(
            creator_address, b"seed"
        )

        # Create named object address
        object_addr = AccountAddress.for_named_object(
            creator_address, b"object_name"
        )

        # Create token collection address
        collection_addr = AccountAddress.for_named_collection(
            creator_address, "My Collection"
        )
"""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import dataclass

from . import asymmetric_crypto, asymmetric_crypto_wrapper, ed25519
from .bcs import Deserializer, Serializer


class AuthKeyScheme:
    """Authentication key schemes for address derivation.

    This class defines the byte constants used as suffixes when deriving addresses
    from various sources. Each scheme represents a different method of address
    derivation and ensures that addresses derived through different methods
    cannot collide.

    Attributes:
        Ed25519: Single Ed25519 key authentication (0x00)
        MultiEd25519: Multi-signature Ed25519 authentication (0x01)
        SingleKey: Single key authentication wrapper (0x02)
        MultiKey: Multi-key authentication with threshold (0x03)
        DeriveObjectAddressFromGuid: Object address from GUID (0xFD)
        DeriveObjectAddressFromSeed: Object address from seed (0xFE)
        DeriveResourceAccountAddress: Resource account address (0xFF)
    """

    Ed25519: bytes = b"\x00"
    MultiEd25519: bytes = b"\x01"
    SingleKey: bytes = b"\x02"
    MultiKey: bytes = b"\x03"
    DeriveObjectAddressFromGuid: bytes = b"\xFD"
    DeriveObjectAddressFromSeed: bytes = b"\xFE"
    DeriveResourceAccountAddress: bytes = b"\xFF"


class ParseAddressError(Exception):
    """Exception raised when there's an error parsing an account address.

    This exception is raised when an address string or byte sequence cannot
    be parsed into a valid AccountAddress, typically due to invalid length,
    format, or content.

    Examples:
        Catching parse errors::

            try:
                addr = AccountAddress.from_str("invalid")
            except ParseAddressError as e:
                print(f"Failed to parse address: {e}")
    """


class AccountAddress:
    """Represents an account address on the Aptos blockchain.

    An AccountAddress is a 32-byte identifier for accounts, objects, and resources
    on the Aptos blockchain. It implements the AIP-40 address standard for parsing
    and formatting addresses in both strict and relaxed modes.

    The address system supports:
    - Special addresses (0x0 through 0xf) with SHORT representation
    - Regular addresses with LONG representation (64 hex characters)
    - Address derivation from public keys
    - Resource account and named object address generation

    Attributes:
        address: The raw 32-byte address data
        LENGTH: The required byte length of all addresses (32)

    Examples:
        Creating addresses::

            # From hex string (strict parsing)
            addr1 = AccountAddress.from_str("0x1")

            # From hex string (relaxed parsing)
            addr2 = AccountAddress.from_str_relaxed("abc123")

            # From public key
            addr3 = AccountAddress.from_key(public_key)

            # From raw bytes
            addr4 = AccountAddress(b"\x00" * 32)

        Address formatting::

            special_addr = AccountAddress.from_str("0xa")
            print(special_addr)  # "0xa" (SHORT form)

            regular_addr = AccountAddress.from_str(
                "0x" + "1" * 64
            )
            print(regular_addr)  # Long form with 0x prefix
    """

    address: bytes
    LENGTH: int = 32

    def __init__(self, address: bytes):
        """Initialize an AccountAddress with raw address bytes.

        Args:
            address: The 32-byte address data.

        Raises:
            ParseAddressError: If the address is not exactly 32 bytes.
        """
        self.address = address

        if len(address) != AccountAddress.LENGTH:
            raise ParseAddressError("Expected address of length 32")

    def __eq__(self, other: object) -> bool:
        """Check equality with another AccountAddress.

        Args:
            other: The object to compare with.

        Returns:
            True if both addresses have the same raw bytes.
        """
        if not isinstance(other, AccountAddress):
            return NotImplemented
        return self.address == other.address

    def __str__(self):
        """Get the AIP-40 compliant string representation of this address.

        Represents an account address according to the v1 address standard
        defined in AIP-40. Special addresses (0x0 through 0xf) are shown in
        SHORT form, while all other addresses are shown in LONG form.

        The formatting rules are:
        - Special addresses: "0x0" through "0xf" (SHORT form)
        - Regular addresses: "0x" + 64 hex characters (LONG form)

        Returns:
            AIP-40 compliant string representation with "0x" prefix.

        Examples:
            Special address formatting::

                addr = AccountAddress(b"\x00" * 32)
                str(addr)  # "0x0"

            Regular address formatting::

                addr = AccountAddress(b"\x10" + b"\x00" * 31)
                str(addr)  # "0x1000000000000000000000000000000000000000000000000000000000000000"

        See Also:
            AIP-40 standard: https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md
        """
        suffix = self.address.hex()
        if self.is_special():
            suffix = suffix.lstrip("0") or "0"
        return f"0x{suffix}"

    def __repr__(self):
        """Get the string representation for debugging.

        Returns:
            Same as __str__ for consistency.
        """
        return self.__str__()

    def is_special(self):
        """Check if this address qualifies as a "special" address.

        Special addresses are those in the range 0x0 to 0xf (inclusive) that
        can be represented in SHORT form according to AIP-40. An address is
        considered special if:
        - The first 31 bytes are all zero
        - The last byte is less than 16 (0x10)

        This corresponds to addresses that match the regex pattern:
        ^0{63}[0-9a-f]$ in hexadecimal representation.

        Returns:
            True if this is a special address that can use SHORT form.

        Examples:
            Special addresses::

                AccountAddress(b"\x00" * 32).is_special()  # True (0x0)
                AccountAddress(b"\x00" * 31 + b"\x0f").is_special()  # True (0xf)

            Non-special addresses::

                AccountAddress(b"\x00" * 31 + b"\x10").is_special()  # False (0x10)
                AccountAddress(b"\x01" + b"\x00" * 31).is_special()  # False

        See Also:
            AIP-40 standard: https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md
        """
        return all(b == 0 for b in self.address[:-1]) and self.address[-1] < 0b10000

    @staticmethod
    def from_str(address: str) -> AccountAddress:
        """Create an AccountAddress from a hex string with strict AIP-40 validation.

        This function enforces the strictest address format requirements defined
        by AIP-40. It only accepts properly formatted addresses with appropriate
        prefixes and length requirements.

        Accepted formats:
        - LONG form: "0x" + exactly 64 hex characters
        - SHORT form: "0x" + single hex character (0-f) for special addresses only

        Args:
            address: A hex string representing the account address.

        Returns:
            A new AccountAddress instance.

        Raises:
            RuntimeError: If the address format doesn't meet strict AIP-40 requirements:
                - Missing "0x" prefix
                - Wrong length for address type
                - Padding zeroes in special addresses
                - Short form used for non-special addresses

        Examples:
            Valid strict format usage::

                # Special addresses in SHORT form
                addr1 = AccountAddress.from_str("0x0")
                addr2 = AccountAddress.from_str("0xf")

                # Regular addresses in LONG form
                addr3 = AccountAddress.from_str(
                    "0x" + "1" * 64
                )

            Invalid formats (will raise RuntimeError)::

                # Missing 0x prefix
                AccountAddress.from_str("123abc...")

                # Padded special address
                AccountAddress.from_str("0x0f")

                # Short form for non-special address
                AccountAddress.from_str("0x10")

        See Also:
            - from_str_relaxed: For lenient parsing
            - AIP-40: https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md
        """
        # Assert the string starts with 0x.
        if not address.startswith("0x"):
            raise RuntimeError("Hex string must start with a leading 0x.")

        out = AccountAddress.from_str_relaxed(address)

        # Check if the address is in LONG form. If it is not, this is only allowed for
        # special addresses, in which case we check it is in proper SHORT form.
        if len(address) != AccountAddress.LENGTH * 2 + 2:
            if not out.is_special():
                raise RuntimeError(
                    "The given hex string is not a special address, it must be represented "
                    "as 0x + 64 chars."
                )
            else:
                # 0x + one hex char is the only valid SHORT form for special addresses.
                if len(address) != 3:
                    raise RuntimeError(
                        "The given hex string is a special address not in LONG form, "
                        "it must be 0x0 to 0xf without padding zeroes."
                    )

        # Assert that only special addresses can use short form.
        if len(address[2:]) != AccountAddress.LENGTH * 2 and not out.is_special():
            raise RuntimeError(
                "Padding zeroes are not allowed, the address must be represented as "
                "0x0 to 0xf for special addresses or 0x + 64 chars for all other addresses."
            )

        return out

    @staticmethod
    def from_str_relaxed(address: str) -> AccountAddress:
        """Create an AccountAddress from a hex string with relaxed validation.

        This function provides backward compatibility by accepting various address
        formats beyond the strict AIP-40 requirements. It's more permissive than
        from_str() and handles padding and missing prefixes automatically.

        Accepted formats:
        - LONG form: 64 hex characters (with or without "0x" prefix)
        - SHORT form: 1-63 hex characters (with or without "0x" prefix)
        - Padding zeroes are automatically added as needed

        Args:
            address: A hex string representing the account address.

        Returns:
            A new AccountAddress instance.

        Raises:
            RuntimeError: If the hex string is invalid:
                - Empty or too long (>64 characters after removing "0x")
                - Contains non-hexadecimal characters

        Examples:
            Flexible format handling::

                # With or without 0x prefix
                addr1 = AccountAddress.from_str_relaxed("0x1")
                addr2 = AccountAddress.from_str_relaxed("1")

                # Padding handled automatically
                addr3 = AccountAddress.from_str_relaxed("abc123")
                addr4 = AccountAddress.from_str_relaxed("0x00abc123")

                # Long addresses
                addr5 = AccountAddress.from_str_relaxed(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                )

        Note:
            Use from_str() instead when possible for strict AIP-40 compliance.
            This method is primarily for backward compatibility.

        See Also:
            - from_str: For strict AIP-40 compliant parsing
            - AIP-40: https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md
        """
        addr = address

        # Strip 0x prefix if present.
        if address[0:2] == "0x":
            addr = address[2:]

        # Assert the address is at least one hex char long.
        if len(addr) < 1:
            raise RuntimeError(
                "Hex string is too short, must be 1 to 64 chars long, excluding the "
                "leading 0x."
            )

        # Assert the address is at most 64 hex chars long.
        if len(addr) > 64:
            raise RuntimeError(
                "Hex string is too long, must be 1 to 64 chars long, excluding the "
                "leading 0x."
            )

        if len(addr) < AccountAddress.LENGTH * 2:
            pad = "0" * (AccountAddress.LENGTH * 2 - len(addr))
            addr = pad + addr

        return AccountAddress(bytes.fromhex(addr))

    @staticmethod
    def from_key(key: asymmetric_crypto.PublicKey) -> AccountAddress:
        """Derive an account address from a public key.

        Creates an account address by hashing the public key bytes along with
        the appropriate authentication scheme identifier. This ensures that
        different key types produce different addresses even with identical
        key material.

        The derivation process:
        1. Hash the public key's cryptographic bytes
        2. Append the appropriate AuthKeyScheme suffix
        3. Take the SHA3-256 hash to produce the 32-byte address

        Args:
            key: A public key implementing the asymmetric_crypto.PublicKey interface.
                Supported types:
                - ed25519.PublicKey (single Ed25519 key)
                - ed25519.MultiPublicKey (multi-signature Ed25519)
                - asymmetric_crypto_wrapper.PublicKey (single key wrapper)
                - asymmetric_crypto_wrapper.MultiPublicKey (multi-key wrapper)

        Returns:
            The derived AccountAddress for the given public key.

        Raises:
            Exception: If the key type is not supported.

        Examples:
            Deriving addresses from different key types::

                # From Ed25519 public key
                ed25519_key = ed25519.PrivateKey.random().public_key()
                addr1 = AccountAddress.from_key(ed25519_key)

                # From multi-signature key
                keys = [ed25519.PrivateKey.random().public_key() for _ in range(3)]
                multisig_key = ed25519.MultiPublicKey(keys, threshold=2)
                addr2 = AccountAddress.from_key(multisig_key)

        Note:
            The same public key will always produce the same address, but
            different key types (even with identical cryptographic material)
            will produce different addresses due to the scheme suffixes.
        """
        hasher = hashlib.sha3_256()
        hasher.update(key.to_crypto_bytes())

        if isinstance(key, ed25519.PublicKey):
            hasher.update(AuthKeyScheme.Ed25519)
        elif isinstance(key, ed25519.MultiPublicKey):
            hasher.update(AuthKeyScheme.MultiEd25519)
        elif isinstance(key, asymmetric_crypto_wrapper.PublicKey):
            hasher.update(AuthKeyScheme.SingleKey)
        elif isinstance(key, asymmetric_crypto_wrapper.MultiPublicKey):
            hasher.update(AuthKeyScheme.MultiKey)
        else:
            raise Exception("Unsupported asymmetric_crypto.PublicKey key type.")

        return AccountAddress(hasher.digest())

    @staticmethod
    def for_resource_account(creator: AccountAddress, seed: bytes) -> AccountAddress:
        """Generate a resource account address.

        Resource accounts are special accounts that don't have corresponding private
        keys and are used to hold resources on behalf of other accounts. They are
        created deterministically from a creator address and seed.

        Args:
            creator: The address of the account creating the resource account.
            seed: Arbitrary bytes used to ensure uniqueness.

        Returns:
            The deterministic address for the resource account.

        Examples:
            Creating resource account addresses::

                creator_addr = AccountAddress.from_str("0x1")

                # Different seeds produce different addresses
                resource1 = AccountAddress.for_resource_account(
                    creator_addr, b"my_resource_1"
                )
                resource2 = AccountAddress.for_resource_account(
                    creator_addr, b"my_resource_2"
                )

                # Same creator + seed = same address (deterministic)
                resource3 = AccountAddress.for_resource_account(
                    creator_addr, b"my_resource_1"
                )
                assert resource1 == resource3

        Note:
            Resource accounts are commonly used for storing program resources
            and don't have associated private keys, making them secure for
            holding assets controlled by smart contracts.
        """
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveResourceAccountAddress)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_guid_object(creator: AccountAddress, creation_num: int) -> AccountAddress:
        """Generate an object address from a GUID (Globally Unique Identifier).

        Creates a deterministic object address using the creator's address and
        a creation number. This is used for objects that are created sequentially
        and need unique addresses.

        Args:
            creator: The address of the account creating the object.
            creation_num: A sequential number used for uniqueness (typically
                incremented for each object created by this account).

        Returns:
            The deterministic address for the object.

        Examples:
            Creating sequential object addresses::

                creator = AccountAddress.from_str("0x123abc...")

                # Sequential object creation
                obj1 = AccountAddress.for_guid_object(creator, 0)
                obj2 = AccountAddress.for_guid_object(creator, 1)
                obj3 = AccountAddress.for_guid_object(creator, 2)

                # Same parameters = same address
                obj1_duplicate = AccountAddress.for_guid_object(creator, 0)
                assert obj1 == obj1_duplicate

        Note:
            The creation_num is typically managed by the blockchain to ensure
            uniqueness. Each creator maintains their own sequence counter.
        """
        hasher = hashlib.sha3_256()
        serializer = Serializer()
        serializer.u64(creation_num)
        hasher.update(serializer.output())
        hasher.update(creator.address)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromGuid)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_object(creator: AccountAddress, seed: bytes) -> AccountAddress:
        """Generate a named object address from a seed.

        Creates a deterministic object address using the creator's address and
        an arbitrary seed. This allows for creating objects with predictable
        addresses based on meaningful names or identifiers.

        Args:
            creator: The address of the account creating the object.
            seed: Arbitrary bytes that uniquely identify this object.
                Often derived from human-readable names.

        Returns:
            The deterministic address for the named object.

        Examples:
            Creating named object addresses::

                creator = AccountAddress.from_str("0x123abc...")

                # Objects named with meaningful identifiers
                config_obj = AccountAddress.for_named_object(
                    creator, b"global_config"
                )

                metadata_obj = AccountAddress.for_named_object(
                    creator, b"metadata_store"
                )

                # Same name = same address (deterministic)
                config_duplicate = AccountAddress.for_named_object(
                    creator, b"global_config"
                )
                assert config_obj == config_duplicate

        Note:
            This is commonly used for singleton objects or well-known resources
            that need predictable addresses for easy reference.
        """
        hasher = hashlib.sha3_256()
        hasher.update(creator.address)
        hasher.update(seed)
        hasher.update(AuthKeyScheme.DeriveObjectAddressFromSeed)
        return AccountAddress(hasher.digest())

    @staticmethod
    def for_named_token(
        creator: AccountAddress, collection_name: str, token_name: str
    ) -> AccountAddress:
        """Generate a token address from collection and token names.

        Creates a deterministic address for a specific token within a collection.
        The address is derived from the creator address and a combination of
        the collection name and token name.

        Args:
            creator: The address of the account that created the collection.
            collection_name: The name of the token collection.
            token_name: The name of the specific token within the collection.

        Returns:
            The deterministic address for the named token.

        Examples:
            Creating token addresses::

                creator = AccountAddress.from_str("0x123abc...")

                # Tokens in different collections
                token1 = AccountAddress.for_named_token(
                    creator, "My NFT Collection", "Token #1"
                )

                token2 = AccountAddress.for_named_token(
                    creator, "My NFT Collection", "Token #2"
                )

                # Same collection + token name = same address
                token1_duplicate = AccountAddress.for_named_token(
                    creator, "My NFT Collection", "Token #1"
                )
                assert token1 == token1_duplicate

        Note:
            The seed format is: collection_name + "::" + token_name
            This ensures tokens in different collections have different addresses
            even if they share the same token name.
        """
        collection_bytes = collection_name.encode()
        token_bytes = token_name.encode()
        return AccountAddress.for_named_object(
            creator, collection_bytes + b"::" + token_bytes
        )

    @staticmethod
    def for_named_collection(
        creator: AccountAddress, collection_name: str
    ) -> AccountAddress:
        """Generate a collection address from a collection name.

        Creates a deterministic address for a token collection based on the
        creator address and collection name.

        Args:
            creator: The address of the account creating the collection.
            collection_name: The human-readable name of the collection.

        Returns:
            The deterministic address for the named collection.

        Examples:
            Creating collection addresses::

                creator = AccountAddress.from_str("0x123abc...")

                # Collections with different names
                collection1 = AccountAddress.for_named_collection(
                    creator, "My First Collection"
                )

                collection2 = AccountAddress.for_named_collection(
                    creator, "My Second Collection"
                )

                # Same name = same address (deterministic)
                collection1_duplicate = AccountAddress.for_named_collection(
                    creator, "My First Collection"
                )
                assert collection1 == collection1_duplicate

        Note:
            This is commonly used for NFT collections and other grouped assets
            where a predictable address is needed for the collection metadata.
        """
        return AccountAddress.for_named_object(creator, collection_name.encode())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAddress:
        """Deserialize an AccountAddress from a BCS byte stream.

        Args:
            deserializer: The BCS deserializer to read from.

        Returns:
            The deserialized AccountAddress instance.

        Raises:
            Exception: If there are insufficient bytes in the stream.
        """
        return AccountAddress(deserializer.fixed_bytes(AccountAddress.LENGTH))

    def serialize(self, serializer: Serializer):
        """Serialize this AccountAddress to a BCS byte stream.

        Args:
            serializer: The BCS serializer to write to.
        """
        serializer.fixed_bytes(self.address)


"""
Tests
"""


@dataclass(init=True, frozen=True)
class TestAddresses:
    shortWith0x: str
    shortWithout0x: str
    longWith0x: str
    longWithout0x: str
    bytes: bytes


ADDRESS_ZERO = TestAddresses(
    shortWith0x="0x0",
    shortWithout0x="0",
    longWith0x="0x0000000000000000000000000000000000000000000000000000000000000000",
    longWithout0x="0000000000000000000000000000000000000000000000000000000000000000",
    bytes=bytes([0] * 32),
)

ADDRESS_F = TestAddresses(
    shortWith0x="0xf",
    shortWithout0x="f",
    longWith0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    longWithout0x="000000000000000000000000000000000000000000000000000000000000000f",
    bytes=bytes([0] * 31 + [15]),
)

ADDRESS_F_PADDED_SHORT_FORM = TestAddresses(
    shortWith0x="0x0f",
    shortWithout0x="0f",
    # The rest of these below are the same as for ADDRESS_F.
    longWith0x="0x000000000000000000000000000000000000000000000000000000000000000f",
    longWithout0x="000000000000000000000000000000000000000000000000000000000000000f",
    bytes=bytes([0] * 31 + [15]),
)

ADDRESS_TEN = TestAddresses(
    shortWith0x="0x10",
    shortWithout0x="10",
    longWith0x="0x0000000000000000000000000000000000000000000000000000000000000010",
    longWithout0x="0000000000000000000000000000000000000000000000000000000000000010",
    bytes=bytes([0] * 31 + [16]),
)

ADDRESS_OTHER = TestAddresses(
    shortWith0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    shortWithout0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    longWith0x="0xca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    longWithout0x="ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0",
    bytes=bytes(
        [
            202,
            132,
            50,
            121,
            227,
            66,
            113,
            68,
            206,
            173,
            94,
            77,
            89,
            153,
            163,
            208,
            202,
            132,
            50,
            121,
            227,
            66,
            113,
            68,
            206,
            173,
            94,
            77,
            89,
            153,
            163,
            208,
        ]
    ),
)


class Test(unittest.TestCase):
    """Comprehensive test suite for AccountAddress functionality.

    Tests all aspects of address handling including:
    - Address derivation from various sources
    - String parsing in strict and relaxed modes
    - AIP-40 compliance validation
    - Special address handling
    - Resource and object address generation
    """

    def test_multi_ed25519(self):
        private_key_1 = ed25519.PrivateKey.from_str(
            "4e5e3be60f4bbd5e98d086d932f3ce779ff4b58da99bf9e5241ae1212a29e5fe"
        )
        private_key_2 = ed25519.PrivateKey.from_str(
            "1e70e49b78f976644e2c51754a2f049d3ff041869c669523ba95b172c7329901"
        )
        multisig_public_key = ed25519.MultiPublicKey(
            [private_key_1.public_key(), private_key_2.public_key()], 1
        )

        expected = AccountAddress.from_str_relaxed(
            "835bb8c5ee481062946b18bbb3b42a40b998d6bf5316ca63834c959dc739acf0"
        )
        actual = AccountAddress.from_key(multisig_public_key)
        self.assertEqual(actual, expected)

    def test_resource_account(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "ee89f8c763c27f9d942d496c1a0dcf32d5eacfe78416f9486b8db66155b163b0"
        )
        actual = AccountAddress.for_resource_account(base_address, b"\x0b\x00\x0b")
        self.assertEqual(actual, expected)

    def test_named_object(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_object(base_address, b"bob's collection")
        self.assertEqual(actual, expected)

    def test_collection(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "f417184602a828a3819edf5e36285ebef5e4db1ba36270be580d6fd2d7bcc321"
        )
        actual = AccountAddress.for_named_collection(base_address, "bob's collection")
        self.assertEqual(actual, expected)

    def test_token(self):
        base_address = AccountAddress.from_str_relaxed("b0b")
        expected = AccountAddress.from_str_relaxed(
            "e20d1f22a5400ba7be0f515b7cbd00edc42dbcc31acc01e31128b2b5ddb3c56e"
        )
        actual = AccountAddress.for_named_token(
            base_address, "bob's collection", "bob's token"
        )
        self.assertEqual(actual, expected)

    def test_to_standard_string(self):
        # Test special address: 0x0
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                )
            ),
            "0x0",
        )

        # Test special address: 0x1
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000001"
                )
            ),
            "0x1",
        )

        # Test special address: 0x4
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x0000000000000000000000000000000000000000000000000000000000000004"
                )
            ),
            "0x4",
        )

        # Test special address: 0xf
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    "0x000000000000000000000000000000000000000000000000000000000000000f"
                )
            ),
            "0xf",
        )

        # Test special address from short no 0x: d
        self.assertEqual(
            str(AccountAddress.from_str_relaxed("d")),
            "0xd",
        )

        # Test non-special address from long:
        # 0x0000000000000000000000000000000000000000000000000000000000000010
        value = "0x0000000000000000000000000000000000000000000000000000000000000010"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long:
        # 0x000000000000000000000000000000000000000000000000000000000000001f
        value = "0x000000000000000000000000000000000000000000000000000000000000001f"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long:
        # 0x00000000000000000000000000000000000000000000000000000000000000a0
        value = "0x00000000000000000000000000000000000000000000000000000000000000a0"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            value,
        )

        # Test non-special address from long no 0x:
        # ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0
        value = "ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

        # Test non-special address from long no 0x:
        # 1000000000000000000000000000000000000000000000000000000000000000
        value = "1000000000000000000000000000000000000000000000000000000000000000"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

        # Demonstrate that neither leading nor trailing zeroes get trimmed for
        # non-special addresses:
        # 0f00000000000000000000000000000000000000000000000000000000000000
        value = "0f00000000000000000000000000000000000000000000000000000000000000"
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(value)),
            f"0x{value}",
        )

    def test_from_str_relaxed(self):
        # Demonstrate that all formats are accepted for 0x0.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.longWith0x)),
            ADDRESS_ZERO.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.longWithout0x)),
            ADDRESS_ZERO.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.shortWith0x)),
            ADDRESS_ZERO.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_ZERO.shortWithout0x)),
            ADDRESS_ZERO.shortWith0x,
        )

        # Demonstrate that all formats are accepted for 0xf.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.longWith0x)),
            ADDRESS_F.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.longWithout0x)),
            ADDRESS_F.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.shortWith0x)),
            ADDRESS_F.shortWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_F.shortWithout0x)),
            ADDRESS_F.shortWith0x,
        )

        # Demonstrate that padding zeroes are allowed for 0x0f.
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(ADDRESS_F_PADDED_SHORT_FORM.shortWith0x)
            ),
            ADDRESS_F.shortWith0x,
        )
        self.assertEqual(
            str(
                AccountAddress.from_str_relaxed(
                    ADDRESS_F_PADDED_SHORT_FORM.shortWithout0x
                )
            ),
            ADDRESS_F.shortWith0x,
        )

        # Demonstrate that all formats are accepted for 0x10.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.longWith0x)),
            ADDRESS_TEN.longWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.longWithout0x)),
            ADDRESS_TEN.longWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.shortWith0x)),
            ADDRESS_TEN.longWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_TEN.shortWithout0x)),
            ADDRESS_TEN.longWith0x,
        )

        # Demonstrate that all formats are accepted for other addresses.
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_OTHER.longWith0x)),
            ADDRESS_OTHER.longWith0x,
        )
        self.assertEqual(
            str(AccountAddress.from_str_relaxed(ADDRESS_OTHER.longWithout0x)),
            ADDRESS_OTHER.longWith0x,
        )

    def test_from_str(self):
        # Demonstrate that only LONG and SHORT are accepted for 0x0.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_ZERO.longWith0x)),
            ADDRESS_ZERO.shortWith0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_ZERO.longWithout0x
        )
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_ZERO.shortWith0x)),
            ADDRESS_ZERO.shortWith0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_ZERO.shortWithout0x
        )

        # Demonstrate that only LONG and SHORT are accepted for 0xf.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_F.longWith0x)), ADDRESS_F.shortWith0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_F.longWithout0x
        )
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_F.shortWith0x)), ADDRESS_F.shortWith0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_F.shortWithout0x
        )

        # Demonstrate that padding zeroes are not allowed for 0x0f.
        self.assertRaises(
            RuntimeError,
            AccountAddress.from_str,
            ADDRESS_F_PADDED_SHORT_FORM.shortWith0x,
        )
        self.assertRaises(
            RuntimeError,
            AccountAddress.from_str,
            ADDRESS_F_PADDED_SHORT_FORM.shortWithout0x,
        )

        # Demonstrate that only LONG format is accepted for 0x10.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_TEN.longWith0x)), ADDRESS_TEN.longWith0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.longWithout0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.shortWith0x
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_TEN.shortWithout0x
        )

        # Demonstrate that only LONG format is accepted for other addresses.
        self.assertEqual(
            str(AccountAddress.from_str(ADDRESS_OTHER.longWith0x)),
            ADDRESS_OTHER.longWith0x,
        )
        self.assertRaises(
            RuntimeError, AccountAddress.from_str, ADDRESS_OTHER.longWithout0x
        )
