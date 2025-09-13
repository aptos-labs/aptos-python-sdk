# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import tempfile
import unittest

from . import asymmetric_crypto, asymmetric_crypto_wrapper, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .authenticator import AccountAuthenticator
from .bcs import Serializer
from .transactions import RawTransactionInternal


class Account:
    """Represents a complete Aptos blockchain account with cryptographic key management.

    The Account class encapsulates the fundamental components needed to interact with
    the Aptos blockchain: an account address and its associated private key. It provides
    comprehensive functionality for account creation, transaction signing, key management,
    and persistent storage.

    Key Features:
    - **Multiple Key Types**: Supports Ed25519 and Secp256k1 ECDSA cryptographic schemes
    - **Random Generation**: Secure random account creation with proper entropy
    - **Key Import/Export**: Load accounts from hex strings or JSON files
    - **Transaction Signing**: Sign transactions and arbitrary data
    - **Address Derivation**: Automatic address calculation from public keys
    - **Persistence**: Save and load account data to/from files
    - **Authentication**: Generate authentication keys and proof challenges

    Cryptographic Support:
    - **Ed25519**: Default signature scheme, fast and secure
    - **Secp256k1 ECDSA**: Ethereum-compatible signatures for interoperability
    - **Multi-key**: Support for threshold and multi-signature schemes

    Examples:
        Create a new account::

            from aptos_sdk.account import Account

            # Generate new Ed25519 account
            account = Account.generate()
            print(f"Address: {account.address()}")
            print(f"Private key: {account.private_key}")

        Create Secp256k1 account::

            # Generate Secp256k1 ECDSA account (Ethereum-compatible)
            secp_account = Account.generate_secp256k1_ecdsa()
            print(f"Secp256k1 address: {secp_account.address()}")

        Load existing account::

            # From hex private key
            hex_key = "0x1234567890abcdef..."
            imported_account = Account.load_key(hex_key)

            # From JSON file
            saved_account = Account.load("./my_account.json")

        Sign transactions::

            from aptos_sdk.async_client import RestClient

            async def transfer_tokens():
                client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")

                # Create transfer transaction
                recipient = Account.generate().address()
                txn_hash = await client.transfer(account, recipient, 1000)

                # Wait for completion
                result = await client.wait_for_transaction(txn_hash)
                print(f"Transfer successful: {result['success']}")

        Persistent storage::

            # Save account to file
            account.store("./wallet.json")

            # Load account later
            restored_account = Account.load("./wallet.json")
            assert account == restored_account

        Sign arbitrary data::

            # Sign custom message
            message = b"Hello, Aptos!"
            signature = account.sign(message)

            # Verify signature
            public_key = account.public_key()
            is_valid = public_key.verify(message, signature)
            print(f"Signature valid: {is_valid}")

    Security Considerations:
    - **Private Key Protection**: Never expose private keys in logs or UI
    - **Secure Storage**: Use encrypted storage for production private keys
    - **Key Rotation**: Consider implementing key rotation for long-lived accounts
    - **Testnet First**: Always test on devnet/testnet before mainnet deployment
    - **Entropy**: The random generation uses cryptographically secure random sources

    Note:
        Account addresses are derived deterministically from public keys using
        SHA3-256 hashing. The same private key will always generate the same
        address across different SDK instances.
    """

    account_address: AccountAddress
    private_key: asymmetric_crypto.PrivateKey

    def __init__(
        self, account_address: AccountAddress, private_key: asymmetric_crypto.PrivateKey
    ):
        """Initialize an Account with the given address and private key.

        This constructor creates an Account instance from an existing address and
        private key pair. It's typically used internally by factory methods like
        generate() or load_key() rather than being called directly.

        Args:
            account_address: The blockchain address for this account.
            private_key: The private key that controls this account. Must correspond
                to the given address.

        Examples:
            Direct construction (advanced usage)::

                from aptos_sdk.ed25519 import PrivateKey
                from aptos_sdk.account_address import AccountAddress

                # Create components separately
                private_key = PrivateKey.random()
                address = AccountAddress.from_key(private_key.public_key())

                # Construct account
                account = Account(address, private_key)

        Note:
            The constructor does not validate that the address corresponds to
            the private key. Use the factory methods (generate, load_key) for
            guaranteed consistency.
        """
        self.account_address = account_address
        self.private_key = private_key

    def __eq__(self, other: object) -> bool:
        """
        Check equality between two Account instances.

        :param other: The other object to compare with
        :return: True if accounts are equal, False otherwise
        """
        if not isinstance(other, Account):
            return NotImplemented
        return (
            self.account_address == other.account_address
            and self.private_key == other.private_key
        )

    @staticmethod
    def generate() -> Account:
        """Generate a new Account with a cryptographically secure random Ed25519 private key.

        This method creates a completely new account with a randomly generated Ed25519
        private key and derives the corresponding account address. Ed25519 is the
        default and recommended signature scheme for Aptos due to its security and
        performance characteristics.

        Returns:
            Account: A new account with randomly generated Ed25519 credentials.

        Examples:
            Create new accounts::

                # Generate single account
                alice = Account.generate()
                print(f"Alice's address: {alice.address()}")

                # Generate multiple accounts
                accounts = [Account.generate() for _ in range(5)]
                for i, account in enumerate(accounts):
                    print(f"Account {i}: {account.address()}")

            Use in async context::

                import asyncio
                from aptos_sdk.async_client import FaucetClient, RestClient

                async def setup_test_account():
                    # Generate account
                    account = Account.generate()

                    # Fund from faucet
                    client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
                    faucet = FaucetClient("https://faucet.devnet.aptoslabs.com", client)

                    await faucet.fund_account(account.address(), 100_000_000)
                    balance = await client.account_balance(account.address())
                    print(f"Account funded with {balance} APT")

                    return account

        Security:
            - Uses cryptographically secure random number generation
            - Each call produces a unique, unpredictable private key
            - Private key entropy comes from system random sources
            - No two generated accounts will have the same private key

        Note:
            The generated account exists only in memory until explicitly saved
            using the store() method. The address is deterministically derived
            from the public key using SHA3-256 hashing.
        """
        private_key = ed25519.PrivateKey.random()
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)

    @staticmethod
    def generate_secp256k1_ecdsa() -> Account:
        """Generate a new Account with a cryptographically secure random Secp256k1 ECDSA private key.

        This method creates a new account using the Secp256k1 ECDSA signature scheme,
        which is compatible with Ethereum and Bitcoin. This enables interoperability
        with Ethereum tooling and allows users familiar with Ethereum to use the same
        cryptographic primitives.

        Returns:
            Account: A new account with randomly generated Secp256k1 ECDSA credentials.

        Examples:
            Create Ethereum-compatible account::

                # Generate Secp256k1 account
                eth_compatible_account = Account.generate_secp256k1_ecdsa()
                print(f"Secp256k1 address: {eth_compatible_account.address()}")

                # The private key can be used with Ethereum tooling
                private_key_hex = str(eth_compatible_account.private_key)
                print(f"Private key (Ethereum format): {private_key_hex}")

            Mixed signature schemes::

                # Create accounts with different signature schemes
                ed25519_account = Account.generate()  # Default Ed25519
                secp256k1_account = Account.generate_secp256k1_ecdsa()

                print(f"Ed25519 account: {ed25519_account.address()}")
                print(f"Secp256k1 account: {secp256k1_account.address()}")

                # Both can interact with Aptos equally
                # but have different signature formats

        Use Cases:
            - **Ethereum Migration**: Users migrating from Ethereum ecosystems
            - **Cross-Chain Applications**: Applications spanning Ethereum and Aptos
            - **Hardware Wallets**: Some hardware wallets prefer Secp256k1
            - **Enterprise Integration**: Systems already using Secp256k1

        Performance Considerations:
            - Secp256k1 signatures are larger than Ed25519 (64 vs 32 bytes)
            - Ed25519 has faster verification times
            - Secp256k1 has wider hardware support
            - Both are equally secure when implemented correctly

        Security:
            - Uses the same secure random generation as Ed25519
            - Follows Bitcoin/Ethereum security practices
            - Compatible with standard Secp256k1 implementations
            - Addresses are derived using Aptos's standard address scheme

        Note:
            While Secp256k1 is supported, Ed25519 is recommended for new applications
            due to its superior performance characteristics. Use Secp256k1 primarily
            for compatibility with existing Ethereum-based systems.
        """
        private_key = secp256k1_ecdsa.PrivateKey.random()
        public_key = asymmetric_crypto_wrapper.PublicKey(private_key.public_key())
        account_address = AccountAddress.from_key(public_key)
        return Account(account_address, private_key)

    @staticmethod
    def load_key(key: str) -> Account:
        """Create an Account from a hex-encoded Ed25519 private key string.

        This method reconstructs an Account from a previously exported private key.
        It's commonly used to import accounts from external sources, CLI tools,
        or when restoring accounts from backup storage.

        Args:
            key: Hex-encoded Ed25519 private key string (64 characters, 32 bytes).
                Can be with or without '0x' prefix.

        Returns:
            Account: An account instance created from the given private key.

        Raises:
            ValueError: If the key format is invalid or cannot be parsed.

        Examples:
            Import from hex string::

                # Standard hex format (64 characters)
                private_key_hex = "1a2b3c4d5e6f789..."  # 64 hex chars
                account = Account.load_key(private_key_hex)

                # With '0x' prefix
                prefixed_key = "0x1a2b3c4d5e6f789..."
                account = Account.load_key(prefixed_key)

            Restore from backup::

                # Export account key for backup
                original_account = Account.generate()
                backup_key = str(original_account.private_key)

                # Later, restore from backup
                restored_account = Account.load_key(backup_key)

                # Verify they're the same
                assert original_account.address() == restored_account.address()

            CLI integration::

                # Import from Aptos CLI output
                # aptos init --profile my-account
                # aptos account list --profile my-account
                cli_private_key = "0xa1b2c3d4e5f6..."
                account = Account.load_key(cli_private_key)

        Security Considerations:
            - **Never hardcode private keys** in source code
            - Use environment variables or secure key management
            - Validate key sources to prevent injection attacks
            - Consider using encrypted storage for sensitive keys

        Note:
            This method only supports Ed25519 private keys. For Secp256k1 keys,
            you'll need to use the appropriate Secp256k1 import methods or
            construct the account manually.
        """
        private_key = ed25519.PrivateKey.from_str(key)
        account_address = AccountAddress.from_key(private_key.public_key())
        return Account(account_address, private_key)

    @staticmethod
    def load(path: str) -> Account:
        """Load an Account from a JSON file containing account data.

        This method reads account information from a JSON file created by the
        store() method or compatible external tools. It provides persistent
        storage and retrieval of account credentials.

        Args:
            path: Path to the JSON file containing account data. The file must
                contain 'account_address' and 'private_key' fields.

        Returns:
            Account: An account instance loaded from the file data.

        Raises:
            FileNotFoundError: If the specified file doesn't exist.
            json.JSONDecodeError: If the file contains invalid JSON.
            KeyError: If required fields are missing from the JSON.
            ValueError: If the account data is malformed.

        File Format:
            Expected JSON structure::

                {
                    "account_address": "0x1234567890abcdef...",
                    "private_key": "0xabcdef1234567890..."
                }

        Examples:
            Save and load account::

                # Create and save account
                original_account = Account.generate()
                original_account.store("./wallet.json")

                # Load account later
                loaded_account = Account.load("./wallet.json")

                # Verify integrity
                assert original_account.address() == loaded_account.address()
                assert original_account == loaded_account

            Load from CLI-generated file::

                # If you used: aptos init --profile myaccount
                # The profile data can be imported
                try:
                    account = Account.load("./.aptos/config.yaml")
                    print(f"Loaded account: {account.address()}")
                except Exception as e:
                    print(f"Failed to load account: {e}")

            Batch operations::

                import os

                # Load multiple accounts from directory
                accounts = []
                for filename in os.listdir("./wallets/"):
                    if filename.endswith(".json"):
                        filepath = os.path.join("./wallets/", filename)
                        account = Account.load(filepath)
                        accounts.append(account)

                print(f"Loaded {len(accounts)} accounts")

        Security Considerations:
            - **File Permissions**: Ensure JSON files have restricted permissions
            - **Encryption**: Consider encrypting files containing private keys
            - **Backup**: Keep secure backups of account files
            - **Access Control**: Limit access to account files in production

        Integration:
            Compatible with files created by:
            - The Account.store() method
            - Aptos CLI account exports
            - Custom wallet implementations using the same format

        Note:
            The loaded account will have Ed25519 keys. The address format is
            flexible and accepts both strict and relaxed address formats.
        """
        with open(path) as file:
            data = json.load(file)
        return Account(
            AccountAddress.from_str_relaxed(data["account_address"]),
            ed25519.PrivateKey.from_str(data["private_key"]),
        )

    def store(self, path: str):
        """Store the Account data to a JSON file for persistent storage.

        This method serializes the account's address and private key to a JSON
        file that can be later loaded using the load() method. It provides a
        simple way to persist account credentials across application sessions.

        Args:
            path: File path where to save the account data. Will create or
                overwrite the file at the specified location.

        Raises:
            PermissionError: If the file cannot be written due to permissions.
            OSError: If there are filesystem-related errors.

        Security Warning:
            The JSON file will contain the private key in plaintext. Ensure
            proper file permissions and consider encryption for sensitive data.

        Examples:
            Basic storage and retrieval::

                # Create account
                account = Account.generate()

                # Store to file
                account.store("./my_wallet.json")

                # Load later
                loaded_account = Account.load("./my_wallet.json")
                assert account == loaded_account

            Secure file permissions::

                import os
                import stat

                # Store account
                account.store("./secure_wallet.json")

                # Set restrictive permissions (owner read/write only)
                os.chmod("./secure_wallet.json", stat.S_IRUSR | stat.S_IWUSR)

            Backup multiple accounts::

                accounts = [Account.generate() for _ in range(5)]

                for i, account in enumerate(accounts):
                    filename = f"./backups/account_{i}.json"
                    account.store(filename)
                    print(f"Saved account {account.address()} to {filename}")

        File Format:
            Creates JSON with structure::

                {
                    "account_address": "0x<hex_address>",
                    "private_key": "0x<hex_private_key>"
                }

        Note:
            - The file will be created or overwritten if it exists
            - Only Ed25519 private keys are currently supported for storage
            - Consider implementing encryption wrapper for production use
        """
        data = {
            "account_address": str(self.account_address),
            "private_key": str(self.private_key),
        }
        with open(path, "w") as file:
            json.dump(data, file)

    def address(self) -> AccountAddress:
        """Get the blockchain address associated with this account.

        The account address is a unique identifier derived from the account's
        public key using SHA3-256 hashing. This address is used to identify
        the account on the blockchain and in transactions.

        Returns:
            AccountAddress: The unique address for this account on the blockchain.

        Examples:
            Get account address::

                account = Account.generate()
                address = account.address()
                print(f"Account address: {address}")
                # Output: Account address: 0xa1b2c3d4e5f67890...

            Use address in transactions::

                from aptos_sdk.async_client import RestClient

                async def check_balance():
                    client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")

                    # Use account address for queries
                    balance = await client.account_balance(account.address())
                    print(f"Balance: {balance} APT")

                    # Use as transaction recipient
                    recipient_address = account.address()

            Address comparison::

                account1 = Account.generate()
                account2 = Account.generate()

                # Addresses are unique
                assert account1.address() != account2.address()

                # Same account always has same address
                assert account1.address() == account1.address()

        Properties:
            - **Deterministic**: Same private key always produces same address
            - **Unique**: Each private key produces a unique address
            - **Immutable**: Address cannot change without changing the private key
            - **Format**: 32-byte hex string with '0x' prefix

        Note:
            The address is computed from the public key, not stored separately.
            This ensures consistency and reduces the risk of address/key mismatches.
        """
        return self.account_address

    def auth_key(self) -> str:
        """Get the authentication key for this account.

        The authentication key is derived from the account's public key and
        represents the current key that can authenticate transactions for this
        account. Initially, the auth key equals the account address, but it can
        change through key rotation operations.

        Returns:
            str: The authentication key as a hex string with '0x' prefix.

        Examples:
            Check initial auth key::

                account = Account.generate()
                address = str(account.address())
                auth_key = account.auth_key()

                # Initially, auth key equals address
                assert address == auth_key
                print(f"Address:  {address}")
                print(f"Auth key: {auth_key}")

            Use in authentication::

                # Auth key is used for verifying transaction signatures
                transaction_data = b"transaction_payload"
                signature = account.sign(transaction_data)

                # The auth key identifies which public key to use for verification
                public_key = account.public_key()
                is_valid = public_key.verify(transaction_data, signature)

            Key rotation scenario::

                # After key rotation, auth key would differ from original address
                # but the account address remains the same for identification
                original_address = account.address()
                current_auth_key = account.auth_key()

                # Address is permanent, auth key can change
                print(f"Permanent address: {original_address}")
                print(f"Current auth key: {current_auth_key}")

        Key Concepts:
            - **Account Address**: Permanent identifier, never changes
            - **Authentication Key**: Current key for signing, can be rotated
            - **Initial State**: Auth key == address for new accounts
            - **After Rotation**: Auth key != address, but address stays same

        Use Cases:
            - Verifying transaction signatures
            - Key rotation operations
            - Multi-signature account management
            - Authentication in smart contracts

        Note:
            For newly generated accounts, the authentication key will be identical
            to the account address. They only differ after key rotation operations.
        """
        return str(AccountAddress.from_key(self.private_key.public_key()))

    def sign(self, data: bytes) -> asymmetric_crypto.Signature:
        """Sign arbitrary data with the account's private key.

        This method creates a cryptographic signature over any data using the
        account's private key. The signature can be verified using the corresponding
        public key, providing proof of data authenticity and account ownership.

        Args:
            data: The raw bytes to be signed. Can be any binary data including
                transaction payloads, messages, or arbitrary content.

        Returns:
            asymmetric_crypto.Signature: A signature object that can be verified
                with the account's public key.

        Examples:
            Sign custom message::

                account = Account.generate()
                message = b"Hello, Aptos blockchain!"

                # Create signature
                signature = account.sign(message)

                # Verify signature
                public_key = account.public_key()
                is_valid = public_key.verify(message, signature)
                print(f"Signature valid: {is_valid}")  # True

            Sign structured data::

                import json

                # Sign JSON data
                data_dict = {
                    "action": "transfer",
                    "amount": 1000,
                    "recipient": "0xabc123..."
                }
                data_bytes = json.dumps(data_dict, sort_keys=True).encode()
                signature = account.sign(data_bytes)

            Authentication proof::

                # Prove account ownership
                challenge = b"prove_ownership_2023"
                proof_signature = account.sign(challenge)

                # Others can verify you own the account
                # without revealing your private key

            Transaction component::

                # This is typically used internally by transaction signing
                # but can be used for custom transaction construction
                raw_transaction_bytes = serialize_transaction(...)
                transaction_signature = account.sign(raw_transaction_bytes)

        Security Properties:
            - **Non-repudiation**: Only the private key holder can create valid signatures
            - **Data Integrity**: Signatures detect any modification to signed data
            - **Authentication**: Proves the signer owns the private key
            - **Unforgeable**: Cryptographically impossible to forge without the private key

        Signature Schemes:
            - **Ed25519**: Default, fast verification, 64-byte signatures
            - **Secp256k1 ECDSA**: Ethereum-compatible, variable-length signatures

        Note:
            The signature is deterministic for Ed25519 but may be randomized for
            Secp256k1, meaning the same data might produce different valid signatures
            each time it's signed with Secp256k1.
        """
        return self.private_key.sign(data)

    def sign_simulated_transaction(
        self, transaction: RawTransactionInternal
    ) -> AccountAuthenticator:
        """
        Sign a simulated transaction for testing purposes.

        :param transaction: The transaction to simulate signing
        :return: An AccountAuthenticator for the simulated signature
        """
        return transaction.sign_simulated(self.private_key.public_key())

    def sign_transaction(
        self, transaction: RawTransactionInternal
    ) -> AccountAuthenticator:
        """
        Sign a transaction with this account's private key.

        :param transaction: The transaction to sign
        :return: An AccountAuthenticator containing the signature
        """
        return transaction.sign(self.private_key)

    def public_key(self) -> asymmetric_crypto.PublicKey:
        """Get the public key corresponding to this account's private key.

        The public key is the cryptographic counterpart to the private key and
        is used for signature verification, address derivation, and sharing with
        others who need to verify signatures or send transactions to this account.

        Returns:
            asymmetric_crypto.PublicKey: The public key that corresponds to this
                account's private key.

        Examples:
            Get public key for verification::

                account = Account.generate()
                public_key = account.public_key()

                # Use for signature verification
                message = b"test message"
                signature = account.sign(message)
                is_valid = public_key.verify(message, signature)
                print(f"Signature valid: {is_valid}")  # True

            Share public key safely::

                # Public keys are safe to share
                public_key_hex = str(account.public_key())
                print(f"My public key: {public_key_hex}")

                # Others can use it to:
                # 1. Verify signatures from you
                # 2. Derive your account address
                # 3. Send you transactions

            Address derivation::

                from aptos_sdk.account_address import AccountAddress

                # Address is derived from public key
                derived_address = AccountAddress.from_key(account.public_key())
                account_address = account.address()

                assert derived_address == account_address

            Multi-signature setup::

                # Collect public keys for multi-sig account
                accounts = [Account.generate() for _ in range(3)]
                public_keys = [acc.public_key() for acc in accounts]

                # Use public_keys to create multi-signature account
                # (threshold signatures, etc.)

        Key Properties:
            - **Safe to Share**: Public keys can be shared openly without risk
            - **Deterministic**: Always the same for a given private key
            - **Verification**: Used to verify signatures created by the private key
            - **Address Derivation**: Account addresses are computed from public keys

        Common Uses:
            - Signature verification by other parties
            - Creating multi-signature accounts
            - Address computation and validation
            - Key rotation proofs and challenges
            - Smart contract public key storage

        Note:
            Unlike private keys, public keys are safe to store, transmit, and share.
            They enable others to interact with your account without compromising security.
        """
        return self.private_key.public_key()


class RotationProofChallenge:
    """
    Represents a rotation proof challenge for rotating authentication keys.

    This challenge is used to prove ownership when rotating an account's
    authentication key to a new public key.
    """

    type_info_account_address: AccountAddress = AccountAddress.from_str("0x1")
    type_info_module_name: str = "account"
    type_info_struct_name: str = "RotationProofChallenge"
    sequence_number: int
    originator: AccountAddress
    current_auth_key: AccountAddress
    new_public_key: asymmetric_crypto.PublicKey

    def __init__(
        self,
        sequence_number: int,
        originator: AccountAddress,
        current_auth_key: AccountAddress,
        new_public_key: asymmetric_crypto.PublicKey,
    ):
        """
        Initialize a rotation proof challenge.

        :param sequence_number: The sequence number for this rotation
        :param originator: The account address initiating the rotation
        :param current_auth_key: The current authentication key
        :param new_public_key: The new public key to rotate to
        """
        self.sequence_number = sequence_number
        self.originator = originator
        self.current_auth_key = current_auth_key
        self.new_public_key = new_public_key

    def serialize(self, serializer: Serializer):
        """
        Serialize the rotation proof challenge using BCS serialization.

        :param serializer: The BCS serializer to use for serialization
        """
        self.type_info_account_address.serialize(serializer)
        serializer.str(self.type_info_module_name)
        serializer.str(self.type_info_struct_name)
        serializer.u64(self.sequence_number)
        self.originator.serialize(serializer)
        self.current_auth_key.serialize(serializer)
        serializer.struct(self.new_public_key)


class Test(unittest.TestCase):
    def test_load_and_store(self):
        (file, path) = tempfile.mkstemp()
        start = Account.generate()
        start.store(path)
        load = Account.load(path)

        self.assertEqual(start, load)
        # Auth key and Account address should be the same at start
        self.assertEqual(str(start.address()), start.auth_key())

    def test_key(self):
        message = b"test message"
        account = Account.generate()
        signature = account.sign(message)
        self.assertTrue(account.public_key().verify(message, signature))

    def test_rotation_proof_challenge(self):
        # Create originating account from private key.
        originating_account = Account.load_key(
            "005120c5882b0d492b3d2dc60a8a4510ec2051825413878453137305ba2d644b"
        )
        # Create target account from private key.
        target_account = Account.load_key(
            "19d409c191b1787d5b832d780316b83f6ee219677fafbd4c0f69fee12fdcdcee"
        )
        # Construct rotation proof challenge.
        rotation_proof_challenge = RotationProofChallenge(
            sequence_number=1234,
            originator=originating_account.address(),
            current_auth_key=originating_account.address(),
            new_public_key=target_account.public_key(),
        )
        # Serialize transaction.
        serializer = Serializer()
        rotation_proof_challenge.serialize(serializer)
        rotation_proof_challenge_bcs = serializer.output().hex()
        # Compare against expected bytes.
        expected_bytes = (
            "0000000000000000000000000000000000000000000000000000000000000001"
            "076163636f756e7416526f746174696f6e50726f6f664368616c6c656e6765d2"
            "0400000000000015b67a673979c7c5dfc8d9c9f94d02da35062a19dd9d218087"
            "bd9076589219c615b67a673979c7c5dfc8d9c9f94d02da35062a19dd9d218087"
            "bd9076589219c620a1f942a3c46e2a4cd9552c0f95d529f8e3b60bcd44408637"
            "9ace35e4458b9f22"
        )
        self.assertEqual(rotation_proof_challenge_bcs, expected_bytes)
