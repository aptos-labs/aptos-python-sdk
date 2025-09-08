# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Transaction authentication infrastructure for the Aptos blockchain.

This module provides the authentication framework that validates transaction signatures
and ensures proper authorization for blockchain operations. It supports multiple signature
schemes and complex transaction types including multi-agent and fee payer scenarios.

Authentication Flow:
    1. **Transaction Creation**: Transactions are built with specific payloads
    2. **Signing**: Accounts sign the transaction hash using their private keys
    3. **Authenticator Packaging**: Signatures are wrapped in appropriate authenticators
    4. **Verification**: The blockchain validates signatures against stored authentication keys
    5. **Execution**: Validated transactions are processed on-chain

Supported Authentication Types:
- **Single Signature**: Ed25519 and other single-key schemes
- **Multi-Signature**: Threshold-based multi-signature authentication
- **Multi-Agent**: Transactions requiring multiple distinct signers
- **Fee Payer**: Transactions with sponsored gas fees
- **Single Sender**: Modern unified single signature format

Key Features:
- **Algorithm Flexibility**: Support for Ed25519, secp256k1, and other schemes
- **Multi-Party Transactions**: Complex transaction patterns with multiple signers
- **Threshold Security**: N-of-M multi-signature requirements
- **Fee Sponsorship**: Gas fee delegation to third parties
- **Backward Compatibility**: Support for legacy authentication formats
- **BCS Serialization**: Efficient binary encoding for blockchain storage

Authentication Hierarchy:
    TransactionAuthenticator (top level)
    │
    ├── SingleSenderAuthenticator (modern single signature)
    │
    ├── MultiAgentAuthenticator (multiple distinct signers)
    │   └── Contains: sender + list of AccountAuthenticators
    │
    └── FeePayerAuthenticator (fee sponsorship)
        └── Contains: sender + fee payer + list of AccountAuthenticators

    AccountAuthenticator (account-level)
    │
    ├── Ed25519Authenticator (legacy single Ed25519)
    ├── MultiEd25519Authenticator (legacy multi-Ed25519)
    ├── SingleKeyAuthenticator (modern single key)
    └── MultiKeyAuthenticator (modern multi-key)

Examples:
    Basic single signature transaction::

        from aptos_sdk.authenticator import Ed25519Authenticator, Authenticator
        from aptos_sdk import ed25519

        # Create Ed25519 authenticator
        private_key = ed25519.PrivateKey.random()
        public_key = private_key.public_key()

        # Sign transaction hash
        tx_hash = b"transaction_hash_bytes"
        signature = private_key.sign(tx_hash)

        # Create authenticator
        account_auth = Ed25519Authenticator(public_key, signature)
        tx_auth = Authenticator(account_auth)

        # Verify signature
        is_valid = tx_auth.verify(tx_hash)

    Multi-signature authentication::

        from aptos_sdk.authenticator import MultiEd25519Authenticator
        from aptos_sdk import ed25519

        # Create 2-of-3 multisig
        private_keys = [ed25519.PrivateKey.random() for _ in range(3)]
        public_keys = [pk.public_key() for pk in private_keys]
        multi_pub_key = ed25519.MultiPublicKey(public_keys, threshold=2)

        # Sign with 2 keys (indices 0 and 2)
        signatures = [
            (0, private_keys[0].sign(tx_hash)),
            (2, private_keys[2].sign(tx_hash))
        ]
        multi_signature = ed25519.MultiSignature(signatures)

        # Create multi-signature authenticator
        multi_auth = MultiEd25519Authenticator(multi_pub_key, multi_signature)
        tx_auth = Authenticator(multi_auth)

    Multi-agent transaction::

        # Transaction requiring multiple distinct signers
        sender_auth = Ed25519Authenticator(sender_public_key, sender_signature)
        agent1_auth = Ed25519Authenticator(agent1_public_key, agent1_signature)
        agent2_auth = Ed25519Authenticator(agent2_public_key, agent2_signature)

        # Create multi-agent authenticator
        multi_agent_auth = MultiAgentAuthenticator(
            sender=sender_auth,
            secondary_signers=[agent1_auth, agent2_auth]
        )
        tx_auth = Authenticator(multi_agent_auth)

    Fee payer transaction::

        # Transaction where someone else pays the gas fees
        sender_auth = Ed25519Authenticator(sender_public_key, sender_signature)
        fee_payer_auth = Ed25519Authenticator(fee_payer_public_key, fee_payer_signature)

        fee_payer_tx_auth = FeePayerAuthenticator(
            sender=sender_auth,
            secondary_signers=[],
            fee_payer=fee_payer_auth
        )
        tx_auth = Authenticator(fee_payer_tx_auth)

Security Considerations:
- **Signature Verification**: All signatures must be cryptographically valid
- **Key Authorization**: Public keys must match stored authentication keys
- **Replay Protection**: Transaction hashes include sequence numbers and timestamps
- **Multi-Signature Thresholds**: Ensure sufficient signatures meet threshold requirements
- **Agent Authorization**: Verify all required parties have signed multi-agent transactions

Gas and Performance:
- Single signatures: ~20-50 gas units for verification
- Multi-signatures: ~50-200 gas units depending on threshold and key count
- Multi-agent: Additional gas per secondary signer
- Fee payer: Overhead for fee delegation logic

Best Practices:
- Use Ed25519 for new applications (faster, smaller signatures)
- Implement proper key rotation for long-term security
- Set reasonable multi-signature thresholds (not too high)
- Validate all signatures before transaction submission
- Use appropriate authenticator types for each use case

See Also:
    - ed25519: Ed25519 cryptographic primitives
    - asymmetric_crypto_wrapper: Unified cryptographic interfaces
    - transactions: Transaction construction and management
"""

from __future__ import annotations

import typing
import unittest
from typing import List

from . import asymmetric_crypto, asymmetric_crypto_wrapper, ed25519, secp256k1_ecdsa
from .account_address import AccountAddress
from .bcs import Deserializer, Serializer


class Authenticator:
    """Top-level transaction authenticator for the Aptos blockchain.

    Each transaction submitted to the Aptos blockchain contains a TransactionAuthenticator
    that proves the transaction was authorized by the appropriate accounts. During
    transaction execution, the executor validates that every signature is well-formed
    and matches the AuthenticationKey stored under each participating account.

    The Authenticator class serves as a wrapper that can contain different types of
    authentication schemes, from simple single signatures to complex multi-party
    transactions with fee delegation.

    Supported Authentication Types:
        ED25519 (0): Legacy single Ed25519 signature
        MULTI_ED25519 (1): Legacy multi-Ed25519 signatures
        MULTI_AGENT (2): Multiple distinct signers for complex transactions
        FEE_PAYER (3): Transactions with fee sponsorship
        SINGLE_SENDER (4): Modern unified single signature format

    Attributes:
        variant (int): Integer identifier for the authentication type
        authenticator (typing.Any): The underlying concrete authenticator implementation

    Examples:
        Simple single signature::

            private_key = ed25519.PrivateKey.random()
            signature = private_key.sign(transaction_hash)

            ed25519_auth = Ed25519Authenticator(private_key.public_key(), signature)
            tx_auth = Authenticator(ed25519_auth)

        Multi-agent transaction::

            sender_auth = Ed25519Authenticator(sender_key.public_key(), sender_sig)
            agent_auth = Ed25519Authenticator(agent_key.public_key(), agent_sig)

            multi_agent = MultiAgentAuthenticator(sender_auth, [agent_auth])
            tx_auth = Authenticator(multi_agent)

        Serialization and verification::

            # Serialize for blockchain submission
            serializer = Serializer()
            tx_auth.serialize(serializer)
            auth_bytes = serializer.output()

            # Verify signatures
            is_valid = tx_auth.verify(transaction_hash)

    Note:
        The authenticator type is automatically determined from the wrapped
        authenticator implementation and cannot be changed after construction.
    """

    ED25519: int = 0
    MULTI_ED25519: int = 1
    MULTI_AGENT: int = 2
    FEE_PAYER: int = 3
    SINGLE_SENDER: int = 4

    variant: int
    authenticator: typing.Any

    def __init__(self, authenticator: typing.Any):
        """
        Initialize an Authenticator with the appropriate variant.

        :param authenticator: The specific authenticator implementation
        :raises Exception: If authenticator type is not recognized
        """
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = Authenticator.ED25519
        elif isinstance(authenticator, MultiEd25519Authenticator):
            self.variant = Authenticator.MULTI_ED25519
        elif isinstance(authenticator, MultiAgentAuthenticator):
            self.variant = Authenticator.MULTI_AGENT
        elif isinstance(authenticator, FeePayerAuthenticator):
            self.variant = Authenticator.FEE_PAYER
        elif isinstance(authenticator, SingleSenderAuthenticator):
            self.variant = Authenticator.SINGLE_SENDER
        else:
            raise Exception("Invalid type")
        self.authenticator = authenticator

    def from_key(key: asymmetric_crypto.PublicKey) -> int:
        """
        Determine the appropriate authenticator variant for a given public key type.

        :param key: The public key to determine the variant for
        :return: The authenticator variant constant
        :raises NotImplementedError: If key type is not supported
        """
        if isinstance(key, ed25519.PublicKey):
            return Authenticator.ED25519
        elif isinstance(key, ed25519.MultiPublicKey):
            return Authenticator.MULTI_ED25519
        else:
            raise NotImplementedError()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Authenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __str__(self) -> str:
        return self.authenticator.__str__()

    def verify(self, data: bytes) -> bool:
        """
        Verify the signature against the provided data.

        :param data: The data that was signed
        :return: True if the signature is valid, False otherwise
        """
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Authenticator:
        variant = deserializer.uleb128()

        if variant == Authenticator.ED25519:
            authenticator: typing.Any = Ed25519Authenticator.deserialize(deserializer)
        elif variant == Authenticator.MULTI_ED25519:
            authenticator = MultiEd25519Authenticator.deserialize(deserializer)
        elif variant == Authenticator.MULTI_AGENT:
            authenticator = MultiAgentAuthenticator.deserialize(deserializer)
        elif variant == Authenticator.FEE_PAYER:
            authenticator = FeePayerAuthenticator.deserialize(deserializer)
        elif variant == Authenticator.SINGLE_SENDER:
            authenticator = SingleSenderAuthenticator.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return Authenticator(authenticator)

    def serialize(self, serializer: Serializer):
        """
        Serialize this authenticator using BCS serialization.

        :param serializer: The BCS serializer to use
        """
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)


class AccountAuthenticator:
    """
    An authenticator for a single account signature.

    This wraps different types of signature schemes that can be used
    to authenticate an account's authorization of a transaction.
    """

    ED25519: int = 0
    MULTI_ED25519: int = 1
    SINGLE_KEY: int = 2
    MULTI_KEY: int = 3

    variant: int
    authenticator: typing.Any

    def __init__(self, authenticator: typing.Any):
        """
        Initialize an AccountAuthenticator with the appropriate variant.

        :param authenticator: The specific authenticator implementation
        :raises Exception: If authenticator type is not recognized
        """
        if isinstance(authenticator, Ed25519Authenticator):
            self.variant = AccountAuthenticator.ED25519
        elif isinstance(authenticator, MultiEd25519Authenticator):
            self.variant = AccountAuthenticator.MULTI_ED25519
        elif isinstance(authenticator, SingleKeyAuthenticator):
            self.variant = AccountAuthenticator.SINGLE_KEY
        elif isinstance(authenticator, MultiKeyAuthenticator):
            self.variant = AccountAuthenticator.MULTI_KEY
        else:
            raise Exception("Invalid type")
        self.authenticator = authenticator

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AccountAuthenticator):
            return NotImplemented
        return (
            self.variant == other.variant and self.authenticator == other.authenticator
        )

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return self.authenticator.__str__()

    def verify(self, data: bytes) -> bool:
        """
        Verify the signature against the provided data.

        :param data: The data that was signed
        :return: True if the signature is valid, False otherwise
        """
        return self.authenticator.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> AccountAuthenticator:
        variant = deserializer.uleb128()

        if variant == AccountAuthenticator.ED25519:
            authenticator: typing.Any = Ed25519Authenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.MULTI_ED25519:
            authenticator = MultiEd25519Authenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.SINGLE_KEY:
            authenticator = SingleKeyAuthenticator.deserialize(deserializer)
        elif variant == AccountAuthenticator.MULTI_KEY:
            authenticator = MultiKeyAuthenticator.deserialize(deserializer)
        else:
            raise Exception(f"Invalid type: {variant}")

        return AccountAuthenticator(authenticator)

    def serialize(self, serializer: Serializer):
        """
        Serialize this account authenticator using BCS serialization.

        :param serializer: The BCS serializer to use
        """
        serializer.uleb128(self.variant)
        serializer.struct(self.authenticator)


class Ed25519Authenticator:
    """
    An authenticator that uses Ed25519 signature scheme.

    This is the most common signature scheme used in Aptos.
    """

    public_key: ed25519.PublicKey
    signature: ed25519.Signature

    def __init__(self, public_key: ed25519.PublicKey, signature: ed25519.Signature):
        """
        Initialize an Ed25519 authenticator.

        :param public_key: The Ed25519 public key
        :param signature: The Ed25519 signature
        """
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519Authenticator):
            return NotImplemented

        return self.public_key == other.public_key and self.signature == other.signature

    def __str__(self) -> str:
        return f"PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """
        Verify the Ed25519 signature against the provided data.

        :param data: The data that was signed
        :return: True if the signature is valid, False otherwise
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Ed25519Authenticator:
        key = deserializer.struct(ed25519.PublicKey)
        signature = deserializer.struct(ed25519.Signature)
        return Ed25519Authenticator(key, signature)

    def serialize(self, serializer: Serializer):
        """
        Serialize this Ed25519 authenticator using BCS serialization.

        :param serializer: The BCS serializer to use
        """
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class FeePayerAuthenticator:
    """
    An authenticator for fee-payer transactions.

    This allows a different account to pay the transaction fees
    while still requiring signatures from all participants.
    """

    sender: AccountAuthenticator
    secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]]
    fee_payer: typing.Tuple[AccountAddress, AccountAuthenticator]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]],
        fee_payer: typing.Tuple[AccountAddress, AccountAuthenticator],
    ):
        """
        Initialize a fee payer authenticator.

        :param sender: The sender's authenticator
        :param secondary_signers: List of (address, authenticator) pairs for secondary signers
        :param fee_payer: Tuple of (address, authenticator) for the fee payer
        """
        self.sender = sender
        self.secondary_signers = secondary_signers
        self.fee_payer = fee_payer

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FeePayerAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
            and self.fee_payer == other.fee_payer
        )

    def __str__(self) -> str:
        return f"FeePayer: \n\tSender: {self.sender}\n\tSecondary Signers: {self.secondary_signers}\n\t{self.fee_payer}"

    def fee_payer_address(self) -> AccountAddress:
        """
        Get the address of the fee payer.

        :return: The fee payer's account address
        """
        return self.fee_payer[0]

    def secondary_addresses(self) -> List[AccountAddress]:
        """
        Get the addresses of all secondary signers.

        :return: List of secondary signer addresses
        """
        return [x[0] for x in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        """
        Verify all signatures against the provided data.

        :param data: The data that was signed
        :return: True if all signatures are valid, False otherwise
        """
        if not self.sender.verify(data):
            return False
        if not self.fee_payer[1].verify(data):
            return False
        return all([x[1].verify(data) for x in self.secondary_signers])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> FeePayerAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_authenticators = deserializer.sequence(
            AccountAuthenticator.deserialize
        )
        fee_payer_address = deserializer.struct(AccountAddress)
        fee_payer_authenticator = deserializer.struct(AccountAuthenticator)
        return FeePayerAuthenticator(
            sender,
            list(zip(secondary_addresses, secondary_authenticators)),
            (fee_payer_address, fee_payer_authenticator),
        )

    def serialize(self, serializer: Serializer):
        """
        Serialize this fee payer authenticator using BCS serialization.

        :param serializer: The BCS serializer to use
        """
        serializer.struct(self.sender)
        serializer.sequence([x[0] for x in self.secondary_signers], Serializer.struct)
        serializer.sequence([x[1] for x in self.secondary_signers], Serializer.struct)
        serializer.struct(self.fee_payer[0])
        serializer.struct(self.fee_payer[1])


class MultiAgentAuthenticator:
    """
    An authenticator for multi-agent transactions.

    This requires signatures from multiple accounts to authorize a transaction.
    """

    sender: AccountAuthenticator
    secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]]

    def __init__(
        self,
        sender: AccountAuthenticator,
        secondary_signers: List[typing.Tuple[AccountAddress, AccountAuthenticator]],
    ):
        """
        Initialize a multi-agent authenticator.

        :param sender: The sender's authenticator
        :param secondary_signers: List of (address, authenticator) pairs for secondary signers
        """
        self.sender = sender
        self.secondary_signers = secondary_signers

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MultiAgentAuthenticator):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.secondary_signers == other.secondary_signers
        )

    def secondary_addresses(self) -> List[AccountAddress]:
        """
        Get the addresses of all secondary signers.

        :return: List of secondary signer addresses
        """
        return [x[0] for x in self.secondary_signers]

    def verify(self, data: bytes) -> bool:
        """
        Verify all signatures against the provided data.

        :param data: The data that was signed
        :return: True if all signatures are valid, False otherwise
        """
        if not self.sender.verify(data):
            return False
        return all([x[1].verify(data) for x in self.secondary_signers])

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiAgentAuthenticator:
        sender = deserializer.struct(AccountAuthenticator)
        secondary_addresses = deserializer.sequence(AccountAddress.deserialize)
        secondary_authenticators = deserializer.sequence(
            AccountAuthenticator.deserialize
        )
        return MultiAgentAuthenticator(
            sender, list(zip(secondary_addresses, secondary_authenticators))
        )

    def serialize(self, serializer: Serializer):
        """
        Serialize this multi-agent authenticator using BCS serialization.

        :param serializer: The BCS serializer to use
        """
        serializer.struct(self.sender)
        serializer.sequence([x[0] for x in self.secondary_signers], Serializer.struct)
        serializer.sequence([x[1] for x in self.secondary_signers], Serializer.struct)


class MultiEd25519Authenticator:
    """An authenticator that uses multi-signature Ed25519 scheme.

    This authenticator supports threshold signatures using multiple Ed25519 keys,
    requiring a minimum number of signatures (threshold) from a set of public keys
    to authorize a transaction. This is useful for shared accounts, multi-party
    custody, and governance scenarios.

    Features:
    - N-of-M threshold signatures (e.g., 2-of-3, 3-of-5)
    - Efficient Ed25519 cryptography
    - Legacy support for older multi-signature formats
    - BCS serialization compatibility

    Security Properties:
    - Requires threshold number of valid signatures
    - Each signature must be from a different key in the set
    - Provides non-repudiation and authenticity
    - Resistant to single key compromise

    Examples:
        Create a 2-of-3 multi-signature::

            import ed25519

            # Generate 3 key pairs
            private_keys = [ed25519.PrivateKey.random() for _ in range(3)]
            public_keys = [pk.public_key() for pk in private_keys]

            # Create multi-public key with threshold 2
            multi_pub_key = ed25519.MultiPublicKey(public_keys, threshold=2)

            # Sign with keys 0 and 2 (meeting threshold)
            tx_hash = b"transaction_hash"
            signatures = [
                (0, private_keys[0].sign(tx_hash)),
                (2, private_keys[2].sign(tx_hash))
            ]
            multi_signature = ed25519.MultiSignature(signatures)

            # Create authenticator
            auth = MultiEd25519Authenticator(multi_pub_key, multi_signature)

        Verify the multi-signature::

            is_valid = auth.verify(tx_hash)  # Should return True

    Attributes:
        public_key (ed25519.MultiPublicKey): The multi-public key containing all keys and threshold
        signature (ed25519.MultiSignature): The multi-signature containing threshold signatures

    Note:
        This is a legacy format. New applications should consider using
        MultiKeyAuthenticator for better algorithm flexibility.
    """

    public_key: ed25519.MultiPublicKey
    signature: ed25519.MultiSignature

    def __init__(
        self, public_key: ed25519.MultiPublicKey, signature: ed25519.MultiSignature
    ):
        """Initialize a multi-Ed25519 authenticator.

        Args:
            public_key: The multi-public key containing all keys and threshold requirements
            signature: The multi-signature with the required threshold signatures

        Examples:
            Basic initialization::

                multi_pub_key = ed25519.MultiPublicKey([pk1, pk2, pk3], threshold=2)
                multi_sig = ed25519.MultiSignature([(0, sig1), (2, sig3)])
                auth = MultiEd25519Authenticator(multi_pub_key, multi_sig)
        """
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        """Check equality with another MultiEd25519Authenticator.

        Args:
            other: Object to compare with

        Returns:
            True if public keys and signatures are equal, False otherwise
        """
        if not isinstance(other, MultiEd25519Authenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __str__(self) -> str:
        """String representation of the multi-Ed25519 authenticator.

        Returns:
            Human-readable string showing public key and signature details
        """
        return f"MultiPublicKey: {self.public_key}, MultiSignature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """Verify the multi-signature against the provided data.

        This method validates that:
        1. The threshold number of signatures is provided
        2. Each signature is from a different key in the multi-public key
        3. Each signature is cryptographically valid

        Args:
            data: The data that was signed (typically a transaction hash)

        Returns:
            True if the multi-signature is valid, False otherwise

        Note:
            This method is currently not implemented in the base class.
            Implementations should delegate to the underlying ed25519.MultiPublicKey.verify method.
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiEd25519Authenticator:
        """Deserialize a MultiEd25519Authenticator from BCS bytes.

        Args:
            deserializer: The BCS deserializer containing the authenticator data

        Returns:
            A MultiEd25519Authenticator instance

        Raises:
            DeserializationError: If the data is malformed or incomplete
        """
        public_key = deserializer.struct(ed25519.MultiPublicKey)
        signature = deserializer.struct(ed25519.MultiSignature)
        return MultiEd25519Authenticator(public_key, signature)

    def serialize(self, serializer: Serializer):
        """Serialize this multi-Ed25519 authenticator using BCS serialization.

        This serializes both the multi-public key (including all public keys
        and the threshold) and the multi-signature (including signature indices
        and the actual signature bytes).

        Args:
            serializer: The BCS serializer to write to
        """
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class SingleSenderAuthenticator:
    """Modern unified single signature authenticator for the Aptos blockchain.

    This is the preferred authenticator format for simple single-signature transactions
    in newer versions of Aptos. It provides a clean, unified interface that can wrap
    different types of single-key authentication schemes.

    The SingleSenderAuthenticator is part of the Transaction Authenticator V2 format
    and is designed to be more extensible and consistent than the legacy authenticator
    formats.

    Features:
    - Modern unified interface for single signatures
    - Supports multiple signature algorithms through AccountAuthenticator
    - Consistent with Transaction Authenticator V2 specification
    - Efficient serialization and verification
    - Forward compatibility with future signature schemes

    Use Cases:
    - Standard single-account transactions
    - Modern applications preferring the unified format
    - Systems requiring forward compatibility
    - Clean integration with newer Aptos features

    Examples:
        Create with Ed25519 signature::

            from aptos_sdk import ed25519
            from aptos_sdk.authenticator import (
                Ed25519Authenticator,
                AccountAuthenticator,
                SingleSenderAuthenticator,
                Authenticator
            )

            # Generate key and sign
            private_key = ed25519.PrivateKey.random()
            public_key = private_key.public_key()
            signature = private_key.sign(transaction_hash)

            # Create authenticator chain
            ed25519_auth = Ed25519Authenticator(public_key, signature)
            account_auth = AccountAuthenticator(ed25519_auth)
            single_sender = SingleSenderAuthenticator(account_auth)
            tx_auth = Authenticator(single_sender)

        Create with modern single key::

            from aptos_sdk.authenticator import SingleKeyAuthenticator

            # Using the modern single key format
            single_key_auth = SingleKeyAuthenticator(public_key, signature)
            account_auth = AccountAuthenticator(single_key_auth)
            single_sender = SingleSenderAuthenticator(account_auth)

        Verification::

            # Verify the signature
            is_valid = single_sender.verify(transaction_hash)
            print(f"Signature valid: {is_valid}")

    Attributes:
        sender (AccountAuthenticator): The account authenticator for the sender

    Note:
        While this format is more modern, existing applications using Ed25519Authenticator
        directly can continue to work. This format provides better extensibility for
        future signature scheme additions.
    """

    sender: AccountAuthenticator

    def __init__(
        self,
        sender: AccountAuthenticator,
    ):
        """Initialize a single sender authenticator.

        Args:
            sender: The account authenticator for the transaction sender

        Examples:
            Basic initialization::

                ed25519_auth = Ed25519Authenticator(public_key, signature)
                account_auth = AccountAuthenticator(ed25519_auth)
                single_sender = SingleSenderAuthenticator(account_auth)
        """
        self.sender = sender

    def __eq__(self, other: object) -> bool:
        """Check equality with another SingleSenderAuthenticator.

        Args:
            other: Object to compare with

        Returns:
            True if sender authenticators are equal, False otherwise
        """
        if not isinstance(other, SingleSenderAuthenticator):
            return NotImplemented
        return self.sender == other.sender

    def __str__(self) -> str:
        """String representation of the single sender authenticator.

        Returns:
            Human-readable string showing sender details
        """
        return f"SingleSender: {self.sender}"

    def verify(self, data: bytes) -> bool:
        """Verify the sender's signature against the provided data.

        This delegates verification to the underlying account authenticator,
        which in turn delegates to the specific signature implementation.

        Args:
            data: The data that was signed (typically a transaction hash)

        Returns:
            True if the signature is valid, False otherwise
        """
        return self.sender.verify(data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SingleSenderAuthenticator:
        """Deserialize a SingleSenderAuthenticator from BCS bytes.

        Args:
            deserializer: The BCS deserializer containing the authenticator data

        Returns:
            A SingleSenderAuthenticator instance

        Raises:
            DeserializationError: If the data is malformed or incomplete
        """
        sender = deserializer.struct(AccountAuthenticator)
        return SingleSenderAuthenticator(sender)

    def serialize(self, serializer: Serializer):
        """Serialize this single sender authenticator using BCS serialization.

        This serializes the underlying account authenticator which contains
        the specific signature scheme and signature data.

        Args:
            serializer: The BCS serializer to write to
        """
        serializer.struct(self.sender)


class SingleKeyAuthenticator:
    """Modern single-key authenticator with algorithm flexibility.

    This is the preferred single-key authentication format in newer Aptos versions.
    Unlike Ed25519Authenticator which is tied to a specific algorithm, SingleKeyAuthenticator
    can work with multiple signature algorithms through the asymmetric_crypto_wrapper.

    The authenticator uses the AIP-80 compliant key format, providing a unified interface
    for different cryptographic algorithms while maintaining compatibility with existing
    Aptos authentication infrastructure.

    Supported Algorithms:
    - Ed25519: Fast and secure elliptic curve signatures
    - Secp256k1: Bitcoin-compatible signatures
    - Future algorithms: Extensible through the wrapper interface

    Features:
    - Algorithm-agnostic interface
    - AIP-80 compliant key formatting
    - Efficient serialization and verification
    - Forward compatibility with new signature schemes
    - Consistent API across different algorithms

    Examples:
        Create with Ed25519::

            from aptos_sdk import ed25519
            from aptos_sdk.authenticator import SingleKeyAuthenticator

            # Generate Ed25519 key pair
            private_key = ed25519.PrivateKey.random()
            public_key = private_key.public_key()

            # Sign transaction hash
            tx_hash = b"transaction_hash_bytes"
            signature = private_key.sign(tx_hash)

            # Create single key authenticator
            auth = SingleKeyAuthenticator(public_key, signature)

            # Verify signature
            is_valid = auth.verify(tx_hash)

        Create with secp256k1::

            from aptos_sdk import secp256k1_ecdsa

            # Generate secp256k1 key pair
            private_key = secp256k1_ecdsa.PrivateKey.random()
            public_key = private_key.public_key()
            signature = private_key.sign(tx_hash)

            # Create authenticator (same interface)
            auth = SingleKeyAuthenticator(public_key, signature)

        Serialization::

            # Serialize for blockchain submission
            serializer = Serializer()
            auth.serialize(serializer)
            auth_bytes = serializer.output()

            # Deserialize from bytes
            deserializer = Deserializer(auth_bytes)
            restored_auth = SingleKeyAuthenticator.deserialize(deserializer)

    Attributes:
        public_key (asymmetric_crypto_wrapper.PublicKey): Wrapped public key with algorithm info
        signature (asymmetric_crypto_wrapper.Signature): Wrapped signature with algorithm info

    Note:
        The wrapper classes automatically handle algorithm detection and provide
        a unified interface for verification. This authenticator is preferred over
        algorithm-specific authenticators for new applications.
    """

    public_key: asymmetric_crypto_wrapper.PublicKey
    signature: asymmetric_crypto_wrapper.Signature

    def __init__(
        self,
        public_key: asymmetric_crypto.PublicKey,
        signature: asymmetric_crypto.Signature,
    ):
        """Initialize a single key authenticator with algorithm detection.

        The constructor automatically wraps the provided public key and signature
        with the appropriate wrapper classes that handle algorithm-specific details.

        Args:
            public_key: The public key (Ed25519, secp256k1, etc.)
            signature: The signature corresponding to the public key

        Examples:
            With raw Ed25519 objects::

                ed25519_key = ed25519.PublicKey.from_str("...")
                ed25519_sig = ed25519.Signature.from_str("...")
                auth = SingleKeyAuthenticator(ed25519_key, ed25519_sig)

            With pre-wrapped objects::

                wrapped_key = asymmetric_crypto_wrapper.PublicKey(ed25519_key)
                wrapped_sig = asymmetric_crypto_wrapper.Signature(ed25519_sig)
                auth = SingleKeyAuthenticator(wrapped_key, wrapped_sig)
        """
        if isinstance(public_key, asymmetric_crypto_wrapper.PublicKey):
            self.public_key = public_key
        else:
            self.public_key = asymmetric_crypto_wrapper.PublicKey(public_key)

        if isinstance(signature, asymmetric_crypto_wrapper.Signature):
            self.signature = signature
        else:
            self.signature = asymmetric_crypto_wrapper.Signature(signature)

    def __eq__(self, other: object) -> bool:
        """Check equality with another SingleKeyAuthenticator.

        Args:
            other: Object to compare with

        Returns:
            True if public keys and signatures are equal, False otherwise
        """
        if not isinstance(other, SingleKeyAuthenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __str__(self) -> str:
        """String representation of the single key authenticator.

        Returns:
            Human-readable string showing key and signature details
        """
        return f"SingleKey - PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """Verify the signature against the provided data.

        This method delegates to the wrapped public key's verification method,
        which automatically handles the algorithm-specific verification logic.

        Args:
            data: The data that was signed (typically a transaction hash)

        Returns:
            True if the signature is valid, False otherwise
        """
        return self.public_key.verify(data, self.signature.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> SingleKeyAuthenticator:
        """Deserialize a SingleKeyAuthenticator from BCS bytes.

        Args:
            deserializer: The BCS deserializer containing the authenticator data

        Returns:
            A SingleKeyAuthenticator instance with the deserialized key and signature

        Raises:
            DeserializationError: If the data is malformed or incomplete
        """
        public_key = deserializer.struct(asymmetric_crypto_wrapper.PublicKey)
        signature = deserializer.struct(asymmetric_crypto_wrapper.Signature)
        return SingleKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer):
        """Serialize this single key authenticator using BCS serialization.

        This serializes the wrapped public key and signature, including their
        algorithm identifiers as specified in AIP-80.

        Args:
            serializer: The BCS serializer to write to
        """
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class MultiKeyAuthenticator:
    """Modern multi-key authenticator with algorithm flexibility and threshold signatures.

    This is the preferred multi-signature authentication format in newer Aptos versions.
    Unlike MultiEd25519Authenticator which is tied to Ed25519, MultiKeyAuthenticator
    can work with mixed signature algorithms through the asymmetric_crypto_wrapper,
    allowing for heterogeneous multi-signature schemes.

    The authenticator uses the AIP-80 compliant key format and supports threshold
    signatures where N-of-M keys must sign to authorize a transaction. This provides
    flexible multi-party authentication with algorithm diversity.

    Supported Algorithm Combinations:
    - Mixed Ed25519 and secp256k1 keys in the same multi-signature
    - Pure Ed25519 multi-signatures (recommended for performance)
    - Pure secp256k1 multi-signatures (for Bitcoin compatibility)
    - Future algorithm combinations through the wrapper interface

    Features:
    - Algorithm-agnostic multi-signature interface
    - Heterogeneous key mixing (Ed25519 + secp256k1 + future algorithms)
    - N-of-M threshold signatures with configurable thresholds
    - AIP-80 compliant key formatting
    - Efficient serialization and verification
    - Forward compatibility with new signature schemes
    - Superior to legacy MultiEd25519Authenticator

    Use Cases:
    - Multi-party custody with different cryptographic preferences
    - Governance scenarios requiring diverse signature algorithms
    - Cross-chain compatibility requiring secp256k1 support
    - Organizations with mixed cryptographic infrastructure
    - Future-proofing against algorithm deprecation

    Examples:
        Mixed Ed25519 and secp256k1 2-of-3::

            from aptos_sdk import ed25519, secp256k1_ecdsa
            from aptos_sdk import asymmetric_crypto_wrapper
            from aptos_sdk.authenticator import MultiKeyAuthenticator

            # Generate mixed key pairs
            ed25519_key1 = ed25519.PrivateKey.random()
            ed25519_key2 = ed25519.PrivateKey.random()
            secp256k1_key = secp256k1_ecdsa.PrivateKey.random()

            # Create public key list
            public_keys = [
                ed25519_key1.public_key(),
                ed25519_key2.public_key(),
                secp256k1_key.public_key()
            ]

            # Create multi-public key with threshold 2
            multi_pub_key = asymmetric_crypto_wrapper.MultiPublicKey(public_keys, threshold=2)

            # Sign with keys 0 and 2 (Ed25519 + secp256k1)
            tx_hash = b"transaction_hash"
            signatures = [
                (0, ed25519_key1.sign(tx_hash)),
                (2, secp256k1_key.sign(tx_hash))
            ]
            multi_signature = asymmetric_crypto_wrapper.MultiSignature(signatures)

            # Create authenticator
            auth = MultiKeyAuthenticator(multi_pub_key, multi_signature)

            # Verify the mixed multi-signature
            is_valid = auth.verify(tx_hash)

        Pure Ed25519 3-of-5 (recommended for performance)::

            # Generate Ed25519 keys only
            ed25519_keys = [ed25519.PrivateKey.random() for _ in range(5)]
            public_keys = [key.public_key() for key in ed25519_keys]

            # Create 3-of-5 threshold
            multi_pub_key = asymmetric_crypto_wrapper.MultiPublicKey(public_keys, threshold=3)

            # Sign with keys 1, 2, and 4
            signatures = [
                (1, ed25519_keys[1].sign(tx_hash)),
                (2, ed25519_keys[2].sign(tx_hash)),
                (4, ed25519_keys[4].sign(tx_hash))
            ]
            multi_signature = asymmetric_crypto_wrapper.MultiSignature(signatures)
            auth = MultiKeyAuthenticator(multi_pub_key, multi_signature)

        Integration with SingleSenderAuthenticator::

            # Wrap in account and transaction authenticators
            account_auth = AccountAuthenticator(multi_key_auth)
            single_sender = SingleSenderAuthenticator(account_auth)
            tx_auth = Authenticator(single_sender)

            # Submit to blockchain
            serializer = Serializer()
            tx_auth.serialize(serializer)
            auth_bytes = serializer.output()

    Attributes:
        public_key (asymmetric_crypto_wrapper.MultiPublicKey): Multi-public key with mixed algorithms
        signature (asymmetric_crypto_wrapper.MultiSignature): Multi-signature with threshold validation

    Security Considerations:
        - Mixed algorithms provide defense against algorithm-specific attacks
        - Threshold must be set appropriately (not too low, not too high)
        - Each signature algorithm contributes its own security properties
        - Key management complexity increases with algorithm diversity

    Performance Notes:
        - Pure Ed25519 multi-signatures are fastest
        - Mixed algorithms have slight verification overhead
        - Serialization size increases with algorithm diversity
        - Network latency impact depends on signature sizes

    Note:
        This is the modern replacement for MultiEd25519Authenticator.
        New applications should prefer this format for its flexibility
        and future compatibility.
    """

    public_key: asymmetric_crypto_wrapper.MultiPublicKey
    signature: asymmetric_crypto_wrapper.MultiSignature

    def __init__(
        self,
        public_key: asymmetric_crypto_wrapper.MultiPublicKey,
        signature: asymmetric_crypto_wrapper.MultiSignature,
    ):
        """Initialize a multi-key authenticator with mixed algorithms.

        Args:
            public_key: Multi-public key containing keys from different algorithms
            signature: Multi-signature with the required threshold signatures

        Examples:
            Basic mixed algorithm initialization::

                # Assume we have ed25519 and secp256k1 keys
                mixed_keys = [ed25519_pub, secp256k1_pub, another_ed25519_pub]
                multi_pub_key = asymmetric_crypto_wrapper.MultiPublicKey(mixed_keys, threshold=2)

                # Signatures from threshold keys (indices 0 and 2)
                signatures = [(0, ed25519_sig), (2, another_ed25519_sig)]
                multi_sig = asymmetric_crypto_wrapper.MultiSignature(signatures)

                auth = MultiKeyAuthenticator(multi_pub_key, multi_sig)
        """
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other: object) -> bool:
        """Check equality with another MultiKeyAuthenticator.

        Args:
            other: Object to compare with

        Returns:
            True if public keys and signatures are equal, False otherwise
        """
        if not isinstance(other, MultiKeyAuthenticator):
            return NotImplemented
        return self.public_key == other.public_key and self.signature == other.signature

    def __str__(self) -> str:
        """String representation of the multi-key authenticator.

        Returns:
            Human-readable string showing multi-key details
        """
        return f"MultiKey - PublicKey: {self.public_key}, Signature: {self.signature}"

    def verify(self, data: bytes) -> bool:
        """Verify the multi-signature against the provided data.

        This method validates that:
        1. The threshold number of signatures is provided
        2. Each signature is from a different key in the multi-public key
        3. Each signature is cryptographically valid for its algorithm
        4. Mixed algorithm signatures are handled correctly

        Args:
            data: The data that was signed (typically a transaction hash)

        Returns:
            True if the multi-signature meets the threshold and all signatures are valid
        """
        return self.public_key.verify(data, self.signature)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> MultiKeyAuthenticator:
        """Deserialize a MultiKeyAuthenticator from BCS bytes.

        Args:
            deserializer: The BCS deserializer containing the authenticator data

        Returns:
            A MultiKeyAuthenticator instance with mixed algorithm support

        Raises:
            DeserializationError: If the data is malformed or incomplete
        """
        public_key = deserializer.struct(asymmetric_crypto_wrapper.MultiPublicKey)
        signature = deserializer.struct(asymmetric_crypto_wrapper.MultiSignature)
        return MultiKeyAuthenticator(public_key, signature)

    def serialize(self, serializer: Serializer):
        """Serialize this multi-key authenticator using BCS serialization.

        This serializes the multi-public key (including all public keys with
        their algorithm identifiers and the threshold) and the multi-signature
        (including signature indices and algorithm-specific signature bytes).

        Args:
            serializer: The BCS serializer to write to
        """
        serializer.struct(self.public_key)
        serializer.struct(self.signature)


class Test(unittest.TestCase):
    """Unit tests for authenticator functionality.

    Tests serialization, deserialization, and verification of various authenticator types,
    including mixed-algorithm multi-key authentication scenarios.
    """

    def test_multi_key_auth(self):
        expected_output = bytes.fromhex(
            "040303002020fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a1440141049b8327d929a0e45285c04d19c9fffbee065c266b701972922d807228120e43f34ad68ac77f6ec0205fe39f7c5b6055dad973a03464a3a743302de0feaf6ec6d90141049b8327d929a0e45285c04d19c9fffbee065c266b701972922d807228120e43f34ad68ac77f6ec0205fe39f7c5b6055dad973a03464a3a743302de0feaf6ec6d902020040a9839b56be99b48c285ec252cf9bf779e42d3b62eb8664c31b18c1fdb29b574b1bfde0b89aedddb9fb8304ca5913c9feefea75d332d8f72ac3ab4598a884ea0801402bd50683abe6332a496121f8ec7db7be351f49b0087fa0dfb258c469822bd52e59fc9344944a1f338b0f0a61c7173453e0cd09cf961e45cb9396808fa67eeef301c0"
        )
        der = Deserializer(expected_output)
        der.struct(Authenticator)

        pk0 = ed25519.PublicKey.from_str(
            "20FDBAC9B10B7587BBA7B5BC163BCE69E796D71E4ED44C10FCB4488689F7A144"
        )
        pk1 = secp256k1_ecdsa.PublicKey.from_str(
            "049B8327D929A0E45285C04D19C9FFFBEE065C266B701972922D807228120E43F34AD68AC77F6EC0205FE39F7C5B6055DAD973A03464A3A743302DE0FEAF6EC6D9"
        )
        pk2 = secp256k1_ecdsa.PublicKey.from_str(
            "049B8327D929A0E45285C04D19C9FFFBEE065C266B701972922D807228120E43F34AD68AC77F6EC0205FE39F7C5B6055DAD973A03464A3A743302DE0FEAF6EC6D9"
        )
        sig0 = ed25519.Signature.from_str(
            "a9839b56be99b48c285ec252cf9bf779e42d3b62eb8664c31b18c1fdb29b574b1bfde0b89aedddb9fb8304ca5913c9feefea75d332d8f72ac3ab4598a884ea08"
        )
        sig1 = secp256k1_ecdsa.Signature.from_str(
            "2bd50683abe6332a496121f8ec7db7be351f49b0087fa0dfb258c469822bd52e59fc9344944a1f338b0f0a61c7173453e0cd09cf961e45cb9396808fa67eeef3"
        )

        multi_key = asymmetric_crypto_wrapper.MultiPublicKey([pk0, pk1, pk2], 2)
        multi_sig = asymmetric_crypto_wrapper.MultiSignature([(0, sig0), (1, sig1)])
        multi_key_auth = MultiKeyAuthenticator(multi_key, multi_sig)
        single_sender_auth = SingleSenderAuthenticator(
            AccountAuthenticator(multi_key_auth)
        )
        txn_auth = Authenticator(single_sender_auth)
        ser = Serializer()
        txn_auth.serialize(ser)
        self.assertEqual(expected_output, ser.output())
