# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Python SDK

A Python library for interacting with the Aptos blockchain.

Quick Start:
    >>> import asyncio
    >>> from aptos_sdk import Account, RestClient, FaucetClient
    >>>
    >>> async def main():
    ...     async with RestClient("https://fullnode.testnet.aptoslabs.com/v1") as client:
    ...         account = Account.generate()
    ...         faucet = FaucetClient("https://faucet.testnet.aptoslabs.com", client)
    ...         await faucet.fund_account(account.address(), 100_000_000)
    ...         balance = await client.account_balance(account.address())
    ...         print(f"Balance: {balance}")
    >>>
    >>> asyncio.run(main())

For more examples, see the examples/ directory.
"""

__version__ = "0.12.0"

# =============================================================================
# Core
# =============================================================================
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.type_tag import StructTag, TypeTag

# =============================================================================
# Cryptography
# =============================================================================
from aptos_sdk.ed25519 import (
    MultiPublicKey as Ed25519MultiPublicKey,
    MultiSignature as Ed25519MultiSignature,
    PrivateKey as Ed25519PrivateKey,
    PublicKey as Ed25519PublicKey,
    Signature as Ed25519Signature,
)
from aptos_sdk.secp256k1_ecdsa import (
    PrivateKey as Secp256k1PrivateKey,
    PublicKey as Secp256k1PublicKey,
    Signature as Secp256k1Signature,
)
from aptos_sdk.asymmetric_crypto import PrivateKey, PublicKey, Signature
from aptos_sdk.asymmetric_crypto_wrapper import (
    AnyPublicKey,
    AnySignature,
    MultiKey,
    MultiKeySignature,
)

# =============================================================================
# Account
# =============================================================================
from aptos_sdk.account import Account

# =============================================================================
# Transactions
# =============================================================================
from aptos_sdk.transactions import (
    EntryFunction,
    ModuleId,
    MultiAgentRawTransaction,
    RawTransaction,
    RawTransactionWithData,
    Script,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk.authenticator import (
    AccountAuthenticator,
    Authenticator,
    FeePayerAuthenticator,
    MultiAgentAuthenticator,
)

# =============================================================================
# Client
# =============================================================================
from aptos_sdk.async_client import (
    ClientConfig,
    FaucetClient,
    IndexerClient,
    RestClient,
)

# =============================================================================
# Tokens
# =============================================================================
from aptos_sdk.aptos_token_client import (
    AptosTokenClient,
    Object,
    Property,
    PropertyMap,
    ReadObject,
)

# =============================================================================
# Utilities
# =============================================================================
from aptos_sdk.account_sequence_number import AccountSequenceNumber
from aptos_sdk.transaction_worker import TransactionWorker
from aptos_sdk.package_publisher import PackagePublisher

# =============================================================================
# Network Configuration
# =============================================================================
from aptos_sdk.network import (
    Network,
    NetworkConfig,
    MAINNET_URL,
    TESTNET_URL,
    DEVNET_URL,
)

# =============================================================================
# ANS (Aptos Names Service) & Fungible Assets
# =============================================================================
from aptos_sdk import ans
from aptos_sdk import fungible_asset as fa
from aptos_sdk.fungible_asset import FungibleAssetMetadata

# =============================================================================
# Errors
# =============================================================================
from aptos_sdk.errors import (
    AccountNotFound,
    AddressError,
    ApiError,
    AptosError,
    BcsError,
    ConfigurationError,
    CryptoError,
    DeserializationError,
    InvalidAddress,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidTypeTag,
    ModuleNotFound,
    ResourceNotFound,
    SerializationError,
    SimulationError,
    TransactionError,
    TransactionFailed,
    TransactionTimeout,
)

# Legacy error imports for backward compatibility
from aptos_sdk.async_client import (
    ApiError as _LegacyApiError,
    AccountNotFound as _LegacyAccountNotFound,
    ResourceNotFound as _LegacyResourceNotFound,
)

__all__ = [
    # Version
    "__version__",
    # Core
    "AccountAddress",
    "Deserializer",
    "Serializer",
    "StructTag",
    "TypeTag",
    # Crypto - Ed25519
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "Ed25519MultiPublicKey",
    "Ed25519MultiSignature",
    # Crypto - Secp256k1
    "Secp256k1PrivateKey",
    "Secp256k1PublicKey",
    "Secp256k1Signature",
    # Crypto - Abstract
    "PrivateKey",
    "PublicKey",
    "Signature",
    # Crypto - MultiKey
    "AnyPublicKey",
    "AnySignature",
    "MultiKey",
    "MultiKeySignature",
    # Account
    "Account",
    # Transactions
    "EntryFunction",
    "ModuleId",
    "MultiAgentRawTransaction",
    "RawTransaction",
    "RawTransactionWithData",
    "Script",
    "SignedTransaction",
    "TransactionArgument",
    "TransactionPayload",
    # Authenticators
    "AccountAuthenticator",
    "Authenticator",
    "FeePayerAuthenticator",
    "MultiAgentAuthenticator",
    # Client
    "ClientConfig",
    "FaucetClient",
    "IndexerClient",
    "RestClient",
    # Tokens
    "AptosTokenClient",
    "Object",
    "Property",
    "PropertyMap",
    "ReadObject",
    # Utilities
    "AccountSequenceNumber",
    "TransactionWorker",
    "PackagePublisher",
    # Network
    "Network",
    "NetworkConfig",
    "MAINNET_URL",
    "TESTNET_URL",
    "DEVNET_URL",
    # ANS & Fungible Assets
    "ans",
    "fa",
    "FungibleAssetMetadata",
    # Errors
    "AccountNotFound",
    "AddressError",
    "ApiError",
    "AptosError",
    "BcsError",
    "ConfigurationError",
    "CryptoError",
    "DeserializationError",
    "InvalidAddress",
    "InvalidPrivateKey",
    "InvalidPublicKey",
    "InvalidSignature",
    "InvalidTypeTag",
    "ModuleNotFound",
    "ResourceNotFound",
    "SerializationError",
    "SimulationError",
    "TransactionError",
    "TransactionFailed",
    "TransactionTimeout",
]