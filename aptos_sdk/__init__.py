# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Aptos Python SDK — async-first SDK for the Aptos blockchain.

This is the public API surface.  Import the most commonly used types
directly from ``aptos_sdk``::

    from aptos_sdk import (
        Account,
        AccountAddress,
        RestClient,
        FaucetClient,
        Network,
    )
"""

__version__ = "0.12.0"

# Core types
from .account import Account
from .account_address import AccountAddress, AuthKeyScheme
from .asymmetric_crypto import PrivateKeyVariant
from .async_client import (
    AccountInfo,
    FaucetClient,
    GasEstimate,
    LedgerInfo,
    Resource,
    RestClient,
    Transaction,
)
from .authenticator import AccountAuthenticator, TransactionAuthenticator
from .bcs import Deserializer, Serializer
from .chain_id import ChainId
from .crypto_wrapper import (
    AnyPublicKey,
    AnySignature,
    MultiKeyPublicKey,
    MultiKeySignature,
)
from .ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519Signature,
    MultiEd25519PublicKey,
    MultiEd25519Signature,
)
from .errors import (
    ApiError,
    AptosError,
    AptosTimeoutError,
    BadRequestError,
    BcsError,
    ConflictError,
    CryptoError,
    InsufficientBalanceError,
    InternalServerError,
    InvalidAddressError,
    InvalidInputError,
    InvalidStateError,
    NetworkError,
    NotFoundError,
    ParseError,
    RateLimitedError,
    SerializationError,
    TransactionSubmissionError,
    VmError,
)
from .hashing import HashPrefix, sha3_256
from .network import Network, NetworkConfig
from .retry import RetryConfig
from .secp256k1_ecdsa import Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature
from .transaction_builder import TransactionBuilder
from .transactions import (
    EntryFunction,
    FeePayerRawTransaction,
    ModuleId,
    MultiAgentRawTransaction,
    RawTransaction,
    Script,
    SignedTransaction,
    TransactionArgument,
    TransactionPayload,
)
from .type_tag import StructTag, TypeTag

__all__ = [
    # Core types
    "AccountAddress",
    "AuthKeyScheme",
    "ChainId",
    "StructTag",
    "TypeTag",
    # Errors
    "AptosError",
    "AptosTimeoutError",
    "ApiError",
    "BadRequestError",
    "BcsError",
    "ConflictError",
    "CryptoError",
    "InsufficientBalanceError",
    "InternalServerError",
    "InvalidAddressError",
    "InvalidInputError",
    "InvalidStateError",
    "NetworkError",
    "NotFoundError",
    "ParseError",
    "RateLimitedError",
    "SerializationError",
    "TransactionSubmissionError",
    "VmError",
    # BCS
    "Deserializer",
    "Serializer",
    # Hashing
    "HashPrefix",
    "sha3_256",
    # Crypto
    "PrivateKeyVariant",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "MultiEd25519PublicKey",
    "MultiEd25519Signature",
    "Secp256k1PrivateKey",
    "Secp256k1PublicKey",
    "Secp256k1Signature",
    "AnyPublicKey",
    "AnySignature",
    "MultiKeyPublicKey",
    "MultiKeySignature",
    # Accounts
    "Account",
    # Transactions
    "EntryFunction",
    "FeePayerRawTransaction",
    "ModuleId",
    "MultiAgentRawTransaction",
    "RawTransaction",
    "Script",
    "SignedTransaction",
    "TransactionArgument",
    "TransactionPayload",
    "AccountAuthenticator",
    "TransactionAuthenticator",
    "TransactionBuilder",
    # Network + Clients
    "Network",
    "NetworkConfig",
    "FaucetClient",
    "RestClient",
    "AccountInfo",
    "GasEstimate",
    "LedgerInfo",
    "Resource",
    "Transaction",
    "RetryConfig",
]
