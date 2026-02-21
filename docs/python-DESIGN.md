# Aptos Python SDK - Design Document

## Ground-Up Rewrite from Aptos SDK Specification v1.0.0

**Target**: Tier 2 (P0 + P1) Compliance
**Python**: 3.10+
**Status**: Complete
**Date**: 2026-02-21

---

## 1. Executive Summary

This document describes the ground-up rewrite of the Aptos Python SDK to fully conform to the
[Aptos SDK Specification v1.0.0](https://github.com/aptos-labs/aptos-sdk-specs/tree/main/specifications).
The rewrite achieves **Tier 2 compliance** (all P0 and P1 requirements), is **async-only**, uses
**httpx** for HTTP/2, **Poetry** for packaging, and **plain dataclasses** with a protocol-based BCS
serialization layer.

### Implementation Statistics

| Metric                | Value           |
|-----------------------|-----------------|
| Total source lines    | ~11,500         |
| Number of modules     | 19              |
| Unit tests            | 1,060           |
| Integration tests     | 22              |
| Test coverage         | 96%             |
| Spec compliance       | Tier 2 (P0+P1) |

### Key Decisions

| Decision           | Choice                           | Rationale                                      |
|--------------------|----------------------------------|-------------------------------------------------|
| Async model        | Async-only                       | Simpler internals, modern Python patterns       |
| HTTP client        | httpx (HTTP/2)                   | Mature, async-native, well-typed                |
| Build system       | Poetry                           | Familiar, handles deps + packaging              |
| Min Python         | 3.10+                            | Union types `X \| Y`, match/case, 3.9 is EOL    |
| Error hierarchy    | Spec-aligned categorical         | Full spec compliance, rich context              |
| BCS approach       | Dataclass + Serializable protocol| Type-safe, clean, extensible                    |
| Data models        | Plain dataclasses                | Lightweight, no extra deps, full control        |
| Location           | Replace `aptos_sdk/` in-place    | Same package name, seamless upgrades            |

---

## 2. Architecture Overview

### 2.1 Module Dependency Graph

```
                    ┌─────────────────────┐
                    │    aptos_sdk.client  │  ← REST / Faucet
                    │  (async_client.py)   │
                    └──────────┬──────────┘
                               │ uses
                    ┌──────────▼──────────┐
                    │ aptos_sdk.transaction│  ← RawTransaction, Builder,
                    │  (transactions.py,   │    Signing, SignedTransaction
                    │   transaction_       │
                    │   builder.py)        │
                    └──────────┬──────────┘
                               │ uses
              ┌────────────────┼────────────────┐
              │                │                │
   ┌──────────▼───┐  ┌────────▼────────┐  ┌────▼──────────┐
   │ aptos_sdk.   │  │ aptos_sdk.      │  │ aptos_sdk.    │
   │ account      │  │ authenticator   │  │ type_tag      │
   │ (account.py) │  │(authenticator.py│) │ (type_tag.py) │
   └──────┬───────┘  └───────┬────────┘  └───────────────┘
          │                  │
   ┌──────▼──────────────────▼────────┐
   │        aptos_sdk.crypto          │  ← Ed25519, Secp256k1,
   │ (ed25519.py, secp256k1_ecdsa.py, │    Hashing, Key Derivation
   │  asymmetric_crypto.py,           │
   │  crypto_wrapper.py)              │
   └──────────────┬───────────────────┘
                  │ uses
   ┌──────────────▼───────────────────┐
   │         aptos_sdk.bcs            │  ← Serializer, Deserializer,
   │         (bcs.py)                 │    Serializable protocol
   └──────────────┬───────────────────┘
                  │ uses
   ┌──────────────▼───────────────────┐
   │      aptos_sdk.core_types        │  ← AccountAddress, ChainId
   │   (account_address.py,           │
   │    chain_id.py)                  │
   └──────────────────────────────────┘

   ┌──────────────────────────────────┐
   │      aptos_sdk.errors            │  ← AptosError hierarchy
   │      (errors.py)                 │    (used by ALL modules)
   └──────────────────────────────────┘

   ┌──────────────────────────────────┐
   │      aptos_sdk.network           │  ← NetworkConfig, Network
   │      (network.py)                │    constants
   └──────────────────────────────────┘

   ┌──────────────────────────────────┐
   │      aptos_sdk.retry             │  ← RetryConfig, with_retry
   │      (retry.py)                  │
   └──────────────────────────────────┘
```

### 2.2 Package Layout

```
aptos_sdk/
├── __init__.py              # Public API re-exports (162 lines)
├── errors.py                # Error hierarchy (spec 08) — 751 lines
├── bcs.py                   # BCS Serializer/Deserializer (spec 02) — 604 lines
├── account_address.py       # AccountAddress, constants (spec 01) — 395 lines
├── type_tag.py              # TypeTag, StructTag, parsing (spec 01) — 886 lines
├── chain_id.py              # ChainId (spec 01) — 88 lines
├── asymmetric_crypto.py     # PrivateKey/PublicKey/Signature protocols (spec 03) — 378 lines
├── ed25519.py               # Ed25519 + MultiEd25519 implementation (spec 03) — 850 lines
├── secp256k1_ecdsa.py       # Secp256k1 ECDSA implementation (spec 03) — 894 lines
├── crypto_wrapper.py        # SingleKey/MultiKey wrappers (spec 03) — 773 lines
├── hashing.py               # SHA3-256, SHA2-256, domain-separated (spec 03) — 144 lines
├── account.py               # Account types (spec 04) — 379 lines
├── mnemonic.py              # BIP-39/BIP-44 key derivation (spec 04 P1) — 266 lines
├── authenticator.py         # Transaction authenticators (spec 05/07) — 881 lines
├── transactions.py          # RawTransaction, payloads, signing (spec 05) — 1,239 lines
├── transaction_builder.py   # TransactionBuilder pattern (spec 05 P1) — 444 lines
├── network.py               # Network config (spec 06) — 171 lines
├── async_client.py          # RestClient, FaucetClient (spec 06) — 1,957 lines
└── retry.py                 # Retry strategy (spec 06 P1) — 287 lines
```

Total: **19 modules, ~11,550 lines of source code**

---

## 3. Module Designs

### 3.1 Error Handling (`errors.py`) — Spec 08

The error module is foundational; all other modules import from it.

```
AptosError (base)
├── ParseError
│   ├── InvalidAddressError
│   ├── InvalidHexError
│   ├── InvalidLengthError
│   ├── InvalidTypeTagError
│   ├── InvalidStructTagError
│   └── InvalidModuleIdError
├── CryptoError
│   ├── InvalidPrivateKeyError
│   ├── InvalidPublicKeyError
│   ├── InvalidSignatureError
│   ├── VerificationFailedError
│   └── KeyGenerationFailedError
├── SerializationError
│   ├── BcsError
│   └── JsonError
├── NetworkError
│   └── ConnectionFailedError
├── ApiError
│   ├── BadRequestError         (HTTP 400)
│   ├── NotFoundError           (HTTP 404)
│   ├── ConflictError           (HTTP 409)
│   ├── RateLimitedError        (HTTP 429)
│   ├── InternalServerError     (HTTP 5xx)
│   └── VmError
├── AptosTimeoutError
├── InvalidStateError
│   └── EphemeralKeyExpiredError
├── InvalidInputError
│   ├── MissingSenderError
│   ├── MissingSequenceNumberError
│   ├── MissingPayloadError
│   ├── MissingChainIdError
│   └── InvalidExpirationError
└── TransactionSubmissionError
    ├── SequenceNumberMismatchError
    ├── InsufficientBalanceError
    ├── TransactionExpiredError
    └── DuplicateTransactionError
```

Each error class carries:
- `category: ErrorCategory` — categorical discriminant (parse, crypto, api, etc.)
- `error_code: str | None` — machine-readable error code
- `cause: Exception | None` — chained exception for context

```python
class ErrorCategory(Enum):
    PARSE = "parse"
    CRYPTO = "crypto"
    SERIALIZATION = "serialization"
    NETWORK = "network"
    API = "api"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    INVALID_STATE = "invalid_state"
    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    INTERNAL = "internal"

class AptosError(Exception):
    """Base exception for all Aptos SDK errors."""
    category: ErrorCategory
    error_code: str | None

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        if cause is not None:
            self.__cause__ = cause
```

### 3.2 BCS Serialization (`bcs.py`) — Spec 02

Protocol-based approach with `Serializable` / `Deserializable` interfaces.

```python
from typing import Protocol, TypeVar, runtime_checkable

T = TypeVar("T")

@runtime_checkable
class Serializable(Protocol):
    def serialize(self, serializer: "Serializer") -> None: ...

@runtime_checkable
class Deserializable(Protocol):
    @staticmethod
    def deserialize(deserializer: "Deserializer") -> "Deserializable": ...
```

**Serializer API** (complete from spec):
```
Serializer:
  bool(value)           → 1 byte (0x00 or 0x01)
  u8(value)             → 1 byte
  u16(value)            → 2 bytes LE
  u32(value)            → 4 bytes LE
  u64(value)            → 8 bytes LE
  u128(value)           → 16 bytes LE
  u256(value)           → 32 bytes LE
  bytes(value)          → ULEB128(len) || bytes
  str(value)            → ULEB128(len) || UTF-8 bytes
  fixed_bytes(value)    → raw bytes (no length prefix)
  sequence(items)       → ULEB128(len) || items...
  option(value)         → 0x00 | 0x01 || value
  struct(value)         → value.serialize(self)
  variant_index(idx)    → ULEB128(idx)
  uleb128(value)        → variable-length encoding
  map(items)            → ULEB128(len) || (key,val)...
```

**Key changes from previous SDK:**
- Added `option()` method for `Option<T>` serialization
- Added proper `variant_index()` for enum serialization
- Added `map()` for sorted map serialization
- Added `u256()` support (32-byte LE)

### 3.3 Core Types (`account_address.py`, `chain_id.py`, `type_tag.py`) — Spec 01

#### AccountAddress

```python
@dataclass(frozen=True)
class AccountAddress(Serializable):
    data: bytes  # exactly 32 bytes

    # Constants
    ZERO: ClassVar[AccountAddress]
    ONE: ClassVar[AccountAddress]
    THREE: ClassVar[AccountAddress]
    FOUR: ClassVar[AccountAddress]

    # Construction
    @staticmethod
    def from_hex(hex_str: str) -> AccountAddress: ...
    @staticmethod
    def from_bytes(data: bytes) -> AccountAddress: ...
    @staticmethod
    def from_key(public_key: PublicKey) -> AccountAddress: ...

    # Formatting (AIP-40 compliant)
    def to_hex(self) -> str: ...          # full 0x + 64 chars
    def to_short_string(self) -> str: ... # 0x + trimmed leading zeros

    # Spec compliance
    def is_special(self) -> bool: ...     # <= 0xf (short-form eligible)

    # BCS
    def serialize(self, s: Serializer) -> None: ...
    @staticmethod
    def deserialize(d: Deserializer) -> AccountAddress: ...
```

**Key changes from previous SDK:**
- `frozen=True` dataclass (immutable)
- `from_hex()` replaces `from_str()` / `from_str_relaxed()` — single method, spec-compliant
- `ClassVar` constants instead of module-level variables
- Strict validation per spec (empty input → error, 65+ hex chars → error)
- AIP-40 compliant formatting

#### TypeTag

```python
class TypeTagVariant(Enum):
    BOOL = 0
    U8 = 1
    U64 = 2
    U128 = 3
    ADDRESS = 4
    SIGNER = 5
    VECTOR = 6
    STRUCT = 7
    U16 = 8
    U32 = 9
    U256 = 10

@dataclass(frozen=True)
class TypeTag(Serializable):
    value: TypeTagVariant | StructTag | tuple[TypeTag]  # tuple for Vector

    @staticmethod
    def from_str(s: str) -> TypeTag: ...  # Parse "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>"
```

**Key changes from previous SDK:**
- Full string parsing for nested generics (recursive descent parser)
- Proper `from_str()` with spec-compliant parsing rules
- Immutable frozen dataclass

### 3.4 Cryptography — Spec 03

#### Protocols (`asymmetric_crypto.py`)

```python
class PrivateKeyVariant(Enum):
    ED25519 = 0
    SECP256K1 = 1

class PrivateKey(Protocol):
    @staticmethod
    def generate() -> PrivateKey: ...
    @staticmethod
    def from_bytes(data: bytes) -> PrivateKey: ...
    @staticmethod
    def from_hex(hex_str: str) -> PrivateKey: ...
    def to_bytes(self) -> bytes: ...
    def to_hex(self) -> str: ...
    def public_key(self) -> PublicKey: ...
    def sign(self, message: bytes) -> Signature: ...

    # AIP-80 compliance (P1)
    def to_aip80(self) -> str: ...            # "ed25519-priv-0x..."
    @staticmethod
    def from_aip80(s: str) -> PrivateKey: ... # Parse AIP-80 format

    @staticmethod
    def variant() -> PrivateKeyVariant: ...
```

#### Ed25519 (`ed25519.py`) — P0

```
Ed25519PrivateKey  → 32 bytes (PyNaCl SigningKey)
Ed25519PublicKey   → 32 bytes (PyNaCl VerifyKey)
Ed25519Signature   → 64 bytes
MultiEd25519PublicKey  → N public keys + threshold
MultiEd25519Signature  → signatures + bitmap
```

- Auth key: `SHA3-256(public_key_bytes || 0x00)`
- AIP-80 format: `ed25519-priv-0x<hex>`

#### Secp256k1 ECDSA (`secp256k1_ecdsa.py`) — P1

```
Secp256k1PrivateKey  → 32 bytes (ecdsa library)
Secp256k1PublicKey   → 65 bytes (uncompressed)
Secp256k1Signature   → 64 bytes (r || s, low-S normalized)
```

- Auth key: `SHA3-256(public_key_bytes || 0x01)`
- Signing uses SHA3-256 as hash function
- AIP-80 format: `secp256k1-ecdsa-priv-0x<hex>`

#### Crypto Wrappers (`crypto_wrapper.py`) — Spec 03

```python
class AnyPublicKey(Serializable):
    """Wraps any public key variant with a type discriminant."""
    ...

class AnySignature(Serializable):
    """Wraps any signature variant with a type discriminant."""
    ...

class MultiKeyPublicKey(Serializable):
    """N-of-M multi-key, supporting mixed key types."""
    ...

class MultiKeySignature(Serializable):
    """Bitmap-indexed signatures for a MultiKeyPublicKey."""
    ...
```

#### Hashing (`hashing.py`)

```python
def sha3_256(data: bytes) -> bytes: ...
def sha2_256(data: bytes) -> bytes: ...

class HashPrefix:
    """Domain-separated hashing per spec."""
    RAW_TRANSACTION = sha3_256(b"APTOS::RawTransaction")
    RAW_TRANSACTION_WITH_DATA = sha3_256(b"APTOS::RawTransactionWithData")

    @staticmethod
    def prefix_for(domain: str) -> bytes:
        return sha3_256(f"APTOS::{domain}".encode())
```

**Key changes from previous SDK:**
- Dedicated hashing module (was inline in various files)
- All domain prefixes centralized
- `sha2_256` added for BIP-39 (P1)

### 3.5 Accounts (`account.py`, `mnemonic.py`) — Spec 04

```python
@dataclass
class Account:
    """An Aptos account with address and signing capability."""
    private_key: PrivateKey
    address: AccountAddress

    @staticmethod
    def generate(variant: PrivateKeyVariant = PrivateKeyVariant.ED25519) -> Account: ...

    @staticmethod
    def from_private_key(key: PrivateKey) -> Account: ...

    @staticmethod
    def from_mnemonic(mnemonic: str, path: str = "m/44'/637'/0'/0'/0'") -> Account: ...  # P1

    def sign(self, message: bytes) -> Signature: ...
    def sign_transaction(self, transaction) -> AccountAuthenticator: ...
    def public_key(self) -> PublicKey: ...
    def auth_key(self) -> bytes: ...
```

#### Mnemonic Support (`mnemonic.py`) — P1

```python
def generate_mnemonic(word_count: int = 12) -> str: ...
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes: ...
def derive_key(seed: bytes, path: str) -> bytes: ...
```

- BIP-39 wordlist (English)
- BIP-44 derivation path: `m/44'/637'/0'/0'/0'`
- HMAC-SHA512 for master key derivation
- Ed25519-specific child key derivation (SLIP-0010)
- Optional dependency: `mnemonic` package (via `poetry install -E mnemonic`)

### 3.6 Transactions (`transactions.py`, `transaction_builder.py`) — Spec 05

#### Core Transaction Types

```python
@dataclass
class RawTransaction(Serializable):
    sender: AccountAddress
    sequence_number: int
    payload: TransactionPayload
    max_gas_amount: int
    gas_unit_price: int
    expiration_timestamp_secs: int
    chain_id: ChainId

    def signing_message(self) -> bytes:
        """SHA3-256("APTOS::RawTransaction") || BCS(self)"""
        ...

    def sign(self, account: Account) -> SignedTransaction: ...

@dataclass
class MultiAgentRawTransaction(Serializable):
    raw_transaction: RawTransaction
    secondary_signers: list[AccountAddress]

@dataclass
class FeePayerRawTransaction(Serializable):
    raw_transaction: RawTransaction
    secondary_signers: list[AccountAddress]
    fee_payer: AccountAddress | None
```

#### TransactionPayload

```python
@dataclass
class TransactionPayload(Serializable):
    value: EntryFunction | Script | Multisig

    def serialize(self, s: Serializer) -> None:
        # Variant dispatch: Script=0, EntryFunction=2, Multisig=3
        ...
```

#### EntryFunction

```python
@dataclass
class EntryFunction(Serializable):
    module: ModuleId
    function: str
    type_args: list[TypeTag]
    args: list[bytes]  # Each arg is BCS-encoded

    @staticmethod
    def natural(
        module: str,       # "0x1::aptos_account"
        function: str,     # "transfer"
        type_args: list[TypeTag],
        args: list[TransactionArgument],
    ) -> EntryFunction: ...
```

#### TransactionBuilder — P1

```python
class TransactionBuilder:
    """Builder pattern for constructing transactions."""

    def sender(self, address: AccountAddress) -> TransactionBuilder: ...
    def payload(self, payload: TransactionPayload) -> TransactionBuilder: ...
    def max_gas_amount(self, amount: int) -> TransactionBuilder: ...
    def gas_unit_price(self, price: int) -> TransactionBuilder: ...
    def expiration(self, timestamp_secs: int) -> TransactionBuilder: ...
    def chain_id(self, chain_id: ChainId) -> TransactionBuilder: ...
    def sequence_number(self, seq: int) -> TransactionBuilder: ...

    def build(self) -> RawTransaction: ...
```

### 3.7 Authenticators (`authenticator.py`) — Spec 05/07

```
TransactionAuthenticator
├── Ed25519 (variant 0)
│   └── public_key + signature
├── MultiEd25519 (variant 1)
│   └── public_keys + signatures + bitmap
├── MultiAgent (variant 2)
│   └── sender_auth + secondary_addresses + secondary_auths
├── FeePayer (variant 3)
│   └── sender_auth + secondary_addresses + secondary_auths + fee_payer
└── SingleSender (variant 4)
    └── AccountAuthenticator

AccountAuthenticator
├── Ed25519 (variant 0)
├── MultiEd25519 (variant 1)
├── SingleKey (variant 2)
│   └── AnyPublicKey + AnySignature
└── MultiKey (variant 3)
    └── public_keys + signatures_bitmap
```

All authenticator variants support:
- BCS serialization/deserialization
- `verify(message: bytes) -> bool` for signature verification
- Display methods for debugging

### 3.8 API Clients (`async_client.py`, `network.py`, `retry.py`) — Spec 06

#### Network Configuration

```python
@dataclass(frozen=True)
class NetworkConfig:
    name: str
    fullnode_url: str
    faucet_url: str | None = None
    indexer_url: str | None = None
    chain_id: int | None = None

class Network:
    MAINNET = NetworkConfig(
        name="mainnet",
        fullnode_url="https://fullnode.mainnet.aptoslabs.com/v1",
        indexer_url="https://indexer.mainnet.aptoslabs.com/v1/graphql",
        chain_id=1,
    )
    TESTNET = NetworkConfig(
        name="testnet",
        fullnode_url="https://fullnode.testnet.aptoslabs.com/v1",
        faucet_url="https://faucet.testnet.aptoslabs.com",
        indexer_url="https://indexer.testnet.aptoslabs.com/v1/graphql",
        chain_id=2,
    )
    DEVNET = NetworkConfig(
        name="devnet",
        fullnode_url="https://fullnode.devnet.aptoslabs.com/v1",
        faucet_url="https://faucet.devnet.aptoslabs.com",
        indexer_url="https://indexer.devnet.aptoslabs.com/v1/graphql",
    )
    LOCALNET = NetworkConfig(
        name="localnet",
        fullnode_url="http://localhost:8080/v1",
        faucet_url="http://localhost:8081",
        chain_id=4,
    )
    LOCAL = LOCALNET  # Backward-compatibility alias

    @staticmethod
    def custom(fullnode_url: str, **kwargs) -> NetworkConfig: ...
```

#### RestClient

```python
class RestClient:
    """Async client for the Aptos Fullnode REST API."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None: ...

    async def __aenter__(self) -> RestClient: ...
    async def __aexit__(self, *args) -> None: ...
    async def close(self) -> None: ...

    # Ledger (P0)
    async def get_ledger_info(self) -> LedgerInfo: ...

    # Accounts (P0)
    async def get_account(self, address: AccountAddress) -> AccountInfo: ...
    async def get_account_resources(self, address: AccountAddress) -> list[Resource]: ...
    async def get_account_resource(self, address: AccountAddress, resource_type: str) -> Resource: ...
    async def account_balance(self, address: AccountAddress) -> int: ...
    async def account_sequence_number(self, address: AccountAddress) -> int: ...

    # Modules (P1)
    async def get_account_modules(self, address: AccountAddress) -> list[dict]: ...
    async def get_account_module(self, address: AccountAddress, module_name: str) -> dict: ...

    # Transactions (P0)
    async def get_transaction_by_hash(self, txn_hash: str) -> dict: ...
    async def get_transactions(self, *, start: int | None, limit: int | None) -> list[dict]: ...
    async def get_account_transactions(
        self, address: AccountAddress, *, start: int | None = None, limit: int | None = None
    ) -> list[dict]: ...

    # Transaction Building (P0)
    async def create_bcs_transaction(
        self, sender: Account, payload: TransactionPayload, sequence_number: int | None = None
    ) -> RawTransaction: ...
    async def create_bcs_signed_transaction(
        self, sender: Account, payload: TransactionPayload
    ) -> SignedTransaction: ...
    async def create_multi_agent_bcs_transaction(
        self, sender: Account, secondary_accounts: list[Account], payload: TransactionPayload
    ) -> SignedTransaction: ...

    # Submission (P0)
    async def submit_transaction(self, account: Account, payload: TransactionPayload) -> str: ...
    async def submit_bcs_transaction(self, signed_txn: SignedTransaction) -> str: ...
    async def wait_for_transaction(self, txn_hash: str, *, timeout_secs: int = 20) -> dict: ...

    # Convenience (P0)
    async def bcs_transfer(
        self, sender: Account, recipient: AccountAddress, amount: int
    ) -> str: ...
    async def transfer_coins(
        self, sender: Account, recipient: AccountAddress, amount: int,
        coin_type: str = "0x1::aptos_coin::AptosCoin"
    ) -> str: ...

    # View Functions (P1)
    async def view_function(
        self, module: str, function: str, type_args: list[str], args: list[str]
    ) -> list[Any]: ...
    async def view_bcs_payload(self, payload: EntryFunction) -> list[Any]: ...

    # Gas (P1)
    async def estimate_gas_price(self) -> GasEstimate: ...

    # Simulation (P1)
    async def simulate_transaction(
        self, raw_txn: RawTransaction, sender: Account, *, estimate_gas: bool = False
    ) -> dict: ...
    async def simulate_bcs_transaction(
        self, signed_txn: SignedTransaction, *, estimate_gas: bool = False
    ) -> dict: ...
```

#### FaucetClient

```python
class FaucetClient:
    """Client for the Aptos Faucet (testnet/devnet only)."""

    def __init__(
        self,
        base_url: str,
        rest_client: RestClient,
        *,
        auth_token: str | None = None,
    ) -> None: ...

    async def fund_account(self, address: AccountAddress | str, amount: int) -> list[str]: ...
```

#### Retry Strategy (`retry.py`) — P1

```python
@dataclass
class RetryConfig:
    max_retries: int = 3
    initial_backoff_ms: int = 200
    max_backoff_ms: int = 10000
    backoff_multiplier: float = 2.0
    retryable_status_codes: frozenset[int] = frozenset({429, 500, 502, 503})

async def with_retry(
    fn: Callable[..., Awaitable[T]],
    config: RetryConfig = RetryConfig(),
) -> T: ...
```

**Retryable conditions (from spec):**
- Network errors (connection failures)
- Timeout errors
- HTTP 429 (rate limited)
- HTTP 5xx (server errors)

**Non-retryable:**
- Parse errors, invalid input, not found, bad request (400)

### 3.9 Response Types

Structured dataclasses for API responses:

```python
@dataclass
class LedgerInfo:
    chain_id: int
    epoch: int
    ledger_version: int
    oldest_ledger_version: int
    ledger_timestamp: int
    block_height: int
    oldest_block_height: int

@dataclass
class AccountInfo:
    sequence_number: int
    authentication_key: str

@dataclass
class Resource:
    type: str
    data: dict[str, Any]

@dataclass
class GasEstimate:
    gas_estimate: int
    deprioritized_gas_estimate: int | None = None
    prioritized_gas_estimate: int | None = None

@dataclass
class Transaction:
    hash: str
    type: str
    version: int | None = None
    success: bool | None = None
    vm_status: str | None = None
    # ... additional fields
```

---

## 4. Differences from Previous SDK

### 4.1 New Capabilities

| Feature                    | Spec Section | Priority | Status in Old SDK |
|----------------------------|-------------|----------|-------------------|
| Spec-aligned error hierarchy| 08          | P0       | Flat exceptions   |
| TransactionBuilder pattern | 05          | P1       | Not present       |
| BIP-39/BIP-44 mnemonics   | 04          | P1       | Not present       |
| Retry strategy             | 06          | P1       | Not present       |
| Domain-separated hashing   | 03          | P0       | Inline/scattered  |
| TypeTag string parsing     | 01          | P0       | Partial           |
| Structured API responses   | 06          | P0       | Raw dicts         |
| View function support      | 06          | P1       | Partial           |
| Gas estimation             | 06          | P1       | Not present       |
| VM error code decoding     | 08          | P1       | Not present       |
| AIP-80 private key format  | 03          | P1       | Not present       |
| AIP-40 address formatting  | 01          | P0       | Partial           |
| MultiKey / AnyKey wrappers | 03          | P1       | Not present       |

### 4.2 Removed/Simplified

| Component                  | Reason                                    |
|----------------------------|-------------------------------------------|
| `aptos_token_client.py`   | Token-specific; can be layered on top     |
| `aptos_tokenv1_client.py` | Legacy v1 tokens, deprecated              |
| `transaction_worker.py`   | Can be built on top of core SDK           |
| `aptos_cli_wrapper.py`    | Separate concern from SDK core            |
| `cli.py`                  | Separate package/tool                     |
| `package_publisher.py`    | Can be layered on top with EntryFunction  |
| `ans.py`                  | Domain-specific, layer on top             |
| `fungible_asset.py`       | Domain-specific, layer on top             |
| `metadata.py`             | Unused                                    |
| `account_sequence_number.py` | Replaced by client methods             |
| `asymmetric_crypto_wrapper.py` | Replaced by `crypto_wrapper.py`      |

### 4.3 Breaking Changes

| Change                                 | Migration Path                              |
|----------------------------------------|---------------------------------------------|
| Python 3.10+ required                  | Upgrade Python (3.9 is EOL)                 |
| Error classes restructured             | Catch `AptosError` subtypes by category     |
| `AccountAddress.from_str()` → `from_hex()` | Rename calls                           |
| `EntryFunction.natural()` args change  | Args use `TransactionArgument` helper       |
| Network config restructured            | Use `Network.TESTNET` etc.                  |
| Response types are dataclasses         | Access `.field` instead of `["field"]`      |
| No sync API                            | Wrap with `asyncio.run()` if needed         |
| `TimeoutError` → `AptosTimeoutError`  | Avoids shadowing builtin `TimeoutError`     |

---

## 5. Dependency Changes

### 5.1 Production Dependencies

| Dependency          | Version    | Purpose                        | Change    |
|---------------------|-----------|--------------------------------|-----------|
| `httpx[http2]`      | ^0.28     | Async HTTP client              | Keep      |
| `PyNaCl`            | ^1.5      | Ed25519 cryptography           | Keep      |
| `ecdsa`             | ^0.19     | Secp256k1 ECDSA                | Keep      |
| `typing-extensions` | ^4.15     | Backport type features         | Keep      |
| `mnemonic`          | ^0.21     | BIP-39 wordlist + generation   | NEW (opt) |

The `mnemonic` package is an **optional dependency** — users install it via
`poetry install -E mnemonic` or `pip install aptos-sdk[mnemonic]`.

### 5.2 Removed Dependencies

| Dependency              | Reason                                    |
|-------------------------|-------------------------------------------|
| `python-graphql-client` | Replace with direct httpx GraphQL calls   |
| `tomli`                 | Only needed for CLI/package publisher      |

### 5.3 Dev Dependencies

| Dependency    | Version   | Purpose                    |
|---------------|-----------|----------------------------|
| `pytest`      | ^8.0      | Test framework             |
| `pytest-asyncio` | ^0.24 | Async test support         |
| `coverage`    | ^7.6      | Code coverage              |
| `black`       | ^24.10    | Code formatting            |
| `isort`       | ^5.13     | Import sorting             |
| `autoflake`   | ^2.3      | Remove unused imports      |
| `mypy`        | ^1.16     | Type checking              |
| `flake8`      | ^7.2      | Linting                    |

---

## 6. Testing Strategy

### 6.1 Test Structure

```
tests/
├── conftest.py                # Shared fixtures, mock httpx clients
├── test_errors.py             # Error hierarchy, categories, messages
├── test_bcs.py                # Serializer/Deserializer, all types, edge cases
├── test_account_address.py    # Parsing, formatting, constants
├── test_type_tag.py           # TypeTag/StructTag parsing, nested generics
├── test_chain_id.py           # ChainId serialization
├── test_ed25519.py            # Key gen, sign, verify, AIP-80, MultiEd25519
├── test_secp256k1.py          # Key gen, sign, verify, AIP-80
├── test_hashing.py            # SHA3-256, SHA2-256, domain prefixes
├── test_crypto_wrapper.py     # AnyPublicKey, MultiKey, SingleKey
├── test_account.py            # Account creation, signing, from_mnemonic
├── test_mnemonic.py           # BIP-39/44 derivation
├── test_authenticator.py      # All authenticator variants, verify
├── test_transactions.py       # RawTransaction, payloads, multi-agent, fee-payer
├── test_transaction_builder.py # TransactionBuilder
├── test_network.py            # Network config
├── test_async_client.py       # RestClient, FaucetClient (mocked httpx)
├── test_retry.py              # Retry logic, backoff
└── integration/
    ├── conftest.py            # Integration fixtures (env-based config)
    ├── test_transfer.py       # Full transfer flow against devnet
    ├── test_fee_payer.py      # Sponsored transaction flow
    ├── test_simulate.py       # Simulation and gas estimation
    ├── test_secp256k1.py      # Secp256k1 on-chain
    └── test_node.py           # Node connectivity, ledger info
```

### 6.2 Test Counts and Coverage

| Module                 | Tests | Coverage |
|------------------------|-------|----------|
| `errors.py`            | —     | 100%     |
| `bcs.py`               | 80+   | 95%      |
| `account_address.py`   | 60+   | 100%     |
| `type_tag.py`          | 90+   | 97%      |
| `chain_id.py`          | 10+   | 97%      |
| `ed25519.py`           | 50+   | 89%      |
| `secp256k1_ecdsa.py`   | 40+   | 90%      |
| `crypto_wrapper.py`    | 60+   | 97%      |
| `asymmetric_crypto.py` | 20+   | 77%      |
| `hashing.py`           | 15+   | 100%     |
| `account.py`           | 40+   | 99%      |
| `mnemonic.py`          | 15+   | 90%      |
| `authenticator.py`     | 70+   | 100%     |
| `transactions.py`      | 120+  | 99%      |
| `transaction_builder.py`| 30+  | 100%     |
| `network.py`           | 10+   | 92%      |
| `async_client.py`      | 100+  | 100%     |
| `retry.py`             | 15+   | 92%      |
| **Total**              |**1,060**|**96%** |

### 6.3 Coverage Enforcement

- Coverage configured in `pyproject.toml` with `fail_under = 50` minimum
- Actual achieved coverage: **96%** (3,084 statements, 117 missed)
- Integration tests are excluded from coverage runs (they require a live network)

### 6.4 Test Configuration

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"        # No need to mark async tests
testpaths = ["tests"]
markers = [
    "integration: marks tests that require a live Aptos network",
]
```

- Unit tests: `make test` or `poetry run pytest tests/ -v -m "not integration"`
- Integration tests: `make integration_test` or `poetry run pytest tests/integration/ -v -m integration`
- Coverage: `make test-coverage`

---

## 7. Performance Considerations

### 7.1 Connection Pooling

httpx's `AsyncClient` maintains a connection pool by default. The `RestClient` supports
`async with` context manager for proper lifecycle management, and an explicit `close()` method.

### 7.2 HTTP/2 Multiplexing

HTTP/2 is enabled by default (`httpx[http2]`), allowing multiple concurrent requests over a single
connection — critical for parallel transaction submission.

### 7.3 BCS vs JSON Submission

The SDK defaults to BCS-encoded transaction submission for:
- **Smaller payloads**: BCS is more compact than JSON
- **No ambiguity**: BCS is canonical, JSON has ordering issues
- **Performance**: Less server-side parsing

Both `submit_bcs_transaction` and JSON-based `submit_transaction` are available.

### 7.4 Pre-computed Hash Prefixes

Domain-separated hash prefixes (`SHA3-256("APTOS::RawTransaction")`) are computed once at module
load time via `HashPrefix` class attributes and reused, avoiding redundant hashing.

### 7.5 Efficient BCS Implementation

The BCS serializer/deserializer uses `io.BytesIO` for efficient byte buffer operations
and `struct.pack`/`struct.unpack` for zero-copy integer encoding/decoding.

---

## 8. Security Considerations

### 8.1 Key Material

- Private keys are stored as `bytes` with no `__repr__` to prevent logging
- `PrivateKey.__repr__()` returns `"Ed25519PrivateKey(***)"` — never the actual key
- AIP-80 format (`ed25519-priv-0x...`) for human-readable serialization with clear labeling

### 8.2 Constant-Time Comparisons

- Signature verification uses library-provided constant-time comparison
- Authentication key comparison uses `hmac.compare_digest()`

### 8.3 Input Validation

- All `from_hex()` / `from_bytes()` methods validate lengths and content
- BCS Deserializer checks bounds on all integer types
- ULEB128 decoding has maximum iteration limit
- Secp256k1 signatures enforce low-S normalization

### 8.4 Dependency Security

- All dependencies pinned with upper bounds in `pyproject.toml`
- Regular `poetry update` + dependency audit in CI

---

## 9. Implementation Phases (Completed)

### Phase 1: Foundation (errors, bcs, core types) ✓

1. `errors.py` — Full error hierarchy with categories and chaining
2. `bcs.py` — Serializer/Deserializer with all BCS types
3. `account_address.py` — AccountAddress with AIP-40 spec compliance
4. `chain_id.py` — ChainId with BCS support
5. `type_tag.py` — TypeTag, StructTag with recursive descent parser
6. `hashing.py` — SHA3-256, SHA2-256, domain-separated prefixes
7. Unit tests for all above

### Phase 2: Cryptography + Accounts ✓

8. `asymmetric_crypto.py` — Protocol definitions, AIP-80 helpers
9. `ed25519.py` — Ed25519 + MultiEd25519 key/sign/verify
10. `secp256k1_ecdsa.py` — Secp256k1 ECDSA with low-S normalization
11. `crypto_wrapper.py` — AnyPublicKey, AnySignature, MultiKey
12. `account.py` — Account with key generation and signing
13. `mnemonic.py` — BIP-39/BIP-44 derivation (SLIP-0010 compliant)
14. Unit tests + signature verification tests

### Phase 3: Transactions + Authenticators ✓

15. `transactions.py` — RawTransaction, all payloads, signing, multi-agent, fee-payer
16. `authenticator.py` — All authenticator variants with BCS and verify
17. `transaction_builder.py` — Builder pattern with validation
18. Unit tests for transaction building and authenticators

### Phase 4: API Clients + Network ✓

19. `network.py` — NetworkConfig, Network constants, backward-compat alias
20. `retry.py` — Exponential backoff retry with configurable strategy
21. `async_client.py` — RestClient with all methods, FaucetClient
22. `__init__.py` — Public API re-exports
23. Integration tests against devnet

### Phase 5: Polish + CI ✓

24. `pyproject.toml` — Updated dependencies, metadata, tool config
25. `Makefile` — Updated targets (test, lint, fmt, integration_test)
26. Formatting pass (`black`, `isort`, `autoflake`)
27. Type checking pass (`mypy`) — clean across `aptos_sdk/`, `tests/`, `examples/`
28. Linting pass (`flake8`) — clean across all directories
29. Coverage achieved: **96%** (target was 80%+)

---

## 10. Public API Surface (`__init__.py`)

```python
# Core types
from aptos_sdk.account_address import AccountAddress, AuthKeyScheme
from aptos_sdk.chain_id import ChainId
from aptos_sdk.type_tag import TypeTag, StructTag

# Cryptography
from aptos_sdk.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    MultiEd25519PublicKey, MultiEd25519Signature,
)
from aptos_sdk.secp256k1_ecdsa import (
    Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
)
from aptos_sdk.asymmetric_crypto import PrivateKeyVariant
from aptos_sdk.crypto_wrapper import (
    AnyPublicKey, AnySignature, MultiKeyPublicKey, MultiKeySignature,
)

# Hashing
from aptos_sdk.hashing import HashPrefix, sha3_256

# Accounts
from aptos_sdk.account import Account

# Transactions
from aptos_sdk.transactions import (
    RawTransaction, SignedTransaction, TransactionPayload,
    EntryFunction, Script, ModuleId, TransactionArgument,
    MultiAgentRawTransaction, FeePayerRawTransaction,
)
from aptos_sdk.transaction_builder import TransactionBuilder
from aptos_sdk.authenticator import (
    TransactionAuthenticator, AccountAuthenticator,
)

# Network + Clients
from aptos_sdk.network import Network, NetworkConfig
from aptos_sdk.async_client import (
    RestClient, FaucetClient,
    LedgerInfo, AccountInfo, Resource, GasEstimate, Transaction,
)
from aptos_sdk.retry import RetryConfig

# Errors
from aptos_sdk.errors import (
    AptosError, AptosTimeoutError, ParseError, CryptoError,
    SerializationError, NetworkError, ApiError, InvalidInputError,
    InvalidStateError, TransactionSubmissionError,
    InvalidAddressError, BadRequestError, NotFoundError,
    ConflictError, RateLimitedError, InternalServerError,
    VmError, BcsError, InsufficientBalanceError,
)
```

---

## 11. Spec Compliance Matrix (Tier 2)

| Spec Section | Requirement         | Priority | Status    |
|-------------|---------------------|----------|-----------|
| 01          | AccountAddress      | P0       | Complete  |
| 01          | ChainId             | P0       | Complete  |
| 01          | TypeTag/StructTag   | P0       | Complete  |
| 01          | MoveModuleId        | P0       | Complete  |
| 01          | U256                | P1       | Complete  |
| 02          | BCS Serializer      | P0       | Complete  |
| 02          | BCS Deserializer    | P0       | Complete  |
| 02          | ULEB128             | P0       | Complete  |
| 02          | All primitive types | P0       | Complete  |
| 03          | Ed25519             | P0       | Complete  |
| 03          | Secp256k1 ECDSA     | P1       | Complete  |
| 03          | SHA3-256            | P0       | Complete  |
| 03          | SHA2-256            | P0       | Complete  |
| 03          | Auth key derivation | P0       | Complete  |
| 03          | AIP-80 format       | P1       | Complete  |
| 04          | Ed25519 accounts    | P0       | Complete  |
| 04          | Secp256k1 accounts  | P1       | Complete  |
| 04          | BIP-39 mnemonics    | P1       | Complete  |
| 04          | BIP-44 derivation   | P1       | Complete  |
| 05          | RawTransaction      | P0       | Complete  |
| 05          | EntryFunction       | P0       | Complete  |
| 05          | Transaction signing | P0       | Complete  |
| 05          | SignedTransaction   | P0       | Complete  |
| 05          | TransactionBuilder  | P1       | Complete  |
| 05          | Script payload      | P1       | Complete  |
| 05          | Multi-agent txns    | P1       | Complete  |
| 05          | Fee-payer txns      | P1       | Complete  |
| 06          | Network config      | P0       | Complete  |
| 06          | RestClient          | P0       | Complete  |
| 06          | Account queries     | P0       | Complete  |
| 06          | Transaction queries | P0       | Complete  |
| 06          | Transaction submit  | P0       | Complete  |
| 06          | Wait for txn        | P0       | Complete  |
| 06          | View functions      | P1       | Complete  |
| 06          | Gas estimation      | P1       | Complete  |
| 06          | FaucetClient        | P1       | Complete  |
| 06          | Retry strategy      | P1       | Complete  |
| 06          | Account modules     | P1       | Complete  |
| 06          | Account transactions| P1       | Complete  |
| 06          | Simulation          | P1       | Complete  |
| 07          | SingleKey auth      | P1       | Complete  |
| 07          | MultiKey auth       | P1       | Complete  |
| 08          | Error categories    | P0       | Complete  |
| 08          | Error hierarchy     | P0       | Complete  |
| 08          | API error mapping   | P0       | Complete  |
| 08          | VM error codes      | P1       | Complete  |
| 08          | Error context       | P1       | Complete  |
| 08          | Retry classification| P1       | Complete  |

### Tier 3 (P2) — Not Yet Implemented

| Spec Section | Requirement         | Priority | Notes                    |
|-------------|---------------------|----------|--------------------------|
| 06          | IndexerClient       | P2       | GraphQL-based indexer API |
| 06          | Pagination support  | P2       | Cursor-based pagination   |
| 03          | Keyless (ZK) auth   | P2       | OpenID Connect-based      |
| 05          | Multisig v2         | P2       | On-chain multisig mgmt   |

---

## 12. Cross-Language Comparison

The Aptos SDK Specification is implemented in multiple languages. This section highlights
key differences in how this Python implementation maps spec concepts compared to other
language SDKs.

### 12.1 Python-Specific Idioms

| Spec Concept             | Python Implementation            | TypeScript Equivalent          |
|--------------------------|----------------------------------|--------------------------------|
| Error hierarchy          | Class inheritance + `ErrorCategory` enum | Class inheritance            |
| BCS serialization        | `Serializable` Protocol + explicit methods | Class-based with decorators  |
| Async I/O                | `async/await` with `httpx`       | `Promise`-based with `axios`   |
| Key protocols            | `typing.Protocol` (structural)   | TypeScript interfaces          |
| Configuration            | `@dataclass(frozen=True)`        | Object literal + readonly      |
| Builder pattern          | Fluent methods returning `self`  | Method chaining                |
| Optional dependencies    | Poetry extras (`-E mnemonic`)    | Peer dependencies              |

### 12.2 Design Trade-offs

| Decision                  | Python Choice                  | Alternative Considered          |
|---------------------------|--------------------------------|---------------------------------|
| Sync vs Async             | Async-only                     | Sync wrapper (adds complexity)  |
| HTTP library              | httpx (HTTP/2, async-native)   | aiohttp (less typed)            |
| Crypto library            | PyNaCl + ecdsa                 | cryptography (heavier)          |
| Mnemonic dependency       | Optional extra                 | Required (bloats core)          |
| Response types            | Dataclasses                    | TypedDicts (less ergonomic)     |
| Type checking             | mypy (strict)                  | pyright (stricter but niche)    |
