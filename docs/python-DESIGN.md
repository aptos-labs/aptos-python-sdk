# Aptos Python SDK - Design Document

## Ground-Up Rewrite from Aptos SDK Specification v1.0.0

**Target**: Tier 2 (P0 + P1) Compliance
**Python**: 3.10+
**Date**: 2026-02-20

---

## 1. Executive Summary

This document describes the ground-up rewrite of the Aptos Python SDK to fully conform to the
[Aptos SDK Specification v1.0.0](https://github.com/aptos-labs/aptos-sdk-specs/tree/main/specifications).
The rewrite targets **Tier 2 compliance** (all P0 and P1 requirements), is **async-only**, uses
**httpx** for HTTP, **Poetry** for packaging, and **plain dataclasses** with a protocol-based BCS
serialization layer.

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
                    │    aptos_sdk.client  │  ← REST / Faucet / Indexer
                    │  (async_client.py)   │
                    └──────────┬──────────┘
                               │ uses
                    ┌──────────▼──────────┐
                    │ aptos_sdk.transaction│  ← RawTransaction, Builder,
                    │  (transactions.py)   │    Signing, SignedTransaction
                    └──────────┬──────────┘
                               │ uses
              ┌────────────────┼────────────────┐
              │                │                │
   ┌──────────▼───┐  ┌────────▼────────┐  ┌────▼──────────┐
   │ aptos_sdk.   │  │ aptos_sdk.      │  │ aptos_sdk.    │
   │ account      │  │ authenticator   │  │ type_tag      │
   │ (account.py) │  │(authenticator.py│  │ (type_tag.py) │
   └──────┬───────┘  └───────┬────────┘  └───────────────┘
          │                  │
   ┌──────▼──────────────────▼────────┐
   │        aptos_sdk.crypto          │  ← Ed25519, Secp256k1,
   │ (ed25519.py, secp256k1_ecdsa.py, │    Hashing, Key Derivation
   │  asymmetric_crypto.py)           │
   └──────────────┬───────────────────┘
                  │ uses
   ┌──────────────▼───────────────────┐
   │         aptos_sdk.bcs            │  ← Serializer, Deserializer,
   │         (bcs.py)                 │    Serializable protocol
   └──────────────┬───────────────────┘
                  │ uses
   ┌──────────────▼───────────────────┐
   │      aptos_sdk.core_types        │  ← AccountAddress, ChainId
   │   (account_address.py)           │
   └──────────────────────────────────┘

   ┌──────────────────────────────────┐
   │      aptos_sdk.errors            │  ← AptosError hierarchy
   │      (errors.py)                 │    (used by ALL modules)
   └──────────────────────────────────┘
```

### 2.2 Package Layout

```
aptos_sdk/
├── __init__.py              # Public API re-exports
├── errors.py                # Error hierarchy (spec 08)
├── bcs.py                   # BCS Serializer/Deserializer (spec 02)
├── account_address.py       # AccountAddress, constants (spec 01)
├── type_tag.py              # TypeTag, StructTag, parsing (spec 01)
├── chain_id.py              # ChainId (spec 01)
├── asymmetric_crypto.py     # PrivateKey/PublicKey/Signature protocols (spec 03)
├── ed25519.py               # Ed25519 implementation (spec 03)
├── secp256k1_ecdsa.py       # Secp256k1 ECDSA implementation (spec 03)
├── crypto_wrapper.py        # SingleKey/MultiKey wrappers (spec 03)
├── hashing.py               # SHA3-256, SHA2-256, domain-separated (spec 03)
├── account.py               # Account types (spec 04)
├── mnemonic.py              # BIP-39/BIP-44 key derivation (spec 04 P1)
├── authenticator.py         # Transaction authenticators (spec 05/07)
├── transactions.py          # RawTransaction, payloads, signing (spec 05)
├── transaction_builder.py   # TransactionBuilder pattern (spec 05)
├── network.py               # Network config (spec 06)
├── async_client.py          # RestClient, FaucetClient (spec 06)
├── indexer_client.py        # IndexerClient (spec 06 P2, included)
├── retry.py                 # Retry strategy (spec 06 P1)
└── py.typed                 # PEP 561 marker
```

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
│   ├── BadRequestError         (400)
│   ├── NotFoundError           (404)
│   ├── ConflictError           (409)
│   ├── RateLimitedError        (429)
│   ├── InternalServerError     (5xx)
│   └── VmError
├── TimeoutError
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

```python
from enum import Enum

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

**Key changes from existing SDK:**
- Add `option()` method for `Option<T>` serialization
- Add proper `variant_index()` for enum serialization
- Add `map()` for sorted map serialization
- `u256()` support (32-byte LE)

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

    # Formatting
    def to_hex(self) -> str: ...          # full 0x + 64 chars
    def to_short_string(self) -> str: ... # 0x + trimmed leading zeros

    # Spec compliance
    def is_special(self) -> bool: ...     # <= 0xf (short-form eligible)

    # BCS
    def serialize(self, s: Serializer) -> None: ...

    @staticmethod
    def deserialize(d: Deserializer) -> AccountAddress: ...
```

**Key changes from existing SDK:**
- `frozen=True` dataclass (immutable)
- `from_hex()` replaces `from_str()` / `from_str_relaxed()` — single method, spec-compliant
- `ClassVar` constants instead of module-level variables
- Strict validation per spec (empty input → error, 65+ hex chars → error)

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

**Key changes from existing SDK:**
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

class PublicKey(Protocol):
    @staticmethod
    def from_bytes(data: bytes) -> PublicKey: ...
    def to_bytes(self) -> bytes: ...
    def verify(self, message: bytes, signature: Signature) -> bool: ...
    def auth_key(self) -> AuthenticationKey: ...

class Signature(Protocol):
    @staticmethod
    def from_bytes(data: bytes) -> Signature: ...
    def to_bytes(self) -> bytes: ...
```

#### Ed25519 (`ed25519.py`) — P0

```
Ed25519PrivateKey  → 32 bytes (PyNaCl SigningKey)
Ed25519PublicKey   → 32 bytes (PyNaCl VerifyKey)
Ed25519Signature   → 64 bytes
```

- Auth key: `SHA3-256(public_key_bytes || 0x00)`

#### Secp256k1 ECDSA (`secp256k1_ecdsa.py`) — P1

```
Secp256k1PrivateKey  → 32 bytes (ecdsa library)
Secp256k1PublicKey   → 65 bytes (uncompressed)
Secp256k1Signature   → 64 bytes (r || s, low-S normalized)
```

- Auth key: `SHA3-256(public_key_bytes || 0x01)`
- Signing uses SHA3-256 as hash function

#### Hashing (`hashing.py`)

```python
def sha3_256(data: bytes) -> bytes: ...
def sha2_256(data: bytes) -> bytes: ...

class HashPrefix:
    """Domain-separated hashing per spec."""
    RAW_TRANSACTION = sha3_256(b"APTOS::RawTransaction")
    RAW_TRANSACTION_WITH_DATA = sha3_256(b"APTOS::RawTransactionWithData")
    MULTI_AGENT = sha3_256(b"APTOS::MultiAgentRawTransaction") # unused now

    @staticmethod
    def prefix_for(domain: str) -> bytes:
        return sha3_256(f"APTOS::{domain}".encode())
```

**Key changes from existing SDK:**
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
    def public_key(self) -> PublicKey: ...
    def auth_key(self) -> AuthenticationKey: ...
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

**Key changes from existing SDK:**
- Mnemonic support is NEW (not in current SDK)
- `Account.from_mnemonic()` convenience method
- SLIP-0010 compliant derivation

### 3.6 Transactions (`transactions.py`, `transaction_builder.py`) — Spec 05

#### RawTransaction

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
```

#### TransactionPayload

```python
class TransactionPayloadVariant(Enum):
    SCRIPT = 0
    # MODULE_BUNDLE = 1  # deprecated
    ENTRY_FUNCTION = 2
    MULTISIG = 3

@dataclass
class TransactionPayload(Serializable):
    variant: TransactionPayloadVariant
    value: EntryFunction | Script | Multisig
```

#### EntryFunction

```python
@dataclass
class EntryFunction(Serializable):
    module: MoveModuleId
    function: str
    type_args: list[TypeTag]
    args: list[bytes]  # Each arg is BCS-encoded

    @staticmethod
    def natural(
        module: str,       # "0x1::aptos_account"
        function: str,     # "transfer"
        type_args: list[TypeTag],
        args: list[bytes],
    ) -> EntryFunction:
        """Convenience constructor parsing module string."""
        ...
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

**Key changes from existing SDK:**
- `TransactionBuilder` is NEW (spec P1)
- Cleaner `EntryFunction` with `args` as pre-encoded `list[bytes]`
- `RawTransaction.signing_message()` uses domain-separated hashing
- `Multisig` payload variant added

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

**Key changes from existing SDK:**
- Cleaner variant dispatch via match/case (Python 3.10+)
- `SingleKey` authenticator wraps `AnyPublicKey` / `AnySignature` with variant tags

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
        chain_id=1,
    )
    TESTNET = NetworkConfig(
        name="testnet",
        fullnode_url="https://fullnode.testnet.aptoslabs.com/v1",
        faucet_url="https://faucet.testnet.aptoslabs.com",
        chain_id=2,
    )
    DEVNET = NetworkConfig(
        name="devnet",
        fullnode_url="https://fullnode.devnet.aptoslabs.com/v1",
        faucet_url="https://faucet.devnet.aptoslabs.com",
    )
    LOCALNET = NetworkConfig(
        name="localnet",
        fullnode_url="http://localhost:8080/v1",
        faucet_url="http://localhost:8081",
        chain_id=4,
    )

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
        max_retries: int = 3,
    ) -> None: ...

    async def __aenter__(self) -> RestClient: ...
    async def __aexit__(self, *args) -> None: ...

    # Ledger (P0)
    async def get_ledger_info(self) -> LedgerInfo: ...

    # Accounts (P0)
    async def get_account(self, address: AccountAddress) -> AccountInfo: ...
    async def get_account_resources(self, address: AccountAddress) -> list[Resource]: ...
    async def get_account_resource(self, address: AccountAddress, resource_type: str) -> Resource: ...
    async def account_balance(self, address: AccountAddress) -> int: ...
    async def account_sequence_number(self, address: AccountAddress) -> int: ...

    # Modules (P1)
    async def get_account_modules(self, address: AccountAddress) -> list[Module]: ...
    async def get_account_module(self, address: AccountAddress, module_name: str) -> Module: ...

    # Transactions (P0)
    async def get_transaction_by_hash(self, txn_hash: str) -> Transaction: ...
    async def get_transaction_by_version(self, version: int) -> Transaction: ...
    async def get_account_transactions(
        self, address: AccountAddress, *, start: int | None = None, limit: int | None = None
    ) -> list[Transaction]: ...

    # Submission (P0)
    async def submit_transaction(self, account: Account, payload: TransactionPayload) -> str: ...
    async def submit_bcs_transaction(self, signed_txn: SignedTransaction) -> str: ...
    async def wait_for_transaction(self, txn_hash: str, *, timeout_secs: int = 30) -> Transaction: ...

    # Convenience (P0)
    async def submit_and_wait(self, account: Account, payload: TransactionPayload) -> Transaction: ...

    # View Functions (P1)
    async def view_function(
        self, module: str, function: str, type_args: list[str], args: list[str]
    ) -> list[Any]: ...

    # Gas (P1)
    async def estimate_gas_price(self) -> GasEstimate: ...

    # Simulation (P1)
    async def simulate_transaction(
        self, account: Account, payload: TransactionPayload
    ) -> list[Transaction]: ...
```

#### FaucetClient

```python
class FaucetClient:
    """Client for the Aptos Faucet (testnet/devnet only)."""

    def __init__(self, base_url: str) -> None: ...

    async def fund_account(self, address: AccountAddress, amount: int) -> list[str]: ...
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

New dataclasses for structured API responses:

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

## 4. Differences from Existing SDK

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

### 4.3 Breaking Changes

| Change                                 | Migration Path                              |
|----------------------------------------|---------------------------------------------|
| Python 3.10+ required                  | Upgrade Python (3.9 is EOL)                 |
| Error classes restructured             | Catch `AptosError` subtypes by category     |
| `AccountAddress.from_str()` → `from_hex()` | Rename calls                           |
| `EntryFunction.natural()` args change  | Args are now `list[bytes]` (pre-BCS-encoded)|
| Network config restructured            | Use `Network.TESTNET` etc.                  |
| Response types are dataclasses         | Access `.field` instead of `["field"]`      |
| No sync API                            | Wrap with `asyncio.run()` if needed         |

---

## 5. Dependency Changes

### 5.1 Production Dependencies

| Dependency          | Version    | Purpose                        | Change    |
|---------------------|-----------|--------------------------------|-----------|
| `httpx[http2]`      | ^0.28     | Async HTTP client              | Keep      |
| `PyNaCl`            | ^1.5      | Ed25519 cryptography           | Keep      |
| `ecdsa`             | ^0.19     | Secp256k1 ECDSA                | Keep      |
| `typing-extensions` | ^4.15     | Backport type features         | Keep      |
| `mnemonic`          | ^0.21     | BIP-39 wordlist + generation   | NEW       |
| `hmac` / `hashlib`  | stdlib    | BIP-44 key derivation          | stdlib    |

### 5.2 Removed Dependencies

| Dependency              | Reason                                    |
|-------------------------|-------------------------------------------|
| `python-graphql-client` | Replace with direct httpx GraphQL calls   |
| `tomli`                 | Only needed for CLI/package publisher      |
| `behave`                | Keep for BDD but move to dev deps only    |

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
| `behave`      | ^1.2      | BDD testing                |

---

## 6. Testing Strategy

### 6.1 Test Structure

```
tests/
├── conftest.py              # Shared fixtures, mock clients
├── unit/
│   ├── test_errors.py       # Error hierarchy, categories, messages
│   ├── test_bcs.py          # Serializer/Deserializer, all types
│   ├── test_account_address.py  # Parsing, formatting, constants
│   ├── test_type_tag.py     # TypeTag/StructTag parsing
│   ├── test_chain_id.py     # ChainId
│   ├── test_ed25519.py      # Key gen, sign, verify
│   ├── test_secp256k1.py    # Key gen, sign, verify
│   ├── test_hashing.py      # SHA3-256, SHA2-256, domain prefixes
│   ├── test_account.py      # Account creation, signing
│   ├── test_mnemonic.py     # BIP-39/44 derivation
│   ├── test_authenticator.py # All authenticator variants
│   ├── test_transactions.py  # RawTransaction, payloads, signing
│   ├── test_builder.py       # TransactionBuilder
│   ├── test_network.py       # Network config
│   ├── test_client.py        # RestClient (mocked httpx)
│   ├── test_faucet.py        # FaucetClient (mocked)
│   ├── test_retry.py         # Retry logic
│   └── test_response_types.py # Response dataclasses
├── integration/
│   ├── test_devnet.py        # Full flow against devnet
│   └── test_faucet_devnet.py # Faucet against devnet
└── vectors/
    ├── test_address_vectors.py  # Spec test vectors
    ├── test_bcs_vectors.py      # BCS test vectors
    ├── test_signature_vectors.py # Crypto test vectors
    └── test_transaction_vectors.py # Transaction vectors
```

### 6.2 Test Vector Compliance

The spec provides test vectors in `test-vectors/`. We will import and validate against:
- `addresses.json` — Address parsing/formatting
- `bcs.json` — BCS serialization
- `signatures.json` — Cryptographic signatures
- `transactions.json` — Transaction serialization
- `type-tags.json` — TypeTag parsing
- `mnemonics.json` — BIP-39/44 derivation

### 6.3 Coverage Target

- **Unit tests**: 80%+ coverage (up from 50%)
- **All P0 and P1 spec scenarios**: 100% covered
- **Integration tests**: Smoke test against devnet

### 6.4 BDD Features

Retain and expand Behave BDD tests from the spec's Gherkin scenarios:
- `features/01-core-types/` — Account address, type tags
- `features/02-bcs/` — Serialization/deserialization
- `features/03-crypto/` — Signing/verification
- `features/04-accounts/` — Account management
- `features/05-transactions/` — Transaction building
- `features/06-api-clients/` — API client behavior

---

## 7. Performance Considerations

### 7.1 Connection Pooling

httpx's `AsyncClient` maintains a connection pool by default. The `RestClient` will use
`async with` to ensure proper lifecycle management.

### 7.2 HTTP/2 Multiplexing

HTTP/2 is enabled by default (`httpx[http2]`), allowing multiple concurrent requests over a single
connection — critical for parallel transaction submission.

### 7.3 BCS vs JSON Submission

The spec recommends BCS-encoded transaction submission for:
- **Smaller payloads**: BCS is more compact than JSON
- **No ambiguity**: BCS is canonical, JSON has ordering issues
- **Performance**: Less server-side parsing

We will default to BCS submission (`submit_bcs_transaction`) and provide JSON submission as fallback.

### 7.4 Lazy Imports

Heavy crypto dependencies (`PyNaCl`, `ecdsa`) will be lazily imported where possible to reduce
import time for users who only need a subset of functionality.

### 7.5 Pre-computed Hash Prefixes

Domain-separated hash prefixes (`SHA3-256("APTOS::RawTransaction")`) are computed once at module
load time and reused, avoiding redundant hashing.

---

## 8. Security Considerations

### 8.1 Key Material

- Private keys are stored as `bytes` with no `__repr__` to prevent logging
- `PrivateKey.__repr__()` returns `"PrivateKey(***)"` — never the actual key
- AIP-80 format (`ed25519-priv-0x...`) for human-readable serialization with clear labeling

### 8.2 Constant-Time Comparisons

- Signature verification uses library-provided constant-time comparison
- Authentication key comparison uses `hmac.compare_digest()`

### 8.3 Input Validation

- All `from_hex()` / `from_bytes()` methods validate lengths and content
- BCS Deserializer checks bounds on all integer types
- ULEB128 decoding has maximum iteration limit

### 8.4 Dependency Security

- All dependencies pinned with upper bounds
- `urllib3 >= 2.5.0`, `requests >= 2.32.5` for known CVE fixes
- Regular `poetry update` + `safety check` in CI

---

## 9. Implementation Plan

### Phase 1: Foundation (errors, bcs, core types)

1. `errors.py` — Full error hierarchy with categories
2. `bcs.py` — Serializer/Deserializer with all types
3. `account_address.py` — AccountAddress with spec compliance
4. `chain_id.py` — ChainId
5. `type_tag.py` — TypeTag, StructTag with string parsing
6. `hashing.py` — SHA3-256, SHA2-256, domain prefixes
7. Unit tests for all above
8. Test vectors validation

### Phase 2: Cryptography + Accounts

9. `asymmetric_crypto.py` — Protocol definitions
10. `ed25519.py` — Ed25519 key/sign/verify
11. `secp256k1_ecdsa.py` — Secp256k1 ECDSA
12. `crypto_wrapper.py` — SingleKey/MultiKey wrappers
13. `account.py` — Account with key generation
14. `mnemonic.py` — BIP-39/44 derivation (P1)
15. Unit tests + signature test vectors

### Phase 3: Transactions + Authenticators

16. `transactions.py` — RawTransaction, payloads, signing
17. `authenticator.py` — All authenticator variants
18. `transaction_builder.py` — Builder pattern (P1)
19. Unit tests + transaction test vectors

### Phase 4: API Clients + Network

20. `network.py` — NetworkConfig, Network constants
21. `retry.py` — Retry strategy (P1)
22. `async_client.py` — RestClient with all methods
23. `indexer_client.py` — IndexerClient (lightweight)
24. `__init__.py` — Public API exports
25. Integration tests against devnet

### Phase 5: Polish + CI

26. `pyproject.toml` — Updated dependencies, metadata
27. `Makefile` — Updated targets
28. Formatting pass (`black`, `isort`, `autoflake`)
29. Type checking pass (`mypy --strict`)
30. Linting pass (`flake8`)
31. Coverage verification (80%+ target)
32. BDD feature alignment with spec scenarios

---

## 10. Public API Surface (`__init__.py`)

```python
# Core types
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.chain_id import ChainId
from aptos_sdk.type_tag import TypeTag, StructTag

# Cryptography
from aptos_sdk.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
)
from aptos_sdk.secp256k1_ecdsa import (
    Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
)
from aptos_sdk.asymmetric_crypto import PrivateKeyVariant

# Accounts
from aptos_sdk.account import Account

# Transactions
from aptos_sdk.transactions import (
    RawTransaction, SignedTransaction,
    TransactionPayload, EntryFunction, Script,
)
from aptos_sdk.transaction_builder import TransactionBuilder
from aptos_sdk.authenticator import (
    TransactionAuthenticator, AccountAuthenticator,
)

# Clients
from aptos_sdk.network import Network, NetworkConfig
from aptos_sdk.async_client import RestClient, FaucetClient

# BCS
from aptos_sdk.bcs import Serializer, Deserializer, Serializable

# Errors
from aptos_sdk.errors import (
    AptosError, ParseError, CryptoError, SerializationError,
    NetworkError, ApiError, TimeoutError, InvalidInputError,
)
```

---

## 11. Appendix: Spec Compliance Matrix (Tier 2)

| Spec Section | Requirement         | Priority | Covered |
|-------------|---------------------|----------|---------|
| 01          | AccountAddress      | P0       | Yes     |
| 01          | ChainId             | P0       | Yes     |
| 01          | TypeTag/StructTag   | P0       | Yes     |
| 01          | MoveModuleId        | P0       | Yes     |
| 01          | U256                | P1       | Yes     |
| 02          | BCS Serializer      | P0       | Yes     |
| 02          | BCS Deserializer    | P0       | Yes     |
| 02          | ULEB128             | P0       | Yes     |
| 02          | All primitive types | P0       | Yes     |
| 03          | Ed25519             | P0       | Yes     |
| 03          | Secp256k1 ECDSA     | P1       | Yes     |
| 03          | SHA3-256            | P0       | Yes     |
| 03          | SHA2-256            | P0       | Yes     |
| 03          | Auth key derivation | P0       | Yes     |
| 03          | AIP-80 format       | P1       | Yes     |
| 04          | Ed25519 accounts    | P0       | Yes     |
| 04          | Secp256k1 accounts  | P1       | Yes     |
| 04          | BIP-39 mnemonics    | P1       | Yes     |
| 04          | BIP-44 derivation   | P1       | Yes     |
| 05          | RawTransaction      | P0       | Yes     |
| 05          | EntryFunction       | P0       | Yes     |
| 05          | Transaction signing | P0       | Yes     |
| 05          | SignedTransaction   | P0       | Yes     |
| 05          | TransactionBuilder  | P1       | Yes     |
| 05          | Script payload      | P1       | Yes     |
| 06          | Network config      | P0       | Yes     |
| 06          | RestClient          | P0       | Yes     |
| 06          | Account queries     | P0       | Yes     |
| 06          | Transaction queries | P0       | Yes     |
| 06          | Transaction submit  | P0       | Yes     |
| 06          | Wait for txn        | P0       | Yes     |
| 06          | View functions      | P1       | Yes     |
| 06          | Gas estimation      | P1       | Yes     |
| 06          | FaucetClient        | P1       | Yes     |
| 06          | Retry strategy      | P1       | Yes     |
| 06          | Account modules     | P1       | Yes     |
| 06          | Account transactions| P1       | Yes     |
| 08          | Error categories    | P0       | Yes     |
| 08          | Error hierarchy     | P0       | Yes     |
| 08          | API error mapping   | P0       | Yes     |
| 08          | VM error codes      | P1       | Yes     |
| 08          | Error context       | P1       | Yes     |
| 08          | Retry classification| P1       | Yes     |
