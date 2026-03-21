# Aptos Python SDK v2 — LLM Developer Guide

## Overview

- **Package:** `aptos-python-sdk-v2` (import as `aptos_sdk_v2`)
- **Python:** >=3.12 (uses `match`, `type X = ...` union syntax in dataclasses)
- **Async-first:** all network I/O is `async`/`await`; crypto and BCS are synchronous
- **`__slots__`** on every non-dataclass class; frozen dataclasses for value types
- **Strict mypy** (`strict = true`), **ruff** linting (`E,F,I,N,W,UP`), line length 100
- **100% test coverage** target (388+ unit tests)

## Directory Map

```
src/aptos_sdk_v2/
├── __init__.py              # Public re-exports: Account, Aptos, AptosConfig, Network, types
├── _version.py              # Single-source __version__
├── aptos.py                 # Aptos facade — lazy-init API accessors
├── config.py                # AptosConfig (frozen dataclass), Network enum, URL maps
├── errors.py                # Full exception hierarchy (AptosError base)
├── account/
│   ├── __init__.py          # Re-exports Account
│   └── account.py           # Account class — keypair + address, generate/from_mnemonic
├── api/
│   ├── __init__.py          # Re-exports all API classes
│   ├── account_api.py       # AccountApi — get_info, get_balance, get_resource(s), get_modules
│   ├── coin_api.py          # CoinApi — transfer, balance (0x1::coin module)
│   ├── faucet_api.py        # FaucetApi — fund_account (devnet/testnet)
│   ├── fungible_asset_api.py # FungibleAssetApi — transfer, balance (0x1::primary_fungible_store)
│   ├── general_api.py       # GeneralApi — ledger info, blocks, table items, view functions
│   ├── http_client.py       # HttpClient — aiohttp with retry, connection pool, BCS content types
│   └── transaction_api.py   # TransactionApi — build, simulate, sign, submit, wait pipeline
├── bcs/
│   ├── __init__.py          # Re-exports Serializer, Deserializer, protocols
│   ├── deserializer.py      # BCS deserialization (u8..u256, str, bytes, sequence, option)
│   ├── protocols.py         # Serializable/Deserializable protocols with to_bytes/from_bytes
│   └── serializer.py        # BCS serialization (u8..u256, str, bytes, sequence, option)
├── crypto/
│   ├── __init__.py          # Re-exports key types
│   ├── authentication_key.py # AuthenticationKey — derive address from public key
│   ├── ed25519.py           # Ed25519PrivateKey/PublicKey/Signature (PyNaCl)
│   ├── keys.py              # Abstract PrivateKey/PublicKey/Signature + AIP-80 helpers
│   ├── mnemonic.py          # BIP-39 generate/validate + BIP-44 key derivation
│   ├── secp256k1.py         # Secp256k1PrivateKey/PublicKey/Signature (coincurve)
│   └── single_key.py        # AnyPublicKey/AnySignature wrappers for non-Ed25519 keys
├── transactions/
│   ├── __init__.py          # Re-exports all transaction types
│   ├── authenticator.py     # Auth variants: Ed25519, SingleKey, MultiAgent, FeePayer, Authenticator
│   ├── payload.py           # EntryFunction, Script, ScriptArgument, TransactionPayload, etc.
│   ├── raw_transaction.py   # RawTransaction, MultiAgentRawTransaction, FeePayerRawTransaction
│   └── signed_transaction.py # SignedTransaction (raw_txn + authenticator)
└── types/
    ├── __init__.py          # Re-exports AccountAddress, TypeTag, StructTag
    ├── account_address.py   # AccountAddress (frozen dataclass) — AIP-40 parsing, derived addresses
    ├── chain_id.py          # ChainId wrapper
    └── type_tag.py          # TypeTag, StructTag, primitive tags, string parser
```

## Core Patterns

Every change to this codebase **must** follow these 7 conventions:

### 1. `__slots__` on all non-dataclass classes

```python
class CoinApi:
    __slots__ = ("_config", "_client", "_transaction")
```

Dataclasses use `slots=True` in the decorator instead.

### 2. Async boundary

- **`api/` package = async** — every method that touches the network is `async def`
- **Everything else = sync** — BCS, crypto, type construction, transaction building (except `TransactionApi.build` which fetches sequence number)
- The `Aptos` class is an async context manager: `async with Aptos(config) as aptos:`

### 3. BCS serialize/deserialize protocol

Every BCS type implements:
```python
def serialize(self, serializer: Serializer) -> None: ...

@staticmethod
def deserialize(deserializer: Deserializer) -> Self: ...
```

Use `Serializable` and `Deserializable` protocols from `bcs/protocols.py`. Call `serializer.struct(obj)` for nested types, `serializer.sequence(items, Serializer.struct)` for lists.

### 4. Frozen dataclasses for value types

Value types (AccountAddress, TypeTag, StructTag, primitive tags) are `@dataclass(frozen=True, slots=True)`. This makes them hashable and immutable.

### 5. Lazy API initialization in `Aptos`

Each API accessor is a `@property` that creates the instance on first access:
```python
@property
def coin(self) -> CoinApi:
    if self._coin is None:
        self._coin = CoinApi(self._config, self._client, self.transaction)
    return self._coin
```

### 6. Error hierarchy (always raise most specific subclass)

```
AptosError
├── ApiError(message, status_code)
│   ├── AccountNotFoundError(address)
│   └── ResourceNotFoundError(address, resource_type)
├── TransactionError
│   ├── TransactionTimeoutError(txn_hash)
│   └── TransactionFailedError(txn_hash, vm_status)
├── BcsError
│   ├── BcsSerializationError
│   └── BcsDeserializationError
├── CryptoError
│   ├── InvalidKeyError
│   ├── InvalidSignatureError
│   └── InvalidMnemonicError
├── InvalidAddressError
└── InvalidTypeTagError
```

Never raise bare `AptosError` — always use the most specific subclass.

### 7. AIP-40 strict address parsing

- `AccountAddress.from_str()` — **strict**: requires `0x` prefix, full 66-char form for non-special addresses, short form (`0x0`–`0xf`) only for special addresses
- `AccountAddress.from_str_relaxed()` — allows short form, padding, optional `0x`
- Special addresses: first 31 bytes are zero and last byte < 0x10

## How To: Add a New API Method

1. **Add the method** to the appropriate `api/*_api.py` class
2. **Signature:** `async def method_name(self, ...) -> ReturnType:`
3. **Build payload** with `EntryFunction.natural(module, function, ty_args, args)` for write operations, or use `self._client.post(url, json={...})` for view functions
4. **Wrap** in `TransactionPayload(payload)` for transaction submission
5. **Build + submit:** `raw_txn = await self._transaction.build(...)` then `return await self._transaction.sign_and_submit(raw_txn, sender)`
6. **Add tests** in `tests/unit/api/test_{module}_api.py` using `aioresponses` to mock HTTP
7. **Re-export** if needed in the package `__init__.py`

## How To: Add a New Transaction Type

1. **Define the class** in `transactions/` with `__slots__`, `serialize()`, `deserialize()`, and `keyed()` methods
2. **Domain separator:** single-sender uses `APTOS::RawTransaction`, multi-signer uses `APTOS::RawTransactionWithData`
3. **`keyed()` method:** `prehash || BCS(self)` — this is the message that gets signed
4. **Signing:** call `_sign_internal(self.keyed(), private_key)` from `raw_transaction.py`
5. **Secp256k1 wrapping:** non-Ed25519 keys automatically get wrapped in `SingleKeyAuthenticator` → `AnyPublicKey` / `AnySignature`
6. **Register** in `TransactionPayload` if it's a new payload variant, or in `Authenticator` if it's a new auth variant
7. **Re-export** from `transactions/__init__.py`

## Transaction Pipeline Internals

```
EntryFunction.natural(module, fn, ty_args, args)
    ↓
TransactionPayload(entry_function)
    ↓
TransactionApi.build(sender, payload) → RawTransaction
    ↓
RawTransaction.keyed() → SHA3-256("APTOS::RawTransaction") || BCS(raw_txn)
    ↓
PrivateKey.sign(keyed_data) → Signature
    ↓
AccountAuthenticator(Ed25519Authenticator | SingleKeyAuthenticator)
    ↓
SignedTransaction(raw_txn, authenticator)
    ↓
BCS serialize → POST /transactions (Content-Type: application/x.aptos.signed_transaction+bcs)
    ↓
wait_for_transaction(hash) → poll until committed or timeout
```

**Multi-agent/fee-payer variants** use `APTOS::RawTransactionWithData` domain separator and `MultiAgentRawTransaction` / `FeePayerRawTransaction` wrappers. All signers sign the same `keyed()` bytes.

**Orderless transactions** wrap the payload in `TransactionInnerPayload(TransactionExecutable, TransactionExtraConfig)` with a `replay_protection_nonce` instead of a sequence number.

## Crypto Layer

- **Ed25519:** PyNaCl (`nacl.signing`). Default key type. Auth scheme byte `0x00`.
- **Secp256k1:** coincurve. Wrapped in `AnyPublicKey` for address derivation (auth scheme `0x02`).
- **Mnemonic:** BIP-39 via `bip-utils`. Default path: `m/44'/637'/0'/0'/0'`. Vary index 3 (account) for multi-account. Both Ed25519 and Secp256k1 derivation supported.
- **AIP-80 format:** private keys serialize as `ed25519-priv-0x{hex}` or `secp256k1-priv-0x{hex}`. Use `key.aip80()` to get this format.
- **AuthenticationKey:** `SHA3-256(public_key_bytes || scheme_byte)`. For Secp256k1, the public key is first wrapped in `AnyPublicKey` (BCS-serialized with variant tag).

## HTTP Client

- **Library:** aiohttp with `TCPConnector(limit=100, limit_per_host=25)`
- **Retry:** exponential backoff (`2^attempt * 0.25s`) on 429 and 5xx, up to `max_retries` (default 3)
- **Session:** lazily created, reused across requests, closed via `Aptos.close()` or `async with`
- **BCS submission:** `Content-Type: application/x.aptos.signed_transaction+bcs`
- **User-Agent:** `aptos-python-sdk-v2/{version}`
- **API key:** passed as `Authorization: Bearer {key}` header if configured

## Type System

- **TypeTag:** wrapper around variant types (BoolTag, U8Tag, ..., StructTag)
- **StructTag:** `address::module::name<type_args>` — parse with `StructTag.from_str("0x1::aptos_coin::AptosCoin")`
- **TypeTag construction:** `TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))` for entry function type args
- **ScriptArgument:** variant-tagged values for Script payloads — `ScriptArgument(ScriptArgument.U64, 1000)`

## Testing Conventions

- **Framework:** pytest + pytest-asyncio (auto mode — no `@pytest.mark.asyncio` needed)
- **HTTP mocking:** `aioresponses` — mock specific URLs with expected request/response
- **Structure:** `tests/unit/` mirrors `src/aptos_sdk_v2/` package structure
- **Coverage:** 100% target — `uv run pytest tests/unit --cov=aptos_sdk_v2 --cov-report=term-missing`
- **No integration tests in CI** — examples are devnet-only, run manually

## Import Conventions

```python
# Top-level re-exports (preferred for user code)
from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network

# Sub-path imports for transaction internals
from aptos_sdk_v2.transactions import EntryFunction, TransactionPayload, TransactionArgument
from aptos_sdk_v2.bcs import Serializer

# Type imports
from aptos_sdk_v2.types import AccountAddress, StructTag, TypeTag

# Crypto sub-path (not re-exported at top level)
from aptos_sdk_v2.crypto.mnemonic import generate_mnemonic, validate_mnemonic
```

Internal code uses **relative imports** (`from ..config import AptosConfig`).

## Linting

- **ruff:** `select = ["E", "F", "I", "N", "W", "UP"]`, target Python 3.12, line length 100
- **mypy:** strict mode, `warn_return_any = false`, ignores missing imports for `bip_utils` and `coincurve`
- **Run:** `uv run ruff check src/` and `uv run mypy src/`
