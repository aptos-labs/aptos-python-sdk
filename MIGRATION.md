# Migrating from v1 to v2

This guide covers migrating from the v1 API (`aptos_sdk`) to the v2 API (`aptos_sdk.v2`).

Both APIs are available in the same package — you can migrate incrementally.

## Requirements

- **Python 3.12+** (was 3.10+ in v1)
- New dependencies: `coincurve`, `bip-utils`, `aiohttp`
- `cryptography` is no longer needed for Secp256k1 (replaced by `coincurve`)

## Quick comparison

```python
# ── v1 ──
from aptos_sdk.async_client import RestClient, ClientConfig
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk import ed25519

client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
alice = Account.generate()
balance = await client.account_balance(alice.address())
await client.close()

# ── v2 ──
from aptos_sdk.v2 import Aptos, AptosConfig, Network, Account

async with Aptos(AptosConfig(network=Network.DEVNET)) as aptos:
    alice = Account.generate()
    balance = await aptos.coin.balance(alice.address)
```

## Step-by-step migration

### 1. Imports

| v1 | v2 |
|----|-----|
| `from aptos_sdk.async_client import RestClient` | `from aptos_sdk.v2 import Aptos, AptosConfig` |
| `from aptos_sdk.account import Account` | `from aptos_sdk.v2 import Account` |
| `from aptos_sdk.account_address import AccountAddress` | `from aptos_sdk.v2 import AccountAddress` |
| `from aptos_sdk.ed25519 import PrivateKey` | `from aptos_sdk.v2.crypto.ed25519 import Ed25519PrivateKey` |
| `from aptos_sdk.secp256k1_ecdsa import PrivateKey` | `from aptos_sdk.v2.crypto.secp256k1 import Secp256k1PrivateKey` |
| `from aptos_sdk.bcs import Serializer, Deserializer` | `from aptos_sdk.v2.bcs import Serializer, Deserializer` |
| `from aptos_sdk.transactions import EntryFunction, ...` | `from aptos_sdk.v2.transactions import EntryFunction, ...` |
| `from aptos_sdk.type_tag import TypeTag, StructTag` | `from aptos_sdk.v2.types import TypeTag, StructTag` |

### 2. Client setup

**v1** — URL string + optional `ClientConfig`:
```python
config = ClientConfig()
config.max_gas_amount = 200_000
client = RestClient("https://fullnode.devnet.aptoslabs.com/v1", config)
# ...
await client.close()
```

**v2** — `AptosConfig` with `Network` enum + async context manager:
```python
config = AptosConfig(
    network=Network.DEVNET,      # or MAINNET, TESTNET, LOCAL, CUSTOM
    max_gas_amount=200_000,
    gas_unit_price=100,
    expiration_ttl=600,
    transaction_wait_secs=20,
    max_retries=3,
    api_key=None,
)
async with Aptos(config) as aptos:
    # ...
```

The `async with` pattern ensures the HTTP session is closed. You can also call `await aptos.close()` manually.

### 3. Account creation

| Operation | v1 | v2 |
|-----------|----|----|
| Generate Ed25519 | `Account.generate()` | `Account.generate()` |
| Generate Secp256k1 | `Account.generate_secp256k1_ecdsa()` | `Account.generate_secp256k1()` |
| From private key hex | `Account.load_key("0x...")` | `Account.from_private_key(Ed25519PrivateKey.from_str("0x..."))` |
| From JSON file | `Account.load(path)` | *(not built-in — deserialize manually)* |
| From mnemonic | *(not available)* | `Account.from_mnemonic("word1 word2 ...")` |
| Get address | `account.address()` (method) | `account.address` (property) |
| Get public key | `account.public_key()` (method) | `account.public_key` (property) |
| Get private key | `account.private_key` (attribute) | `account.private_key` (property) |

### 4. Crypto class names

| v1 | v2 |
|----|-----|
| `ed25519.PrivateKey` | `Ed25519PrivateKey` |
| `ed25519.PublicKey` | `Ed25519PublicKey` |
| `ed25519.Signature` | `Ed25519Signature` |
| `ed25519.PrivateKey.random()` | `Ed25519PrivateKey.generate()` |
| `secp256k1_ecdsa.PrivateKey` | `Secp256k1PrivateKey` |
| `secp256k1_ecdsa.PublicKey` | `Secp256k1PublicKey` |
| `secp256k1_ecdsa.Signature` | `Secp256k1Signature` |
| `secp256k1_ecdsa.PrivateKey.random()` | `Secp256k1PrivateKey.generate()` |

Both v1 and v2 support AIP-80 formatting (`key.aip80()`) and parsing (`from_str("ed25519-priv-0x...")`).

### 5. Querying data

**v1** — all methods on `RestClient`:
```python
info = await client.account(address)
balance = await client.account_balance(address)
seq = await client.account_sequence_number(address)
resource = await client.account_resource(address, "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
resources = await client.account_resources(address)
modules = await client.account_modules(address)
chain_id = await client.chain_id()
ledger = await client.info()
block = await client.blocks_by_height(100, with_transactions=True)
table_item = await client.get_table_item(handle, key_type, value_type, key)
```

**v2** — domain-specific API accessors on `Aptos`:
```python
info = await aptos.account.get_info(address)
balance = await aptos.coin.balance(address)
seq = await aptos.account.get_sequence_number(address)
resource = await aptos.account.get_resource(address, "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>")
resources = await aptos.account.get_resources(address)
modules = await aptos.account.get_modules(address)
chain_id = await aptos.general.get_chain_id()
ledger = await aptos.general.get_ledger_info()
block = await aptos.general.get_block_by_height(100, with_transactions=True)
table_item = await aptos.general.get_table_item(handle, key_type, value_type, key)
```

### 6. Submitting transactions

**v1** — manual pipeline:
```python
payload = EntryFunction.natural(
    "0x1::coin", "transfer",
    [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
    [TransactionArgument(recipient, Serializer.struct),
     TransactionArgument(amount, Serializer.u64)],
)
raw_txn = RawTransaction(
    sender.address(), seq_num, TransactionPayload(payload),
    max_gas, gas_price, expiration, chain_id,
)
authenticator = sender.sign_transaction(raw_txn)
signed_txn = SignedTransaction(raw_txn, authenticator)
txn_hash = await client.submit_bcs_transaction(signed_txn)
await client.wait_for_transaction(txn_hash)
```

**v2** — high-level helpers:
```python
# One-liner for coin transfers:
txn_hash = await aptos.coin.transfer(sender, recipient.address, amount)
await aptos.transaction.wait_for_transaction(txn_hash)

# Or manual pipeline with automatic sequence number / chain ID:
payload = EntryFunction.natural(
    "0x1::coin", "transfer",
    [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
    [TransactionArgument(recipient.address, Serializer.struct),
     TransactionArgument(amount, Serializer.u64)],
)
raw_txn = await aptos.transaction.build(
    sender=sender.address,
    payload=TransactionPayload(payload),
)
txn_hash = await aptos.transaction.sign_and_submit(raw_txn, sender)
await aptos.transaction.wait_for_transaction(txn_hash)
```

### 7. Simulating transactions

**v1:**
```python
result = await client.simulate_transaction(raw_txn, sender)
```

**v2:**
```python
result = await aptos.transaction.simulate(raw_txn, sender.public_key)
```

### 8. Faucet

**v1:**
```python
from aptos_sdk.async_client import FaucetClient
faucet = FaucetClient("https://faucet.devnet.aptoslabs.com", client)
await faucet.fund_account(address, 100_000_000)
```

**v2:**
```python
await aptos.faucet.fund_account(address, 100_000_000)
```

### 9. Error handling

| v1 | v2 |
|----|-----|
| `aptos_sdk.async_client.ApiError` | `aptos_sdk.v2.errors.ApiError` |
| `aptos_sdk.async_client.AccountNotFound` | `aptos_sdk.v2.errors.AccountNotFoundError` |
| `aptos_sdk.async_client.ResourceNotFound` | `aptos_sdk.v2.errors.ResourceNotFoundError` |
| `aptos_sdk.async_client.TransactionTimeout` | `aptos_sdk.v2.errors.TransactionTimeoutError` |
| `aptos_sdk.async_client.TransactionFailed` | `aptos_sdk.v2.errors.TransactionFailedError` |
| `aptos_sdk.errors.DeserializationError` | `aptos_sdk.v2.errors.BcsDeserializationError` |
| `aptos_sdk.errors.SerializationError` | `aptos_sdk.v2.errors.BcsSerializationError` |
| `aptos_sdk.errors.InvalidKeyError` | `aptos_sdk.v2.errors.InvalidKeyError` |
| *(no base class)* | `aptos_sdk.v2.errors.AptosError` (catches all) |

v2 has a structured error hierarchy — catch `AptosError` to catch everything, or be specific:
```python
from aptos_sdk.v2.errors import (
    AptosError,                # base for all
    ApiError,                  # HTTP errors (has .status_code)
    AccountNotFoundError,      # 404 for account
    ResourceNotFoundError,     # 404 for resource
    TransactionTimeoutError,   # wait exceeded timeout
    TransactionFailedError,    # committed but VM failed (has .vm_status)
)
```

### 10. Address derivation

**v1:**
```python
from aptos_sdk.account_address import AccountAddress
address = AccountAddress.from_key(public_key)
resource_addr = AccountAddress.for_resource_account(creator, seed)
object_addr = AccountAddress.for_named_object(creator, seed)
```

**v2:**
```python
from aptos_sdk.v2.crypto.authentication_key import AuthenticationKey
from aptos_sdk.v2.types import AccountAddress

auth_key = AuthenticationKey.from_public_key(public_key)
address = auth_key.account_address()

resource_addr = AccountAddress.for_resource_account(creator, seed)
object_addr = AccountAddress.for_named_object(creator, seed)
```

### 11. BIP-39 mnemonic (v2 only)

```python
from aptos_sdk.v2.crypto.mnemonic import (
    generate_mnemonic,
    validate_mnemonic,
    derive_ed25519_private_key,
    derive_secp256k1_private_key,
)

phrase = generate_mnemonic()
assert validate_mnemonic(phrase)

# Derive account from mnemonic
account = Account.from_mnemonic(phrase)

# Or derive raw keys with custom path
key = derive_ed25519_private_key(phrase, "m/44'/637'/0'/0'/0'")
```

### 12. BCS serialization

The `Serializer` and `Deserializer` APIs are identical between v1 and v2. No changes needed for BCS code — just update the import path:

```python
# v1
from aptos_sdk.bcs import Serializer, Deserializer

# v2
from aptos_sdk.v2.bcs import Serializer, Deserializer
```

### 13. Secp256k1 library change

v1 used the `cryptography` library for Secp256k1. v2 uses `coincurve` (a Python binding for libsecp256k1). This is faster and produces identical signatures.

If you were constructing `secp256k1_ecdsa.PrivateKey` directly with a `cryptography` key object, update to use `coincurve.PrivateKey` or the factory methods:

```python
# v1 (cryptography)
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256K1())
pk = secp256k1_ecdsa.PrivateKey(key)

# v2 (coincurve)
from aptos_sdk.v2.crypto.secp256k1 import Secp256k1PrivateKey
pk = Secp256k1PrivateKey.generate()

# Or from hex (works in both v1 and v2):
pk = Secp256k1PrivateKey.from_str("0x...")
```

## Features only in v2

- `AptosConfig` + `Network` enum for configuration
- `Aptos` async context manager with lazy API initialization
- `CoinApi` and `FungibleAssetApi` high-level helpers
- `FaucetApi` built into the `Aptos` facade
- BIP-39 mnemonic generation and key derivation
- `coincurve` for faster Secp256k1
- Structured error hierarchy with `AptosError` base
- HTTP retry with exponential backoff (configurable `max_retries`)
- Orderless transactions (`TransactionInnerPayload` with replay-protection nonce)
- Frozen dataclasses for immutable value types (`AccountAddress`, `TypeTag`, etc.)

## Features only in v1

- `IndexerClient` (GraphQL)
- `FaucetClient` (standalone)
- Token clients (`aptos_token_client`, `aptos_tokenv1_client`)
- `TransactionWorker` (batch submission)
- `AccountSequenceNumber` (automatic sequence number management)
- `PackagePublisher`
- CLI wrappers (`aptos_cli_wrapper`, `cli`)
- `MultiPublicKey` / `MultiSignature` (multi-ed25519)
- `ledger_version` parameter on query methods
- `Account.load()` / `Account.store()` (JSON file persistence)

## Incremental migration

You don't need to migrate everything at once. Both APIs coexist in the same package:

```python
# Mix v1 and v2 in the same codebase
from aptos_sdk.v2 import Aptos, AptosConfig, Network, Account as V2Account
from aptos_sdk.aptos_token_client import AptosTokenClient  # v1-only feature

async with Aptos(AptosConfig(network=Network.DEVNET)) as aptos:
    alice = V2Account.generate()
    await aptos.faucet.fund_account(alice.address, 100_000_000)

    # Use v1 token client for NFT operations not yet in v2
    token_client = AptosTokenClient(rest_client)
    # ...
```

v1 types and v2 types produce identical BCS bytes, so they can be used interchangeably for serialization.
