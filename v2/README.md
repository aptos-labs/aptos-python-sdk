# Aptos Python SDK v2

Async-first Python SDK for the [Aptos](https://aptos.dev) blockchain.

## Installation

```bash
pip install aptos-python-sdk-v2
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add aptos-python-sdk-v2
```

Requires **Python 3.12+**.

## Quickstart

```python
import asyncio
from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network

async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        alice = Account.generate()
        bob = Account.generate()
        await aptos.faucet.fund_account(alice.address, 100_000_000)
        await aptos.faucet.fund_account(bob.address, 10_000_000)
        txn_hash = await aptos.coin.transfer(alice, bob.address, 1_000)
        await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Bob balance: {await aptos.coin.balance(bob.address)}")

asyncio.run(main())
```

## Key Features

- **Async-first** — built on `aiohttp` with connection pooling and automatic retries
- **Ed25519 & Secp256k1** — both key types work identically for signing and submitting
- **BIP-39 mnemonic** — generate, validate, and derive accounts from mnemonic phrases
- **Coin & Fungible Asset APIs** — transfer and query balances using either the Coin or FA module
- **Multi-agent transactions** — multiple signers on a single transaction
- **Fee-payer (sponsored) transactions** — a third party pays gas fees
- **Orderless transactions** — replay-protection nonce instead of sequence numbers
- **Full BCS support** — serialize and deserialize all on-chain types
- **100% test coverage** — 388+ unit tests

## API Overview

The `Aptos` class is the main entry point. Access domain-specific APIs via properties:

| Accessor | Class | Description |
|---|---|---|
| `aptos.account` | `AccountApi` | Query account info, resources, modules, balances |
| `aptos.coin` | `CoinApi` | Transfer and query Coin balances (APT and custom coins) |
| `aptos.fungible_asset` | `FungibleAssetApi` | Transfer and query Fungible Asset balances |
| `aptos.faucet` | `FaucetApi` | Fund accounts on devnet/testnet |
| `aptos.general` | `GeneralApi` | Ledger info, blocks, table items, view functions |
| `aptos.transaction` | `TransactionApi` | Build, simulate, sign, submit, and wait for transactions |

## Accounts

```python
from aptos_sdk_v2 import Account
from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey
from aptos_sdk_v2.crypto.mnemonic import generate_mnemonic

# Generate a new Ed25519 account
alice = Account.generate()

# Generate a new Secp256k1 account
bob = Account.generate_secp256k1()

# Restore from an existing private key
key = Ed25519PrivateKey.from_hex("0xYOUR_PRIVATE_KEY_HEX")
carol = Account.from_private_key(key)

# Derive from a BIP-39 mnemonic phrase
phrase = generate_mnemonic()
dave = Account.from_mnemonic(phrase)
```

## Configuration

```python
from aptos_sdk_v2 import AptosConfig, Network

config = AptosConfig(
    network=Network.DEVNET,       # MAINNET | TESTNET | DEVNET | LOCAL | CUSTOM
    fullnode_url=None,            # Override node URL (required for CUSTOM)
    faucet_url=None,              # Override faucet URL
    max_gas_amount=200_000,       # Max gas units per transaction
    gas_unit_price=100,           # Gas price in octas
    expiration_ttl=600,           # Transaction expiration (seconds from now)
    transaction_wait_secs=20,     # Timeout for wait_for_transaction
    max_retries=3,                # HTTP retry count (retries on 429 and 5xx)
    api_key=None,                 # Bearer token for authenticated endpoints
)
```

## Transaction Pipeline

### High-Level Helper

```python
# CoinApi handles build + sign + submit internally
txn_hash = await aptos.coin.transfer(sender, recipient.address, amount)
await aptos.transaction.wait_for_transaction(txn_hash)
```

### Manual Pipeline

```python
from aptos_sdk_v2.transactions import EntryFunction, TransactionArgument, TransactionPayload
from aptos_sdk_v2.bcs import Serializer
from aptos_sdk_v2.types import StructTag, TypeTag

# 1. Build the payload
payload = EntryFunction.natural(
    "0x1::coin",
    "transfer",
    [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
    [
        TransactionArgument(recipient.address, Serializer.struct),
        TransactionArgument(1_000, Serializer.u64),
    ],
)

# 2. Build the raw transaction (fetches sequence number and chain ID)
raw_txn = await aptos.transaction.build(
    sender=alice.address,
    payload=TransactionPayload(payload),
)

# 3. Simulate (optional)
sim = await aptos.transaction.simulate(raw_txn, alice.public_key)
print(f"Gas used: {sim[0]['gas_used']}")

# 4. Sign, submit, and wait
result = await aptos.transaction.sign_submit_and_wait(raw_txn, alice)
print(f"Success: {result['success']}")
```

## Building Payloads

Use `EntryFunction.natural()` for most transactions:

```python
payload = EntryFunction.natural(
    "0x1::module_name",              # Module: address::module
    "function_name",                 # Function name
    [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],  # Type arguments
    [                                # Arguments (BCS-encoded)
        TransactionArgument(address, Serializer.struct),
        TransactionArgument(amount, Serializer.u64),
        TransactionArgument(True, Serializer.bool),
    ],
)
```

Common serializer methods: `Serializer.struct`, `Serializer.u8`, `Serializer.u16`, `Serializer.u32`, `Serializer.u64`, `Serializer.u128`, `Serializer.u256`, `Serializer.bool`, `Serializer.str`, `Serializer.to_bytes`.

## Advanced Transactions

### Multi-Agent

Multiple parties sign a single transaction. See [`examples/multi_agent_transfer.py`](examples/multi_agent_transfer.py).

### Fee-Payer (Sponsored)

A third party pays the gas fees. See [`examples/sponsored_transaction.py`](examples/sponsored_transaction.py).

### Orderless

Uses a replay-protection nonce instead of sequence numbers, enabling parallel submission. See [`examples/orderless_transfer.py`](examples/orderless_transfer.py).

## Error Handling

```python
from aptos_sdk_v2.errors import (
    AptosError,
    ApiError,
    AccountNotFoundError,
    TransactionFailedError,
    TransactionTimeoutError,
)

try:
    result = await aptos.transaction.sign_submit_and_wait(raw_txn, alice)
except TransactionFailedError as e:
    print(f"VM error: {e.vm_status}")
except TransactionTimeoutError as e:
    print(f"Timed out waiting for: {e.txn_hash}")
except ApiError as e:
    print(f"HTTP {e.status_code}: {e}")
except AptosError as e:
    print(f"SDK error: {e}")
```

## Examples

| Example | Description |
|---|---|
| [`transfer_apt.py`](examples/transfer_apt.py) | Basic APT transfer between two accounts |
| [`different_key_types.py`](examples/different_key_types.py) | Ed25519 vs Secp256k1 account creation and transfers |
| [`multi_agent_transfer.py`](examples/multi_agent_transfer.py) | Multi-agent transaction with two signers |
| [`sponsored_transaction.py`](examples/sponsored_transaction.py) | Fee-payer sponsored transaction |
| [`orderless_transfer.py`](examples/orderless_transfer.py) | Orderless transaction with replay-protection nonce |
| [`batch_orderless_transfers.py`](examples/batch_orderless_transfers.py) | Parallel orderless transfers |
| [`simulate_transaction.py`](examples/simulate_transaction.py) | Simulate a transaction before submitting |
| [`fetch_on_chain_data.py`](examples/fetch_on_chain_data.py) | Query ledger info, blocks, resources, and view functions |
| [`mnemonic_key_recovery.py`](examples/mnemonic_key_recovery.py) | BIP-39 mnemonic generation, validation, and key derivation |
| [`custom_coin_fungible_asset.py`](examples/custom_coin_fungible_asset.py) | Coin API vs Fungible Asset API side-by-side |
| [`script_transaction.py`](examples/script_transaction.py) | Script payload construction with typed ScriptArguments |

## Development

```bash
cd v2

# Install with dev dependencies
uv sync --extra dev

# Run tests with coverage
uv run pytest tests/unit --cov=aptos_sdk_v2 --cov-report=term-missing -q

# Type checking
uv run mypy src/

# Lint
uv run ruff check src/
```

## License

Apache-2.0
