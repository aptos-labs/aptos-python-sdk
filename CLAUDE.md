# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the official Aptos Python SDK for interacting with the Aptos blockchain. It's an async-first SDK supporting Python 3.9+, using Poetry for package management.

## Common Commands

```bash
# Install dependencies
poetry install

# Run all tests (pytest + BDD)
make test

# Run only pytest
poetry run pytest tests/ -v

# Run a single test file
poetry run pytest tests/test_account.py -v

# Run a single test function
poetry run pytest tests/test_account.py::TestAccount::test_generate -v

# Run tests with coverage
make test-coverage

# Format code (autoflake, isort, black)
make fmt

# Lint and type check (mypy, flake8)
make lint

# Run examples (requires local node or testnet)
make examples

# Generate docs
make docs
```

## Architecture

### Core Modules

- **`async_client.py`** - Main entry point: `RestClient`, `FaucetClient`, `IndexerClient`. All I/O is async.
- **`transactions.py`** - Transaction building: `RawTransaction`, `EntryFunction`, `Script`, `SignedTransaction`
- **`account.py`** - Account management with address + private key
- **`bcs.py`** - Binary Canonical Serialization (Serializer/Deserializer)
- **`authenticator.py`** - Transaction authenticators (Ed25519, MultiAgent, FeePayer, SingleKey)

### Cryptography Stack

- **`asymmetric_crypto.py`** - Abstract `PrivateKey`/`PublicKey`/`Signature` protocols
- **`ed25519.py`** - Ed25519 implementation (default)
- **`secp256k1_ecdsa.py`** - Secp256k1 ECDSA implementation
- **`asymmetric_crypto_wrapper.py`** - Multi-key support

### Blockchain Features

- **`aptos_token_client.py`** - Token v2 (NFTs)
- **`package_publisher.py`** - Deploy Move packages
- **`ans.py`** - Aptos Names Service resolution
- **`fungible_asset.py`** - Fungible asset operations

### Network Configuration

```python
from aptos_sdk import Network
Network.MAINNET  # Production
Network.TESTNET  # Testing
Network.DEVNET   # Development
Network.LOCAL    # Local node (127.0.0.1:8080)
```

## Key Patterns

### Async Context Manager (Preferred)

```python
async with RestClient(Network.TESTNET.fullnode_url) as client:
    balance = await client.account_balance(address)
```

### Transaction Building

```python
payload = EntryFunction.natural(
    "0x1::aptos_account",
    "transfer",
    [],  # type args
    [TransactionArgument(recipient, Serializer.struct),
     TransactionArgument(amount, Serializer.u64)],
)
txn_hash = await client.submit_transaction(account, TransactionPayload(payload))
await client.wait_for_transaction(txn_hash)
```

### Error Handling

All SDK exceptions inherit from `AptosError`. Key exceptions: `ApiError`, `AccountNotFound`, `TransactionFailed`, `TransactionTimeout`.

## Testing

- Tests use `pytest-asyncio` with `asyncio_mode = "auto"` (no need to mark async tests)
- Shared fixtures in `tests/conftest.py` include `mock_httpx_client`, `mock_rest_client_response`
- Integration tests marked with `@pytest.mark.integration`
- Coverage target: 50% minimum (enforced in CI)

## Code Style

- Line length: 88 (black default)
- Type hints required throughout
- Formatting: black + isort (profile="black")
- All public modules have Apache-2.0 license headers
