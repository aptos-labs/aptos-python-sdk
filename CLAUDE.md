# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the official Aptos Python SDK for interacting with the Aptos blockchain. It's an async-first SDK supporting Python 3.10+, using Poetry for package management.

## Common Commands

```bash
# Install dependencies
poetry install

# Run unit tests (excludes integration tests)
make test

# Run integration tests (requires live network)
make integration_test

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

# Run examples (requires devnet or localnet)
make examples
```

## Architecture

### Core Modules

- **`async_client.py`** - Main entry point: `RestClient`, `FaucetClient`. All I/O is async via httpx HTTP/2.
- **`transactions.py`** - Transaction building: `RawTransaction`, `EntryFunction`, `Script`, `SignedTransaction`
- **`transaction_builder.py`** - High-level transaction construction helpers
- **`account.py`** - Account management with address + private key
- **`bcs.py`** - Binary Canonical Serialization (Serializer/Deserializer)
- **`authenticator.py`** - Transaction authenticators (Ed25519, MultiAgent, FeePayer, SingleKey)
- **`errors.py`** - Spec-aligned error hierarchy (all exceptions inherit from `AptosError`)

### Cryptography Stack

- **`asymmetric_crypto.py`** - Abstract `PrivateKey`/`PublicKey`/`Signature` protocols
- **`ed25519.py`** - Ed25519 implementation (default)
- **`secp256k1_ecdsa.py`** - Secp256k1 ECDSA implementation
- **`crypto_wrapper.py`** - AnyPublicKey/AnySignature and multi-key support
- **`hashing.py`** - SHA3-256 hashing with domain-separation prefixes

### Network & Configuration

- **`network.py`** - Network enum and configuration (MAINNET, TESTNET, DEVNET, LOCAL)
- **`chain_id.py`** - Chain ID type
- **`retry.py`** - Retry configuration for REST client
- **`mnemonic.py`** - BIP-39 mnemonic support (optional dependency)

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

All SDK exceptions inherit from `AptosError`. Key exceptions: `ApiError`, `NotFoundError`, `BadRequestError`, `RateLimitedError`, `NetworkError`, `CryptoError`, `BcsError`.

## Testing

- Tests use `pytest-asyncio` with `asyncio_mode = "auto"` (no need to mark async tests)
- Integration test fixtures in `tests/integration/conftest.py` (env-var driven network config)
- Integration tests marked with `@pytest.mark.integration`
- `make test` excludes integration tests; `make integration_test` runs them
- Coverage target: 50% minimum (enforced in CI)

## Code Style

- Line length: 88 (black default)
- Type hints required throughout
- Formatting: black + isort (profile="black")
- All public modules have Apache-2.0 license headers
