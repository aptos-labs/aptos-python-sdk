# Aptos Python SDK

[![Discord][discord-image]][discord-url]
[![PyPI Package Version][pypi-image-version]][pypi-url]
[![PyPI Package Downloads][pypi-image-downloads]][pypi-url]

Official Python SDK for interacting with the [Aptos](https://github.com/aptos-labs/aptos-core/) blockchain.

## Installation

```bash
pip install aptos-sdk
```

Or with Poetry:

```bash
poetry add aptos-sdk
```

## Quick Start

```python
import asyncio
from aptos_sdk import Account, RestClient, FaucetClient, Network

async def main():
    # Connect to testnet
    async with RestClient(Network.TESTNET.fullnode_url) as client:
        faucet = FaucetClient(Network.TESTNET.faucet_url, client)

        # Create and fund a new account
        alice = Account.generate()
        await faucet.fund_account(alice.address(), 100_000_000)

        # Check balance
        balance = await client.account_balance(alice.address())
        print(f"Alice's balance: {balance / 100_000_000} APT")

        # Get account info
        info = await client.account(alice.address())
        print(f"Sequence number: {info['sequence_number']}")

asyncio.run(main())
```

## Features

- **Account Management** - Ed25519, Secp256k1-ECDSA, MultiKey support
- **Transaction Building** - Entry functions, scripts, multi-agent, fee payer
- **Digital Assets (NFTs)** - Token v2 creation, minting, transfers
- **Package Publishing** - Standard, object, and large package deployment
- **Indexer Support** - GraphQL queries via IndexerClient
- **BCS Serialization** - Full serialization/deserialization support
- **Async/Await** - Modern async HTTP client with HTTP/2

## Network Presets

```python
from aptos_sdk import Network

# Use preset network configurations
Network.MAINNET.fullnode_url  # https://fullnode.mainnet.aptoslabs.com/v1
Network.TESTNET.fullnode_url  # https://fullnode.testnet.aptoslabs.com/v1
Network.DEVNET.fullnode_url   # https://fullnode.devnet.aptoslabs.com/v1
Network.LOCAL.fullnode_url    # http://127.0.0.1:8080/v1

# Or from string
network = Network.from_string("testnet")
```

## Examples

### Transfer Coins

```python
from aptos_sdk import Account, RestClient, Network
from aptos_sdk.transactions import EntryFunction, TransactionArgument, TransactionPayload
from aptos_sdk.bcs import Serializer

async def transfer():
    async with RestClient(Network.TESTNET.fullnode_url) as client:
        sender = Account.load_key("your_private_key")
        recipient = "0x1"  # recipient address
        amount = 1_000_000  # 0.01 APT

        payload = EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )

        txn_hash = await client.submit_transaction(sender, TransactionPayload(payload))
        await client.wait_for_transaction(txn_hash)
        print(f"Transaction: {txn_hash}")
```

### ANS (Aptos Names Service)

```python
from aptos_sdk import RestClient, Network, ans

async def resolve_name():
    async with RestClient(Network.MAINNET.fullnode_url) as client:
        # Resolve name to address
        address = await ans.get_address(client, "alice.apt")
        if address:
            print(f"alice.apt -> {address}")

        # Get primary name for address
        name = await ans.get_primary_name(client, some_address)
        if name:
            print(f"{some_address} -> {name}")
```

### Fungible Assets

```python
from aptos_sdk import RestClient, Network, fa

async def check_balance():
    async with RestClient(Network.MAINNET.fullnode_url) as client:
        # Get FA metadata
        metadata = await fa.get_metadata(client, token_address)
        print(f"Token: {metadata.name} ({metadata.symbol})")

        # Get balance
        balance = await fa.get_balance(client, owner_address, token_address)
        formatted = fa.format_amount(balance, metadata.decimals)
        print(f"Balance: {formatted} {metadata.symbol}")
```

See the [examples/](./examples/) directory for more complete examples.

## Documentation

- [Aptos Developer Docs](https://aptos.dev)
- [Python SDK Guide](https://aptos.dev/en/build/sdks/python-sdk)
- [API Reference](https://aptos.dev/en/build/sdks/python-sdk/aptos-python-sdk)

## Development

### Requirements

This SDK uses [Poetry](https://python-poetry.org/docs/#installation) for packaging:

```bash
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

### Running Tests

```bash
# Unit tests (pytest)
poetry run pytest tests/

# Unit tests (unittest - legacy)
make test

# BDD tests
poetry run behave

# Integration tests (requires local node)
make integration_test

# With coverage
poetry run pytest --cov=aptos_sdk --cov-report=html
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Type checking
poetry run mypy aptos_sdk/
```

### E2E Testing with Local Node

1. Install the [Aptos CLI](https://aptos.dev/tools/aptos-cli/install-cli/)
2. Run a local testnet:
   ```bash
   aptos node run-local-testnet --force-restart --assume-yes
   ```
3. Run integration tests:
   ```bash
   export APTOS_NODE_URL="http://127.0.0.1:8080/v1"
   export APTOS_FAUCET_URL="http://127.0.0.1:8081"
   make examples
   ```

## Error Handling

The SDK provides a comprehensive exception hierarchy:

```python
from aptos_sdk import RestClient
from aptos_sdk.errors import (
    AptosError,          # Base class for all SDK errors
    ApiError,            # HTTP API errors
    AccountNotFound,     # Account doesn't exist
    TransactionFailed,   # Transaction execution failed
    TransactionTimeout,  # Transaction didn't confirm in time
)

async with RestClient(url) as client:
    try:
        await client.account(address)
    except AccountNotFound:
        print("Account doesn't exist yet")
    except ApiError as e:
        print(f"API error {e.status_code}: {e}")
    except AptosError as e:
        print(f"SDK error: {e}")
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Semantic Versioning

This project follows [semver](https://semver.org/) as closely as possible.

## License

Apache-2.0

[repo]: https://github.com/aptos-labs/aptos-python-sdk
[pypi-image-version]: https://img.shields.io/pypi/v/aptos-sdk.svg
[pypi-image-downloads]: https://img.shields.io/pypi/dm/aptos-sdk.svg
[pypi-url]: https://pypi.org/project/aptos-sdk
[discord-image]: https://img.shields.io/discord/945856774056083548?label=Discord&logo=discord&style=flat
[discord-url]: https://discord.gg/aptosnetwork
