# Aptos Python SDK
[![Discord][discord-image]][discord-url]
[![PyPI Package Version][pypi-image-version]][pypi-url]
[![PyPI Package Downloads][pypi-image-downloads]][pypi-url]
[![codecov][codecov-image]][codecov-url]

The official Python SDK for interacting with the [Aptos](https://github.com/aptos-labs/aptos-core/) blockchain. Get started with the [integration guide](https://aptos.dev/guides/system-integrators-guide/#getting-started).

> **Note:** The sync client is deprecated. Please use the async client for all new projects.

## Installation

```bash
pip install aptos-sdk
```

## Quickstart

```python
import asyncio
from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, RestClient

async def main():
    rest_client = RestClient("https://fullnode.devnet.aptoslabs.com/v1")
    faucet_client = FaucetClient("https://faucet.devnet.aptoslabs.com", rest_client)

    # Create and fund two accounts
    alice = Account.generate()
    bob = Account.generate()
    await faucet_client.fund_account(alice.address(), 100_000_000)
    await faucet_client.fund_account(bob.address(), 0)

    # Transfer 1_000 octas from Alice to Bob
    txn_hash = await rest_client.bcs_transfer(alice, bob.address(), 1_000)
    await rest_client.wait_for_transaction(txn_hash)

    print(f"Bob's balance: {await rest_client.account_balance(bob.address())}")
    await rest_client.close()

asyncio.run(main())
```

## API Overview

| Class | Description |
|-------|-------------|
| `RestClient` | Async client for the Aptos REST API (accounts, transactions, events, blocks). |
| `FaucetClient` | Funds accounts on devnet/testnet via the faucet service. |
| `Account` | Represents a keypair and address; supports Ed25519 and Secp256k1. |
| `AccountAddress` | 32-byte account address with AIP-40 compliant formatting. |
| `EntryFunction` | Constructs Move entry function payloads for submission. |
| `PackagePublisher` | Publishes and upgrades Move packages, with large-package chunking support. |

## Development

### Requirements
This SDK uses [uv](https://docs.astral.sh/uv/) for packaging and dependency management:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --extra dev
```

### Unit testing
```bash
make test
```

### Quick devnet smoke test

A single command that verifies node, faucet, transaction submission, simulation,
balance reads, and indexer (gracefully skipped on rate-limit) all work end-to-end:

```bash
make smoke           # uses public devnet by default
APTOS_NODE_URL=http://127.0.0.1:8080/v1 \
APTOS_FAUCET_URL=http://127.0.0.1:8081  \
make smoke           # against a local testnet
```

### Test coverage

```bash
make test-coverage
```

The legacy `aptos_sdk/` package targets ≥ 90 % unit-test coverage. The standalone
v2 package under `v2/` targets ≥ 95 %. Coverage from both is uploaded to
[Codecov][codecov-url] under the `v1-sdk` and `v2-sdk` flags respectively.

### E2E testing and Using the Aptos CLI

* Download and install the [Aptos CLI](https://aptos.dev/tools/aptos-cli/use-cli/running-a-local-network).
* Set the environment variable `APTOS_CLI_PATH` to the full path of the CLI.
* Retrieve the [Aptos Core Github Repo](https://github.com/aptos-labs/aptos-core) (git clone https://github.com/aptos-labs/aptos-core)
* Set the environment variable `APTOS_CORE_REPO` to the full path of the Repository.
* `make integration_test`

You can do this a bit more manually by:

First, run a local testnet (run this from the root of aptos-core):

```bash
aptos node run-local-testnet --force-restart --assume-yes --with-indexer-api
```

Next, tell the end-to-end tests to talk to this locally running testnet:

```bash
export APTOS_CORE_REPO="/path/to/repo"
export APTOS_FAUCET_URL="http://127.0.0.1:8081"
export APTOS_INDEXER_URL="http://127.0.0.1:8090/v1/graphql"
export APTOS_NODE_URL="http://127.0.0.1:8080/v1"
```

Finally run the tests:

```bash
make examples
```

Integration Testing Using the Aptos CLI:

```bash
make integration_test
```

> [!NOTE]
> The Python SDK does not require the Indexer, if you would prefer to test without it, unset or do not set the environmental variable `APTOS_INDEXER_URL` and exclude `--with-indexer-api` from running the aptos node software.

### Autoformatting
```bash
make fmt
```

### Autolinting
```bash
make lint
```

### Package Publishing

* Download the [Aptos CLI](https://aptos.dev/tools/aptos-cli/install-cli/).
* Set the environment variable `APTOS_CLI_PATH` to the full path of the CLI.
* `uv run python -m aptos_sdk.cli` and set the appropriate command-line parameters

## Semantic versioning
This project follows [semver](https://semver.org/) as closely as possible

[repo]: https://github.com/aptos-labs/aptos-core
[pypi-image-version]: https://img.shields.io/pypi/v/aptos-sdk.svg
[pypi-image-downloads]: https://img.shields.io/pypi/dm/aptos-sdk.svg
[pypi-url]: https://pypi.org/project/aptos-sdk
[discord-image]: https://img.shields.io/discord/945856774056083548?label=Discord&logo=discord&style=flat~~~~
[discord-url]: https://discord.gg/aptosnetwork
[codecov-image]: https://codecov.io/gh/aptos-labs/aptos-python-sdk/branch/main/graph/badge.svg
[codecov-url]: https://codecov.io/gh/aptos-labs/aptos-python-sdk
