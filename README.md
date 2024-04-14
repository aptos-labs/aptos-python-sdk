# Aptos Python SDK
[![Discord][discord-image]][discord-url]
[![PyPI Package Version][pypi-image-version]][pypi-url]
[![PyPI Package Downloads][pypi-image-downloads]][pypi-url]

This provides basic functionalities to interact with [Aptos](https:/github.com/aptos-labs/aptos-core/). Get started [here](https://aptos.dev/guides/system-integrators-guide/#getting-started).

Currently, this is still in development and may not be suitable for production purposes.

Note: The sync client is deprecated, please only start new projects using the async client. Feature contributions to the sync client will be rejected.

## Requirements
This SDK uses [Poetry](https://python-poetry.org/docs/#installation) for packaging and dependency management:

```
curl -sSL https://install.python-poetry.org | python3 -
poetry install
```

## Unit testing
```bash
make test
```

## E2E testing and Using the Aptos CLI

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

## Autoformatting
```bash
make fmt
```

## Autolinting
```bash
make lint
```

## Package Publishing

* Download the [Aptos CLI](https://aptos.dev/tools/aptos-cli/install-cli/).
* Set the environment variable `APTOS_CLI_PATH` to the full path of the CLI.
* `poetry run python -m aptos_sdk.cli` and set the appropriate command-line parameters

## Semantic versioning
This project follows [semver](https://semver.org/) as closely as possible

[repo]: https://github.com/aptos-labs/aptos-core
[pypi-image-version]: https://img.shields.io/pypi/v/aptos-sdk.svg
[pypi-image-downloads]: https://img.shields.io/pypi/dm/aptos-sdk.svg
[pypi-url]: https://pypi.org/project/aptos-sdk
[discord-image]: https://img.shields.io/discord/945856774056083548?label=Discord&logo=discord&style=flat~~~~
[discord-url]: https://discord.gg/aptosnetwork
