## Cursor Cloud specific instructions

### Project overview

Aptos Python SDK — a pure Python library for interacting with the Aptos blockchain. No infrastructure services (databases, Docker, etc.) are required for development.

### Prerequisites

- **uv** must be available on PATH. Install via `curl -LsSf https://astral.sh/uv/install.sh | sh`.
- **Python 3.12+** is required (Python 3.12 is pre-installed on the VM).

### Common commands

All `make` targets use `uv run`. See `Makefile` for the full list.

| Task | Command |
|---|---|
| Install deps | `uv sync --extra dev` |
| Unit tests + BDD specs | `make test` |
| Lint (mypy + ruff) | `make lint` |
| Autoformat | `make fmt` |
| Test coverage | `make test-coverage` |

### Caveats

- `make fmt` reformats files via `ruff`. After running it, check `git diff` — the existing codebase may not be fully formatted, so `make fmt` can produce changes even on a clean checkout. Do not commit those unless the PR is specifically about formatting.
- E2E / integration tests (`make examples`, `make integration_test`) require a running Aptos local testnet and the `APTOS_CLI_PATH` environment variable. These are **not** needed for normal SDK development or unit testing.
- The sync client (`client.py`) is deprecated; use `async_client.py` for new work.
