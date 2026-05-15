# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

"""
End-to-end smoke test for the SDK against a live Aptos network.

Exercises (in order):
    1. ``RestClient.info`` and ``chain_id`` — node liveness + ID caching
    2. ``FaucetClient.fund_account`` — account funding
    3. ``RestClient.account_balance`` — coin / FA balance read
    4. ``RestClient.simulate_transaction`` — pre-flight gas estimation
    5. ``RestClient.bcs_transfer`` — APT transfer
    6. ``RestClient.transfer_coins`` — typed coin transfer
    7. ``RestClient.account_resources`` and ``transactions_by_account``
    8. Optional: ``IndexerClient.query`` — graceful skip on rate limit

Run against devnet (default), localnet, or testnet:

.. code-block:: bash

    uv run python -m examples.e2e_smoke
    APTOS_NODE_URL=http://127.0.0.1:8080/v1 \\
    APTOS_FAUCET_URL=http://127.0.0.1:8081 \\
        uv run python -m examples.e2e_smoke

The script exits non-zero on the first failure so it can be wired into CI as a
single-command health check.
"""

from __future__ import annotations

import asyncio
import sys
import traceback

from aptos_sdk.account import Account
from aptos_sdk.async_client import (
    FaucetClient,
    IndexerClient,
    IndexerError,
    RestClient,
)
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

from .common import (
    CLIENT_CONFIG,
    FAUCET_AUTH_TOKEN,
    FAUCET_URL,
    INDEXER_URL,
    NODE_URL,
)

APTOS_COIN = "0x1::aptos_coin::AptosCoin"


async def _step(name: str, coro):
    print(f"  -> {name} ... ", end="", flush=True)
    try:
        result = await coro
    except Exception as exc:  # surface any failure clearly
        print(f"FAIL\n    {type(exc).__name__}: {exc}")
        traceback.print_exc()
        raise
    print("OK")
    return result


def _transfer_payload(recipient, amount: int) -> TransactionPayload:
    return TransactionPayload(
        EntryFunction.natural(
            "0x1::aptos_account",
            "transfer",
            [],
            [
                TransactionArgument(recipient, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
            ],
        )
    )


async def main() -> int:
    print(f"Node: {NODE_URL}")
    print(f"Faucet: {FAUCET_URL}")
    rest = RestClient(NODE_URL, client_config=CLIENT_CONFIG)
    faucet = FaucetClient(FAUCET_URL, rest, FAUCET_AUTH_TOKEN)

    try:
        info = await _step("ledger info", rest.info())
        print(f"    chain_id={info['chain_id']}, version={info['ledger_version']}")
        chain_id = await _step("chain_id() caches", rest.chain_id())
        assert chain_id == int(info["chain_id"])

        alice = Account.generate()
        bob = Account.generate()
        print(f"    Alice = {alice.address()}")
        print(f"    Bob   = {bob.address()}")

        await _step(
            "faucet.fund_account(alice)",
            faucet.fund_account(alice.address(), 100_000_000),
        )
        await _step(
            "faucet.fund_account(bob)",
            faucet.fund_account(bob.address(), 1),
        )

        alice_balance = await _step("account_balance(alice)", rest.account_balance(alice.address()))
        assert alice_balance > 0, "Alice was just funded; balance must be positive"

        # Pre-flight simulation (uses a zero-signature authenticator).
        raw = await rest.create_bcs_transaction(alice, _transfer_payload(bob.address(), 1))
        sim = await _step("simulate_transaction(transfer)", rest.simulate_transaction(raw, alice))
        assert sim and sim[0].get("success"), f"simulation failed: {sim}"

        h1 = await _step(
            "bcs_transfer(alice -> bob, 1000)",
            rest.bcs_transfer(alice, bob.address(), 1_000),
        )
        await _step(f"wait_for_transaction({h1[:10]}...)", rest.wait_for_transaction(h1))

        h2 = await _step(
            "transfer_coins(alice -> bob, 1000, AptosCoin)",
            rest.transfer_coins(alice, bob.address(), APTOS_COIN, 1_000),
        )
        await _step(f"wait_for_transaction({h2[:10]}...)", rest.wait_for_transaction(h2))

        bob_balance = await _step("account_balance(bob)", rest.account_balance(bob.address()))
        assert bob_balance >= 2_001, f"Bob should have at least 2001, got {bob_balance}"

        await _step("account_resources(alice)", rest.account_resources(alice.address()))
        await _step(
            "transactions_by_account(alice)",
            rest.transactions_by_account(alice.address(), limit=5),
        )

        if INDEXER_URL and INDEXER_URL != "none":
            indexer = IndexerClient(INDEXER_URL)
            try:
                await indexer.query(
                    "query Q { account_transactions(limit: 1) { transaction_version } }",
                    {},
                )
                print("  -> indexer reachable and returned data")
            except IndexerError as exc:
                # The public devnet indexer is rate limited; treat as soft skip.
                print(f"  -> indexer skipped (rate-limited or down): {exc}")

        print("\nAll smoke checks passed.")
        return 0
    finally:
        await rest.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
