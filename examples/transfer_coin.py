# Copyright © Aptos Foundation
# SPDX-License-Identifier: Apache-2.0

import asyncio
from typing import Optional

from aptos_sdk.account import Account
from aptos_sdk.async_client import FaucetClient, IndexerClient, IndexerError, RestClient

from .common import CLIENT_CONFIG, FAUCET_AUTH_TOKEN, FAUCET_URL, INDEXER_URL, NODE_URL


async def main():
    # :!:>section_1
    rest_client = RestClient(NODE_URL, client_config=CLIENT_CONFIG)
    faucet_client = FaucetClient(FAUCET_URL, rest_client, FAUCET_AUTH_TOKEN)  # <:!:section_1
    if INDEXER_URL and INDEXER_URL != "none":
        indexer_client = IndexerClient(INDEXER_URL)
    else:
        indexer_client = None

    # :!:>section_2
    alice = Account.generate()
    bob = Account.generate()  # <:!:section_2

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    # :!:>section_3
    alice_fund = faucet_client.fund_account(alice.address(), 1_000_000_000)
    bob_fund = faucet_client.fund_account(bob.address(), 1)  # <:!:section_3
    await asyncio.gather(*[alice_fund, bob_fund])

    print("\n=== Initial Balances ===")
    # :!:>section_4
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    # Have Alice give Bob 1_000 coins
    # :!:>section_5
    txn_hash = await rest_client.bcs_transfer(alice, bob.address(), 1_000)  # <:!:section_5
    # :!:>section_6
    await rest_client.wait_for_transaction(txn_hash)  # <:!:section_6

    print("\n=== Intermediate Balances ===")
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")  # <:!:section_4

    # Have Alice give Bob another 1_000 coins using BCS
    txn_hash = await rest_client.bcs_transfer(alice, bob.address(), 1_000)
    await rest_client.wait_for_transaction(txn_hash)

    print("\n=== Final Balances ===")
    alice_balance = rest_client.account_balance(alice.address())
    bob_balance = rest_client.account_balance(bob.address())
    [alice_balance, bob_balance] = await asyncio.gather(*[alice_balance, bob_balance])
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")

    if indexer_client:
        query = """
            query TransactionsQuery($account: String) {
              account_transactions(
                limit: 20
                where: {account_address: {_eq: $account}}
              ) {
                transaction_version
              }
            }
        """

        variables = {"account": f"{bob.address()}"}
        data = None
        last_error: Optional[Exception] = None
        for _ in range(20):
            try:
                data = await indexer_client.query(query, variables)
            except IndexerError as exc:
                # The public devnet indexer is heavily rate-limited; treat that
                # as a soft failure for the example rather than crashing.
                last_error = exc
                await asyncio.sleep(1)
                continue
            if data and "data" in data and len(data["data"]["account_transactions"]) > 0:
                break
            await asyncio.sleep(1)

        if last_error is not None and (
            data is None or "data" not in data or not data["data"]["account_transactions"]
        ):
            # Indexer was unreachable / rate-limited the whole time; soft-skip.
            print(
                "\n=== Indexer ===\n"
                f"Skipped indexer assertion (no data returned). Last error: {last_error}"
            )
        else:
            # The indexer responded; assert it actually saw Bob's transactions
            # so we still verify correctness end-to-end on healthy networks.
            assert data is not None and "data" in data, (
                f"indexer returned malformed payload: {data!r}"
            )
            assert len(data["data"]["account_transactions"]) > 0, (
                "indexer returned no transactions for Bob despite no transport errors"
            )

    await rest_client.close()


if __name__ == "__main__":
    asyncio.run(main())
