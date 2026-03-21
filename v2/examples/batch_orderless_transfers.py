"""Example: Batch concurrent orderless transactions.

Demonstrates submitting multiple transactions simultaneously using orderless
nonces — no sequence number coordination needed. Each transaction gets a
unique random nonce for replay protection.
"""

import asyncio
import random
import time

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.bcs import Serializer
from aptos_sdk_v2.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
from aptos_sdk_v2.types import StructTag, TypeTag

BATCH_SIZE = 5
AMOUNT_PER_TXN = 100


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice: {alice.address}")
        print(f"Bob:   {bob.address}")

        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
        )

        bob_before = await aptos.coin.balance(bob.address)

        # Build N transactions with unique nonces — all at once
        print(f"\nBuilding {BATCH_SIZE} orderless transactions...")
        expiration = int(time.time()) + 60
        raw_txns = []
        for i in range(BATCH_SIZE):
            payload = EntryFunction.natural(
                "0x1::coin",
                "transfer",
                [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
                [
                    TransactionArgument(bob.address, Serializer.struct),
                    TransactionArgument(AMOUNT_PER_TXN, Serializer.u64),
                ],
            )
            nonce = random.randint(0, 2**64 - 1)
            raw_txn = await aptos.transaction.build(
                sender=alice.address,
                payload=TransactionPayload(payload),
                replay_protection_nonce=nonce,
                expiration_timestamps_secs=expiration,
            )
            raw_txns.append(raw_txn)
            print(f"  Transaction {i + 1}: nonce={nonce}")

        # Sign all transactions
        signed_txns = [aptos.transaction.sign(txn, alice) for txn in raw_txns]

        # Submit all concurrently
        print(f"\nSubmitting {BATCH_SIZE} transactions concurrently...")
        hashes = await asyncio.gather(
            *[aptos.transaction.submit(signed) for signed in signed_txns]
        )

        # Wait for all to complete
        print("Waiting for all transactions...")
        results = await asyncio.gather(
            *[aptos.transaction.wait_for_transaction(h) for h in hashes]
        )

        for i, result in enumerate(results):
            print(f"  Transaction {i + 1}: success={result['success']}, gas={result['gas_used']}")

        bob_after = await aptos.coin.balance(bob.address)
        print(f"\nBob received: {bob_after - bob_before} octas total")
        print(f"Expected:     {BATCH_SIZE * AMOUNT_PER_TXN} octas")


if __name__ == "__main__":
    asyncio.run(main())
