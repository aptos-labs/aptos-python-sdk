"""Example: Orderless transaction with nonce-based replay protection.

Orderless transactions (AIP-123/129) replace sequence numbers with random
nonces, enabling concurrent transaction submission without coordination.
Key properties:
  - No sequence number required (set to 0, ignored on-chain)
  - Replay protection via a random 64-bit nonce
  - Maximum expiration window of 60 seconds
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


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice: {alice.address}")
        print(f"Bob:   {bob.address}")

        # Fund accounts
        print("\nFunding accounts...")
        await asyncio.gather(
            aptos.faucet.fund_account(alice.address, 100_000_000),
            aptos.faucet.fund_account(bob.address, 10_000_000),
        )

        # Build a transfer payload
        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(1_000, Serializer.u64),
            ],
        )

        # Generate a random nonce for replay protection
        nonce = random.randint(0, 2**64 - 1)
        print(f"\nUsing replay protection nonce: {nonce}")

        # Build with orderless nonce — note: expiration must be <= 60s from now
        raw_txn = await aptos.transaction.build(
            sender=alice.address,
            payload=TransactionPayload(payload),
            replay_protection_nonce=nonce,
            expiration_timestamps_secs=int(time.time()) + 60,
        )

        # The payload is now wrapped in TransactionInnerPayload (variant 4)
        print(f"Payload variant: {raw_txn.payload.variant} (4 = orderless)")
        print(f"Sequence number: {raw_txn.sequence_number} (ignored for orderless)")

        # Sign and submit
        result = await aptos.transaction.sign_submit_and_wait(raw_txn, alice)
        print(f"\nTransaction success: {result['success']}")
        print(f"Gas used: {result['gas_used']}")

        bob_balance = await aptos.coin.balance(bob.address)
        print(f"Bob balance: {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
