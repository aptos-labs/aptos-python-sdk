"""Example: Simulate a transaction before submitting."""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network
from aptos_sdk_v2.bcs import Serializer
from aptos_sdk_v2.transactions import EntryFunction, TransactionArgument, TransactionPayload
from aptos_sdk_v2.types import StructTag, TypeTag


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice: {alice.address}")
        print(f"Bob:   {bob.address}")

        # Fund accounts
        await aptos.faucet.fund_account(alice.address, 100_000_000)
        await aptos.faucet.fund_account(bob.address, 10_000_000)

        # Build a transfer payload
        payload = EntryFunction.natural(
            "0x1::coin",
            "transfer",
            [TypeTag(StructTag.from_str("0x1::aptos_coin::AptosCoin"))],
            [
                TransactionArgument(bob.address, Serializer.struct),
                TransactionArgument(50_000, Serializer.u64),
            ],
        )

        # Build the raw transaction
        raw_txn = await aptos.transaction.build(
            sender=alice.address,
            payload=TransactionPayload(payload),
        )

        # Simulate first
        print("\nSimulating transaction...")
        sim_result = await aptos.transaction.simulate(raw_txn, alice.public_key)
        print(f"Simulation success: {sim_result[0]['success']}")
        print(f"Gas used: {sim_result[0]['gas_used']}")
        print(f"VM status: {sim_result[0]['vm_status']}")

        # Now actually submit
        print("\nSubmitting transaction...")
        result = await aptos.transaction.sign_submit_and_wait(raw_txn, alice)
        print(f"Transaction success: {result['success']}")
        print(f"Gas used: {result['gas_used']}")


if __name__ == "__main__":
    asyncio.run(main())
