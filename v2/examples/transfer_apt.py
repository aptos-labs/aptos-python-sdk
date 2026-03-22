"""Example: Transfer APT between accounts on devnet."""

import asyncio

from aptos_sdk_v2 import Account, Aptos, AptosConfig, Network


async def main():
    config = AptosConfig(network=Network.DEVNET)
    async with Aptos(config) as aptos:
        # Create two accounts
        alice = Account.generate()
        bob = Account.generate()
        print(f"Alice: {alice.address}")
        print(f"Bob:   {bob.address}")

        # Fund Alice
        print("\nFunding Alice...")
        await aptos.faucet.fund_account(alice.address, 100_000_000)

        # Fund Bob so account exists on-chain
        print("Funding Bob...")
        await aptos.faucet.fund_account(bob.address, 10_000_000)

        # Check balances
        alice_balance = await aptos.coin.balance(alice.address)
        bob_balance = await aptos.coin.balance(bob.address)
        print(f"\nAlice balance: {alice_balance}")
        print(f"Bob balance:   {bob_balance}")

        # Transfer 1000 octas from Alice to Bob
        print("\nTransferring 1000 octas from Alice to Bob...")
        txn_hash = await aptos.coin.transfer(alice, bob.address, 1_000)
        result = await aptos.transaction.wait_for_transaction(txn_hash)
        print(f"Transaction: {txn_hash}")
        print(f"Success: {result['success']}")

        # Check final balances
        alice_balance = await aptos.coin.balance(alice.address)
        bob_balance = await aptos.coin.balance(bob.address)
        print(f"\nAlice balance: {alice_balance}")
        print(f"Bob balance:   {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
